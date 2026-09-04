package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"golang.org/x/sys/unix"
)

var (
	ErrControllerAlreadyRunning  = errors.New("gateway controller is already running")
	ErrControllerRuntimeConflict = errors.New("gateway controller runtime conflicts with an existing resource")
	ErrControllerGeneration      = errors.New("authoritative state generation conflict")
	localOperationPattern        = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)
)

type ControllerStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

type UnitObservation struct {
	Name        string `json:"name"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
}

type Observation struct {
	ObservedAt time.Time         `json:"observed_at"`
	Units      []UnitObservation `json:"units"`
	Issues     []string          `json:"issues"`
}

type PassiveObserver interface {
	Observe(context.Context, model.State) (Observation, error)
}

type MutationDispatcher interface {
	Dispatch(context.Context, model.State, string, json.RawMessage) (model.State, json.RawMessage, error)
}

// PreparedMutationDispatcher is the data-plane-safe mutation path. Prepare is
// read-only; Apply activates the candidate runtime before authoritative state
// is committed, and Rollback restores the exact previous runtime if that state
// commit fails. Legacy pure-state dispatchers remain supported above.
type PreparedMutationDispatcher interface {
	Prepare(context.Context, model.State, string, json.RawMessage) (PreparedMutation, error)
}

type PreparedMutation struct {
	Candidate model.State
	Data      json.RawMessage
	Changed   bool
	Apply     func(context.Context) error
	Rollback  func(context.Context) error
}

type ControllerRuntime struct {
	Paths      store.Paths
	State      ControllerStateStore
	Observer   PassiveObserver
	Dispatcher MutationDispatcher
	Now        func() time.Time
}

type Controller struct {
	runtime ControllerRuntime

	mutationMu  sync.Mutex
	observation sync.RWMutex
	lastState   model.State
	lastObserve Observation
}

func NewController(runtime ControllerRuntime) (*Controller, error) {
	if runtime.State == nil || runtime.Observer == nil {
		return nil, fmt.Errorf("controller dependencies are incomplete")
	}
	want, err := store.NewPaths(runtime.Paths.Root)
	if err != nil || want != runtime.Paths {
		return nil, fmt.Errorf("controller paths do not match the system root")
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	return &Controller{runtime: runtime}, nil
}

// Serve owns only the local Unix listener. Cancellation closes admission,
// waits for accepted requests, and removes the exact socket inode; it never
// starts, stops, restarts, or converges a data-plane unit.
func (controller *Controller) Serve(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if controller == nil {
		return fmt.Errorf("controller is required")
	}
	if err := controller.validateRuntimeDirectory(); err != nil {
		return err
	}
	lock, err := controller.acquireWriterLock()
	if err != nil {
		return err
	}
	defer func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		_ = lock.Close()
	}()

	state, err := controller.runtime.State.Load()
	if err != nil {
		return fmt.Errorf("load authoritative gateway state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return fmt.Errorf("controller requires gateway state, found role %s", state.Host.Role)
	}
	controller.recordObservation(ctx, state)
	listener, socketInfo, err := controller.listen()
	if err != nil {
		return err
	}
	defer controller.removeOwnedSocket(socketInfo)

	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-closed:
		}
	}()
	defer close(closed)

	var handlers sync.WaitGroup
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			return fmt.Errorf("accept controller connection: %w", err)
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer connection.Close()
			controller.handleConnection(connection)
		}()
	}
	handlers.Wait()
	return nil
}

func (controller *Controller) handleConnection(connection *net.UnixConn) {
	_ = connection.SetReadDeadline(time.Now().Add(control.LocalTimeout))
	data, err := io.ReadAll(io.LimitReader(connection, control.LocalMaximumBytes+1))
	if err != nil {
		controller.writeResponse(connection, localFailure("read_failed", "local request could not be read"))
		return
	}
	_ = connection.SetReadDeadline(time.Time{})
	if len(data) > control.LocalMaximumBytes {
		controller.writeResponse(connection, localFailure("request_too_large", "local request exceeds the size limit"))
		return
	}
	request, err := control.DecodeLocalRequest(data)
	if err != nil {
		controller.writeResponse(connection, localFailure("invalid_request", "local request is invalid"))
		return
	}

	var response control.LocalResponse
	switch request.Method {
	case control.LocalObserve:
		response = controller.observeResponse()
	case control.LocalMutate:
		response = controller.mutateResponse(request)
	default:
		response = localFailure("unsupported_method", "local request method is unsupported")
	}
	controller.writeResponse(connection, response)
}

func (controller *Controller) observeResponse() control.LocalResponse {
	state, err := controller.runtime.State.Load()
	if err != nil {
		return localFailure("state_unavailable", "authoritative state could not be loaded")
	}
	controller.recordObservation(context.Background(), state)
	controller.observation.RLock()
	state = controller.lastState
	observation := controller.lastObserve
	controller.observation.RUnlock()
	data, err := json.Marshal(struct {
		Role        model.Role  `json:"role"`
		Observation Observation `json:"observation"`
	}{Role: state.Host.Role, Observation: observation})
	if err != nil {
		return localFailure("internal", "controller could not encode observation")
	}
	return control.LocalResponse{SchemaVersion: control.LocalSchemaVersion, OK: true, Generation: state.Generation, Data: data}
}

func (controller *Controller) mutateResponse(request control.LocalRequest) control.LocalResponse {
	if controller.runtime.Dispatcher == nil || !localOperationPattern.MatchString(request.Operation) {
		return localFailure("unsupported_operation", "local mutation operation is unsupported")
	}
	controller.mutationMu.Lock()
	defer controller.mutationMu.Unlock()

	state, err := controller.runtime.State.Load()
	if err != nil {
		return localFailure("state_unavailable", "authoritative state could not be loaded")
	}
	if request.ExpectedGeneration != 0 && request.ExpectedGeneration != state.Generation {
		return localFailureWithGeneration("generation_conflict", "authoritative state generation changed", state.Generation)
	}
	if dispatcher, ok := controller.runtime.Dispatcher.(PreparedMutationDispatcher); ok {
		return controller.applyPreparedMutation(state, request, dispatcher)
	}
	candidate, data, err := controller.runtime.Dispatcher.Dispatch(context.Background(), state, request.Operation, append(json.RawMessage(nil), request.Payload...))
	if err != nil {
		return localFailureWithGeneration("mutation_failed", "local mutation was rejected", state.Generation)
	}
	if err := controller.runtime.State.Save(state.Generation, candidate); err != nil {
		if errors.Is(err, store.ErrStateConflict) {
			return localFailureWithGeneration("generation_conflict", ErrControllerGeneration.Error(), state.Generation)
		}
		return localFailureWithGeneration("state_write_failed", "authoritative state could not be committed", state.Generation)
	}
	controller.recordObservation(context.Background(), candidate)
	if len(data) == 0 {
		data = json.RawMessage(`{}`)
	}
	return control.LocalResponse{SchemaVersion: control.LocalSchemaVersion, OK: true, Generation: candidate.Generation, Data: data}
}

func (controller *Controller) applyPreparedMutation(state model.State, request control.LocalRequest, dispatcher PreparedMutationDispatcher) control.LocalResponse {
	prepared, err := dispatcher.Prepare(context.Background(), state, request.Operation, append(json.RawMessage(nil), request.Payload...))
	if err != nil {
		return localFailureWithGeneration("mutation_failed", "local mutation was rejected", state.Generation)
	}
	if len(prepared.Data) == 0 {
		prepared.Data = json.RawMessage(`{}`)
	}
	if !prepared.Changed {
		return control.LocalResponse{SchemaVersion: control.LocalSchemaVersion, OK: true, Generation: state.Generation, Data: prepared.Data}
	}
	if prepared.Apply == nil || prepared.Rollback == nil {
		return localFailureWithGeneration("mutation_failed", "local mutation was rejected", state.Generation)
	}
	applyContext, cancelApply := context.WithTimeout(context.Background(), control.LocalTimeout)
	err = prepared.Apply(applyContext)
	cancelApply()
	if err != nil {
		return localFailureWithGeneration("runtime_apply_failed", "operation runtime could not be activated", state.Generation)
	}
	if err := controller.runtime.State.Save(state.Generation, prepared.Candidate); err != nil {
		observed, loadErr := controller.runtime.State.Load()
		if loadErr == nil && reflect.DeepEqual(observed, prepared.Candidate) {
			controller.recordObservation(context.Background(), observed)
			return localFailureWithGeneration("state_write_failed", "authoritative state activation completed without a durable success acknowledgement", observed.Generation)
		}
		if loadErr != nil || !reflect.DeepEqual(observed, state) {
			return localFailureWithGeneration("rollback_failed", "authoritative state outcome is ambiguous; runtime was left on the prepared candidate", state.Generation)
		}
		rollbackContext, cancelRollback := context.WithTimeout(context.Background(), control.LocalTimeout)
		rollbackErr := prepared.Rollback(rollbackContext)
		cancelRollback()
		if rollbackErr != nil {
			return localFailureWithGeneration("rollback_failed", "runtime rollback failed after authoritative state write failure", state.Generation)
		}
		if errors.Is(err, store.ErrStateConflict) {
			return localFailureWithGeneration("generation_conflict", ErrControllerGeneration.Error(), state.Generation)
		}
		return localFailureWithGeneration("state_write_failed", "authoritative state could not be committed", state.Generation)
	}
	controller.recordObservation(context.Background(), prepared.Candidate)
	return control.LocalResponse{SchemaVersion: control.LocalSchemaVersion, OK: true, Generation: prepared.Candidate.Generation, Data: prepared.Data}
}

func (controller *Controller) recordObservation(ctx context.Context, state model.State) {
	observed, err := controller.runtime.Observer.Observe(ctx, state)
	if observed.ObservedAt.IsZero() {
		observed.ObservedAt = controller.runtime.Now().UTC()
	}
	if observed.Units == nil {
		observed.Units = []UnitObservation{}
	}
	if observed.Issues == nil {
		observed.Issues = []string{}
	}
	if err != nil {
		observed.Issues = append(observed.Issues, "observation_failed")
	}
	controller.observation.Lock()
	if state.Generation >= controller.lastState.Generation {
		controller.lastState = state
		controller.lastObserve = observed
	}
	controller.observation.Unlock()
}

func (controller *Controller) listen() (*net.UnixListener, os.FileInfo, error) {
	if err := controller.validateRuntimeDirectory(); err != nil {
		return nil, nil, err
	}
	path := controller.runtime.Paths.ControlSocket
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
			return nil, nil, fmt.Errorf("%w: %s", ErrControllerRuntimeConflict, path)
		}
		if err := os.Remove(path); err != nil {
			return nil, nil, fmt.Errorf("remove stale controller socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, fmt.Errorf("listen on controller socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, nil, fmt.Errorf("set controller socket permissions: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, nil, fmt.Errorf("controller socket did not reach mode 0600")
	}
	return listener, info, nil
}

func (controller *Controller) validateRuntimeDirectory() error {
	runtimeInfo, err := os.Lstat(controller.runtime.Paths.RuntimeDir)
	if err != nil || runtimeInfo.Mode()&os.ModeSymlink != 0 || !runtimeInfo.IsDir() || runtimeInfo.Mode().Perm() != 0o700 {
		return fmt.Errorf("controller runtime directory must be a real mode-0700 directory")
	}
	return nil
}

func (controller *Controller) acquireWriterLock() (*os.File, error) {
	path := controller.runtime.Paths.StateLock
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: %s", ErrControllerRuntimeConflict, path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	descriptor, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open controller writer lock: %w", err)
	}
	lock := os.NewFile(uintptr(descriptor), path)
	keep := false
	defer func() {
		if !keep {
			_ = lock.Close()
		}
	}()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("controller writer lock must be a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%w: controller writer lock is not mode 0600", ErrControllerRuntimeConflict)
	}
	if err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrControllerAlreadyRunning
		}
		return nil, fmt.Errorf("lock authoritative gateway writer: %w", err)
	}
	keep = true
	return lock, nil
}

func (controller *Controller) removeOwnedSocket(owned os.FileInfo) {
	current, err := os.Lstat(controller.runtime.Paths.ControlSocket)
	if err == nil && current.Mode()&os.ModeSocket != 0 && os.SameFile(owned, current) {
		_ = os.Remove(controller.runtime.Paths.ControlSocket)
		if directory, openErr := os.Open(filepath.Dir(controller.runtime.Paths.ControlSocket)); openErr == nil {
			_ = directory.Sync()
			_ = directory.Close()
		}
	}
}

func (controller *Controller) writeResponse(connection *net.UnixConn, response control.LocalResponse) {
	_ = connection.SetWriteDeadline(time.Now().Add(control.LocalTimeout))
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > control.LocalMaximumBytes {
		encoded, _ = json.Marshal(localFailure("internal", "controller could not encode response"))
	}
	_, _ = connection.Write(append(encoded, '\n'))
}

func localFailure(code, message string) control.LocalResponse {
	return localFailureWithGeneration(code, message, 0)
}

func localFailureWithGeneration(code, message string, generation uint64) control.LocalResponse {
	return control.LocalResponse{SchemaVersion: control.LocalSchemaVersion, OK: false, Generation: generation, ErrorCode: code, Message: message}
}
