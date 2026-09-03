package controller

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestControllerSerializesConcurrentLocalMutations(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	dispatcher := &serialMutationDispatcher{}
	observer := &recordingObserver{}
	server, err := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: observer, Dispatcher: dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(ctx) }()
	waitForControllerSocket(t, paths.ControlSocket, serveErrors)

	runtimeInfo, err := os.Stat(paths.RuntimeDir)
	if err != nil || runtimeInfo.Mode().Perm() != 0o700 {
		t.Fatalf("runtime directory = %v, %v", runtimeInfo, err)
	}
	socketInfo, err := os.Lstat(paths.ControlSocket)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0o600 {
		t.Fatalf("control socket = %v, %v", socketInfo, err)
	}
	lockInfo, err := os.Lstat(paths.StateLock)
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("writer lock = %v, %v", lockInfo, err)
	}

	const mutations = 12
	responses := make(chan control.LocalResponse, mutations)
	errorsSeen := make(chan error, mutations)
	var callers sync.WaitGroup
	for index := 0; index < mutations; index++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			response, err := control.CallLocal(context.Background(), paths.ControlSocket, control.LocalRequest{
				SchemaVersion: control.LocalSchemaVersion,
				Method:        control.LocalMutate,
				Operation:     "test.advance",
				Payload:       json.RawMessage(`{"enabled":true}`),
			})
			if err != nil {
				errorsSeen <- err
				return
			}
			responses <- response
		}()
	}
	callers.Wait()
	close(errorsSeen)
	close(responses)
	for err := range errorsSeen {
		t.Errorf("CallLocal() error = %v", err)
	}
	for response := range responses {
		if !response.OK {
			t.Errorf("mutation response = %+v", response)
		}
	}
	if dispatcher.maximumActive != 1 || dispatcher.calls != mutations {
		t.Fatalf("dispatcher concurrency/calls = %d/%d, want 1/%d", dispatcher.maximumActive, dispatcher.calls, mutations)
	}
	state, err := stateStore.Load()
	if err != nil || state.Generation != 1+mutations {
		t.Fatalf("final state generation = %d, %v", state.Generation, err)
	}

	competing, _ := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: observer})
	if err := competing.Serve(context.Background()); !errors.Is(err, ErrControllerAlreadyRunning) {
		t.Fatalf("second controller Serve() error = %v", err)
	}
	cancel()
	if err := <-serveErrors; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if _, err := os.Lstat(paths.ControlSocket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remained after graceful stop: %v", err)
	}
}

func TestControllerRestartOnlyObservesDataPlane(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	dataPlane := &dataPlaneMock{active: true}

	for restart := 0; restart < 2; restart++ {
		server, err := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: dataPlane})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		serveErrors := make(chan error, 1)
		go func() { serveErrors <- server.Serve(ctx) }()
		waitForControllerSocket(t, paths.ControlSocket, serveErrors)
		response, err := control.CallLocal(context.Background(), paths.ControlSocket, control.LocalRequest{
			SchemaVersion: control.LocalSchemaVersion,
			Method:        control.LocalObserve,
		})
		if err != nil || !response.OK || response.Generation != 1 {
			t.Fatalf("observe after start %d = %+v, %v", restart, response, err)
		}
		cancel()
		if err := <-serveErrors; err != nil {
			t.Fatalf("Serve() restart %d error = %v", restart, err)
		}
		if !dataPlane.active || dataPlane.starts != 0 || dataPlane.stops != 0 || dataPlane.restarts != 0 {
			t.Fatalf("data plane changed across restart %d: %+v", restart, dataPlane)
		}
	}
	if dataPlane.observations < 4 {
		t.Fatalf("passive observations = %d, want at least 4", dataPlane.observations)
	}
	state, err := stateStore.Load()
	if err != nil || state.Generation != 1 {
		t.Fatalf("controller restart changed authoritative state: generation=%d error=%v", state.Generation, err)
	}
}

func TestControllerPreparedMutationAppliesBeforeStateAndRollsBackOnWriteFailure(t *testing.T) {
	paths, persisted := controllerTestState(t, model.RoleGateway)
	state, err := persisted.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name           string
		failSave       bool
		commitThenFail bool
		wantOK         bool
		wantCode       string
	}{
		{name: "commit", wantOK: true},
		{name: "rollback", failSave: true, wantCode: "state_write_failed"},
		{name: "committed without durable acknowledgement", failSave: true, commitThenFail: true, wantCode: "state_write_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateStore := &preparedMutationStateStore{state: state, failSave: test.failSave, commitThenFail: test.commitThenFail}
			dispatcher := &preparedTestDispatcher{}
			server, err := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: &recordingObserver{}, Dispatcher: dispatcher})
			if err != nil {
				t.Fatal(err)
			}
			response := server.mutateResponse(control.LocalRequest{
				SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate, Operation: "dns.set",
				ExpectedGeneration: state.Generation, Payload: json.RawMessage(`{"ipv4":["9.9.9.9"]}`),
			})
			if response.OK != test.wantOK || response.ErrorCode != test.wantCode {
				t.Fatalf("prepared response = %+v", response)
			}
			if dispatcher.applies != 1 {
				t.Fatalf("apply calls = %d", dispatcher.applies)
			}
			wantRollbacks := 0
			if test.failSave && !test.commitThenFail {
				wantRollbacks = 1
			}
			if dispatcher.rollbacks != wantRollbacks {
				t.Fatalf("rollback calls = %d, want %d", dispatcher.rollbacks, wantRollbacks)
			}
			if test.failSave && !test.commitThenFail && stateStore.state.Generation != state.Generation {
				t.Fatal("failed state write changed authoritative state")
			}
		})
	}
}

func TestControllerGracefulStopWaitsForAcceptedMutation(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	dispatcher := &blockingMutationDispatcher{started: make(chan struct{}), release: make(chan struct{})}
	server, _ := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: &recordingObserver{}, Dispatcher: dispatcher})
	ctx, cancel := context.WithCancel(context.Background())
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(ctx) }()
	waitForControllerSocket(t, paths.ControlSocket, serveErrors)
	responses := make(chan control.LocalResponse, 1)
	callErrors := make(chan error, 1)
	go func() {
		response, err := control.CallLocal(context.Background(), paths.ControlSocket, control.LocalRequest{
			SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate, Operation: "test.block",
		})
		responses <- response
		callErrors <- err
	}()
	select {
	case <-dispatcher.started:
	case <-time.After(2 * time.Second):
		t.Fatal("mutation was not accepted")
	}
	cancel()
	select {
	case err := <-serveErrors:
		t.Fatalf("Serve() returned before accepted mutation completed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(dispatcher.release)
	if err := <-callErrors; err != nil {
		t.Fatalf("CallLocal() error = %v", err)
	}
	if response := <-responses; !response.OK || response.Generation != 2 {
		t.Fatalf("mutation response = %+v", response)
	}
	if err := <-serveErrors; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	state, _ := stateStore.Load()
	if state.Generation != 2 {
		t.Fatalf("accepted mutation was not committed: generation=%d", state.Generation)
	}
}

func TestControllerRefusesForeignSocketAndLockResources(t *testing.T) {
	for _, target := range []string{"socket", "lock"} {
		t.Run(target, func(t *testing.T) {
			paths, stateStore := controllerTestState(t, model.RoleGateway)
			path := paths.ControlSocket
			if target == "lock" {
				path = paths.StateLock
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			server, _ := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: &recordingObserver{}})
			if err := server.Serve(context.Background()); !errors.Is(err, ErrControllerRuntimeConflict) {
				t.Fatalf("Serve() error = %v", err)
			}
			if info, err := os.Stat(path); err != nil || !info.IsDir() {
				t.Fatalf("foreign resource changed: %v, %v", info, err)
			}
		})
	}
}

func TestControllerRefusesUnsafeRuntimeAndLockModesWithoutAdoption(t *testing.T) {
	t.Run("runtime", func(t *testing.T) {
		paths, stateStore := controllerTestState(t, model.RoleGateway)
		if err := os.Chmod(paths.RuntimeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		server, _ := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: &recordingObserver{}})
		if err := server.Serve(context.Background()); err == nil {
			t.Fatal("Serve() accepted non-private runtime directory")
		}
		if _, err := os.Lstat(paths.StateLock); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unsafe runtime caused lock mutation: %v", err)
		}
	})

	t.Run("lock", func(t *testing.T) {
		paths, stateStore := controllerTestState(t, model.RoleGateway)
		if err := os.WriteFile(paths.StateLock, []byte("foreign"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(paths.StateLock, 0o644); err != nil {
			t.Fatal(err)
		}
		server, _ := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: &recordingObserver{}})
		if err := server.Serve(context.Background()); !errors.Is(err, ErrControllerRuntimeConflict) {
			t.Fatalf("Serve() error = %v", err)
		}
		info, err := os.Stat(paths.StateLock)
		content, readErr := os.ReadFile(paths.StateLock)
		if err != nil || readErr != nil || info.Mode().Perm() != 0o644 || string(content) != "foreign" {
			t.Fatalf("foreign lock was adopted: info=%v content=%q errors=%v/%v", info, content, err, readErr)
		}
	})
}

func TestControllerRequiresGatewayState(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleNode)
	server, _ := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: &recordingObserver{}})
	if err := server.Serve(context.Background()); err == nil || !strings.Contains(err.Error(), "requires gateway state") {
		t.Fatalf("Serve(node state) error = %v", err)
	}
}

func TestControllerPathsStayInsideSelectedRoot(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	paths.ControlSocket = filepath.Join(t.TempDir(), "control.sock")
	if _, err := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: &recordingObserver{}}); err == nil {
		t.Fatal("NewController() accepted mismatched paths")
	}
}

func controllerTestState(t *testing.T, role model.Role) (store.Paths, *store.StateStore) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "vpnctl-controller-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{paths.StateDir, paths.RuntimeDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	host := model.Host{
		SchemaVersion: model.ResourceSchemaVersion,
		ID:            "10000000-0000-4000-8000-000000000001",
		Role:          role,
		OS:            "ubuntu", OSVersion: "24.04", Architecture: "amd64",
		InitializedAt: time.Date(2026, time.September, 2, 10, 0, 0, 0, time.UTC),
	}
	if role == model.RoleGateway {
		host.PublicIPv4 = "203.0.113.10"
		host.ExternalInterface = "eth0"
		host.SSHPort = 22
		host.ClientCIDR = "10.66.0.0/24"
		host.NodeCIDR = "10.67.0.0/24"
	}
	state := model.State{
		SchemaVersion: model.StateSchemaVersion,
		Generation:    1,
		Host:          host,
		Nodes:         []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports: []model.Transport{}, Exposes: []model.Expose{}, Certificates: []model.Certificate{},
		Operations: []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{}, Invites: []model.Invite{},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0-dev",
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: 1, StateSchemaMaximum: 1,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1,
			MigrationReversible: true,
			Components:          []model.ComponentPin{{Name: "vpnctl", Version: "v2.0.0-dev", Source: "bundle:vpnctl", Bundled: true, SHA256: strings.Repeat("1", 64), Capabilities: []string{"cli", "controller"}}},
		},
	}
	if err := stateStore.Save(0, state); err != nil {
		t.Fatal(err)
	}
	return paths, stateStore
}

func waitForControllerSocket(t *testing.T, path string, serveErrors <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-serveErrors:
			t.Fatalf("controller exited before creating socket: %v", err)
		default:
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o600 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("controller socket %s did not appear", path)
}

type recordingObserver struct {
	mu    sync.Mutex
	calls int
}

func (observer *recordingObserver) Observe(context.Context, model.State) (Observation, error) {
	observer.mu.Lock()
	observer.calls++
	observer.mu.Unlock()
	return Observation{Units: []UnitObservation{}, Issues: []string{}}, nil
}

type serialMutationDispatcher struct {
	mu            sync.Mutex
	active        int
	maximumActive int
	calls         int
}

func (dispatcher *serialMutationDispatcher) Dispatch(_ context.Context, state model.State, _ string, _ json.RawMessage) (model.State, json.RawMessage, error) {
	dispatcher.mu.Lock()
	dispatcher.active++
	dispatcher.calls++
	if dispatcher.active > dispatcher.maximumActive {
		dispatcher.maximumActive = dispatcher.active
	}
	dispatcher.mu.Unlock()
	time.Sleep(5 * time.Millisecond)
	state.Generation++
	if state.Host.SSHPort == 22 {
		state.Host.SSHPort = 2222
	} else {
		state.Host.SSHPort = 22
	}
	dispatcher.mu.Lock()
	dispatcher.active--
	dispatcher.mu.Unlock()
	return state, json.RawMessage(`{"committed":true}`), nil
}

type blockingMutationDispatcher struct {
	started chan struct{}
	release chan struct{}
}

type preparedMutationStateStore struct {
	state          model.State
	failSave       bool
	commitThenFail bool
}

func (stateStore *preparedMutationStateStore) Load() (model.State, error) {
	return stateStore.state, nil
}

func (stateStore *preparedMutationStateStore) Save(expected uint64, candidate model.State) error {
	if stateStore.failSave {
		if stateStore.commitThenFail {
			stateStore.state = candidate
		}
		return errors.New("injected state write failure")
	}
	if expected != stateStore.state.Generation {
		return store.ErrStateConflict
	}
	stateStore.state = candidate
	return nil
}

type preparedTestDispatcher struct {
	applies   int
	rollbacks int
}

func (*preparedTestDispatcher) Dispatch(context.Context, model.State, string, json.RawMessage) (model.State, json.RawMessage, error) {
	return model.State{}, nil, errors.New("legacy dispatch must not be used")
}

func (dispatcher *preparedTestDispatcher) Prepare(_ context.Context, state model.State, _ string, _ json.RawMessage) (PreparedMutation, error) {
	state.Generation++
	if state.Host.SSHPort == 22 {
		state.Host.SSHPort = 2222
	} else {
		state.Host.SSHPort = 22
	}
	return PreparedMutation{
		Candidate: state, Changed: true, Data: json.RawMessage(`{"changed":true}`),
		Apply: func(context.Context) error {
			dispatcher.applies++
			return nil
		},
		Rollback: func(context.Context) error {
			dispatcher.rollbacks++
			return nil
		},
	}, nil
}

func (dispatcher *blockingMutationDispatcher) Dispatch(_ context.Context, state model.State, _ string, _ json.RawMessage) (model.State, json.RawMessage, error) {
	close(dispatcher.started)
	<-dispatcher.release
	state.Generation++
	state.Host.SSHPort = 2222
	return state, json.RawMessage(`{}`), nil
}

type dataPlaneMock struct {
	active       bool
	starts       int
	stops        int
	restarts     int
	observations int
}

func (dataPlane *dataPlaneMock) Observe(context.Context, model.State) (Observation, error) {
	dataPlane.observations++
	active := "inactive"
	if dataPlane.active {
		active = "active"
	}
	return Observation{Units: []UnitObservation{{Name: "mock-data-plane.service", LoadState: "loaded", ActiveState: active, SubState: "running"}}, Issues: []string{}}, nil
}
