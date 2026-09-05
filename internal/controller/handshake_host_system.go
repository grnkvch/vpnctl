package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"golang.org/x/sys/unix"
)

const (
	handshakeHostActivationLockName = "handshake-host-activation.lock"
	handshakeHostStagePrefix        = ".handshake-host-stage-"
	handshakeHostRuntimeTimeout     = 20 * time.Second
	handshakeHostHealthRetry        = 100 * time.Millisecond
	handshakeHostMaximumFileBytes   = 2 << 20
)

var (
	ErrHandshakeHostRuntimeConflict = errors.New("handshake-host runtime activation conflicts with another operation")
	ErrHandshakeHostRuntimeDrift    = errors.New("handshake-host live listener differs from authoritative state")
)

type SystemGatewayHandshakeHostRuntime struct {
	paths   store.Paths
	state   *store.StateStore
	secrets *store.SecretStore
	runner  linuxplatform.ProbeRunner
}

func NewSystemGatewayHandshakeHostRuntime(paths store.Paths, state *store.StateStore, secrets *store.SecretStore) (*SystemGatewayHandshakeHostRuntime, error) {
	return newSystemGatewayHandshakeHostRuntime(paths, state, secrets, linuxplatform.OSProbeRunner{})
}

func newSystemGatewayHandshakeHostRuntime(
	paths store.Paths,
	state *store.StateStore,
	secrets *store.SecretStore,
	runner linuxplatform.ProbeRunner,
) (*SystemGatewayHandshakeHostRuntime, error) {
	canonical, err := store.NewPaths(paths.Root)
	if err != nil || paths != canonical {
		return nil, fmt.Errorf("handshake-host runtime paths are invalid")
	}
	if state == nil || secrets == nil || runner == nil {
		return nil, fmt.Errorf("handshake-host runtime dependencies are incomplete")
	}
	return &SystemGatewayHandshakeHostRuntime{paths: paths, state: state, secrets: secrets, runner: runner}, nil
}

func (runtime *SystemGatewayHandshakeHostRuntime) Prepare(ctx context.Context, candidate model.State) (_ transport.HandshakeHostGatewayActivation, returnErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if runtime == nil || runtime.state == nil || runtime.secrets == nil || runtime.runner == nil {
		return nil, fmt.Errorf("handshake-host runtime is incomplete")
	}
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("handshake-host runtime candidate must be valid gateway state: %w", err)
	}
	if candidate.Host.Role != model.RoleGateway || candidate.HandshakeHost == nil {
		return nil, fmt.Errorf("handshake-host runtime candidate must be initialized gateway state")
	}
	if err := validateHandshakeHostRuntimeDirectories(runtime.paths); err != nil {
		return nil, err
	}
	lockContext, cancelLock := context.WithTimeout(ctx, handshakeHostRuntimeTimeout)
	lock, err := acquireHandshakeHostActivationLock(lockContext, runtime.paths)
	cancelLock()
	if err != nil {
		return nil, err
	}
	stageRoot := ""
	keep := false
	defer func() {
		if keep {
			return
		}
		returnErr = errors.Join(returnErr, cleanupHandshakeHostStage(runtime.paths, stageRoot))
		releaseHandshakeHostActivationLock(lock)
	}()

	if err := rejectRetainedHandshakeHostStages(runtime.paths); err != nil {
		return nil, err
	}
	current, err := runtime.state.Load()
	if err != nil {
		return nil, fmt.Errorf("load current handshake-host runtime state: %w", err)
	}
	if err := current.Validate(); err != nil || current.Host.Role != model.RoleGateway || current.HandshakeHost == nil {
		return nil, fmt.Errorf("current handshake-host runtime state is invalid")
	}
	if candidate.Generation != current.Generation+1 || candidate.HandshakeHost.Hostname == current.HandshakeHost.Hostname {
		return nil, fmt.Errorf("%w: candidate does not advance the current handshake-host generation", ErrHandshakeHostRuntimeConflict)
	}

	previous, err := renderRestrictedRuntimePublication(current, runtime.secrets)
	if err != nil {
		return nil, fmt.Errorf("render current restricted listener: %w", err)
	}
	next, err := renderRestrictedRuntimePublication(candidate, runtime.secrets)
	if err != nil {
		return nil, fmt.Errorf("render candidate restricted listener: %w", err)
	}
	if bytes.Equal(previous[0].content, next[0].content) {
		return nil, fmt.Errorf("%w: candidate restricted listener is unchanged", ErrHandshakeHostRuntimeConflict)
	}
	if err := verifyRestrictedRuntimePublication(runtime.paths, previous); err != nil {
		return nil, err
	}

	stageRoot, err = stageRestrictedRuntimePublication(runtime.paths, previous, next)
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(stageRoot, "candidate-"+transport.RestrictedConfigFileName)
	validationContext, cancelValidation := context.WithTimeout(ctx, handshakeHostRuntimeTimeout)
	err = transport.ValidatePinnedMihomoConfig(
		validationContext,
		runtime.runner,
		filepath.Join(runtime.paths.Root, transport.RestrictedBinaryRelativePath),
		filepath.Join(runtime.paths.StateDir, transport.RestrictedStateRelativePath),
		configPath,
	)
	cancelValidation()
	if err != nil {
		return nil, fmt.Errorf("validate staged restricted listener: %w", err)
	}
	if err := verifyStagedRestrictedRuntimePublication(stageRoot, next, "candidate-"); err != nil {
		return nil, err
	}
	if err := verifyRestrictedRuntimePublication(runtime.paths, previous); err != nil {
		return nil, fmt.Errorf("%w: live listener changed during candidate validation: %v", ErrHandshakeHostRuntimeDrift, err)
	}

	activation := &systemGatewayHandshakeHostActivation{
		paths: runtime.paths, runner: runtime.runner, lock: lock, stageRoot: stageRoot,
		previous: previous, candidate: next,
	}
	keep = true
	return activation, nil
}

type restrictedRuntimeFile struct {
	name    string
	content []byte
}

func renderRestrictedRuntimePublication(state model.State, secrets *store.SecretStore) ([2]restrictedRuntimeFile, error) {
	var result [2]restrictedRuntimeFile
	artifact, err := transport.RenderGatewayRestrictedConfig(transport.GatewayRestrictedRenderRequest{
		State: state, CredentialRef: transport.GatewayRestrictedCredentialRef, Credentials: secrets,
	})
	if err != nil {
		return result, err
	}
	result[0] = restrictedRuntimeFile{name: transport.RestrictedConfigFileName, content: artifact.Bytes()}
	result[1] = restrictedRuntimeFile{name: transport.GatewayRestrictedReadyFileName, content: artifact.ReadyMarker()}
	return result, nil
}

type systemGatewayHandshakeHostActivation struct {
	mu        sync.Mutex
	paths     store.Paths
	runner    linuxplatform.ProbeRunner
	lock      *os.File
	stageRoot string
	previous  [2]restrictedRuntimeFile
	candidate [2]restrictedRuntimeFile
	activated bool
	finished  bool
}

func (activation *systemGatewayHandshakeHostActivation) Activate() error {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validatePending(); err != nil {
		return err
	}
	if err := verifyRestrictedRuntimePublication(activation.paths, activation.previous); err != nil {
		return err
	}
	for index, file := range activation.candidate {
		staged := filepath.Join(activation.stageRoot, "candidate-"+file.name)
		live := restrictedRuntimeLivePath(activation.paths, file.name)
		if err := os.Rename(staged, live); err != nil {
			return fmt.Errorf("publish candidate restricted runtime file %s: %w", file.name, err)
		}
		if index == 0 {
			activation.activated = true
		}
	}
	if err := syncHandshakeHostDirectory(restrictedRuntimeRoot(activation.paths)); err != nil {
		return err
	}
	if err := verifyRestrictedRuntimePublication(activation.paths, activation.candidate); err != nil {
		return err
	}
	if err := restartAndObserveRestrictedListener(activation.runner); err != nil {
		return err
	}
	return nil
}

func (activation *systemGatewayHandshakeHostActivation) Commit() error {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validatePending(); err != nil {
		return err
	}
	if !activation.activated {
		return fmt.Errorf("candidate restricted listener was not activated")
	}
	err := cleanupHandshakeHostStage(activation.paths, activation.stageRoot)
	activation.finish()
	if err != nil {
		return fmt.Errorf("discard previous restricted listener generation: %w", err)
	}
	return nil
}

func (activation *systemGatewayHandshakeHostActivation) Rollback() error {
	activation.mu.Lock()
	defer activation.mu.Unlock()
	if err := activation.validatePending(); err != nil {
		return err
	}
	if !activation.activated {
		err := cleanupHandshakeHostStage(activation.paths, activation.stageRoot)
		activation.finish()
		return err
	}
	var restoreErr error
	for _, file := range activation.previous {
		staged := filepath.Join(activation.stageRoot, "previous-"+file.name)
		live := restrictedRuntimeLivePath(activation.paths, file.name)
		if err := os.Rename(staged, live); err != nil {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("restore previous restricted runtime file %s: %w", file.name, err))
		}
	}
	if restoreErr == nil {
		restoreErr = syncHandshakeHostDirectory(restrictedRuntimeRoot(activation.paths))
	}
	if restoreErr == nil {
		restoreErr = verifyRestrictedRuntimePublication(activation.paths, activation.previous)
	}
	if restoreErr == nil {
		restoreErr = restartAndObserveRestrictedListener(activation.runner)
	}
	if restoreErr == nil {
		restoreErr = cleanupHandshakeHostStage(activation.paths, activation.stageRoot)
	}
	activation.finish()
	return restoreErr
}

func (activation *systemGatewayHandshakeHostActivation) validatePending() error {
	if activation == nil || activation.runner == nil || activation.lock == nil || activation.stageRoot == "" {
		return fmt.Errorf("handshake-host activation is incomplete")
	}
	if activation.finished {
		return fmt.Errorf("handshake-host activation is already finalized")
	}
	return nil
}

func (activation *systemGatewayHandshakeHostActivation) finish() {
	activation.finished = true
	releaseHandshakeHostActivationLock(activation.lock)
	activation.lock = nil
}

func restrictedRuntimeRoot(paths store.Paths) string {
	return filepath.Join(paths.ConfigDir, "generated", string(model.RoleGateway))
}

func restrictedRuntimeLivePath(paths store.Paths, name string) string {
	return filepath.Join(restrictedRuntimeRoot(paths), name)
}

func validateHandshakeHostRuntimeDirectories(paths store.Paths) error {
	for _, path := range []string{paths.RuntimeDir, restrictedRuntimeRoot(paths), filepath.Join(paths.StateDir, transport.RestrictedStateRelativePath)} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("handshake-host runtime directory %s must be a private real directory", path)
		}
	}
	return nil
}

func acquireHandshakeHostActivationLock(ctx context.Context, paths store.Paths) (*os.File, error) {
	lockPath := filepath.Join(paths.RuntimeDir, handshakeHostActivationLockName)
	descriptor, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open handshake-host activation lock: %w", err)
	}
	lock := os.NewFile(uintptr(descriptor), lockPath)
	if lock == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("open handshake-host activation lock")
	}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 {
		_ = lock.Close()
		return nil, fmt.Errorf("handshake-host activation lock is unsafe")
	}
	for {
		err = unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = lock.Close()
			return nil, fmt.Errorf("lock handshake-host activation: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = lock.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func releaseHandshakeHostActivationLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}

func rejectRetainedHandshakeHostStages(paths store.Paths) error {
	entries, err := os.ReadDir(restrictedRuntimeRoot(paths))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), handshakeHostStagePrefix) {
			return fmt.Errorf("%w: retained stage %s requires repair", ErrHandshakeHostRuntimeConflict, entry.Name())
		}
	}
	return nil
}

func stageRestrictedRuntimePublication(paths store.Paths, previous, candidate [2]restrictedRuntimeFile) (stageRoot string, returnErr error) {
	stageRoot, err := os.MkdirTemp(restrictedRuntimeRoot(paths), handshakeHostStagePrefix)
	if err != nil {
		return "", fmt.Errorf("create handshake-host stage: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			returnErr = errors.Join(returnErr, cleanupHandshakeHostStage(paths, stageRoot))
		}
	}()
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		return "", err
	}
	if err := syncHandshakeHostDirectory(restrictedRuntimeRoot(paths)); err != nil {
		return "", err
	}
	for _, publication := range []struct {
		prefix string
		files  [2]restrictedRuntimeFile
	}{{prefix: "previous-", files: previous}, {prefix: "candidate-", files: candidate}} {
		for _, file := range publication.files {
			if err := writeHandshakeHostStageFile(filepath.Join(stageRoot, publication.prefix+file.name), file.content); err != nil {
				return "", err
			}
		}
	}
	if err := syncHandshakeHostDirectory(stageRoot); err != nil {
		return "", err
	}
	keep = true
	return stageRoot, nil
}

func writeHandshakeHostStageFile(path string, content []byte) error {
	if len(content) == 0 || len(content) > handshakeHostMaximumFileBytes {
		return fmt.Errorf("staged handshake-host file has invalid size")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}

func verifyRestrictedRuntimePublication(paths store.Paths, files [2]restrictedRuntimeFile) error {
	for _, file := range files {
		content, err := readHandshakeHostRuntimeFile(restrictedRuntimeLivePath(paths, file.name))
		if err != nil || !bytes.Equal(content, file.content) {
			return fmt.Errorf("%w: %s", ErrHandshakeHostRuntimeDrift, file.name)
		}
	}
	return nil
}

func verifyStagedRestrictedRuntimePublication(stageRoot string, files [2]restrictedRuntimeFile, prefix string) error {
	for _, file := range files {
		content, err := readHandshakeHostRuntimeFile(filepath.Join(stageRoot, prefix+file.name))
		if err != nil || !bytes.Equal(content, file.content) {
			return fmt.Errorf("%w: staged %s", ErrHandshakeHostRuntimeDrift, file.name)
		}
	}
	return nil
}

func readHandshakeHostRuntimeFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > handshakeHostMaximumFileBytes {
		return nil, fmt.Errorf("handshake-host runtime file %s is unsafe", path)
	}
	return os.ReadFile(path)
}

func cleanupHandshakeHostStage(paths store.Paths, stageRoot string) error {
	if stageRoot == "" {
		return nil
	}
	if filepath.Dir(stageRoot) != restrictedRuntimeRoot(paths) || !strings.HasPrefix(filepath.Base(stageRoot), handshakeHostStagePrefix) {
		return fmt.Errorf("refuse unsafe handshake-host stage cleanup %s", stageRoot)
	}
	info, err := os.Lstat(stageRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("handshake-host stage %s is unsafe", stageRoot)
	}
	if err := os.RemoveAll(stageRoot); err != nil {
		return err
	}
	return syncHandshakeHostDirectory(restrictedRuntimeRoot(paths))
}

func syncHandshakeHostDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func restartAndObserveRestrictedListener(runner linuxplatform.ProbeRunner) error {
	ctx, cancel := context.WithTimeout(context.Background(), handshakeHostRuntimeTimeout)
	defer cancel()
	result, err := runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"restart", "vpnctl-restricted.service"}})
	if err != nil || result.ExitCode != 0 {
		return fmt.Errorf("restart gateway restricted listener")
	}
	observer, err := transport.NewRestrictedGatewayHealthObserver(runner)
	if err != nil {
		return err
	}
	for {
		condition, code, observeErr := observer.ObserveListener(ctx)
		if observeErr != nil {
			return observeErr
		}
		if condition == transport.HealthHealthy {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("gateway restricted listener failed health gate: %s", code)
		case <-time.After(handshakeHostHealthRetry):
		}
	}
}

var _ transport.HandshakeHostGatewayRuntime = (*SystemGatewayHandshakeHostRuntime)(nil)
var _ transport.HandshakeHostGatewayActivation = (*systemGatewayHandshakeHostActivation)(nil)
