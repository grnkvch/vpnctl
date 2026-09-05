package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrConvergenceSnapshotConflict         = errors.New("convergence snapshot compare-and-swap conflict")
	ErrConvergenceSnapshotOutcomeUncertain = errors.New("convergence snapshot publication outcome is uncertain")
)

type convergenceSnapshotWriteStage string

const (
	convergenceSnapshotCandidateSynced convergenceSnapshotWriteStage = "candidate-synced"
	convergenceSnapshotRenamed         convergenceSnapshotWriteStage = "snapshot-renamed"
	convergenceSnapshotDirectorySynced convergenceSnapshotWriteStage = "directory-synced"
)

// FileConvergenceSnapshotStore is the mutation-side companion to the
// read-only FileConvergenceSnapshotSource. Callers must provide the exact
// previously read snapshot for updates; a stale writer can never overwrite a
// newer baseline. The planner itself receives only the source interface.
type FileConvergenceSnapshotStore struct {
	path     string
	lockPath string
	source   *FileConvergenceSnapshotSource
	hook     func(convergenceSnapshotWriteStage) error
}

func NewFileConvergenceSnapshotStore(path string) (*FileConvergenceSnapshotStore, error) {
	return newFileConvergenceSnapshotStore(path, nil)
}

func newFileConvergenceSnapshotStore(
	path string,
	hook func(convergenceSnapshotWriteStage) error,
) (*FileConvergenceSnapshotStore, error) {
	source, err := NewFileConvergenceSnapshotSource(path)
	if err != nil {
		return nil, err
	}
	return &FileConvergenceSnapshotStore{
		path: path, lockPath: filepath.Join(filepath.Dir(path), "convergence.lock"), source: source, hook: hook,
	}, nil
}

// Initialize publishes the first baseline only when no snapshot exists.
func (store *FileConvergenceSnapshotStore) Initialize(ctx context.Context, candidate ConvergenceSnapshot) error {
	_, err := store.save(ctx, nil, candidate, false)
	return err
}

// EnsureInitialized is the idempotent post-commit form used by lifecycle
// recovery. It accepts an existing byte-logically equal baseline but still
// rejects every different snapshot.
func (store *FileConvergenceSnapshotStore) EnsureInitialized(ctx context.Context, candidate ConvergenceSnapshot) (bool, error) {
	return store.save(ctx, nil, candidate, true)
}

// CompareAndSwap publishes candidate only when the current canonical snapshot
// is byte-logically equal to expected. It returns false for an exact no-op.
func (store *FileConvergenceSnapshotStore) CompareAndSwap(
	ctx context.Context,
	expected ConvergenceSnapshot,
	candidate ConvergenceSnapshot,
) (bool, error) {
	canonicalExpected, err := canonicalSnapshot(expected)
	if err != nil {
		return false, fmt.Errorf("validate expected convergence snapshot: %w", err)
	}
	return store.save(ctx, &canonicalExpected, candidate, false)
}

func (store *FileConvergenceSnapshotStore) save(
	ctx context.Context,
	expected *ConvergenceSnapshot,
	candidate ConvergenceSnapshot,
	acceptExistingEqual bool,
) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("context is required")
	}
	if store == nil || store.source == nil || store.path == "" || store.lockPath == "" {
		return false, fmt.Errorf("convergence snapshot store is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	canonicalCandidate, err := canonicalSnapshot(candidate)
	if err != nil {
		return false, fmt.Errorf("validate candidate convergence snapshot: %w", err)
	}
	encoded, err := json.Marshal(canonicalCandidate)
	if err != nil {
		return false, fmt.Errorf("encode convergence snapshot: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaximumConvergenceSnapshotBytes {
		return false, fmt.Errorf("candidate convergence snapshot exceeds %d bytes", MaximumConvergenceSnapshotBytes)
	}
	defer clear(encoded)

	if err := validateConvergenceSnapshotDirectory(filepath.Dir(store.path)); err != nil {
		return false, err
	}
	lock, err := store.acquireLock(ctx)
	if err != nil {
		return false, err
	}
	defer func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		_ = lock.Close()
	}()
	if err := ctx.Err(); err != nil {
		return false, err
	}

	current, readErr := store.source.ReadConvergenceSnapshot(ctx)
	switch {
	case expected == nil && errors.Is(readErr, ErrConvergenceSnapshotUnavailable):
	case expected == nil && readErr == nil && acceptExistingEqual && reflect.DeepEqual(current, canonicalCandidate):
		return false, nil
	case expected == nil && readErr == nil:
		return false, fmt.Errorf("%w: snapshot already exists", ErrConvergenceSnapshotConflict)
	case expected == nil:
		return false, readErr
	case readErr != nil:
		if errors.Is(readErr, ErrConvergenceSnapshotUnavailable) {
			return false, fmt.Errorf("%w: snapshot is absent", ErrConvergenceSnapshotConflict)
		}
		return false, readErr
	case !reflect.DeepEqual(current, *expected):
		return false, fmt.Errorf("%w: current snapshot differs from expected", ErrConvergenceSnapshotConflict)
	case reflect.DeepEqual(current, canonicalCandidate):
		return false, nil
	}

	return store.publish(ctx, encoded)
}

func (store *FileConvergenceSnapshotStore) acquireLock(ctx context.Context) (*os.File, error) {
	descriptor, err := unix.Open(store.lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open convergence snapshot lock: %w", err)
	}
	lock := os.NewFile(uintptr(descriptor), store.lockPath)
	keep := false
	defer func() {
		if !keep {
			_ = lock.Close()
		}
	}()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("convergence snapshot lock must be a 0600 regular file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return nil, fmt.Errorf("convergence snapshot lock must have exactly one filesystem link")
	}
	for {
		err = unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("lock convergence snapshot writer: %w", err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	keep = true
	return lock, nil
}

func (store *FileConvergenceSnapshotStore) publish(ctx context.Context, encoded []byte) (bool, error) {
	directory := filepath.Dir(store.path)
	temporary, err := os.CreateTemp(directory, ".convergence.json.*.tmp")
	if err != nil {
		return false, fmt.Errorf("create convergence snapshot candidate: %w", err)
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return false, fmt.Errorf("restrict convergence snapshot candidate: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		return false, fmt.Errorf("write convergence snapshot candidate: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return false, fmt.Errorf("sync convergence snapshot candidate: %w", err)
	}
	if err := temporary.Close(); err != nil {
		closed = true
		return false, fmt.Errorf("close convergence snapshot candidate: %w", err)
	}
	closed = true
	if err := store.checkpoint(convergenceSnapshotCandidateSynced); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return false, fmt.Errorf("activate convergence snapshot: %w", err)
	}
	if err := store.checkpoint(convergenceSnapshotRenamed); err != nil {
		return true, fmt.Errorf("%w: %v", ErrConvergenceSnapshotOutcomeUncertain, err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return true, fmt.Errorf("%w: open convergence snapshot directory: %v", ErrConvergenceSnapshotOutcomeUncertain, err)
	}
	syncErr := directoryHandle.Sync()
	closeErr := directoryHandle.Close()
	if syncErr != nil || closeErr != nil {
		return true, fmt.Errorf("%w: sync convergence snapshot directory: %v", ErrConvergenceSnapshotOutcomeUncertain, errors.Join(syncErr, closeErr))
	}
	if err := store.checkpoint(convergenceSnapshotDirectorySynced); err != nil {
		return true, fmt.Errorf("%w: %v", ErrConvergenceSnapshotOutcomeUncertain, err)
	}
	return true, nil
}

func (store *FileConvergenceSnapshotStore) checkpoint(stage convergenceSnapshotWriteStage) error {
	if store.hook == nil {
		return nil
	}
	if err := store.hook(stage); err != nil {
		return fmt.Errorf("convergence snapshot write checkpoint %s: %w", stage, err)
	}
	return nil
}

func validateConvergenceSnapshotDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect convergence snapshot directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("convergence snapshot directory must be a 0700 real directory")
	}
	return nil
}
