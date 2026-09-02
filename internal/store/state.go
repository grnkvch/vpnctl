package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	StateFileMode os.FileMode = 0o600
	MaxStateBytes             = 16 << 20
)

var (
	ErrStateNotFound = errors.New("vpnctl state not found")
	ErrStateConflict = errors.New("vpnctl state generation conflict")
)

type StateStore struct {
	paths Paths
	hook  func(writeStage) error
}

type writeStage string

const (
	stageCandidateSynced         writeStage = "candidate-synced"
	stagePreviousRenamed         writeStage = "previous-renamed"
	stagePreviousDirectorySynced writeStage = "previous-directory-synced"
	stageStateRenamed            writeStage = "state-renamed"
	stageStateDirectorySynced    writeStage = "state-directory-synced"
)

func NewStateStore(paths Paths) (*StateStore, error) {
	return newStateStore(paths, nil)
}

func newStateStore(paths Paths, hook func(writeStage) error) (*StateStore, error) {
	if !filepath.IsAbs(paths.StateDir) || !filepath.IsAbs(paths.StateFile) || !filepath.IsAbs(paths.PreviousStateFile) {
		return nil, fmt.Errorf("state store paths must be absolute")
	}
	if filepath.Clean(paths.StateDir) != paths.StateDir || filepath.Clean(paths.StateFile) != paths.StateFile || filepath.Clean(paths.PreviousStateFile) != paths.PreviousStateFile {
		return nil, fmt.Errorf("state store paths must be clean")
	}
	if filepath.Dir(paths.StateFile) != paths.StateDir || filepath.Dir(paths.PreviousStateFile) != paths.StateDir {
		return nil, fmt.Errorf("state and previous state files must be direct children of state directory")
	}
	if paths.StateFile == paths.PreviousStateFile {
		return nil, fmt.Errorf("state and previous state paths must differ")
	}
	return &StateStore{paths: paths, hook: hook}, nil
}

func (store *StateStore) Load() (model.State, error) {
	return store.load(store.paths.StateFile)
}

func (store *StateStore) LoadPrevious() (model.State, error) {
	return store.load(store.paths.PreviousStateFile)
}

func (store *StateStore) Save(expectedGeneration uint64, candidate model.State) error {
	encoded, err := model.EncodeState(candidate)
	if err != nil {
		return fmt.Errorf("encode candidate state: %w", err)
	}
	if len(encoded) > MaxStateBytes {
		return fmt.Errorf("candidate state exceeds %d bytes", MaxStateBytes)
	}
	if err := validateStateDirectory(store.paths.StateDir); err != nil {
		return err
	}

	currentData, current, err := store.loadData(store.paths.StateFile)
	switch {
	case errors.Is(err, ErrStateNotFound):
		if expectedGeneration != 0 {
			return fmt.Errorf("%w: expected %d but state is absent", ErrStateConflict, expectedGeneration)
		}
		if _, previousErr := os.Lstat(store.paths.PreviousStateFile); previousErr == nil {
			return fmt.Errorf("%w: current state is absent but previous state exists", ErrStateConflict)
		} else if !errors.Is(previousErr, os.ErrNotExist) {
			return fmt.Errorf("inspect previous state: %w", previousErr)
		}
		if candidate.Generation != 1 {
			return fmt.Errorf("%w: initial state generation must be 1", ErrStateConflict)
		}
		return store.activateInitial(encoded)
	case err != nil:
		return err
	}
	if expectedGeneration == 0 || current.Generation != expectedGeneration {
		return fmt.Errorf("%w: expected %d, current %d", ErrStateConflict, expectedGeneration, current.Generation)
	}
	if err := model.ValidateTransition(current, candidate); err != nil {
		return fmt.Errorf("validate state transition: %w", err)
	}
	return store.activateNext(currentData, encoded)
}

func (store *StateStore) activateInitial(candidate []byte) error {
	temporary, err := writeSyncedTemporary(store.paths.StateDir, ".state.json.", candidate)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := store.checkpoint(stageCandidateSynced); err != nil {
		return err
	}
	if err := os.Rename(temporary, store.paths.StateFile); err != nil {
		return fmt.Errorf("activate initial state: %w", err)
	}
	if err := store.checkpoint(stageStateRenamed); err != nil {
		return err
	}
	if err := syncDirectory(store.paths.StateDir); err != nil {
		return err
	}
	return store.checkpoint(stageStateDirectorySynced)
}

func (store *StateStore) activateNext(current, candidate []byte) error {
	candidateTemporary, err := writeSyncedTemporary(store.paths.StateDir, ".state.json.", candidate)
	if err != nil {
		return err
	}
	defer os.Remove(candidateTemporary)
	if err := store.checkpoint(stageCandidateSynced); err != nil {
		return err
	}

	previousTemporary, err := writeSyncedTemporary(store.paths.StateDir, ".state.previous.json.", current)
	if err != nil {
		return err
	}
	defer os.Remove(previousTemporary)
	if err := os.Rename(previousTemporary, store.paths.PreviousStateFile); err != nil {
		return fmt.Errorf("activate previous state: %w", err)
	}
	if err := store.checkpoint(stagePreviousRenamed); err != nil {
		return err
	}
	if err := syncDirectory(store.paths.StateDir); err != nil {
		return err
	}
	if err := store.checkpoint(stagePreviousDirectorySynced); err != nil {
		return err
	}

	if err := os.Rename(candidateTemporary, store.paths.StateFile); err != nil {
		return fmt.Errorf("activate candidate state: %w", err)
	}
	if err := store.checkpoint(stageStateRenamed); err != nil {
		return err
	}
	if err := syncDirectory(store.paths.StateDir); err != nil {
		return err
	}
	return store.checkpoint(stageStateDirectorySynced)
}

func (store *StateStore) load(path string) (model.State, error) {
	_, state, err := store.loadData(path)
	return state, err
}

func (store *StateStore) loadData(path string) ([]byte, model.State, error) {
	data, err := readBoundedRegularFile(path, MaxStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, model.State{}, fmt.Errorf("%w: %s", ErrStateNotFound, path)
	}
	if err != nil {
		return nil, model.State{}, fmt.Errorf("read state %s: %w", path, err)
	}
	state, err := model.DecodeState(data)
	if err != nil {
		return nil, model.State{}, fmt.Errorf("decode state %s: %w", path, err)
	}
	return data, state, nil
}

func (store *StateStore) checkpoint(stage writeStage) error {
	if store.hook == nil {
		return nil
	}
	if err := store.hook(stage); err != nil {
		return fmt.Errorf("state write checkpoint %s: %w", stage, err)
	}
	return nil
}

func validateStateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("state directory must be a real directory")
	}
	return nil
}

func writeSyncedTemporary(directory, pattern string, data []byte) (string, error) {
	file, err := os.CreateTemp(directory, pattern+"*.tmp")
	if err != nil {
		return "", fmt.Errorf("create state temporary file: %w", err)
	}
	path := file.Name()
	closed := false
	keep := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(StateFileMode); err != nil {
		return "", fmt.Errorf("set state temporary mode: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return "", fmt.Errorf("write state temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync state temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close state temporary file: %w", err)
	}
	closed = true
	keep = true
	return path, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open state directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("must be a regular file")
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("exceeds %d bytes", maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("exceeds %d bytes", maximum)
	}
	return data, nil
}
