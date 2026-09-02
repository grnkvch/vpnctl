package store

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestStateStoreKeepsExactlyOnePreviousGeneration(t *testing.T) {
	t.Parallel()

	store, paths := newTestStateStore(t)
	first := testState(1)
	if err := store.Save(0, first); err != nil {
		t.Fatalf("Save(initial) error = %v", err)
	}
	assertStoredState(t, store.Load, first)
	if _, err := store.LoadPrevious(); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("LoadPrevious(initial) error = %v", err)
	}
	assertFileMode(t, paths.StateFile, StateFileMode)

	second := testState(2)
	if err := store.Save(1, second); err != nil {
		t.Fatalf("Save(second) error = %v", err)
	}
	assertStoredState(t, store.Load, second)
	assertStoredState(t, store.LoadPrevious, first)
	assertFileMode(t, paths.PreviousStateFile, StateFileMode)

	third := testState(3)
	if err := store.Save(2, third); err != nil {
		t.Fatalf("Save(third) error = %v", err)
	}
	assertStoredState(t, store.Load, third)
	assertStoredState(t, store.LoadPrevious, second)

	matches, err := filepath.Glob(filepath.Join(paths.StateDir, "state.previous*"))
	if err != nil {
		t.Fatalf("Glob(previous) error = %v", err)
	}
	if len(matches) != 1 || matches[0] != paths.PreviousStateFile {
		t.Fatalf("previous state files = %v", matches)
	}
}

func TestStateStoreRejectsInvalidOrConflictingWritesBeforeActivation(t *testing.T) {
	t.Parallel()

	store, paths := newTestStateStore(t)
	invalidInitial := testState(2)
	if err := store.Save(0, invalidInitial); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("Save(generation 2 initial) error = %v", err)
	}
	if _, err := os.Stat(paths.StateFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file after refused init: %v", err)
	}

	first := testState(1)
	if err := store.Save(0, first); err != nil {
		t.Fatalf("Save(initial) error = %v", err)
	}
	if err := store.Save(0, testState(2)); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("Save(reinitialize) error = %v", err)
	}
	if err := store.Save(9, testState(2)); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("Save(stale expected generation) error = %v", err)
	}

	replacedHost := testState(2)
	replacedHost.Host.ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if err := store.Save(1, replacedHost); !errors.Is(err, model.ErrInvalidTransition) {
		t.Fatalf("Save(replaced host) error = %v", err)
	}
	assertStoredState(t, store.Load, first)
	if _, err := store.LoadPrevious(); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("LoadPrevious(after rejected writes) error = %v", err)
	}
}

func TestStateStoreRefusesInitializationOverRecoveryEvidence(t *testing.T) {
	t.Parallel()

	store, paths := newTestStateStore(t)
	encoded, err := model.EncodeState(testState(1))
	if err != nil {
		t.Fatalf("EncodeState() error = %v", err)
	}
	if err := os.WriteFile(paths.PreviousStateFile, encoded, StateFileMode); err != nil {
		t.Fatalf("write previous state: %v", err)
	}
	if err := store.Save(0, testState(1)); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("Save(initial with previous present) error = %v", err)
	}
	if _, err := os.Stat(paths.StateFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file after refused init: %v", err)
	}
	assertStoredState(t, store.LoadPrevious, testState(1))
}

func TestStateStoreFaultCheckpointsLeaveOldOrNewValidState(t *testing.T) {
	t.Parallel()

	injected := errors.New("injected write fault")
	tests := []struct {
		stage              writeStage
		currentGeneration  uint64
		previousGeneration uint64
	}{
		{stage: stageCandidateSynced, currentGeneration: 1},
		{stage: stagePreviousRenamed, currentGeneration: 1, previousGeneration: 1},
		{stage: stagePreviousDirectorySynced, currentGeneration: 1, previousGeneration: 1},
		{stage: stageStateRenamed, currentGeneration: 2, previousGeneration: 1},
		{stage: stageStateDirectorySynced, currentGeneration: 2, previousGeneration: 1},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.stage), func(t *testing.T) {
			t.Parallel()
			regular, paths := newTestStateStore(t)
			if err := regular.Save(0, testState(1)); err != nil {
				t.Fatalf("Save(initial) error = %v", err)
			}
			faulting, err := newStateStore(paths, func(stage writeStage) error {
				if stage == test.stage {
					return injected
				}
				return nil
			})
			if err != nil {
				t.Fatalf("newStateStore() error = %v", err)
			}
			if err := faulting.Save(1, testState(2)); !errors.Is(err, injected) {
				t.Fatalf("Save(fault at %s) error = %v", test.stage, err)
			}
			current, err := regular.Load()
			if err != nil || current.Generation != test.currentGeneration {
				t.Fatalf("Load() generation = %d, %v", current.Generation, err)
			}
			previous, err := regular.LoadPrevious()
			if test.previousGeneration == 0 {
				if !errors.Is(err, ErrStateNotFound) {
					t.Fatalf("LoadPrevious() error = %v", err)
				}
			} else if err != nil || previous.Generation != test.previousGeneration {
				t.Fatalf("LoadPrevious() generation = %d, %v", previous.Generation, err)
			}
			assertNoTemporaryStateFiles(t, paths.StateDir)
		})
	}
}

func TestStateStoreWriteStageOrder(t *testing.T) {
	t.Parallel()

	regular, paths := newTestStateStore(t)
	if err := regular.Save(0, testState(1)); err != nil {
		t.Fatalf("Save(initial) error = %v", err)
	}
	var stages []writeStage
	observed, err := newStateStore(paths, func(stage writeStage) error {
		stages = append(stages, stage)
		return nil
	})
	if err != nil {
		t.Fatalf("newStateStore() error = %v", err)
	}
	if err := observed.Save(1, testState(2)); err != nil {
		t.Fatalf("Save(second) error = %v", err)
	}
	want := []writeStage{
		stageCandidateSynced,
		stagePreviousRenamed,
		stagePreviousDirectorySynced,
		stageStateRenamed,
		stageStateDirectorySynced,
	}
	if !reflect.DeepEqual(stages, want) {
		t.Fatalf("write stages = %v, want %v", stages, want)
	}
}

func TestStateStoreSubprocessKillNeverExposesPartialState(t *testing.T) {
	if os.Getenv("VPNCTL_STATE_CRASH_HELPER") == "1" {
		runStateStoreCrashHelper()
		return
	}

	tests := []struct {
		stage              writeStage
		currentGeneration  uint64
		previousGeneration uint64
	}{
		{stage: stageCandidateSynced, currentGeneration: 1},
		{stage: stagePreviousRenamed, currentGeneration: 1, previousGeneration: 1},
		{stage: stagePreviousDirectorySynced, currentGeneration: 1, previousGeneration: 1},
		{stage: stageStateRenamed, currentGeneration: 2, previousGeneration: 1},
		{stage: stageStateDirectorySynced, currentGeneration: 2, previousGeneration: 1},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.stage), func(t *testing.T) {
			store, paths := newTestStateStore(t)
			if err := store.Save(0, testState(1)); err != nil {
				t.Fatalf("Save(initial) error = %v", err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestStateStoreSubprocessKillNeverExposesPartialState$")
			command.Env = append(os.Environ(),
				"VPNCTL_STATE_CRASH_HELPER=1",
				"VPNCTL_STATE_CRASH_ROOT="+paths.Root,
				"VPNCTL_STATE_CRASH_STAGE="+string(test.stage),
			)
			err := command.Run()
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) || exitError.ExitCode() != 97 {
				t.Fatalf("crash helper error = %v", err)
			}

			current, err := store.Load()
			if err != nil || current.Generation != test.currentGeneration {
				t.Fatalf("Load() after kill generation = %d, %v", current.Generation, err)
			}
			previous, err := store.LoadPrevious()
			if test.previousGeneration == 0 {
				if !errors.Is(err, ErrStateNotFound) {
					t.Fatalf("LoadPrevious() after kill error = %v", err)
				}
			} else if err != nil || previous.Generation != test.previousGeneration {
				t.Fatalf("LoadPrevious() after kill generation = %d, %v", previous.Generation, err)
			}
		})
	}
}

func TestStateStoreCorruptCurrentDoesNotHidePrevious(t *testing.T) {
	t.Parallel()

	store, paths := newTestStateStore(t)
	if err := store.Save(0, testState(1)); err != nil {
		t.Fatalf("Save(initial) error = %v", err)
	}
	if err := store.Save(1, testState(2)); err != nil {
		t.Fatalf("Save(second) error = %v", err)
	}
	if err := os.WriteFile(paths.StateFile, []byte("{\"schema_version\":"), StateFileMode); err != nil {
		t.Fatalf("write corrupt current state: %v", err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "decode state") {
		t.Fatalf("Load(corrupt current) error = %v", err)
	}
	previous, err := store.LoadPrevious()
	if err != nil || previous.Generation != 1 {
		t.Fatalf("LoadPrevious() generation = %d, %v", previous.Generation, err)
	}
}

func TestStateStoreIgnoresUnactivatedTemporaryFile(t *testing.T) {
	t.Parallel()

	store, paths := newTestStateStore(t)
	state := testState(1)
	if err := store.Save(0, state); err != nil {
		t.Fatalf("Save(initial) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(paths.StateDir, ".state.json.partial.tmp"), []byte("partial"), StateFileMode); err != nil {
		t.Fatalf("write partial temporary: %v", err)
	}
	assertStoredState(t, store.Load, state)
}

func TestStateStoreRejectsNonRegularStateAndDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	paths, err := NewPaths(root)
	if err != nil {
		t.Fatalf("NewPaths() error = %v", err)
	}
	store, err := NewStateStore(paths)
	if err != nil {
		t.Fatalf("NewStateStore() error = %v", err)
	}
	if err := store.Save(0, testState(1)); err == nil || !strings.Contains(err.Error(), "state directory") {
		t.Fatalf("Save(missing directory) error = %v", err)
	}

	realDirectory := filepath.Join(root, "real-state")
	if err := os.MkdirAll(realDirectory, 0o700); err != nil {
		t.Fatalf("MkdirAll(real state): %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.StateDir), 0o700); err != nil {
		t.Fatalf("MkdirAll(state parent): %v", err)
	}
	if err := os.Symlink(realDirectory, paths.StateDir); err != nil {
		t.Fatalf("Symlink(state directory): %v", err)
	}
	if err := store.Save(0, testState(1)); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("Save(symlink directory) error = %v", err)
	}
}

func TestNewStateStoreRejectsUnsafeLayout(t *testing.T) {
	t.Parallel()

	paths, err := NewPaths(t.TempDir())
	if err != nil {
		t.Fatalf("NewPaths() error = %v", err)
	}
	paths.StateFile = filepath.Join(paths.StateDir, "nested", "state.json")
	if _, err := NewStateStore(paths); err == nil {
		t.Fatal("NewStateStore(nested state path) error = nil")
	}
	paths, _ = NewPaths(t.TempDir())
	paths.PreviousStateFile = paths.StateFile
	if _, err := NewStateStore(paths); err == nil {
		t.Fatal("NewStateStore(equal paths) error = nil")
	}
}

func runStateStoreCrashHelper() {
	paths, err := NewPaths(os.Getenv("VPNCTL_STATE_CRASH_ROOT"))
	if err != nil {
		os.Exit(91)
	}
	target := writeStage(os.Getenv("VPNCTL_STATE_CRASH_STAGE"))
	store, err := newStateStore(paths, func(stage writeStage) error {
		if stage == target {
			os.Exit(97)
		}
		return nil
	})
	if err != nil {
		os.Exit(92)
	}
	current, err := store.Load()
	if err != nil {
		os.Exit(93)
	}
	current.Generation++
	if err := store.Save(current.Generation-1, current); err != nil {
		os.Exit(94)
	}
	os.Exit(95)
}

func newTestStateStore(t *testing.T) (*StateStore, Paths) {
	t.Helper()
	paths, err := NewPaths(t.TempDir())
	if err != nil {
		t.Fatalf("NewPaths() error = %v", err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(state directory): %v", err)
	}
	store, err := NewStateStore(paths)
	if err != nil {
		t.Fatalf("NewStateStore() error = %v", err)
	}
	return store, paths
}

func testState(generation uint64) model.State {
	initializedAt := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	return model.State{
		SchemaVersion: model.StateSchemaVersion,
		Generation:    generation,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion,
			ID:            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			Role:          model.RoleNode,
			OS:            "ubuntu",
			OSVersion:     "24.04",
			Architecture:  "amd64",
			InitializedAt: initializedAt,
		},
		Nodes:        []model.Node{},
		Clients:      []model.Client{},
		Presets:      []model.Preset{},
		Policies:     []model.Policy{},
		Transports:   []model.Transport{},
		Exposes:      []model.Expose{},
		Certificates: []model.Certificate{},
		Operations:   []model.Operation{},
		Logging:      []model.LoggingSession{},
		Backups:      []model.Backup{},
		Components: model.ComponentManifest{
			SchemaVersion:            model.ComponentManifestSchemaVersion,
			ManifestVersion:          1,
			VPNCTLVersion:            "v2.0.0-dev",
			ControlProtocols:         []string{"1.0"},
			StateSchemaMinimum:       model.StateSchemaVersion,
			StateSchemaMaximum:       model.StateSchemaVersion,
			TargetOS:                 "ubuntu 24.04",
			TargetArchitecture:       "amd64",
			HandshakeHostListVersion: 1,
			MigrationReversible:      true,
			Components: []model.ComponentPin{{
				Name:         "vpnctl",
				Version:      "v2.0.0-dev",
				Source:       "bundle:vpnctl",
				Bundled:      true,
				SHA256:       strings.Repeat("a", 64),
				Capabilities: []string{"cli", "controller"},
			}},
		},
	}
}

func assertStoredState(t *testing.T, load func() (model.State, error), want model.State) {
	t.Helper()
	got, err := load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stored state\nwant: %#v\n got: %#v", want, got)
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%s) = %o, want %o", path, got, want)
	}
}

func assertNoTemporaryStateFiles(t *testing.T, directory string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".state*.tmp"))
	if err != nil {
		t.Fatalf("Glob(temporary state): %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary state files remain: %v", matches)
	}
}

func ExampleStateStore_Save() {
	paths, _ := NewPaths("/tmp/vpnctl-example-root")
	store, _ := NewStateStore(paths)
	_ = store
	fmt.Println(paths.StateFile)
	// Output: /tmp/vpnctl-example-root/var/lib/vpnctl/state.json
}
