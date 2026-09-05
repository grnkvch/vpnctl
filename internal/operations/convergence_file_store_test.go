package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFileConvergenceSnapshotStoreInitializesCanonicalRootOnlySnapshot(t *testing.T) {
	t.Parallel()

	path := newConvergenceSnapshotStorePath(t)
	store, err := NewFileConvergenceSnapshotStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first := convergenceFileStoreSnapshot(t, 4, "first")
	if err := store.Initialize(context.Background(), reverseConvergenceFileStoreSnapshot(first)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot info = %+v, %v", info, err)
	}
	lockInfo, err := os.Lstat(filepath.Join(filepath.Dir(path), "convergence.lock"))
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("lock info = %+v, %v", lockInfo, err)
	}
	source, _ := NewFileConvergenceSnapshotSource(path)
	loaded, err := source.ReadConvergenceSnapshot(context.Background())
	if err != nil || !reflect.DeepEqual(loaded, first) {
		t.Fatalf("loaded snapshot = %+v, %v", loaded, err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(first)
	want = append(want, '\n')
	if !bytes.Equal(encoded, want) {
		t.Fatalf("snapshot bytes are not canonical\ngot:  %s\nwant: %s", encoded, want)
	}
}

func TestFileConvergenceSnapshotStoreCASRejectsStaleAndPreservesNoOp(t *testing.T) {
	t.Parallel()

	path := newConvergenceSnapshotStorePath(t)
	store, _ := NewFileConvergenceSnapshotStore(path)
	first := convergenceFileStoreSnapshot(t, 1, "first")
	second := convergenceFileStoreSnapshot(t, 2, "second")
	stale := convergenceFileStoreSnapshot(t, 1, "stale")
	if err := store.Initialize(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if changed, err := store.CompareAndSwap(context.Background(), stale, second); changed || !errors.Is(err, ErrConvergenceSnapshotConflict) {
		t.Fatalf("stale CAS = %t, %v", changed, err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("stale CAS changed the snapshot")
	}
	if changed, err := store.CompareAndSwap(context.Background(), first, first); err != nil || changed {
		t.Fatalf("no-op CAS = %t, %v", changed, err)
	}
	if changed, err := store.CompareAndSwap(context.Background(), first, second); err != nil || !changed {
		t.Fatalf("update CAS = %t, %v", changed, err)
	}
	if err := store.Initialize(context.Background(), second); !errors.Is(err, ErrConvergenceSnapshotConflict) {
		t.Fatalf("duplicate initialize error = %v", err)
	}
}

func TestFileConvergenceSnapshotStoreSerializesCompetingCAS(t *testing.T) {
	t.Parallel()

	path := newConvergenceSnapshotStorePath(t)
	store, _ := NewFileConvergenceSnapshotStore(path)
	first := convergenceFileStoreSnapshot(t, 1, "first")
	if err := store.Initialize(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	candidates := []ConvergenceSnapshot{
		convergenceFileStoreSnapshot(t, 2, "second-a"),
		convergenceFileStoreSnapshot(t, 2, "second-b"),
	}
	start := make(chan struct{})
	type outcome struct {
		changed bool
		err     error
	}
	outcomes := make(chan outcome, len(candidates))
	var ready sync.WaitGroup
	ready.Add(len(candidates))
	for _, candidate := range candidates {
		candidate := candidate
		go func() {
			ready.Done()
			<-start
			changed, err := store.CompareAndSwap(context.Background(), first, candidate)
			outcomes <- outcome{changed: changed, err: err}
		}()
	}
	ready.Wait()
	close(start)
	successes, conflicts := 0, 0
	for range candidates {
		result := <-outcomes
		switch {
		case result.changed && result.err == nil:
			successes++
		case !result.changed && errors.Is(result.err, ErrConvergenceSnapshotConflict):
			conflicts++
		default:
			t.Fatalf("competing CAS outcome = %+v", result)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("competing CAS successes/conflicts = %d/%d", successes, conflicts)
	}
}

func TestFileConvergenceSnapshotStoreReportsPostRenameUncertainOutcome(t *testing.T) {
	t.Parallel()

	path := newConvergenceSnapshotStorePath(t)
	want := convergenceFileStoreSnapshot(t, 3, "published")
	store, err := newFileConvergenceSnapshotStore(path, func(stage convergenceSnapshotWriteStage) error {
		if stage == convergenceSnapshotRenamed {
			return errors.New("simulated directory durability failure")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Initialize(context.Background(), want); !errors.Is(err, ErrConvergenceSnapshotOutcomeUncertain) {
		t.Fatalf("uncertain initialize error = %v", err)
	}
	source, _ := NewFileConvergenceSnapshotSource(path)
	got, err := source.ReadConvergenceSnapshot(context.Background())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("post-rename snapshot = %+v, %v", got, err)
	}
}

func TestFileConvergenceSnapshotStoreRejectsUnsafeDirectoryAndLock(t *testing.T) {
	t.Parallel()

	snapshot := convergenceFileStoreSnapshot(t, 1, "first")
	t.Run("directory mode", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		store, _ := NewFileConvergenceSnapshotStore(filepath.Join(directory, "convergence.json"))
		if err := store.Initialize(context.Background(), snapshot); err == nil {
			t.Fatal("unsafe directory mode was accepted")
		}
	})
	for _, test := range []struct {
		name    string
		prepare func(*testing.T, string)
	}{
		{name: "symlink", prepare: func(t *testing.T, directory string) {
			victim := filepath.Join(directory, "victim")
			if err := os.WriteFile(victim, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, filepath.Join(directory, "convergence.lock")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink", prepare: func(t *testing.T, directory string) {
			victim := filepath.Join(directory, "victim")
			if err := os.WriteFile(victim, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(victim, filepath.Join(directory, "convergence.lock")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := newConvergenceSnapshotStorePath(t)
			test.prepare(t, filepath.Dir(path))
			store, _ := NewFileConvergenceSnapshotStore(path)
			if err := store.Initialize(context.Background(), snapshot); err == nil {
				t.Fatal("unsafe lock was accepted")
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe lock created snapshot: %v", err)
			}
		})
	}
}

func TestFileConvergenceSnapshotStoreHonorsCancellationBeforeMutation(t *testing.T) {
	t.Parallel()

	path := newConvergenceSnapshotStorePath(t)
	store, _ := NewFileConvergenceSnapshotStore(path)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Initialize(ctx, convergenceFileStoreSnapshot(t, 1, "first")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled initialize error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(path), "convergence.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled initialize created lock: %v", err)
	}
}

func TestFileConvergenceSnapshotStoreHonorsCancellationWhileLockIsContended(t *testing.T) {
	t.Parallel()

	path := newConvergenceSnapshotStorePath(t)
	store, _ := NewFileConvergenceSnapshotStore(path)
	first := convergenceFileStoreSnapshot(t, 1, "first")
	if err := store.Initialize(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(filepath.Dir(path), "convergence.lock")
	descriptor, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(descriptor)
	if err := unix.Flock(descriptor, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(descriptor, unix.LOCK_UN)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(25*time.Millisecond, cancel)
	changed, err := store.CompareAndSwap(ctx, first, convergenceFileStoreSnapshot(t, 2, "second"))
	if changed || !errors.Is(err, context.Canceled) {
		t.Fatalf("contended cancelled CAS = %t, %v", changed, err)
	}
	source, _ := NewFileConvergenceSnapshotSource(path)
	got, err := source.ReadConvergenceSnapshot(context.Background())
	if err != nil || !reflect.DeepEqual(got, first) {
		t.Fatalf("cancelled contended snapshot = %+v, %v", got, err)
	}
}

func newConvergenceSnapshotStorePath(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "convergence.json")
}

func convergenceFileStoreSnapshot(t *testing.T, generation uint64, material string) ConvergenceSnapshot {
	t.Helper()
	resources := []ManagedResource{
		resource(ManagedResourceKey{Component: "routing", Kind: ManagedResourceFile, ID: "/etc/vpnctl/generated/node/routing.yaml"}, material+"-routing", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
		resource(ManagedResourceKey{Component: "transport", Kind: ManagedResourceFile, ID: "/etc/vpnctl/generated/node/standard.conf"}, material+"-transport", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	}
	manifest, err := NewConvergenceManifest(generation, resources)
	if err != nil {
		t.Fatal(err)
	}
	return ConvergenceSnapshot{Desired: cloneManifest(manifest), Applied: cloneManifest(manifest), Pending: []PendingOperation{}}
}

func reverseConvergenceFileStoreSnapshot(snapshot ConvergenceSnapshot) ConvergenceSnapshot {
	snapshot.Desired = cloneManifest(snapshot.Desired)
	snapshot.Applied = cloneManifest(snapshot.Applied)
	snapshot.Pending = append([]PendingOperation{}, snapshot.Pending...)
	snapshot.Desired.Resources[0], snapshot.Desired.Resources[1] = snapshot.Desired.Resources[1], snapshot.Desired.Resources[0]
	snapshot.Applied.Resources[0], snapshot.Applied.Resources[1] = snapshot.Applied.Resources[1], snapshot.Applied.Resources[0]
	return snapshot
}
