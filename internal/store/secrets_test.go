package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestSecretStorePutGetReplaceDelete(t *testing.T) {
	t.Parallel()

	store, paths := newTestSecretStore(t)
	reference := mustSecretRef(t, "control-key:gateway")
	first := []byte("first-private-material")
	if err := store.Put(reference, first); err != nil {
		t.Fatalf("Put(first) error = %v", err)
	}
	got, err := store.Get(reference)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("Get(first) = %q, %v", got, err)
	}
	kindPath := filepath.Join(paths.SecretsDir, "control-key")
	secretPath := filepath.Join(kindPath, "gateway")
	assertFileMode(t, paths.SecretsDir, SecretDirectoryMode)
	assertFileMode(t, kindPath, SecretDirectoryMode)
	assertFileMode(t, secretPath, SecretFileMode)

	second := []byte("second-private-material")
	if err := store.Put(reference, second); err != nil {
		t.Fatalf("Put(second) error = %v", err)
	}
	got, err = store.Get(reference)
	if err != nil || !bytes.Equal(got, second) {
		t.Fatalf("Get(second) = %q, %v", got, err)
	}
	if bytes.Contains(got, first) {
		t.Fatal("atomic replacement retained bytes from the old secret")
	}

	deleted, err := store.Delete(reference)
	if err != nil || !deleted {
		t.Fatalf("Delete() = %t, %v", deleted, err)
	}
	deleted, err = store.Delete(reference)
	if err != nil || deleted {
		t.Fatalf("idempotent Delete() = %t, %v", deleted, err)
	}
	if _, err := store.Get(reference); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get(deleted) error = %v", err)
	}
}

func TestSecretStorePutIfAbsentNeverReplacesOrTears(t *testing.T) {
	t.Parallel()

	secretStore, _ := newTestSecretStore(t)
	reference := mustSecretRef(t, "control-key:gateway")
	const writers = 16
	start := make(chan struct{})
	results := make(chan struct {
		value []byte
		err   error
	}, writers)
	var group sync.WaitGroup
	for index := 0; index < writers; index++ {
		value := bytes.Repeat([]byte{byte(index + 1)}, 4096)
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- struct {
				value []byte
				err   error
			}{value: value, err: secretStore.PutIfAbsent(reference, value)}
		}()
	}
	close(start)
	group.Wait()
	close(results)
	winners := 0
	var winner []byte
	for result := range results {
		if result.err == nil {
			winners++
			winner = result.value
			continue
		}
		if !errors.Is(result.err, ErrSecretExists) {
			t.Fatalf("PutIfAbsent() error = %v", result.err)
		}
	}
	if winners != 1 {
		t.Fatalf("PutIfAbsent() winners = %d, want 1", winners)
	}
	stored, err := secretStore.Get(reference)
	if err != nil || !bytes.Equal(stored, winner) {
		t.Fatalf("stored winner = %d bytes, %v", len(stored), err)
	}
	if err := secretStore.PutIfAbsent(reference, []byte("replacement")); !errors.Is(err, ErrSecretExists) {
		t.Fatalf("PutIfAbsent(existing) error = %v", err)
	}
	stored, _ = secretStore.Get(reference)
	if !bytes.Equal(stored, winner) {
		t.Fatal("PutIfAbsent(existing) replaced the identity")
	}
}

func TestSecretStoreRejectsInvalidValuesAndReferences(t *testing.T) {
	t.Parallel()

	store, _ := newTestSecretStore(t)
	valid := mustSecretRef(t, "token:node")
	if err := store.Put(valid, nil); err == nil {
		t.Fatal("Put(empty) error = nil")
	}
	if err := store.Put(valid, make([]byte, MaxSecretBytes+1)); err == nil {
		t.Fatal("Put(oversized) error = nil")
	}
	if err := store.Put(model.SecretRef("../escape:value"), []byte("secret")); err == nil {
		t.Fatal("Put(path traversal reference) error = nil")
	}
	if _, err := store.Get(model.SecretRef("invalid")); err == nil {
		t.Fatal("Get(invalid reference) error = nil")
	}
}

func TestSecretStoreRejectsSymlinkComponents(t *testing.T) {
	t.Parallel()

	t.Run("root", func(t *testing.T) {
		store, paths := newTestSecretStore(t)
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.Mkdir(victim, 0o700); err != nil {
			t.Fatalf("Mkdir(victim): %v", err)
		}
		if err := os.Symlink(victim, paths.SecretsDir); err != nil {
			t.Fatalf("Symlink(secrets): %v", err)
		}
		err := store.Put(mustSecretRef(t, "token:node"), []byte("canary"))
		if !errors.Is(err, ErrUnsafeSecretPath) {
			t.Fatalf("Put(root symlink) error = %v", err)
		}
		entries, _ := os.ReadDir(victim)
		if len(entries) != 0 {
			t.Fatalf("root symlink target was modified: %v", entries)
		}
	})

	t.Run("kind", func(t *testing.T) {
		store, paths := newTestSecretStore(t)
		if err := store.Put(mustSecretRef(t, "seed-kind:value"), []byte("seed")); err != nil {
			t.Fatalf("Put(seed) error = %v", err)
		}
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.Mkdir(victim, 0o700); err != nil {
			t.Fatalf("Mkdir(victim): %v", err)
		}
		if err := os.Symlink(victim, filepath.Join(paths.SecretsDir, "token")); err != nil {
			t.Fatalf("Symlink(kind): %v", err)
		}
		err := store.Put(mustSecretRef(t, "token:node"), []byte("canary"))
		if !errors.Is(err, ErrUnsafeSecretPath) {
			t.Fatalf("Put(kind symlink) error = %v", err)
		}
		entries, _ := os.ReadDir(victim)
		if len(entries) != 0 {
			t.Fatalf("kind symlink target was modified: %v", entries)
		}
	})

	t.Run("secret", func(t *testing.T) {
		store, paths := newTestSecretStore(t)
		reference := mustSecretRef(t, "token:node")
		seed := mustSecretRef(t, "token:seed")
		if err := store.Put(seed, []byte("seed")); err != nil {
			t.Fatalf("Put(seed) error = %v", err)
		}
		victimPath := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victimPath, []byte("victim-content"), 0o600); err != nil {
			t.Fatalf("WriteFile(victim): %v", err)
		}
		secretPath := filepath.Join(paths.SecretsDir, "token", "node")
		if err := os.Symlink(victimPath, secretPath); err != nil {
			t.Fatalf("Symlink(secret): %v", err)
		}
		if err := store.Put(reference, []byte("replacement")); !errors.Is(err, ErrUnsafeSecretPath) {
			t.Fatalf("Put(secret symlink) error = %v", err)
		}
		if _, err := store.Get(reference); !errors.Is(err, ErrUnsafeSecretPath) {
			t.Fatalf("Get(secret symlink) error = %v", err)
		}
		if _, err := store.Delete(reference); !errors.Is(err, ErrUnsafeSecretPath) {
			t.Fatalf("Delete(secret symlink) error = %v", err)
		}
		victim, err := os.ReadFile(victimPath)
		if err != nil || string(victim) != "victim-content" {
			t.Fatalf("symlink victim = %q, %v", victim, err)
		}
	})
}

func TestSecretStorePermissionDiagnosticsAndRepair(t *testing.T) {
	t.Parallel()

	store, paths := newTestSecretStore(t)
	reference := mustSecretRef(t, "control-key:gateway")
	secret := []byte("private-material")
	if err := store.Put(reference, secret); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	kindPath := filepath.Join(paths.SecretsDir, "control-key")
	secretPath := filepath.Join(kindPath, "gateway")
	for path, mode := range map[string]os.FileMode{
		paths.SecretsDir: 0o755,
		kindPath:         0o750,
		secretPath:       0o644,
	} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("Chmod(%s): %v", path, err)
		}
	}
	if _, err := store.Get(reference); !errors.Is(err, ErrSecretPermissions) {
		t.Fatalf("Get(permissive root) error = %v", err)
	}
	issues, err := store.DiagnosePermissions()
	if err != nil {
		t.Fatalf("DiagnosePermissions() error = %v", err)
	}
	wantPaths := []string{".", "control-key", "control-key/gateway"}
	gotPaths := make([]string, len(issues))
	for index, issue := range issues {
		gotPaths[index] = issue.RelativePath
		if !issue.Repairable {
			t.Fatalf("mode issue is not repairable: %#v", issue)
		}
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("permission issue paths = %v, want %v", gotPaths, wantPaths)
	}
	repaired, err := store.RepairPermissions()
	if err != nil || !reflect.DeepEqual(repaired, issues) {
		t.Fatalf("RepairPermissions() = %#v, %v", repaired, err)
	}
	remaining, err := store.DiagnosePermissions()
	if err != nil || len(remaining) != 0 {
		t.Fatalf("DiagnosePermissions(after repair) = %#v, %v", remaining, err)
	}
	got, err := store.Get(reference)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Get(after repair) = %q, %v", got, err)
	}
}

func TestPermissionRepairDoesNotTouchTreeWithUnsafeEntry(t *testing.T) {
	t.Parallel()

	store, paths := newTestSecretStore(t)
	if err := store.Put(mustSecretRef(t, "token:seed"), []byte("seed")); err != nil {
		t.Fatalf("Put(seed) error = %v", err)
	}
	if err := os.Chmod(paths.SecretsDir, 0o755); err != nil {
		t.Fatalf("Chmod(secrets root): %v", err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatalf("WriteFile(victim): %v", err)
	}
	if err := os.Symlink(victim, filepath.Join(paths.SecretsDir, "token", "unsafe")); err != nil {
		t.Fatalf("Symlink(unsafe secret): %v", err)
	}
	issues, err := store.RepairPermissions()
	if !errors.Is(err, ErrUnsafeSecretPath) || len(issues) != 2 {
		t.Fatalf("RepairPermissions(unsafe tree) = %#v, %v", issues, err)
	}
	assertFileMode(t, paths.SecretsDir, 0o755)
	victimData, _ := os.ReadFile(victim)
	if string(victimData) != "victim" {
		t.Fatalf("unsafe repair modified symlink victim: %q", victimData)
	}
}

func TestSecretStoreConcurrentReplacementIsNeverTorn(t *testing.T) {
	t.Parallel()

	store, _ := newTestSecretStore(t)
	reference := mustSecretRef(t, "tunnel-token:node")
	const writers = 32
	values := make([][]byte, writers)
	start := make(chan struct{})
	errorsChannel := make(chan error, writers)
	var group sync.WaitGroup
	for index := 0; index < writers; index++ {
		values[index] = bytes.Repeat([]byte{byte(index + 1)}, 64<<10)
		group.Add(1)
		go func(value []byte) {
			defer group.Done()
			<-start
			errorsChannel <- store.Put(reference, value)
		}(values[index])
	}
	close(start)
	group.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent Put() error = %v", err)
		}
	}
	got, err := store.Get(reference)
	if err != nil {
		t.Fatalf("Get(after concurrent Put) error = %v", err)
	}
	matched := false
	for _, value := range values {
		if bytes.Equal(got, value) {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("concurrent secret is torn: length=%d", len(got))
	}
}

func newTestSecretStore(t *testing.T) (*SecretStore, Paths) {
	t.Helper()
	paths, err := NewPaths(t.TempDir())
	if err != nil {
		t.Fatalf("NewPaths() error = %v", err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(state directory): %v", err)
	}
	store, err := NewSecretStore(paths)
	if err != nil {
		t.Fatalf("NewSecretStore() error = %v", err)
	}
	return store, paths
}

func mustSecretRef(t *testing.T, value string) model.SecretRef {
	t.Helper()
	reference, err := model.ParseSecretRef(value)
	if err != nil {
		t.Fatalf("ParseSecretRef(%q): %v", value, err)
	}
	return reference
}
