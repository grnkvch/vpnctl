package operations

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestWatchdogArmPersistsSnapshotBeforeStartingTimer(t *testing.T) {
	t.Parallel()

	paths := testWatchdogPaths(t)
	network := &fakeWatchdogNetwork{snapshot: testNetworkSnapshot()}
	supervisor := &fakeWatchdogSupervisor{}
	watchdog, err := NewWatchdog(paths, network, supervisor)
	if err != nil {
		t.Fatalf("NewWatchdog() error = %v", err)
	}
	preparedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	watchdog.clock = fixedWatchdogClock{now: preparedAt}
	watchdog.newID = func() (string, error) { return "12345678-1234-4234-8234-123456789abc", nil }
	supervisor.onStart = func(id string) error {
		if _, err := watchdog.store.Load(id); err != nil {
			return errors.New("snapshot was not durable before timer start")
		}
		return nil
	}

	transaction, err := watchdog.Arm(context.Background(), WatchdogArmInput{
		AllowedSSHPort: 2222,
		Origin: &linuxplatform.SSHConnection{
			ClientAddress: "198.51.100.20", ClientPort: 55000,
			ServerAddress: "203.0.113.10", ServerPort: 2222,
		},
		NetworkScope: linuxplatform.OwnedNetworkScope{Sysctls: []string{"net.ipv4.ip_forward"}},
	})
	if err != nil {
		t.Fatalf("Arm() error = %v", err)
	}
	if transaction.Deadline.Sub(transaction.PreparedAt) != 120*time.Second {
		t.Fatalf("watchdog duration = %s", transaction.Deadline.Sub(transaction.PreparedAt))
	}
	if !reflect.DeepEqual(supervisor.started, []string{transaction.ID}) {
		t.Fatalf("started timers = %v", supervisor.started)
	}
	if !reflect.DeepEqual(network.scopes, []linuxplatform.OwnedNetworkScope{{Sysctls: []string{"net.ipv4.ip_forward"}}}) {
		t.Fatalf("snapshot scopes = %+v", network.scopes)
	}

	directory := filepath.Join(paths.WatchdogDir, transaction.ID)
	assertWatchdogMode(t, directory, 0o700)
	assertWatchdogMode(t, filepath.Join(directory, watchdogSnapshotFile), 0o600)
	assertWatchdogMode(t, filepath.Join(directory, watchdogLockFile), 0o600)
	loaded, err := watchdog.store.Load(transaction.ID)
	if err != nil || !reflect.DeepEqual(loaded, transaction) {
		t.Fatalf("Load() = %+v, %v", loaded, err)
	}
}

func TestWatchdogArmNeverStartsTimerAfterSnapshotFailure(t *testing.T) {
	t.Parallel()

	paths := testWatchdogPaths(t)
	network := &fakeWatchdogNetwork{snapshotError: errors.New("injected snapshot failure")}
	supervisor := &fakeWatchdogSupervisor{}
	watchdog, _ := NewWatchdog(paths, network, supervisor)
	if _, err := watchdog.Arm(context.Background(), WatchdogArmInput{AllowedSSHPort: 22}); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("Arm() error = %v", err)
	}
	if len(supervisor.started) != 0 {
		t.Fatalf("timer started after snapshot failure: %v", supervisor.started)
	}
}

func TestWatchdogRollbackIsIdempotentAndStopsTimer(t *testing.T) {
	t.Parallel()

	paths := testWatchdogPaths(t)
	network := &fakeWatchdogNetwork{snapshot: testNetworkSnapshot()}
	supervisor := &fakeWatchdogSupervisor{}
	watchdog, _ := NewWatchdog(paths, network, supervisor)
	watchdog.clock = fixedWatchdogClock{now: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
	watchdog.newID = func() (string, error) { return "12345678-1234-4234-8234-123456789abd", nil }
	transaction, err := watchdog.Arm(context.Background(), WatchdogArmInput{AllowedSSHPort: 22})
	if err != nil {
		t.Fatalf("Arm() error = %v", err)
	}
	supervisor.onRollback = func(id string) error {
		return watchdog.store.Rollback(context.Background(), id, network, watchdog.clock.Now())
	}
	if err := watchdog.RollbackNow(context.Background(), transaction.ID); err != nil {
		t.Fatalf("RollbackNow() error = %v", err)
	}
	if err := watchdog.store.Rollback(context.Background(), transaction.ID, network, watchdog.clock.Now()); err != nil {
		t.Fatalf("second Rollback() error = %v", err)
	}
	if network.restoreCalls != 1 {
		t.Fatalf("network restore calls = %d", network.restoreCalls)
	}
	if !reflect.DeepEqual(supervisor.stopped, []string{transaction.ID}) {
		t.Fatalf("stopped timers = %v", supervisor.stopped)
	}
	assertWatchdogMode(t, filepath.Join(paths.WatchdogDir, transaction.ID, watchdogRolledBackFile), 0o600)
}

func TestWatchdogRollbackTreatsCommittedTransactionAsNoOp(t *testing.T) {
	t.Parallel()

	paths := testWatchdogPaths(t)
	network := &fakeWatchdogNetwork{snapshot: testNetworkSnapshot()}
	watchdog, _ := NewWatchdog(paths, network, &fakeWatchdogSupervisor{})
	watchdog.clock = fixedWatchdogClock{now: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
	watchdog.newID = func() (string, error) { return "12345678-1234-4234-8234-123456789abe", nil }
	transaction, err := watchdog.Arm(context.Background(), WatchdogArmInput{AllowedSSHPort: 22})
	if err != nil {
		t.Fatalf("Arm() error = %v", err)
	}
	directory := filepath.Join(paths.WatchdogDir, transaction.ID)
	if err := writeWatchdogFile(directory, watchdogCommittedFile, []byte("{}\n"), true); err != nil {
		t.Fatalf("write commit marker: %v", err)
	}
	if err := watchdog.store.Rollback(context.Background(), transaction.ID, network, watchdog.clock.Now()); err != nil {
		t.Fatalf("Rollback(committed) error = %v", err)
	}
	if network.restoreCalls != 0 {
		t.Fatalf("committed transaction restored network %d time(s)", network.restoreCalls)
	}
}

func TestWatchdogStoreRejectsTamperingAndSymlinks(t *testing.T) {
	t.Parallel()

	paths := testWatchdogPaths(t)
	transactionStore, _ := NewWatchdogStore(paths)
	transaction := testWatchdogTransaction("12345678-1234-4234-8234-123456789abf")
	if err := transactionStore.Create(transaction); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	snapshotPath := filepath.Join(paths.WatchdogDir, transaction.ID, watchdogSnapshotFile)
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(data), `"value": "0"`, `"value": "1"`, 1)
	if err := os.WriteFile(snapshotPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := transactionStore.Load(transaction.ID); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("Load(tampered) error = %v", err)
	}

	second := testWatchdogTransaction("12345678-1234-4234-8234-123456789ac0")
	if err := transactionStore.Create(second); err != nil {
		t.Fatalf("Create(second) error = %v", err)
	}
	secondPath := filepath.Join(paths.WatchdogDir, second.ID, watchdogSnapshotFile)
	if err := os.Remove(secondPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(snapshotPath, secondPath); err != nil {
		t.Fatal(err)
	}
	if _, err := transactionStore.Load(second.ID); err == nil || !strings.Contains(err.Error(), "root-only regular") {
		t.Fatalf("Load(symlink) error = %v", err)
	}
}

func TestWatchdogRollbackRefusesUnsafeCommitMarkerBeforeMutation(t *testing.T) {
	t.Parallel()

	paths := testWatchdogPaths(t)
	transactionStore, _ := NewWatchdogStore(paths)
	transaction := testWatchdogTransaction("12345678-1234-4234-8234-123456789ac2")
	if err := transactionStore.Create(transaction); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	directory := filepath.Join(paths.WatchdogDir, transaction.ID)
	if err := os.Symlink(watchdogSnapshotFile, filepath.Join(directory, watchdogCommittedFile)); err != nil {
		t.Fatal(err)
	}
	network := &fakeWatchdogNetwork{}
	err := transactionStore.Rollback(context.Background(), transaction.ID, network, time.Now())
	if err == nil || !strings.Contains(err.Error(), "root-only regular") {
		t.Fatalf("Rollback(unsafe marker) error = %v", err)
	}
	if network.restoreCalls != 0 {
		t.Fatalf("unsafe marker allowed %d network mutation(s)", network.restoreCalls)
	}
}

func TestSystemdWatchdogSupervisorUsesExactInstances(t *testing.T) {
	t.Parallel()

	runner := &recordingProbeRunner{}
	supervisor := NewSystemdWatchdogSupervisor(runner)
	id := "12345678-1234-4234-8234-123456789ac1"
	if err := supervisor.StartTimer(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.TriggerRollback(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.StopTimer(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"start", "vpnctl-watchdog@" + id + ".timer"},
		{"start", "vpnctl-watchdog@" + id + ".service"},
		{"stop", "vpnctl-watchdog@" + id + ".timer"},
	}
	if !reflect.DeepEqual(runner.args, want) {
		t.Fatalf("systemctl args = %v, want %v", runner.args, want)
	}
}

func testWatchdogPaths(t *testing.T) store.Paths {
	t.Helper()
	root := t.TempDir()
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return paths
}

func testNetworkSnapshot() linuxplatform.NetworkSnapshot {
	return linuxplatform.NetworkSnapshot{
		SchemaVersion: linuxplatform.NetworkSnapshotSchemaVersion,
		Routes:        []linuxplatform.Route{},
		PolicyRules:   []linuxplatform.PolicyRule{},
		Sysctls:       []linuxplatform.SysctlSnapshot{{Name: "net.ipv4.ip_forward", Value: "0"}},
	}
}

func testWatchdogTransaction(id string) WatchdogTransaction {
	preparedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	network := testNetworkSnapshot()
	return WatchdogTransaction{
		SchemaVersion: WatchdogTransactionSchemaVersion,
		ID:            id, PreparedAt: preparedAt, Deadline: preparedAt.Add(120 * time.Second),
		AllowedSSHPort: 22, NetworkSHA256: networkDigest(network), Network: network,
	}
}

func assertWatchdogMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s) error = %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("mode(%s) = %o, want %o", path, info.Mode().Perm(), want)
	}
}

type fakeWatchdogNetwork struct {
	snapshot      linuxplatform.NetworkSnapshot
	snapshotError error
	restoreError  error
	scopes        []linuxplatform.OwnedNetworkScope
	restoreCalls  int
}

func (network *fakeWatchdogNetwork) Snapshot(_ context.Context, scope linuxplatform.OwnedNetworkScope) (linuxplatform.NetworkSnapshot, error) {
	network.scopes = append(network.scopes, scope)
	return network.snapshot, network.snapshotError
}

func (network *fakeWatchdogNetwork) Restore(_ context.Context, _ linuxplatform.NetworkSnapshot) error {
	network.restoreCalls++
	return network.restoreError
}

type fakeWatchdogSupervisor struct {
	started    []string
	rolledBack []string
	stopped    []string
	onStart    func(string) error
	onRollback func(string) error
}

func (supervisor *fakeWatchdogSupervisor) StartTimer(_ context.Context, id string) error {
	supervisor.started = append(supervisor.started, id)
	if supervisor.onStart != nil {
		return supervisor.onStart(id)
	}
	return nil
}

func (supervisor *fakeWatchdogSupervisor) TriggerRollback(_ context.Context, id string) error {
	supervisor.rolledBack = append(supervisor.rolledBack, id)
	if supervisor.onRollback != nil {
		return supervisor.onRollback(id)
	}
	return nil
}

func (supervisor *fakeWatchdogSupervisor) StopTimer(_ context.Context, id string) error {
	supervisor.stopped = append(supervisor.stopped, id)
	return nil
}

type fixedWatchdogClock struct{ now time.Time }

func (clock fixedWatchdogClock) Now() time.Time { return clock.now }

type recordingProbeRunner struct{ args [][]string }

func (runner *recordingProbeRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	if command.Name != "systemctl" {
		return linuxplatform.ProbeResult{}, errors.New("unexpected command")
	}
	runner.args = append(runner.args, append([]string(nil), command.Args...))
	return linuxplatform.ProbeResult{}, nil
}
