package operations

import (
	"context"
	"errors"
	"fmt"
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
	watchdog.newID = func() (string, error) { return "fw-00000A", nil }
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
	watchdog.newID = func() (string, error) { return "fw-00000B", nil }
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
	watchdog.newID = func() (string, error) { return "fw-00000C", nil }
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
	transaction := testWatchdogTransaction("fw-00000D")
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

	second := testWatchdogTransaction("fw-00000E")
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
	transaction := testWatchdogTransaction("fw-00000F")
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
	id := "fw-00000G"
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

func TestWatchdogConfirmRequiresNewSSHSessionAndCommitsOnce(t *testing.T) {
	t.Parallel()

	watchdog, supervisor, transaction := newActivatedWatchdog(t, "fw-NEW001")
	watchdog.sessions.(*fakeWatchdogSessions).proof = validNewSessionProof(22)

	confirmation, err := watchdog.Confirm(context.Background(), transaction.ID, "192.0.2.20 55001 203.0.113.10 22")
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if confirmation.TransactionID != transaction.ID || !confirmation.TimerStopped {
		t.Fatalf("confirmation = %+v", confirmation)
	}
	if !reflect.DeepEqual(supervisor.stopped, []string{transaction.ID}) {
		t.Fatalf("stopped timers = %v", supervisor.stopped)
	}
	marker := filepath.Join(watchdog.store.paths.WatchdogDir, transaction.ID, watchdogCommittedFile)
	assertWatchdogMode(t, marker, 0o600)
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "192.0.2.20") || !strings.Contains(string(data), `"ssh_server_port":22`) {
		t.Fatalf("unsafe or incomplete commit marker: %s", data)
	}

	if _, err := watchdog.Confirm(context.Background(), transaction.ID, "192.0.2.20 55002 203.0.113.10 22"); !errors.Is(err, ErrWatchdogAlreadyCommitted) {
		t.Fatalf("second Confirm() error = %v", err)
	}
	if len(supervisor.stopped) != 1 {
		t.Fatalf("reused ID stopped timer again: %v", supervisor.stopped)
	}
}

func TestWatchdogConfirmRejectsOriginalSessionWrongPortAndExpiryWithoutCommit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		proof linuxplatform.SSHSessionProof
		want  error
	}{
		{name: "original session", proof: func() linuxplatform.SSHSessionProof {
			proof := validNewSessionProof(22)
			proof.StartedMonotonicNanos = 5_000_000_000
			return proof
		}(), want: ErrWatchdogOriginalSession},
		{name: "wrong listener port", proof: validNewSessionProof(2222), want: ErrWatchdogWrongSSHPort},
		{name: "expired", proof: func() linuxplatform.SSHSessionProof {
			proof := validNewSessionProof(22)
			proof.ObservedMonotonicNanos = 125_000_000_000
			return proof
		}(), want: ErrWatchdogExpired},
	}
	for index, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			watchdog, supervisor, transaction := newActivatedWatchdog(t, fmt.Sprintf("fw-BAD%03d", index))
			watchdog.sessions.(*fakeWatchdogSessions).proof = test.proof
			if _, err := watchdog.Confirm(context.Background(), transaction.ID, "192.0.2.20 55001 203.0.113.10 22"); !errors.Is(err, test.want) {
				t.Fatalf("Confirm() error = %v, want %v", err, test.want)
			}
			if len(supervisor.stopped) != 0 {
				t.Fatalf("rejected confirmation stopped timer: %v", supervisor.stopped)
			}
			if _, err := os.Lstat(filepath.Join(watchdog.store.paths.WatchdogDir, transaction.ID, watchdogCommittedFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected confirmation published marker: %v", err)
			}
		})
	}
}

func TestWatchdogConfirmReportsRolledBackTransactionAsExpired(t *testing.T) {
	t.Parallel()

	watchdog, supervisor, transaction := newActivatedWatchdog(t, "fw-EXP001")
	if err := watchdog.store.Rollback(context.Background(), transaction.ID, watchdog.network, watchdog.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := watchdog.Confirm(context.Background(), transaction.ID, "192.0.2.20 55001 203.0.113.10 22"); !errors.Is(err, ErrWatchdogExpired) {
		t.Fatalf("Confirm(rolled back) error = %v", err)
	}
	if len(supervisor.stopped) != 0 {
		t.Fatalf("expired confirmation stopped timer: %v", supervisor.stopped)
	}
}

func TestWatchdogArmRetriesAtomicShortIDCollision(t *testing.T) {
	t.Parallel()

	paths := testWatchdogPaths(t)
	network := &fakeWatchdogNetwork{snapshot: testNetworkSnapshot()}
	watchdog, _ := NewWatchdog(paths, network, &fakeWatchdogSupervisor{})
	watchdog.clock = fixedWatchdogClock{now: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
	ids := []string{"fw-SAME01", "fw-SAME01", "fw-NEXT01"}
	watchdog.newID = func() (string, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
	first, err := watchdog.Arm(context.Background(), WatchdogArmInput{AllowedSSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	second, err := watchdog.Arm(context.Background(), WatchdogArmInput{AllowedSSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != "fw-SAME01" || second.ID != "fw-NEXT01" {
		t.Fatalf("collision IDs = %s, %s", first.ID, second.ID)
	}
}

func newActivatedWatchdog(t *testing.T, id string) (*Watchdog, *fakeWatchdogSupervisor, WatchdogTransaction) {
	t.Helper()
	paths := testWatchdogPaths(t)
	network := &fakeWatchdogNetwork{snapshot: testNetworkSnapshot()}
	supervisor := &fakeWatchdogSupervisor{}
	watchdog, err := NewWatchdog(paths, network, supervisor)
	if err != nil {
		t.Fatal(err)
	}
	preparedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	watchdog.clock = fixedWatchdogClock{now: preparedAt}
	watchdog.newID = func() (string, error) { return id, nil }
	watchdog.sessions = &fakeWatchdogSessions{boundary: linuxplatform.MonotonicBoundary{
		BootID: "12345678-1234-4234-8234-123456789abc", MonotonicNanos: 5_000_000_000,
	}}
	transaction, err := watchdog.Arm(context.Background(), WatchdogArmInput{AllowedSSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	watchdog.clock = fixedWatchdogClock{now: preparedAt.Add(time.Second)}
	if err := watchdog.MarkActivated(context.Background(), transaction.ID); err != nil {
		t.Fatal(err)
	}
	return watchdog, supervisor, transaction
}

func validNewSessionProof(port int) linuxplatform.SSHSessionProof {
	return linuxplatform.SSHSessionProof{
		Connection: linuxplatform.SSHConnection{
			ClientAddress: "192.0.2.20", ClientPort: 55001,
			ServerAddress: "203.0.113.10", ServerPort: port,
		},
		BootID:                 "12345678-1234-4234-8234-123456789abc",
		StartedMonotonicNanos:  6_000_000_000,
		ObservedMonotonicNanos: 7_000_000_000,
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

type fakeWatchdogSessions struct {
	boundary    linuxplatform.MonotonicBoundary
	boundaryErr error
	proof       linuxplatform.SSHSessionProof
	proofErr    error
}

func (sessions *fakeWatchdogSessions) ActivationBoundary(context.Context) (linuxplatform.MonotonicBoundary, error) {
	return sessions.boundary, sessions.boundaryErr
}

func (sessions *fakeWatchdogSessions) CurrentSSHSession(context.Context, string) (linuxplatform.SSHSessionProof, error) {
	return sessions.proof, sessions.proofErr
}

type recordingProbeRunner struct{ args [][]string }

func (runner *recordingProbeRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	if command.Name != "systemctl" {
		return linuxplatform.ProbeResult{}, errors.New("unexpected command")
	}
	runner.args = append(runner.args, append([]string(nil), command.Args...))
	return linuxplatform.ProbeResult{}, nil
}
