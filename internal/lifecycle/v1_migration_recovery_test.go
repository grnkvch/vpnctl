package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestV1MigrationRollbackRestoresV1AndRemovesOnlyOwnedV2Resources(t *testing.T) {
	fixture := newV1MigrationRecoveryFixture(t)
	result, err := fixture.driver.RecoverV1Migration(context.Background(), V1MigrationRecoveryInput{
		MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
		Action: V1MigrationRecoveryRollback, Confirmed: true,
	})
	if err != nil || result.Status != "rolled_back" || len(result.CompletedPhases) != len(v1MigrationRollbackPhaseOrder) {
		t.Fatalf("rollback result = %+v, err=%v", result, err)
	}
	fixture.assertRestored(t)
	second, err := fixture.driver.RecoverV1Migration(context.Background(), V1MigrationRecoveryInput{
		MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
		Action: V1MigrationRecoveryRollback, Confirmed: true,
	})
	if err != nil || !reflect.DeepEqual(result, second) {
		t.Fatalf("repeated rollback = %+v, err=%v", second, err)
	}
	if _, err := fixture.driver.RecoverV1Migration(context.Background(), V1MigrationRecoveryInput{
		MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
		Action: V1MigrationRecoveryAccept, Confirmed: true,
	}); !errors.Is(err, ErrV1MigrationTerminal) {
		t.Fatalf("accept after rollback error = %v", err)
	}
}

func TestV1MigrationRollbackRestoresCapturedUFWAndWireGuardUnitStates(t *testing.T) {
	for _, test := range []struct {
		name       string
		ufwEnabled bool
		wgEnabled  bool
		wgActive   bool
	}{
		{name: "all enabled", ufwEnabled: true, wgEnabled: true, wgActive: true},
		{name: "all disabled", ufwEnabled: false, wgEnabled: false, wgActive: false},
		{name: "enabled inactive", ufwEnabled: true, wgEnabled: true, wgActive: false},
		{name: "disabled active", ufwEnabled: false, wgEnabled: false, wgActive: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newV1MigrationRecoveryFixtureWithState(t, test.ufwEnabled, test.wgEnabled, test.wgActive)
			result, err := fixture.driver.RecoverV1Migration(context.Background(), V1MigrationRecoveryInput{
				MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
				Action: V1MigrationRecoveryRollback, Confirmed: true,
			})
			if err != nil || result.Status != "rolled_back" {
				t.Fatalf("rollback result = %+v, err=%v", result, err)
			}
			fixture.assertRestored(t)
			if fixture.runner.ufwEnabled != test.ufwEnabled || len(fixture.runner.ufwActions) != 1 {
				t.Fatalf("restored UFW enabled=%t actions=%v", fixture.runner.ufwEnabled, fixture.runner.ufwActions)
			}
		})
	}
}

func TestV1MigrationRollbackResumesEveryInterruptedPhase(t *testing.T) {
	for _, interrupted := range v1MigrationRollbackPhaseOrder {
		interrupted := interrupted
		t.Run(string(interrupted), func(t *testing.T) {
			fixture := newV1MigrationRecoveryFixture(t)
			injected := false
			fixture.driver.recoveryHook = func(phase V1MigrationRecoveryPhase) error {
				if phase == interrupted && !injected {
					injected = true
					return errors.New("injected recovery interruption")
				}
				return nil
			}
			input := V1MigrationRecoveryInput{
				MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
				Action: V1MigrationRecoveryRollback, Confirmed: true,
			}
			if _, err := fixture.driver.RecoverV1Migration(context.Background(), input); err == nil || !strings.Contains(err.Error(), "injected recovery") {
				t.Fatalf("interrupted rollback error = %v", err)
			}
			fixture.driver.recoveryHook = nil
			result, err := fixture.driver.RecoverV1Migration(context.Background(), input)
			if err != nil || result.Status != "rolled_back" {
				t.Fatalf("resumed rollback = %+v, err=%v", result, err)
			}
			fixture.assertRestored(t)
			if fixture.watchdog.restoreEffects != 1 || fixture.runner.ufwEnableEffects != 1 || fixture.runner.v1RestoreEffects != 1 {
				t.Fatalf("recovery effects watchdog=%d ufw=%d service=%d", fixture.watchdog.restoreEffects, fixture.runner.ufwEnableEffects, fixture.runner.v1RestoreEffects)
			}
		})
	}
}

func TestV1MigrationAcceptanceRemovesRollbackPayloadAndPreservesV2(t *testing.T) {
	fixture := newV1MigrationRecoveryFixture(t)
	v2Binary, err := os.ReadFile(filepath.Join(fixture.systemRoot, "usr", "local", "bin", "vpnctl"))
	if err != nil {
		t.Fatal(err)
	}
	input := V1MigrationRecoveryInput{
		MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
		Action: V1MigrationRecoveryAccept, Confirmed: true,
	}
	result, err := fixture.driver.RecoverV1Migration(context.Background(), input)
	if err != nil || result.Status != "accepted" {
		t.Fatalf("accept result = %+v, err=%v", result, err)
	}
	for _, name := range []string{v1MigrationSnapshotName, v1MigrationStageName, v1MigrationRecoveryBundleName} {
		if _, err := os.Lstat(filepath.Join(fixture.maintenanceRoot, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("accepted payload %s remains: %v", name, err)
		}
	}
	currentBinary, err := os.ReadFile(filepath.Join(fixture.systemRoot, "usr", "local", "bin", "vpnctl"))
	if err != nil || !reflect.DeepEqual(currentBinary, v2Binary) {
		t.Fatalf("acceptance changed v2 binary: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.systemRoot, strings.TrimPrefix(ReleaseInstalledBundlePath, "/"))); err != nil {
		t.Fatalf("acceptance removed installed v2 bundle: %v", err)
	}
	if second, err := fixture.driver.RecoverV1Migration(context.Background(), input); err != nil || !reflect.DeepEqual(second, result) {
		t.Fatalf("repeated accept = %+v, err=%v", second, err)
	}
	if _, err := fixture.driver.RecoverV1Migration(context.Background(), V1MigrationRecoveryInput{
		MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
		Action: V1MigrationRecoveryRollback, Confirmed: true,
	}); !errors.Is(err, ErrV1MigrationTerminal) {
		t.Fatalf("rollback after accept error = %v", err)
	}
}

func TestV1MigrationAcceptanceResumesAfterPayloadRemovalInterruption(t *testing.T) {
	fixture := newV1MigrationRecoveryFixture(t)
	injected := false
	fixture.driver.recoveryHook = func(phase V1MigrationRecoveryPhase) error {
		if phase == V1MigrationRecoveryPayloadRemoved && !injected {
			injected = true
			return errors.New("injected acceptance interruption")
		}
		return nil
	}
	input := V1MigrationRecoveryInput{
		MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
		Action: V1MigrationRecoveryAccept, Confirmed: true,
	}
	if _, err := fixture.driver.RecoverV1Migration(context.Background(), input); err == nil || !strings.Contains(err.Error(), "injected acceptance") {
		t.Fatalf("interrupted acceptance error = %v", err)
	}
	fixture.driver.recoveryHook = nil
	result, err := fixture.driver.RecoverV1Migration(context.Background(), input)
	if err != nil || result.Status != "accepted" || !reflect.DeepEqual(result.CompletedPhases, v1MigrationAcceptPhaseOrder) {
		t.Fatalf("resumed acceptance = %+v, err=%v", result, err)
	}
}

func TestV1MigrationRecoverySelectionIsAtomic(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		journal *v1MigrationRecoveryJournal
		err     error
	}
	const attempts = 24
	start := make(chan struct{})
	results := make(chan outcome, attempts)
	var wait sync.WaitGroup
	for index := 0; index < attempts; index++ {
		action := V1MigrationRecoveryRollback
		if index%2 != 0 {
			action = V1MigrationRecoveryAccept
		}
		wait.Add(1)
		go func(action V1MigrationRecoveryAction) {
			defer wait.Done()
			<-start
			journal, err := createOrLoadV1MigrationRecoveryJournal(root, v1MigrationRecoveryJournal{
				SchemaVersion: V1MigrationSchemaVersion, MigrationID: "mig-0123456789abcdef", Action: action,
				StartedAt: time.Date(2026, 9, 4, 18, 0, 0, 0, time.UTC), CompletedPhases: []V1MigrationRecoveryPhase{},
			})
			results <- outcome{journal: journal, err: err}
		}(action)
	}
	close(start)
	wait.Wait()
	close(results)
	selected, err := loadV1MigrationRecoveryJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	for result := range results {
		if result.err != nil || result.journal == nil || result.journal.Action != selected.Action {
			t.Fatalf("concurrent recovery selection = %+v, err=%v; selected=%s", result.journal, result.err, selected.Action)
		}
	}
}

func TestV1MigrationRecoveryPreflightRejectsDriftBeforeMutation(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *v1MigrationRecoveryFixture){
		"missing recovery bundle": func(t *testing.T, fixture *v1MigrationRecoveryFixture) {
			if err := os.Remove(filepath.Join(fixture.maintenanceRoot, v1MigrationRecoveryBundleName)); err != nil {
				t.Fatal(err)
			}
		},
		"changed component": func(t *testing.T, fixture *v1MigrationRecoveryFixture) {
			path := filepath.Join(fixture.systemRoot, "usr", "local", "libexec", "vpnctl", "mihomo")
			if err := os.WriteFile(path, []byte("foreign replacement\n"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"changed role unit": func(t *testing.T, fixture *v1MigrationRecoveryFixture) {
			request, _ := linuxplatform.RenderGatewayRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
			path := filepath.Join(fixture.systemRoot, "etc", "systemd", "system", request.Units[0].Name)
			if err := os.WriteFile(path, []byte("[Unit]\nDescription=foreign\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"unsafe owned tree": func(t *testing.T, fixture *v1MigrationRecoveryFixture) {
			if err := os.RemoveAll(fixture.driver.paths.StateDir); err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			if err := os.Symlink(outside, fixture.driver.paths.StateDir); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newV1MigrationRecoveryFixture(t)
			binaryPath := filepath.Join(fixture.systemRoot, strings.TrimPrefix(linuxplatform.DefaultVPNCTLBinaryPath, "/"))
			binaryBefore, err := os.ReadFile(binaryPath)
			if err != nil {
				t.Fatal(err)
			}
			mutate(t, fixture)
			_, err = fixture.driver.RecoverV1Migration(context.Background(), V1MigrationRecoveryInput{
				MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
				Action: V1MigrationRecoveryRollback, Confirmed: true,
			})
			if err == nil {
				t.Fatal("drifted rollback succeeded")
			}
			binaryAfter, readErr := os.ReadFile(binaryPath)
			if readErr != nil || !reflect.DeepEqual(binaryAfter, binaryBefore) || fixture.runner.mutationEffects != 0 || fixture.watchdog.restoreEffects != 0 {
				t.Fatalf("preflight mutated host: read=%v service=%d network=%d", readErr, fixture.runner.mutationEffects, fixture.watchdog.restoreEffects)
			}
			if _, journalErr := os.Lstat(filepath.Join(fixture.maintenanceRoot, v1MigrationRecoveryJournalName)); !errors.Is(journalErr, os.ErrNotExist) {
				t.Fatalf("terminal action was selected after failed preflight: %v", journalErr)
			}
		})
	}
}

func TestV1MigrationRecoveryRejectsDifferentRootsAndUnsafeMaintenanceRoot(t *testing.T) {
	for name, invoke := range map[string]func(*testing.T, *v1MigrationRecoveryFixture) error{
		"different workspace": func(t *testing.T, fixture *v1MigrationRecoveryFixture) error {
			_, err := fixture.driver.RecoverV1Migration(context.Background(), V1MigrationRecoveryInput{
				MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: t.TempDir(),
				Action: V1MigrationRecoveryRollback, Confirmed: true,
			})
			return err
		},
		"different system root": func(t *testing.T, fixture *v1MigrationRecoveryFixture) error {
			driver := *fixture.driver
			driver.root = t.TempDir()
			_, err := driver.RecoverV1Migration(context.Background(), V1MigrationRecoveryInput{
				MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
				Action: V1MigrationRecoveryRollback, Confirmed: true,
			})
			return err
		},
		"unsafe maintenance mode": func(t *testing.T, fixture *v1MigrationRecoveryFixture) error {
			if err := os.Chmod(fixture.maintenanceRoot, 0o755); err != nil {
				t.Fatal(err)
			}
			_, err := fixture.driver.RecoverV1Migration(context.Background(), V1MigrationRecoveryInput{
				MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
				Action: V1MigrationRecoveryRollback, Confirmed: true,
			})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newV1MigrationRecoveryFixture(t)
			if err := invoke(t, fixture); err == nil {
				t.Fatal("unsafe recovery input succeeded")
			}
			if fixture.runner.mutationEffects != 0 || fixture.watchdog.restoreEffects != 0 {
				t.Fatalf("root validation mutated host: service=%d network=%d", fixture.runner.mutationEffects, fixture.watchdog.restoreEffects)
			}
			if _, journalErr := os.Lstat(filepath.Join(fixture.maintenanceRoot, v1MigrationRecoveryJournalName)); !errors.Is(journalErr, os.ErrNotExist) {
				t.Fatalf("terminal action was selected for unsafe roots: %v", journalErr)
			}
		})
	}
}

func TestV1MigrationAcceptancePreflightRejectsChangedInstalledBundle(t *testing.T) {
	fixture := newV1MigrationRecoveryFixture(t)
	installed := filepath.Join(fixture.systemRoot, strings.TrimPrefix(ReleaseInstalledBundlePath, "/"))
	if err := os.WriteFile(installed, []byte("changed installed bundle\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.driver.RecoverV1Migration(context.Background(), V1MigrationRecoveryInput{
		MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
		Action: V1MigrationRecoveryAccept, Confirmed: true,
	})
	if err == nil || fixture.runner.mutationEffects != 0 || fixture.watchdog.restoreEffects != 0 {
		t.Fatalf("changed-bundle acceptance error=%v service=%d network=%d", err, fixture.runner.mutationEffects, fixture.watchdog.restoreEffects)
	}
	if _, journalErr := os.Lstat(filepath.Join(fixture.maintenanceRoot, v1MigrationRecoveryJournalName)); !errors.Is(journalErr, os.ErrNotExist) {
		t.Fatalf("terminal action was selected after failed acceptance preflight: %v", journalErr)
	}
}

func TestV1MigrationAcceptanceRequiresCompletedMigrationAndConfirmation(t *testing.T) {
	fixture := newV1MigrationRecoveryFixture(t)
	journal, err := loadV1MigrationJournal(fixture.maintenanceRoot)
	if err != nil {
		t.Fatal(err)
	}
	journal.CompletedPhases = journal.CompletedPhases[:len(journal.CompletedPhases)-1]
	journal.ClientValidation = []V1MigrationClientValidation{}
	if err := writeV1MigrationJournal(fixture.maintenanceRoot, *journal); err != nil {
		t.Fatal(err)
	}
	input := V1MigrationRecoveryInput{
		MaintenanceRoot: fixture.maintenanceRoot, WorkspaceRoot: fixture.workspace,
		Action: V1MigrationRecoveryAccept,
	}
	if _, err := fixture.driver.RecoverV1Migration(context.Background(), input); err == nil {
		t.Fatal("acceptance without confirmation succeeded")
	}
	input.Confirmed = true
	if _, err := fixture.driver.RecoverV1Migration(context.Background(), input); err == nil || !strings.Contains(err.Error(), "complete client validation") {
		t.Fatalf("incomplete acceptance error = %v", err)
	}
}

type v1MigrationRecoveryFixture struct {
	driver          *SystemV1MigrationDriver
	runner          *v1MigrationRecoveryRunner
	watchdog        *v1MigrationRecoveryWatchdog
	workspace       string
	systemRoot      string
	maintenanceRoot string
	v1Files         map[string]v1MigrationExpectedFile
	wgEnabled       bool
	wgActive        bool
}

type v1MigrationExpectedFile struct {
	content []byte
	mode    os.FileMode
}

func newV1MigrationRecoveryFixture(t *testing.T) *v1MigrationRecoveryFixture {
	return newV1MigrationRecoveryFixtureWithState(t, true, true, true)
}

func newV1MigrationRecoveryFixtureWithState(t *testing.T, ufwEnabled, wgEnabled, wgActive bool) *v1MigrationRecoveryFixture {
	t.Helper()
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	if !ufwEnabled {
		if err := os.WriteFile(filepath.Join(systemRoot, "etc", "ufw", "ufw.conf"), []byte("ENABLED=no\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	runner := &v1MigrationRecoveryRunner{systemRoot: systemRoot, v1Enabled: wgEnabled, v1Active: wgActive, ufwEnabled: ufwEnabled}
	watchdog := &v1MigrationRecoveryWatchdog{}
	maintenanceRoot := filepath.Join(v1MigrationRealTempDir(t), "migration")
	if err := os.Mkdir(maintenanceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshotRoot := filepath.Join(maintenanceRoot, v1MigrationSnapshotName)
	snapshot, err := (&SystemV1MigrationDriver{runner: runner, binaryPath: linuxplatform.DefaultVPNCTLBinaryPath}).CreateMaintenanceSnapshot(context.Background(), snapshotRoot, &inspection)
	if err != nil {
		t.Fatal(err)
	}
	manifest, artifacts, _ := releaseBundleFixture(t)
	recoveryBundle := filepath.Join(maintenanceRoot, v1MigrationRecoveryBundleName)
	writeReleaseBundleFile(t, recoveryBundle, manifest, artifacts)
	installer, err := NewReleaseBundleInstaller(systemRoot, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := installer.InstallV1Migration(context.Background(), recoveryBundle, model.RoleGateway, snapshotRoot, linuxplatform.DefaultVPNCTLBinaryPath); err != nil {
		t.Fatal(err)
	}
	paths, err := store.NewPaths(systemRoot)
	if err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{
		filepath.Join(systemRoot, "etc", "systemd", "system"): 0o755,
		paths.ConfigDir: 0o700, paths.StateDir: 0o700, paths.RuntimeDir: 0o700,
	} {
		if err := os.MkdirAll(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	roles, _ := linuxplatform.NewRoleSystemdInstaller(systemRoot, paths.ConfigDir, runner)
	request, _ := linuxplatform.RenderGatewayRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	if _, err := roles.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	watchdogUnits, _ := linuxplatform.NewWatchdogUnitInstaller(systemRoot, runner)
	watchdogPlan, _ := watchdogUnits.Plan(linuxplatform.DefaultVPNCTLBinaryPath)
	if _, err := watchdogUnits.Apply(context.Background(), watchdogPlan); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.StateDir, "migration-owned"), []byte("v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stageRoot := filepath.Join(maintenanceRoot, v1MigrationStageName)
	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(stageRoot, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	ufwConfig := filepath.Join(systemRoot, "etc", "ufw", "ufw.conf")
	if err := os.WriteFile(ufwConfig, []byte("ENABLED=no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner.v1Enabled, runner.v1Active = false, false
	runner.ufwEnabled = false
	journal := v1MigrationJournal{
		SchemaVersion: V1MigrationSchemaVersion, MigrationID: "mig-0123456789abcdef",
		InputSHA256: strings.Repeat("a", 64), ReleaseVersion: manifest.ComponentManifest.VPNCTLVersion,
		StartedAt: time.Date(2026, 9, 4, 18, 0, 0, 0, time.UTC), HandshakeHost: gatewayTestHandshakeHost(),
		SourceWorkspace: inspection.workspaceRoot, SourceSystemRoot: inspection.systemRoot,
		SourceUFW: cloneV1UFWReport(inspection.Report.UFW), CompletedPhases: append([]V1MigrationPhase(nil), v1MigrationPhaseOrder...),
		WatchdogTransactionID: "fw-7K3M2P", Snapshot: &snapshot,
		Conversion:       &V1ConversionResult{SchemaVersion: V1ConversionSchemaVersion, Status: "converted", Clients: []V1ClientConversion{}, Presets: []V1PresetConversion{}, PreservedArtifacts: []V1ArtifactConversion{}},
		ClientValidation: []V1MigrationClientValidation{},
	}
	if err := writeV1MigrationJournal(maintenanceRoot, journal); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(systemRoot, "opt", "foreign-service", "keep")
	writeV1FixtureFile(t, foreign, []byte("foreign\n"), 0o640)
	v1Files := map[string]v1MigrationExpectedFile{}
	snapshotManifest, err := loadV1MaintenanceSnapshotManifest(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range snapshotManifest.Entries {
		data, err := os.ReadFile(filepath.Join(snapshotRoot, filepath.FromSlash(entry.Path)))
		if err != nil {
			t.Fatal(err)
		}
		v1Files[entry.Path] = v1MigrationExpectedFile{content: data, mode: os.FileMode(entry.Mode)}
	}
	network, _ := linuxplatform.NewNetworkManager(runner)
	driver := &SystemV1MigrationDriver{
		root: systemRoot, paths: paths, bundles: installer, runner: runner, network: network,
		binaryPath: linuxplatform.DefaultVPNCTLBinaryPath, watchdog: watchdog,
	}
	runner.trackMutations = true
	return &v1MigrationRecoveryFixture{
		driver: driver, runner: runner, watchdog: watchdog, workspace: workspace,
		systemRoot: systemRoot, maintenanceRoot: maintenanceRoot, v1Files: v1Files,
		wgEnabled: wgEnabled, wgActive: wgActive,
	}
}

func (fixture *v1MigrationRecoveryFixture) assertRestored(t *testing.T) {
	t.Helper()
	for logical, expected := range fixture.v1Files {
		var path string
		if strings.HasPrefix(logical, "v1-workspace/") {
			path = filepath.Join(fixture.workspace, filepath.FromSlash(strings.TrimPrefix(logical, "v1-workspace/")))
		} else {
			path = filepath.Join(fixture.systemRoot, filepath.FromSlash(strings.TrimPrefix(logical, "v1-system/")))
		}
		data, err := os.ReadFile(path)
		info, statErr := os.Lstat(path)
		if err != nil || statErr != nil || !reflect.DeepEqual(data, expected.content) || info.Mode().Perm() != expected.mode {
			t.Fatalf("restored %s mismatch: read=%v stat=%v", logical, err, statErr)
		}
	}
	for _, path := range []string{
		fixture.driver.paths.ConfigDir, fixture.driver.paths.StateDir, fixture.driver.paths.RuntimeDir,
		filepath.Join(fixture.systemRoot, "usr", "local", "libexec", "vpnctl", "mihomo"),
		filepath.Join(fixture.systemRoot, "usr", "local", "libexec", "vpnctl", "frps"),
		filepath.Join(fixture.systemRoot, strings.TrimPrefix(ReleaseInstalledBundlePath, "/")),
		filepath.Join(fixture.maintenanceRoot, v1MigrationSnapshotName),
		filepath.Join(fixture.maintenanceRoot, v1MigrationStageName),
		filepath.Join(fixture.maintenanceRoot, v1MigrationRecoveryBundleName),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rollback-owned path remains %s: %v", path, err)
		}
	}
	request, _ := linuxplatform.RenderGatewayRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	for _, unit := range request.Units {
		path := filepath.Join(fixture.systemRoot, "etc", "systemd", "system", unit.Name)
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rollback role unit remains %s: %v", path, err)
		}
	}
	watchdogUnits, _ := linuxplatform.NewWatchdogUnitInstaller(fixture.systemRoot, fixture.runner)
	watchdogPlan, _ := watchdogUnits.Plan(linuxplatform.DefaultVPNCTLBinaryPath)
	for _, path := range watchdogPlan.UnitFiles {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rollback watchdog unit remains %s: %v", path, err)
		}
	}
	foreign := filepath.Join(fixture.systemRoot, "opt", "foreign-service", "keep")
	if data, err := os.ReadFile(foreign); err != nil || string(data) != "foreign\n" {
		t.Fatalf("foreign file changed: %q, %v", data, err)
	}
	if fixture.runner.v1Enabled != fixture.wgEnabled || fixture.runner.v1Active != fixture.wgActive {
		t.Fatalf("v1 unit state enabled=%t active=%t, want %t/%t", fixture.runner.v1Enabled, fixture.runner.v1Active, fixture.wgEnabled, fixture.wgActive)
	}
}

type v1MigrationRecoveryRunner struct {
	systemRoot       string
	v1Enabled        bool
	v1Active         bool
	ufwEnabled       bool
	ufwEnableEffects int
	ufwActions       []string
	v1RestoreEffects int
	trackMutations   bool
	mutationEffects  int
}

func (runner *v1MigrationRecoveryRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	if command.Name == "ufw" && len(command.Args) == 2 && command.Args[0] == "--force" && (command.Args[1] == "enable" || command.Args[1] == "disable") {
		path := filepath.Join(runner.systemRoot, "etc", "ufw", "ufw.conf")
		data, err := os.ReadFile(path)
		if err != nil {
			return linuxplatform.ProbeResult{}, err
		}
		if runner.trackMutations {
			runner.mutationEffects++
		}
		runner.ufwActions = append(runner.ufwActions, command.Args[1])
		enabled := command.Args[1] == "enable"
		if enabled && !runner.ufwEnabled {
			runner.ufwEnableEffects++
		}
		runner.ufwEnabled = enabled
		value := "no"
		if enabled {
			value = "yes"
		}
		lines := strings.ReplaceAll(string(data), "ENABLED=no", "ENABLED="+value)
		lines = strings.ReplaceAll(lines, "ENABLED=yes", "ENABLED="+value)
		data = []byte(lines)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return linuxplatform.ProbeResult{}, err
		}
		return linuxplatform.ProbeResult{}, nil
	}
	if command.Name != "systemctl" {
		return linuxplatform.ProbeResult{}, errors.New("unexpected recovery command")
	}
	if runner.trackMutations && len(command.Args) != 0 {
		switch command.Args[0] {
		case "start", "stop", "restart", "enable", "disable", "daemon-reload":
			runner.mutationEffects++
		}
	}
	if len(command.Args) == 2 && command.Args[1] == "wg-quick@wg0.service" {
		switch command.Args[0] {
		case "is-enabled":
			if runner.v1Enabled {
				return linuxplatform.ProbeResult{Stdout: []byte("enabled\n")}, nil
			}
			return linuxplatform.ProbeResult{Stdout: []byte("disabled\n"), ExitCode: 1}, nil
		case "is-active":
			if runner.v1Active {
				return linuxplatform.ProbeResult{Stdout: []byte("active\n")}, nil
			}
			return linuxplatform.ProbeResult{Stdout: []byte("inactive\n"), ExitCode: 3}, nil
		case "enable":
			wasRestored := runner.v1Enabled && runner.v1Active
			runner.v1Enabled = true
			if !wasRestored && runner.v1Active {
				runner.v1RestoreEffects++
			}
			return linuxplatform.ProbeResult{}, nil
		case "disable":
			runner.v1Enabled = false
			return linuxplatform.ProbeResult{}, nil
		case "restart":
			if !runner.v1Active {
				runner.v1RestoreEffects++
			}
			runner.v1Active = true
			return linuxplatform.ProbeResult{}, nil
		case "stop":
			runner.v1Active = false
			return linuxplatform.ProbeResult{}, nil
		}
	}
	return linuxplatform.ProbeResult{}, nil
}

type v1MigrationRecoveryWatchdog struct {
	restored       bool
	restoreEffects int
}

func (watchdog *v1MigrationRecoveryWatchdog) ArmPrepared(context.Context, int, *linuxplatform.SSHConnection, func(V1MigrationWatchdogTransaction) error) (V1MigrationWatchdogTransaction, error) {
	return V1MigrationWatchdogTransaction{}, errors.New("not used")
}

func (watchdog *v1MigrationRecoveryWatchdog) EnsureTimer(context.Context, string) error   { return nil }
func (watchdog *v1MigrationRecoveryWatchdog) MarkActivated(context.Context, string) error { return nil }
func (watchdog *v1MigrationRecoveryWatchdog) Status(context.Context, string) (V1MigrationWatchdogStatus, error) {
	return V1MigrationWatchdogCommitted, nil
}
func (watchdog *v1MigrationRecoveryWatchdog) Restore(context.Context, string) error {
	if !watchdog.restored {
		watchdog.restored = true
		watchdog.restoreEffects++
	}
	return nil
}

var _ V1MigrationNetworkWatchdog = (*v1MigrationRecoveryWatchdog)(nil)
