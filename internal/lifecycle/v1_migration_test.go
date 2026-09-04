package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestV1MigrationRepeatedDryRunIsReadOnlyAndDeterministic(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	before := snapshotV1InspectionTrees(t, workspace, systemRoot)
	maintenance := filepath.Join(v1MigrationRealTempDir(t), "migration")
	driver := newV1MigrationTestDriver(t, systemRoot)
	migrator := newV1MigrationTestMigrator(t, workspace, systemRoot, driver)
	input := v1MigrationTestInput(t, maintenance, true)

	first, err := migrator.Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := migrator.Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || first.Status != "planned" || !first.DryRun || first.NextPhase != V1MigrationSnapshotCreated {
		t.Fatalf("dry-run results differ:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if _, err := os.Lstat(maintenance); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run maintenance root error = %v", err)
	}
	if after := snapshotV1InspectionTrees(t, workspace, systemRoot); !reflect.DeepEqual(before, after) {
		t.Fatal("dry-run changed the inspected v1 installation")
	}
	if driver.snapshotEffects != 0 || driver.convertEffects != 0 || driver.roleEffects != 0 || driver.networkEffects != 0 || driver.ufwEffects != 0 || driver.clientEffects != 0 {
		t.Fatalf("dry-run mutation effects = %+v", driver.effectCounts())
	}
	if driver.verifyCalls != 2 || driver.handshakeCalls != 2 {
		t.Fatalf("dry-run read calls verify=%d handshake=%d", driver.verifyCalls, driver.handshakeCalls)
	}
	if containsMigrationPrivateData(first.String(), v1MigrationClientPrivateKey(t, workspace)) {
		t.Fatal("dry-run result exposed a retained private key")
	}
}

func TestV1MigrationResumesEveryInterruptedEffectWithoutRepeatingMutation(t *testing.T) {
	for _, interrupted := range []V1MigrationPhase{
		V1MigrationSnapshotCreated,
		V1MigrationConversionStaged,
		V1MigrationRoleSetup,
		V1MigrationNetworkActivated,
		V1MigrationUFWTranslated,
		V1MigrationClientsValidated,
	} {
		t.Run(string(interrupted), func(t *testing.T) {
			workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
			maintenance := filepath.Join(v1MigrationRealTempDir(t), "migration")
			driver := newV1MigrationTestDriver(t, systemRoot)
			driver.networkStatus = V1MigrationNetworkCommitted
			migrator := newV1MigrationTestMigrator(t, workspace, systemRoot, driver)
			migrator.hook = func(phase V1MigrationPhase) error {
				if phase == interrupted {
					return errors.New("injected interruption")
				}
				return nil
			}
			input := v1MigrationTestInput(t, maintenance, false)

			if _, err := migrator.Run(context.Background(), input); err == nil || !strings.Contains(err.Error(), "injected interruption") {
				t.Fatalf("interrupted run error = %v", err)
			}
			resumed := newV1MigrationTestMigrator(t, workspace, systemRoot, driver)
			result, err := resumed.Run(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != "complete" || result.NextPhase != "" || len(result.CompletedPhases) != len(v1MigrationPhaseOrder) {
				t.Fatalf("resumed result = %+v", result)
			}
			if driver.snapshotEffects != 1 || driver.convertEffects != 1 || driver.roleEffects != 1 || driver.networkEffects != 1 || driver.ufwEffects != 1 || driver.clientEffects != 1 {
				t.Fatalf("resumed mutation effects = %+v", driver.effectCounts())
			}
			if _, err := loadV1MigrationJournal(maintenance); err != nil {
				t.Fatalf("load completed journal: %v", err)
			}
		})
	}
}

func TestV1MigrationWaitsForWatchdogConfirmationAndRejectsChangedInputs(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	maintenance := filepath.Join(v1MigrationRealTempDir(t), "migration")
	driver := newV1MigrationTestDriver(t, systemRoot)
	migrator := newV1MigrationTestMigrator(t, workspace, systemRoot, driver)
	input := v1MigrationTestInput(t, maintenance, false)

	pending, err := migrator.Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != "awaiting_network_confirmation" || pending.NextPhase != V1MigrationNetworkConfirmed || pending.WatchdogTransactionID != driver.transactionID || len(pending.RequiresAction) != 1 {
		t.Fatalf("pending result = %+v", pending)
	}
	if driver.clientEffects != 0 {
		t.Fatal("clients were validated before watchdog confirmation")
	}

	driver.networkStatus = V1MigrationNetworkCommitted
	complete, err := migrator.Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if complete.Status != "complete" || driver.networkEffects != 1 || driver.clientEffects != 1 {
		t.Fatalf("complete result/effects = %+v / %+v", complete, driver.effectCounts())
	}

	changed := input
	changed.PublicIPv4 = "8.8.4.4"
	if _, err := migrator.Run(context.Background(), changed); !errors.Is(err, ErrV1MigrationConflict) {
		t.Fatalf("changed-input resume error = %v", err)
	}
}

func TestV1MigrationReportsIndependentWatchdogRollback(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	driver := newV1MigrationTestDriver(t, systemRoot)
	migrator := newV1MigrationTestMigrator(t, workspace, systemRoot, driver)
	input := v1MigrationTestInput(t, filepath.Join(v1MigrationRealTempDir(t), "migration"), false)
	if _, err := migrator.Run(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	driver.networkStatus = V1MigrationNetworkRolledBack
	result, err := migrator.Run(context.Background(), input)
	if !errors.Is(err, ErrV1MigrationRolledBack) || result.Status != "network_rolled_back" || driver.clientEffects != 0 {
		t.Fatalf("rolled-back result/error = %+v / %v", result, err)
	}
}

func TestV1MigrationRejectsUFWChangeBeforeConfirmedNetwork(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	driver := newV1MigrationTestDriver(t, systemRoot)
	migrator := newV1MigrationTestMigrator(t, workspace, systemRoot, driver)
	input := v1MigrationTestInput(t, filepath.Join(v1MigrationRealTempDir(t), "migration"), false)
	if result, err := migrator.Run(context.Background(), input); err != nil || result.Status != "awaiting_network_confirmation" {
		t.Fatalf("initial migration = %+v, err=%v", result, err)
	}
	ufwConfig := filepath.Join(systemRoot, "etc", "ufw", "ufw.conf")
	if err := os.WriteFile(ufwConfig, []byte("ENABLED=no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := migrator.Run(context.Background(), input); !errors.Is(err, ErrV1MigrationConflict) {
		t.Fatalf("pre-confirmation UFW change error = %v", err)
	}
}

type v1MigrationTestInspector struct {
	workspace string
	system    string
}

func (inspector v1MigrationTestInspector) Inspect(ctx context.Context) (V1Inspection, error) {
	value, err := NewV1InstallationInspector(inspector.workspace, inspector.system)
	if err != nil {
		return V1Inspection{}, err
	}
	return value.Inspect(ctx)
}

type v1MigrationTestDriver struct {
	t               *testing.T
	manifest        ReleaseManifest
	verifyCalls     int
	handshakeCalls  int
	snapshotEffects int
	convertEffects  int
	roleEffects     int
	networkEffects  int
	clientEffects   int
	ufwEffects      int
	snapshotDone    bool
	conversion      *V1ConversionResult
	roleDone        bool
	networkDone     bool
	clientsDone     bool
	ufwDone         bool
	networkStatus   V1MigrationNetworkStatus
	transactionID   string
	systemRoot      string
}

func newV1MigrationTestDriver(t *testing.T, systemRoots ...string) *v1MigrationTestDriver {
	t.Helper()
	manifest, _ := releaseManifestFixture()
	var systemRoot string
	if len(systemRoots) != 0 {
		systemRoot = systemRoots[0]
	}
	return &v1MigrationTestDriver{
		t: t, manifest: manifest, networkStatus: V1MigrationNetworkPending,
		transactionID: "fw-7K3M2P", systemRoot: systemRoot,
	}
}

func (driver *v1MigrationTestDriver) VerifyBundle(_ context.Context, _ string) (ReleaseManifest, error) {
	driver.verifyCalls++
	return cloneReleaseManifest(driver.manifest), nil
}

func (driver *v1MigrationTestDriver) SelectHandshakeHost(_ context.Context, manifest ReleaseManifest, now time.Time) (model.HandshakeHost, error) {
	driver.handshakeCalls++
	return model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion,
		ListVersion:   manifest.ComponentManifest.HandshakeHostListVersion,
		CandidateID:   "migration-test", Hostname: "www.microsoft.com", SelectedAt: now,
	}, nil
}

func (driver *v1MigrationTestDriver) CreateMaintenanceSnapshot(_ context.Context, root string, _ *V1Inspection) (V1MaintenanceSnapshot, error) {
	result := V1MaintenanceSnapshot{
		SchemaVersion: 1, Files: 7, Bytes: 4096,
		LogicalRoots: []string{"v1-system", "v1-workspace"}, SHA256: strings.Repeat("a", 64),
		WireGuardUnit: V1MigrationUnitSnapshot{Name: "wg-quick@wg0.service", Enabled: true, Active: true},
	}
	if driver.snapshotDone {
		return result, nil
	}
	driver.snapshotDone = true
	driver.snapshotEffects++
	if err := os.Mkdir(root, 0o700); err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	return result, nil
}

func (driver *v1MigrationTestDriver) EnsureConvertedStage(ctx context.Context, input V1ConversionInput) (V1ConversionResult, error) {
	if driver.conversion != nil {
		return *driver.conversion, nil
	}
	result, err := ConvertV1ToV2Stage(ctx, input)
	if err != nil {
		return V1ConversionResult{}, err
	}
	driver.convertEffects++
	driver.conversion = &result
	return result, nil
}

func (driver *v1MigrationTestDriver) SetupGatewayRole(_ context.Context, stageRoot string, _ ReleaseManifest, _ *V1Inspection) error {
	if driver.roleDone {
		return nil
	}
	if _, err := os.Lstat(filepath.Join(stageRoot, "var", "lib", "vpnctl", "state.json")); err != nil {
		return err
	}
	driver.roleDone = true
	driver.roleEffects++
	return nil
}

func (driver *v1MigrationTestDriver) ActivateGatewayNetwork(_ context.Context, _ string, _ int, _ string) (string, error) {
	if !driver.networkDone {
		driver.networkDone = true
		driver.networkEffects++
	}
	return driver.transactionID, nil
}

func (driver *v1MigrationTestDriver) TranslateKnownUFW(_ context.Context, _ *V1Inspection) error {
	if !driver.ufwDone {
		driver.ufwDone = true
		driver.ufwEffects++
		if driver.systemRoot != "" {
			path := filepath.Join(driver.systemRoot, "etc", "ufw", "ufw.conf")
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(data), "ENABLED=yes", "ENABLED=no")), 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

func (driver *v1MigrationTestDriver) GatewayNetworkStatus(_ context.Context, transactionID string) (V1MigrationNetworkStatus, error) {
	if transactionID != driver.transactionID {
		return "", errors.New("wrong watchdog transaction")
	}
	return driver.networkStatus, nil
}

func (driver *v1MigrationTestDriver) ValidateMigratedClients(_ context.Context, _ string, conversion V1ConversionResult) ([]V1MigrationClientValidation, error) {
	if !driver.clientsDone {
		driver.clientsDone = true
		driver.clientEffects++
	}
	result := make([]V1MigrationClientValidation, 0, len(conversion.Clients))
	for _, client := range conversion.Clients {
		result = append(result, V1MigrationClientValidation{
			TargetClientID: client.TargetID, Status: "valid",
			AddressKept: true, KeyPairKept: true, ProfileStatus: "preserved",
		})
	}
	return result, nil
}

func (driver *v1MigrationTestDriver) effectCounts() map[string]int {
	return map[string]int{
		"snapshot": driver.snapshotEffects, "conversion": driver.convertEffects,
		"role": driver.roleEffects, "network": driver.networkEffects, "ufw": driver.ufwEffects,
		"clients": driver.clientEffects,
	}
}

func newV1MigrationTestMigrator(t *testing.T, workspace, systemRoot string, driver *v1MigrationTestDriver) *V1Migrator {
	t.Helper()
	migrator, err := NewV1Migrator(v1MigrationTestInspector{workspace: workspace, system: systemRoot}, driver)
	if err != nil {
		t.Fatal(err)
	}
	migrator.now = func() time.Time { return time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC) }
	return migrator
}

func v1MigrationTestInput(t *testing.T, maintenance string, dryRun bool) V1MigrationInput {
	t.Helper()
	bundle := filepath.Join(t.TempDir(), "vpnctl.bundle")
	if err := os.WriteFile(bundle, []byte("verified by fake driver"), 0o600); err != nil {
		t.Fatal(err)
	}
	return V1MigrationInput{
		BundlePath: bundle, MaintenanceRoot: maintenance, PublicIPv4: "8.8.8.8",
		NodeCIDR: model.DefaultNodeCIDR, SSHPort: 22, SSHConnection: "192.0.2.2 8.8.8.8 50123 22",
		DryRun: dryRun,
	}
}

func v1MigrationRealTempDir(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func v1MigrationClientPrivateKey(t *testing.T, workspace string) string {
	t.Helper()
	value, err := os.ReadFile(filepath.Join(workspace, ".vpnctl", "secrets", "clients", "iphone.key"))
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func containsMigrationPrivateData(value, privateKey string) bool {
	return privateKey != "" && len(value) >= len(privateKey) && stringContains(value, privateKey)
}

func stringContains(value, part string) bool {
	for index := 0; index+len(part) <= len(value); index++ {
		if value[index:index+len(part)] == part {
			return true
		}
	}
	return false
}

var _ V1MigrationInspector = v1MigrationTestInspector{}
var _ V1MigrationDriver = (*v1MigrationTestDriver)(nil)
