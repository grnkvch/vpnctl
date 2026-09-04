package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestSystemV1MigrationSnapshotIsCompleteIdempotentAndTamperEvident(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	before := snapshotV1InspectionTrees(t, workspace, systemRoot)
	root := filepath.Join(v1MigrationRealTempDir(t), "maintenance-snapshot")
	driver := &SystemV1MigrationDriver{runner: v1MigrationSnapshotRunner{}}

	first, err := driver.CreateMaintenanceSnapshot(context.Background(), root, &inspection)
	if err != nil {
		t.Fatal(err)
	}
	second, err := driver.CreateMaintenanceSnapshot(context.Background(), root, &inspection)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || first.Files < 8 || first.Bytes <= 0 || len(first.SHA256) != 64 {
		t.Fatalf("snapshot summaries = %+v / %+v", first, second)
	}
	manifestData, err := os.ReadFile(filepath.Join(root, v1MigrationSnapshotManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var manifest v1MaintenanceSnapshotManifest
	if err := decodeV1Strict(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Entries) != first.Files {
		t.Fatalf("snapshot manifest entries = %d, want %d", len(manifest.Entries), first.Files)
	}
	for _, entry := range manifest.Entries {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(entry.Path)))
		if err != nil {
			t.Fatalf("stat snapshot entry %s: %v", entry.Path, err)
		}
		if info.Mode().Perm() != 0o600 || entry.Mode == 0 {
			t.Fatalf("snapshot entry %s mode = %v, source=%o, err=%v", entry.Path, info.Mode().Perm(), entry.Mode, err)
		}
	}
	if after := snapshotV1InspectionTrees(t, workspace, systemRoot); !reflect.DeepEqual(before, after) {
		t.Fatal("maintenance snapshot changed its v1 sources")
	}
	tampered := filepath.Join(root, filepath.FromSlash(manifest.Entries[0].Path))
	if err := os.WriteFile(tampered, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.CreateMaintenanceSnapshot(context.Background(), root, &inspection); !errors.Is(err, ErrV1MigrationConflict) {
		t.Fatalf("tampered snapshot error = %v", err)
	}
}

func TestSystemV1MigrationSnapshotRetainsVerifiedBundleAtRollbackBoundary(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	maintenanceRoot := v1MigrationRealTempDir(t)
	snapshotRoot := filepath.Join(maintenanceRoot, v1MigrationSnapshotName)
	bundlePath := filepath.Join(v1MigrationRealTempDir(t), "vpnctl-v2.bundle")
	bundle := []byte("previously verified signed bundle fixture\n")
	writeV1FixtureFile(t, bundlePath, bundle, 0o600)
	driver := &SystemV1MigrationDriver{
		runner: v1MigrationSnapshotRunner{}, bundles: &v1MigrationBundleInstallerStub{manifest: v1MigrationGatewayManifest()},
	}
	if _, err := driver.VerifyBundle(context.Background(), bundlePath); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.CreateMaintenanceSnapshot(context.Background(), snapshotRoot, &inspection); err != nil {
		t.Fatal(err)
	}
	recoveryBundle := filepath.Join(maintenanceRoot, v1MigrationRecoveryBundleName)
	if data, err := os.ReadFile(recoveryBundle); err != nil || !reflect.DeepEqual(data, bundle) {
		t.Fatalf("retained recovery bundle = %q, err=%v", data, err)
	}
	if err := os.Remove(recoveryBundle); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.CreateMaintenanceSnapshot(context.Background(), snapshotRoot, &inspection); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(recoveryBundle); err != nil || !reflect.DeepEqual(data, bundle) {
		t.Fatalf("re-retained recovery bundle = %q, err=%v", data, err)
	}
}

func TestSystemV1MigrationPreservesForeignIncompleteSnapshotDirectory(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	root := filepath.Join(v1MigrationRealTempDir(t), "maintenance-snapshot")
	incomplete := root + ".incomplete"
	if err := os.Mkdir(incomplete, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(incomplete, "foreign")
	if err := os.WriteFile(foreign, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&SystemV1MigrationDriver{runner: v1MigrationSnapshotRunner{}}).CreateMaintenanceSnapshot(context.Background(), root, &inspection); !errors.Is(err, ErrV1MigrationConflict) {
		t.Fatalf("foreign incomplete snapshot error = %v", err)
	}
	if data, err := os.ReadFile(foreign); err != nil || string(data) != "keep\n" {
		t.Fatalf("foreign file changed: %q, %v", data, err)
	}
}

func TestSystemV1MigrationSnapshotRejectsOversizedSourceWithoutPublishing(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	oversized := filepath.Join(workspace, ".vpnctl", "oversized-sparse")
	file, err := os.OpenFile(oversized, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(v1MigrationMaximumSnapshotBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(v1MigrationRealTempDir(t), v1MigrationSnapshotName)
	if _, err := (&SystemV1MigrationDriver{runner: v1MigrationSnapshotRunner{}}).CreateMaintenanceSnapshot(context.Background(), root, &inspection); err == nil {
		t.Fatal("oversized snapshot source succeeded")
	}
	for _, path := range []string{root, root + ".incomplete"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("oversized snapshot published %s: %v", path, err)
		}
	}
}

func TestSystemV1MigrationPreparesConvertedGatewayRoleIdempotently(t *testing.T) {
	workspace, systemRoot, serverPrivate, _ := completeV1InspectionFixture(t)
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	manifest := v1MigrationGatewayManifest()
	stageRoot := filepath.Join(v1MigrationRealTempDir(t), "v2-stage")
	driver := &SystemV1MigrationDriver{
		binaryPath: "/usr/local/bin/vpnctl", entropy: rand.Reader,
		keyRunner: gatewayInitWireGuardRunner{privateKey: serverPrivate, publicKey: inspection.Report.Server.WireGuardPublicKey},
	}
	conversion, err := driver.EnsureConvertedStage(context.Background(), V1ConversionInput{
		Inspection: &inspection, StageRoot: stageRoot, PublicIPv4: "8.8.8.8", SSHPort: 22,
		NodeCIDR: model.DefaultNodeCIDR, ConvertedAt: time.Date(2026, 9, 4, 18, 0, 0, 0, time.UTC),
		Components: manifest.ComponentManifest,
		HandshakeHost: model.HandshakeHost{
			SchemaVersion: model.ResourceSchemaVersion, ListVersion: manifest.ComponentManifest.HandshakeHostListVersion,
			CandidateID: "migration-test", Hostname: "www.microsoft.com", SelectedAt: time.Date(2026, 9, 4, 18, 0, 0, 0, time.UTC),
		},
	})
	if err != nil || len(conversion.Clients) != 1 {
		t.Fatalf("conversion = %+v, err=%v", conversion, err)
	}
	first, err := driver.prepareGatewayStage(context.Background(), stageRoot, manifest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := driver.prepareGatewayStage(context.Background(), stageRoot, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("repeated stage role preparation changed the role request")
	}
	paths, _ := store.NewPaths(stageRoot)
	stateStore, _ := store.NewStateStore(paths)
	state, err := stateStore.Load()
	if err != nil || state.Generation != 3 || len(state.Certificates) != 3 || state.EnrollmentIdentity == nil {
		t.Fatalf("prepared state = %+v, err=%v", state, err)
	}
	if len(state.Transports) != 2 || state.Transports[1].Kind != model.TransportRestricted || state.Transports[1].State != model.TransportStandby {
		t.Fatalf("prepared migrated transports = %+v", state.Transports)
	}
	secrets, _ := store.NewSecretStore(paths)
	standard, err := secrets.Get(transport.GatewayStandardCredentialRef)
	if err != nil || string(standard) != serverPrivate {
		t.Fatalf("preserved server private key mismatch/error = %q / %v", standard, err)
	}
	if len(first.Configs) < 8 {
		t.Fatalf("prepared gateway configs = %d", len(first.Configs))
	}
	for _, config := range first.Configs {
		path := filepath.Join(paths.ConfigDir, "generated", "gateway", config.Name)
		content, err := os.ReadFile(path)
		if err != nil || !reflect.DeepEqual(content, config.Content) {
			t.Fatalf("prepared config %s mismatch/error = %v", config.Name, err)
		}
	}
}

func TestSystemV1MigrationSetsUpGatewayRoleFromVerifiedBundleIdempotently(t *testing.T) {
	workspace, systemRoot, serverPrivate, _ := completeV1InspectionFixture(t)
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	manifest := v1MigrationGatewayManifest()
	bundlePath := filepath.Join(v1MigrationRealTempDir(t), "vpnctl-v2.bundle")
	writeV1FixtureFile(t, bundlePath, []byte("verified test bundle\n"), 0o600)
	if err := os.MkdirAll(filepath.Join(systemRoot, "etc", "systemd", "system"), 0o755); err != nil {
		t.Fatal(err)
	}
	paths, err := store.NewPaths(systemRoot)
	if err != nil {
		t.Fatal(err)
	}
	installer := &v1MigrationBundleInstallerStub{manifest: manifest}
	runner := &gatewayInitSystemdRunner{}
	network, err := linuxplatform.NewNetworkManager(runner)
	if err != nil {
		t.Fatal(err)
	}
	driver := &SystemV1MigrationDriver{
		root: systemRoot, paths: paths, bundles: installer, runner: runner, network: network,
		binaryPath: linuxplatform.DefaultVPNCTLBinaryPath, entropy: rand.Reader,
		keyRunner: gatewayInitWireGuardRunner{privateKey: serverPrivate, publicKey: inspection.Report.Server.WireGuardPublicKey},
	}
	verified, err := driver.VerifyBundle(context.Background(), bundlePath)
	if err != nil || !reflect.DeepEqual(verified, manifest) {
		t.Fatalf("verified bundle = %+v, err=%v", verified, err)
	}
	stageRoot := filepath.Join(v1MigrationRealTempDir(t), "v2-stage")
	if _, err := driver.EnsureConvertedStage(context.Background(), V1ConversionInput{
		Inspection: &inspection, StageRoot: stageRoot, PublicIPv4: "8.8.8.8", SSHPort: 22,
		NodeCIDR: model.DefaultNodeCIDR, ConvertedAt: time.Date(2026, 9, 4, 18, 0, 0, 0, time.UTC),
		Components: manifest.ComponentManifest,
		HandshakeHost: model.HandshakeHost{
			SchemaVersion: model.ResourceSchemaVersion, ListVersion: manifest.ComponentManifest.HandshakeHostListVersion,
			CandidateID: "migration-test", Hostname: "www.microsoft.com", SelectedAt: time.Date(2026, 9, 4, 18, 0, 0, 0, time.UTC),
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := driver.SetupGatewayRole(context.Background(), stageRoot, manifest, &inspection); err != nil {
		t.Fatal(err)
	}
	if err := driver.SetupGatewayRole(context.Background(), stageRoot, manifest, &inspection); err != nil {
		t.Fatal(err)
	}
	stateStore, _ := store.NewStateStore(paths)
	state, err := stateStore.Load()
	if err != nil || state.Host.Role != model.RoleGateway || state.Generation != 3 {
		t.Fatalf("published gateway state = %+v, err=%v", state, err)
	}
	if installer.installCalls != 2 || installer.role != model.RoleGateway {
		t.Fatalf("bundle install calls/role = %d/%s", installer.installCalls, installer.role)
	}
	if len(runner.calls) < 4 || runner.calls[0] != "systemctl stop wg-quick@wg0.service" || runner.calls[1] != "systemctl disable wg-quick@wg0.service" {
		t.Fatalf("v1 quiesce ordering = %v", runner.calls)
	}
}

func TestReleaseBundleInstallerReplacesOnlyCapturedV1BinaryAndRetainsBundle(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	snapshotRoot := filepath.Join(v1MigrationRealTempDir(t), "maintenance-snapshot")
	if _, err := (&SystemV1MigrationDriver{runner: v1MigrationSnapshotRunner{}, binaryPath: linuxplatform.DefaultVPNCTLBinaryPath}).CreateMaintenanceSnapshot(context.Background(), snapshotRoot, &inspection); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, artifacts, installed := releaseBundleFixture(t)
	bundlePath := filepath.Join(v1MigrationRealTempDir(t), "vpnctl-v2.bundle")
	writeReleaseBundleFile(t, bundlePath, manifest, privateKey, artifacts)
	installer, err := NewReleaseBundleInstaller(systemRoot, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := installer.InstallV1Migration(context.Background(), bundlePath, model.RoleGateway, snapshotRoot, linuxplatform.DefaultVPNCTLBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := installer.InstallV1Migration(context.Background(), bundlePath, model.RoleGateway, snapshotRoot, linuxplatform.DefaultVPNCTLBinaryPath)
	if err != nil || len(second.ChangedFiles) != 0 || len(first.ChangedFiles) != 4 {
		t.Fatalf("migration installs = %+v / %+v, err=%v", first, second, err)
	}
	assertReleaseInstalledFile(t, systemRoot, "usr/local/bin/vpnctl", installed["vpnctl"])
	assertReleaseInstalledFile(t, systemRoot, "usr/local/libexec/vpnctl/mihomo", installed["mihomo"])
	assertReleaseInstalledFile(t, systemRoot, "usr/local/libexec/vpnctl/frps", installed["frps"])
	retained, err := os.ReadFile(filepath.Join(systemRoot, strings.TrimPrefix(ReleaseInstalledBundlePath, "/")))
	source, sourceErr := os.ReadFile(bundlePath)
	if err != nil || sourceErr != nil || !reflect.DeepEqual(retained, source) {
		t.Fatalf("retained bundle mismatch: %v / %v", err, sourceErr)
	}
}

func TestSystemV1MigrationDisablesKnownUFWAndVerifiesTheResult(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	runner := &v1MigrationUFWRunner{systemRoot: systemRoot}
	driver := &SystemV1MigrationDriver{root: systemRoot, runner: runner}

	if err := driver.TranslateKnownUFW(context.Background(), &inspection); err != nil {
		t.Fatal(err)
	}
	if err := driver.TranslateKnownUFW(context.Background(), &inspection); err != nil {
		t.Fatal(err)
	}
	if runner.disableCalls != 1 {
		t.Fatalf("ufw disable calls = %d, want 1", runner.disableCalls)
	}
	config, err := os.ReadFile(filepath.Join(systemRoot, "etc", "ufw", "ufw.conf"))
	if err != nil || string(config) != "ENABLED=no\n" {
		t.Fatalf("ufw config = %q, err=%v", config, err)
	}
}

func TestSystemV1MigrationRejectsUFWDisableWithoutObservedStateChange(t *testing.T) {
	workspace, systemRoot, _, _ := completeV1InspectionFixture(t)
	inspection := inspectV1ImpactFixture(t, workspace, systemRoot)
	defer inspection.Destroy()
	driver := &SystemV1MigrationDriver{root: systemRoot, runner: &v1MigrationUFWRunner{systemRoot: systemRoot, leaveEnabled: true}}

	if err := driver.TranslateKnownUFW(context.Background(), &inspection); !errors.Is(err, ErrV1MigrationConflict) {
		t.Fatalf("unchanged UFW error = %v", err)
	}
}

type v1MigrationUFWRunner struct {
	systemRoot   string
	disableCalls int
	leaveEnabled bool
}

type v1MigrationSnapshotRunner struct{}

func (v1MigrationSnapshotRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	if command.Name != "systemctl" || len(command.Args) != 2 || command.Args[1] != "wg-quick@wg0.service" {
		return linuxplatform.ProbeResult{}, errors.New("unexpected snapshot command")
	}
	switch command.Args[0] {
	case "is-enabled":
		return linuxplatform.ProbeResult{Stdout: []byte("enabled\n")}, nil
	case "is-active":
		return linuxplatform.ProbeResult{Stdout: []byte("active\n")}, nil
	default:
		return linuxplatform.ProbeResult{}, errors.New("unexpected snapshot action")
	}
}

type v1MigrationBundleInstallerStub struct {
	manifest     ReleaseManifest
	installCalls int
	role         model.Role
}

func (installer *v1MigrationBundleInstallerStub) Inspect(context.Context, string) (ReleaseManifest, error) {
	return cloneReleaseManifest(installer.manifest), nil
}

func (installer *v1MigrationBundleInstallerStub) InstallV1Migration(_ context.Context, _ string, role model.Role, _, _ string) (ReleaseBundleInstallResult, error) {
	installer.installCalls++
	installer.role = role
	return ReleaseBundleInstallResult{Manifest: cloneReleaseManifest(installer.manifest)}, nil
}

func (installer *v1MigrationBundleInstallerStub) PreflightV1MigrationRemoval(context.Context, string, model.Role, string, string) (ReleaseManifest, error) {
	return installer.manifest, nil
}

func (installer *v1MigrationBundleInstallerStub) RemoveV1MigrationComponents(context.Context, string, model.Role, string, string) (ReleaseManifest, error) {
	return cloneReleaseManifest(installer.manifest), nil
}

func v1MigrationGatewayManifest() ReleaseManifest {
	manifest, _ := releaseManifestFixture()
	for index := range manifest.ComponentManifest.Components {
		component := &manifest.ComponentManifest.Components[index]
		if component.Name != transport.RestrictedProviderName {
			continue
		}
		component.Version = transport.RestrictedProviderVersion
		component.SHA256 = transport.RestrictedProviderSHA256
		component.Capabilities = []string{
			"redir-host-split-dns", "shadowsocks-2022-blake3-aes-256-gcm",
			"shadowtls-v3-strict", "tun-routing", "uot-v2",
		}
	}
	return manifest
}

func (runner *v1MigrationUFWRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	if command.Name != "ufw" || !reflect.DeepEqual(command.Args, []string{"--force", "disable"}) {
		return linuxplatform.ProbeResult{}, errors.New("unexpected migration command")
	}
	runner.disableCalls++
	if !runner.leaveEnabled {
		path := filepath.Join(runner.systemRoot, "etc", "ufw", "ufw.conf")
		data, err := os.ReadFile(path)
		if err != nil {
			return linuxplatform.ProbeResult{}, err
		}
		data = []byte(strings.ReplaceAll(string(data), "ENABLED=yes", "ENABLED=no"))
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return linuxplatform.ProbeResult{}, err
		}
	}
	return linuxplatform.ProbeResult{ExitCode: 0}, nil
}
