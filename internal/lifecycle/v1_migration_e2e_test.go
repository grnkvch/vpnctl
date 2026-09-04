package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/app"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	v1state "github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

const v1MigrationGoldenServerPublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

func TestV1MigrationE2EPreservesEveryClientGoldenAndProducesV2Exports(t *testing.T) {
	workspace, systemRoot, serverPrivate, serverPublic, clientPrivate, v1WireGuard, v1Clash := v1MigrationGoldenInstallation(t)
	beforeDryRun := snapshotV1InspectionTrees(t, workspace, systemRoot)
	inspector, err := NewV1InstallationInspector(workspace, systemRoot)
	if err != nil {
		t.Fatal(err)
	}

	// Exercise the real signed bundle decoder and verifier in the read-only
	// migration path. Provider-exact binary bytes are intentionally left to the
	// release bundle suite; the convergence half below uses its pinned manifest
	// through the same SystemV1MigrationDriver boundary.
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedManifest, signedArtifacts, _ := releaseBundleFixture(t)
	signedBundle := filepath.Join(v1MigrationRealTempDir(t), "signed-v2.bundle")
	writeReleaseBundleFile(t, signedBundle, signedManifest, privateKey, signedArtifacts)
	signedInstaller, err := NewReleaseBundleInstaller(systemRoot, publicKey, ReleasePlatform{
		OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	signedDriver := &SystemV1MigrationDriver{
		bundles:   signedInstaller,
		handshake: &recordingGatewayHandshakeHosts{selection: gatewayTestHandshakeHost()},
	}
	signedMigrator, err := NewV1Migrator(inspector, signedDriver)
	if err != nil {
		t.Fatal(err)
	}
	dryRunRoot := filepath.Join(v1MigrationRealTempDir(t), "signed-dry-run")
	plan, err := signedMigrator.Plan(context.Background(), V1MigrationInput{
		BundlePath: signedBundle, MaintenanceRoot: dryRunRoot, PublicIPv4: "198.211.99.116",
		NodeCIDR: model.DefaultNodeCIDR, SSHPort: 22,
	})
	if err != nil || plan.Status != "ready" || plan.ReleaseVersion != signedManifest.ComponentManifest.VPNCTLVersion {
		t.Fatalf("signed migration dry-run = %+v, err=%v", plan, err)
	}
	if _, err := os.Lstat(dryRunRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("signed dry-run created maintenance state: %v", err)
	}
	if after := snapshotV1InspectionTrees(t, workspace, systemRoot); !reflect.DeepEqual(beforeDryRun, after) {
		t.Fatal("signed migration dry-run changed the v1 installation")
	}

	paths, err := store.NewPaths(systemRoot)
	if err != nil {
		t.Fatal(err)
	}
	manifest := v1MigrationE2EPinnedManifest(t)
	providerBundle := filepath.Join(v1MigrationRealTempDir(t), "provider-exact-v2.bundle")
	writeV1FixtureFile(t, providerBundle, []byte("provider-exact bundle adapter fixture\n"), 0o600)
	runnerState := &v1MigrationRecoveryRunner{
		systemRoot: systemRoot, v1Enabled: true, v1Active: true, ufwEnabled: true,
	}
	runner := &v1MigrationE2EProbeRunner{base: runnerState}
	network, err := linuxplatform.NewNetworkManager(runner)
	if err != nil {
		t.Fatal(err)
	}
	watchdog := &v1MigrationE2EWatchdog{status: V1MigrationWatchdogArmed}
	driver := &SystemV1MigrationDriver{
		root: systemRoot, paths: paths,
		bundles:    &v1MigrationBundleInstallerStub{manifest: manifest},
		handshake:  &recordingGatewayHandshakeHosts{selection: gatewayTestHandshakeHost()},
		runner:     runner,
		network:    network,
		binaryPath: linuxplatform.DefaultVPNCTLBinaryPath,
		keyRunner:  v1MigrationE2EWireGuardRunner{gatewayPrivate: serverPrivate},
		entropy:    rand.Reader,
		watchdog:   watchdog,
	}
	migrator, err := NewV1Migrator(inspector, driver)
	if err != nil {
		t.Fatal(err)
	}
	migrator.now = func() time.Time { return time.Date(2026, 9, 4, 20, 0, 0, 0, time.UTC) }
	maintenanceRoot := filepath.Join(v1MigrationRealTempDir(t), "migration-e2e")
	input := V1MigrationInput{
		BundlePath: providerBundle, MaintenanceRoot: maintenanceRoot, PublicIPv4: "198.211.99.116",
		NodeCIDR: model.DefaultNodeCIDR, SSHPort: 22,
		SSHConnection: "192.0.2.10 50123 198.211.99.116 22",
	}
	pending, err := migrator.Run(context.Background(), input)
	if err != nil || pending.Status != "awaiting_network_confirmation" || pending.WatchdogTransactionID == "" {
		t.Fatalf("migration before SSH confirmation = %+v, err=%v", pending, err)
	}
	if err := watchdog.Commit(pending.WatchdogTransactionID); err != nil {
		t.Fatal(err)
	}
	completed, err := migrator.Run(context.Background(), input)
	if err != nil || completed.Status != "complete" || !reflect.DeepEqual(completed.CompletedPhases, v1MigrationPhaseOrder) {
		t.Fatalf("completed migration = %+v, err=%v", completed, err)
	}
	if len(completed.Clients) != 1 || completed.Clients[0].Status != "valid" ||
		!completed.Clients[0].AddressKept || !completed.Clients[0].KeyPairKept || completed.Clients[0].ProfileStatus != "preserved" {
		t.Fatalf("migrated client acceptance = %+v", completed.Clients)
	}
	if runnerState.v1Enabled || runnerState.v1Active || runnerState.ufwEnabled {
		t.Fatalf("migration did not quiesce v1 ownership: wg enabled=%t active=%t ufw=%t", runnerState.v1Enabled, runnerState.v1Active, runnerState.ufwEnabled)
	}

	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Generation != 3 || len(migrated.Clients) != 1 || migrated.Clients[0].OverlayIPv4 != "10.66.0.2" ||
		migrated.Clients[0].CredentialGeneration != 1 || !reflect.DeepEqual(migrated.Clients[0].AssignedPresets, []string{"default"}) {
		t.Fatalf("migrated client state = generation %d, clients %+v", migrated.Generation, migrated.Clients)
	}
	clientID := migrated.Clients[0].ID
	standard, restrictedTransport := migratedClientTransports(t, migrated, clientID)
	if standard.PublicKey == "" || restrictedTransport.State != model.TransportStandby ||
		restrictedTransport.HandshakeHost != migrated.HandshakeHost.Hostname {
		t.Fatalf("migrated transports = standard %+v restricted %+v", standard, restrictedTransport)
	}
	secretStore, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	standardSecret, err := secretStore.Get(standard.CredentialRef)
	if err != nil || string(standardSecret) != clientPrivate {
		t.Fatalf("retained WireGuard credential differs: %v", err)
	}
	clear(standardSecret)
	restrictedSecret, err := secretStore.Get(restrictedTransport.CredentialRef)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restricted.DecodeIdentitySecret(restrictedSecret); err != nil {
		t.Fatalf("new restricted client credential is invalid: %v", err)
	}
	clear(restrictedSecret)

	for source, content := range map[string][]byte{"iphone.conf": v1WireGuard, "iphone.clash.yaml": v1Clash} {
		preserved := filepath.Join(paths.ExportsDir, "v1-preserved", "generated", "delivery", source)
		got, err := os.ReadFile(preserved)
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("preserved v1 profile %s differs: %v", source, err)
		}
	}

	exporter, err := routing.NewClientExporter(paths, stateStore, secretStore)
	if err != nil {
		t.Fatal(err)
	}
	wireGuardResult, err := exporter.Export(routing.ClientExportRequest{
		ClientReference: clientID, Format: routing.ClientExportWireGuard, GatewayPublicKey: serverPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	v2WireGuard, err := os.ReadFile(wireGuardResult.OutputPath)
	if err != nil || !bytes.Equal(v2WireGuard, v1WireGuard) {
		t.Fatalf("v2 WireGuard export does not byte-match the retained v1 profile: %v\nv1:\n%s\nv2:\n%s", err, v1WireGuard, v2WireGuard)
	}
	clashResult, err := exporter.Export(routing.ClientExportRequest{
		ClientReference: clientID, Format: routing.ClientExportClash, GatewayPublicKey: serverPublic,
	})
	if err != nil {
		t.Fatal(err)
	}
	v2Clash, err := os.ReadFile(clashResult.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	assertMigratedV2ClashSemantics(t, v1Clash, v2Clash, serverPublic, clientPrivate)
	validateMigratedClashWithPinnedMihomo(t, clashResult.OutputPath)
}

func v1MigrationGoldenInstallation(t *testing.T) (workspace, systemRoot, serverPrivate, serverPublic, clientPrivate string, wireGuardProfile, clashProfile []byte) {
	t.Helper()
	workspace, systemRoot, serverPrivate, clientPrivate = completeV1InspectionFixture(t)
	if err := os.MkdirAll(filepath.Join(systemRoot, "etc", "systemd", "system"), 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(workspace, ".vpnctl")
	state, err := v1state.Load(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	state.Server.PublicEndpoint = "198.211.99.116"
	if err := v1state.Save(stateDir, state); err != nil {
		t.Fatal(err)
	}
	serverPublic = state.Server.WireGuardPublicKey

	wireGuardResult, err := app.ExportClient(app.ExportClientInput{
		StateDir: stateDir, ClientID: "iphone", Type: app.ExportTypeWireGuard,
	})
	if err != nil {
		t.Fatal(err)
	}
	clashResult, err := app.ExportClient(app.ExportClientInput{
		StateDir: stateDir, ClientID: "iphone", Type: app.ExportTypeClash, Ruleset: app.DefaultRulesetID,
	})
	if err != nil {
		t.Fatal(err)
	}
	wireGuardProfile, err = os.ReadFile(wireGuardResult.Path)
	if err != nil {
		t.Fatal(err)
	}
	clashProfile, err = os.ReadFile(clashResult.Path)
	if err != nil {
		t.Fatal(err)
	}

	goldens := v1MigrationClientGoldens(t)
	wantWireGuard := bytes.ReplaceAll(goldens["iphone.wireguard.conf"], []byte(v1MigrationGoldenServerPublicKey), []byte(serverPublic))
	wantClash := bytes.ReplaceAll(goldens["iphone.clash.yaml"], []byte(v1MigrationGoldenServerPublicKey), []byte(serverPublic))
	if !bytes.Equal(wireGuardProfile, wantWireGuard) {
		t.Fatalf("representative WireGuard profile diverged from the checked-in golden after cryptographic key normalization:\n%s", wireGuardProfile)
	}
	if !bytes.Equal(clashProfile, wantClash) {
		t.Fatalf("representative Clash profile diverged from the checked-in golden after cryptographic key normalization:\n%s", clashProfile)
	}
	return workspace, systemRoot, serverPrivate, serverPublic, clientPrivate, wireGuardProfile, clashProfile
}

func v1MigrationClientGoldens(t *testing.T) map[string][]byte {
	t.Helper()
	root := filepath.Join("..", "regression", "testdata", "v1")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string][]byte{}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "server.wireguard.conf" ||
			!(strings.HasSuffix(entry.Name(), ".wireguard.conf") || strings.HasSuffix(entry.Name(), ".clash.yaml")) {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		profiles[entry.Name()] = content
	}
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"iphone.clash.yaml", "iphone.wireguard.conf"}) {
		t.Fatalf("unaccounted v1 client golden profiles: %v", names)
	}
	return profiles
}

func v1MigrationE2EPinnedManifest(t *testing.T) ReleaseManifest {
	t.Helper()
	manifest := v1MigrationGatewayManifest()
	for index := range manifest.Artifacts {
		if manifest.Artifacts[index].Component == transport.RestrictedProviderName {
			manifest.Artifacts[index].SHA256 = transport.RestrictedProviderSHA256
		}
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func migratedClientTransports(t *testing.T, state model.State, clientID string) (model.Transport, model.Transport) {
	t.Helper()
	var standard, restrictedTransport model.Transport
	for _, record := range state.Transports {
		if record.OwnerKind != model.TargetClient || record.OwnerID != clientID {
			continue
		}
		switch record.Kind {
		case model.TransportStandard:
			standard = record
		case model.TransportRestricted:
			restrictedTransport = record
		}
	}
	if standard.Kind == "" || restrictedTransport.Kind == "" {
		t.Fatalf("migrated client transports are incomplete: %+v", state.Transports)
	}
	return standard, restrictedTransport
}

func assertMigratedV2ClashSemantics(t *testing.T, v1Profile, v2Profile []byte, serverPublic, clientPrivate string) {
	t.Helper()
	v1, v2 := string(v1Profile), string(v2Profile)
	for _, retained := range []string{
		"server: 198.211.99.116\n", "port: 51820\n", "ip: 10.66.0.2\n",
		"private-key: \"" + clientPrivate + "\"\n", "public-key: \"" + serverPublic + "\"\n",
		"mtu: 1420\n", "udp: true\n", "- 0.0.0.0/0\n",
	} {
		if !strings.Contains(v1, retained) || !strings.Contains(v2, retained) {
			t.Errorf("retained Clash standard semantic %q is missing", retained)
		}
	}
	for _, domain := range []string{"chatgpt.com", "openai.com", "claude.ai", "anthropic.com"} {
		if !strings.Contains(v1, "DOMAIN-SUFFIX,"+domain+",VPN") ||
			!strings.Contains(v2, "DOMAIN-SUFFIX,"+domain+",VPNCTL-GATEWAY") ||
			!strings.Contains(v2, "\"+."+domain+"\":\n      - \"udp://10.66.0.1:53#VPNCTL-GATEWAY\"") {
			t.Errorf("migrated Clash policy lost selected domain %s", domain)
		}
	}
	for _, required := range []string{
		"mode: rule\n", "log-level: silent\n", "geo-auto-update: false\n", "enhanced-mode: redir-host\n",
		"name: VPNCTL-STANDARD\n", "name: VPNCTL-RESTRICTED\n", "type: ss\n", "port: 8443\n",
		"udp-over-tcp: true\n", "udp-over-tcp-version: 2\n", "plugin: shadow-tls\n", "strict-mode: true\n",
		"- MATCH,DIRECT\n",
	} {
		if !strings.Contains(v2, required) {
			t.Errorf("v2 Clash profile is missing %q", required)
		}
	}
	groupStart, rulesStart := strings.Index(v2, "proxy-groups:\n"), strings.Index(v2, "\nrules:\n")
	if groupStart < 0 || rulesStart <= groupStart {
		t.Fatalf("v2 Clash group/rule layout is invalid:\n%s", v2)
	}
	group := v2[groupStart:rulesStart]
	for _, forbidden := range []string{"DIRECT", "fallback", "url-test", "load-balance", "health-check", "interval:", "tolerance:"} {
		if strings.Contains(group, forbidden) {
			t.Errorf("migrated Clash gateway group contains forbidden automatic/direct choice %q:\n%s", forbidden, group)
		}
	}
	if strings.Index(group, "- VPNCTL-STANDARD\n") < 0 || strings.Index(group, "- VPNCTL-RESTRICTED\n") < 0 ||
		strings.Index(group, "- VPNCTL-STANDARD\n") > strings.Index(group, "- VPNCTL-RESTRICTED\n") {
		t.Errorf("migrated Clash alternatives are not an explicit standard-first manual choice:\n%s", group)
	}
}

func validateMigratedClashWithPinnedMihomo(t *testing.T, profilePath string) {
	t.Helper()
	binary := os.Getenv("VPNCTL_PINNED_MIHOMO")
	if binary == "" {
		t.Log("pinned Mihomo parse skipped; set VPNCTL_PINNED_MIHOMO in the Linux acceptance fixture")
		return
	}
	version, err := exec.Command(binary, "-v").CombinedOutput()
	if err != nil || !strings.Contains(string(version), transport.RestrictedProviderVersion) {
		t.Fatalf("Mihomo runtime is not pinned %s: %v: %s", transport.RestrictedProviderVersion, err, version)
	}
	output, err := exec.Command(binary, "-t", "-d", filepath.Dir(profilePath), "-f", profilePath).CombinedOutput()
	if err != nil {
		t.Fatalf("pinned Mihomo rejected migrated Clash profile: %v:\n%s", err, output)
	}
}

type v1MigrationE2EProbeRunner struct {
	base  *v1MigrationRecoveryRunner
	calls []linuxplatform.ProbeCommand
}

func (runner *v1MigrationE2EProbeRunner) Run(ctx context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	runner.calls = append(runner.calls, command)
	switch command.Name {
	case "nft", "sysctl":
		return linuxplatform.ProbeResult{}, nil
	default:
		return runner.base.Run(ctx, command)
	}
}

type v1MigrationE2EWireGuardRunner struct{ gatewayPrivate string }

func (runner v1MigrationE2EWireGuardRunner) Run(_ context.Context, name string, arguments []string, input string) (string, error) {
	if name != "wg" {
		return "", errors.New("unexpected migration E2E WireGuard command")
	}
	if reflect.DeepEqual(arguments, []string{"genkey"}) {
		return runner.gatewayPrivate + "\n", nil
	}
	if reflect.DeepEqual(arguments, []string{"pubkey"}) {
		publicKey, err := v1WireGuardPublicKey([]byte(strings.TrimSpace(input)))
		if err != nil {
			return "", err
		}
		return publicKey + "\n", nil
	}
	return "", errors.New("unexpected migration E2E WireGuard arguments")
}

type v1MigrationE2EWatchdog struct {
	transactionID string
	status        V1MigrationWatchdogStatus
}

func (watchdog *v1MigrationE2EWatchdog) ArmPrepared(_ context.Context, _ int, _ *linuxplatform.SSHConnection, prepared func(V1MigrationWatchdogTransaction) error) (V1MigrationWatchdogTransaction, error) {
	transaction := V1MigrationWatchdogTransaction{ID: "fw-7K3M2P"}
	if watchdog.transactionID != "" {
		transaction.ID = watchdog.transactionID
		return transaction, nil
	}
	if err := prepared(transaction); err != nil {
		return V1MigrationWatchdogTransaction{}, err
	}
	watchdog.transactionID = transaction.ID
	watchdog.status = V1MigrationWatchdogArmed
	return transaction, nil
}

func (watchdog *v1MigrationE2EWatchdog) EnsureTimer(context.Context, string) error { return nil }

func (watchdog *v1MigrationE2EWatchdog) MarkActivated(_ context.Context, transactionID string) error {
	if transactionID != watchdog.transactionID || watchdog.status != V1MigrationWatchdogArmed {
		return errors.New("migration E2E watchdog activation is out of order")
	}
	watchdog.status = V1MigrationWatchdogActive
	return nil
}

func (watchdog *v1MigrationE2EWatchdog) Status(_ context.Context, transactionID string) (V1MigrationWatchdogStatus, error) {
	if transactionID != watchdog.transactionID {
		return "", errors.New("unknown migration E2E watchdog transaction")
	}
	return watchdog.status, nil
}

func (watchdog *v1MigrationE2EWatchdog) Restore(_ context.Context, transactionID string) error {
	if transactionID != watchdog.transactionID {
		return errors.New("unknown migration E2E watchdog transaction")
	}
	watchdog.status = V1MigrationWatchdogRolledBack
	return nil
}

func (watchdog *v1MigrationE2EWatchdog) Commit(transactionID string) error {
	if transactionID != watchdog.transactionID || watchdog.status != V1MigrationWatchdogActive {
		return errors.New("migration E2E watchdog commit is out of order")
	}
	watchdog.status = V1MigrationWatchdogCommitted
	return nil
}
