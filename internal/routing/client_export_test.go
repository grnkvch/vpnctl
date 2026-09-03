package routing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/render"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestClientExporterPublishesManagedClashProfileAndSafeOutput(t *testing.T) {
	t.Parallel()

	fixture := newClientExporterFixture(t)
	result, err := fixture.exporter.Export(ClientExportRequest{
		ClientReference: fixture.clientID, Format: ClientExportClash,
		GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatalf("Export(clash) error = %v", err)
	}
	wantPath := filepath.Join(fixture.paths.ClientExportsDir, "iphone.clash.yaml")
	if result.ClientID != fixture.clientID || result.ClientName != "iphone" || result.Format != ClientExportClash ||
		result.OutputPath != wantPath || !result.ManagedPath || result.FileMode != "0600" ||
		result.SourceStateGeneration != 2 || result.PolicyGeneration != 1 || result.CredentialGeneration != 1 {
		t.Fatalf("Export(clash) = %#v", result)
	}
	if got, want := result.SCPHint, "scp root@203.0.113.10:"+wantPath+" ."; got != want {
		t.Fatalf("SCP hint = %q, want %q", got, want)
	}

	content := readExportFile(t, wantPath, clientExportFileMode)
	if !bytes.Contains(content, []byte(fixture.privateKey)) || !bytes.Contains(content, []byte("DOMAIN-SUFFIX,telegram.org,VPNCTL-GATEWAY")) {
		t.Fatalf("managed Clash profile lost credential or selected rule:\n%s", content)
	}
	assertDirectoryMode(t, fixture.paths.ExportsDir, clientExportDirectoryMode)
	assertDirectoryMode(t, fixture.paths.ClientExportsDir, clientExportDirectoryMode)
	assertDirectoryMode(t, filepath.Join(fixture.paths.ClientExportsDir, clientExportMetadataDir), clientExportDirectoryMode)

	manifest := readClientExportManifest(t, result.metadataPath)
	if manifest.SourceStateGeneration != result.SourceStateGeneration || len(manifest.Artifacts) != 1 {
		t.Fatalf("Clash export manifest = %#v", manifest)
	}
	record := manifest.Artifacts[0]
	digest := sha256.Sum256(content)
	if record.Path != wantPath || record.Mode != "0600" || record.ContentSHA256 != hex.EncodeToString(digest[:]) ||
		!reflect.DeepEqual(record.PolicyGenerations, []render.SourceGeneration{{Kind: "client-policy", ID: fixture.clientID, Generation: 1}}) ||
		!reflect.DeepEqual(record.CredentialGenerations, []render.SourceGeneration{{Kind: "client-credential", ID: fixture.clientID, Generation: 1}}) {
		t.Fatalf("Clash artifact record = %#v", record)
	}

	public := result.OutputResult()
	if err := public.Validate(); err != nil {
		t.Fatalf("OutputResult().Validate() error = %v", err)
	}
	var human bytes.Buffer
	if err := output.RenderHuman(&human, public); err != nil {
		t.Fatalf("RenderHuman() error = %v", err)
	}
	var machine bytes.Buffer
	if err := output.RenderJSON(&machine, public); err != nil {
		t.Fatalf("RenderJSON() error = %v", err)
	}
	for name, rendered := range map[string]string{"human": human.String(), "json": machine.String()} {
		if !strings.Contains(rendered, wantPath) || !strings.Contains(rendered, "scp root@203.0.113.10:") {
			t.Fatalf("%s output omitted path/copy action: %s", name, rendered)
		}
		for _, forbidden := range []string{fixture.privateKey, "private-key", "wireguard:", "proxies:", record.ContentSHA256, result.metadataPath} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("%s output exposed %q: %s", name, forbidden, rendered)
			}
		}
	}
	var decoded map[string]any
	if err := json.Unmarshal(machine.Bytes(), &decoded); err != nil {
		t.Fatalf("decode JSON output: %v", err)
	}
	if got := decoded["data"].(map[string]any); len(got) != 3 || got["output_path"] != wantPath || got["file_mode"] != "0600" {
		t.Fatalf("JSON export data = %#v", got)
	}
}

func TestClientExporterPlanIsReadOnlySecretFreeAndRejectsTampering(t *testing.T) {
	t.Parallel()

	fixture := newClientExporterFixture(t)
	plan, err := fixture.exporter.Plan(ClientExportRequest{
		ClientReference: "iphone", Format: ClientExportClash,
		GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatalf("Plan(clash) error = %v", err)
	}
	if plan.ClientID != fixture.clientID || plan.OutputPath != filepath.Join(fixture.paths.ClientExportsDir, "iphone.clash.yaml") ||
		!plan.ManagedPath || plan.PolicyGeneration != 1 || plan.CredentialGeneration != 1 {
		t.Fatalf("Plan(clash) = %#v", plan)
	}
	if _, err := os.Stat(fixture.paths.ExportsDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Plan(clash) created export directory: %v", err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("Marshal(plan) error = %v", err)
	}
	for _, forbidden := range []string{fixture.privateKey, "private-key", "proxies:", v1CompatibleServerPublicKey, ".metadata"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("plan JSON exposed %q: %s", forbidden, encoded)
		}
	}
	formatted := fmt.Sprintf("%s %v %q %#v %+v", plan, plan, plan, plan, plan)
	if strings.Contains(formatted, fixture.privateKey) || strings.Contains(formatted, v1CompatibleServerPublicKey) ||
		strings.Count(formatted, clientExportPlanMarker) != 5 {
		t.Fatalf("ordinary plan formatting was not redacted: %s", formatted)
	}
	dryRun := plan.OutputResult()
	if err := dryRun.Validate(); err != nil || len(dryRun.RequiresAction) != 0 {
		t.Fatalf("dry-run OutputResult() = %#v, %v", dryRun, err)
	}

	tampered := plan
	tampered.OutputPath = filepath.Join(fixture.paths.Root, "tampered.yaml")
	if _, err := fixture.exporter.Commit(tampered); err == nil || !strings.Contains(err.Error(), "changed or was modified") {
		t.Fatalf("Commit(tampered plan) error = %v", err)
	}
	if _, err := os.Stat(fixture.paths.ExportsDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Commit(tampered plan) created export directory: %v", err)
	}
}

func TestClientExporterCommitRejectsStateChangedAfterPlan(t *testing.T) {
	t.Parallel()

	fixture := newClientExporterFixture(t)
	plan, err := fixture.exporter.Plan(ClientExportRequest{
		ClientReference: "iphone", Format: ClientExportClash,
		GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatalf("Plan(clash) error = %v", err)
	}
	policyManager, err := NewPolicyManager(fixture.paths, fixture.stateStore)
	if err != nil {
		t.Fatalf("NewPolicyManager() error = %v", err)
	}
	policyPlan, err := policyManager.PlanClientSet(fixture.clientID, []string{"openai"})
	if err != nil {
		t.Fatalf("PlanClientSet() error = %v", err)
	}
	if _, err := policyManager.Commit(policyPlan); err != nil {
		t.Fatalf("Commit(policy replacement) error = %v", err)
	}
	if _, err := fixture.exporter.Commit(plan); err == nil || !strings.Contains(err.Error(), "changed or was modified") {
		t.Fatalf("Commit(stale export plan) error = %v", err)
	}
	if _, err := os.Stat(fixture.paths.ExportsDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Commit(stale export plan) created export directory: %v", err)
	}
}

func TestClientExporterPublishesWireGuardWithoutPolicyDependencyAndReplacesManagedPath(t *testing.T) {
	t.Parallel()

	fixture := newClientExporterFixture(t)
	request := ClientExportRequest{
		ClientReference: "IPHONE", Format: ClientExportWireGuard,
		GatewayPublicKey: v1CompatibleServerPublicKey,
	}
	first, err := fixture.exporter.Export(request)
	if err != nil {
		t.Fatalf("Export(wireguard) error = %v", err)
	}
	wantPath := filepath.Join(fixture.paths.ClientExportsDir, "iphone.wireguard.conf")
	if first.OutputPath != wantPath || first.PolicyGeneration != 0 || first.CredentialGeneration != 1 {
		t.Fatalf("Export(wireguard) = %#v", first)
	}
	firstContent := readExportFile(t, wantPath, clientExportFileMode)
	if !bytes.Contains(firstContent, []byte(fixture.privateKey)) || !bytes.Contains(firstContent, []byte("AllowedIPs = 0.0.0.0/0")) {
		t.Fatalf("WireGuard export is not a full-tunnel profile:\n%s", firstContent)
	}
	manifest := readClientExportManifest(t, first.metadataPath)
	if len(manifest.Artifacts) != 1 || manifest.Artifacts[0].PolicyGenerations == nil || len(manifest.Artifacts[0].PolicyGenerations) != 0 {
		t.Fatalf("WireGuard manifest has a policy dependency: %#v", manifest)
	}

	if err := os.WriteFile(wantPath, []byte("operator edit\n"), 0o644); err != nil {
		t.Fatalf("replace managed export fixture: %v", err)
	}
	second, err := fixture.exporter.Export(request)
	if err != nil {
		t.Fatalf("explicit managed re-export error = %v", err)
	}
	secondContent := readExportFile(t, wantPath, clientExportFileMode)
	if !bytes.Equal(secondContent, firstContent) || second.OutputPath != first.OutputPath {
		t.Fatalf("managed re-export was not deterministic/atomic:\nfirst %q\nsecond %q", firstContent, secondContent)
	}
	assertNoExportTemporaryFiles(t, fixture.paths.ClientExportsDir)
}

func TestClientExporterRequiresForceForExistingCustomOutput(t *testing.T) {
	t.Parallel()

	fixture := newClientExporterFixture(t)
	custom := filepath.Join(fixture.paths.Root, "operator exports", "phone.yaml")
	if err := os.MkdirAll(filepath.Dir(custom), 0o755); err != nil {
		t.Fatalf("create custom parent: %v", err)
	}
	original := []byte("keep this file\n")
	if err := os.WriteFile(custom, original, 0o640); err != nil {
		t.Fatalf("create custom output: %v", err)
	}
	request := ClientExportRequest{
		ClientReference: "iphone", Format: ClientExportClash, OutputPath: custom,
		GatewayPublicKey: v1CompatibleServerPublicKey,
	}
	if _, err := fixture.exporter.Export(request); !errors.Is(err, ErrClientExportExists) {
		t.Fatalf("Export(existing custom) error = %v, want ErrClientExportExists", err)
	}
	if got := readExportFile(t, custom, 0o640); !bytes.Equal(got, original) {
		t.Fatalf("refused custom export changed existing bytes: %q", got)
	}
	if _, err := os.Stat(fixture.exporter.metadataPath(fixture.clientID, ClientExportClash)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused custom export created metadata: %v", err)
	}

	request.Force = true
	result, err := fixture.exporter.Export(request)
	if err != nil {
		t.Fatalf("Export(existing custom --force) error = %v", err)
	}
	if result.ManagedPath || result.OutputPath != custom || !strings.Contains(result.SCPHint, "'root@203.0.113.10:") {
		t.Fatalf("forced custom export result = %#v", result)
	}
	forced := readExportFile(t, custom, clientExportFileMode)
	if bytes.Equal(forced, original) || !bytes.Contains(forced, []byte(fixture.privateKey)) {
		t.Fatalf("forced custom export did not replace content: %q", forced)
	}
	if got := fileMode(t, filepath.Dir(custom)); got != 0o755 {
		t.Fatalf("existing custom directory mode = %04o, want unchanged 0755", got)
	}
	assertNoExportTemporaryFiles(t, filepath.Dir(custom))
}

func TestClientExporterCreatesPrivateCustomDirectoryAndRejectsSymlinkTargets(t *testing.T) {
	t.Parallel()

	fixture := newClientExporterFixture(t)
	custom := filepath.Join(fixture.paths.Root, "new", "nested", "phone.conf")
	result, err := fixture.exporter.Export(ClientExportRequest{
		ClientReference: "iphone", Format: ClientExportWireGuard, OutputPath: custom,
		GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatalf("Export(new custom) error = %v", err)
	}
	if result.ManagedPath || result.OutputPath != custom {
		t.Fatalf("Export(new custom) = %#v", result)
	}
	assertDirectoryMode(t, filepath.Dir(custom), clientExportDirectoryMode)
	readExportFile(t, custom, clientExportFileMode)

	target := filepath.Join(fixture.paths.Root, "do-not-touch")
	if err := os.WriteFile(target, []byte("safe\n"), 0o600); err != nil {
		t.Fatalf("create symlink target: %v", err)
	}
	link := filepath.Join(filepath.Dir(custom), "linked.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create output symlink: %v", err)
	}
	_, err = fixture.exporter.Export(ClientExportRequest{
		ClientReference: "iphone", Format: ClientExportWireGuard, OutputPath: link, Force: true,
		GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if !errors.Is(err, ErrClientExportUnsafe) {
		t.Fatalf("Export(symlink --force) error = %v, want ErrClientExportUnsafe", err)
	}
	if got, readErr := os.ReadFile(target); readErr != nil || string(got) != "safe\n" {
		t.Fatalf("symlink target changed: %q, %v", got, readErr)
	}
}

func TestClientExportManifestsTrackFormatSpecificStaleness(t *testing.T) {
	t.Parallel()

	fixture := newClientExporterFixture(t)
	clash, err := fixture.exporter.Export(ClientExportRequest{
		ClientReference: "iphone", Format: ClientExportClash, GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatalf("Export(clash) error = %v", err)
	}
	wireGuard, err := fixture.exporter.Export(ClientExportRequest{
		ClientReference: "iphone", Format: ClientExportWireGuard, GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatalf("Export(wireguard) error = %v", err)
	}
	previousClash := readClientExportManifest(t, clash.metadataPath)
	previousWireGuard := readClientExportManifest(t, wireGuard.metadataPath)

	policyManager, err := NewPolicyManager(fixture.paths, fixture.stateStore)
	if err != nil {
		t.Fatalf("NewPolicyManager() error = %v", err)
	}
	plan, err := policyManager.PlanClientSet(fixture.clientID, []string{"openai"})
	if err != nil {
		t.Fatalf("PlanClientSet() error = %v", err)
	}
	if _, err := policyManager.Commit(plan); err != nil {
		t.Fatalf("Commit(policy replacement) error = %v", err)
	}

	currentClash := renderClientExportForTest(t, fixture.exporter, ClientExportRequest{
		ClientReference: "iphone", Format: ClientExportClash, GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	desiredClash, err := buildClientExportManifest(clash.OutputPath, currentClash)
	if err != nil {
		t.Fatalf("build desired Clash manifest: %v", err)
	}
	changes, err := render.CompareManifests(previousClash, desiredClash)
	if err != nil || !reflect.DeepEqual(changes, []render.ArtifactChange{{Path: clash.OutputPath, Kind: render.ArtifactUpdated}}) {
		t.Fatalf("Clash policy staleness = %#v, %v", changes, err)
	}

	currentWireGuard := renderClientExportForTest(t, fixture.exporter, ClientExportRequest{
		ClientReference: "iphone", Format: ClientExportWireGuard, GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	desiredWireGuard, err := buildClientExportManifest(wireGuard.OutputPath, currentWireGuard)
	if err != nil {
		t.Fatalf("build desired WireGuard manifest: %v", err)
	}
	changes, err = render.CompareManifests(previousWireGuard, desiredWireGuard)
	if err != nil || len(changes) != 0 {
		t.Fatalf("WireGuard policy-only staleness = %#v, %v; want current", changes, err)
	}

	currentClashManifest, err := buildClientExportManifest(clash.OutputPath, currentClash)
	if err != nil {
		t.Fatalf("build current Clash manifest: %v", err)
	}
	currentWireGuardManifest, err := buildClientExportManifest(wireGuard.OutputPath, currentWireGuard)
	if err != nil {
		t.Fatalf("build current WireGuard manifest: %v", err)
	}
	rotatedClash := currentClash
	rotatedClash.credentialGeneration++
	rotatedWireGuard := currentWireGuard
	rotatedWireGuard.credentialGeneration++
	for name, test := range map[string]struct {
		previous render.ArtifactManifest
		path     string
		profile  renderedClientExport
	}{
		"clash":     {currentClashManifest, clash.OutputPath, rotatedClash},
		"wireguard": {currentWireGuardManifest, wireGuard.OutputPath, rotatedWireGuard},
	} {
		desired, buildErr := buildClientExportManifest(test.path, test.profile)
		if buildErr != nil {
			t.Fatalf("build %s rotated manifest: %v", name, buildErr)
		}
		changes, compareErr := render.CompareManifests(test.previous, desired)
		if compareErr != nil || !reflect.DeepEqual(changes, []render.ArtifactChange{{Path: test.path, Kind: render.ArtifactUpdated}}) {
			t.Fatalf("%s credential staleness = %#v, %v", name, changes, compareErr)
		}
	}
}

func TestHandshakeHostReplacementStalesOnlyAffectedClashExport(t *testing.T) {
	t.Parallel()

	fixture := newClientExporterFixture(t)
	state := loadPolicyState(t, fixture.stateStore)
	restrictedCredential, err := model.NewSecretRef("client-restricted", fixture.clientID)
	if err != nil {
		t.Fatalf("NewSecretRef(restricted) error = %v", err)
	}
	state.Generation++
	state.Transports = append(append([]model.Transport(nil), state.Transports...), model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetClient, OwnerID: fixture.clientID,
		Kind: model.TransportRestricted, State: model.TransportStandby, Provider: "mihomo", Protocol: model.ProtocolTCP,
		Port: 8443, CredentialGeneration: 1, CredentialRef: restrictedCredential,
		HandshakeHost: state.HandshakeHost.Hostname, ConfigHash: strings.Repeat("e", 64),
	})
	if err := fixture.stateStore.Save(state.Generation-1, state); err != nil {
		t.Fatalf("Save(restricted client transport) error = %v", err)
	}

	clash, err := fixture.exporter.Export(ClientExportRequest{
		ClientReference: fixture.clientID, Format: ClientExportClash, GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatalf("Export(clash) error = %v", err)
	}
	wireGuard, err := fixture.exporter.Export(ClientExportRequest{
		ClientReference: fixture.clientID, Format: ClientExportWireGuard, GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatalf("Export(wireguard) error = %v", err)
	}
	previousClash := readClientExportManifest(t, clash.metadataPath)
	previousWireGuard := readClientExportManifest(t, wireGuard.metadataPath)
	wantSource := []render.SourceGeneration{{Kind: "handshake-host", ID: state.HandshakeHost.CandidateID, Generation: uint64(state.HandshakeHost.ListVersion)}}
	if !reflect.DeepEqual(previousClash.Artifacts[0].SourceGenerations, wantSource) {
		t.Fatalf("Clash handshake-host dependency = %#v, want %#v", previousClash.Artifacts[0].SourceGenerations, wantSource)
	}
	if len(previousWireGuard.Artifacts[0].SourceGenerations) != 0 {
		t.Fatalf("WireGuard unexpectedly depends on handshake host: %#v", previousWireGuard.Artifacts[0].SourceGenerations)
	}
	clashBytes := readExportFile(t, clash.OutputPath, clientExportFileMode)
	wireGuardBytes := readExportFile(t, wireGuard.OutputPath, clientExportFileMode)

	changed := state
	changed.Generation++
	changed.HandshakeHost = &model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: state.HandshakeHost.ListVersion,
		CandidateID: "apple", Hostname: "www.apple.com", SelectedAt: state.HandshakeHost.SelectedAt.Add(time.Hour),
	}
	changed.Transports = append([]model.Transport(nil), state.Transports...)
	for index := range changed.Transports {
		if changed.Transports[index].Kind == model.TransportRestricted {
			changed.Transports[index].HandshakeHost = changed.HandshakeHost.Hostname
		}
	}
	if err := changed.Validate(); err != nil {
		t.Fatalf("Validate(changed handshake host) error = %v", err)
	}
	changedStore := &clientExportStaticStateStore{state: changed}
	fixture.exporter.state = changedStore
	fixture.exporter.clash.state = changedStore
	fixture.exporter.wireguard.state = changedStore

	client := findClientByID(t, changed.Clients, fixture.clientID)
	if found, current := inspectClientExportFormat(fixture.paths, changed, client, ClientExportClash); !found || current {
		t.Fatalf("Clash export after handshake-host replacement = found %t current %t, want found stale", found, current)
	}
	if found, current := inspectClientExportFormat(fixture.paths, changed, client, ClientExportWireGuard); !found || !current {
		t.Fatalf("WireGuard export after handshake-host replacement = found %t current %t, want found current", found, current)
	}

	currentClash := renderClientExportForTest(t, fixture.exporter, ClientExportRequest{
		ClientReference: fixture.clientID, Format: ClientExportClash, GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	currentWireGuard := renderClientExportForTest(t, fixture.exporter, ClientExportRequest{
		ClientReference: fixture.clientID, Format: ClientExportWireGuard, GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if !bytes.Equal(currentClash.content, clashBytes) || !bytes.Equal(currentWireGuard.content, wireGuardBytes) {
		t.Fatal("handshake-host metadata change unexpectedly changed exported profile bytes")
	}
	desiredClash, err := buildClientExportManifest(clash.OutputPath, currentClash)
	if err != nil {
		t.Fatalf("build changed Clash manifest: %v", err)
	}
	changes, err := render.CompareManifests(previousClash, desiredClash)
	if err != nil || !reflect.DeepEqual(changes, []render.ArtifactChange{{Path: clash.OutputPath, Kind: render.ArtifactUpdated}}) {
		t.Fatalf("Clash handshake-host staleness = %#v, %v", changes, err)
	}
	desiredWireGuard, err := buildClientExportManifest(wireGuard.OutputPath, currentWireGuard)
	if err != nil {
		t.Fatalf("build changed WireGuard manifest: %v", err)
	}
	changes, err = render.CompareManifests(previousWireGuard, desiredWireGuard)
	if err != nil || len(changes) != 0 {
		t.Fatalf("WireGuard handshake-host staleness = %#v, %v; want current", changes, err)
	}
}

func TestLegacyClashManifestWithoutHandshakeHostDependencyIsReadableButStale(t *testing.T) {
	t.Parallel()

	fixture := newClientExporterFixture(t)
	state := loadPolicyState(t, fixture.stateStore)
	restrictedCredential, err := model.NewSecretRef("client-restricted", fixture.clientID)
	if err != nil {
		t.Fatalf("NewSecretRef(restricted) error = %v", err)
	}
	state.Generation++
	state.Transports = append(append([]model.Transport(nil), state.Transports...), model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetClient, OwnerID: fixture.clientID,
		Kind: model.TransportRestricted, State: model.TransportStandby, Provider: "mihomo", Protocol: model.ProtocolTCP,
		Port: 8443, CredentialGeneration: 1, CredentialRef: restrictedCredential,
		HandshakeHost: state.HandshakeHost.Hostname, ConfigHash: strings.Repeat("e", 64),
	})
	if err := fixture.stateStore.Save(state.Generation-1, state); err != nil {
		t.Fatalf("Save(restricted client transport) error = %v", err)
	}
	result, err := fixture.exporter.Export(ClientExportRequest{
		ClientReference: fixture.clientID, Format: ClientExportClash, GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatalf("Export(clash) error = %v", err)
	}
	legacy := readClientExportManifest(t, result.metadataPath)
	legacy.Artifacts[0].SourceGenerations = nil
	encoded, err := render.EncodeManifest(legacy)
	if err != nil {
		t.Fatalf("EncodeManifest(legacy) error = %v", err)
	}
	if bytes.Contains(encoded, []byte("source_generations")) {
		t.Fatalf("legacy manifest unexpectedly encoded optional dependency: %s", encoded)
	}
	if err := os.WriteFile(result.metadataPath, encoded, clientExportFileMode); err != nil {
		t.Fatalf("WriteFile(legacy metadata) error = %v", err)
	}
	if _, err := render.DecodeManifest(encoded); err != nil {
		t.Fatalf("DecodeManifest(legacy) error = %v", err)
	}
	client := findClientByID(t, state.Clients, fixture.clientID)
	if found, current := inspectClientExportFormat(fixture.paths, state, client, ClientExportClash); !found || current {
		t.Fatalf("legacy Clash export = found %t current %t, want found stale", found, current)
	}
}

type clientExportStaticStateStore struct {
	state model.State
}

func (store *clientExportStaticStateStore) Load() (model.State, error) {
	return store.state, nil
}

func (*clientExportStaticStateStore) Save(uint64, model.State) error {
	return errors.New("static client export state is read-only")
}

func TestPublishClientExportLeavesProfileUntouchedWhenMetadataTargetIsUnsafe(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	profilePath := filepath.Join(root, "profile.yaml")
	metadataPath := filepath.Join(root, "metadata.json")
	prior := []byte("prior\n")
	if err := os.WriteFile(profilePath, prior, 0o640); err != nil {
		t.Fatalf("create prior profile: %v", err)
	}
	if err := os.Mkdir(metadataPath, 0o700); err != nil {
		t.Fatalf("create blocking metadata directory: %v", err)
	}
	err := publishClientExport(profilePath, []byte("next\n"), true, metadataPath, []byte("{}\n"))
	if !errors.Is(err, ErrClientExportUnsafe) {
		t.Fatalf("publishClientExport(blocked metadata) error = %v, want ErrClientExportUnsafe", err)
	}
	if got := readExportFile(t, profilePath, 0o640); !bytes.Equal(got, prior) {
		t.Fatalf("failed publication changed profile: %q", got)
	}
	assertNoExportTemporaryFiles(t, root)
}

func TestRollbackPublishedProfileRestoresPriorBytesAndMode(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	profilePath := filepath.Join(root, "profile.yaml")
	prior := []byte("prior\n")
	published := []byte("next\n")
	if err := os.WriteFile(profilePath, published, clientExportFileMode); err != nil {
		t.Fatalf("create published profile: %v", err)
	}
	cause := errors.New("metadata activation failed")
	err := rollbackPublishedProfile(profilePath, published, exportFileSnapshot{
		exists: true, mode: 0o640, data: prior,
	}, cause)
	if !errors.Is(err, cause) || errors.Is(err, ErrClientExportUncertain) {
		t.Fatalf("rollbackPublishedProfile() error = %v, want known cause", err)
	}
	if got := readExportFile(t, profilePath, 0o640); !bytes.Equal(got, prior) {
		t.Fatalf("rollback restored %q, want %q", got, prior)
	}
	assertNoExportTemporaryFiles(t, root)
}

func TestClientExporterRejectsInvalidRequestsWithoutPublishing(t *testing.T) {
	t.Parallel()

	fixture := newClientExporterFixture(t)
	stateAlias := filepath.Join(fixture.paths.Root, "state-alias")
	if err := os.Symlink(fixture.paths.StateDir, stateAlias); err != nil {
		t.Fatalf("create state alias: %v", err)
	}
	tests := []ClientExportRequest{
		{Format: ClientExportClash, GatewayPublicKey: v1CompatibleServerPublicKey},
		{ClientReference: "iphone", Format: "unknown", GatewayPublicKey: v1CompatibleServerPublicKey},
		{ClientReference: "iphone", Format: ClientExportClash, GatewayPublicKey: v1CompatibleServerPublicKey, WireGuardDNSServers: []string{"1.1.1.1"}},
		{ClientReference: "iphone", Format: ClientExportWireGuard, GatewayPublicKey: v1CompatibleServerPublicKey, ClashDNSMode: ClashDNSPolicy},
		{ClientReference: "iphone", Format: ClientExportWireGuard, GatewayPublicKey: v1CompatibleServerPublicKey, OutputPath: "/"},
		{ClientReference: "iphone", Format: ClientExportWireGuard, GatewayPublicKey: v1CompatibleServerPublicKey, OutputPath: "bad\npath"},
		{ClientReference: "iphone", Format: ClientExportWireGuard, GatewayPublicKey: v1CompatibleServerPublicKey, OutputPath: fixture.paths.StateFile, Force: true},
		{ClientReference: "iphone", Format: ClientExportWireGuard, GatewayPublicKey: v1CompatibleServerPublicKey, OutputPath: filepath.Join(stateAlias, "nested", "profile.conf"), Force: true},
	}
	for index, request := range tests {
		if _, err := fixture.exporter.Export(request); err == nil {
			t.Fatalf("invalid request %d succeeded: %#v", index, request)
		}
	}
	if _, err := os.Stat(fixture.paths.ExportsDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid requests created export directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fixture.paths.StateDir, "nested")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reserved symlink alias created a managed directory: %v", err)
	}
}

type clientExporterFixture struct {
	exporter   *ClientExporter
	paths      store.Paths
	stateStore *store.StateStore
	clientID   string
	privateKey string
}

func newClientExporterFixture(t *testing.T) clientExporterFixture {
	t.Helper()
	manager, paths, stateStore, secretStore, credentials, _ := newClientManagerFixture(t, nil)
	plan, err := manager.PlanAdd(ClientAddRequest{Name: "iphone", PresetNames: []string{"telegram"}})
	if err != nil {
		t.Fatalf("PlanAdd() error = %v", err)
	}
	created, err := manager.CommitAdd(context.Background(), plan)
	if err != nil {
		t.Fatalf("CommitAdd() error = %v", err)
	}
	exporter, err := NewClientExporter(paths, stateStore, secretStore)
	if err != nil {
		t.Fatalf("NewClientExporter() error = %v", err)
	}
	return clientExporterFixture{
		exporter: exporter, paths: paths, stateStore: stateStore,
		clientID: created.Client.ID, privateKey: credentials.generated[0].PrivateKey,
	}
}

func renderClientExportForTest(t *testing.T, exporter *ClientExporter, request ClientExportRequest) renderedClientExport {
	t.Helper()
	profile, err := exporter.render(request)
	if err != nil {
		t.Fatalf("render client export: %v", err)
	}
	return profile
}

func readClientExportManifest(t *testing.T, path string) render.ArtifactManifest {
	t.Helper()
	data := readExportFile(t, path, clientExportFileMode)
	manifest, err := render.DecodeManifest(data)
	if err != nil {
		t.Fatalf("DecodeManifest(%s) error = %v", path, err)
	}
	return manifest
}

func readExportFile(t *testing.T, path string, wantMode os.FileMode) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	if got := fileMode(t, path); got != wantMode {
		t.Fatalf("mode(%s) = %04o, want %04o", path, got, wantMode)
	}
	return data
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	return info.Mode().Perm()
}

func assertDirectoryMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s) error = %v", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != want {
		t.Fatalf("directory %s mode/type = %v, want real directory %04o", path, info.Mode(), want)
	}
}

func assertNoExportTemporaryFiles(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("ReadDir(%s) error = %v", path, err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".client-") && strings.HasSuffix(entry.Name(), ".tmp") {
			t.Fatalf("temporary export file remained: %s", filepath.Join(path, entry.Name()))
		}
	}
}
