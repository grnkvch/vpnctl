package lifecycle

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

func TestGatewayRestoreCleanHostPreservesSameEndpointTrustAndProfiles(t *testing.T) {
	restorer, host, input, passphrase := newGatewayRestoreFixture(t, GatewayRestoreHostState{})
	entered := append([]byte(nil), passphrase...)
	plan, err := restorer.Plan(context.Background(), input, entered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entered, make([]byte, len(entered))) {
		t.Fatal("restore plan retained the caller passphrase")
	}
	if plan.Replace || plan.EmergencySnapshotNeeded || !plan.SameEndpoint || !plan.TrustPreserved ||
		plan.NodeCount != 1 || plan.ClientCount != 1 || plan.GatewayID != backupAllowlistGatewayID {
		t.Fatalf("clean-host restore plan = %+v", plan)
	}
	if host.mutationCalls() != 0 {
		t.Fatalf("restore planning mutated host: %+v", host)
	}
	result, err := restorer.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !result.SameEndpoint || !result.TrustPreserved || result.EmergencySnapshot != nil ||
		result.GatewayID != backupAllowlistGatewayID || result.Generation != plan.TargetGeneration {
		t.Fatalf("clean-host restore result = %+v", result)
	}
	if host.activateCalls != 1 || host.healthCalls != 1 || host.commitCalls != 1 || host.rollbackCalls != 0 || host.snapshotCalls != 0 {
		t.Fatalf("clean-host restore transaction = %+v", host)
	}
	if !host.observedNodeTrust || !host.observedClientProfile {
		t.Fatalf("same-endpoint reconnect material was not preserved: node=%t client=%t", host.observedNodeTrust, host.observedClientProfile)
	}
}

func TestGatewayRestoreChangedEndpointRotatesIngressAndListsEveryStaleResource(t *testing.T) {
	archivePath, passphrase, archived := writeGatewayRestoreArchiveFixture(t)
	encrypted, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	_, files := decryptGatewayBackupFiles(t, encrypted, passphrase)
	delete(files, "manifest.json")
	const sensitiveWebhookPath = "/telegram/fixture-secret-webhook-token"
	archived.Exposes = []model.Expose{
		{
			SchemaVersion: model.ResourceSchemaVersion, ID: "94000000-0000-4000-8000-000000000020", NodeID: backupAllowlistNodeID, Name: "telegram",
			Upstream: "127.0.0.1:3000", RouteMode: model.RouteExact, Path: sensitiveWebhookPath,
			BodyLimitBytes: 1 << 20, UpstreamTimeoutSeconds: 15, ConcurrentRequests: 40,
			TunnelPort: 20000, State: model.ExposeReady, Generation: 1, CreatedAt: archived.Host.InitializedAt,
		},
		{
			SchemaVersion: model.ResourceSchemaVersion, ID: "94000000-0000-4000-8000-000000000021", NodeID: backupAllowlistNodeID, Name: "disabled",
			Upstream: "127.0.0.1:3001", RouteMode: model.RouteExact, Path: "/disabled-secret",
			BodyLimitBytes: 1 << 20, UpstreamTimeoutSeconds: 15, ConcurrentRequests: 40,
			TunnelPort: 20001, State: model.ExposeDisabled, Generation: 1, CreatedAt: archived.Host.InitializedAt,
		},
	}
	if err := archived.Validate(); err != nil {
		t.Fatal(err)
	}
	files["state/state.json"], err = model.EncodeState(archived)
	if err != nil {
		t.Fatal(err)
	}
	files["exports/clients/iphone.wireguard.conf"] = []byte("stale wireguard profile\n")
	files["exports/clients/.metadata/"+backupAllowlistClientID+".wireguard.json"] = []byte("legacy metadata\n")
	archivePath = writeAuthenticatedRestoreTestFiles(t, archived, files, passphrase)
	restorer, host, input := newGatewayRestoreFixtureForArchive(t, GatewayRestoreHostState{}, archivePath)
	input.PublicIPv4 = "198.51.100.20"
	plan, err := restorer.Plan(context.Background(), input, append([]byte(nil), passphrase...))
	if err != nil {
		t.Fatal(err)
	}
	if plan.SameEndpoint || !plan.TrustPreserved || plan.OriginalPublicIPv4 != "203.0.113.10" || plan.PublicIPv4 != "198.51.100.20" ||
		plan.PublicCertificate == nil || plan.PublicCertificate.ID != "94000000-0000-4000-8000-000000000012" ||
		plan.PublicCertificate.Generation != 2 || !reflect.DeepEqual(plan.PublicCertificate.SANs, []string{"IP:198.51.100.20"}) ||
		plan.PublicCertificate.Fingerprint == archived.Certificates[2].Fingerprint {
		t.Fatalf("changed-endpoint restore plan = %+v", plan)
	}
	if !reflect.DeepEqual(plan.AffectedNodes, []GatewayRestoreAffectedNode{{ID: backupAllowlistNodeID, Name: "private-node"}}) ||
		!reflect.DeepEqual(plan.StaleClientExports, []GatewayRestoreAffectedClientExport{
			{ClientID: backupAllowlistClientID, ClientName: "iphone", Format: "clash"},
			{ClientID: backupAllowlistClientID, ClientName: "iphone", Format: "wireguard"},
		}) || !reflect.DeepEqual(plan.AffectedExposes, []GatewayRestoreAffectedExpose{{
		ID: "94000000-0000-4000-8000-000000000020", NodeID: backupAllowlistNodeID, Name: "telegram", State: model.ExposeReady,
	}}) {
		t.Fatalf("changed-endpoint impact = nodes:%+v clients:%+v exposes:%+v", plan.AffectedNodes, plan.StaleClientExports, plan.AffectedExposes)
	}
	if strings.Contains(fmt.Sprintf("%+v", plan), sensitiveWebhookPath) || strings.Contains(fmt.Sprintf("%+v", plan), "/disabled-secret") {
		t.Fatal("changed-endpoint public plan exposed a webhook path")
	}
	for _, metadata := range []string{
		"exports/clients/.metadata/" + backupAllowlistClientID + ".clash.json",
		"exports/clients/.metadata/" + backupAllowlistClientID + ".wireguard.json",
	} {
		if _, err := plan.payload.Open(metadata); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale client metadata %s remains active: %v", metadata, err)
		}
	}
	for _, old := range []string{"secrets/ingress-cert/public-g1", "secrets/ingress-key/public-g1"} {
		if _, err := plan.payload.Open(old); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("superseded public certificate material %s remains active: %v", old, err)
		}
	}
	candidate := plan.preflight.Candidate
	if !reflect.DeepEqual(candidate.EnrollmentIdentity, archived.EnrollmentIdentity) || !reflect.DeepEqual(candidate.Nodes, archived.Nodes) ||
		!reflect.DeepEqual(candidate.Clients, archived.Clients) || !reflect.DeepEqual(candidate.Transports, archived.Transports) ||
		!reflect.DeepEqual(nonPublicRestoreCertificates(candidate.Certificates), nonPublicRestoreCertificates(archived.Certificates)) {
		t.Fatal("changed endpoint altered control, node, or client trust material")
	}
	tampered := plan
	tampered.AffectedExposes = nil
	if _, err := restorer.Apply(context.Background(), tampered); err == nil || !strings.Contains(err.Error(), "impact") {
		t.Fatalf("incomplete endpoint action plan error = %v", err)
	}
	if host.mutationCalls() != 0 {
		t.Fatalf("tampered endpoint action plan mutated host: %+v", host)
	}
	result, err := restorer.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.SameEndpoint || !result.TrustPreserved || result.PublicCertificate == nil ||
		!reflect.DeepEqual(result.AffectedNodes, plan.AffectedNodes) || !reflect.DeepEqual(result.StaleClientExports, plan.StaleClientExports) ||
		!reflect.DeepEqual(result.AffectedExposes, plan.AffectedExposes) || !host.observedRotatedCertificate || !host.observedStaleClientMetadata {
		t.Fatalf("changed-endpoint result/host = %+v / %+v", result, host)
	}
	for _, interruption := range result.ExpectedInterruptions {
		if strings.Contains(strings.ToLower(interruption), "seamless") {
			t.Fatalf("restore claimed seamless continuity: %q", interruption)
		}
	}
}

func TestGatewayRestoreChangedEndpointEntropyFailureLeavesNoPrivateStageOrHostMutation(t *testing.T) {
	restorer, host, input, passphrase := newGatewayRestoreFixture(t, GatewayRestoreHostState{})
	restorer.runtime.Entropy = failingGatewayRestoreEntropy{}
	input.PublicIPv4 = "198.51.100.20"
	if _, err := restorer.Plan(context.Background(), input, append([]byte(nil), passphrase...)); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("changed-endpoint entropy failure = %v", err)
	}
	if host.preflightCalls != 0 || host.mutationCalls() != 0 {
		t.Fatalf("failed endpoint planning reached host: %+v", host)
	}
	entries, err := os.ReadDir(restorer.runtime.Archives.scratch)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed endpoint planning retained private stage: %v, entries=%v", err, entries)
	}
}

func TestGatewayRestoreInitializedGatewayRequiresReplaceAndDurableEmergencySnapshot(t *testing.T) {
	existing := GatewayRestoreHostState{
		Initialized: true, Role: model.RoleGateway, StateGeneration: 44,
		OwnershipSHA256: strings.Repeat("a", 64), CurrentGatewayID: "96000000-0000-4000-8000-000000000001",
	}
	restorer, host, input, passphrase := newGatewayRestoreFixture(t, existing)
	if _, err := restorer.Plan(context.Background(), input, append([]byte(nil), passphrase...)); !errors.Is(err, ErrGatewayRestoreReplaceNeeded) {
		t.Fatalf("restore without --replace error = %v", err)
	}
	if host.mutationCalls() != 0 {
		t.Fatalf("missing --replace mutated host: %+v", host)
	}
	input.Replace = true
	plan, err := restorer.Plan(context.Background(), input, append([]byte(nil), passphrase...))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ReplacingInitialized || !plan.EmergencySnapshotNeeded {
		t.Fatalf("replacement plan = %+v", plan)
	}
	result, err := restorer.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.EmergencySnapshot == nil || result.EmergencySnapshot.ID != restoreTestSnapshotID || host.snapshotCalls != 1 || host.activateCalls != 1 || host.commitCalls != 1 {
		t.Fatalf("replacement result/host = %+v / %+v", result, host)
	}
}

func TestGatewayRestoreFailureAndStalePlanRollBackWithoutPartialConvergence(t *testing.T) {
	existing := GatewayRestoreHostState{
		Initialized: true, Role: model.RoleGateway, StateGeneration: 7,
		OwnershipSHA256: strings.Repeat("b", 64), CurrentGatewayID: "96000000-0000-4000-8000-000000000002",
	}

	t.Run("health failure", func(t *testing.T) {
		restorer, host, input, passphrase := newGatewayRestoreFixture(t, existing)
		input.Replace = true
		plan, err := restorer.Plan(context.Background(), input, append([]byte(nil), passphrase...))
		if err != nil {
			t.Fatal(err)
		}
		host.healthErr = errors.New("injected restored gateway health failure")
		if _, err := restorer.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "health") {
			t.Fatalf("health failure error = %v", err)
		}
		if host.snapshotCalls != 1 || host.activateCalls != 1 || host.healthCalls != 1 || host.rollbackCalls != 1 || host.commitCalls != 0 {
			t.Fatalf("failed replacement transaction = %+v", host)
		}
		if _, err := os.Lstat(host.lastPayloadRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed restore left plaintext stage: %v", err)
		}
	})

	t.Run("stale plan", func(t *testing.T) {
		restorer, host, input, passphrase := newGatewayRestoreFixture(t, existing)
		input.Replace = true
		plan, err := restorer.Plan(context.Background(), input, append([]byte(nil), passphrase...))
		if err != nil {
			t.Fatal(err)
		}
		host.state.StateGeneration++
		host.state.OwnershipSHA256 = strings.Repeat("c", 64)
		if _, err := restorer.Apply(context.Background(), plan); !errors.Is(err, ErrGatewayRestoreConflict) {
			t.Fatalf("stale restore error = %v", err)
		}
		if host.mutationCalls() != 0 {
			t.Fatalf("stale restore plan mutated host: %+v", host)
		}
	})
}

func TestGatewayRestoreInvalidInputsAndArchivesNeverReachHostMutation(t *testing.T) {
	restorer, host, input, passphrase := newGatewayRestoreFixture(t, GatewayRestoreHostState{})

	changedEndpoint := input
	changedEndpoint.PublicIPv4 = "198.51.100.20"
	changedPlan, err := restorer.Plan(context.Background(), changedEndpoint, append([]byte(nil), passphrase...))
	if err != nil || changedPlan.SameEndpoint || changedPlan.PublicCertificate == nil {
		t.Fatalf("changed endpoint plan = %+v, %v", changedPlan, err)
	}
	if err := restorer.Discard(changedPlan); err != nil {
		t.Fatal(err)
	}

	wrong := []byte("incorrect passphrase")
	if _, err := restorer.Plan(context.Background(), input, wrong); !errors.Is(err, ErrBackupAuthentication) {
		t.Fatalf("invalid archive authentication error = %v", err)
	}
	if host.preflightCalls != 1 || host.mutationCalls() != 0 {
		t.Fatalf("invalid restore reached host preflight/mutation: %+v", host)
	}

	node := GatewayRestoreHostState{
		Initialized: true, Role: model.RoleNode, StateGeneration: 3, OwnershipSHA256: strings.Repeat("d", 64),
		CurrentGatewayID: "96000000-0000-4000-8000-000000000003",
	}
	nodeRestorer, nodeHost, nodeInput, nodePassphrase := newGatewayRestoreFixture(t, node)
	nodeInput.Replace = true
	if _, err := nodeRestorer.Plan(context.Background(), nodeInput, append([]byte(nil), nodePassphrase...)); !errors.Is(err, ErrGatewayRestoreConflict) {
		t.Fatalf("node replacement error = %v", err)
	}
	if nodeHost.mutationCalls() != 0 {
		t.Fatalf("node restore mutated host: %+v", nodeHost)
	}
}

func TestGatewayRestoreRefusesReleaseChangesBetweenPlanAndApplyBeforeHostMutation(t *testing.T) {
	t.Run("install failure", func(t *testing.T) {
		restorer, host, input, passphrase := newGatewayRestoreFixture(t, GatewayRestoreHostState{})
		plan, err := restorer.Plan(context.Background(), input, append([]byte(nil), passphrase...))
		if err != nil {
			t.Fatal(err)
		}
		release := restorer.runtime.Release.(*staticGatewayRestoreRelease)
		release.installErr = errors.New("injected release install failure")
		if _, err := restorer.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "install") {
			t.Fatalf("release install failure = %v", err)
		}
		if release.installCalls != 1 || host.mutationCalls() != 0 {
			t.Fatalf("release/host calls = %d/%d", release.installCalls, host.mutationCalls())
		}
	})

	t.Run("installed manifest changed", func(t *testing.T) {
		restorer, host, input, passphrase := newGatewayRestoreFixture(t, GatewayRestoreHostState{})
		plan, err := restorer.Plan(context.Background(), input, append([]byte(nil), passphrase...))
		if err != nil {
			t.Fatal(err)
		}
		release := restorer.runtime.Release.(*staticGatewayRestoreRelease)
		changed, err := NewV2ReleaseManifest("v2.0.1", strings.Repeat("f", 64), 1, true)
		if err != nil {
			t.Fatal(err)
		}
		release.installManifest = &changed
		if _, err := restorer.Apply(context.Background(), plan); !errors.Is(err, ErrGatewayRestoreIncompatible) {
			t.Fatalf("changed release error = %v", err)
		}
		if release.installCalls != 1 || host.mutationCalls() != 0 {
			t.Fatalf("release/host calls = %d/%d", release.installCalls, host.mutationCalls())
		}
	})
}

func TestGatewayRestoreRequiresCanonicalPublicIPv4(t *testing.T) {
	for _, address := range []string{"", "203.0.113.010", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "198.18.0.1", "2001:db8::1"} {
		input := GatewayRestoreInput{ArchivePath: "/srv/gateway.v2b", PublicIPv4: address}
		if err := validateGatewayRestoreInput(input); err == nil {
			t.Fatalf("validateGatewayRestoreInput(%q) succeeded", address)
		}
	}
	if err := validateGatewayRestoreInput(GatewayRestoreInput{ArchivePath: "/srv/gateway.v2b", PublicIPv4: "203.0.113.10"}); err != nil {
		t.Fatalf("canonical IPv4 rejected: %v", err)
	}
}

const (
	restoreTestActivationID = "96000000-0000-4000-8000-000000000010"
	restoreTestSnapshotID   = "96000000-0000-4000-8000-000000000011"
)

type staticGatewayRestoreRelease struct {
	manifest        ReleaseManifest
	inspectErr      error
	installManifest *ReleaseManifest
	installErr      error
	installCalls    int
}

func (source *staticGatewayRestoreRelease) Inspect(context.Context) (ReleaseManifest, error) {
	return source.manifest, source.inspectErr
}

func (source *staticGatewayRestoreRelease) Install(context.Context, model.Role) (ReleaseBundleInstallResult, error) {
	source.installCalls++
	if source.installErr != nil {
		return ReleaseBundleInstallResult{}, source.installErr
	}
	manifest := source.manifest
	if source.installManifest != nil {
		manifest = *source.installManifest
	}
	return ReleaseBundleInstallResult{Manifest: manifest}, nil
}

type recordingGatewayRestoreHost struct {
	state GatewayRestoreHostState

	inspectCalls   int
	preflightCalls int
	snapshotCalls  int
	activateCalls  int
	healthCalls    int
	commitCalls    int
	rollbackCalls  int

	healthErr                   error
	lastPayloadRoot             string
	observedNodeTrust           bool
	observedClientProfile       bool
	observedRotatedCertificate  bool
	observedStaleClientMetadata bool
}

func (host *recordingGatewayRestoreHost) Inspect(context.Context) (GatewayRestoreHostState, error) {
	host.inspectCalls++
	return host.state, nil
}

func (host *recordingGatewayRestoreHost) Preflight(_ context.Context, _ *GatewayRestorePayload, candidate model.State, _ GatewayRestoreHostState) (GatewayRestorePreflight, error) {
	host.preflightCalls++
	return GatewayRestorePreflight{
		Candidate: candidate,
		Network: linuxplatform.GatewayNetworkPlan{
			PublicIPv4: candidate.Host.PublicIPv4, ClientCIDR: candidate.Host.ClientCIDR, NodeCIDR: candidate.Host.NodeCIDR,
			ExternalInterface: candidate.Host.ExternalInterface, InterfaceSource: "restore_fixture",
		},
		SSH:                   linuxplatform.SSHPortPlan{Port: candidate.Host.SSHPort, Source: linuxplatform.SSHPortFromOverride, ListenerAddresses: []string{"0.0.0.0"}},
		PortRemaps:            []tunnel.PortRemap{},
		AffectedServices:      restoreTestServices(),
		ExpectedInterruptions: []string{"existing transport sessions reconnect during restore"},
	}, nil
}

func (host *recordingGatewayRestoreHost) EmergencySnapshot(context.Context, GatewayRestoreHostState) (GatewayRestoreEmergencySnapshot, error) {
	host.snapshotCalls++
	return GatewayRestoreEmergencySnapshot{ID: restoreTestSnapshotID, Path: "/var/lib/vpnctl/snapshots/restore-" + restoreTestSnapshotID, CreatedAt: time.Date(2026, 9, 4, 18, 0, 0, 0, time.UTC)}, nil
}

func (host *recordingGatewayRestoreHost) Activate(_ context.Context, payload *GatewayRestorePayload, preflight GatewayRestorePreflight, _ GatewayRestoreEmergencySnapshot) (GatewayRestoreActivation, error) {
	host.activateCalls++
	host.lastPayloadRoot = payload.root
	nodeTrust, err := payload.Open("secrets/tunnel-token/" + backupAllowlistNodeID + "-g1")
	if err == nil {
		content, readErr := io.ReadAll(nodeTrust)
		_ = nodeTrust.Close()
		host.observedNodeTrust = readErr == nil && bytes.Equal(content, []byte("INCLUDED-GATEWAY-NODE-TUNNEL-SHARED-MATERIAL"))
	}
	profile, err := payload.Open("exports/clients/iphone.clash.yaml")
	if err == nil {
		content, readErr := io.ReadAll(profile)
		_ = profile.Close()
		host.observedClientProfile = readErr == nil && bytes.Equal(content, []byte("client profile secret\n"))
	}
	if certificate, found := gatewayRestorePublicCertificate(preflight.Candidate); found && certificate.Generation > 1 {
		certificatePath, _ := gatewayRestoreSecretPath(model.SecretRef(certificate.CertificateRef))
		privateKeyPath, _ := gatewayRestoreSecretPath(certificate.PrivateKeyRef)
		certificateFile, certificateErr := payload.Open(certificatePath)
		privateKeyFile, privateKeyErr := payload.Open(privateKeyPath)
		if certificateErr == nil && privateKeyErr == nil {
			certificatePEM, certificateReadErr := io.ReadAll(certificateFile)
			privateKeyPEM, privateKeyReadErr := io.ReadAll(privateKeyFile)
			_, validationErr := ingress.ValidatePublicCertificatePEM(certificatePEM, certificate, preflight.Candidate.Host.PublicIPv4)
			_, pairErr := tls.X509KeyPair(certificatePEM, privateKeyPEM)
			host.observedRotatedCertificate = certificateReadErr == nil && privateKeyReadErr == nil && validationErr == nil && pairErr == nil
		}
		if certificateFile != nil {
			_ = certificateFile.Close()
		}
		if privateKeyFile != nil {
			_ = privateKeyFile.Close()
		}
		clashMetadata, clashMetadataErr := payload.Open("exports/clients/.metadata/" + backupAllowlistClientID + ".clash.json")
		wireGuardMetadata, wireGuardMetadataErr := payload.Open("exports/clients/.metadata/" + backupAllowlistClientID + ".wireguard.json")
		if clashMetadata != nil {
			_ = clashMetadata.Close()
		}
		if wireGuardMetadata != nil {
			_ = wireGuardMetadata.Close()
		}
		host.observedStaleClientMetadata = errors.Is(clashMetadataErr, os.ErrNotExist) && errors.Is(wireGuardMetadataErr, os.ErrNotExist)
	}
	return GatewayRestoreActivation{ID: restoreTestActivationID, Started: true}, nil
}

func (host *recordingGatewayRestoreHost) Health(context.Context, GatewayRestoreActivation, model.State) error {
	host.healthCalls++
	return host.healthErr
}

func (host *recordingGatewayRestoreHost) Commit(context.Context, GatewayRestoreActivation) error {
	host.commitCalls++
	return nil
}

func (host *recordingGatewayRestoreHost) Rollback(context.Context, GatewayRestoreActivation, GatewayRestoreEmergencySnapshot) error {
	host.rollbackCalls++
	return nil
}

func (host *recordingGatewayRestoreHost) mutationCalls() int {
	return host.snapshotCalls + host.activateCalls + host.healthCalls + host.commitCalls + host.rollbackCalls
}

func newGatewayRestoreFixture(t *testing.T, hostState GatewayRestoreHostState) (*GatewayRestorer, *recordingGatewayRestoreHost, GatewayRestoreInput, []byte) {
	t.Helper()
	archivePath, passphrase, _ := writeGatewayRestoreArchiveFixture(t)
	restorer, host, input := newGatewayRestoreFixtureForArchive(t, hostState, archivePath)
	return restorer, host, input, passphrase
}

func newGatewayRestoreFixtureForArchive(t *testing.T, hostState GatewayRestoreHostState, archivePath string) (*GatewayRestorer, *recordingGatewayRestoreHost, GatewayRestoreInput) {
	t.Helper()
	loader, err := newGatewayRestoreArchiveLoader(t.TempDir(), fastBackupArchiveCodec())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := NewV2ReleaseManifest("v2.0.0", strings.Repeat("e", 64), 1, true)
	if err != nil {
		t.Fatal(err)
	}
	host := &recordingGatewayRestoreHost{state: hostState}
	restorer, err := NewGatewayRestorer(GatewayRestoreRuntime{Archives: loader, Release: &staticGatewayRestoreRelease{manifest: manifest}, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	return restorer, host, GatewayRestoreInput{ArchivePath: archivePath, PublicIPv4: "203.0.113.10"}
}

func nonPublicRestoreCertificates(certificates []model.Certificate) []model.Certificate {
	result := make([]model.Certificate, 0, len(certificates))
	for _, certificate := range certificates {
		if certificate.Kind != model.CertificatePublicIngress {
			result = append(result, certificate)
		}
	}
	return result
}

type failingGatewayRestoreEntropy struct{}

func (failingGatewayRestoreEntropy) Read([]byte) (int, error) {
	return 0, errors.New("injected entropy failure")
}

func restoreTestServices() []string {
	return []string{
		"vpnctl-controller.service", "vpnctl-dns.service", "vpnctl-restricted.service",
		"vpnctl-standard.service", "vpnctl-tunnel-server.service",
	}
}

func TestGatewayRestorePlanDoesNotRetainPubliclySerializableSecrets(t *testing.T) {
	restorer, _, input, passphrase := newGatewayRestoreFixture(t, GatewayRestoreHostState{})
	plan, err := restorer.Plan(context.Background(), input, append([]byte(nil), passphrase...))
	if err != nil {
		t.Fatal(err)
	}
	defer restorer.Discard(plan)
	encoded := fmt.Sprintf("%+v", plan)
	for _, secret := range []string{"INCLUDED-GATEWAY", "client profile secret", string(passphrase)} {
		if strings.Contains(encoded, secret) {
			t.Fatalf("public restore plan contains secret material %q", secret)
		}
	}
	if filepath.Base(plan.ArchivePath) == "" || !reflect.DeepEqual(plan.AffectedServices, restoreTestServices()) {
		t.Fatalf("restore plan lost public impact metadata: %+v", plan)
	}
}
