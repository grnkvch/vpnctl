package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
	if _, err := restorer.Plan(context.Background(), changedEndpoint, append([]byte(nil), passphrase...)); !errors.Is(err, ErrGatewayRestoreEndpointMove) {
		t.Fatalf("changed endpoint error = %v", err)
	}

	wrong := []byte("incorrect passphrase")
	if _, err := restorer.Plan(context.Background(), input, wrong); !errors.Is(err, ErrBackupAuthentication) {
		t.Fatalf("invalid archive authentication error = %v", err)
	}
	if host.preflightCalls != 0 || host.mutationCalls() != 0 {
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

	healthErr             error
	lastPayloadRoot       string
	observedNodeTrust     bool
	observedClientProfile bool
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

func (host *recordingGatewayRestoreHost) Activate(_ context.Context, payload *GatewayRestorePayload, _ GatewayRestorePreflight, _ GatewayRestoreEmergencySnapshot) (GatewayRestoreActivation, error) {
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
	return restorer, host, GatewayRestoreInput{ArchivePath: archivePath, PublicIPv4: "203.0.113.10"}, passphrase
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
