package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestUpdaterPlansLatestStableAndAppliesOnlyLocalComponentsWithHealth(t *testing.T) {
	fixture := newUpdaterFixture(t, model.RoleGateway, "new")
	plan, err := fixture.updater.Plan(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.updater.Discard(plan)
	if !plan.LatestStable || plan.RequestedVersion != "" || plan.CurrentVersion != "v2.0.0" || plan.TargetVersion != "v2.1.0" ||
		!plan.Changed || plan.Blocked || !plan.Fleet.Compatible || !plan.RollbackAvailable || plan.Migration.FromSchema != 1 ||
		plan.Migration.ToSchema != 1 || len(plan.Migration.Steps) != 0 || len(plan.ExpectedInterruptions) != 5 {
		t.Fatalf("update plan = %+v", plan)
	}
	if fixture.source.requests != 1 || fixture.source.requested != "" || len(fixture.host.calls) != 1 || fixture.host.calls[0] != "preflight:gateway" {
		t.Fatalf("planning calls source=%d/%q host=%q", fixture.source.requests, fixture.source.requested, fixture.host.calls)
	}
	result, err := fixture.updater.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.PreviousVersion != "v2.0.0" || result.CurrentVersion != "v2.1.0" || result.Generation != 4 || len(result.ComponentResults) != 6 {
		t.Fatalf("update result = %+v", result)
	}
	wantCalls := []string{
		"preflight:gateway", "quiesce:gateway", "activate:frp", "activate:mihomo", "activate:vpnctl", "resume:gateway",
	}
	if !reflect.DeepEqual(fixture.host.calls, wantCalls) {
		t.Fatalf("local host calls = %q, want %q", fixture.host.calls, wantCalls)
	}
	if fixture.host.remoteUpdates != 0 || fixture.state.saves != 3 || fixture.state.state.Components.VPNCTLVersion != "v2.1.0" ||
		len(fixture.state.state.Operations) != 1 || fixture.state.state.Operations[0].Type != model.OperationUpdate {
		t.Fatalf("post-update state=%+v saves=%d remote=%d", fixture.state.state, fixture.state.saves, fixture.host.remoteUpdates)
	}
	assertUpdateInstalledFiles(t, fixture.root, fixture.targetInstalled, fixture.targetAssets)
}

func TestUpdaterHealthFailureRollsBackFilesAndLeavesStateUntouched(t *testing.T) {
	fixture := newUpdaterFixture(t, model.RoleNode, "new")
	fixture.host.failHealth = "mihomo"
	beforeFiles := snapshotReleaseUpdateRoot(t, fixture.root)
	beforeState := fixture.state.state
	plan, err := fixture.updater.Plan(context.Background(), "v2.1.0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.updater.Apply(context.Background(), plan)
	if !errors.Is(err, ErrUpdateHealth) {
		t.Fatalf("health failure = %v", err)
	}
	if after := snapshotReleaseUpdateRoot(t, fixture.root); !reflect.DeepEqual(beforeFiles, after) {
		t.Fatalf("failed update changed release root\nbefore=%+v\nafter=%+v", beforeFiles, after)
	}
	if !reflect.DeepEqual(beforeState.Components, fixture.state.state.Components) || fixture.state.saves != 2 || fixture.host.remoteUpdates != 0 ||
		len(fixture.state.state.Operations) != 1 || fixture.state.state.Operations[0].State != model.OperationFailed {
		t.Fatalf("failed update changed state=%+v saves=%d remote=%d", fixture.state.state, fixture.state.saves, fixture.host.remoteUpdates)
	}
	want := []string{
		"preflight:node", "quiesce:node", "activate:frp", "activate:mihomo", "rollback:mihomo", "rollback:frp", "resume:node",
	}
	if !reflect.DeepEqual(fixture.host.calls, want) {
		t.Fatalf("rollback calls = %q, want %q", fixture.host.calls, want)
	}
}

func TestUpdaterBlockedAndNoopPlansNeverMutateHost(t *testing.T) {
	t.Run("fleet incompatible", func(t *testing.T) {
		fixture := newUpdaterFixture(t, model.RoleGateway, "new")
		fixture.fleet.compatible = false
		plan, err := fixture.updater.Plan(context.Background(), "v2.1.0")
		if err != nil {
			t.Fatal(err)
		}
		if !plan.Blocked || len(plan.RequiresAction) == 0 {
			t.Fatalf("blocked plan = %+v", plan)
		}
		if _, err := fixture.updater.Apply(context.Background(), plan); !errors.Is(err, ErrUpdateIncompatible) {
			t.Fatalf("blocked apply = %v", err)
		}
		if err := fixture.updater.Discard(plan); err != nil {
			t.Fatal(err)
		}
		if len(fixture.host.calls) != 1 || fixture.state.saves != 0 {
			t.Fatalf("blocked plan mutated host: calls=%q saves=%d", fixture.host.calls, fixture.state.saves)
		}
	})

	t.Run("same release", func(t *testing.T) {
		fixture := newUpdaterFixture(t, model.RoleGateway, "old")
		plan, err := fixture.updater.Plan(context.Background(), "v2.0.0")
		if err != nil {
			t.Fatal(err)
		}
		if plan.Changed || len(plan.ExpectedInterruptions) != 0 {
			t.Fatalf("no-op plan = %+v", plan)
		}
		result, err := fixture.updater.Apply(context.Background(), plan)
		if err != nil || result.Changed || result.Generation != 1 {
			t.Fatalf("no-op result = %+v, %v", result, err)
		}
		if len(fixture.host.calls) != 1 || fixture.state.saves != 0 {
			t.Fatalf("no-op update mutated host: calls=%q saves=%d", fixture.host.calls, fixture.state.saves)
		}
	})
}

func TestUpdateMigrationPreviewKeepsBinaryOnlyRollbackAvailable(t *testing.T) {
	state := model.State{SchemaVersion: model.StateSchemaVersion}
	target := model.ComponentManifest{
		StateSchemaMinimum: model.StateSchemaVersion, StateSchemaMaximum: model.StateSchemaVersion,
		MigrationReversible: false,
	}
	plan := planUpdateStateMigration(state, target)
	if plan.FromSchema != model.StateSchemaVersion || plan.ToSchema != model.StateSchemaVersion || !plan.Reversible || len(plan.Steps) != 0 {
		t.Fatalf("binary-only migration preview = %+v", plan)
	}
}

func TestGatewayAndNodeUpdateFleetCompatibility(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	manifest, _ := releaseManifestFixture()
	state := initialGatewayState("91000000-0000-4000-8000-000000000001", now, linuxplatform.GatewayNetworkPlan{
		PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
	}, 22, manifest.ComponentManifest, model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: manifest.ComponentManifest.HandshakeHostListVersion,
		CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: now,
	})
	state.EnrollmentIdentity = updateTestEnrollmentIdentity(now)
	state.Nodes = []model.Node{
		updateTestGatewayNode("91000000-0000-4000-8000-000000000002", "compatible", "10.67.0.2", now),
		updateTestGatewayNode("91000000-0000-4000-8000-000000000003", "old", "10.67.0.3", now),
	}
	state.Nodes[0].ControlProtocol = "2.1"
	state.Transports = []model.Transport{
		updateTestNodeTransport(state.Nodes[0], "transport-key:compatible"),
		updateTestNodeTransport(state.Nodes[1], "transport-key:old"),
	}
	state.Invites = []model.Invite{
		updateTestConsumedInvite(state, state.Nodes[0], "2.1", now),
		updateTestConsumedInvite(state, state.Nodes[1], "1.9", now),
	}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	target := manifest.ComponentManifest
	target.ControlProtocols = []string{"3.0", "2.5"}
	fleet, err := (GatewayUpdateFleetChecker{}).Check(context.Background(), state, target)
	if err != nil || fleet.Compatible || len(fleet.Nodes) != 2 || !fleet.Nodes[0].Compatible || fleet.Nodes[1].Code != "node_outside_target_window" {
		t.Fatalf("gateway fleet = %+v, %v", fleet, err)
	}

	preflight := &staticNodeUpdatePreflight{plan: NodeUpdatePreflightPlan{
		Status: NodeUpdateReady, GatewayVPNCTLVersion: "v2.1.0", SelectedProtocol: "2.4", RequiresAction: []string{},
	}}
	checker, _ := NewNodeUpdateFleetChecker(preflight)
	nodeState := initialNodeState("91000000-0000-4000-8000-000000000004", now, manifest.ComponentManifest, []string{"192.0.2.53"})
	nodeFleet, err := checker.Check(context.Background(), nodeState, target)
	if err != nil || !nodeFleet.Compatible || preflight.calls != 0 {
		t.Fatalf("unjoined node fleet = %+v calls=%d error=%v", nodeFleet, preflight.calls, err)
	}
}

func TestGatewayUpdatePostActionsIncludeOnlyCompatibleActiveNodes(t *testing.T) {
	plan := UpdatePlan{
		Role: model.RoleGateway, Changed: true, TargetVersion: "v2.1.0",
		Fleet: UpdateFleetCompatibility{Nodes: []UpdateFleetNode{
			{Name: "private-api", Compatible: true},
			{Name: "legacy", Compatible: false},
		}},
	}
	actions := updatePostActions(plan)
	if len(actions) != 1 || actions[0] != "connect to node private-api over SSH and run vpnctl update v2.1.0 locally" {
		t.Fatalf("post-update actions = %v", actions)
	}
}

type updaterFixture struct {
	root            string
	updater         *Updater
	state           *memoryUpdateState
	source          *staticUpdateReleaseStager
	fleet           *staticUpdateFleetChecker
	host            *recordingUpdateHost
	targetAssets    map[string][]byte
	targetInstalled map[string][]byte
}

func newUpdaterFixture(t *testing.T, role model.Role, targetMarker string) updaterFixture {
	t.Helper()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	installer, _ := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	currentAssets, currentManifest, _ := updateReleaseAssetsWithInstalled(t, privateKey, "v2.0.0", "old")
	targetVersion := "v2.1.0"
	if targetMarker == "old" {
		targetVersion = "v2.0.0"
	}
	targetAssets, targetManifest, targetInstalled := updateReleaseAssetsWithInstalled(t, privateKey, targetVersion, targetMarker)
	current := writeStagedUpdateRelease(t, currentAssets, currentManifest)
	t.Cleanup(func() { _ = current.Close() })
	target := writeStagedUpdateRelease(t, targetAssets, targetManifest)
	if _, err := installer.Install(context.Background(), current.BundlePath, role); err != nil {
		t.Fatal(err)
	}
	installStandardReleaseMetadata(t, root, current)
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	var state model.State
	if role == model.RoleGateway {
		state = initialGatewayState("90000000-0000-4000-8000-000000000001", now, linuxplatform.GatewayNetworkPlan{
			PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
		}, 22, currentManifest.ComponentManifest, model.HandshakeHost{
			SchemaVersion: model.ResourceSchemaVersion, ListVersion: currentManifest.ComponentManifest.HandshakeHostListVersion,
			CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: now,
		})
	} else {
		state = initialNodeState("90000000-0000-4000-8000-000000000002", now, currentManifest.ComponentManifest, []string{"192.0.2.53"})
	}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	stateStore := &memoryUpdateState{state: state}
	source := &staticUpdateReleaseStager{stage: target}
	fleet := &staticUpdateFleetChecker{compatible: true}
	host := &recordingUpdateHost{}
	updater, err := NewUpdater(UpdateRuntime{
		State: stateStore, Releases: source, Bundles: installer, Fleet: fleet, Host: host,
		CurrentBundlePath: standardReleaseBundleInRoot(root), Now: func() time.Time { return now.Add(time.Minute) },
		NewUUID: func() (string, error) { return "90000000-0000-4000-8000-000000000010", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return updaterFixture{
		root: root, updater: updater, state: stateStore, source: source, fleet: fleet, host: host,
		targetAssets: targetAssets, targetInstalled: targetInstalled,
	}
}

type memoryUpdateState struct {
	state model.State
	saves int
}

func (state *memoryUpdateState) Load() (model.State, error) { return state.state, nil }

func (state *memoryUpdateState) Save(expected uint64, candidate model.State) error {
	if state.state.Generation != expected {
		return fmt.Errorf("generation conflict")
	}
	if err := model.ValidateTransition(state.state, candidate); err != nil {
		return err
	}
	state.state = candidate
	state.saves++
	return nil
}

type staticUpdateReleaseStager struct {
	stage     *StagedUpdateRelease
	requests  int
	requested string
}

func (source *staticUpdateReleaseStager) Stage(_ context.Context, requested string) (*StagedUpdateRelease, error) {
	source.requests++
	source.requested = requested
	return source.stage, nil
}

type staticUpdateFleetChecker struct{ compatible bool }

func (checker *staticUpdateFleetChecker) Check(_ context.Context, state model.State, _ model.ComponentManifest) (UpdateFleetCompatibility, error) {
	actions := []string{}
	if !checker.compatible {
		actions = append(actions, "resolve fleet compatibility")
	}
	return UpdateFleetCompatibility{Role: state.Host.Role, Compatible: checker.compatible, Nodes: []UpdateFleetNode{}, RequiresAction: actions}, nil
}

type recordingUpdateHost struct {
	calls         []string
	failHealth    string
	remoteUpdates int
}

func (host *recordingUpdateHost) Preflight(_ context.Context, role model.Role, manifest ReleaseManifest) ([]UpdatePackageCheck, error) {
	host.calls = append(host.calls, "preflight:"+string(role))
	result := []UpdatePackageCheck{}
	for _, compatibility := range manifest.APTPackages {
		if releaseRolesContain(compatibility.Roles, role) {
			result = append(result, UpdatePackageCheck{Component: compatibility.Component, Package: compatibility.Package, InstalledVersion: compatibility.MinimumVersion, Compatible: true})
		}
	}
	return result, nil
}

func (host *recordingUpdateHost) QuiesceManagement(_ context.Context, role model.Role) error {
	host.calls = append(host.calls, "quiesce:"+string(role))
	return nil
}

func (host *recordingUpdateHost) ActivateAndHealth(_ context.Context, _ model.Role, change UpdateComponentChange) error {
	host.calls = append(host.calls, "activate:"+change.Name)
	if host.failHealth == change.Name {
		return errors.New("injected health failure")
	}
	return nil
}

func (host *recordingUpdateHost) RollbackAndHealth(_ context.Context, _ model.Role, change UpdateComponentChange) error {
	host.calls = append(host.calls, "rollback:"+change.Name)
	return nil
}

func (host *recordingUpdateHost) ResumeManagement(_ context.Context, role model.Role) error {
	host.calls = append(host.calls, "resume:"+string(role))
	return nil
}

type staticNodeUpdatePreflight struct {
	plan  NodeUpdatePreflightPlan
	calls int
}

func (preflight *staticNodeUpdatePreflight) Preflight(context.Context, model.ComponentManifest) (NodeUpdatePreflightPlan, error) {
	preflight.calls++
	return preflight.plan, nil
}

func updateTestEnrollmentIdentity(now time.Time) *model.EnrollmentIdentity {
	return &model.EnrollmentIdentity{
		SchemaVersion: model.ResourceSchemaVersion, Algorithm: "Ed25519", Fingerprint: "sha256:" + strings.Repeat("a", 64),
		PublicKeyRef: "enrollment-public:gateway", PrivateKeyRef: "enrollment-private:gateway", Generation: 1, CreatedAt: now,
	}
}

func updateTestGatewayNode(id, name, address string, now time.Time) model.Node {
	return model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: id, Name: name, Lifecycle: model.LifecycleActive, OverlayIPv4: address,
		CredentialGeneration: 1, AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
		IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: now,
	}
}

func updateTestConsumedInvite(state model.State, node model.Node, protocol string, now time.Time) model.Invite {
	consumed := now.Add(time.Minute)
	inviteID := "inv-ABC234"
	if node.Name == "old" {
		inviteID = "inv-ABC235"
	}
	return model.Invite{
		SchemaVersion: model.ResourceSchemaVersion, ID: inviteID, NodeName: node.Name,
		ControlProtocol: protocol, GatewayEndpoint: "https://" + state.Host.PublicIPv4 + "/.well-known/vpnctl/enroll",
		EnrollmentFingerprint: state.EnrollmentIdentity.Fingerprint, SecretHash: strings.Repeat("b", 64), State: model.InviteConsumed,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(14 * time.Minute), ConsumedAt: &consumed, ConsumptionHash: strings.Repeat("c", 64),
	}
}

func updateTestNodeTransport(node model.Node, reference model.SecretRef) model.Transport {
	return model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: node.ID,
		Kind: model.TransportStandard, State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP,
		Port: 51820, CredentialGeneration: 1, CredentialRef: reference, PublicKey: "public-" + node.Name,
		ConfigHash: strings.Repeat("d", 64),
	}
}
