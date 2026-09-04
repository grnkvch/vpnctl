package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if _, err := fixture.snapshots.LoadPrevious(context.Background()); !errors.Is(err, ErrUpdateSnapshotNotFound) {
		t.Fatalf("failed update retained rollback snapshot: %v", err)
	}
}

func TestUpdateRollbackRestoresPreviousReleaseAndStateAndConsumesSnapshot(t *testing.T) {
	fixture := newUpdaterFixture(t, model.RoleGateway, "new")
	originalState := fixture.state.state
	originalFiles := snapshotReleaseUpdateRoot(t, fixture.root)
	plan, err := fixture.updater.Plan(context.Background(), "v2.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.updater.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	snapshot, err := fixture.snapshots.LoadPrevious(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot.State, originalState) || snapshot.Metadata.PreviousVersion != "v2.0.0" || snapshot.Metadata.UpdatedToVersion != "v2.1.0" {
		t.Fatalf("previous snapshot=%+v state_equal=%t", snapshot.Metadata, reflect.DeepEqual(snapshot.State, originalState))
	}
	_ = snapshot.Close()

	fixture.updater.runtime.NewUUID = func() (string, error) { return "90000000-0000-4000-8000-000000000020", nil }
	rollbackPlan, err := fixture.updater.PlanRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rollbackPlan.Blocked || rollbackPlan.CurrentVersion != "v2.1.0" || rollbackPlan.TargetVersion != "v2.0.0" || len(rollbackPlan.Components) == 0 {
		t.Fatalf("rollback plan = %+v", rollbackPlan)
	}
	if fixture.source.requests != 1 {
		t.Fatalf("rollback contacted release source: requests=%d", fixture.source.requests)
	}
	result, err := fixture.updater.ApplyRollback(context.Background(), rollbackPlan)
	if err != nil {
		t.Fatal(err)
	}
	if result.CurrentVersion != "v2.0.0" || !result.Changed || fixture.state.state.Components.VPNCTLVersion != "v2.0.0" ||
		len(fixture.state.state.Operations) != 2 || fixture.state.state.Operations[1].Type != model.OperationUpdateRollback ||
		fixture.state.state.Operations[1].State != model.OperationCompleted {
		t.Fatalf("rollback result=%+v state=%+v", result, fixture.state.state)
	}
	restored := fixture.state.state
	restored.Generation = originalState.Generation
	restored.Operations = append([]model.Operation{}, originalState.Operations...)
	if !reflect.DeepEqual(restored, originalState) {
		t.Fatalf("rollback did not restore prior semantic state")
	}
	if after := snapshotReleaseUpdateRoot(t, fixture.root); !reflect.DeepEqual(after, originalFiles) {
		t.Fatalf("rollback release tree differs from exact prior tree")
	}
	if _, err := fixture.snapshots.LoadPrevious(context.Background()); !errors.Is(err, ErrUpdateSnapshotNotFound) {
		t.Fatalf("consumed snapshot remains available: %v", err)
	}
}

func TestUpdateRollbackRefusesIrreversibleMigrationBeforeMutation(t *testing.T) {
	fixture := updatedFixtureWithSnapshot(t, model.RoleNode)
	loaded, err := fixture.snapshots.LoadPrevious(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	metadata := loaded.Metadata
	_ = loaded.Close()
	metadata.MigrationReversible = false
	encoded, _ := encodeUpdateSnapshotJSON(metadata)
	path := filepath.Join(fixture.snapshots.root, "update-"+metadata.SnapshotID, updateSnapshotMetadataFile)
	if err := replaceUpdateSnapshotFile(path, encoded, true); err != nil {
		t.Fatal(err)
	}
	assertUpdateRollbackBlockedWithoutMutation(t, &fixture, "irreversible")
}

func TestUpdateRollbackRefusesStateChangedAfterUpdateBeforeMutation(t *testing.T) {
	fixture := updatedFixtureWithSnapshot(t, model.RoleGateway)
	fixture.state.state.Generation++
	assertUpdateRollbackBlockedWithoutMutation(t, &fixture, "state changed")
}

func TestUpdateRollbackWithoutSnapshotDoesNotContactReleaseSourceOrHost(t *testing.T) {
	fixture := newUpdaterFixture(t, model.RoleGateway, "new")
	if _, err := fixture.updater.PlanRollback(context.Background()); !errors.Is(err, ErrUpdateSnapshotNotFound) {
		t.Fatalf("rollback without snapshot = %v", err)
	}
	if fixture.source.requests != 0 || fixture.state.saves != 0 || len(fixture.host.calls) != 0 {
		t.Fatalf("missing rollback snapshot caused work: source=%d saves=%d calls=%v", fixture.source.requests, fixture.state.saves, fixture.host.calls)
	}
}

func updatedFixtureWithSnapshot(t *testing.T, role model.Role) updaterFixture {
	t.Helper()
	fixture := newUpdaterFixture(t, role, "new")
	plan, err := fixture.updater.Plan(context.Background(), "v2.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.updater.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	fixture.updater.runtime.NewUUID = func() (string, error) { return "90000000-0000-4000-8000-000000000020", nil }
	return fixture
}

func assertUpdateRollbackBlockedWithoutMutation(t *testing.T, fixture *updaterFixture, expectedAction string) {
	t.Helper()
	beforeSaves, beforeCalls := fixture.state.saves, len(fixture.host.calls)
	plan, err := fixture.updater.PlanRollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.updater.DiscardRollback(plan)
	if !plan.Blocked || len(plan.RequiresAction) != 1 || !strings.Contains(plan.RequiresAction[0], expectedAction) ||
		fixture.state.saves != beforeSaves || len(fixture.host.calls) != beforeCalls {
		t.Fatalf("blocked rollback=%+v saves=%d calls=%v", plan, fixture.state.saves, fixture.host.calls)
	}
	if _, err := fixture.updater.ApplyRollback(context.Background(), plan); !errors.Is(err, ErrUpdateIncompatible) {
		t.Fatalf("blocked rollback apply = %v", err)
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

func TestUpdaterRejectsInstalledDriftAfterPlanningBeforeMutation(t *testing.T) {
	fixture := newUpdaterFixture(t, model.RoleGateway, "new")
	plan, err := fixture.updater.Plan(context.Background(), "v2.1.0")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.root, "usr/local/bin/vpnctl")
	if err := os.WriteFile(path, []byte("drift-after-plan"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.updater.Apply(context.Background(), plan); !errors.Is(err, ErrReleaseUpdateConflict) {
		t.Fatalf("post-plan drift apply = %v", err)
	}
	if fixture.state.saves != 0 || len(fixture.host.calls) != 1 {
		t.Fatalf("post-plan drift mutated state/service: saves=%d calls=%v", fixture.state.saves, fixture.host.calls)
	}
}

func TestControllerOnlyUpdateKeepsForwardingAndNeverRestartsDataPlane(t *testing.T) {
	fixture := newUpdaterFixture(t, model.RoleGateway, "new")
	configureControllerOnlyUpdate(t, &fixture)
	host := newContinuityUpdateHost()
	fixture.updater.runtime.Host = host
	plan, err := fixture.updater.Plan(context.Background(), "v2.1.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, component := range plan.Components {
		if component.Name != "vpnctl" && (component.FileChanged || len(component.AffectedServices) != 0) {
			t.Fatalf("controller-only plan changes data plane: %+v", component)
		}
	}
	if _, err := fixture.updater.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	wantRestarts := map[string]int{"vpnctl-controller.service": 1}
	if !host.forwarding || host.forwardingChecks < 4 || host.forwardingWhileQuiesced < 2 || !reflect.DeepEqual(host.restarts, wantRestarts) || len(host.rollbacks) != 0 {
		t.Fatalf("controller-only continuity forwarding=%t checks=%d while-quiesced=%d restarts=%v rollbacks=%v calls=%v", host.forwarding, host.forwardingChecks, host.forwardingWhileQuiesced, host.restarts, host.rollbacks, host.calls)
	}
	for _, dataPlane := range []string{
		"vpnctl-standard.service", "vpnctl-restricted.service", "vpnctl-dns.service",
		"vpnctl-tunnel-server.service", "vpnctl-routing.service", "vpnctl-tunnel-client.service", "nginx.service",
	} {
		if host.restarts[dataPlane] != 0 || host.rollbacks[dataPlane] != 0 {
			t.Fatalf("unchanged data-plane service %s was restarted or rolled back", dataPlane)
		}
	}
	want := []string{"preflight:gateway", "quiesce:gateway", "activate:vpnctl", "resume:gateway"}
	if !reflect.DeepEqual(host.calls, want) {
		t.Fatalf("controller-only calls=%v want=%v", host.calls, want)
	}
}

func TestChangedComponentRollbackCountersExcludeUntouchedUnits(t *testing.T) {
	for _, test := range []struct {
		failed        string
		wantRestarts  map[string]int
		wantRollbacks map[string]int
	}{
		{
			failed:        "frp",
			wantRestarts:  map[string]int{"vpnctl-tunnel-client.service": 1},
			wantRollbacks: map[string]int{"vpnctl-tunnel-client.service": 1},
		},
		{
			failed:        "mihomo",
			wantRestarts:  map[string]int{"vpnctl-tunnel-client.service": 1, "vpnctl-routing.service": 1},
			wantRollbacks: map[string]int{"vpnctl-tunnel-client.service": 1, "vpnctl-routing.service": 1},
		},
	} {
		t.Run(test.failed, func(t *testing.T) {
			fixture := newUpdaterFixture(t, model.RoleNode, "new")
			host := newContinuityUpdateHost()
			host.failHealth = test.failed
			fixture.updater.runtime.Host = host
			plan, err := fixture.updater.Plan(context.Background(), "v2.1.0")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.updater.Apply(context.Background(), plan); !errors.Is(err, ErrUpdateHealth) {
				t.Fatalf("health failure = %v", err)
			}
			if !reflect.DeepEqual(host.restarts, test.wantRestarts) || !reflect.DeepEqual(host.rollbacks, test.wantRollbacks) {
				t.Fatalf("component counters restarts=%v rollbacks=%v", host.restarts, host.rollbacks)
			}
			for _, untouched := range []string{"nginx.service", "vpnctl-controller.service", "vpnctl-restricted.service"} {
				if host.restarts[untouched] != 0 || host.rollbacks[untouched] != 0 {
					t.Fatalf("untouched service %s was restarted or rolled back", untouched)
				}
			}
		})
	}
}

func configureControllerOnlyUpdate(t *testing.T, fixture *updaterFixture) {
	t.Helper()
	installed := map[string][]byte{
		"vpnctl": []byte("vpnctl-controller-only"), "frpc": []byte("frpc-old"),
		"frps": []byte("frps-old"), "mihomo": []byte("mihomo-old"),
	}
	assets, manifest := updateReleaseAssetsForInstalled(t, fixture.signingKey, "v2.1.0", installed, map[string]string{
		"frp": "0.69.0-old", "mihomo": "v1.19.30-old",
	})
	fixture.source.stage = writeStagedUpdateRelease(t, assets, manifest)
	fixture.targetAssets = assets
	fixture.targetInstalled = installed
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
	snapshots       *FilesystemUpdateSnapshotStore
	signingKey      ed25519.PrivateKey
}

func newUpdaterFixture(t *testing.T, role model.Role, targetMarker string) updaterFixture {
	t.Helper()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	installer, _ := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	snapshotRoot := filepath.Join(root, "var/lib/vpnctl/snapshots")
	if err := os.MkdirAll(snapshotRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshots, err := NewFilesystemUpdateSnapshotStore(snapshotRoot, publicKey, installer)
	if err != nil {
		t.Fatal(err)
	}
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
		State: stateStore, Snapshots: snapshots, Releases: source, Bundles: installer, Fleet: fleet, Host: host,
		CurrentBundlePath: standardReleaseBundleInRoot(root), Now: func() time.Time { return now.Add(time.Minute) },
		NewUUID: func() (string, error) { return "90000000-0000-4000-8000-000000000010", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return updaterFixture{
		root: root, updater: updater, state: stateStore, source: source, fleet: fleet, host: host,
		targetAssets: targetAssets, targetInstalled: targetInstalled, snapshots: snapshots, signingKey: privateKey,
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

type continuityUpdateHost struct {
	*recordingUpdateHost
	forwarding              bool
	forwardingChecks        int
	managementDown          bool
	forwardingWhileQuiesced int
	restarts                map[string]int
	rollbacks               map[string]int
}

func newContinuityUpdateHost() *continuityUpdateHost {
	return &continuityUpdateHost{
		recordingUpdateHost: &recordingUpdateHost{}, forwarding: true,
		restarts: map[string]int{}, rollbacks: map[string]int{},
	}
}

func (host *continuityUpdateHost) observeForwarding() {
	if host.forwarding {
		host.forwardingChecks++
		if host.managementDown {
			host.forwardingWhileQuiesced++
		}
	}
}

func (host *continuityUpdateHost) Preflight(ctx context.Context, role model.Role, manifest ReleaseManifest) ([]UpdatePackageCheck, error) {
	host.observeForwarding()
	return host.recordingUpdateHost.Preflight(ctx, role, manifest)
}

func (host *continuityUpdateHost) QuiesceManagement(ctx context.Context, role model.Role) error {
	host.observeForwarding()
	if err := host.recordingUpdateHost.QuiesceManagement(ctx, role); err != nil {
		return err
	}
	host.managementDown = role == model.RoleGateway
	host.observeForwarding()
	return nil
}

func (host *continuityUpdateHost) ActivateAndHealth(ctx context.Context, role model.Role, change UpdateComponentChange) error {
	host.observeForwarding()
	for _, service := range change.AffectedServices {
		host.restarts[service]++
	}
	return host.recordingUpdateHost.ActivateAndHealth(ctx, role, change)
}

func (host *continuityUpdateHost) RollbackAndHealth(ctx context.Context, role model.Role, change UpdateComponentChange) error {
	host.observeForwarding()
	for _, service := range change.AffectedServices {
		host.rollbacks[service]++
	}
	return host.recordingUpdateHost.RollbackAndHealth(ctx, role, change)
}

func (host *continuityUpdateHost) ResumeManagement(ctx context.Context, role model.Role) error {
	host.observeForwarding()
	if err := host.recordingUpdateHost.ResumeManagement(ctx, role); err != nil {
		return err
	}
	host.managementDown = false
	host.observeForwarding()
	return nil
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
