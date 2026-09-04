package operations

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestRepairRestoresOnlyOwnedDriftToAppliedGenerationAndPreservesPendingAndForeign(t *testing.T) {
	t.Parallel()

	missingKey := ManagedResourceKey{Component: "dns", Kind: ManagedResourceFile, ID: "/etc/vpnctl/dns.conf"}
	modifiedKey := ManagedResourceKey{Component: "ingress", Kind: ManagedResourceFile, ID: "/etc/vpnctl/nginx.conf"}
	unexpectedKey := ManagedResourceKey{Component: "routing", Kind: ManagedResourceNetwork, ID: "owned-orphan"}
	foreignKey := ManagedResourceKey{Component: "foreign", Kind: ManagedResourceFile, ID: "/etc/foreign/service.conf"}
	applied := convergenceManifest(t, 7, []ManagedResource{
		resource(missingKey, "applied-missing", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
		resource(modifiedKey, "applied-modified", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	})
	desired := convergenceManifest(t, 8, []ManagedResource{
		resource(missingKey, "applied-missing", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
		resource(modifiedKey, "future-pending", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	})
	source := &applySnapshotSource{snapshot: ConvergenceSnapshot{
		Desired: desired, Applied: applied,
		Pending: []PendingOperation{{
			ID: "operation-1", Type: "apply", ExpectedGeneration: 7, DesiredGeneration: 8,
			Resources: []ManagedResourceKey{modifiedKey},
		}},
	}}
	discovery := &applyDiscovery{observed: []OwnedResourceObservation{
		observation(modifiedKey, "manual-modification", ConvergenceImpactAvailability),
		observation(unexpectedKey, "owned-orphan", ConvergenceImpactDestructive),
	}}
	resolver := &repairScopeMap{scopes: map[string]ApplyScope{
		resourceOrder(missingKey):    {Role: model.RoleGateway},
		resourceOrder(modifiedKey):   {Role: model.RoleGateway},
		resourceOrder(unexpectedKey): {Role: model.RoleGateway},
	}}
	foreignHash := ManagedFingerprint([]byte("foreign-byte-identical"))
	executor := &recordingGatewayRepair{actual: map[string]string{
		resourceOrder(modifiedKey):   ManagedFingerprint([]byte("manual-modification")),
		resourceOrder(unexpectedKey): ManagedFingerprint([]byte("owned-orphan")),
		resourceOrder(foreignKey):    foreignHash,
	}}
	coordinator := newGatewayRepairFixture(t, source, discovery, resolver, executor)
	beforeSnapshot := source.snapshot

	plan, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if plan.TargetGeneration != 7 || plan.Convergence.DesiredGeneration != 8 || len(plan.Actions) != 3 {
		t.Fatalf("repair plan = %+v", plan)
	}
	for _, action := range plan.Actions {
		if action.Resource == modifiedKey && action.TargetSHA256 != applied.Resources[1].RuntimeSHA256 {
			t.Fatalf("modified repair targets pending desired instead of applied: %+v", action)
		}
	}
	result, err := coordinator.Repair(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Generation != 7 || len(result.Resources) != 3 || executor.calls != 1 {
		t.Fatalf("repair result = %+v; executor calls=%d", result, executor.calls)
	}
	for _, action := range plan.Actions {
		actual, present := executor.actual[resourceOrder(action.Resource)]
		if action.Action == RepairRestore && (!present || actual != action.TargetSHA256) {
			t.Fatalf("restored resource does not match applied hash: %+v actual=%q", action, actual)
		}
		if action.Action == RepairRemove && present {
			t.Fatalf("unexpected owned resource was not removed: %+v", action)
		}
	}
	if executor.actual[resourceOrder(foreignKey)] != foreignHash {
		t.Fatal("foreign resource changed during repair")
	}
	if !reflect.DeepEqual(source.snapshot, beforeSnapshot) {
		t.Fatal("repair changed desired/applied/pending authoritative snapshot")
	}
	if source.reads != 2 || discovery.calls != 2 || resolver.calls != 6 {
		t.Fatalf("plan/revalidation calls = source:%d discovery:%d resolver:%d", source.reads, discovery.calls, resolver.calls)
	}
}

func TestRepairRejectsStalePreviewAndUnownedInjectedAction(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "ingress", Kind: ManagedResourceFile, ID: "/etc/vpnctl/nginx.conf"}
	source, discovery := singleRepairDrift(t, key)
	resolver := &repairScopeMap{scopes: map[string]ApplyScope{resourceOrder(key): {Role: model.RoleGateway}}}
	executor := &recordingGatewayRepair{}
	coordinator := newGatewayRepairFixture(t, source, discovery, resolver, executor)
	approved, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	foreign := RepairAction{
		Resource:  ManagedResourceKey{Component: "foreign", Kind: ManagedResourceFile, ID: "/etc/foreign.conf"},
		DriftKind: OwnedDriftUnexpected, Action: RepairRemove, Impact: ConvergenceImpactDestructive,
		Scope: ApplyScope{Role: model.RoleGateway}, ObservedSHA256: ManagedFingerprint([]byte("foreign")),
	}
	tampered := approved
	tampered.Actions = append(cloneRepairActions(approved.Actions), foreign)
	if _, err := coordinator.Repair(context.Background(), tampered); !errors.Is(err, ErrRepairInvalid) {
		t.Fatalf("unowned injected action error = %v", err)
	}
	if executor.calls != 0 {
		t.Fatal("unowned injected action reached executor")
	}

	discovery.observed[0] = observation(key, "changed-after-preview", ConvergenceImpactAvailability)
	if _, err := coordinator.Repair(context.Background(), approved); !errors.Is(err, ErrRepairConflict) {
		t.Fatalf("stale repair preview error = %v", err)
	}
	if executor.calls != 0 {
		t.Fatal("stale repair preview reached executor")
	}
}

func TestRepairRejectsExecutorHashOrAbsenceMismatch(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "dns", Kind: ManagedResourceFile, ID: "/etc/vpnctl/dns.conf"}
	source, discovery := singleRepairDrift(t, key)
	resolver := &repairScopeMap{scopes: map[string]ApplyScope{resourceOrder(key): {Role: model.RoleGateway}}}
	executor := &recordingGatewayRepair{result: &RepairExecutionResult{
		Changed: true, TargetGeneration: 3,
		Resources: []RepairResourceResult{{Resource: key, Present: true, RuntimeSHA256: ManagedFingerprint([]byte("wrong"))}},
	}}
	coordinator := newGatewayRepairFixture(t, source, discovery, resolver, executor)
	plan, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Repair(context.Background(), plan); !errors.Is(err, ErrRepairInvalid) {
		t.Fatalf("wrong repaired hash error = %v", err)
	}
}

func TestGatewayRepairCannotSimulateNodeOrPartiallyRepairMixedScope(t *testing.T) {
	t.Parallel()

	firstKey := ManagedResourceKey{Component: "ingress", Kind: ManagedResourceFile, ID: "/etc/vpnctl/nginx.conf"}
	secondKey := ManagedResourceKey{Component: "routing", Kind: ManagedResourceNetwork, ID: "node-routes"}
	manifest := convergenceManifest(t, 5, []ManagedResource{
		resource(firstKey, "first", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
		resource(secondKey, "second", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	})
	source := &applySnapshotSource{snapshot: ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}}}
	discovery := &applyDiscovery{observed: []OwnedResourceObservation{
		observation(firstKey, "first-drift", ConvergenceImpactAvailability),
		observation(secondKey, "second-drift", ConvergenceImpactAvailability),
	}}
	resolver := &repairScopeMap{scopes: map[string]ApplyScope{
		resourceOrder(firstKey):  {Role: model.RoleGateway},
		resourceOrder(secondKey): {Role: model.RoleNode, NodeID: applyNodeID},
	}}
	executor := &recordingGatewayRepair{}
	coordinator := newGatewayRepairFixture(t, source, discovery, resolver, executor)
	if _, err := coordinator.Plan(context.Background()); !errors.Is(err, ErrRepairNodeAgentUnavailable) {
		t.Fatalf("gateway node repair error = %v", err)
	}
	if executor.calls != 0 {
		t.Fatal("gateway partially executed mixed repair")
	}
}

func TestNodeRepairRequiresGatewayAndCurrentNodeScope(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "routing", Kind: ManagedResourceNetwork, ID: "node-routes"}
	source, discovery := singleRepairDrift(t, key)
	resolver := &repairScopeMap{scopes: map[string]ApplyScope{resourceOrder(key): {Role: model.RoleNode, NodeID: applyNodeID}}}
	executor := &recordingNodeRepair{}
	coordinator := newNodeRepairFixture(t, source, discovery, resolver, executor)
	plan, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Repair(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || executor.requireCalls != 1 || executor.repairCalls != 1 ||
		executor.batch.Role != model.RoleNode || executor.batch.CurrentNodeID != applyNodeID {
		t.Fatalf("node repair = %+v; executor=%+v", result, executor)
	}

	resolver.scopes[resourceOrder(key)] = ApplyScope{Role: model.RoleNode, NodeID: applyOtherNodeID}
	if _, err := coordinator.Plan(context.Background()); !errors.Is(err, ErrRepairConflict) {
		t.Fatalf("foreign node repair error = %v", err)
	}
	if executor.repairCalls != 1 {
		t.Fatal("foreign-node repair reached executor")
	}
}

func TestNodeRepairRequiresGatewayEvenForNoOp(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "routing", Kind: ManagedResourceNetwork, ID: "node-routes"}
	manifest := convergenceManifest(t, 3, []ManagedResource{resource(key, "same", ConvergenceImpactNone, ConvergenceImpactNone)})
	source := &applySnapshotSource{snapshot: ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}}}
	executor := &recordingNodeRepair{gatewayErr: errors.New("gateway unavailable")}
	coordinator := newNodeRepairFixture(t, source, &applyDiscovery{observed: observationsFromResources(manifest.Resources)}, &repairScopeMap{scopes: map[string]ApplyScope{}}, executor)
	plan, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Repair(context.Background(), plan); !errors.Is(err, ErrRepairGatewayUnavailable) {
		t.Fatalf("node no-op gateway error = %v", err)
	}
	if executor.requireCalls != 1 || executor.repairCalls != 0 {
		t.Fatalf("node executor calls = %d/%d", executor.requireCalls, executor.repairCalls)
	}
}

func TestGatewayRepairNoOpDoesNotInvokeExecutor(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "control", Kind: ManagedResourceState, ID: "fleet"}
	manifest := convergenceManifest(t, 3, []ManagedResource{resource(key, "same", ConvergenceImpactNone, ConvergenceImpactNone)})
	executor := &recordingGatewayRepair{}
	coordinator := newGatewayRepairFixture(t,
		&applySnapshotSource{snapshot: ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}}},
		&applyDiscovery{observed: observationsFromResources(manifest.Resources)},
		&repairScopeMap{scopes: map[string]ApplyScope{}}, executor,
	)
	plan, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Repair(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Generation != 3 || len(result.Actions) != 0 || len(result.Resources) != 0 || executor.calls != 0 {
		t.Fatalf("no-op repair = %+v; executor calls=%d", result, executor.calls)
	}
}

type repairScopeMap struct {
	scopes map[string]ApplyScope
	calls  int
}

func (resolver *repairScopeMap) ResolveRepairScope(action RepairAction) (ApplyScope, error) {
	resolver.calls++
	scope, exists := resolver.scopes[resourceOrder(action.Resource)]
	if !exists {
		return ApplyScope{}, errors.New("resource has no registered repair scope")
	}
	return scope, nil
}

type recordingGatewayRepair struct {
	calls  int
	batch  RepairExecutionBatch
	actual map[string]string
	result *RepairExecutionResult
}

func (executor *recordingGatewayRepair) RepairGateway(_ context.Context, batch RepairExecutionBatch) (RepairExecutionResult, error) {
	executor.calls++
	executor.batch = batch
	if executor.result != nil {
		return *executor.result, nil
	}
	if executor.actual == nil {
		executor.actual = map[string]string{}
	}
	resources := make([]RepairResourceResult, len(batch.Actions))
	for index, action := range batch.Actions {
		switch action.Action {
		case RepairRestore:
			executor.actual[resourceOrder(action.Resource)] = action.TargetSHA256
			resources[index] = RepairResourceResult{Resource: action.Resource, Present: true, RuntimeSHA256: action.TargetSHA256}
		case RepairRemove:
			delete(executor.actual, resourceOrder(action.Resource))
			resources[index] = RepairResourceResult{Resource: action.Resource}
		}
	}
	return RepairExecutionResult{Changed: true, TargetGeneration: batch.TargetGeneration, Resources: resources}, nil
}

type recordingNodeRepair struct {
	requireCalls int
	repairCalls  int
	gatewayErr   error
	batch        RepairExecutionBatch
}

func (executor *recordingNodeRepair) RequireGateway(context.Context, string) error {
	executor.requireCalls++
	return executor.gatewayErr
}

func (executor *recordingNodeRepair) RepairCurrentNode(_ context.Context, batch RepairExecutionBatch) (RepairExecutionResult, error) {
	executor.repairCalls++
	executor.batch = batch
	resources := make([]RepairResourceResult, len(batch.Actions))
	for index, action := range batch.Actions {
		if action.Action == RepairRestore {
			resources[index] = RepairResourceResult{Resource: action.Resource, Present: true, RuntimeSHA256: action.TargetSHA256}
		} else {
			resources[index] = RepairResourceResult{Resource: action.Resource}
		}
	}
	return RepairExecutionResult{Changed: true, TargetGeneration: batch.TargetGeneration, Resources: resources}, nil
}

func newGatewayRepairFixture(
	t *testing.T,
	source *applySnapshotSource,
	discovery *applyDiscovery,
	resolver *repairScopeMap,
	executor *recordingGatewayRepair,
) *RepairCoordinator {
	t.Helper()
	planner, err := NewConvergencePlanner(source, discovery)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewGatewayRepairCoordinator(planner, resolver, executor)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func newNodeRepairFixture(
	t *testing.T,
	source *applySnapshotSource,
	discovery *applyDiscovery,
	resolver *repairScopeMap,
	executor *recordingNodeRepair,
) *RepairCoordinator {
	t.Helper()
	planner, err := NewConvergencePlanner(source, discovery)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewNodeRepairCoordinator(applyNodeID, planner, resolver, executor)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func singleRepairDrift(t *testing.T, key ManagedResourceKey) (*applySnapshotSource, *applyDiscovery) {
	t.Helper()
	manifest := convergenceManifest(t, 3, []ManagedResource{resource(key, "applied", ConvergenceImpactAvailability, ConvergenceImpactAvailability)})
	return &applySnapshotSource{snapshot: ConvergenceSnapshot{
		Desired: manifest, Applied: manifest, Pending: []PendingOperation{},
	}}, &applyDiscovery{observed: []OwnedResourceObservation{observation(key, "modified", ConvergenceImpactAvailability)}}
}
