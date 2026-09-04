package operations

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	applyNodeID      = "74000000-0000-4000-8000-000000000001"
	applyOtherNodeID = "74000000-0000-4000-8000-000000000002"
)

func TestGatewayApplyExecutesOnlyRegisteredChangesAndLeavesUnrelatedDrift(t *testing.T) {
	t.Parallel()

	changeKey := ManagedResourceKey{Component: "ingress", Kind: ManagedResourceFile, ID: "/etc/vpnctl/nginx.conf"}
	driftKey := ManagedResourceKey{Component: "transport", Kind: ManagedResourceUnit, ID: "vpnctl-standard.service"}
	applied := convergenceManifest(t, 4, []ManagedResource{
		resource(changeKey, "old", ConvergenceImpactNone, ConvergenceImpactNone),
		resource(driftKey, "unit", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	})
	desired := convergenceManifest(t, 5, []ManagedResource{
		resource(changeKey, "new", ConvergenceImpactNone, ConvergenceImpactNone),
		resource(driftKey, "unit", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	})
	source := &applySnapshotSource{snapshot: ConvergenceSnapshot{
		Desired: desired, Applied: applied,
		Pending: []PendingOperation{{
			ID: "operation-1", Type: "apply", ExpectedGeneration: 4, DesiredGeneration: 5,
			Resources: []ManagedResourceKey{changeKey},
		}},
	}}
	discovery := &applyDiscovery{observed: []OwnedResourceObservation{
		observation(changeKey, "old", ConvergenceImpactNone),
		observation(driftKey, "manually-stopped", ConvergenceImpactAvailability),
	}}
	resolver := &applyScopeMap{scopes: map[string]ApplyScope{"operation-1": {Role: model.RoleGateway}}}
	executor := &recordingGatewayApply{}
	coordinator := newGatewayApplyFixture(t, source, discovery, resolver, executor)

	plan, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Impact != ConvergenceImpactNone || len(plan.Operations) != 1 || len(plan.RemainingDrift) != 1 ||
		plan.Operations[0].Changes[0].Resource != changeKey || plan.RemainingDrift[0].Resource != driftKey {
		t.Fatalf("apply plan = %+v", plan)
	}
	result, err := coordinator.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Generation != 5 || !reflect.DeepEqual(result.OperationIDs, []string{"operation-1"}) ||
		len(result.RemainingDrift) != 1 || executor.calls != 1 {
		t.Fatalf("apply result = %+v; executor calls=%d", result, executor.calls)
	}
	if len(executor.batch.Operations) != 1 || len(executor.batch.Operations[0].Changes) != 1 ||
		executor.batch.Operations[0].Changes[0].Resource != changeKey ||
		executor.batch.Operations[0].ExpectedGeneration != 4 || executor.batch.Operations[0].DesiredGeneration != 5 {
		t.Fatalf("executor received non-pending work: %+v", executor.batch)
	}
	if source.reads != 2 || discovery.calls != 2 || resolver.calls != 2 {
		t.Fatalf("plan/revalidation calls = source:%d discovery:%d resolver:%d", source.reads, discovery.calls, resolver.calls)
	}
}

func TestApplyRejectsUnregisteredDiffAndGenerationOnlyGap(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "dns", Kind: ManagedResourceFile, ID: "/etc/vpnctl/dns.conf"}
	applied := convergenceManifest(t, 4, []ManagedResource{resource(key, "old", ConvergenceImpactAvailability, ConvergenceImpactAvailability)})
	desired := convergenceManifest(t, 5, []ManagedResource{resource(key, "new", ConvergenceImpactAvailability, ConvergenceImpactAvailability)})
	executor := &recordingGatewayApply{}
	resolver := &applyScopeMap{scopes: map[string]ApplyScope{}}
	coordinator := newGatewayApplyFixture(t, &applySnapshotSource{snapshot: ConvergenceSnapshot{
		Desired: desired, Applied: applied, Pending: []PendingOperation{},
	}}, &applyDiscovery{observed: observationsFromResources(applied.Resources)}, resolver, executor)
	if _, err := coordinator.Plan(context.Background()); !errors.Is(err, ErrConvergencePlanInvalid) {
		t.Fatalf("unregistered diff error = %v", err)
	}
	if resolver.calls != 0 || executor.calls != 0 {
		t.Fatal("unregistered diff reached scope resolution or execution")
	}

	sameDesired := applied
	sameDesired.Generation = 5
	coordinator = newGatewayApplyFixture(t, &applySnapshotSource{snapshot: ConvergenceSnapshot{
		Desired: sameDesired, Applied: applied, Pending: []PendingOperation{},
	}}, &applyDiscovery{observed: observationsFromResources(applied.Resources)}, resolver, executor)
	if _, err := coordinator.Plan(context.Background()); !errors.Is(err, ErrApplyInvalid) {
		t.Fatalf("generation-only gap error = %v", err)
	}
	if executor.calls != 0 {
		t.Fatal("generation-only gap reached executor")
	}

	coordinator = newGatewayApplyFixture(t, &applySnapshotSource{snapshot: ConvergenceSnapshot{
		Desired: desired, Applied: applied,
		Pending: []PendingOperation{{
			ID: "operation-1", Type: "apply", ExpectedGeneration: 3, DesiredGeneration: 5,
			Resources: []ManagedResourceKey{key},
		}},
	}}, &applyDiscovery{observed: observationsFromResources(applied.Resources)}, resolver, executor)
	if _, err := coordinator.Plan(context.Background()); !errors.Is(err, ErrConvergencePlanInvalid) {
		t.Fatalf("stale pending generation error = %v", err)
	}
}

func TestApplyRejectsOverlappingOwnedDriftBeforeScopeOrExecution(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "routing", Kind: ManagedResourceNetwork, ID: "policy-rules"}
	applied := convergenceManifest(t, 7, []ManagedResource{resource(key, "old", ConvergenceImpactAvailability, ConvergenceImpactAvailability)})
	desired := convergenceManifest(t, 8, []ManagedResource{resource(key, "new", ConvergenceImpactAvailability, ConvergenceImpactAvailability)})
	source := &applySnapshotSource{snapshot: ConvergenceSnapshot{
		Desired: desired, Applied: applied,
		Pending: []PendingOperation{{
			ID: "operation-1", Type: "policy-set", ExpectedGeneration: 7, DesiredGeneration: 8,
			Resources: []ManagedResourceKey{key},
		}},
	}}
	resolver := &applyScopeMap{scopes: map[string]ApplyScope{"operation-1": {Role: model.RoleGateway}}}
	executor := &recordingGatewayApply{}
	coordinator := newGatewayApplyFixture(t, source, &applyDiscovery{observed: []OwnedResourceObservation{
		observation(key, "manual-change", ConvergenceImpactAvailability),
	}}, resolver, executor)
	_, err := coordinator.Plan(context.Background())
	var conflict *ApplyDriftConflictError
	if !errors.As(err, &conflict) || !errors.Is(err, ErrApplyConflict) ||
		!reflect.DeepEqual(conflict.Resources, []ManagedResourceKey{key}) {
		t.Fatalf("overlapping drift error = %v", err)
	}
	if resolver.calls != 0 || executor.calls != 0 {
		t.Fatal("overlapping drift reached scope resolution or execution")
	}
}

func TestGatewayApplyCannotSimulateNodeAgentOrPartiallyApplyMixedBatch(t *testing.T) {
	t.Parallel()

	firstKey := ManagedResourceKey{Component: "control", Kind: ManagedResourceState, ID: "gateway"}
	secondKey := ManagedResourceKey{Component: "routing", Kind: ManagedResourceNetwork, ID: "node-routes"}
	applied := convergenceManifest(t, 10, []ManagedResource{
		resource(firstKey, "old-gateway", ConvergenceImpactNone, ConvergenceImpactNone),
		resource(secondKey, "old-node", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	})
	desired := convergenceManifest(t, 12, []ManagedResource{
		resource(firstKey, "new-gateway", ConvergenceImpactNone, ConvergenceImpactNone),
		resource(secondKey, "new-node", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	})
	source := &applySnapshotSource{snapshot: ConvergenceSnapshot{
		Desired: desired, Applied: applied,
		Pending: []PendingOperation{
			{ID: "operation-1", Type: "apply", ExpectedGeneration: 10, DesiredGeneration: 11, Resources: []ManagedResourceKey{firstKey}},
			{ID: "operation-2", Type: "policy-set", TargetKind: "node", TargetID: applyNodeID, ExpectedGeneration: 11, DesiredGeneration: 12, Resources: []ManagedResourceKey{secondKey}},
		},
	}}
	resolver := &applyScopeMap{scopes: map[string]ApplyScope{
		"operation-1": {Role: model.RoleGateway},
		"operation-2": {Role: model.RoleNode, NodeID: applyNodeID},
	}}
	executor := &recordingGatewayApply{}
	coordinator := newGatewayApplyFixture(t, source, &applyDiscovery{observed: observationsFromResources(applied.Resources)}, resolver, executor)
	if _, err := coordinator.Plan(context.Background()); !errors.Is(err, ErrApplyNodeAgentUnavailable) {
		t.Fatalf("gateway node-scope error = %v", err)
	}
	if executor.calls != 0 {
		t.Fatal("gateway partially executed a mixed gateway/node batch")
	}
}

func TestNodeApplyRequiresGatewayAndAcceptsOnlyCurrentNodeScope(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "transport", Kind: ManagedResourceFile, ID: "/etc/vpnctl/restricted.yaml"}
	source, discovery := singleApplyChange(t, key, "transport-switch", "node", applyNodeID)
	resolver := &applyScopeMap{scopes: map[string]ApplyScope{"operation-1": {Role: model.RoleNode, NodeID: applyNodeID}}}
	executor := &recordingNodeApply{}
	coordinator := newNodeApplyFixture(t, source, discovery, resolver, executor)
	plan, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || executor.requireCalls != 1 || executor.applyCalls != 1 ||
		executor.batch.Role != model.RoleNode || executor.batch.CurrentNodeID != applyNodeID {
		t.Fatalf("node result = %+v; executor=%+v", result, executor)
	}

	resolver.scopes["operation-1"] = ApplyScope{Role: model.RoleNode, NodeID: applyOtherNodeID}
	if _, err := coordinator.Plan(context.Background()); !errors.Is(err, ErrApplyConflict) {
		t.Fatalf("foreign-node scope error = %v", err)
	}
	if executor.applyCalls != 1 {
		t.Fatal("foreign-node plan reached node executor")
	}
}

func TestNodeApplyRequiresReachableGatewayEvenForNoOp(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "routing", Kind: ManagedResourceNetwork, ID: "node-routes"}
	manifest := convergenceManifest(t, 3, []ManagedResource{resource(key, "same", ConvergenceImpactNone, ConvergenceImpactNone)})
	source := &applySnapshotSource{snapshot: ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}}}
	executor := &recordingNodeApply{gatewayErr: errors.New("control endpoint unreachable")}
	coordinator := newNodeApplyFixture(t, source, &applyDiscovery{observed: observationsFromResources(manifest.Resources)}, &applyScopeMap{scopes: map[string]ApplyScope{}}, executor)
	plan, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Apply(context.Background(), plan); !errors.Is(err, ErrApplyGatewayUnavailable) {
		t.Fatalf("node gateway requirement error = %v", err)
	}
	if executor.requireCalls != 1 || executor.applyCalls != 0 {
		t.Fatalf("node executor calls = require:%d apply:%d", executor.requireCalls, executor.applyCalls)
	}
}

func TestApplyReplansAfterPreviewAndRejectsStalePlan(t *testing.T) {
	t.Parallel()

	changeKey := ManagedResourceKey{Component: "ingress", Kind: ManagedResourceFile, ID: "/etc/vpnctl/nginx.conf"}
	driftKey := ManagedResourceKey{Component: "transport", Kind: ManagedResourceUnit, ID: "vpnctl-standard.service"}
	applied := convergenceManifest(t, 4, []ManagedResource{
		resource(changeKey, "old", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
		resource(driftKey, "unit", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	})
	desired := convergenceManifest(t, 5, []ManagedResource{
		resource(changeKey, "new", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
		resource(driftKey, "unit", ConvergenceImpactAvailability, ConvergenceImpactAvailability),
	})
	source := &applySnapshotSource{snapshot: ConvergenceSnapshot{
		Desired: desired, Applied: applied,
		Pending: []PendingOperation{{ID: "operation-1", Type: "apply", ExpectedGeneration: 4, DesiredGeneration: 5, Resources: []ManagedResourceKey{changeKey}}},
	}}
	discovery := &applyDiscovery{observed: observationsFromResources(applied.Resources)}
	executor := &recordingGatewayApply{}
	coordinator := newGatewayApplyFixture(t, source, discovery, &applyScopeMap{scopes: map[string]ApplyScope{"operation-1": {Role: model.RoleGateway}}}, executor)
	approved, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	discovery.observed = []OwnedResourceObservation{
		observation(changeKey, "old", ConvergenceImpactAvailability),
		observation(driftKey, "changed-after-preview", ConvergenceImpactAvailability),
	}
	if _, err := coordinator.Apply(context.Background(), approved); !errors.Is(err, ErrApplyConflict) {
		t.Fatalf("stale preview error = %v", err)
	}
	if executor.calls != 0 {
		t.Fatal("stale preview reached executor")
	}
}

func TestApplyRejectsExecutorResultThatDoesNotMatchBatch(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "control", Kind: ManagedResourceState, ID: "fleet"}
	source, discovery := singleApplyChange(t, key, "apply", "", "")
	executor := &recordingGatewayApply{result: &ApplyExecutionResult{
		Changed: true, AppliedGeneration: 4, OperationIDs: []string{"another-operation"},
	}}
	coordinator := newGatewayApplyFixture(t, source, discovery, &applyScopeMap{scopes: map[string]ApplyScope{"operation-1": {Role: model.RoleGateway}}}, executor)
	plan, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Apply(context.Background(), plan); !errors.Is(err, ErrApplyInvalid) {
		t.Fatalf("invalid executor result error = %v", err)
	}
}

func TestGatewayApplyNoOpDoesNotInvokeExecutor(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{Component: "control", Kind: ManagedResourceState, ID: "fleet"}
	manifest := convergenceManifest(t, 3, []ManagedResource{resource(key, "same", ConvergenceImpactNone, ConvergenceImpactNone)})
	executor := &recordingGatewayApply{}
	coordinator := newGatewayApplyFixture(t,
		&applySnapshotSource{snapshot: ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}}},
		&applyDiscovery{observed: observationsFromResources(manifest.Resources)},
		&applyScopeMap{scopes: map[string]ApplyScope{}}, executor,
	)
	plan, err := coordinator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Generation != 3 || result.OperationIDs == nil || len(result.OperationIDs) != 0 || executor.calls != 0 {
		t.Fatalf("no-op result = %+v; executor calls=%d", result, executor.calls)
	}
}

type applySnapshotSource struct {
	snapshot ConvergenceSnapshot
	reads    int
}

func (source *applySnapshotSource) ReadConvergenceSnapshot(context.Context) (ConvergenceSnapshot, error) {
	source.reads++
	return source.snapshot, nil
}

type applyDiscovery struct {
	observed []OwnedResourceObservation
	calls    int
}

func (discovery *applyDiscovery) DiscoverOwnedResources(context.Context, ConvergenceManifest) ([]OwnedResourceObservation, error) {
	discovery.calls++
	return append([]OwnedResourceObservation(nil), discovery.observed...), nil
}

type applyScopeMap struct {
	scopes map[string]ApplyScope
	calls  int
}

func (resolver *applyScopeMap) ResolveApplyScope(operation ApplyOperation) (ApplyScope, error) {
	resolver.calls++
	scope, exists := resolver.scopes[operation.ID]
	if !exists {
		return ApplyScope{}, errors.New("operation has no registered scope")
	}
	return scope, nil
}

type recordingGatewayApply struct {
	calls  int
	batch  ApplyExecutionBatch
	result *ApplyExecutionResult
}

func (executor *recordingGatewayApply) ApplyGateway(_ context.Context, batch ApplyExecutionBatch) (ApplyExecutionResult, error) {
	executor.calls++
	executor.batch = batch
	if executor.result != nil {
		return *executor.result, nil
	}
	return successfulApplyExecution(batch), nil
}

type recordingNodeApply struct {
	requireCalls int
	applyCalls   int
	gatewayErr   error
	batch        ApplyExecutionBatch
}

func (executor *recordingNodeApply) RequireGateway(context.Context, string) error {
	executor.requireCalls++
	return executor.gatewayErr
}

func (executor *recordingNodeApply) ApplyCurrentNode(_ context.Context, batch ApplyExecutionBatch) (ApplyExecutionResult, error) {
	executor.applyCalls++
	executor.batch = batch
	return successfulApplyExecution(batch), nil
}

func successfulApplyExecution(batch ApplyExecutionBatch) ApplyExecutionResult {
	ids := make([]string, len(batch.Operations))
	for index, operation := range batch.Operations {
		ids[index] = operation.ID
	}
	return ApplyExecutionResult{Changed: true, AppliedGeneration: batch.DesiredGeneration, OperationIDs: ids}
}

func newGatewayApplyFixture(
	t *testing.T,
	source *applySnapshotSource,
	discovery *applyDiscovery,
	resolver *applyScopeMap,
	executor *recordingGatewayApply,
) *ApplyCoordinator {
	t.Helper()
	planner, err := NewConvergencePlanner(source, discovery)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewGatewayApplyCoordinator(planner, resolver, executor)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func newNodeApplyFixture(
	t *testing.T,
	source *applySnapshotSource,
	discovery *applyDiscovery,
	resolver *applyScopeMap,
	executor *recordingNodeApply,
) *ApplyCoordinator {
	t.Helper()
	planner, err := NewConvergencePlanner(source, discovery)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewNodeApplyCoordinator(applyNodeID, planner, resolver, executor)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

func singleApplyChange(
	t *testing.T,
	key ManagedResourceKey,
	operationType string,
	targetKind string,
	targetID string,
) (*applySnapshotSource, *applyDiscovery) {
	t.Helper()
	applied := convergenceManifest(t, 3, []ManagedResource{resource(key, "old", ConvergenceImpactAvailability, ConvergenceImpactAvailability)})
	desired := convergenceManifest(t, 4, []ManagedResource{resource(key, "new", ConvergenceImpactAvailability, ConvergenceImpactAvailability)})
	return &applySnapshotSource{snapshot: ConvergenceSnapshot{
		Desired: desired, Applied: applied,
		Pending: []PendingOperation{{
			ID: "operation-1", Type: operationType, TargetKind: targetKind, TargetID: targetID,
			ExpectedGeneration: 3, DesiredGeneration: 4, Resources: []ManagedResourceKey{key},
		}},
	}}, &applyDiscovery{observed: observationsFromResources(applied.Resources)}
}
