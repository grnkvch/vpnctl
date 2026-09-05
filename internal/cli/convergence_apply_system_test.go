package cli

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestSystemConvergenceApplyProvesStableGatewayNoOp(t *testing.T) {
	t.Parallel()

	state := cliDNSState(model.RoleGateway)
	planner := &staticSystemApplyPlanner{plan: emptySystemApplyConvergence(t, state.Generation)}
	operator := &systemConvergenceApply{
		role: model.RoleGateway, state: &mutableSystemApplyState{state: state}, planner: planner,
	}
	plan, err := operator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Role != model.RoleGateway || plan.DesiredGeneration != state.Generation || len(plan.Operations) != 0 {
		t.Fatalf("no-op plan=%+v", plan)
	}
	result, err := operator.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Generation != state.Generation || result.OperationIDs == nil || result.RemainingDrift == nil || planner.calls != 3 {
		t.Fatalf("no-op result=%+v planner calls=%d", result, planner.calls)
	}
}

func TestSystemConvergenceApplyNeverMistakesUnpublishedPendingIntentForNoOp(t *testing.T) {
	t.Parallel()

	state := cliDNSState(model.RoleGateway)
	state.Generation++
	at := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	state.Operations = []model.Operation{{
		SchemaVersion: model.ResourceSchemaVersion,
		ID:            "75000000-0000-4000-8000-000000000001", Type: model.OperationApply,
		State: model.OperationPending, TargetKind: "preset", TargetID: "telegram",
		ExpectedGeneration: state.Generation - 1, DesiredGeneration: state.Generation,
		Steps: []model.OperationStep{}, CreatedAt: at, UpdatedAt: at,
	}}
	if err := state.Validate(); err != nil {
		t.Fatalf("pending state fixture: %v", err)
	}
	operator := &systemConvergenceApply{
		role: model.RoleGateway, state: &mutableSystemApplyState{state: state},
		planner: &staticSystemApplyPlanner{plan: emptySystemApplyConvergence(t, state.Generation-1)},
	}
	if _, err := operator.Plan(context.Background()); !errors.Is(err, ErrSystemConvergenceApplyUnavailable) {
		t.Fatalf("unpublished pending intent error=%v", err)
	}
}

func TestSystemConvergenceApplyPreviewsPublishedTransportSwitchButDoesNotFakeExecution(t *testing.T) {
	t.Parallel()

	state, convergence := systemTransportApplyPendingFixture(t)
	probe := &countingSystemApplyGatewayProbe{}
	operator := &systemConvergenceApply{
		role: model.RoleNode, nodeID: state.Nodes[0].ID,
		state: &mutableSystemApplyState{state: state}, planner: &staticSystemApplyPlanner{plan: convergence}, probe: probe,
	}
	plan, err := operator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Operations) != 1 || plan.Operations[0].ID != state.Operations[len(state.Operations)-1].ID ||
		plan.Operations[0].Scope.Role != model.RoleNode || plan.Operations[0].Scope.NodeID != state.Nodes[0].ID ||
		plan.AppliedGeneration+2 != plan.DesiredGeneration || plan.Impact != operations.ConvergenceImpactAvailability {
		t.Fatalf("transport switch apply preview=%+v", plan)
	}
	if _, err := operator.Apply(context.Background(), plan); !errors.Is(err, ErrSystemConvergenceApplyExecutorUnavailable) {
		t.Fatalf("unconnected transport executor error=%v", err)
	}
	if probe.calls != 1 || probe.nodeID != state.Nodes[0].ID {
		t.Fatalf("gateway probe=%+v", probe)
	}
}

func TestSystemConvergenceApplyRejectsAuthorityChangeAfterPreview(t *testing.T) {
	t.Parallel()

	state := cliDNSState(model.RoleGateway)
	reader := &mutableSystemApplyState{state: state}
	operator := &systemConvergenceApply{
		role: model.RoleGateway, state: reader,
		planner: &staticSystemApplyPlanner{plan: emptySystemApplyConvergence(t, state.Generation)},
	}
	plan, err := operator.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reader.state.Generation++
	if _, err := operator.Apply(context.Background(), plan); !errors.Is(err, operations.ErrApplyConflict) {
		t.Fatalf("changed authority apply error=%v", err)
	}
}

type mutableSystemApplyState struct{ state model.State }

func (state *mutableSystemApplyState) Load() (model.State, error) { return state.state, nil }

type staticSystemApplyPlanner struct {
	plan  operations.ConvergencePlan
	calls int
}

type countingSystemApplyGatewayProbe struct {
	calls  int
	nodeID string
	err    error
}

func (probe *countingSystemApplyGatewayProbe) RequireGateway(_ context.Context, nodeID string) error {
	probe.calls++
	probe.nodeID = nodeID
	return probe.err
}

func (planner *staticSystemApplyPlanner) Plan(context.Context) (operations.ConvergencePlan, error) {
	planner.calls++
	return planner.plan, nil
}

func emptySystemApplyConvergence(t *testing.T, generation uint64) operations.ConvergencePlan {
	t.Helper()
	manifest, err := operations.NewConvergenceManifest(generation, []operations.ManagedResource{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := operations.ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []operations.PendingOperation{}}
	planner, err := operations.NewConvergencePlanner(&staticRepairSnapshotSource{snapshot: snapshot}, emptyRepairDiscoverer{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.Changes, []operations.DesiredChange{}) || !reflect.DeepEqual(plan.Drift, []operations.OwnedDrift{}) {
		t.Fatalf("empty convergence=%+v", plan)
	}
	return plan
}

func systemTransportApplyPendingFixture(t *testing.T) (model.State, operations.ConvergencePlan) {
	t.Helper()
	state := cliDoctorJoinedNodeState(t)
	expectedNodeGeneration := state.Generation
	state.Generation++
	requestID := "76000000-0000-4000-8000-000000000001"
	operationID, err := transport.SwitchOperationID(requestID)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := transport.NewSwitchIntentTarget(state.Nodes[0].ID, model.TransportStandard, expectedNodeGeneration)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, time.September, 6, 12, 0, 0, 0, time.UTC)
	steps := make([]model.OperationStep, len(transport.SwitchOperationStepNames()))
	for index, name := range transport.SwitchOperationStepNames() {
		steps[index] = model.OperationStep{Name: name, State: model.OperationPending, UpdatedAt: at}
	}
	operation := model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: operationID, Type: model.OperationTransportSwitch,
		State: model.OperationPending, TargetKind: "transport", TargetID: intent.String(), RequestID: requestID,
		ExpectedGeneration: state.Nodes[0].Gateway.LastKnownGatewayGeneration,
		DesiredGeneration:  state.Nodes[0].Gateway.LastKnownGatewayGeneration + 2,
		Steps:              steps, CreatedAt: at, UpdatedAt: at,
	}
	state.Operations = append(state.Operations, operation)
	state.Nodes[0].Gateway.PendingRequestID = requestID
	state.Nodes[0].Gateway.LastKnownGatewayGeneration++
	if err := state.Validate(); err != nil {
		t.Fatalf("pending node fixture: %v", err)
	}
	key := operations.ManagedResourceKey{Component: "role.node", Kind: operations.ManagedResourceFile, ID: "/etc/vpnctl/generated/node/routing.yaml"}
	change := operations.DesiredChange{
		OperationID: operation.ID, OperationType: string(operation.Type),
		OperationExpectedGeneration: intent.ExpectedNodeGeneration, OperationDesiredGeneration: intent.DesiredNodeGeneration,
		TargetKind: operation.TargetKind, TargetID: operation.TargetID,
		Resource: key, Kind: operations.DesiredUpdate, Impact: operations.ConvergenceImpactAvailability,
		FromSHA256: operations.ManagedFingerprint([]byte("before")), ToSHA256: operations.ManagedFingerprint([]byte("after")),
	}
	convergence := operations.ConvergencePlan{
		DesiredGeneration: intent.DesiredNodeGeneration, AppliedGeneration: intent.ExpectedNodeGeneration,
		Impact: operations.ConvergenceImpactAvailability, Changes: []operations.DesiredChange{change}, Drift: []operations.OwnedDrift{},
	}
	if err := convergence.Validate(); err != nil {
		t.Fatal(err)
	}
	return state, convergence
}
