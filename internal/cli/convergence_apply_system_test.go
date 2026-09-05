package cli

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
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
