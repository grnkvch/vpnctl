package cli

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestCommittedNodeRepairPreviewsConfirmsAndActivatesExactGeneration(t *testing.T) {
	t.Parallel()

	plan := committedNodeRepairTestPlan()
	var events []string
	operator := &recordingCommittedNodeRepairOperator{plan: plan, events: &events}
	terminal := &orderedPromptIO{visible: []string{"yes"}, events: &events}
	outcome, err := RunCommittedNodeRepair(context.Background(), false, false, false, terminal, operator)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"plan", "visible", "repair"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("repair events = %v, want %v", events, want)
	}
	if outcome.Mode != MutationImmediate || outcome.Plan.Impact != ImpactAvailability || operator.repairCalls != 1 {
		t.Fatalf("repair outcome = %+v, calls=%d", outcome, operator.repairCalls)
	}
	if !reflect.DeepEqual(operator.approved, plan) || outcome.Result.Data["generation"] != plan.Generation || outcome.Result.ResourceIDs["node_id"] != plan.NodeID {
		t.Fatalf("approved/result = %+v / %+v", operator.approved, outcome.Result)
	}
}

func TestCommittedNodeRepairDryRunDoesNotPromptOrActivate(t *testing.T) {
	t.Parallel()

	operator := &recordingCommittedNodeRepairOperator{plan: committedNodeRepairTestPlan()}
	outcome, err := RunCommittedNodeRepair(context.Background(), true, false, true, nil, operator)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Mode != MutationDryRun || operator.planCalls != 1 || operator.repairCalls != 0 || outcome.Result.Data["changed"] != true {
		t.Fatalf("dry-run outcome=%+v calls=%d/%d", outcome, operator.planCalls, operator.repairCalls)
	}
}

func TestCommittedNodeRepairRejectsModifiedPreview(t *testing.T) {
	t.Parallel()

	operator := &recordingCommittedNodeRepairOperator{plan: committedNodeRepairTestPlan()}
	workflow, err := NewCommittedNodeRepairWorkflow(operator)
	if err != nil {
		t.Fatal(err)
	}
	public, err := workflow.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	public.Result.Data["generation"] = uint64(99)
	if _, err := workflow.Apply(context.Background(), public, nil); !errors.Is(err, ErrInvalidMutationPlan) {
		t.Fatalf("modified preview error = %v", err)
	}
	if operator.repairCalls != 0 {
		t.Fatal("modified preview reached activation")
	}
}

func TestSystemCommittedNodeRepairRejectsStaleGenerationAndPreservesFailure(t *testing.T) {
	t.Parallel()

	state := committedNodeRepairTestState(7)
	loader := &mutableCommittedNodeRepairState{state: state}
	activation := &repairingNodeActivation{artifacts: committedNodeRepairTestArtifacts()}
	repair, err := newSystemCommittedNodeRepair(loader, activation)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := repair.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	loader.state.Generation++
	if err := repair.Repair(context.Background(), plan); !errors.Is(err, ErrCommittedNodeRepairStale) {
		t.Fatalf("stale repair error = %v", err)
	}
	if activation.calls != 0 {
		t.Fatal("stale repair reached activation")
	}

	loader.state = state
	activation.err = errors.New("routing is unavailable")
	if err := repair.Repair(context.Background(), plan); !errors.Is(err, enrollment.ErrNodeActivationPending) {
		t.Fatalf("activation repair error = %v", err)
	}
	if activation.calls != 1 || activation.generation != plan.Generation {
		t.Fatalf("activation calls/generation = %d/%d", activation.calls, activation.generation)
	}
}

func committedNodeRepairTestPlan() CommittedNodeRepairPlan {
	return CommittedNodeRepairPlan{
		Generation: 7,
		NodeID:     "76000000-0000-4000-8000-000000000001",
		Services:   append([]string{}, committedNodeRepairServices...),
		Artifacts:  committedNodeRepairTestArtifacts(),
	}
}

func committedNodeRepairTestArtifacts() []CommittedNodeRepairArtifact {
	return []CommittedNodeRepairArtifact{{Name: "node-standard.ready", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
}

func committedNodeRepairTestState(generation uint64) model.State {
	return model.State{
		Generation: generation,
		Host:       model.Host{Role: model.RoleNode},
		Nodes: []model.Node{{
			ID: "76000000-0000-4000-8000-000000000001", Lifecycle: model.LifecycleActive, Gateway: &model.GatewayTrust{},
		}},
	}
}

type recordingCommittedNodeRepairOperator struct {
	plan        CommittedNodeRepairPlan
	planCalls   int
	repairCalls int
	approved    CommittedNodeRepairPlan
	events      *[]string
	err         error
}

func (operator *recordingCommittedNodeRepairOperator) Plan(context.Context) (CommittedNodeRepairPlan, error) {
	operator.planCalls++
	if operator.events != nil {
		*operator.events = append(*operator.events, "plan")
	}
	return cloneCommittedNodeRepairPlan(operator.plan), nil
}

func (operator *recordingCommittedNodeRepairOperator) Repair(_ context.Context, plan CommittedNodeRepairPlan) error {
	operator.repairCalls++
	operator.approved = cloneCommittedNodeRepairPlan(plan)
	if operator.events != nil {
		*operator.events = append(*operator.events, "repair")
	}
	return operator.err
}

type mutableCommittedNodeRepairState struct{ state model.State }

func (state *mutableCommittedNodeRepairState) Load() (model.State, error) { return state.state, nil }

type repairingNodeActivation struct {
	calls      int
	generation uint64
	err        error
	artifacts  []CommittedNodeRepairArtifact
}

func (activation *repairingNodeActivation) Activate(_ context.Context, generation uint64) error {
	activation.calls++
	activation.generation = generation
	return activation.err
}

func (activation *repairingNodeActivation) PlanRepair(_ context.Context, _ uint64) ([]CommittedNodeRepairArtifact, error) {
	return cloneCommittedNodeRepairArtifacts(activation.artifacts), nil
}

func (activation *repairingNodeActivation) ApplyRepair(_ context.Context, generation uint64, artifacts []CommittedNodeRepairArtifact) error {
	activation.calls++
	activation.generation = generation
	if !reflect.DeepEqual(artifacts, activation.artifacts) {
		return ErrCommittedNodeRepairStale
	}
	return activation.err
}
