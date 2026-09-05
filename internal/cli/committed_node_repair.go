package cli

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	ErrCommittedNodeRepairInvalid = errors.New("committed node repair plan is invalid")
	ErrCommittedNodeRepairStale   = errors.New("committed node repair plan is stale")
)

var committedNodeRepairServices = []string{
	"vpnctl-standard.service",
	"vpnctl-routing-guard.service",
	"vpnctl-routing.service",
	"vpnctl-tunnel-client.service",
}

// CommittedNodeRepairPlan is deliberately generation-bound. It represents
// the complete node data plane that can be reconstructed from authoritative
// local state after a join committed but service activation did not finish.
type CommittedNodeRepairPlan struct {
	Generation uint64
	NodeID     string
	Services   []string
	Artifacts  []CommittedNodeRepairArtifact
}

type CommittedNodeRepairArtifact struct {
	Name   string
	SHA256 string
}

func (plan CommittedNodeRepairPlan) Validate() error {
	if plan.Generation == 0 || plan.NodeID == "" || !reflect.DeepEqual(plan.Services, committedNodeRepairServices) || len(plan.Artifacts) == 0 {
		return ErrCommittedNodeRepairInvalid
	}
	seen := make(map[string]struct{}, len(plan.Artifacts))
	for _, artifact := range plan.Artifacts {
		if artifact.Name == "" || len(artifact.SHA256) != 64 {
			return ErrCommittedNodeRepairInvalid
		}
		if _, duplicate := seen[artifact.Name]; duplicate {
			return ErrCommittedNodeRepairInvalid
		}
		seen[artifact.Name] = struct{}{}
	}
	return nil
}

type CommittedNodeRepairOperator interface {
	Plan(context.Context) (CommittedNodeRepairPlan, error)
	Repair(context.Context, CommittedNodeRepairPlan) error
}

type committedNodeRepairState interface {
	Load() (model.State, error)
}

type committedNodeRepairRuntime interface {
	committedNodeActivator
	PlanRepair(context.Context, uint64) ([]CommittedNodeRepairArtifact, error)
	ApplyRepair(context.Context, uint64, []CommittedNodeRepairArtifact) error
}

type systemCommittedNodeRepair struct {
	state   committedNodeRepairState
	runtime committedNodeRepairRuntime
}

func newSystemCommittedNodeRepair(state committedNodeRepairState, runtime committedNodeRepairRuntime) (*systemCommittedNodeRepair, error) {
	if state == nil || runtime == nil {
		return nil, fmt.Errorf("committed node repair dependencies are incomplete")
	}
	return &systemCommittedNodeRepair{state: state, runtime: runtime}, nil
}

func buildSystemCommittedNodeRepair(paths store.Paths) (CommittedNodeRepairOperator, error) {
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, err
	}
	activation, err := buildSystemCommittedNodeActivator(paths, state, secrets)
	if err != nil {
		return nil, err
	}
	return newSystemCommittedNodeRepair(state, activation)
}

func (repair *systemCommittedNodeRepair) Plan(ctx context.Context) (CommittedNodeRepairPlan, error) {
	if ctx == nil || repair == nil || repair.state == nil || repair.runtime == nil {
		return CommittedNodeRepairPlan{}, fmt.Errorf("committed node repair is incomplete")
	}
	state, err := repair.state.Load()
	if err != nil {
		return CommittedNodeRepairPlan{}, fmt.Errorf("load committed node repair state: %w", err)
	}
	if state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Lifecycle != model.LifecycleActive || state.Nodes[0].Gateway == nil {
		return CommittedNodeRepairPlan{}, fmt.Errorf("%w: repair requires one joined active local node", ErrCommittedNodeRepairInvalid)
	}
	artifacts, err := repair.runtime.PlanRepair(ctx, state.Generation)
	if err != nil {
		return CommittedNodeRepairPlan{}, fmt.Errorf("compile committed node repair preview: %w", err)
	}
	plan := CommittedNodeRepairPlan{
		Generation: state.Generation,
		NodeID:     state.Nodes[0].ID,
		Services:   append([]string{}, committedNodeRepairServices...),
		Artifacts:  cloneCommittedNodeRepairArtifacts(artifacts),
	}
	return plan, plan.Validate()
}

func (repair *systemCommittedNodeRepair) Repair(ctx context.Context, plan CommittedNodeRepairPlan) error {
	if ctx == nil || repair == nil || repair.state == nil || repair.runtime == nil {
		return fmt.Errorf("committed node repair is incomplete")
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	freshState, err := repair.state.Load()
	if err != nil {
		return err
	}
	if freshState.Generation != plan.Generation || freshState.Host.Role != model.RoleNode || len(freshState.Nodes) != 1 ||
		freshState.Nodes[0].ID != plan.NodeID || freshState.Nodes[0].Lifecycle != model.LifecycleActive || freshState.Nodes[0].Gateway == nil {
		return ErrCommittedNodeRepairStale
	}
	if err := repair.runtime.ApplyRepair(ctx, plan.Generation, cloneCommittedNodeRepairArtifacts(plan.Artifacts)); err != nil {
		return errors.Join(enrollment.ErrNodeActivationPending, err)
	}
	return nil
}

// CommittedNodeRepairWorkflow retains the exact generation shown before
// consent and rejects any modified public preview before activation.
type CommittedNodeRepairWorkflow struct {
	operator CommittedNodeRepairOperator

	mu      sync.Mutex
	planned *CommittedNodeRepairPlan
}

func NewCommittedNodeRepairWorkflow(operator CommittedNodeRepairOperator) (*CommittedNodeRepairWorkflow, error) {
	if operator == nil {
		return nil, fmt.Errorf("committed node repair operator is required")
	}
	return &CommittedNodeRepairWorkflow{operator: operator}, nil
}

func (workflow *CommittedNodeRepairWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if ctx == nil || workflow == nil || workflow.operator == nil {
		return MutationPlan{}, fmt.Errorf("committed node repair workflow is incomplete")
	}
	plan, err := workflow.operator.Plan(ctx)
	if err != nil {
		return MutationPlan{}, err
	}
	if err := plan.Validate(); err != nil {
		return MutationPlan{}, err
	}
	result := committedNodeRepairOutput(plan)
	workflow.mu.Lock()
	retained := cloneCommittedNodeRepairPlan(plan)
	workflow.planned = &retained
	workflow.mu.Unlock()
	return MutationPlan{Impact: ImpactAvailability, Result: result}, nil
}

func (workflow *CommittedNodeRepairWorkflow) Apply(ctx context.Context, publicPlan MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if ctx == nil || workflow == nil || workflow.operator == nil {
		return AppliedMutation{}, fmt.Errorf("committed node repair workflow is incomplete")
	}
	workflow.mu.Lock()
	if workflow.planned == nil {
		workflow.mu.Unlock()
		return AppliedMutation{}, fmt.Errorf("%w: committed node repair was not planned", ErrInvalidMutationPlan)
	}
	retained := cloneCommittedNodeRepairPlan(*workflow.planned)
	workflow.mu.Unlock()
	if publicPlan.Impact != ImpactAvailability || !reflect.DeepEqual(publicPlan.Result, committedNodeRepairOutput(retained)) {
		return AppliedMutation{}, fmt.Errorf("%w: public committed node repair plan differs from retained plan", ErrInvalidMutationPlan)
	}
	if err := workflow.operator.Repair(ctx, retained); err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: committedNodeRepairOutput(retained)}, nil
}

func RunCommittedNodeRepair(
	ctx context.Context,
	dryRun bool,
	yes bool,
	jsonMode bool,
	terminal PromptIO,
	operator CommittedNodeRepairOperator,
) (MutationOutcome, error) {
	workflow, err := NewCommittedNodeRepairWorkflow(operator)
	if err != nil {
		return MutationOutcome{}, err
	}
	return V2CommandRegistry().RunMutation(ctx, MutationRequest{
		CommandID: "repair", Role: RoleNode, DryRun: dryRun, Yes: yes, JSON: jsonMode,
	}, terminal, workflow, nil)
}

func committedNodeRepairOutput(plan CommittedNodeRepairPlan) output.Result {
	artifacts := make(output.SafeList, len(plan.Artifacts))
	for index, artifact := range plan.Artifacts {
		artifacts[index] = output.SafeObject{"name": artifact.Name, "sha256": artifact.SHA256}
	}
	result := output.NewResult("repair", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed":    true,
		"generation": plan.Generation,
		"scope":      "committed_node_services",
		"services":   append([]string{}, plan.Services...),
		"artifacts":  artifacts,
	})
	result.ResourceIDs["node_id"] = plan.NodeID
	return result
}

func cloneCommittedNodeRepairPlan(plan CommittedNodeRepairPlan) CommittedNodeRepairPlan {
	plan.Services = append([]string{}, plan.Services...)
	plan.Artifacts = cloneCommittedNodeRepairArtifacts(plan.Artifacts)
	return plan
}

func cloneCommittedNodeRepairArtifacts(artifacts []CommittedNodeRepairArtifact) []CommittedNodeRepairArtifact {
	return append([]CommittedNodeRepairArtifact{}, artifacts...)
}

var (
	_ CommittedNodeRepairOperator = (*systemCommittedNodeRepair)(nil)
	_ MutationWorkflow            = (*CommittedNodeRepairWorkflow)(nil)
)
