package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

type NodeLifecycleOperator interface {
	PlanRevoke(string) (enrollment.NodeLifecyclePlan, error)
	CommitRevoke(context.Context, enrollment.NodeLifecyclePlan) (enrollment.NodeLifecycleResult, error)
	PlanDelete(string) (enrollment.NodeLifecyclePlan, error)
	CommitDelete(context.Context, enrollment.NodeLifecyclePlan) (enrollment.NodeLifecycleResult, error)
}

type NodeLifecycleMutationWorkflow struct {
	manager   NodeLifecycleOperator
	reference string
	command   enrollment.NodeLifecycleCommand
	plan      enrollment.NodeLifecyclePlan
	planned   bool
}

func NewNodeRevokeMutationWorkflow(manager NodeLifecycleOperator, reference string) (*NodeLifecycleMutationWorkflow, error) {
	return newNodeLifecycleMutationWorkflow(manager, reference, enrollment.NodeRevoke)
}

func NewNodeDeleteMutationWorkflow(manager NodeLifecycleOperator, reference string) (*NodeLifecycleMutationWorkflow, error) {
	return newNodeLifecycleMutationWorkflow(manager, reference, enrollment.NodeDelete)
}

func newNodeLifecycleMutationWorkflow(
	manager NodeLifecycleOperator,
	reference string,
	command enrollment.NodeLifecycleCommand,
) (*NodeLifecycleMutationWorkflow, error) {
	if manager == nil || reference == "" {
		return nil, fmt.Errorf("node lifecycle manager and reference are required")
	}
	if command != enrollment.NodeRevoke && command != enrollment.NodeDelete {
		return nil, fmt.Errorf("unsupported node lifecycle command %q", command)
	}
	return &NodeLifecycleMutationWorkflow{manager: manager, reference: reference, command: command}, nil
}

func (workflow *NodeLifecycleMutationWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.manager == nil {
		return MutationPlan{}, fmt.Errorf("node lifecycle workflow is incomplete")
	}
	var (
		plan enrollment.NodeLifecyclePlan
		err  error
	)
	switch workflow.command {
	case enrollment.NodeRevoke:
		plan, err = workflow.manager.PlanRevoke(workflow.reference)
	case enrollment.NodeDelete:
		plan, err = workflow.manager.PlanDelete(workflow.reference)
	default:
		err = fmt.Errorf("unsupported node lifecycle command %q", workflow.command)
	}
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan, workflow.planned = plan, true
	impact := ImpactAvailability
	if workflow.command == enrollment.NodeDelete {
		impact = ImpactDestructive
	}
	return MutationPlan{Impact: impact, Result: planNodeLifecycleOutput(plan)}, nil
}

func (workflow *NodeLifecycleMutationWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.manager == nil || !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("node lifecycle mutation was not planned")
	}
	var (
		result enrollment.NodeLifecycleResult
		err    error
	)
	switch workflow.command {
	case enrollment.NodeRevoke:
		result, err = workflow.manager.CommitRevoke(ctx, workflow.plan)
	case enrollment.NodeDelete:
		result, err = workflow.manager.CommitDelete(ctx, workflow.plan)
	default:
		err = fmt.Errorf("unsupported node lifecycle command %q", workflow.command)
	}
	if err != nil {
		// The authoritative lifecycle transition has already committed when the
		// manager reports cleanup pending. Preserve its structured repair actions
		// instead of replacing them with an opaque apply error.
		if errors.Is(err, enrollment.ErrNodeCleanupPending) && result.NodeID != "" {
			return AppliedMutation{Result: result.OutputResult()}, nil
		}
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: result.OutputResult()}, nil
}

func planNodeLifecycleOutput(plan enrollment.NodeLifecyclePlan) output.Result {
	result := output.NewResult(string(plan.Command), output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": plan.Changed, "generation": plan.NextStateGeneration,
	})
	result.ResourceIDs["node_id"] = plan.NodeID
	return result
}

var _ MutationWorkflow = (*NodeLifecycleMutationWorkflow)(nil)
