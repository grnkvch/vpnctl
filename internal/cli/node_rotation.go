package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

type NodeRotationOperator interface {
	Plan() (enrollment.NodeRotationPlan, error)
	Apply(context.Context, enrollment.NodeRotationPlan) (enrollment.NodeRotationResult, error)
}

type NodeRotationMutationWorkflow struct {
	manager NodeRotationOperator
	plan    enrollment.NodeRotationPlan
	planned bool
}

func NewNodeRotationMutationWorkflow(manager NodeRotationOperator) (*NodeRotationMutationWorkflow, error) {
	if manager == nil {
		return nil, fmt.Errorf("node rotation manager is required")
	}
	return &NodeRotationMutationWorkflow{manager: manager}, nil
}

func (workflow *NodeRotationMutationWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.manager == nil {
		return MutationPlan{}, fmt.Errorf("node rotation workflow is incomplete")
	}
	plan, err := workflow.manager.Plan()
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan, workflow.planned = plan, true
	result := output.NewResult("node.rotate", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": plan.NextLocalStateGeneration,
		"credential_generation": plan.RequestedCredentialGeneration,
		"active":                string(plan.ActiveTransport),
	})
	result.ResourceIDs["node_id"] = plan.NodeID
	return MutationPlan{Impact: ImpactAvailability, Result: result}, nil
}

func (workflow *NodeRotationMutationWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.manager == nil || !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("node rotation mutation was not planned")
	}
	result, err := workflow.manager.Apply(ctx, workflow.plan)
	if err != nil {
		if result.NodeID != "" && (errors.Is(err, enrollment.ErrNodeRotationCleanupPending) ||
			errors.Is(err, enrollment.ErrNodeRotationCommitUncertain)) {
			return AppliedMutation{Result: result.OutputResult()}, nil
		}
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: result.OutputResult()}, nil
}

var _ MutationWorkflow = (*NodeRotationMutationWorkflow)(nil)
