package cli

import (
	"context"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

type NodeJoiner interface {
	PlanJoin(model.TransportKind, []string) (enrollment.NodeJoinPlan, error)
	Join(context.Context, *output.Secret, model.TransportKind, []string) (enrollment.NodeJoinResult, error)
}

// NodeJoinMutationWorkflow keeps token input in the common hidden-input
// boundary. Plan is read-only; key generation and public enrollment begin only
// in Apply after the explicit availability confirmation.
type NodeJoinMutationWorkflow struct {
	joiner    NodeJoiner
	transport model.TransportKind
	presets   []string
	planned   bool
}

func NewNodeJoinMutationWorkflow(joiner NodeJoiner, transportKind model.TransportKind, presets []string) (*NodeJoinMutationWorkflow, error) {
	if joiner == nil {
		return nil, fmt.Errorf("node joiner is required")
	}
	if err := enrollment.ValidateNodeJoinIntent(transportKind, presets); err != nil {
		return nil, err
	}
	return &NodeJoinMutationWorkflow{
		joiner: joiner, transport: transportKind, presets: append([]string{}, presets...),
	}, nil
}

func (workflow *NodeJoinMutationWorkflow) Plan(_ context.Context, inputs *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.joiner == nil {
		return MutationPlan{}, fmt.Errorf("node join workflow is incomplete")
	}
	token := inputs.Copy(StepInviteToken)
	defer wipeBytes(token)
	if len(token) == 0 {
		return MutationPlan{}, fmt.Errorf("join requires a hidden invite token")
	}
	joinPlan, err := workflow.joiner.PlanJoin(workflow.transport, workflow.presets)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.planned = true
	return MutationPlan{
		Impact: ImpactAvailability,
		Result: output.NewResult("join", output.StatusOK, output.CategorySuccess, output.SafeObject{
			"changed": true, "generation": joinPlan.CurrentStateGeneration + 1,
		}),
	}, nil
}

func (workflow *NodeJoinMutationWorkflow) Apply(ctx context.Context, _ MutationPlan, inputs *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.joiner == nil || !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("node join was not planned")
	}
	tokenBytes := inputs.Take(StepInviteToken)
	defer wipeBytes(tokenBytes)
	token, err := output.NewSecret(tokenBytes)
	if err != nil {
		return AppliedMutation{}, fmt.Errorf("read hidden invite token: %w", err)
	}
	defer token.Destroy()
	result, err := workflow.joiner.Join(ctx, &token, workflow.transport, workflow.presets)
	if err != nil {
		return AppliedMutation{}, err
	}
	public := output.NewResult("join", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": result.LocalStateGeneration,
	})
	public.ResourceIDs["node_id"] = result.NodeID
	return AppliedMutation{Result: public}, nil
}

var _ MutationWorkflow = (*NodeJoinMutationWorkflow)(nil)
