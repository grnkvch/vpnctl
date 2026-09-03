package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

type GatewayRecoveryIssuer interface {
	PlanIssue(string) (enrollment.RecoveryIssuePlan, error)
	CommitIssue(context.Context, enrollment.RecoveryIssuePlan) (enrollment.RecoveryIssueResult, error)
}

type GatewayRecoveryIssueWorkflow struct {
	issuer    GatewayRecoveryIssuer
	reference string
	plan      enrollment.RecoveryIssuePlan
	planned   bool
}

func NewGatewayRecoveryIssueWorkflow(issuer GatewayRecoveryIssuer, reference string) (*GatewayRecoveryIssueWorkflow, error) {
	if issuer == nil || reference == "" {
		return nil, fmt.Errorf("gateway recovery issuer and node reference are required")
	}
	return &GatewayRecoveryIssueWorkflow{issuer: issuer, reference: reference}, nil
}

func (workflow *GatewayRecoveryIssueWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.issuer == nil {
		return MutationPlan{}, fmt.Errorf("gateway recovery issue workflow is incomplete")
	}
	plan, err := workflow.issuer.PlanIssue(workflow.reference)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan, workflow.planned = plan, true
	result := recoveryIssueOutput(plan.ExpiresAt, false, "", plan.NodeID)
	return MutationPlan{Impact: ImpactAvailability, Result: result}, nil
}

func (workflow *GatewayRecoveryIssueWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.issuer == nil || !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("gateway recovery issue was not planned")
	}
	result, err := workflow.issuer.CommitIssue(ctx, workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	if result.Token == nil {
		return AppliedMutation{}, fmt.Errorf("gateway recovery issuer returned no one-time token")
	}
	return AppliedMutation{
		Result: recoveryIssueOutput(result.ExpiresAt, true, result.RecoveryID, result.NodeID), OneTimeSecret: result.Token,
	}, nil
}

func recoveryIssueOutput(expiresAt time.Time, displayed bool, recoveryID, nodeID string) output.Result {
	result := output.NewResult("node.recover", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"displayed_to_tty": displayed, "expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
	if recoveryID != "" {
		result.ResourceIDs["recovery_id"] = recoveryID
	}
	if nodeID != "" {
		result.ResourceIDs["node_id"] = nodeID
	}
	return result
}

type NodeRecoveryOperator interface {
	Plan(*output.Secret) (enrollment.NodeRecoveryPlan, error)
	Apply(context.Context, enrollment.NodeRecoveryPlan, *output.Secret) (enrollment.NodeRecoveryResult, error)
}

type NodeRecoveryMutationWorkflow struct {
	operator NodeRecoveryOperator
	plan     enrollment.NodeRecoveryPlan
	planned  bool
}

func NewNodeRecoveryMutationWorkflow(operator NodeRecoveryOperator) (*NodeRecoveryMutationWorkflow, error) {
	if operator == nil {
		return nil, fmt.Errorf("node recovery operator is required")
	}
	return &NodeRecoveryMutationWorkflow{operator: operator}, nil
}

func (workflow *NodeRecoveryMutationWorkflow) Plan(_ context.Context, inputs *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.operator == nil || inputs == nil {
		return MutationPlan{}, fmt.Errorf("node recovery workflow is incomplete")
	}
	tokenBytes := inputs.Copy(StepRecoveryToken)
	defer wipeBytes(tokenBytes)
	if len(tokenBytes) == 0 {
		return MutationPlan{}, fmt.Errorf("node recovery requires a hidden recovery token")
	}
	token, err := output.NewSecret(tokenBytes)
	if err != nil {
		return MutationPlan{}, err
	}
	defer token.Destroy()
	plan, err := workflow.operator.Plan(&token)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan, workflow.planned = plan, true
	result := output.NewResult("node.recover", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": plan.NextLocalStateGeneration,
		"credential_generation": plan.RequestedCredentialGeneration, "active": string(plan.ActiveTransport),
	})
	result.ResourceIDs["node_id"] = plan.NodeID
	return MutationPlan{Impact: ImpactAvailability, Result: result}, nil
}

func (workflow *NodeRecoveryMutationWorkflow) Apply(
	ctx context.Context,
	_ MutationPlan,
	inputs *InteractionInputs,
) (AppliedMutation, error) {
	if workflow == nil || workflow.operator == nil || !workflow.planned || inputs == nil {
		return AppliedMutation{}, fmt.Errorf("node recovery mutation was not planned")
	}
	tokenBytes := inputs.Take(StepRecoveryToken)
	defer wipeBytes(tokenBytes)
	token, err := output.NewSecret(tokenBytes)
	if err != nil {
		return AppliedMutation{}, fmt.Errorf("read hidden recovery token: %w", err)
	}
	defer token.Destroy()
	result, err := workflow.operator.Apply(ctx, workflow.plan, &token)
	if err != nil {
		if result.NodeID != "" && (errors.Is(err, enrollment.ErrNodeRotationCleanupPending) ||
			errors.Is(err, enrollment.ErrNodeRotationCommitUncertain)) {
			return AppliedMutation{Result: result.OutputResult()}, nil
		}
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: result.OutputResult()}, nil
}

var _ MutationWorkflow = (*GatewayRecoveryIssueWorkflow)(nil)
var _ MutationWorkflow = (*NodeRecoveryMutationWorkflow)(nil)
