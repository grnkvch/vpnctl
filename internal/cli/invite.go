package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

type InviteIssuer interface {
	PlanIssue(nodeName string) (enrollment.InviteIssuePlan, error)
	CommitIssue(context.Context, enrollment.InviteIssuePlan) (enrollment.InviteIssueResult, error)
}

type InviteCanceller interface {
	PlanCancel(inviteID string) (enrollment.InviteCancelPlan, error)
	CommitCancel(enrollment.InviteCancelPlan) (enrollment.InviteCancelResult, error)
}

type InviteIssueWorkflow struct {
	issuer   InviteIssuer
	nodeName string
	plan     enrollment.InviteIssuePlan
	planned  bool
}

func NewInviteIssueWorkflow(issuer InviteIssuer, nodeName string) (*InviteIssueWorkflow, error) {
	if issuer == nil {
		return nil, fmt.Errorf("invite issuer is required")
	}
	if nodeName == "" {
		return nil, fmt.Errorf("invite node name is required")
	}
	return &InviteIssueWorkflow{issuer: issuer, nodeName: nodeName}, nil
}

func (workflow *InviteIssueWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.issuer == nil {
		return MutationPlan{}, fmt.Errorf("invite issue workflow is incomplete")
	}
	plan, err := workflow.issuer.PlanIssue(workflow.nodeName)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan = plan
	workflow.planned = true
	return MutationPlan{Impact: ImpactNone, Result: inviteIssueOutput(plan.ExpiresAt, false, "")}, nil
}

func (workflow *InviteIssueWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.issuer == nil || !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("invite issue was not planned")
	}
	result, err := workflow.issuer.CommitIssue(ctx, workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	if result.Token == nil {
		return AppliedMutation{}, fmt.Errorf("invite issuer returned no one-time token")
	}
	return AppliedMutation{
		Result:        inviteIssueOutput(result.Invite.ExpiresAt, true, result.Invite.ID),
		OneTimeSecret: result.Token,
	}, nil
}

type InviteCancelWorkflow struct {
	canceller InviteCanceller
	inviteID  string
	plan      enrollment.InviteCancelPlan
	planned   bool
}

func NewInviteCancelWorkflow(canceller InviteCanceller, inviteID string) (*InviteCancelWorkflow, error) {
	if canceller == nil {
		return nil, fmt.Errorf("invite canceller is required")
	}
	if inviteID == "" {
		return nil, fmt.Errorf("invite ID is required")
	}
	return &InviteCancelWorkflow{canceller: canceller, inviteID: inviteID}, nil
}

func (workflow *InviteCancelWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.canceller == nil {
		return MutationPlan{}, fmt.Errorf("invite cancellation workflow is incomplete")
	}
	plan, err := workflow.canceller.PlanCancel(workflow.inviteID)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan = plan
	workflow.planned = true
	return MutationPlan{Impact: ImpactNone, Result: inviteCancelOutput(plan.InviteID, plan.Changed, plan.NextStateGeneration)}, nil
}

func (workflow *InviteCancelWorkflow) Apply(_ context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.canceller == nil || !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("invite cancellation was not planned")
	}
	result, err := workflow.canceller.CommitCancel(workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: inviteCancelOutput(result.InviteID, result.Changed, result.StateGeneration)}, nil
}

func inviteIssueOutput(expiresAt time.Time, displayed bool, inviteID string) output.Result {
	result := output.NewResult("invite", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"displayed_to_tty": displayed,
		"expires_at":       expiresAt.UTC().Format(time.RFC3339),
	})
	if inviteID != "" {
		result.ResourceIDs["invite_id"] = inviteID
	}
	return result
}

func inviteCancelOutput(inviteID string, changed bool, generation uint64) output.Result {
	result := output.NewResult("invite.cancel", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": changed, "generation": generation,
	})
	result.ResourceIDs["invite_id"] = inviteID
	return result
}

var _ MutationWorkflow = (*InviteIssueWorkflow)(nil)
var _ MutationWorkflow = (*InviteCancelWorkflow)(nil)
