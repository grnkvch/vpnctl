package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestInviteIssueWorkflowDisplaysTokenOnlyThroughTTY(t *testing.T) {
	t.Parallel()

	issuer := &recordingInviteIssuer{token: "opaque-invite-token-canary"}
	workflow, err := NewInviteIssueWorkflow(issuer, "bot-server")
	if err != nil {
		t.Fatal(err)
	}
	terminal := &orderedPromptIO{}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "invite", Role: RoleGateway, JSON: true,
	}, terminal, workflow, nil)
	if err != nil {
		t.Fatalf("RunMutation(invite) error = %v", err)
	}
	if issuer.planCalls != 1 || issuer.commitCalls != 1 || terminal.writes != 1 || string(terminal.written) != issuer.token {
		t.Fatalf("invite calls plan=%d commit=%d tty writes=%d value=%q", issuer.planCalls, issuer.commitCalls, terminal.writes, terminal.written)
	}
	if outcome.Result.ResourceIDs["invite_id"] != "inv-ABC234" || outcome.Result.Data["displayed_to_tty"] != true {
		t.Fatalf("invite result = %+v", outcome.Result)
	}
	encoded, err := json.Marshal(outcome.Result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), issuer.token) || strings.Contains(string(encoded), "secret") {
		t.Fatalf("public invite result leaked secret material: %s", encoded)
	}
}

func TestInviteIssueWorkflowDryRunCreatesAndDisplaysNothing(t *testing.T) {
	t.Parallel()

	issuer := &recordingInviteIssuer{token: "must-not-be-created"}
	workflow, _ := NewInviteIssueWorkflow(issuer, "bot-server")
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "invite", Role: RoleGateway, DryRun: true, JSON: true,
	}, nil, workflow, nil)
	if err != nil {
		t.Fatalf("RunMutation(invite --dry-run) error = %v", err)
	}
	if issuer.planCalls != 1 || issuer.commitCalls != 0 || outcome.Result.Data["displayed_to_tty"] != false || len(outcome.Result.ResourceIDs) != 0 {
		t.Fatalf("dry-run result=%+v plan=%d commit=%d", outcome.Result, issuer.planCalls, issuer.commitCalls)
	}
}

func TestInviteCancelWorkflowReturnsIdempotentOperationShape(t *testing.T) {
	t.Parallel()

	canceller := &recordingInviteCanceller{changed: false, generation: 7}
	workflow, err := NewInviteCancelWorkflow(canceller, "inv-ABC234")
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "invite.cancel", Role: RoleGateway, DryRun: false,
	}, nil, workflow, nil)
	if err != nil {
		t.Fatalf("RunMutation(invite.cancel) error = %v", err)
	}
	if canceller.planCalls != 1 || canceller.commitCalls != 1 || outcome.Result.Data["changed"] != false || outcome.Result.Data["generation"] != uint64(7) {
		t.Fatalf("cancel result=%+v plan=%d commit=%d", outcome.Result, canceller.planCalls, canceller.commitCalls)
	}
}

type recordingInviteIssuer struct {
	token       string
	planCalls   int
	commitCalls int
}

func (issuer *recordingInviteIssuer) PlanIssue(nodeName string) (enrollment.InviteIssuePlan, error) {
	issuer.planCalls++
	issuedAt := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	return enrollment.InviteIssuePlan{
		NodeName: nodeName, ControlProtocol: "1.0", GatewayEndpoint: "https://203.0.113.10/.well-known/vpnctl/enroll",
		EnrollmentFingerprint: "sha256:" + strings.Repeat("a", 64), IssuedAt: issuedAt,
		ExpiresAt: issuedAt.Add(15 * time.Minute), ExpectedStateGeneration: 1,
	}, nil
}

func (issuer *recordingInviteIssuer) CommitIssue(_ context.Context, plan enrollment.InviteIssuePlan) (enrollment.InviteIssueResult, error) {
	issuer.commitCalls++
	secret, err := output.NewSecretString(issuer.token)
	if err != nil {
		return enrollment.InviteIssueResult{}, err
	}
	return enrollment.InviteIssueResult{
		Invite: enrollment.InviteStatus{
			ID: "inv-ABC234", NodeName: plan.NodeName, State: enrollment.InviteDisplayActive,
			ControlProtocol: plan.ControlProtocol, GatewayEndpoint: plan.GatewayEndpoint,
			IssuedAt: plan.IssuedAt, ExpiresAt: plan.ExpiresAt,
		},
		StateGeneration: 2, Token: &secret,
	}, nil
}

type recordingInviteCanceller struct {
	changed     bool
	generation  uint64
	planCalls   int
	commitCalls int
}

func (canceller *recordingInviteCanceller) PlanCancel(inviteID string) (enrollment.InviteCancelPlan, error) {
	canceller.planCalls++
	return enrollment.InviteCancelPlan{
		InviteID: inviteID, NodeName: "bot-server", Changed: canceller.changed,
		ExpectedStateGeneration: canceller.generation, NextStateGeneration: canceller.generation,
	}, nil
}

func (canceller *recordingInviteCanceller) CommitCancel(plan enrollment.InviteCancelPlan) (enrollment.InviteCancelResult, error) {
	canceller.commitCalls++
	return enrollment.InviteCancelResult{
		InviteID: plan.InviteID, NodeName: plan.NodeName, Changed: plan.Changed, StateGeneration: canceller.generation,
	}, nil
}
