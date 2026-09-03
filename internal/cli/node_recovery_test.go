package cli

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestGatewayRecoveryWorkflowConfirmsThenWritesTokenOnlyToTTY(t *testing.T) {
	issuer := &recordingGatewayRecoveryIssuer{token: "vpnctl-recovery-v1.secret.canary"}
	workflow, err := NewGatewayRecoveryIssueWorkflow(issuer, "private-node")
	if err != nil {
		t.Fatal(err)
	}
	terminal := &orderedPromptIO{}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "node.recover.gateway", Role: RoleGateway, Yes: true, JSON: true,
	}, terminal, workflow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if issuer.plans != 1 || issuer.commits != 1 || terminal.writes != 1 || string(terminal.written) != issuer.token ||
		outcome.Result.Command != "node.recover" || outcome.Result.ResourceIDs["recovery_id"] != "rec-ABC234" ||
		outcome.Result.ResourceIDs["node_id"] != rotationCLINodeID || outcome.Result.Data["displayed_to_tty"] != true {
		t.Fatalf("gateway recovery outcome=%+v issuer=%+v tty=%q", outcome, issuer, terminal.written)
	}
	encoded, err := json.Marshal(outcome.Result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), issuer.token) || strings.Contains(string(encoded), "secret") {
		t.Fatalf("gateway recovery result leaked token: %s", encoded)
	}
}

func TestGatewayRecoveryDryRunDoesNotCreateToken(t *testing.T) {
	issuer := &recordingGatewayRecoveryIssuer{token: "must-not-exist"}
	workflow, _ := NewGatewayRecoveryIssueWorkflow(issuer, rotationCLINodeID)
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "node.recover.gateway", Role: RoleGateway, DryRun: true,
	}, nil, workflow, nil)
	if err != nil || issuer.plans != 1 || issuer.commits != 0 || outcome.Result.Data["displayed_to_tty"] != false {
		t.Fatalf("dry-run outcome=%+v error=%v issuer=%+v", outcome, err, issuer)
	}
}

func TestNodeRecoveryWorkflowUsesHiddenTokenAndAvailabilityConfirmation(t *testing.T) {
	operator := &recordingNodeRecoveryOperator{}
	workflow, _ := NewNodeRecoveryMutationWorkflow(operator)
	terminal := &orderedPromptIO{hidden: [][]byte{[]byte("vpnctl-recovery-v1.hidden.canary")}}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "node.recover.node", Role: RoleNode, Yes: true, JSON: true,
	}, terminal, workflow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if operator.plans != 1 || operator.applies != 1 || operator.planToken != "vpnctl-recovery-v1.hidden.canary" ||
		operator.applyToken != operator.planToken || terminal.writes != 0 || outcome.Result.Command != "node.recover" ||
		outcome.Result.ResourceIDs["node_id"] != rotationCLINodeID || outcome.Result.Data["credential_generation"] != uint64(4) {
		t.Fatalf("node recovery outcome=%+v operator=%+v", outcome, operator)
	}
}

func TestNodeRecoveryWorkflowPreservesCommittedPendingActions(t *testing.T) {
	operator := &recordingNodeRecoveryOperator{
		applyErr: enrollment.ErrNodeRotationCommitUncertain,
		result: enrollment.NodeRecoveryResult{
			NodeID: rotationCLINodeID, NodeName: "private-node", ActiveTransport: model.TransportRestricted,
			PreviousCredentialGeneration: 3, CredentialGeneration: 4,
			GatewayStateGeneration: 15, LocalStateGeneration: 12, CommitConfirmationNeeded: true,
		},
	}
	workflow, _ := NewNodeRecoveryMutationWorkflow(operator)
	inputs := &InteractionInputs{values: map[string][]byte{StepRecoveryToken: []byte("token")}}
	plan, err := workflow.Plan(context.Background(), inputs)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := workflow.Apply(context.Background(), plan, inputs)
	if err != nil || applied.Result.Status != output.StatusPending || len(applied.Result.RequiresAction) != 1 ||
		applied.Result.RequiresAction[0].Code != "inspect_node_recovery" {
		t.Fatalf("Apply(pending) = %+v, %v", applied, err)
	}
}

type recordingGatewayRecoveryIssuer struct {
	token   string
	plans   int
	commits int
}

func (issuer *recordingGatewayRecoveryIssuer) PlanIssue(reference string) (enrollment.RecoveryIssuePlan, error) {
	issuer.plans++
	if reference == "" {
		return enrollment.RecoveryIssuePlan{}, errors.New("missing reference")
	}
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	return enrollment.RecoveryIssuePlan{
		NodeID: rotationCLINodeID, NodeName: "private-node", CredentialGeneration: 3,
		BindingFingerprint: "sha256:" + strings.Repeat("a", 64), ControlProtocol: "1.0",
		GatewayEndpoint:       "https://203.0.113.10" + enrollment.EnrollmentRecoveryPath,
		EnrollmentFingerprint: "sha256:" + strings.Repeat("b", 64),
		IssuedAt:              now, ExpiresAt: now.Add(15 * time.Minute), ExpectedStateGeneration: 14,
	}, nil
}

func (issuer *recordingGatewayRecoveryIssuer) CommitIssue(
	_ context.Context,
	plan enrollment.RecoveryIssuePlan,
) (enrollment.RecoveryIssueResult, error) {
	issuer.commits++
	secret, err := output.NewSecretString(issuer.token)
	if err != nil {
		return enrollment.RecoveryIssueResult{}, err
	}
	return enrollment.RecoveryIssueResult{
		RecoveryID: "rec-ABC234", NodeID: plan.NodeID, NodeName: plan.NodeName,
		ExpiresAt: plan.ExpiresAt, StateGeneration: plan.ExpectedStateGeneration + 1, Token: &secret,
	}, nil
}

type recordingNodeRecoveryOperator struct {
	plans      int
	applies    int
	planToken  string
	applyToken string
	applyErr   error
	result     enrollment.NodeRecoveryResult
}

func (operator *recordingNodeRecoveryOperator) Plan(token *output.Secret) (enrollment.NodeRecoveryPlan, error) {
	operator.plans++
	_ = token.Use(func(value []byte) error { operator.planToken = string(value); return nil })
	return enrollment.NodeRecoveryPlan{
		RecoveryID: "rec-ABC234", NodeID: rotationCLINodeID, NodeName: "private-node",
		ActiveTransport: model.TransportRestricted, ExpectedLocalStateGeneration: 10,
		NextLocalStateGeneration: 12, ExpectedGatewayStateGeneration: 14,
		CurrentCredentialGeneration: 3, RequestedCredentialGeneration: 4,
		ExpiresAt: time.Date(2026, time.September, 3, 12, 15, 0, 0, time.UTC),
	}, nil
}

func (operator *recordingNodeRecoveryOperator) Apply(
	_ context.Context,
	plan enrollment.NodeRecoveryPlan,
	token *output.Secret,
) (enrollment.NodeRecoveryResult, error) {
	operator.applies++
	_ = token.Use(func(value []byte) error { operator.applyToken = string(value); return nil })
	if operator.result.NodeID != "" {
		return operator.result, operator.applyErr
	}
	return enrollment.NodeRecoveryResult{
		NodeID: plan.NodeID, NodeName: plan.NodeName, ActiveTransport: plan.ActiveTransport,
		PreviousCredentialGeneration: plan.CurrentCredentialGeneration,
		CredentialGeneration:         plan.RequestedCredentialGeneration,
		GatewayStateGeneration:       plan.ExpectedGatewayStateGeneration + 1,
		LocalStateGeneration:         plan.NextLocalStateGeneration,
	}, operator.applyErr
}
