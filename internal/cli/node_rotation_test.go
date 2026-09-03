package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestNodeRotationWorkflowUsesConfirmedImmediateAvailabilityImpact(t *testing.T) {
	operator := &recordingNodeRotationOperator{}
	workflow, err := NewNodeRotationMutationWorkflow(operator)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := workflow.Plan(context.Background(), nil)
	if err != nil || plan.Impact != ImpactAvailability || plan.Result.Command != "node.rotate" || operator.applies != 0 {
		t.Fatalf("Plan() = %+v, %v; operator=%+v", plan, err, operator)
	}
	if plan.Result.Data["generation"] != uint64(12) || plan.Result.Data["credential_generation"] != uint64(4) {
		t.Fatalf("plan output = %+v", plan.Result)
	}
	applied, err := workflow.Apply(context.Background(), plan, nil)
	if err != nil || operator.applies != 1 || applied.Result.ResourceIDs["node_id"] != rotationCLINodeID {
		t.Fatalf("Apply() = %+v, %v; operator=%+v", applied, err, operator)
	}
	if err := applied.Result.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNodeRotationWorkflowPreservesCommittedCleanupActions(t *testing.T) {
	operator := &recordingNodeRotationOperator{
		applyErr: enrollment.ErrNodeRotationCleanupPending,
		result: enrollment.NodeRotationResult{
			NodeID: rotationCLINodeID, NodeName: "private-node", ActiveTransport: model.TransportRestricted,
			PreviousCredentialGeneration: 3, CredentialGeneration: 4,
			GatewayStateGeneration: 15, LocalStateGeneration: 12, GatewayCleanupNeeded: true,
		},
	}
	workflow, _ := NewNodeRotationMutationWorkflow(operator)
	plan, _ := workflow.Plan(context.Background(), nil)
	applied, err := workflow.Apply(context.Background(), plan, nil)
	if err != nil || applied.Result.Status != output.StatusPending || len(applied.Result.RequiresAction) != 1 ||
		applied.Result.RequiresAction[0].Code != "repair_gateway_rotation" {
		t.Fatalf("Apply(cleanup pending) = %+v, %v", applied, err)
	}
}

func TestNodeRotationWorkflowRejectsFailedPlanAndApplyBeforePlan(t *testing.T) {
	operator := &recordingNodeRotationOperator{planErr: enrollment.ErrNodeRotationStale}
	workflow, _ := NewNodeRotationMutationWorkflow(operator)
	if _, err := workflow.Plan(context.Background(), nil); !errors.Is(err, enrollment.ErrNodeRotationStale) {
		t.Fatalf("Plan() error = %v", err)
	}
	if _, err := workflow.Apply(context.Background(), MutationPlan{}, nil); err == nil || operator.applies != 0 {
		t.Fatalf("Apply() error = %v; applies=%d", err, operator.applies)
	}
}

const rotationCLINodeID = "90000000-0000-4000-8000-000000000009"

type recordingNodeRotationOperator struct {
	planErr  error
	applyErr error
	result   enrollment.NodeRotationResult
	applies  int
}

func (operator *recordingNodeRotationOperator) Plan() (enrollment.NodeRotationPlan, error) {
	if operator.planErr != nil {
		return enrollment.NodeRotationPlan{}, operator.planErr
	}
	return enrollment.NodeRotationPlan{
		NodeID: rotationCLINodeID, NodeName: "private-node", ActiveTransport: model.TransportRestricted,
		ExpectedLocalStateGeneration: 10, NextLocalStateGeneration: 12,
		ExpectedGatewayStateGeneration: 14, CurrentCredentialGeneration: 3, RequestedCredentialGeneration: 4,
	}, nil
}

func (operator *recordingNodeRotationOperator) Apply(_ context.Context, plan enrollment.NodeRotationPlan) (enrollment.NodeRotationResult, error) {
	operator.applies++
	if operator.result.NodeID != "" {
		return operator.result, operator.applyErr
	}
	return enrollment.NodeRotationResult{
		NodeID: plan.NodeID, NodeName: plan.NodeName, ActiveTransport: plan.ActiveTransport,
		PreviousCredentialGeneration: plan.CurrentCredentialGeneration,
		CredentialGeneration:         plan.RequestedCredentialGeneration,
		GatewayStateGeneration:       plan.ExpectedGatewayStateGeneration + 1,
		LocalStateGeneration:         plan.NextLocalStateGeneration,
	}, operator.applyErr
}
