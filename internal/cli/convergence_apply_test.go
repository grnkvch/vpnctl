package cli

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestRunConvergenceApplyUsesConditionalConsentAndPreservesUnrelatedDrift(t *testing.T) {
	t.Parallel()

	plan := convergenceApplyTestPlan(t, operations.ConvergenceImpactAvailability, true)
	operator := &recordingConvergenceApplyOperator{plan: plan, result: operations.ApplyResult{
		Changed: true, Generation: plan.DesiredGeneration,
		OperationIDs: []string{"operation-1"}, RemainingDrift: append([]operations.OwnedDrift{}, plan.RemainingDrift...),
	}}
	terminal := &fakePromptIO{visible: []string{"yes"}}
	outcome, err := RunConvergenceApply(context.Background(), RoleGateway, false, false, terminal, operator)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Mode != MutationImmediate || outcome.Plan.Impact != ImpactAvailability || operator.planCalls != 1 || operator.applyCalls != 1 {
		t.Fatalf("apply outcome = %+v; operator calls=%d/%d", outcome, operator.planCalls, operator.applyCalls)
	}
	if outcome.Result.Command != "apply" || outcome.Result.Status != output.StatusOK ||
		outcome.Result.Data["changed"] != true || outcome.Result.Data["generation"] != uint64(5) ||
		outcome.Result.Data["operation_id"] != "operation-1" {
		t.Fatalf("apply result = %+v", outcome.Result)
	}
	if len(outcome.Result.Warnings) != 1 || outcome.Result.Warnings[0].Code != "unrelated_drift_remains" ||
		len(outcome.Result.RequiresAction) != 1 || outcome.Result.RequiresAction[0].Command != "vpnctl repair" {
		t.Fatalf("remaining drift output = %+v / %+v", outcome.Result.Warnings, outcome.Result.RequiresAction)
	}
	if !reflect.DeepEqual(operator.approved, plan) {
		t.Fatal("workflow did not apply the exact retained domain plan")
	}
}

func TestRunConvergenceApplyJSONDoesNotGrantConditionalConsent(t *testing.T) {
	t.Parallel()

	plan := convergenceApplyTestPlan(t, operations.ConvergenceImpactDestructive, false)
	operator := &recordingConvergenceApplyOperator{plan: plan}
	if _, err := RunConvergenceApply(context.Background(), RoleGateway, false, true, nil, operator); !errors.Is(err, ErrInteractionRefused) {
		t.Fatalf("JSON apply consent error = %v", err)
	}
	if operator.planCalls != 1 || operator.applyCalls != 0 {
		t.Fatalf("JSON apply calls = %d/%d", operator.planCalls, operator.applyCalls)
	}

	operator = &recordingConvergenceApplyOperator{plan: plan, result: operations.ApplyResult{
		Changed: true, Generation: plan.DesiredGeneration,
		OperationIDs: []string{"operation-1"}, RemainingDrift: []operations.OwnedDrift{},
	}}
	if _, err := RunConvergenceApply(context.Background(), RoleGateway, true, true, nil, operator); err != nil {
		t.Fatalf("explicit --yes apply: %v", err)
	}
	if operator.applyCalls != 1 {
		t.Fatal("explicitly consented apply did not execute")
	}
}

func TestRunConvergenceApplyNoOpNeedsNoConsentAndRoleGatePrecedesPlan(t *testing.T) {
	t.Parallel()

	plan := convergenceApplyNoOpPlan(t)
	operator := &recordingConvergenceApplyOperator{plan: plan, result: operations.ApplyResult{
		Changed: false, Generation: plan.DesiredGeneration,
		OperationIDs: []string{}, RemainingDrift: []operations.OwnedDrift{},
	}}
	outcome, err := RunConvergenceApply(context.Background(), RoleNode, false, true, nil, operator)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Plan.Impact != ImpactNone || outcome.Result.Data["changed"] != false || operator.applyCalls != 1 {
		t.Fatalf("no-op apply outcome = %+v; applies=%d", outcome, operator.applyCalls)
	}

	operator = &recordingConvergenceApplyOperator{plan: plan}
	if _, err := RunConvergenceApply(context.Background(), RoleUninitialized, false, false, nil, operator); !errors.Is(err, ErrUnsupportedRole) {
		t.Fatalf("uninitialized apply error = %v", err)
	}
	if operator.planCalls != 0 || operator.applyCalls != 0 {
		t.Fatal("unsupported role reached apply operator")
	}
}

func TestRunConvergenceApplyRejectsOperatorForDifferentHostRole(t *testing.T) {
	t.Parallel()

	operator := &recordingConvergenceApplyOperator{plan: convergenceApplyTestPlan(t, operations.ConvergenceImpactNone, false)}
	if _, err := RunConvergenceApply(context.Background(), RoleNode, false, false, nil, operator); !errors.Is(err, ErrInvalidMutationPlan) {
		t.Fatalf("cross-role apply operator error = %v", err)
	}
	if operator.planCalls != 1 || operator.applyCalls != 0 {
		t.Fatalf("cross-role operator calls = %d/%d", operator.planCalls, operator.applyCalls)
	}
}

func TestConvergenceApplyWorkflowRejectsModifiedPublicPlan(t *testing.T) {
	t.Parallel()

	plan := convergenceApplyTestPlan(t, operations.ConvergenceImpactAvailability, false)
	operator := &recordingConvergenceApplyOperator{plan: plan}
	workflow, err := NewConvergenceApplyWorkflow(RoleGateway, operator)
	if err != nil {
		t.Fatal(err)
	}
	publicPlan, err := workflow.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	publicPlan.Result.Data["generation"] = uint64(999)
	if _, err := workflow.Apply(context.Background(), publicPlan, nil); !errors.Is(err, ErrInvalidMutationPlan) {
		t.Fatalf("modified public plan error = %v", err)
	}
	if operator.applyCalls != 0 {
		t.Fatal("modified public plan reached apply operator")
	}
}

func TestConvergenceApplyOutputStaysInsideOperationV1Shape(t *testing.T) {
	t.Parallel()

	plan := convergenceApplyTestPlan(t, operations.ConvergenceImpactNone, false)
	result, err := convergenceApplyPlanOutput(plan)
	if err != nil {
		t.Fatal(err)
	}
	wantKeys := map[string]any{"changed": true, "generation": uint64(5), "operation_id": "operation-1"}
	if !reflect.DeepEqual(result.Data, output.SafeObject(wantKeys)) {
		t.Fatalf("operation-v1 data = %#v", result.Data)
	}
	for _, forbidden := range []string{"changes", "drift", "scope", "resource_id", "from_sha256", "to_sha256"} {
		if _, exposed := result.Data[forbidden]; exposed {
			t.Fatalf("apply operation output exposed %s", forbidden)
		}
	}
}

type recordingConvergenceApplyOperator struct {
	plan       operations.ApplyPlan
	result     operations.ApplyResult
	planCalls  int
	applyCalls int
	approved   operations.ApplyPlan
}

func (operator *recordingConvergenceApplyOperator) Plan(context.Context) (operations.ApplyPlan, error) {
	operator.planCalls++
	return operator.plan, nil
}

func (operator *recordingConvergenceApplyOperator) Apply(_ context.Context, plan operations.ApplyPlan) (operations.ApplyResult, error) {
	operator.applyCalls++
	operator.approved = plan
	return operator.result, nil
}

func convergenceApplyTestPlan(t *testing.T, impact operations.ConvergenceImpact, withDrift bool) operations.ApplyPlan {
	t.Helper()
	before := operations.ManagedFingerprint([]byte("before"))
	after := operations.ManagedFingerprint([]byte("after"))
	key := operations.ManagedResourceKey{Component: "ingress", Kind: operations.ManagedResourceFile, ID: "/etc/vpnctl/nginx.conf"}
	change := operations.DesiredChange{
		OperationID: "operation-1", OperationType: "apply",
		OperationExpectedGeneration: 4, OperationDesiredGeneration: 5,
		Resource: key, Kind: operations.DesiredUpdate, Impact: impact,
		FromSHA256: before, ToSHA256: after,
	}
	drift := []operations.OwnedDrift{}
	convergenceImpact := impact
	if withDrift {
		driftKey := operations.ManagedResourceKey{Component: "transport", Kind: operations.ManagedResourceUnit, ID: "vpnctl-standard.service"}
		drift = append(drift, operations.OwnedDrift{
			Resource: driftKey, Kind: operations.OwnedDriftMissing,
			Impact: operations.ConvergenceImpactAvailability, ExpectedSHA256: operations.ManagedFingerprint([]byte("unit")),
		})
		if convergenceImpact == operations.ConvergenceImpactNone {
			convergenceImpact = operations.ConvergenceImpactAvailability
		}
	}
	convergence := operations.ConvergencePlan{
		DesiredGeneration: 5, AppliedGeneration: 4, Impact: convergenceImpact,
		Changes: []operations.DesiredChange{change}, Drift: drift,
	}
	plan := operations.ApplyPlan{
		Role: model.RoleGateway, AppliedGeneration: 4, DesiredGeneration: 5, Impact: impact,
		Operations: []operations.ApplyOperation{{
			ID: "operation-1", Type: "apply", ExpectedGeneration: 4, DesiredGeneration: 5,
			Scope:  operations.ApplyScope{Role: model.RoleGateway},
			Impact: impact, Changes: []operations.DesiredChange{change},
		}},
		RemainingDrift: append([]operations.OwnedDrift{}, drift...), Convergence: convergence,
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("test apply plan: %v", err)
	}
	return plan
}

func convergenceApplyNoOpPlan(t *testing.T) operations.ApplyPlan {
	t.Helper()
	convergence := operations.ConvergencePlan{
		DesiredGeneration: 4, AppliedGeneration: 4, Impact: operations.ConvergenceImpactNone,
		Changes: []operations.DesiredChange{}, Drift: []operations.OwnedDrift{},
	}
	plan := operations.ApplyPlan{
		Role: model.RoleNode, CurrentNodeID: "74000000-0000-4000-8000-000000000001",
		AppliedGeneration: 4, DesiredGeneration: 4, Impact: operations.ConvergenceImpactNone,
		Operations: []operations.ApplyOperation{}, RemainingDrift: []operations.OwnedDrift{}, Convergence: convergence,
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("test no-op apply plan: %v", err)
	}
	return plan
}
