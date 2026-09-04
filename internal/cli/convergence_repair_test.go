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

func TestRunConvergenceRepairPreviewsThenConfirmsExactOwnedActions(t *testing.T) {
	t.Parallel()

	plan := convergenceRepairTestPlan(t)
	result := convergenceRepairTestResult(plan)
	var events []string
	operator := &recordingConvergenceRepairOperator{plan: plan, result: result, events: &events}
	terminal := &orderedPromptIO{visible: []string{"yes"}, events: &events}
	outcome, err := RunConvergenceRepair(context.Background(), RoleGateway, false, false, false, terminal, operator)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"plan", "visible", "repair"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("repair events = %v, want %v", events, want)
	}
	if outcome.Mode != MutationImmediate || outcome.Plan.Impact != ImpactDestructive || operator.repairCalls != 1 {
		t.Fatalf("repair outcome = %+v; calls=%d", outcome, operator.repairCalls)
	}
	if !reflect.DeepEqual(operator.approved, plan) {
		t.Fatal("workflow did not repair the exact retained domain plan")
	}
	if outcome.Result.Command != "repair" || outcome.Result.Data["changed"] != true ||
		outcome.Result.Data["generation"] != uint64(7) || outcome.Result.Data["repair_count"] != 2 {
		t.Fatalf("repair result = %+v", outcome.Result)
	}
	assertRepairPreviewIsOwnedAndSafe(t, outcome.Result)
}

func TestRunConvergenceRepairDryRunDoesNotMutateOrPrompt(t *testing.T) {
	t.Parallel()

	operator := &recordingConvergenceRepairOperator{plan: convergenceRepairTestPlan(t)}
	outcome, err := RunConvergenceRepair(context.Background(), RoleGateway, true, false, true, nil, operator)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Mode != MutationDryRun || operator.planCalls != 1 || operator.repairCalls != 0 {
		t.Fatalf("repair dry-run = %+v; calls=%d/%d", outcome, operator.planCalls, operator.repairCalls)
	}
	if outcome.Result.Data["changed"] != true || outcome.Result.Data["repair_count"] != 2 {
		t.Fatalf("repair dry-run result = %+v", outcome.Result)
	}
	assertRepairPreviewIsOwnedAndSafe(t, outcome.Result)
}

func TestRunConvergenceRepairJSONRequiresExplicitConsent(t *testing.T) {
	t.Parallel()

	plan := convergenceRepairTestPlan(t)
	operator := &recordingConvergenceRepairOperator{plan: plan}
	if _, err := RunConvergenceRepair(context.Background(), RoleGateway, false, false, true, nil, operator); !errors.Is(err, ErrInteractionRefused) {
		t.Fatalf("JSON repair consent error = %v", err)
	}
	if operator.planCalls != 1 || operator.repairCalls != 0 {
		t.Fatalf("JSON repair calls = %d/%d", operator.planCalls, operator.repairCalls)
	}

	operator = &recordingConvergenceRepairOperator{plan: plan, result: convergenceRepairTestResult(plan)}
	if _, err := RunConvergenceRepair(context.Background(), RoleGateway, false, true, true, nil, operator); err != nil {
		t.Fatalf("explicit --yes repair: %v", err)
	}
	if operator.repairCalls != 1 {
		t.Fatal("explicitly consented repair did not execute")
	}
}

func TestConvergenceRepairRejectsCrossRoleAndModifiedPublicPreview(t *testing.T) {
	t.Parallel()

	plan := convergenceRepairTestPlan(t)
	operator := &recordingConvergenceRepairOperator{plan: plan}
	if _, err := RunConvergenceRepair(context.Background(), RoleNode, true, false, false, nil, operator); !errors.Is(err, ErrInvalidMutationPlan) {
		t.Fatalf("cross-role repair error = %v", err)
	}
	if operator.repairCalls != 0 {
		t.Fatal("cross-role repair reached operator")
	}

	operator = &recordingConvergenceRepairOperator{plan: plan}
	workflow, err := NewConvergenceRepairWorkflow(RoleGateway, operator)
	if err != nil {
		t.Fatal(err)
	}
	publicPlan, err := workflow.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	publicPlan.Result.Data["repair_count"] = 999
	if _, err := workflow.Apply(context.Background(), publicPlan, nil); !errors.Is(err, ErrInvalidMutationPlan) {
		t.Fatalf("modified repair preview error = %v", err)
	}
	if operator.repairCalls != 0 {
		t.Fatal("modified repair preview reached operator")
	}
}

func assertRepairPreviewIsOwnedAndSafe(t *testing.T, result output.Result) {
	t.Helper()
	repairs, ok := result.Data["repairs"].(output.SafeList)
	if !ok || len(repairs) != 2 {
		t.Fatalf("repair preview = %#v", result.Data["repairs"])
	}
	for _, raw := range repairs {
		item, ok := raw.(output.SafeObject)
		if !ok {
			t.Fatalf("repair preview item = %#v", raw)
		}
		for _, forbidden := range []string{"material", "content", "foreign", "desired_sha256"} {
			if _, exposed := item[forbidden]; exposed {
				t.Fatalf("repair preview exposed forbidden field %s", forbidden)
			}
		}
		if item["component"] == "foreign" || item["resource_id"] == "/etc/foreign.conf" {
			t.Fatalf("repair preview included foreign resource: %#v", item)
		}
	}
}

type recordingConvergenceRepairOperator struct {
	plan        operations.RepairPlan
	result      operations.RepairResult
	planCalls   int
	repairCalls int
	approved    operations.RepairPlan
	events      *[]string
}

func (operator *recordingConvergenceRepairOperator) Plan(context.Context) (operations.RepairPlan, error) {
	operator.planCalls++
	if operator.events != nil {
		*operator.events = append(*operator.events, "plan")
	}
	return operator.plan, nil
}

func (operator *recordingConvergenceRepairOperator) Repair(_ context.Context, plan operations.RepairPlan) (operations.RepairResult, error) {
	operator.repairCalls++
	operator.approved = plan
	if operator.events != nil {
		*operator.events = append(*operator.events, "repair")
	}
	return operator.result, nil
}

func convergenceRepairTestPlan(t *testing.T) operations.RepairPlan {
	t.Helper()
	modifiedKey := operations.ManagedResourceKey{Component: "ingress", Kind: operations.ManagedResourceFile, ID: "/etc/vpnctl/nginx.conf"}
	unexpectedKey := operations.ManagedResourceKey{Component: "routing", Kind: operations.ManagedResourceNetwork, ID: "owned-orphan"}
	targetHash := operations.ManagedFingerprint([]byte("applied-generation-seven"))
	observedHash := operations.ManagedFingerprint([]byte("manual-modification"))
	orphanHash := operations.ManagedFingerprint([]byte("owned-orphan"))
	drift := []operations.OwnedDrift{
		{
			Resource: modifiedKey, Kind: operations.OwnedDriftModified,
			Impact:         operations.ConvergenceImpactAvailability,
			ExpectedSHA256: targetHash, ActualSHA256: observedHash,
		},
		{
			Resource: unexpectedKey, Kind: operations.OwnedDriftUnexpected,
			Impact: operations.ConvergenceImpactDestructive, ActualSHA256: orphanHash,
		},
	}
	convergence := operations.ConvergencePlan{
		DesiredGeneration: 8, AppliedGeneration: 7,
		Impact:  operations.ConvergenceImpactDestructive,
		Changes: []operations.DesiredChange{}, Drift: drift,
	}
	plan := operations.RepairPlan{
		Role: model.RoleGateway, TargetGeneration: 7,
		Impact: operations.ConvergenceImpactDestructive,
		Actions: []operations.RepairAction{
			{
				Resource: modifiedKey, DriftKind: operations.OwnedDriftModified,
				Action: operations.RepairRestore, Impact: operations.ConvergenceImpactAvailability,
				Scope:        operations.ApplyScope{Role: model.RoleGateway},
				TargetSHA256: targetHash, ObservedSHA256: observedHash,
			},
			{
				Resource: unexpectedKey, DriftKind: operations.OwnedDriftUnexpected,
				Action: operations.RepairRemove, Impact: operations.ConvergenceImpactDestructive,
				Scope: operations.ApplyScope{Role: model.RoleGateway}, ObservedSHA256: orphanHash,
			},
		},
		Convergence: convergence,
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("test repair plan: %v", err)
	}
	return plan
}

func convergenceRepairTestResult(plan operations.RepairPlan) operations.RepairResult {
	return operations.RepairResult{
		Changed: true, Generation: plan.TargetGeneration,
		Actions: append([]operations.RepairAction{}, plan.Actions...),
		Resources: []operations.RepairResourceResult{
			{Resource: plan.Actions[0].Resource, Present: true, RuntimeSHA256: plan.Actions[0].TargetSHA256},
			{Resource: plan.Actions[1].Resource},
		},
	}
}
