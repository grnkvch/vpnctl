package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestApplyCommandDispatchesGlobalJSONAndExplicitConsent(t *testing.T) {
	plan := convergenceApplyTestPlan(t, operations.ConvergenceImpactAvailability, false)
	operator := &recordingConvergenceApplyOperator{plan: plan, result: operations.ApplyResult{
		Changed: true, Generation: plan.DesiredGeneration,
		OperationIDs: []string{"operation-1"}, RemainingDrift: []operations.OwnedDrift{},
	}}
	restore := stubApplyCommand(t, RoleGateway, operator)
	defer restore()
	applyOpenTTY = func() (PromptIO, io.Closer, error) {
		t.Fatal("--yes apply opened a controlling TTY")
		return nil, nil, nil
	}

	var stdout, stderr bytes.Buffer
	if exit := Execute([]string{"--json", "apply", "--yes"}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if operator.planCalls != 1 || operator.applyCalls != 1 || stderr.Len() != 0 ||
		!strings.Contains(stdout.String(), `"command":"apply"`) ||
		!strings.Contains(stdout.String(), `"operation_id":"operation-1"`) {
		t.Fatalf("calls=%d/%d stdout=%s stderr=%s", operator.planCalls, operator.applyCalls, stdout.String(), stderr.String())
	}
}

func TestApplyCommandNoOpDoesNotRequireAvailableTTY(t *testing.T) {
	plan := convergenceApplyGatewayNoOpPlan(t)
	operator := &recordingConvergenceApplyOperator{plan: plan, result: operations.ApplyResult{
		Changed: false, Generation: plan.DesiredGeneration,
		OperationIDs: []string{}, RemainingDrift: []operations.OwnedDrift{},
	}}
	restore := stubApplyCommand(t, RoleGateway, operator)
	defer restore()
	applyOpenTTY = func() (PromptIO, io.Closer, error) { return nil, nil, errors.New("no tty") }

	var stdout, stderr bytes.Buffer
	if exit := Execute([]string{"apply", "--json"}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if operator.applyCalls != 1 || !strings.Contains(stdout.String(), `"changed":false`) {
		t.Fatalf("apply calls=%d stdout=%s", operator.applyCalls, stdout.String())
	}
}

func TestApplyCommandRequiresTTYOnlyAfterImpactPlan(t *testing.T) {
	plan := convergenceApplyTestPlan(t, operations.ConvergenceImpactAvailability, false)
	operator := &recordingConvergenceApplyOperator{plan: plan}
	restore := stubApplyCommand(t, RoleGateway, operator)
	defer restore()
	applyOpenTTY = func() (PromptIO, io.Closer, error) { return nil, nil, errors.New("no tty") }

	var stdout, stderr bytes.Buffer
	if exit := Execute([]string{"apply", "--json"}, &stdout, &stderr); exit != ExitValidation ||
		!strings.Contains(stdout.String(), `"code":"controlling_tty_required"`) {
		t.Fatalf("exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if operator.planCalls != 1 || operator.applyCalls != 0 {
		t.Fatalf("TTY refusal calls=%d/%d", operator.planCalls, operator.applyCalls)
	}
}

func TestApplyCommandRejectsUnsupportedFlagsBeforeSystemBuild(t *testing.T) {
	oldBuild := applyBuild
	applyBuild = func(store.Paths, HostRole) (ConvergenceApplyOperator, error) {
		t.Fatal("invalid apply arguments reached system builder")
		return nil, nil
	}
	defer func() { applyBuild = oldBuild }()

	for _, args := range [][]string{{"--json", "apply", "--dry-run"}, {"--json", "apply", "--defer"}, {"--json", "apply", "extra"}} {
		var stdout, stderr bytes.Buffer
		if exit := Execute(args, &stdout, &stderr); exit != ExitValidation ||
			!strings.Contains(stdout.String(), `"code":"invalid_arguments"`) {
			t.Fatalf("args=%v exit=%d stdout=%s stderr=%s", args, exit, stdout.String(), stderr.String())
		}
	}
}

func TestApplyCommandClassifiesConflictingDriftAndForeignNodeScope(t *testing.T) {
	category, code, _ := classifyConvergenceApplyError(operations.ErrApplyConflict)
	if category != "conflict" || code != "apply_plan_stale" {
		t.Fatalf("drift conflict classification=%s/%s", category, code)
	}
	category, code, _ = classifyConvergenceApplyError(operations.ErrApplyNodeAgentUnavailable)
	if category != "unavailable" || code != "apply_requires_node" {
		t.Fatalf("node scope classification=%s/%s", category, code)
	}
}

func stubApplyCommand(t *testing.T, role HostRole, operator ConvergenceApplyOperator) func() {
	t.Helper()
	oldPaths, oldRole, oldBuild, oldTTY := applySystemPaths, applyLoadRole, applyBuild, applyOpenTTY
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	applySystemPaths = func() store.Paths { return paths }
	applyLoadRole = func(received store.Paths) (HostRole, error) {
		if received != paths {
			t.Fatalf("apply role paths=%+v", received)
		}
		return role, nil
	}
	applyBuild = func(received store.Paths, receivedRole HostRole) (ConvergenceApplyOperator, error) {
		if received != paths || receivedRole != role {
			t.Fatalf("apply build=%+v/%s", received, receivedRole)
		}
		return operator, nil
	}
	return func() {
		applySystemPaths, applyLoadRole, applyBuild, applyOpenTTY = oldPaths, oldRole, oldBuild, oldTTY
	}
}

func convergenceApplyGatewayNoOpPlan(t *testing.T) operations.ApplyPlan {
	t.Helper()
	plan := convergenceApplyNoOpPlan(t)
	plan.Role = model.RoleGateway
	plan.CurrentNodeID = ""
	if err := plan.Validate(); err != nil {
		t.Fatalf("gateway no-op apply plan: %v", err)
	}
	return plan
}
