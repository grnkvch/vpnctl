package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestRepairCommandDispatchesGlobalJSONDryRunWithoutMutation(t *testing.T) {
	operator := &recordingCommittedNodeRepairOperator{plan: committedNodeRepairTestPlan()}
	restore := stubRepairCommand(t, RoleNode, operator)
	defer restore()

	var stdout, stderr bytes.Buffer
	if exit := Execute([]string{"--json", "repair", "--dry-run"}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if operator.planCalls != 1 || operator.repairCalls != 0 || stderr.Len() != 0 ||
		!strings.Contains(stdout.String(), `"command":"repair"`) || !strings.Contains(stdout.String(), `"scope":"committed_node_services"`) {
		t.Fatalf("calls=%d/%d stdout=%s stderr=%s", operator.planCalls, operator.repairCalls, stdout.String(), stderr.String())
	}
}

func TestRepairCommandYesActivatesAndReportsPendingFailure(t *testing.T) {
	operator := &recordingCommittedNodeRepairOperator{plan: committedNodeRepairTestPlan()}
	restore := stubRepairCommand(t, RoleNode, operator)
	defer restore()

	var stdout, stderr bytes.Buffer
	if exit := Execute([]string{"repair", "--yes", "--json"}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("success exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if operator.repairCalls != 1 || !strings.Contains(stdout.String(), `"generation":7`) {
		t.Fatalf("success calls=%d stdout=%s", operator.repairCalls, stdout.String())
	}

	operator.err = errors.Join(enrollment.ErrNodeActivationPending, errors.New("tunnel unavailable"))
	stdout.Reset()
	stderr.Reset()
	if exit := Execute([]string{"repair", "--yes", "--json"}, &stdout, &stderr); exit != ExitUnavailable {
		t.Fatalf("pending exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"code":"repair_activation_pending"`) ||
		!strings.Contains(stdout.String(), `"command":"vpnctl repair"`) || !strings.Contains(stdout.String(), `"changed":true`) {
		t.Fatalf("pending stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestRepairCommandRequiresTTYUnlessYesAndRejectsArgumentsBeforeBuild(t *testing.T) {
	operator := &recordingCommittedNodeRepairOperator{plan: committedNodeRepairTestPlan()}
	restore := stubRepairCommand(t, RoleNode, operator)
	defer restore()
	repairOpenTTY = func() (PromptIO, io.Closer, error) { return nil, nil, errors.New("no tty") }

	var stdout, stderr bytes.Buffer
	if exit := Execute([]string{"repair", "--json"}, &stdout, &stderr); exit != ExitValidation ||
		!strings.Contains(stdout.String(), `"code":"controlling_tty_required"`) {
		t.Fatalf("tty exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if operator.planCalls != 0 || operator.repairCalls != 0 {
		t.Fatalf("TTY refusal reached operator: %d/%d", operator.planCalls, operator.repairCalls)
	}

	stdout.Reset()
	stderr.Reset()
	if exit := Execute([]string{"repair", "extra", "--json"}, &stdout, &stderr); exit != ExitValidation ||
		!strings.Contains(stdout.String(), `"code":"invalid_arguments"`) {
		t.Fatalf("argument exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestRepairCommandDispatchesGatewayRepairAndReportsConfirmation(t *testing.T) {
	operator := &recordingCommittedGatewayRepairOperator{
		plan:   committedGatewayRepairTestPlan(true),
		result: controller.GatewayRepairData{Changed: true, NetworkActivationRequired: true, TransactionID: "fw-7K3M2P"},
	}
	oldPaths, oldRole, oldNode, oldGateway, oldTTY := repairSystemPaths, repairLoadRole, repairBuildNode, repairBuildGateway, repairOpenTTY
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repairSystemPaths = func() store.Paths { return paths }
	repairLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	repairBuildNode = func(store.Paths) (CommittedNodeRepairOperator, error) {
		t.Fatal("gateway repair reached node builder")
		return nil, nil
	}
	repairBuildGateway = func(received store.Paths) (CommittedGatewayRepairOperator, error) {
		if received != paths {
			t.Fatalf("gateway repair paths = %+v", received)
		}
		return operator, nil
	}
	repairOpenTTY = func() (PromptIO, io.Closer, error) {
		t.Fatal("--yes gateway repair opened TTY")
		return nil, nil, nil
	}
	defer func() {
		repairSystemPaths, repairLoadRole, repairBuildNode, repairBuildGateway, repairOpenTTY = oldPaths, oldRole, oldNode, oldGateway, oldTTY
	}()

	var stdout, stderr bytes.Buffer
	if exit := Execute([]string{"repair", "--yes", "--json"}, &stdout, &stderr); exit != ExitSuccess {
		t.Fatalf("gateway repair exit=%d stdout=%s stderr=%s", exit, stdout.String(), stderr.String())
	}
	if operator.planCalls != 1 || operator.repairCalls != 1 || stderr.Len() != 0 ||
		!strings.Contains(stdout.String(), `"scope":"gateway_bootstrap_recovery"`) ||
		!strings.Contains(stdout.String(), `"command":"vpnctl confirm fw-7K3M2P"`) {
		t.Fatalf("gateway repair calls=%d/%d stdout=%s stderr=%s", operator.planCalls, operator.repairCalls, stdout.String(), stderr.String())
	}
}

func TestRepairCommandMarksLostGatewayResponseOutcomeUncertain(t *testing.T) {
	operator := &failingCommittedGatewayRepairOperator{plan: committedGatewayRepairTestPlan(true), err: ErrCommittedGatewayRepairUncertain}
	oldPaths, oldRole, oldGateway, oldTTY := repairSystemPaths, repairLoadRole, repairBuildGateway, repairOpenTTY
	paths, _ := store.NewPaths(t.TempDir())
	repairSystemPaths = func() store.Paths { return paths }
	repairLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	repairBuildGateway = func(store.Paths) (CommittedGatewayRepairOperator, error) { return operator, nil }
	repairOpenTTY = func() (PromptIO, io.Closer, error) { return nil, nil, errors.New("unexpected TTY") }
	defer func() {
		repairSystemPaths, repairLoadRole, repairBuildGateway, repairOpenTTY = oldPaths, oldRole, oldGateway, oldTTY
	}()

	var stdout, stderr bytes.Buffer
	if exit := Execute([]string{"repair", "--yes", "--json"}, &stdout, &stderr); exit != ExitUnavailable ||
		!strings.Contains(stdout.String(), `"code":"gateway_repair_outcome_uncertain"`) ||
		!strings.Contains(stdout.String(), `"code":"inspect_gateway_repair"`) ||
		!strings.Contains(stdout.String(), `"changed":true`) {
		t.Fatalf("uncertain gateway repair exit/output = %d / %s / %s", exit, stdout.String(), stderr.String())
	}
}

func stubRepairCommand(t *testing.T, role HostRole, operator CommittedNodeRepairOperator) func() {
	t.Helper()
	oldPaths, oldRole, oldBuild, oldGateway, oldTTY := repairSystemPaths, repairLoadRole, repairBuildNode, repairBuildGateway, repairOpenTTY
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repairSystemPaths = func() store.Paths { return paths }
	repairLoadRole = func(received store.Paths) (HostRole, error) {
		if received != paths {
			t.Fatalf("repair role paths = %+v", received)
		}
		return role, nil
	}
	repairBuildNode = func(received store.Paths) (CommittedNodeRepairOperator, error) {
		if received != paths {
			t.Fatalf("repair build paths = %+v", received)
		}
		return operator, nil
	}
	repairOpenTTY = func() (PromptIO, io.Closer, error) {
		t.Fatal("unexpected controlling TTY")
		return nil, nil, nil
	}
	return func() {
		repairSystemPaths, repairLoadRole, repairBuildNode, repairBuildGateway, repairOpenTTY = oldPaths, oldRole, oldBuild, oldGateway, oldTTY
	}
}

type failingCommittedGatewayRepairOperator struct {
	plan controller.GatewayRepairPlan
	err  error
}

func (operator *failingCommittedGatewayRepairOperator) Plan(context.Context) (controller.GatewayRepairPlan, error) {
	return cloneCommittedGatewayRepairPlan(operator.plan), nil
}

func (operator *failingCommittedGatewayRepairOperator) Repair(context.Context, controller.GatewayRepairPlan) (controller.GatewayRepairData, error) {
	return controller.GatewayRepairData{}, operator.err
}

var _ CommittedNodeRepairOperator = (*recordingCommittedNodeRepairOperator)(nil)
