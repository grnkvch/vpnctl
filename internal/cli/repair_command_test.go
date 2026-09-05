package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

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

func stubRepairCommand(t *testing.T, role HostRole, operator CommittedNodeRepairOperator) func() {
	t.Helper()
	oldPaths, oldRole, oldBuild, oldTTY := repairSystemPaths, repairLoadRole, repairBuildNode, repairOpenTTY
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
		repairSystemPaths, repairLoadRole, repairBuildNode, repairOpenTTY = oldPaths, oldRole, oldBuild, oldTTY
	}
}

var _ CommittedNodeRepairOperator = (*recordingCommittedNodeRepairOperator)(nil)
