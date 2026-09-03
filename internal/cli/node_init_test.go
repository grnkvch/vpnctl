package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestExecuteNodeInitUsesV2WorkflowWithoutEnrollmentOrConfirmAction(t *testing.T) {
	initializer := &recordingNodeInitializer{}
	restore := stubNodeInitCommand(t, initializer, RoleUninitialized)
	defer restore()

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"--json", "init", "--node", "--yes"}, &stdout, &stderr)
	if code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("Execute() code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if initializer.planCalls != 1 || initializer.applyCalls != 1 {
		t.Fatalf("initializer calls: plan=%d apply=%d", initializer.planCalls, initializer.applyCalls)
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Command != "init.node" || result.Status != output.StatusOK || result.Data["changed"] != true || result.Data["role"] != "node" {
		t.Fatalf("result = %+v", result)
	}
	if result.Data["enrollment_status"] != "unjoined" || result.Data["active_tunnel"] != false {
		t.Fatalf("fresh node activation state = %+v", result.Data)
	}
	if result.ResourceIDs["host_id"] != nodeCLIHostID || len(result.RequiresAction) != 0 {
		t.Fatalf("resource IDs/actions = %v/%+v", result.ResourceIDs, result.RequiresAction)
	}
}

func TestExecuteNodeInitDryRunDoesNotApplyOrRequestTTY(t *testing.T) {
	initializer := &recordingNodeInitializer{}
	restore := stubNodeInitCommand(t, initializer, RoleUninitialized)
	defer restore()
	originalTTY := nodeInitOpenTTY
	nodeInitOpenTTY = func() (PromptIO, io.Closer, error) {
		t.Fatal("dry-run opened controlling TTY")
		return nil, nil, errors.New("unreachable")
	}
	defer func() { nodeInitOpenTTY = originalTTY }()

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"init", "--node", "--dry-run", "--json"}, &stdout, &stderr)
	if code != ExitSuccess || stderr.Len() != 0 || initializer.planCalls != 1 || initializer.applyCalls != 0 {
		t.Fatalf("dry-run code/calls/stdout/stderr = %d/%d/%d/%q/%q", code, initializer.planCalls, initializer.applyCalls, stdout.String(), stderr.String())
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Data["changed"] != true || result.Data["active_tunnel"] != false || len(result.RequiresAction) != 0 {
		t.Fatalf("dry-run result = %+v", result)
	}
}

func TestExecuteNodeInitRequiresOrdinaryConsent(t *testing.T) {
	initializer := &recordingNodeInitializer{}
	restore := stubNodeInitCommand(t, initializer, RoleUninitialized)
	defer restore()
	originalTTY := nodeInitOpenTTY
	terminal := &gatewayInitPrompt{answer: "yes"}
	nodeInitOpenTTY = func() (PromptIO, io.Closer, error) { return terminal, io.NopCloser(strings.NewReader("")), nil }
	defer func() { nodeInitOpenTTY = originalTTY }()

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"init", "--node"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("Execute() code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if terminal.visibleCalls != 1 || initializer.applyCalls != 1 {
		t.Fatalf("consent/apply calls = %d/%d", terminal.visibleCalls, initializer.applyCalls)
	}
}

func TestExecuteNodeInitRejectsGatewayArgumentsBeforeBuilder(t *testing.T) {
	originalBuilder := nodeInitBuilder
	nodeInitBuilder = func(context.Context, store.Paths) (nodeInitializerAPI, error) {
		t.Fatal("invalid arguments built system initializer")
		return nil, nil
	}
	defer func() { nodeInitBuilder = originalBuilder }()

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"init", "--node", "--public-ip", "8.8.8.8", "--json"}, &stdout, &stderr)
	if code != ExitValidation || stderr.Len() != 0 {
		t.Fatalf("Execute() code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "invalid_arguments" || result.Data["changed"] != false {
		t.Fatalf("result = %+v", result)
	}
}

func TestExecuteNodeInitRejectsExistingGatewayBeforeBuilder(t *testing.T) {
	initializer := &recordingNodeInitializer{}
	restore := stubNodeInitCommand(t, initializer, RoleGateway)
	defer restore()
	originalBuilder := nodeInitBuilder
	nodeInitBuilder = func(context.Context, store.Paths) (nodeInitializerAPI, error) {
		t.Fatal("gateway role built node initializer")
		return nil, nil
	}
	defer func() { nodeInitBuilder = originalBuilder }()

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"init", "--node", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitConflict || initializer.planCalls != 0 || initializer.applyCalls != 0 || stderr.Len() != 0 {
		t.Fatalf("Execute() code=%d plan=%d apply=%d stdout=%q stderr=%q", code, initializer.planCalls, initializer.applyCalls, stdout.String(), stderr.String())
	}
}

func TestExecuteRepeatedNodeInitReportsNoChange(t *testing.T) {
	initializer := &recordingNodeInitializer{alreadyInitialized: true}
	restore := stubNodeInitCommand(t, initializer, RoleNode)
	defer restore()

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"init", "--node", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitSuccess || stderr.Len() != 0 || initializer.applyCalls != 1 {
		t.Fatalf("Execute() code/calls = %d/%d stdout=%q stderr=%q", code, initializer.applyCalls, stdout.String(), stderr.String())
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Data["changed"] != false || result.ResourceIDs["host_id"] != nodeCLIHostID {
		t.Fatalf("repeated result = %+v", result)
	}
}

const nodeCLIHostID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

type recordingNodeInitializer struct {
	planCalls          int
	applyCalls         int
	planErr            error
	alreadyInitialized bool
}

func (initializer *recordingNodeInitializer) Plan(context.Context) (lifecycle.NodeInitPlan, error) {
	initializer.planCalls++
	if initializer.planErr != nil {
		return lifecycle.NodeInitPlan{}, initializer.planErr
	}
	if initializer.alreadyInitialized {
		return lifecycle.NodeInitPlan{AlreadyInitialized: true, HostID: nodeCLIHostID, Units: []string{}}, nil
	}
	return lifecycle.NodeInitPlan{
		Changed: true, HostID: nodeCLIHostID,
		Units: []string{"vpnctl-routing-guard.service", "vpnctl-routing.service", "vpnctl-standard.service", "vpnctl-tunnel-client.service"},
	}, nil
}

func (initializer *recordingNodeInitializer) Apply(_ context.Context, plan lifecycle.NodeInitPlan) (lifecycle.NodeInitResult, error) {
	initializer.applyCalls++
	if plan.AlreadyInitialized {
		return lifecycle.NodeInitResult{HostID: plan.HostID, Units: []string{}}, nil
	}
	return lifecycle.NodeInitResult{Changed: true, HostID: plan.HostID, Units: append([]string(nil), plan.Units...)}, nil
}

func stubNodeInitCommand(t *testing.T, initializer nodeInitializerAPI, role HostRole) func() {
	t.Helper()
	originalPaths := nodeInitSystemPaths
	originalRole := nodeInitLoadRole
	originalBuilder := nodeInitBuilder
	paths, _ := store.NewPaths(t.TempDir())
	nodeInitSystemPaths = func() store.Paths { return paths }
	nodeInitLoadRole = func(got store.Paths) (HostRole, error) {
		if !reflect.DeepEqual(got, paths) {
			t.Fatalf("role paths = %+v, want %+v", got, paths)
		}
		return role, nil
	}
	nodeInitBuilder = func(_ context.Context, got store.Paths) (nodeInitializerAPI, error) {
		if !reflect.DeepEqual(got, paths) {
			t.Fatalf("builder paths = %+v, want %+v", got, paths)
		}
		return initializer, nil
	}
	return func() {
		nodeInitSystemPaths = originalPaths
		nodeInitLoadRole = originalRole
		nodeInitBuilder = originalBuilder
	}
}
