package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestExecuteGatewayUninstallPublishesBlockedImpactBeforeForce(t *testing.T) {
	restore := installUninstallCLIFixture(t, RoleGateway)
	defer restore()
	manager := &recordingUninstallManager{plan: cliUninstallPlan(model.RoleGateway, true)}
	uninstallBuilder = func(context.Context, store.Paths, HostRole, lifecycle.UninstallOptions) (uninstallManager, error) {
		return manager, nil
	}

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"--json", "uninstall", "--dry-run"}, &stdout, &stderr)
	if code != ExitConflict || manager.planCalls != 1 || manager.applyCalls != 0 || stderr.Len() != 0 {
		t.Fatalf("blocked uninstall code=%d plan=%d apply=%d stderr=%q", code, manager.planCalls, manager.applyCalls, stderr.String())
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != output.StatusFailed || result.ExitCategory != output.CategoryConflict || len(result.RequiresAction) != 3 || result.Data["force_required"] != true {
		t.Fatalf("blocked uninstall result = %+v", result)
	}

	manager = &recordingUninstallManager{plan: cliUninstallPlan(model.RoleGateway, false), result: cliUninstallResult(model.RoleGateway)}
	uninstallBuilder = func(_ context.Context, _ store.Paths, role HostRole, options lifecycle.UninstallOptions) (uninstallManager, error) {
		if role != RoleGateway || !options.Force || options.LocalOnly {
			t.Fatalf("gateway force builder role/options = %s/%+v", role, options)
		}
		return manager, nil
	}
	stdout.Reset()
	code = Execute([]string{"uninstall", "--force", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitSuccess || manager.applyCalls != 1 {
		t.Fatalf("forced uninstall code=%d apply=%d stdout=%q stderr=%q", code, manager.applyCalls, stdout.String(), stderr.String())
	}
}

func TestExecuteNodeLocalOnlyAppliesAndReturnsMandatoryGatewayAction(t *testing.T) {
	restore := installUninstallCLIFixture(t, RoleNode)
	defer restore()
	plan := cliUninstallPlan(model.RoleNode, false)
	plan.LocalOnly, plan.NodeRevokeRequired = true, true
	result := cliUninstallResult(model.RoleNode)
	result.LocalOnly = true
	manager := &recordingUninstallManager{plan: plan, result: result}
	uninstallBuilder = func(_ context.Context, _ store.Paths, role HostRole, options lifecycle.UninstallOptions) (uninstallManager, error) {
		if role != RoleNode || !options.LocalOnly || options.Force {
			t.Fatalf("node local-only builder role/options = %s/%+v", role, options)
		}
		return manager, nil
	}
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"--json", "uninstall", "--local-only", "--yes"}, &stdout, &stderr)
	if code != ExitSuccess || manager.planCalls != 1 || manager.applyCalls != 1 || stderr.Len() != 0 {
		t.Fatalf("node local-only code=%d plan=%d apply=%d stderr=%q", code, manager.planCalls, manager.applyCalls, stderr.String())
	}
	var document output.Result
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.RequiresAction) != 1 || document.RequiresAction[0].Code != "revoke_node_on_gateway" ||
		document.RequiresAction[0].ResourceIDs["node_id"] != plan.NodeID || document.ResourceIDs["node_id"] != plan.NodeID ||
		document.Data["local_only"] != true {
		t.Fatalf("local-only output = %+v", document)
	}
}

func TestExecuteNodeUninstallMapsUnavailableGatewayWithoutLocalSuccess(t *testing.T) {
	restore := installUninstallCLIFixture(t, RoleNode)
	defer restore()
	plan := cliUninstallPlan(model.RoleNode, false)
	plan.NodeRevokeRequired = true
	manager := &recordingUninstallManager{plan: plan, applyErr: lifecycle.ErrUninstallGatewayUnavailable}
	uninstallBuilder = func(context.Context, store.Paths, HostRole, lifecycle.UninstallOptions) (uninstallManager, error) {
		return manager, nil
	}
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"uninstall", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitUnavailable || manager.applyCalls != 1 || stderr.Len() != 0 {
		t.Fatalf("offline uninstall code=%d apply=%d stderr=%q", code, manager.applyCalls, stderr.String())
	}
	var document output.Result
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Warnings[0].Code != "gateway_revoke_unavailable" || document.Data["changed"] != false {
		t.Fatalf("offline output = %+v", document)
	}
}

func TestExecuteUninstallReportsPartialMutation(t *testing.T) {
	restore := installUninstallCLIFixture(t, RoleNode)
	defer restore()
	result := cliUninstallResult(model.RoleNode)
	result.BinaryRemoved = false
	manager := &recordingUninstallManager{
		plan: cliUninstallPlan(model.RoleNode, false), result: result, applyErr: errors.New("binary removal failed"),
	}
	uninstallBuilder = func(context.Context, store.Paths, HostRole, lifecycle.UninstallOptions) (uninstallManager, error) {
		return manager, nil
	}
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"uninstall", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitInternal || manager.applyCalls != 1 || stderr.Len() != 0 {
		t.Fatalf("partial uninstall code=%d apply=%d stderr=%q", code, manager.applyCalls, stderr.String())
	}
	var document output.Result
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Data["changed"] != true || document.Data["network_restored"] != true || document.Data["binary_removed"] != false ||
		len(document.Warnings) != 1 || document.Warnings[0].Code != "uninstall_internal_error" {
		t.Fatalf("partial uninstall output = %+v", document)
	}
}

func TestUninstallParserRejectsAmbiguousAndExpansiveFlags(t *testing.T) {
	for _, args := range [][]string{
		{"uninstall", "--force", "--local-only"}, {"uninstall", "--defer"},
		{"uninstall", "--include-backups"}, {"uninstall", "extra"}, {"uninstall", "--force", "--force"},
	} {
		if _, err := parseUninstallArguments(args); err == nil {
			t.Fatalf("parseUninstallArguments(%q) succeeded", args)
		}
	}
	if !isUninstallInvocation([]string{"--json", "--force", "uninstall"}) || isUninstallInvocation([]string{"client", "add", "uninstall"}) {
		t.Fatal("uninstall invocation dispatch is ambiguous")
	}
}

func TestUninstallWorkflowRejectsChangedPublicPlanAndAppliesOnce(t *testing.T) {
	manager := &recordingUninstallManager{plan: cliUninstallPlan(model.RoleNode, false), result: cliUninstallResult(model.RoleNode)}
	workflow, _ := NewUninstallWorkflow(manager, lifecycle.UninstallOptions{})
	plan, err := workflow.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	changed := plan
	changed.Impact = ImpactNone
	if _, err := workflow.Apply(context.Background(), changed, nil); err == nil || manager.applyCalls != 0 {
		t.Fatalf("changed public plan apply error=%v calls=%d", err, manager.applyCalls)
	}
	if _, err := workflow.Apply(context.Background(), plan, nil); err != nil || manager.applyCalls != 1 {
		t.Fatalf("valid apply error=%v calls=%d", err, manager.applyCalls)
	}
	if _, err := workflow.Apply(context.Background(), plan, nil); err == nil || manager.applyCalls != 1 {
		t.Fatalf("repeat apply error=%v calls=%d", err, manager.applyCalls)
	}
}

type recordingUninstallManager struct {
	plan       lifecycle.UninstallPlan
	result     lifecycle.UninstallResult
	planErr    error
	applyErr   error
	planCalls  int
	applyCalls int
}

func (manager *recordingUninstallManager) Plan(_ context.Context, _ lifecycle.UninstallOptions) (lifecycle.UninstallPlan, error) {
	manager.planCalls++
	return manager.plan, manager.planErr
}

func (manager *recordingUninstallManager) Apply(_ context.Context, _ lifecycle.UninstallPlan) (lifecycle.UninstallResult, error) {
	manager.applyCalls++
	return manager.result, manager.applyErr
}

func cliUninstallPlan(role model.Role, blocked bool) lifecycle.UninstallPlan {
	plan := lifecycle.UninstallPlan{
		Role: role, Changed: true, Blocked: blocked, ForceRequired: blocked, ExpectedStateGeneration: 7,
		AffectedServices: []string{"vpnctl-standard.service"}, Preserved: []string{"/var/lib/vpnctl/state.json"},
	}
	if role == model.RoleNode {
		plan.NodeID = "99000000-0000-4000-8000-000000000004"
	}
	if role == model.RoleGateway {
		plan.ActiveNodeIDs = []string{"99000000-0000-4000-8000-000000000001"}
		plan.ActiveClientIDs = []string{"99000000-0000-4000-8000-000000000002"}
		plan.ActiveExposeIDs = []string{"99000000-0000-4000-8000-000000000003"}
	}
	return plan
}

func cliUninstallResult(role model.Role) lifecycle.UninstallResult {
	result := lifecycle.UninstallResult{
		Role: role, Changed: true, StateGeneration: 8, DNSRestored: role == model.RoleNode,
		NetworkRestored: true, ManagedSwapDisabled: true, BinaryRemoved: true,
		AffectedServices: []string{"vpnctl-standard.service"}, Preserved: []string{"/var/lib/vpnctl/state.json"},
	}
	if role == model.RoleNode {
		result.NodeID = "99000000-0000-4000-8000-000000000004"
	}
	return result
}

func installUninstallCLIFixture(t *testing.T, role HostRole) func() {
	t.Helper()
	oldPaths, oldRole, oldBuilder, oldTTY := uninstallSystemPaths, uninstallLoadRole, uninstallBuilder, uninstallOpenTTY
	paths, _ := store.NewPaths(t.TempDir())
	uninstallSystemPaths = func() store.Paths { return paths }
	uninstallLoadRole = func(store.Paths) (HostRole, error) { return role, nil }
	uninstallOpenTTY = func() (PromptIO, io.Closer, error) { return nil, nil, errors.New("unexpected TTY") }
	return func() {
		uninstallSystemPaths, uninstallLoadRole, uninstallBuilder, uninstallOpenTTY = oldPaths, oldRole, oldBuilder, oldTTY
	}
}
