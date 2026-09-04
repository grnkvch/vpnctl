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

func TestExecuteGatewayPurgeShowsBlockedImpactThenRequiresBothTypedPhrases(t *testing.T) {
	restore := installPurgeCLIFixture(t, RoleGateway)
	defer restore()
	manager := &recordingPurgeManager{plan: cliPurgePlan(model.RoleGateway, true)}
	purgeBuilder = func(context.Context, store.Paths, HostRole, lifecycle.PurgeOptions) (purgeManager, error) {
		return manager, nil
	}
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"--json", "purge", "--dry-run"}, &stdout, &stderr)
	if code != ExitConflict || manager.planCalls != 1 || manager.applyCalls != 0 || stderr.Len() != 0 {
		t.Fatalf("blocked purge code=%d plan=%d apply=%d stderr=%q", code, manager.planCalls, manager.applyCalls, stderr.String())
	}
	var blocked output.Result
	if err := json.Unmarshal(stdout.Bytes(), &blocked); err != nil || blocked.Data["force_required"] != true || blocked.Status != output.StatusFailed {
		t.Fatalf("blocked purge output = %+v, %v", blocked, err)
	}

	terminal := &purgePromptTerminal{answers: []string{"purge gateway", "delete backups"}}
	purgeOpenTTY = func() (PromptIO, io.Closer, error) { return terminal, io.NopCloser(bytes.NewReader(nil)), nil }
	manager = &recordingPurgeManager{plan: cliPurgePlan(model.RoleGateway, false), result: cliPurgeResult(model.RoleGateway)}
	manager.plan.IncludeBackups = true
	manager.plan.Preserved = []string{}
	manager.result.IncludeBackups = true
	manager.result.BackupsRemoved = true
	manager.result.Preserved = []string{}
	purgeBuilder = func(_ context.Context, _ store.Paths, role HostRole, options lifecycle.PurgeOptions) (purgeManager, error) {
		if role != RoleGateway || !options.Force || !options.IncludeBackups || options.LocalOnly {
			t.Fatalf("gateway purge builder role/options = %s/%+v", role, options)
		}
		return manager, nil
	}
	stdout.Reset()
	code = Execute([]string{"purge", "--force", "--include-backups", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitSuccess || manager.applyCalls != 1 || terminal.index != 2 {
		t.Fatalf("purge code=%d apply=%d reads=%d stdout=%q stderr=%q", code, manager.applyCalls, terminal.index, stdout.String(), stderr.String())
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Data["backups_removed"] != true || len(result.Warnings) != 1 || result.Warnings[0].Code != "managed_recovery_erased" {
		t.Fatalf("full purge output = %+v, %v", result, err)
	}
}

func TestExecutePurgeYesCannotBypassTypedConsent(t *testing.T) {
	restore := installPurgeCLIFixture(t, RoleNode)
	defer restore()
	manager := &recordingPurgeManager{plan: cliPurgePlan(model.RoleNode, false), result: cliPurgeResult(model.RoleNode)}
	purgeBuilder = func(context.Context, store.Paths, HostRole, lifecycle.PurgeOptions) (purgeManager, error) {
		return manager, nil
	}
	purgeOpenTTY = func() (PromptIO, io.Closer, error) { return nil, nil, errors.New("no tty") }
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"purge", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitValidation || manager.planCalls != 1 || manager.applyCalls != 0 {
		t.Fatalf("non-interactive purge code=%d plan=%d apply=%d", code, manager.planCalls, manager.applyCalls)
	}
}

func TestExecuteNodeLocalOnlyPurgeReturnsMandatoryGatewayRevoke(t *testing.T) {
	restore := installPurgeCLIFixture(t, RoleNode)
	defer restore()
	terminal := &purgePromptTerminal{answers: []string{"purge node"}}
	purgeOpenTTY = func() (PromptIO, io.Closer, error) { return terminal, io.NopCloser(bytes.NewReader(nil)), nil }
	plan := cliPurgePlan(model.RoleNode, false)
	plan.LocalOnly, plan.NodeRevokeRequired = true, true
	result := cliPurgeResult(model.RoleNode)
	result.LocalOnly = true
	manager := &recordingPurgeManager{plan: plan, result: result}
	purgeBuilder = func(_ context.Context, _ store.Paths, role HostRole, options lifecycle.PurgeOptions) (purgeManager, error) {
		if role != RoleNode || !options.LocalOnly || options.IncludeBackups {
			t.Fatalf("node purge builder role/options = %s/%+v", role, options)
		}
		return manager, nil
	}
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"--json", "purge", "--local-only"}, &stdout, &stderr)
	if code != ExitSuccess || manager.applyCalls != 1 || terminal.index != 1 {
		t.Fatalf("local-only purge code=%d apply=%d reads=%d", code, manager.applyCalls, terminal.index)
	}
	var document output.Result
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil || len(document.RequiresAction) != 1 ||
		document.RequiresAction[0].Code != "revoke_node_on_gateway" || document.RequiresAction[0].ResourceIDs["node_id"] != plan.NodeID {
		t.Fatalf("local-only purge output = %+v, %v", document, err)
	}
}

func TestExecutePurgeReportsPartialMutationWithoutRecoveryPromise(t *testing.T) {
	restore := installPurgeCLIFixture(t, RoleNode)
	defer restore()
	purgeOpenTTY = func() (PromptIO, io.Closer, error) {
		return &purgePromptTerminal{answers: []string{"purge node"}}, io.NopCloser(bytes.NewReader(nil)), nil
	}
	result := cliPurgeResult(model.RoleNode)
	result.BinaryRemoved = false
	manager := &recordingPurgeManager{
		plan: cliPurgePlan(model.RoleNode, false), result: result, applyErr: errors.New("binary removal failed"),
	}
	purgeBuilder = func(context.Context, store.Paths, HostRole, lifecycle.PurgeOptions) (purgeManager, error) {
		return manager, nil
	}
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"purge", "--json"}, &stdout, &stderr)
	if code != ExitInternal || manager.applyCalls != 1 || stderr.Len() != 0 {
		t.Fatalf("partial purge code=%d apply=%d stderr=%q", code, manager.applyCalls, stderr.String())
	}
	var document output.Result
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Data["changed"] != true || document.Data["data_purged"] != true || document.Data["binary_removed"] != false ||
		len(document.Warnings) != 1 || document.Warnings[0].Code != "purge_internal_error" {
		t.Fatalf("partial purge output = %+v", document)
	}
}

func TestExecuteNodePurgeRejectsIncludeBackupsBeforeBuilder(t *testing.T) {
	restore := installPurgeCLIFixture(t, RoleNode)
	defer restore()
	called := false
	purgeBuilder = func(context.Context, store.Paths, HostRole, lifecycle.PurgeOptions) (purgeManager, error) {
		called = true
		return nil, errors.New("unexpected builder")
	}
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"purge", "--include-backups", "--json"}, &stdout, &stderr)
	if code != ExitValidation || called || stderr.Len() != 0 {
		t.Fatalf("node backup purge code=%d builder=%t stderr=%q", code, called, stderr.String())
	}
}

func TestPurgeParserAndWorkflowRejectAmbiguousOrChangedInput(t *testing.T) {
	for _, args := range [][]string{
		{"purge", "--force", "--local-only"}, {"purge", "--defer"}, {"purge", "extra"},
		{"purge", "--include-backups", "--include-backups"},
	} {
		if _, err := parsePurgeArguments(args); err == nil {
			t.Fatalf("parsePurgeArguments(%q) succeeded", args)
		}
	}
	if !isPurgeInvocation([]string{"--json", "--force", "purge"}) || isPurgeInvocation([]string{"client", "add", "purge"}) {
		t.Fatal("purge invocation dispatch is ambiguous")
	}
	manager := &recordingPurgeManager{plan: cliPurgePlan(model.RoleNode, false), result: cliPurgeResult(model.RoleNode)}
	workflow, _ := NewPurgeWorkflow(manager, lifecycle.PurgeOptions{})
	plan, err := workflow.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	changed := plan
	changed.Impact = ImpactNone
	if _, err := workflow.Apply(context.Background(), changed, nil); err == nil || manager.applyCalls != 0 {
		t.Fatalf("changed purge plan error=%v calls=%d", err, manager.applyCalls)
	}
	if _, err := workflow.Apply(context.Background(), plan, nil); err != nil || manager.applyCalls != 1 {
		t.Fatalf("valid purge apply error=%v calls=%d", err, manager.applyCalls)
	}
}

type recordingPurgeManager struct {
	plan       lifecycle.PurgePlan
	result     lifecycle.PurgeResult
	planErr    error
	applyErr   error
	planCalls  int
	applyCalls int
}

func (manager *recordingPurgeManager) Plan(_ context.Context, _ lifecycle.PurgeOptions) (lifecycle.PurgePlan, error) {
	manager.planCalls++
	return manager.plan, manager.planErr
}

func (manager *recordingPurgeManager) Apply(_ context.Context, _ lifecycle.PurgePlan) (lifecycle.PurgeResult, error) {
	manager.applyCalls++
	return manager.result, manager.applyErr
}

func cliPurgePlan(role model.Role, blocked bool) lifecycle.PurgePlan {
	plan := lifecycle.PurgePlan{
		Role: role, Changed: true, Blocked: blocked, ForceRequired: blocked, ExpectedStateGeneration: 7,
		BackupArchives: 1, AffectedServices: []string{"vpnctl-standard.service"},
		Removed: []string{"/etc/vpnctl"}, Preserved: []string{"/var/lib/vpnctl/backups"},
	}
	if role == model.RoleNode {
		plan.NodeID = "99000000-0000-4000-8000-000000000004"
	} else {
		plan.ActiveNodeIDs = []string{"99000000-0000-4000-8000-000000000001"}
		plan.ActiveClientIDs = []string{"99000000-0000-4000-8000-000000000002"}
		plan.ActiveExposeIDs = []string{"99000000-0000-4000-8000-000000000003"}
	}
	return plan
}

func cliPurgeResult(role model.Role) lifecycle.PurgeResult {
	result := lifecycle.PurgeResult{
		Role: role, SourceStateGeneration: 7, Changed: true, BackupArchives: 1,
		DNSRestored: role == model.RoleNode, NetworkRestored: true, ManagedSwapPurged: true,
		DataPurged: true, BinaryRemoved: true, AffectedServices: []string{"vpnctl-standard.service"},
		Removed: []string{"/etc/vpnctl"}, Preserved: []string{"/var/lib/vpnctl/backups"},
	}
	if role == model.RoleNode {
		result.NodeID = "99000000-0000-4000-8000-000000000004"
	}
	return result
}

type purgePromptTerminal struct {
	answers []string
	steps   []InteractionStep
	index   int
}

func (terminal *purgePromptTerminal) ReadVisible(step InteractionStep) (string, error) {
	terminal.steps = append(terminal.steps, step)
	if terminal.index >= len(terminal.answers) {
		return "", errors.New("no scripted answer")
	}
	answer := terminal.answers[terminal.index]
	terminal.index++
	return answer, nil
}

func (*purgePromptTerminal) ReadHidden(InteractionStep, int) ([]byte, error) {
	return nil, errors.New("unexpected hidden input")
}

func (*purgePromptTerminal) WriteSecret(InteractionStep, []byte) error {
	return errors.New("unexpected secret output")
}

func installPurgeCLIFixture(t *testing.T, role HostRole) func() {
	t.Helper()
	oldPaths, oldRole, oldBuilder, oldTTY := purgeSystemPaths, purgeLoadRole, purgeBuilder, purgeOpenTTY
	paths, _ := store.NewPaths(t.TempDir())
	purgeSystemPaths = func() store.Paths { return paths }
	purgeLoadRole = func(store.Paths) (HostRole, error) { return role, nil }
	purgeOpenTTY = func() (PromptIO, io.Closer, error) { return nil, nil, errors.New("unexpected TTY") }
	return func() {
		purgeSystemPaths, purgeLoadRole, purgeBuilder, purgeOpenTTY = oldPaths, oldRole, oldBuilder, oldTTY
	}
}
