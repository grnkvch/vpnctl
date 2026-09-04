package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestExecuteUpdateSupportsExplicitAndLatestStableOnlyOnInvocation(t *testing.T) {
	oldPaths, oldRole, oldBuilder, oldTTY := updateSystemPaths, updateLoadRole, updateBuilder, updateOpenTTY
	t.Cleanup(func() {
		updateSystemPaths, updateLoadRole, updateBuilder, updateOpenTTY = oldPaths, oldRole, oldBuilder, oldTTY
	})
	paths, _ := store.NewPaths(t.TempDir())
	updateSystemPaths = func() store.Paths { return paths }
	updateLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	manager := &recordingUpdateManager{plan: cliUpdatePlan(false)}
	updateBuilder = func(context.Context, store.Paths, HostRole) (updateManager, error) { return manager, nil }

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"update", "2.1.0", "--dry-run", "--json"}, &stdout, &stderr)
	if code != ExitSuccess || manager.planCalls != 1 || manager.requested != "v2.1.0" || manager.applyCalls != 0 || manager.discardCalls != 1 {
		t.Fatalf("explicit dry-run code=%d plan=%d requested=%q apply=%d discard=%d stderr=%q", code, manager.planCalls, manager.requested, manager.applyCalls, manager.discardCalls, stderr.String())
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	data := document["data"].(map[string]any)
	if data["current_version"] != "v2.0.0" || data["target_version"] != "v2.1.0" || data["latest_stable"] != false {
		t.Fatalf("explicit update output = %+v", data)
	}

	manager = &recordingUpdateManager{plan: cliUpdatePlan(false)}
	updateBuilder = func(context.Context, store.Paths, HostRole) (updateManager, error) { return manager, nil }
	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"--json", "update", "--yes"}, &stdout, &stderr)
	if code != ExitSuccess || manager.requested != "" || manager.planCalls != 1 || manager.applyCalls != 1 || manager.discardCalls != 0 {
		t.Fatalf("latest apply code=%d requested=%q plan=%d apply=%d discard=%d stderr=%q", code, manager.requested, manager.planCalls, manager.applyCalls, manager.discardCalls, stderr.String())
	}
}

func TestBlockedUpdateReturnsPlanWithoutConsentOrMutation(t *testing.T) {
	manager := &recordingUpdateManager{plan: cliUpdatePlan(true)}
	workflow, _ := NewUpdateWorkflow(manager, "v2.1.0")
	terminal := &recordingUpdateTerminal{}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "update", Role: RoleGateway,
	}, terminal, workflow, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer workflow.Discard()
	if outcome.Result.Status != output.StatusFailed || outcome.Result.ExitCategory != output.CategoryConflict ||
		manager.applyCalls != 0 || terminal.reads != 0 || len(outcome.Result.RequiresAction) != 1 {
		t.Fatalf("blocked outcome=%+v apply=%d terminal reads=%d", outcome, manager.applyCalls, terminal.reads)
	}
}

func TestUpdatePlanHumanOutputIncludesFleetAndMigrationEvidence(t *testing.T) {
	plan := cliUpdatePlan(false)
	plan.Fleet.SelectedProtocol = "2.1"
	plan.Fleet.GatewayVersion = "v2.1.0"
	plan.Fleet.Nodes = []lifecycle.UpdateFleetNode{{
		ID: "90000000-0000-4000-8000-000000000011", Name: "private-api", ControlProtocol: "2.0", Compatible: true,
	}}
	plan.Migration.Steps = []string{"state schema remains unchanged"}
	result, err := updatePlanOutput(plan)
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := output.RenderHuman(&rendered, result); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"fleet summary:", "selected protocol=2.1", "gateway version=v2.1.0",
		"fleet:", "name=private-api", "protocol=2.0",
		"migration:", "from schema=1", "to schema=1", "reversible=true", "steps=state schema remains unchanged",
	} {
		if !bytes.Contains(rendered.Bytes(), []byte(expected)) {
			t.Fatalf("human update plan missing %q:\n%s", expected, rendered.String())
		}
	}
}

func TestUpdateParserRejectsDeferredAndNonStableChannels(t *testing.T) {
	for _, args := range [][]string{
		{"update", "--defer"}, {"update", "v2.1.0-beta"}, {"update", "2.01.0"}, {"update", "v2.1"},
	} {
		if _, err := parseUpdateArguments(args); err == nil {
			t.Fatalf("parseUpdateArguments(%q) succeeded", args)
		}
	}
	parsed, err := parseUpdateArguments([]string{"update", "2.1.0", "--yes", "--json"})
	if err != nil || parsed.Version != "v2.1.0" || !parsed.Yes || !parsed.JSON || parsed.Rollback {
		t.Fatalf("canonical parsed update = %+v, %v", parsed, err)
	}
}

func TestUnrelatedCLICommandsNeverConstructOrCheckUpdateSource(t *testing.T) {
	oldBuilder := updateBuilder
	t.Cleanup(func() { updateBuilder = oldBuilder })
	builds := 0
	updateBuilder = func(context.Context, store.Paths, HostRole) (updateManager, error) {
		builds++
		return nil, nil
	}
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"version"}, &stdout, &stderr); code != ExitSuccess || builds != 0 {
		t.Fatalf("version code=%d update builds=%d", code, builds)
	}
}

type recordingUpdateManager struct {
	plan         lifecycle.UpdatePlan
	requested    string
	planCalls    int
	applyCalls   int
	discardCalls int
}

func (manager *recordingUpdateManager) Plan(_ context.Context, requested string) (lifecycle.UpdatePlan, error) {
	manager.planCalls++
	manager.requested = requested
	plan := manager.plan
	plan.RequestedVersion = requested
	plan.LatestStable = requested == ""
	return plan, nil
}

func (manager *recordingUpdateManager) Apply(_ context.Context, plan lifecycle.UpdatePlan) (lifecycle.UpdateResult, error) {
	manager.applyCalls++
	if !reflect.DeepEqual(plan, manager.planWithRequest()) {
		return lifecycle.UpdateResult{}, io.ErrUnexpectedEOF
	}
	return lifecycle.UpdateResult{
		OperationID: plan.OperationID, Role: plan.Role, PreviousVersion: plan.CurrentVersion, CurrentVersion: plan.TargetVersion,
		Generation: 4, Changed: true, ComponentResults: []lifecycle.UpdateComponentResult{{Name: "vpnctl", Changed: true, Healthy: true}},
		ExpectedInterruptions: append([]string{}, plan.ExpectedInterruptions...),
		RequiresAction:        []string{},
	}, nil
}

func (manager *recordingUpdateManager) Discard(lifecycle.UpdatePlan) error {
	manager.discardCalls++
	return nil
}

func (manager *recordingUpdateManager) planWithRequest() lifecycle.UpdatePlan {
	plan := manager.plan
	plan.RequestedVersion = manager.requested
	plan.LatestStable = manager.requested == ""
	return plan
}

func cliUpdatePlan(blocked bool) lifecycle.UpdatePlan {
	actions := []string{}
	if blocked {
		actions = append(actions, "update the incompatible active node first")
	}
	return lifecycle.UpdatePlan{
		OperationID: "90000000-0000-4000-8000-000000000010", Role: model.RoleGateway,
		CurrentVersion: "v2.0.0", TargetVersion: "v2.1.0", ExpectedStateGeneration: 1, Changed: true, Blocked: blocked,
		Components: []lifecycle.UpdateComponentChange{{
			Name: "vpnctl", CurrentVersion: "v2.0.0", TargetVersion: "v2.1.0", Bundled: true, Changed: true, FileChanged: true,
			AffectedServices: []string{"vpnctl-controller.service"},
		}},
		Packages: []lifecycle.UpdatePackageCheck{},
		Fleet: lifecycle.UpdateFleetCompatibility{
			Role: model.RoleGateway, Compatible: !blocked, Nodes: []lifecycle.UpdateFleetNode{}, RequiresAction: append([]string{}, actions...),
		},
		Migration:             lifecycle.UpdateStateMigration{FromSchema: 1, ToSchema: 1, Steps: []string{}, Reversible: true},
		ExpectedInterruptions: []string{"active transport may reconnect"}, RollbackAvailable: true, RequiresAction: actions,
	}
}

type recordingUpdateTerminal struct{ reads int }

func (terminal *recordingUpdateTerminal) ReadVisible(InteractionStep) (string, error) {
	terminal.reads++
	return "yes", nil
}

func (terminal *recordingUpdateTerminal) ReadHidden(InteractionStep, int) ([]byte, error) {
	terminal.reads++
	return nil, io.ErrUnexpectedEOF
}

func (terminal *recordingUpdateTerminal) WriteSecret(InteractionStep, []byte) error {
	terminal.reads++
	return nil
}
