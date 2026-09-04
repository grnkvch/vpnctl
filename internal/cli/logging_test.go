package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestLoggingGrammarRequiresExplicitBoundedOptions(t *testing.T) {
	tests := []struct {
		args      []string
		action    string
		scope     model.LogScope
		level     model.LogLevel
		duration  time.Duration
		file      bool
		dryRun    bool
		jsonMode  bool
		wantError bool
	}{
		{args: []string{"log", "status"}, action: "status"},
		{args: []string{"--json", "log", "enable", "ingress", "--level", "trace", "--for", "10m", "--file", "--dry-run"}, action: "enable", scope: model.LogIngress, level: model.LogTrace, duration: 10 * time.Minute, file: true, dryRun: true, jsonMode: true},
		{args: []string{"log", "disable", "all", "--json"}, action: "disable", scope: model.LogAll, jsonMode: true},
		{args: []string{"log", "enable", "dns", "--for", "10m"}, wantError: true},
		{args: []string{"log", "enable", "dns", "--level", "debug"}, wantError: true},
		{args: []string{"log", "enable", "dns", "--level", "debug", "--for", "1h1s"}, wantError: true},
		{args: []string{"log", "enable", "unknown", "--level", "debug", "--for", "1m"}, wantError: true},
		{args: []string{"log", "status", "--dry-run"}, wantError: true},
		{args: []string{"log", "disable", "dns", "--file"}, wantError: true},
	}
	for _, test := range tests {
		parsed, err := parseLoggingArguments(test.args)
		if (err != nil) != test.wantError {
			t.Fatalf("parseLoggingArguments(%v) error = %v", test.args, err)
		}
		if err == nil && (parsed.Action != test.action || parsed.Scope != test.scope || parsed.Level != test.level ||
			parsed.Duration != test.duration || parsed.File != test.file || parsed.DryRun != test.dryRun || parsed.JSON != test.jsonMode) {
			t.Fatalf("parseLoggingArguments(%v) = %+v", test.args, parsed)
		}
	}
}

func TestExecuteNodeLoggingEnableStatusDisableAndDefaultOff(t *testing.T) {
	paths, _ := store.NewPaths(t.TempDir())
	now := time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC)
	stateStore := &cliDNSStore{state: cliDNSState(model.RoleNode)}
	restore := stubLoggingCommand(t, paths, RoleNode, stateStore, now)
	defer restore()
	loggingCallGateway = func(context.Context, string, control.LocalRequest) (control.LocalResponse, error) {
		t.Fatal("node logging command contacted gateway controller")
		return control.LocalResponse{}, errors.New("unexpected")
	}

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"log", "status", "--json"}, &stdout, &stderr); code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("default status code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if values, ok := result.Data["log_opt_ins"].([]any); !ok || len(values) != 0 || stateStore.saves != 0 {
		t.Fatalf("default log status = %+v saves=%d", result, stateStore.saves)
	}

	stdout.Reset()
	if code := Execute([]string{"log", "enable", "ingress", "--level", "trace", "--for", "10m", "--file", "--json"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("enable code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stateStore.saves != 1 || len(stateStore.state.Logging) != 1 || stateStore.state.Logging[0].Destination != model.LogToFile ||
		stateStore.state.Logging[0].FilePath != filepath.Join(paths.Root, "var", "log", "vpnctl", "ingress.log") {
		t.Fatalf("persisted node logging = %+v saves=%d", stateStore.state.Logging, stateStore.saves)
	}
	if strings.Contains(stdout.String(), stateStore.state.Logging[0].FilePath) || !strings.Contains(stdout.String(), `"remaining_seconds":600`) {
		t.Fatalf("enable output leaked/missed fields: %s", stdout.String())
	}

	stdout.Reset()
	if code := Execute([]string{"log", "status", "--json"}, &stdout, &stderr); code != ExitSuccess || !strings.Contains(stdout.String(), `"scope":"ingress"`) || !strings.Contains(stdout.String(), `"remaining_seconds":600`) {
		t.Fatalf("active status code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "file_path") {
		t.Fatalf("log status exposed file path: %s", stdout.String())
	}

	stdout.Reset()
	if code := Execute([]string{"log", "disable", "ingress", "--json"}, &stdout, &stderr); code != ExitSuccess || stateStore.saves != 2 || stateStore.state.Logging[0].State != model.LogDisabled {
		t.Fatalf("disable code=%d stdout=%q stderr=%q state=%+v", code, stdout.String(), stderr.String(), stateStore.state.Logging)
	}
}

func TestExecuteLoggingDryRunIsReadOnlyAndGatewayMutationUsesController(t *testing.T) {
	paths, _ := store.NewPaths(t.TempDir())
	now := time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC)
	stateStore := &cliDNSStore{state: cliDNSState(model.RoleGateway)}
	restore := stubLoggingCommand(t, paths, RoleGateway, stateStore, now)
	defer restore()
	calls := 0
	loggingCallGateway = func(_ context.Context, socket string, request control.LocalRequest) (control.LocalResponse, error) {
		calls++
		if socket != paths.ControlSocket || request.Operation != "log.enable" || request.Method != control.LocalMutate || request.ExpectedGeneration != 4 {
			t.Fatalf("gateway request = %+v socket=%s", request, socket)
		}
		var payload struct {
			Scope           model.LogScope `json:"scope"`
			Level           model.LogLevel `json:"level"`
			DurationSeconds int64          `json:"duration_seconds"`
			File            bool           `json:"file"`
		}
		if err := json.Unmarshal(request.Payload, &payload); err != nil || payload.Scope != model.LogDNS || payload.Level != model.LogInfo || payload.DurationSeconds != 300 || payload.File {
			t.Fatalf("gateway payload = %+v, %v", payload, err)
		}
		change := operations.LoggingChange{
			Role: model.RoleGateway, Changed: true, Generation: 5, DisabledIDs: []string{}, ExpiredIDs: []string{},
			Enabled: &operations.LoggingOptIn{
				ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Scope: model.LogDNS, Level: model.LogInfo,
				Destination: model.LogToJournald, StartedAt: now, ExpiresAt: now.Add(5 * time.Minute), RemainingSeconds: 300,
			},
		}
		data, _ := json.Marshal(change)
		return control.LocalResponse{SchemaVersion: control.LocalSchemaVersion, OK: true, Generation: 5, Data: data}, nil
	}

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"log", "enable", "dns", "--level", "info", "--for", "5m", "--dry-run", "--json"}, &stdout, &stderr); code != ExitSuccess || calls != 0 || stateStore.saves != 0 {
		t.Fatalf("gateway dry-run code=%d calls=%d saves=%d stdout=%q stderr=%q", code, calls, stateStore.saves, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := Execute([]string{"log", "enable", "dns", "--level", "info", "--for", "5m", "--json"}, &stdout, &stderr); code != ExitSuccess || calls != 1 || stateStore.saves != 0 {
		t.Fatalf("gateway enable code=%d calls=%d saves=%d stdout=%q stderr=%q", code, calls, stateStore.saves, stdout.String(), stderr.String())
	}
}

func TestLogStatusOmitsExpiredSessionsWithoutMutatingState(t *testing.T) {
	paths, _ := store.NewPaths(t.TempDir())
	now := time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC)
	state := cliDNSState(model.RoleNode)
	state.Logging = []model.LoggingSession{{
		SchemaVersion: model.ResourceSchemaVersion, ID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		Scope: model.LogRouting, Level: model.LogDebug, Destination: model.LogToJournald, State: model.LogActive,
		StartedAt: now.Add(-20 * time.Minute), ExpiresAt: now.Add(-5 * time.Minute),
	}}
	stateStore := &cliDNSStore{state: state}
	restore := stubLoggingCommand(t, paths, RoleNode, stateStore, now)
	defer restore()
	before := stateStore.state
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"log", "status", "--json"}, &stdout, &stderr); code != ExitSuccess || !strings.Contains(stdout.String(), `"log_opt_ins":[]`) {
		t.Fatalf("expired status code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stateStore.saves != 0 || !reflect.DeepEqual(stateStore.state, before) {
		t.Fatal("log status mutated expired authoritative state")
	}
}

func stubLoggingCommand(t *testing.T, paths store.Paths, role HostRole, stateSource loggingStateStore, now time.Time) func() {
	t.Helper()
	oldPaths, oldRole, oldStore := loggingSystemPaths, loggingLoadRole, loggingNewStore
	oldCall, oldNow, oldUUID := loggingCallGateway, loggingNow, loggingNewUUID
	loggingSystemPaths = func() store.Paths { return paths }
	loggingLoadRole = func(store.Paths) (HostRole, error) { return role, nil }
	loggingNewStore = func(store.Paths) (loggingStateStore, error) { return stateSource, nil }
	loggingNow = func() time.Time { return now }
	loggingNewUUID = func() (string, error) { return "dddddddd-dddd-4ddd-8ddd-dddddddddddd", nil }
	return func() {
		loggingSystemPaths, loggingLoadRole, loggingNewStore = oldPaths, oldRole, oldStore
		loggingCallGateway, loggingNow, loggingNewUUID = oldCall, oldNow, oldUUID
	}
}
