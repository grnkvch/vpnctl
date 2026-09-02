package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestExecuteConfirmEmitsPublicResultAndUsesSSHConnection(t *testing.T) {
	paths, _ := store.NewPaths(t.TempDir())
	wantID := "fw-7K3M2P"
	wantSSH := "192.0.2.20 55001 203.0.113.10 22"
	var calls []string
	restore := stubConfirmCommand(t, paths, RoleGateway, wantSSH, func(_ context.Context, gotPaths store.Paths, id, rawSSH string) (operations.WatchdogConfirmation, error) {
		if !reflect.DeepEqual(gotPaths, paths) {
			t.Fatalf("paths = %+v, want %+v", gotPaths, paths)
		}
		calls = append(calls, id+"\x00"+rawSSH)
		return operations.WatchdogConfirmation{TransactionID: id, CommittedAt: time.Now(), TimerStopped: true}, nil
	})
	defer restore()

	for _, test := range []struct {
		name string
		args []string
		json bool
	}{
		{name: "human", args: []string{"confirm", wantID}},
		{name: "json after", args: []string{"confirm", wantID, "--json"}, json: true},
		{name: "global json before", args: []string{"--json", "confirm", wantID}, json: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Execute(test.args, &stdout, &stderr); code != ExitSuccess {
				t.Fatalf("Execute() code = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
			if test.json {
				var result output.Result
				if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
					t.Fatalf("JSON result: %v: %q", err, stdout.String())
				}
				if result.Command != "confirm" || result.Status != output.StatusOK || result.ResourceIDs["transaction_id"] != wantID || result.Data["changed"] != true {
					t.Fatalf("result = %+v", result)
				}
			} else if !strings.Contains(stdout.String(), "OK confirm\n") || !strings.Contains(stdout.String(), "transaction id: "+wantID) || !strings.Contains(stdout.String(), "changed: true") {
				t.Fatalf("human result = %q", stdout.String())
			}
		})
	}
	if !reflect.DeepEqual(calls, []string{wantID + "\x00" + wantSSH, wantID + "\x00" + wantSSH, wantID + "\x00" + wantSSH}) {
		t.Fatalf("confirm calls = %q", calls)
	}
}

func TestExecuteConfirmRoleGatePrecedesWatchdogMutation(t *testing.T) {
	paths, _ := store.NewPaths(t.TempDir())
	called := false
	restore := stubConfirmCommand(t, paths, RoleNode, "", func(context.Context, store.Paths, string, string) (operations.WatchdogConfirmation, error) {
		called = true
		return operations.WatchdogConfirmation{}, nil
	})
	defer restore()

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"confirm", "fw-7K3M2P", "--json"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("Execute() code = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if called {
		t.Fatal("unsupported node role invoked watchdog confirmation")
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ExitCategory != output.CategoryValidation || len(result.Warnings) != 1 || result.Warnings[0].Code != "unsupported_role" {
		t.Fatalf("result = %+v", result)
	}
}

func TestExecuteConfirmMapsProofReusePortAndExpiryFailures(t *testing.T) {
	paths, _ := store.NewPaths(t.TempDir())
	tests := []struct {
		name     string
		err      error
		wantCode int
		warning  string
	}{
		{name: "original", err: operations.ErrWatchdogOriginalSession, wantCode: ExitValidation, warning: "new_ssh_session_required"},
		{name: "reused", err: operations.ErrWatchdogAlreadyCommitted, wantCode: ExitConflict, warning: "transaction_id_used"},
		{name: "wrong port", err: operations.ErrWatchdogWrongSSHPort, wantCode: ExitValidation, warning: "ssh_port_mismatch"},
		{name: "expired", err: operations.ErrWatchdogExpired, wantCode: ExitConflict, warning: "transaction_expired"},
		{name: "forged env", err: operations.ErrWatchdogConfirmationProof, wantCode: ExitValidation, warning: "ssh_session_unverified"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			restore := stubConfirmCommand(t, paths, RoleGateway, "connection", func(context.Context, store.Paths, string, string) (operations.WatchdogConfirmation, error) {
				return operations.WatchdogConfirmation{}, test.err
			})
			defer restore()
			var stdout, stderr bytes.Buffer
			code := Execute([]string{"confirm", "fw-7K3M2P", "--json"}, &stdout, &stderr)
			if code != test.wantCode || stderr.Len() != 0 {
				t.Fatalf("Execute() code=%d stderr=%q", code, stderr.String())
			}
			var result output.Result
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Warnings[0].Code != test.warning || result.Data["changed"] != false {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestExecuteConfirmRejectsInvalidIDBeforeRoleOrState(t *testing.T) {
	originalPaths := confirmSystemPaths
	originalRole := loadConfirmRole
	defer func() { confirmSystemPaths, loadConfirmRole = originalPaths, originalRole }()
	confirmSystemPaths = func() store.Paths { t.Fatal("invalid arguments resolved system paths"); return store.Paths{} }
	loadConfirmRole = func(store.Paths) (HostRole, error) { t.Fatal("invalid arguments loaded role"); return "", nil }

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"confirm", "not-an-id", "--json"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("Execute() code = %d", code)
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.ResourceIDs) != 0 || result.Warnings[0].Code != "invalid_arguments" {
		t.Fatalf("result = %+v", result)
	}
}

func TestExecuteConfirmReportsCommittedTimerStopFailureAsDegraded(t *testing.T) {
	paths, _ := store.NewPaths(t.TempDir())
	restore := stubConfirmCommand(t, paths, RoleGateway, "connection", func(context.Context, store.Paths, string, string) (operations.WatchdogConfirmation, error) {
		return operations.WatchdogConfirmation{TransactionID: "fw-7K3M2P", CommittedAt: time.Now()}, errors.New("systemctl unavailable")
	})
	defer restore()

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"confirm", "fw-7K3M2P", "--json"}, &stdout, &stderr); code != ExitUnavailable {
		t.Fatalf("Execute() code = %d", code)
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != output.StatusDegraded || result.Data["changed"] != true || result.Warnings[0].Code != "watchdog_timer_stop_failed" {
		t.Fatalf("result = %+v", result)
	}
}

func stubConfirmCommand(t *testing.T, paths store.Paths, role HostRole, sshConnection string, runner func(context.Context, store.Paths, string, string) (operations.WatchdogConfirmation, error)) func() {
	t.Helper()
	originalPaths := confirmSystemPaths
	originalLookup := confirmLookupEnv
	originalRole := loadConfirmRole
	originalRunner := runWatchdogConfirm
	confirmSystemPaths = func() store.Paths { return paths }
	confirmLookupEnv = func(name string) (string, bool) {
		if name != "SSH_CONNECTION" {
			t.Fatalf("unexpected environment lookup %q", name)
		}
		return sshConnection, sshConnection != ""
	}
	loadConfirmRole = func(store.Paths) (HostRole, error) { return role, nil }
	runWatchdogConfirm = runner
	return func() {
		confirmSystemPaths = originalPaths
		confirmLookupEnv = originalLookup
		loadConfirmRole = originalRole
		runWatchdogConfirm = originalRunner
	}
}
