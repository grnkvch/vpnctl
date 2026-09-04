package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestExecuteRestoreDryRunStillAuthenticatesAndDiscardsWithoutMutation(t *testing.T) {
	restore := installRestoreCLIFixture(t, RoleUninitialized)
	defer restore()
	manager := &recordingRestoreManager{plan: cliRestorePlan(false)}
	restoreBuilder = func(context.Context, store.Paths) (restoreManager, error) { return manager, nil }
	terminal := &restorePromptTerminal{hidden: []byte("restore-passphrase")}
	restoreOpenTTY = func() (PromptIO, io.Closer, error) { return terminal, io.NopCloser(strings.NewReader("")), nil }
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"--json", "restore", "relative.v2b", "--public-ip", "203.0.113.10", "--dry-run"}, &stdout, &stderr)
	if code != ExitSuccess || manager.planCalls != 1 || manager.applyCalls != 0 || manager.discardCalls != 1 || terminal.hiddenReads != 1 || terminal.visibleReads != 0 || stderr.Len() != 0 {
		t.Fatalf("dry-run code=%d plan=%d apply=%d discard=%d hidden=%d visible=%d stderr=%q", code, manager.planCalls, manager.applyCalls, manager.discardCalls, terminal.hiddenReads, terminal.visibleReads, stderr.String())
	}
	if !filepath.IsAbs(manager.input.ArchivePath) || filepath.Base(manager.input.ArchivePath) != "relative.v2b" || manager.input.PublicIPv4 != "203.0.113.10" || manager.input.Replace {
		t.Fatalf("restore input = %+v", manager.input)
	}
	if string(manager.passphrase) != "restore-passphrase" {
		t.Fatalf("restore passphrase was not transferred once")
	}
	assertRestoreJSON(t, stdout.Bytes(), false)
}

func TestExecuteRestoreReplaceUsesExplicitFlagAndReturnsEmergencySnapshot(t *testing.T) {
	restore := installRestoreCLIFixture(t, RoleGateway)
	defer restore()
	manager := &recordingRestoreManager{plan: cliRestorePlan(true), result: cliRestoreResult()}
	restoreBuilder = func(context.Context, store.Paths) (restoreManager, error) { return manager, nil }
	terminal := &restorePromptTerminal{hidden: []byte("restore-passphrase")}
	restoreOpenTTY = func() (PromptIO, io.Closer, error) { return terminal, io.NopCloser(strings.NewReader("")), nil }
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"restore", "/srv/gateway.v2b", "--public-ip=203.0.113.10", "--replace", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitSuccess || !manager.input.Replace || manager.applyCalls != 1 || manager.discardCalls != 0 || terminal.hiddenReads != 1 || terminal.visibleReads != 0 {
		t.Fatalf("replace code=%d input=%+v apply=%d discard=%d terminal=%+v stderr=%q", code, manager.input, manager.applyCalls, manager.discardCalls, terminal, stderr.String())
	}
	assertRestoreJSON(t, stdout.Bytes(), true)
	if strings.Contains(stdout.String(), "restore-passphrase") || strings.Contains(stderr.String(), "restore-passphrase") || strings.Contains(stdout.String(), "/srv/gateway.v2b") {
		t.Fatal("restore output exposed passphrase or archive path")
	}
}

func TestExecuteRestoreRequiresTTYEvenWithYesAndRejectsArgumentsBeforeBuilder(t *testing.T) {
	restore := installRestoreCLIFixture(t, RoleUninitialized)
	defer restore()
	manager := &recordingRestoreManager{plan: cliRestorePlan(false)}
	restoreBuilder = func(context.Context, store.Paths) (restoreManager, error) { return manager, nil }
	restoreOpenTTY = func() (PromptIO, io.Closer, error) { return nil, nil, errors.New("no tty") }
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"restore", "/srv/gateway.v2b", "--public-ip", "203.0.113.10", "--yes", "--json"}, &stdout, &stderr); code != ExitValidation || manager.planCalls != 0 {
		t.Fatalf("missing TTY code=%d plan=%d stdout=%q stderr=%q", code, manager.planCalls, stdout.String(), stderr.String())
	}
	oldBuilder := restoreBuilder
	restoreBuilder = func(context.Context, store.Paths) (restoreManager, error) {
		t.Fatal("invalid restore arguments built a manager")
		return nil, nil
	}
	defer func() { restoreBuilder = oldBuilder }()
	stdout.Reset()
	stderr.Reset()
	if code := Execute([]string{"restore", "/srv/gateway.v2b", "--json"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("missing public IP code=%d", code)
	}
}

func TestRestoreParserRejectsNonCanonicalShapesAndDeferredMode(t *testing.T) {
	for _, args := range [][]string{
		{"restore", "archive"},
		{"restore", "one", "two", "--public-ip", "203.0.113.10"},
		{"restore", "archive", "--public-ip"},
		{"restore", "archive", "--public-ip", "203.0.113.10", "--public-ip=203.0.113.11"},
		{"restore", "archive", "--public-ip", "203.0.113.10", "--defer"},
		{"restore", "archive", "--public-ip", "203.0.113.10", "--replace", "--replace"},
	} {
		if _, err := parseRestoreArguments(args); err == nil {
			t.Fatalf("parseRestoreArguments(%q) succeeded", args)
		}
	}
}

func TestRestoreInvocationUsesTheFirstCommandTokenOnly(t *testing.T) {
	for _, args := range [][]string{
		{"restore", "/srv/gateway.v2b", "--public-ip", "203.0.113.10"},
		{"--json", "--public-ip", "203.0.113.10", "restore", "/srv/gateway.v2b"},
		{"--public-ip=203.0.113.10", "--replace", "restore", "/srv/gateway.v2b"},
	} {
		if !isRestoreInvocation(args) {
			t.Fatalf("isRestoreInvocation(%q) = false", args)
		}
	}
	for _, args := range [][]string{
		{"client", "add", "restore"},
		{"backup", "restore"},
		{"--json", "status", "restore"},
		{"--public-ip", "restore", "backup"},
	} {
		if isRestoreInvocation(args) {
			t.Fatalf("isRestoreInvocation(%q) = true", args)
		}
	}
}

func installRestoreCLIFixture(t *testing.T, role HostRole) func() {
	t.Helper()
	oldPaths, oldRole, oldBuilder, oldLookup, oldTTY := restoreSystemPaths, restoreLoadRole, restoreBuilder, restoreLookupEnv, restoreOpenTTY
	paths, _ := store.NewPaths(t.TempDir())
	restoreSystemPaths = func() store.Paths { return paths }
	restoreLoadRole = func(store.Paths) (HostRole, error) { return role, nil }
	restoreLookupEnv = func(string) (string, bool) { return "", false }
	return func() {
		restoreSystemPaths, restoreLoadRole, restoreBuilder, restoreLookupEnv, restoreOpenTTY = oldPaths, oldRole, oldBuilder, oldLookup, oldTTY
	}
}

func cliRestorePlan(replace bool) lifecycle.GatewayRestorePlan {
	return lifecycle.GatewayRestorePlan{
		ArchivePath: "/srv/gateway.v2b", PublicIPv4: "203.0.113.10", OriginalPublicIPv4: "203.0.113.10",
		Replace: replace, ReplacingInitialized: replace, SameEndpoint: true, TrustPreserved: true,
		GatewayID: "97000000-0000-4000-8000-000000000001", SourceGeneration: 7, TargetGeneration: 8,
		NodeCount: 1, ClientCount: 2, EmergencySnapshotNeeded: replace,
		AffectedServices: []string{"vpnctl-standard.service"}, ExpectedInterruptions: []string{"gateway transports restart"},
	}
}

func cliRestoreResult() lifecycle.GatewayRestoreResult {
	snapshot := lifecycle.GatewayRestoreEmergencySnapshot{
		ID: "97000000-0000-4000-8000-000000000002", Path: "/var/lib/vpnctl-restore-snapshots/restore-97000000-0000-4000-8000-000000000002",
		CreatedAt: time.Date(2026, 9, 4, 18, 0, 0, 0, time.UTC),
	}
	return lifecycle.GatewayRestoreResult{
		Changed: true, GatewayID: "97000000-0000-4000-8000-000000000001", PublicIPv4: "203.0.113.10", Generation: 8,
		SameEndpoint: true, TrustPreserved: true, NodeCount: 1, ClientCount: 2, EmergencySnapshot: &snapshot,
		AffectedServices: []string{"vpnctl-standard.service"}, ExpectedInterruptions: []string{"gateway transports restart"},
	}
}

func assertRestoreJSON(t *testing.T, encoded []byte, snapshot bool) {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	data := document["data"].(map[string]any)
	if document["command"] != "restore" || data["changed"] != true || data["generation"] != float64(8) {
		t.Fatalf("restore JSON = %+v", document)
	}
	_, hasSnapshot := data["snapshot_id"]
	if hasSnapshot != snapshot {
		t.Fatalf("restore snapshot field present=%t want=%t", hasSnapshot, snapshot)
	}
}

type recordingRestoreManager struct {
	plan         lifecycle.GatewayRestorePlan
	result       lifecycle.GatewayRestoreResult
	input        lifecycle.GatewayRestoreInput
	passphrase   []byte
	planCalls    int
	applyCalls   int
	discardCalls int
}

func (manager *recordingRestoreManager) Plan(_ context.Context, input lifecycle.GatewayRestoreInput, passphrase []byte) (lifecycle.GatewayRestorePlan, error) {
	manager.planCalls++
	manager.input = input
	manager.passphrase = append([]byte(nil), passphrase...)
	for index := range passphrase {
		passphrase[index] = 0
	}
	return manager.plan, nil
}

func (manager *recordingRestoreManager) Apply(context.Context, lifecycle.GatewayRestorePlan) (lifecycle.GatewayRestoreResult, error) {
	manager.applyCalls++
	return manager.result, nil
}

func (manager *recordingRestoreManager) Discard(lifecycle.GatewayRestorePlan) error {
	manager.discardCalls++
	return nil
}

type restorePromptTerminal struct {
	hidden       []byte
	hiddenReads  int
	visibleReads int
}

func (terminal *restorePromptTerminal) ReadVisible(InteractionStep) (string, error) {
	terminal.visibleReads++
	return "yes", nil
}

func (terminal *restorePromptTerminal) ReadHidden(_ InteractionStep, _ int) ([]byte, error) {
	terminal.hiddenReads++
	return append([]byte(nil), terminal.hidden...), nil
}

func (*restorePromptTerminal) WriteSecret(InteractionStep, []byte) error {
	return errors.New("restore must not write a one-time secret")
}
