package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestExecuteBackupDryRunPlansWithoutPassphraseOrArchive(t *testing.T) {
	restore := installBackupCLIFixture(t, RoleGateway)
	defer restore()
	manager := &recordingBackupManager{plan: cliBackupPlan()}
	backupBuilder = func(context.Context, store.Paths) (backupManager, error) { return manager, nil }
	backupOpenTTY = func() (PromptIO, io.Closer, error) {
		t.Fatal("backup dry-run opened a controlling terminal")
		return nil, nil, errors.New("unreachable")
	}
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"--json", "backup", "--dry-run"}, &stdout, &stderr)
	if code != ExitSuccess || manager.planCalls != 1 || manager.applyCalls != 0 || manager.discardCalls != 1 || stderr.Len() != 0 {
		t.Fatalf("dry-run code=%d plan=%d apply=%d discard=%d stderr=%q", code, manager.planCalls, manager.applyCalls, manager.discardCalls, stderr.String())
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	data := document["data"].(map[string]any)
	if document["command"] != "backup" || data["output_path"] != manager.plan.OutputPath || data["file_mode"] != "0600" || data["sha256"] != emptyBackupSHA256 {
		t.Fatalf("backup dry-run output = %+v", document)
	}
}

func TestExecuteBackupReadsMatchingHiddenPassphraseEvenWithYes(t *testing.T) {
	restore := installBackupCLIFixture(t, RoleGateway)
	defer restore()
	manager := &recordingBackupManager{plan: cliBackupPlan(), result: cliBackupResult()}
	backupBuilder = func(context.Context, store.Paths) (backupManager, error) { return manager, nil }
	terminal := &backupPromptTerminal{hidden: [][]byte{[]byte("new backup passphrase"), []byte("new backup passphrase")}}
	backupOpenTTY = func() (PromptIO, io.Closer, error) { return terminal, io.NopCloser(strings.NewReader("")), nil }
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"backup", "/srv/backups/gateway.backup", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitSuccess || manager.planCalls != 1 || manager.applyCalls != 1 || manager.discardCalls != 0 || terminal.hiddenReads != 2 {
		t.Fatalf("backup code=%d plan=%d apply=%d discard=%d hidden=%d stderr=%q", code, manager.planCalls, manager.applyCalls, manager.discardCalls, terminal.hiddenReads, stderr.String())
	}
	if manager.requestedPath != "/srv/backups/gateway.backup" || string(manager.receivedPassphrase) != "new backup passphrase" {
		t.Fatalf("backup request path=%q passphrase=%q", manager.requestedPath, manager.receivedPassphrase)
	}
	if strings.Contains(stdout.String(), "new backup passphrase") || strings.Contains(stderr.String(), "new backup passphrase") {
		t.Fatal("backup command output exposed the passphrase")
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["resource_ids"].(map[string]any)["backup"] != manager.result.BackupID || document["data"].(map[string]any)["sha256"] != manager.result.SHA256 {
		t.Fatalf("backup result output = %+v", document)
	}
}

func TestExecuteBackupYesCannotBypassMissingControllingTerminal(t *testing.T) {
	restore := installBackupCLIFixture(t, RoleGateway)
	defer restore()
	manager := &recordingBackupManager{plan: cliBackupPlan(), result: cliBackupResult()}
	backupBuilder = func(context.Context, store.Paths) (backupManager, error) { return manager, nil }
	backupOpenTTY = func() (PromptIO, io.Closer, error) { return nil, nil, errors.New("no controlling terminal") }
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"backup", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitValidation || manager.planCalls != 0 || manager.applyCalls != 0 || manager.discardCalls != 0 {
		t.Fatalf("missing TTY code=%d plan=%d apply=%d discard=%d stdout=%q stderr=%q", code, manager.planCalls, manager.applyCalls, manager.discardCalls, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "no controlling terminal") || strings.Contains(stderr.String(), "no controlling terminal") {
		t.Fatal("backup exposed internal terminal error")
	}
}

func TestExecuteBackupRejectsNodeAndInvalidArgumentsBeforePrompt(t *testing.T) {
	restore := installBackupCLIFixture(t, RoleNode)
	defer restore()
	backupBuilder = func(context.Context, store.Paths) (backupManager, error) {
		t.Fatal("node backup built a manager")
		return nil, nil
	}
	backupOpenTTY = func() (PromptIO, io.Closer, error) {
		t.Fatal("node backup opened a terminal")
		return nil, nil, nil
	}
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"backup", "--json"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("node backup code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Execute([]string{"backup", "one", "two", "--json"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("invalid backup arguments code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestBackupParserRejectsDeferredAndDuplicateFlags(t *testing.T) {
	for _, args := range [][]string{
		{"backup", "--defer"}, {"backup", "--json", "--json"}, {"backup", "--dry-run", "--dry-run"}, {"backup", "--unknown"},
	} {
		if _, err := parseBackupArguments(args); err == nil {
			t.Fatalf("parseBackupArguments(%q) succeeded", args)
		}
	}
}

func installBackupCLIFixture(t *testing.T, role HostRole) func() {
	t.Helper()
	oldPaths, oldRole, oldBuilder, oldTTY := backupSystemPaths, backupLoadRole, backupBuilder, backupOpenTTY
	paths, _ := store.NewPaths(t.TempDir())
	backupSystemPaths = func() store.Paths { return paths }
	backupLoadRole = func(store.Paths) (HostRole, error) { return role, nil }
	return func() {
		backupSystemPaths, backupLoadRole, backupBuilder, backupOpenTTY = oldPaths, oldRole, oldBuilder, oldTTY
	}
}

func cliBackupPlan() lifecycle.GatewayBackupPlan {
	return lifecycle.GatewayBackupPlan{
		BackupID: "93000000-0000-4000-8000-000000000001", OutputPath: "/var/lib/vpnctl/backups/vpnctl-20260904T140506Z.v2b",
		ExpectedStateGeneration: 7, PublicIPv4: "203.0.113.10", CreatedAt: time.Date(2026, 9, 4, 14, 5, 6, 0, time.UTC),
	}
}

func cliBackupResult() lifecycle.GatewayBackupResult {
	return lifecycle.GatewayBackupResult{
		BackupID: "93000000-0000-4000-8000-000000000001", OutputPath: "/srv/backups/gateway.backup",
		FileMode: 0o600, SHA256: strings.Repeat("a", 64), SizeBytes: 4096, StateGeneration: 7,
		CreatedAt: time.Date(2026, 9, 4, 14, 5, 6, 0, time.UTC),
	}
}

type recordingBackupManager struct {
	plan               lifecycle.GatewayBackupPlan
	result             lifecycle.GatewayBackupResult
	requestedPath      string
	receivedPassphrase []byte
	planCalls          int
	applyCalls         int
	discardCalls       int
}

func (manager *recordingBackupManager) Plan(_ context.Context, path string) (lifecycle.GatewayBackupPlan, error) {
	manager.planCalls++
	manager.requestedPath = path
	return manager.plan, nil
}

func (manager *recordingBackupManager) Apply(_ context.Context, _ lifecycle.GatewayBackupPlan, passphrase []byte) (lifecycle.GatewayBackupResult, error) {
	manager.applyCalls++
	manager.receivedPassphrase = append([]byte(nil), passphrase...)
	for index := range passphrase {
		passphrase[index] = 0
	}
	return manager.result, nil
}

func (manager *recordingBackupManager) Discard(lifecycle.GatewayBackupPlan) error {
	manager.discardCalls++
	return nil
}

type backupPromptTerminal struct {
	hidden      [][]byte
	hiddenReads int
}

func (*backupPromptTerminal) ReadVisible(InteractionStep) (string, error) {
	return "", errors.New("backup must not request visible consent")
}

func (terminal *backupPromptTerminal) ReadHidden(_ InteractionStep, _ int) ([]byte, error) {
	if terminal.hiddenReads >= len(terminal.hidden) {
		return nil, errors.New("no hidden backup input")
	}
	value := append([]byte(nil), terminal.hidden[terminal.hiddenReads]...)
	terminal.hiddenReads++
	return value, nil
}

func (*backupPromptTerminal) WriteSecret(InteractionStep, []byte) error {
	return errors.New("backup must not write a one-time secret")
}
