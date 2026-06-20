package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInitCreatesDefaultStateAndRuleset(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")

	if _, err := Init(dir, false); err != nil {
		t.Fatalf("init state: %v", err)
	}

	var st State
	readJSON(t, filepath.Join(dir, "state.json"), &st)
	if st.SchemaVersion != SchemaVersion {
		t.Fatalf("expected schema version %d, got %d", SchemaVersion, st.SchemaVersion)
	}
	if st.Server != nil {
		t.Fatalf("expected nil server, got %#v", st.Server)
	}
	if len(st.Clients) != 0 {
		t.Fatalf("expected no clients, got %#v", st.Clients)
	}

	var ruleset Ruleset
	readJSON(t, filepath.Join(dir, "rulesets", "default.json"), &ruleset)
	if ruleset.ID != "default" {
		t.Fatalf("unexpected ruleset id: %q", ruleset.ID)
	}
	if ruleset.Type != "domain-suffix" {
		t.Fatalf("unexpected ruleset type: %q", ruleset.Type)
	}
	wantDomains := []string{"chatgpt.com", "openai.com", "claude.ai", "anthropic.com"}
	if len(ruleset.Domains) != len(wantDomains) {
		t.Fatalf("expected domains %#v, got %#v", wantDomains, ruleset.Domains)
	}
	for i := range wantDomains {
		if ruleset.Domains[i] != wantDomains[i] {
			t.Fatalf("expected domains %#v, got %#v", wantDomains, ruleset.Domains)
		}
	}
}

func TestInitUsesRestrictedSecretPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")

	if _, err := Init(dir, false); err != nil {
		t.Fatalf("init state: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatalf("stat secrets dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("expected secrets mode 0700, got %o", got)
	}

	info, err = os.Stat(filepath.Join(dir, "secrets", "clients"))
	if err != nil {
		t.Fatalf("stat clients secrets dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("expected client secrets mode 0700, got %o", got)
	}
}

func TestInitDoesNotOverwriteExistingFilesWithoutForce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")

	if _, err := Init(dir, false); err != nil {
		t.Fatalf("init state: %v", err)
	}

	statePath := filepath.Join(dir, "state.json")
	custom := []byte("{\"schema_version\":999}\n")
	if err := os.WriteFile(statePath, custom, 0o644); err != nil {
		t.Fatalf("write custom state: %v", err)
	}

	if _, err := Init(dir, false); err != nil {
		t.Fatalf("init state again: %v", err)
	}

	got, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if string(got) != string(custom) {
		t.Fatalf("expected state not to be overwritten, got %q", string(got))
	}
}

func TestInitForceOverwritesDefaultFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")

	if _, err := Init(dir, false); err != nil {
		t.Fatalf("init state: %v", err)
	}

	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(statePath, []byte("{\"schema_version\":999}\n"), 0o644); err != nil {
		t.Fatalf("write custom state: %v", err)
	}

	if _, err := Init(dir, true); err != nil {
		t.Fatalf("force init state: %v", err)
	}

	var st State
	readJSON(t, statePath, &st)
	if st.SchemaVersion != SchemaVersion {
		t.Fatalf("expected schema version %d, got %d", SchemaVersion, st.SchemaVersion)
	}
}

func readJSON(t *testing.T, path string, value any) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
}
