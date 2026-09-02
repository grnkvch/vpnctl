package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2RegistryMatchesEveryFrozenContractRow(t *testing.T) {
	t.Parallel()

	contract := readFrozenCommandRows(t)
	commands := V2CommandRegistry().Commands()
	if len(commands) != len(contract) {
		t.Fatalf("registry command count = %d, frozen contract rows = %d", len(commands), len(contract))
	}
	registryRows := make(map[string]CommandSpec, len(commands))
	for _, spec := range commands {
		key := spec.Syntax + "\x00" + rolesLabel(spec.Roles)
		if _, duplicate := registryRows[key]; duplicate {
			t.Fatalf("registry duplicates command/role row %q", key)
		}
		registryRows[key] = spec
	}

	for _, row := range contract {
		key := row.Syntax + "\x00" + row.Roles
		spec, found := registryRows[key]
		if !found {
			t.Errorf("frozen command row is absent from registry: %s (%s)", row.Syntax, row.Roles)
			continue
		}
		if spec.ResultContract != row.Result || string(spec.Consent) != row.Consent || yesNo(spec.DryRun) != row.DryRun || string(spec.Defer) != row.Defer {
			t.Errorf("registry metadata for %s (%s) = result=%q consent=%q dry-run=%q defer=%q; contract = result=%q consent=%q dry-run=%q defer=%q",
				row.Syntax, row.Roles, spec.ResultContract, spec.Consent, yesNo(spec.DryRun), spec.Defer,
				row.Result, row.Consent, row.DryRun, row.Defer)
		}
		delete(registryRows, key)
	}
	for _, extra := range registryRows {
		t.Errorf("registry contains command absent from frozen contract: %s (%s)", extra.Syntax, rolesLabel(extra.Roles))
	}
}

func TestV2RegistryExposesOnlyExplicitFullPolicyReplacement(t *testing.T) {
	t.Parallel()

	registry := V2CommandRegistry()
	for _, forbidden := range []string{"policy.add.node", "policy.add.gateway", "policy.remove.node", "policy.remove.gateway", "policy.auto", "policy.assign.default"} {
		if spec, found := registry.Lookup(forbidden); found {
			t.Errorf("forbidden incremental or automatic policy path is registered: %#v", spec)
		}
	}
	want := map[string]struct{}{
		"policy.show.node": {}, "policy.show.gateway": {},
		"policy.set.node": {}, "policy.set.gateway": {},
		"policy.clear.node": {}, "policy.clear.gateway": {},
	}
	for _, spec := range registry.Commands() {
		if !strings.HasPrefix(spec.ID, "policy.") {
			continue
		}
		if _, found := want[spec.ID]; !found {
			t.Errorf("unexpected policy command path: %s (%s)", spec.ID, spec.Syntax)
		}
		delete(want, spec.ID)
	}
	if len(want) != 0 {
		t.Errorf("required explicit policy command paths are absent: %v", want)
	}
}

func TestEveryV2CommandIsRoleGuardedBeforeHandler(t *testing.T) {
	t.Parallel()

	registry := V2CommandRegistry()
	roles := []HostRole{RoleUninitialized, RoleGateway, RoleNode}
	for _, spec := range registry.Commands() {
		spec := spec
		t.Run(spec.ID, func(t *testing.T) {
			for _, role := range roles {
				role := role
				t.Run(string(role), func(t *testing.T) {
					handlerCalls := 0
					err := registry.Dispatch(spec.ID, role, func(received CommandSpec) error {
						handlerCalls++
						if received.ID != spec.ID {
							t.Fatalf("handler command ID = %q, want %q", received.ID, spec.ID)
						}
						return nil
					})
					if spec.AllowsRole(role) {
						if err != nil || handlerCalls != 1 {
							t.Fatalf("allowed Dispatch() calls = %d, error = %v", handlerCalls, err)
						}
						return
					}
					if !errors.Is(err, ErrUnsupportedRole) || handlerCalls != 0 {
						t.Fatalf("rejected Dispatch() calls = %d, error = %v", handlerCalls, err)
					}
				})
			}
		})
	}
}

func TestRegistryRejectsUnknownCommandAndRoleBeforeHandler(t *testing.T) {
	t.Parallel()

	registry := V2CommandRegistry()
	calls := 0
	handler := func(CommandSpec) error { calls++; return nil }
	if err := registry.Dispatch("missing", RoleGateway, handler); !errors.Is(err, ErrUnknownCommand) {
		t.Fatalf("unknown command error = %v", err)
	}
	if err := registry.Dispatch("status", HostRole("proxy"), handler); err == nil || errors.Is(err, ErrUnsupportedRole) {
		t.Fatalf("invalid role error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("handler called %d times before command/role validation", calls)
	}
}

func TestRegistryReturnsDefensiveCopies(t *testing.T) {
	t.Parallel()

	registry := V2CommandRegistry()
	first := registry.Commands()
	first[0].Roles[0] = RoleNode
	second := registry.Commands()
	if first[0].Roles[0] == second[0].Roles[0] {
		t.Fatal("Commands() exposed mutable registry role storage")
	}
	spec, found := registry.Lookup("help")
	if !found {
		t.Fatal("help command not found")
	}
	spec.Roles[0] = RoleNode
	again, _ := registry.Lookup("help")
	if again.Roles[0] != RoleUninitialized {
		t.Fatal("Lookup() exposed mutable registry role storage")
	}
}

func TestNewCommandRegistryRejectsInvalidContracts(t *testing.T) {
	t.Parallel()

	valid := command("status", "status", "status-v1:status", []HostRole{RoleGateway, RoleNode}, ConsentNone, false, DeferNo)
	tests := []struct {
		name  string
		specs []CommandSpec
	}{
		{name: "empty", specs: nil},
		{name: "duplicate id", specs: []CommandSpec{valid, valid}},
		{name: "duplicate row", specs: []CommandSpec{valid, func() CommandSpec { copy := valid; copy.ID = "other"; return copy }()}},
		{name: "no roles", specs: []CommandSpec{func() CommandSpec { copy := valid; copy.Roles = nil; return copy }()}},
		{name: "bad role", specs: []CommandSpec{func() CommandSpec { copy := valid; copy.Roles = []HostRole{"proxy"}; return copy }()}},
		{name: "bad consent", specs: []CommandSpec{func() CommandSpec { copy := valid; copy.Consent = "automatic"; return copy }()}},
		{name: "bad secret flow", specs: []CommandSpec{func() CommandSpec { copy := valid; copy.SecretFlow = PromptConfirm; return copy }()}},
		{name: "bad defer", specs: []CommandSpec{func() CommandSpec { copy := valid; copy.Defer = "sometimes"; return copy }()}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCommandRegistry(test.specs); err == nil {
				t.Fatal("NewCommandRegistry() accepted invalid specs")
			}
		})
	}
}

type frozenCommandRow struct {
	Syntax  string
	Result  string
	Roles   string
	Consent string
	DryRun  string
	Defer   string
}

func readFrozenCommandRows(t *testing.T) []frozenCommandRow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "v2", "CLI_CONTRACT.md"))
	if err != nil {
		t.Fatalf("read frozen CLI contract: %v", err)
	}
	rows := make([]frozenCommandRow, 0)
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "| `vpnctl ") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) != 10 {
			t.Fatalf("unexpected CLI contract table row: %s", line)
		}
		cell := func(index int) string { return strings.Trim(strings.TrimSpace(cells[index]), "`") }
		rows = append(rows, frozenCommandRow{
			Syntax:  strings.TrimPrefix(cell(1), "vpnctl "),
			Result:  cell(2),
			Roles:   cell(3),
			Consent: cell(5),
			DryRun:  cell(6),
			Defer:   cell(7),
		})
	}
	if len(rows) == 0 {
		t.Fatal("frozen CLI contract contains no command rows")
	}
	return rows
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
