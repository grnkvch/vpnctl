package regression

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v2cli "github.com/vgrinkevich/vpnctl/internal/cli"
)

func TestV2CLIContractRowsAreComplete(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "docs", "v2", "CLI_CONTRACT.md")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open v2 CLI contract: %v", err)
	}
	defer file.Close()

	validRoles := stringSet("all", "gateway", "node", "gateway/node")
	validConsent := stringSet("none", "confirm", "conditional", "confirm+typed-if-irreversible", "typed")
	validSupport := stringSet("yes", "no")
	requiredRoots := stringSet(
		"help", "version", "init", "confirm", "status", "doctor", "validate", "plan", "apply", "repair",
		"invite", "join", "node", "client", "preset", "policy", "dns", "transport", "expose", "cert",
		"trust", "log", "backup", "restore", "update", "uninstall", "purge",
	)

	seenCommands := make(map[string]struct{})
	seenRoots := make(map[string]struct{})
	rows := 0
	lineNumber := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if !strings.HasPrefix(line, "| `vpnctl ") {
			continue
		}
		rows++
		columns := strings.Split(line, "|")
		if len(columns) != 10 {
			t.Fatalf("invalid CLI contract row at line %d: got %d columns", lineNumber, len(columns)-2)
		}

		command := strings.Trim(strings.TrimSpace(columns[1]), "`")
		jsonResult := strings.Trim(strings.TrimSpace(columns[2]), "`")
		roles := strings.TrimSpace(columns[3])
		arguments := strings.TrimSpace(columns[4])
		consent := strings.TrimSpace(columns[5])
		dryRun := strings.TrimSpace(columns[6])
		deferSupport := strings.TrimSpace(columns[7])
		example := strings.Trim(strings.TrimSpace(columns[8]), "`")

		if _, duplicate := seenCommands[command]; duplicate {
			t.Errorf("duplicate CLI command at line %d: %s", lineNumber, command)
		}
		seenCommands[command] = struct{}{}
		if _, ok := validRoles[roles]; !ok {
			t.Errorf("invalid role availability %q at line %d", roles, lineNumber)
		}
		if jsonResult != "plain-text" {
			parts := strings.Split(jsonResult, ":")
			if len(parts) != 2 || !strings.HasSuffix(parts[0], "-v1") || parts[1] == "" {
				t.Errorf("invalid JSON result contract %q at line %d", jsonResult, lineNumber)
			}
		}
		if arguments == "" {
			t.Errorf("missing arguments/options contract at line %d: %s", lineNumber, command)
		}
		if _, ok := validConsent[consent]; !ok {
			t.Errorf("invalid consent class %q at line %d", consent, lineNumber)
		}
		if _, ok := validSupport[dryRun]; !ok {
			t.Errorf("invalid dry-run support %q at line %d", dryRun, lineNumber)
		}
		if _, ok := validSupport[deferSupport]; !ok {
			t.Errorf("invalid defer support %q at line %d", deferSupport, lineNumber)
		}
		if !strings.HasPrefix(example, "vpnctl ") && !strings.HasPrefix(example, "sudo vpnctl ") {
			t.Errorf("missing executable example at line %d: %s", lineNumber, command)
		}

		words := strings.Fields(strings.TrimPrefix(command, "vpnctl "))
		if len(words) == 0 {
			t.Errorf("missing command root at line %d", lineNumber)
		} else {
			seenRoots[words[0]] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan v2 CLI contract: %v", err)
	}
	if rows == 0 {
		t.Fatal("v2 CLI contract contains no command rows")
	}
	for root := range requiredRoots {
		if _, ok := seenRoots[root]; !ok {
			t.Errorf("v2 CLI contract is missing command family %q", root)
		}
	}
}

func stringSet(values ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func TestV2CLIContractExamplesExecuteThroughPublicRoleGate(t *testing.T) {
	t.Parallel()

	registry := v2cli.V2CommandRegistry()
	bySyntax := make(map[string]v2cli.CommandSpec)
	for _, spec := range registry.Commands() {
		bySyntax["vpnctl "+spec.Syntax] = spec
	}

	rows := readCLIContractExamples(t)
	if len(rows) != len(bySyntax) {
		t.Fatalf("documented command count = %d, registry count = %d", len(rows), len(bySyntax))
	}
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		spec, found := bySyntax[row.Command]
		if !found {
			t.Errorf("line %d documents command absent from registry: %s", row.Line, row.Command)
			continue
		}
		if _, duplicate := seen[spec.ID]; duplicate {
			t.Errorf("line %d executes duplicate registry command %s", row.Line, spec.ID)
			continue
		}
		seen[spec.ID] = struct{}{}
		assertDocumentedInvocationMatchesSpec(t, row.Example, spec)
		for _, role := range spec.Roles {
			called := false
			err := registry.Dispatch(spec.ID, role, func(executed v2cli.CommandSpec) error {
				called = true
				if executed.ID != spec.ID || executed.Syntax != spec.Syntax {
					return fmt.Errorf("dispatched spec changed from %s to %s", spec.ID, executed.ID)
				}
				return nil
			})
			if err != nil {
				t.Errorf("line %d execute %s as %s: %v", row.Line, row.Example, role, err)
			}
			if !called {
				t.Errorf("line %d did not execute handler for %s as %s", row.Line, spec.ID, role)
			}
		}
	}
	for id := range registryCommandIDs(registry) {
		if _, found := seen[id]; !found {
			t.Errorf("registry command %s has no executed documentation example", id)
		}
	}
}

func TestV2OperatorGuideCommandsExecuteAndStayInsideReleaseScope(t *testing.T) {
	t.Parallel()

	path := filepath.Join("..", "..", "docs", "v2", "OPERATIONS.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read operator guide: %v", err)
	}
	registry := v2cli.V2CommandRegistry()
	commands := parseOperatorGuideCommands(t, string(data))
	required := stringSet(
		"init.gateway", "confirm", "client.add", "client.export", "invite", "init.node", "join",
		"expose", "expose.show", "expose.remove", "preset.validate", "preset.diff",
		"policy.set.node", "policy.set.gateway", "plan", "apply", "dns.show", "dns.set", "dns.reset",
		"transport.test", "transport.switch", "status", "doctor", "log.enable", "log.status",
		"log.disable", "backup", "restore", "update", "update.rollback", "uninstall", "purge", "repair",
	)
	seen := make(map[string]struct{}, len(commands))
	for _, command := range commands {
		spec, found := registry.Lookup(command.ID)
		if !found {
			t.Errorf("line %d uses unknown command ID %s", command.Line, command.ID)
			continue
		}
		role, err := documentedRole(command.Role)
		if err != nil {
			t.Errorf("line %d: %v", command.Line, err)
			continue
		}
		assertDocumentedInvocationMatchesSpec(t, command.Invocation, spec)
		called := false
		err = registry.Dispatch(command.ID, role, func(v2cli.CommandSpec) error {
			called = true
			return nil
		})
		if err != nil {
			t.Errorf("line %d execute %s as %s: %v", command.Line, command.Invocation, role, err)
		}
		if !called {
			t.Errorf("line %d did not execute %s", command.Line, command.ID)
		}
		seen[command.ID] = struct{}{}
		assertNoBacklogCommandSurface(t, command.Line, command.Invocation)
	}
	for id := range required {
		if _, found := seen[id]; !found {
			t.Errorf("operator guide has no executed example for required command %s", id)
		}
	}
	for _, requiredText := range []string{
		"## Install the checksum-verified release",
		"## Happy path A: gateway and personal devices",
		"## Happy path B: private VPS and webhook ingress",
		"## Presets, policy, and the classification boundary",
		"## Manual transport operations and restricted UDP",
		"## Status, doctor, and temporary logging",
		"## Backup, restore, update, and removal",
		"## One-time v1 migration",
		"## Troubleshooting",
		"does not provide domain/ACME ingress",
		"URL/subscription/QR",
		"automatic fallback",
		"full IPv6 transport",
	} {
		if !strings.Contains(string(data), requiredText) {
			t.Errorf("operator guide is missing required boundary %q", requiredText)
		}
	}
}

func TestRootReadmeDoesNotAdvertiseLegacyOrBacklogCommandsAsV2(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read root README: %v", err)
	}
	contents := string(data)
	for _, stale := range []string{
		"vpnctl setup", "vpnctl server ", "vpnctl client create", "vpnctl ruleset ",
		"vpnctl client rotate-keys", "--type wireguard", "--type clash", "--qr",
		"Local Git-friendly state", "state in .vpnctl",
	} {
		if strings.Contains(contents, stale) {
			t.Errorf("root README still advertises stale v1 surface %q", stale)
		}
	}
	for _, required := range []string{
		"docs/v2/OPERATIONS.md", "one immutable role per host", "URL delivery, subscription links, and QR export are not v2.0",
	} {
		if !strings.Contains(contents, required) {
			t.Errorf("root README is missing v2 boundary %q", required)
		}
	}
}

type cliContractExample struct {
	Line    int
	Command string
	Example string
}

func readCLIContractExamples(t *testing.T) []cliContractExample {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "v2", "CLI_CONTRACT.md")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open v2 CLI contract: %v", err)
	}
	defer file.Close()

	var rows []cliContractExample
	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if !strings.HasPrefix(line, "| `vpnctl ") {
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) != 10 {
			t.Fatalf("invalid CLI contract row at line %d", lineNumber)
		}
		cell := func(index int) string { return strings.Trim(strings.TrimSpace(columns[index]), "`") }
		rows = append(rows, cliContractExample{Line: lineNumber, Command: cell(1), Example: cell(8)})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan v2 CLI contract: %v", err)
	}
	return rows
}

func registryCommandIDs(registry v2cli.CommandRegistry) map[string]struct{} {
	ids := make(map[string]struct{})
	for _, spec := range registry.Commands() {
		ids[spec.ID] = struct{}{}
	}
	return ids
}

type operatorGuideCommand struct {
	Line       int
	ID         string
	Role       string
	Invocation string
}

func parseOperatorGuideCommands(t *testing.T, contents string) []operatorGuideCommand {
	t.Helper()
	lines := strings.Split(contents, "\n")
	var commands []operatorGuideCommand
	inside := false
	current := operatorGuideCommand{}
	for index, line := range lines {
		lineNumber := index + 1
		if strings.HasPrefix(line, "```console vpnctl-doc-test ") {
			if inside {
				t.Fatalf("line %d starts a nested documentation command block", lineNumber)
			}
			inside = true
			current = operatorGuideCommand{Line: lineNumber}
			for _, field := range strings.Fields(strings.TrimPrefix(line, "```console vpnctl-doc-test ")) {
				key, value, found := strings.Cut(field, "=")
				if !found || value == "" {
					t.Fatalf("line %d has invalid command metadata %q", lineNumber, field)
				}
				switch key {
				case "id":
					current.ID = value
				case "role":
					current.Role = value
				default:
					t.Fatalf("line %d has unknown command metadata %q", lineNumber, key)
				}
			}
			continue
		}
		if !inside {
			if strings.HasPrefix(strings.TrimSpace(line), "sudo vpnctl ") {
				t.Errorf("line %d contains an unexecuted vpnctl example", lineNumber)
			}
			continue
		}
		if line == "```" {
			if current.ID == "" || current.Role == "" || current.Invocation == "" {
				t.Fatalf("line %d closes an incomplete documentation command block", lineNumber)
			}
			commands = append(commands, current)
			inside = false
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if current.Invocation != "" {
			t.Fatalf("line %d adds a second command to one documentation test block", lineNumber)
		}
		current.Invocation = strings.TrimSpace(line)
	}
	if inside {
		t.Fatal("operator guide ends inside a documentation command block")
	}
	if len(commands) == 0 {
		t.Fatal("operator guide contains no executable documentation commands")
	}
	return commands
}

func documentedRole(value string) (v2cli.HostRole, error) {
	switch value {
	case "uninitialized":
		return v2cli.RoleUninitialized, nil
	case "gateway":
		return v2cli.RoleGateway, nil
	case "node":
		return v2cli.RoleNode, nil
	default:
		return "", fmt.Errorf("unsupported documentation role %q", value)
	}
}

func assertDocumentedInvocationMatchesSpec(t *testing.T, invocation string, spec v2cli.CommandSpec) {
	t.Helper()
	fields := strings.Fields(invocation)
	if len(fields) > 0 && fields[0] == "sudo" {
		fields = fields[1:]
	}
	if len(fields) < 2 || fields[0] != "vpnctl" {
		t.Errorf("documented invocation %q is not a vpnctl command", invocation)
		return
	}
	for _, field := range fields {
		if strings.ContainsAny(field, "<>[]") {
			t.Errorf("documented invocation %q contains an unresolved placeholder", invocation)
		}
	}
	arguments := fields[1:]
	fixed := make([]string, 0)
	for _, token := range strings.Fields(spec.Syntax) {
		if strings.ContainsAny(token, "<[") {
			continue
		}
		fixed = append(fixed, token)
	}
	searchFrom := 0
	for _, token := range fixed {
		found := false
		for searchFrom < len(arguments) {
			if arguments[searchFrom] == token {
				found = true
				searchFrom++
				break
			}
			searchFrom++
		}
		if !found {
			t.Errorf("documented invocation %q does not match command %s syntax %q: missing %q", invocation, spec.ID, spec.Syntax, token)
			return
		}
	}
}

func assertNoBacklogCommandSurface(t *testing.T, line int, invocation string) {
	t.Helper()
	lower := strings.ToLower(invocation)
	for _, forbidden := range []string{
		"--qr", " subscription", " url", "--domain", " acme", " route add",
		" transport auto", " transport fallback", " ingress add", " expose tcp", " expose udp",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("line %d advertises out-of-scope command surface %q in %q", line, forbidden, invocation)
		}
	}
}
