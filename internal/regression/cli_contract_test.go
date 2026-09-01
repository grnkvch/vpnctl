package regression

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
