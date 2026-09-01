package regression

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var taskReferencePattern = regexp.MustCompile(`\b\d+\.\d+(?:-\d+(?:\.\d+)?)?\b`)

func TestV2RequirementTraceabilityIsComplete(t *testing.T) {
	t.Parallel()

	expected := readV2SpecScenarios(t)
	actual := readV2TraceabilityTable(t)

	for key := range expected {
		if _, ok := actual[key]; !ok {
			t.Errorf("v2 spec scenario has no verification assignment: %s", key)
		}
	}
	for key := range actual {
		if _, ok := expected[key]; !ok {
			t.Errorf("traceability row does not match a v2 spec scenario: %s", key)
		}
	}
	if len(expected) != len(actual) {
		t.Errorf("traceability row count = %d, want %d", len(actual), len(expected))
	}
}

type traceabilityKey struct {
	capability  string
	requirement string
	scenario    string
}

func (k traceabilityKey) String() string {
	return fmt.Sprintf("%s / %s / %s", k.capability, k.requirement, k.scenario)
}

func readV2SpecScenarios(t *testing.T) map[traceabilityKey]struct{} {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "openspec", "changes", "vpnctl-v2", "specs", "*", "spec.md"))
	if err != nil {
		t.Fatalf("glob v2 specs: %v", err)
	}
	if len(paths) != 10 {
		t.Fatalf("v2 capability spec count = %d, want 10", len(paths))
	}

	result := make(map[traceabilityKey]struct{})
	for _, path := range paths {
		capability := filepath.Base(filepath.Dir(path))
		file, err := os.Open(path)
		if err != nil {
			t.Fatalf("open v2 spec %s: %v", path, err)
		}

		currentRequirement := ""
		requirementScenarios := make(map[string]int)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "### Requirement: "):
				currentRequirement = strings.TrimPrefix(line, "### Requirement: ")
				requirementScenarios[currentRequirement] = 0
			case strings.HasPrefix(line, "#### Scenario: "):
				if currentRequirement == "" {
					file.Close()
					t.Fatalf("scenario before requirement in %s: %s", path, line)
				}
				scenario := strings.TrimPrefix(line, "#### Scenario: ")
				key := traceabilityKey{capability: capability, requirement: currentRequirement, scenario: scenario}
				if _, duplicate := result[key]; duplicate {
					file.Close()
					t.Fatalf("duplicate v2 spec scenario: %s", key)
				}
				result[key] = struct{}{}
				requirementScenarios[currentRequirement]++
			}
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			t.Fatalf("scan v2 spec %s: %v", path, err)
		}
		if err := file.Close(); err != nil {
			t.Fatalf("close v2 spec %s: %v", path, err)
		}
		for requirement, count := range requirementScenarios {
			if count == 0 {
				t.Errorf("v2 requirement has no scenario: %s / %s", capability, requirement)
			}
		}
	}
	return result
}

func readV2TraceabilityTable(t *testing.T) map[traceabilityKey]struct{} {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "v2", "TEST_TRACEABILITY.md")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open v2 traceability table: %v", err)
	}
	defer file.Close()

	validVerification := map[string]struct{}{
		"unit":                 {},
		"integration":          {},
		"e2e":                  {},
		"spike":                {},
		"manual-compatibility": {},
	}
	result := make(map[traceabilityKey]struct{})
	lineNumber := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		columns := strings.Split(line, "|")
		if len(columns) != 7 {
			t.Fatalf("invalid traceability row at line %d: got %d columns", lineNumber, len(columns)-2)
		}
		key := traceabilityKey{
			capability:  strings.Trim(strings.TrimSpace(columns[1]), "`"),
			requirement: strings.TrimSpace(columns[2]),
			scenario:    strings.TrimSpace(columns[3]),
		}
		if key.capability == "" || key.requirement == "" || key.scenario == "" {
			t.Fatalf("empty traceability identity at line %d", lineNumber)
		}
		if _, duplicate := result[key]; duplicate {
			t.Fatalf("duplicate traceability row at line %d: %s", lineNumber, key)
		}

		verification := splitAndTrim(columns[4])
		if len(verification) == 0 {
			t.Errorf("traceability row has no verification type at line %d: %s", lineNumber, key)
		}
		for _, kind := range verification {
			if _, ok := validVerification[kind]; !ok {
				t.Errorf("unknown verification type %q at line %d: %s", kind, lineNumber, key)
			}
		}
		if !taskReferencePattern.MatchString(columns[5]) {
			t.Errorf("traceability row has no task reference at line %d: %s", lineNumber, key)
		}
		result[key] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan v2 traceability table: %v", err)
	}
	return result
}

func splitAndTrim(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	sort.Strings(result)
	return result
}
