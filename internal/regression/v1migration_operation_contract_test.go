package regression

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type v1MigrationOperationContract struct {
	SchemaVersion     int    `json:"schema_version"`
	ProductBranch     string `json:"product_branch"`
	OperationalBranch string `json:"operational_branch"`
	V1ReleaseRef      string `json:"v1_release_ref"`
	FixtureName       string `json:"fixture_name"`
	AllowedChanges    struct {
		Prefixes []string `json:"prefixes"`
		Globs    []string `json:"globs"`
		Exact    []string `json:"exact"`
	} `json:"allowed_changes"`
	ForbiddenExamples []string `json:"forbidden_examples"`
}

func TestV1MigrationOperationalPathIsolation(t *testing.T) {
	t.Parallel()

	contractPath, err := filepath.Abs(filepath.Join("..", "..", "test", "v1migration", "operation-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	var contract v1MigrationOperationContract
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatal(err)
	}
	if contract.SchemaVersion != 1 || contract.ProductBranch != "feat/vpnctl-v2" ||
		contract.OperationalBranch != "ops/v1-to-v2-migration" || contract.V1ReleaseRef != "0.1.0" ||
		contract.FixtureName != "vpnctl-v1-migration" {
		t.Fatalf("unexpected migration operation identity: %+v", contract)
	}
	assertSortedUniqueMigrationContractValues(t, "prefixes", contract.AllowedChanges.Prefixes)
	assertSortedUniqueMigrationContractValues(t, "globs", contract.AllowedChanges.Globs)
	assertSortedUniqueMigrationContractValues(t, "exact", contract.AllowedChanges.Exact)

	allowed := []string{
		"cmd/vpnctl-v1-migrate/main.go",
		"docs/operations/v1-migration/RUNBOOK_RU.md",
		"internal/lifecycle/v1_migration.go",
		"internal/lifecycle/testdata/v1_conversion_result.golden.json",
		"internal/regression/v1migration_gate_contract_test.go",
		"openspec/changes/isolate-one-time-v1-migration/tasks.md",
		"scripts/migrate-v1-to-v2.sh",
		"scripts/v1migration-gate.sh",
		"test/v1migration/native.sh",
		"test/v2lab/migration/reconnect.sh",
	}
	for _, allowedPath := range allowed {
		if !v1MigrationOperationalPathAllowed(contract, allowedPath) {
			t.Errorf("migration-only path rejected: %s", allowedPath)
		}
	}
	for _, forbidden := range contract.ForbiddenExamples {
		if v1MigrationOperationalPathAllowed(contract, forbidden) {
			t.Errorf("shared product path accepted as migration-only: %s", forbidden)
		}
	}
	for _, unsafe := range []string{"", "/etc/passwd", "../scripts/release.sh", "test/v1migration/../v2lab/lima.yaml", "docs\\operations\\v1-migration\\RUNBOOK_RU.md"} {
		if v1MigrationOperationalPathAllowed(contract, unsafe) {
			t.Errorf("unsafe path accepted as migration-only: %q", unsafe)
		}
	}
}

func v1MigrationOperationalPathAllowed(contract v1MigrationOperationContract, candidate string) bool {
	if candidate == "" || strings.HasPrefix(candidate, "/") || strings.Contains(candidate, "\\") ||
		path.Clean(candidate) != candidate || strings.HasPrefix(candidate, "../") {
		return false
	}
	for _, exact := range contract.AllowedChanges.Exact {
		if candidate == exact {
			return true
		}
	}
	for _, prefix := range contract.AllowedChanges.Prefixes {
		if strings.HasSuffix(prefix, "/") && strings.HasPrefix(candidate, prefix) && candidate != prefix {
			return true
		}
	}
	for _, pattern := range contract.AllowedChanges.Globs {
		matched, err := path.Match(pattern, candidate)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func assertSortedUniqueMigrationContractValues(t *testing.T, name string, values []string) {
	t.Helper()
	if len(values) == 0 {
		t.Fatalf("migration operation %s are empty", name)
	}
	want := append([]string(nil), values...)
	sort.Strings(want)
	for index := range values {
		if values[index] != want[index] {
			t.Fatalf("migration operation %s are not sorted: %v", name, values)
		}
		if index > 0 && values[index] == values[index-1] {
			t.Fatalf("migration operation %s contain duplicate %q", name, values[index])
		}
	}
}
