package regression

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2DeployedReleaseGateContract(t *testing.T) {
	t.Parallel()
	repositoryRoot := filepath.Join("..", "..")
	scriptPath := filepath.Join(repositoryRoot, "scripts", "v2deployed-release-gate.sh")
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("deployed release gate is not executable")
	}
	script := readContractFile(t, scriptPath)
	for _, required := range []string{
		"prepare <vMAJOR.MINOR.PATCH>", "run-automated <evidence-directory>",
		"run-automated --resume <evidence-directory>",
		"status <evidence-directory>", "finalize <evidence-directory>",
		"deployed release gate requires a clean source tree", "task 16.11 to be the only pending task",
		"grep -Eq -- '^- \\[ \\] 16[.]11 '",
		"source_commit_matches_clean_tree", "production_ready: true", "release_labeled: false",
		"TestV2RequirementTraceabilityIsComplete", "openspec validate vpnctl-v2 --strict --no-interactive",
		"go test -p 1 ./... -count=1", "go test -race -p 1 ./... -count=1", "go vet ./...",
		"v2credential-lifecycle-e2e.sh", "v2update-restore-e2e.sh", "v2node-transport-e2e.sh",
		"v2fleet-isolation-e2e.sh", "v2failure-e2e.sh", "v2adversarial-e2e.sh", "v2capacity-e2e.sh",
		"v2personal-client-test.sh", "v2transport-supervision-test.sh", "v2restricted-test.sh",
		"v2watchdog-test.sh", "v2tunnel-release-gate.sh", "v2ingress-release-gate.sh",
		"public_certificate_sha256", "provider_authenticated_request", "cleanup_succeeded",
		"Telegram helper differs from the candidate prepared by this gate", "shasum -a 256 -c",
		"go run ./cmd/vpnctl-release-verify", "Telegram gate used a different public certificate",
		"labeling remains a separate manual action", "cleanup_started_fixtures",
		"automated-attempts", "stage_contract_sha256", "find_reusable_attempt",
		"source_tree_sha256", "lima_image_digest", "stage_attempts",
		"restore_exact_fixtures_stopped", "(umask 022; execute_stage",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("deployed release gate is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"git tag", "git push", "BOT_TOKEN=", "api.telegram.org", "--token", "production_ready: false |",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("deployed release gate contains forbidden automatic action %q", forbidden)
		}
	}

	for _, name := range []string{"deployment.example.json", "clash-mi.example.json"} {
		path := filepath.Join(repositoryRoot, "test", "v2lab", "deployed-release-gate", name)
		var value map[string]any
		if err := json.Unmarshal([]byte(readContractFile(t, path)), &value); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if value["schema_version"] != float64(1) || value["status"] != "pending" {
			t.Errorf("%s is not a pending v1 evidence template", name)
		}
	}

	documentation := readContractFile(t, filepath.Join(repositoryRoot, "docs", "v2", "DEPLOYED_RELEASE_GATE.md"))
	for _, required := range []string{
		"same clean Git commit", "private node", "Clash Mi", "proxy-bound DNS", "selected UoT",
		"strict wrong-host rejection", "no observed fail-direct", "X-Telegram-Bot-Api-Secret-Token",
		"provider cleanup", "three checksum-governed assets", "trusted `scp`",
		"production_ready=true", "release_labeled=false",
	} {
		if !strings.Contains(documentation, required) {
			t.Errorf("deployed release gate documentation is missing %q", required)
		}
	}
}

func TestV2ReleaseVerifierContract(t *testing.T) {
	t.Parallel()
	repositoryRoot := filepath.Join("..", "..")
	verifier := readContractFile(t, filepath.Join(repositoryRoot, "cmd", "vpnctl-release-verify", "main.go"))
	for _, required := range []string{
		"DecodeReleaseChecksums", "VerifyReleaseChecksumRecord",
		"NewReleaseBundleInstaller", "installer.Inspect", "MigrationReversible", "NewV2ReleaseManifest",
		"release bundle differs from the production manifest",
		"standalone binary differs from bundle", "ubuntu-24.04-amd64", "sha256-and-bundle-verified",
	} {
		if !strings.Contains(verifier, required) {
			t.Errorf("release verifier is missing %q", required)
		}
	}
	for _, forbidden := range []string{"http.Get", "exec.Command", "PrivateKey", "signing-key", "releasetrust.PublicKey", "VerifyReleaseChecksums", "release-checksums.txt.sig"} {
		if strings.Contains(verifier, forbidden) {
			t.Errorf("release verifier contains forbidden capability %q", forbidden)
		}
	}
}
