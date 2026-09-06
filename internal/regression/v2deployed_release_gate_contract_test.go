package regression

import (
	"encoding/json"
	"os"
	"os/exec"
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
	registry := readContractFile(t, filepath.Join(repositoryRoot, "test", "v2lab", "deployed-release-gate", "stages.json"))
	contract := script + "\n" + registry
	for _, required := range []string{
		"prepare <vMAJOR.MINOR.PATCH>", "run-automated <evidence-directory>",
		"run-automated --resume <evidence-directory>",
		"run-fast <evidence-directory>", "run-fast --resume <evidence-directory>",
		"run-vm <evidence-directory>", "run-vm --resume <evidence-directory>",
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
		if !strings.Contains(contract, required) {
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

func TestV2DeployedReleaseGateStageRegistryContract(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "test", "v2lab", "deployed-release-gate", "stages.json")
	var registry struct {
		SchemaVersion   int `json:"schema_version"`
		ContractVersion int `json:"contract_version"`
		Stages          []struct {
			Name         string   `json:"name"`
			Phase        string   `json:"phase"`
			Order        int      `json:"order"`
			UsesLima     bool     `json:"uses_lima"`
			Command      string   `json:"command"`
			Dependencies []string `json:"dependencies"`
		} `json:"stages"`
	}
	if err := json.Unmarshal([]byte(readContractFile(t, path)), &registry); err != nil {
		t.Fatal(err)
	}
	if registry.SchemaVersion != 1 || registry.ContractVersion != 2 || len(registry.Stages) != 19 {
		t.Fatalf("registry header = %+v", registry)
	}
	wantFast := []string{"traceability", "openspec", "go-test", "go-race", "go-vet", "credential-lifecycle", "update-restore"}
	wantVM := []string{"personal-client", "restricted-process", "transport-supervision", "watchdog-confirm", "watchdog-timeout", "node-transport", "fleet-isolation", "adversarial", "tunnel-release", "ingress-release", "failure", "capacity"}
	var fast, vm []string
	lastOrder := 0
	for _, stage := range registry.Stages {
		if stage.Order <= lastOrder || stage.Command == "" {
			t.Fatalf("non-monotonic or empty stage: %+v", stage)
		}
		lastOrder = stage.Order
		if stage.Phase == "fast" && !stage.UsesLima {
			fast = append(fast, stage.Name)
		} else if stage.Phase == "vm" && stage.UsesLima {
			vm = append(vm, stage.Name)
		} else {
			t.Fatalf("invalid phase/Lima mapping: %+v", stage)
		}
		if stage.Name == "failure" && strings.Join(stage.Dependencies, ",") != "tunnel-release,ingress-release" {
			t.Fatalf("failure dependencies = %v", stage.Dependencies)
		}
	}
	if strings.Join(fast, ",") != strings.Join(wantFast, ",") || strings.Join(vm, ",") != strings.Join(wantVM, ",") {
		t.Fatalf("stage order fast=%v vm=%v", fast, vm)
	}
	if registry.Stages[len(registry.Stages)-1].Name != "capacity" || registry.Stages[len(registry.Stages)-1].Command != "scripts/v2capacity-e2e.sh verify" {
		t.Fatalf("capacity is not the unchanged final command: %+v", registry.Stages[len(registry.Stages)-1])
	}
}

func TestV2DeployedReleaseGateCleanStateManifestContract(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "test", "v2lab", "deployed-release-gate", "clean-state.json")
	data := readContractFile(t, path)
	var manifest map[string]any
	if err := json.Unmarshal([]byte(data), &manifest); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"gateway", "node"} {
		value, ok := manifest[role].(map[string]any)
		if !ok {
			t.Fatalf("missing role %s", role)
		}
		for _, class := range []string{"paths_absent", "units_inactive", "process_prefixes_absent", "tcp_ports_free", "udp_ports_free", "namespaces_absent", "nftables_absent", "interfaces_absent", "ip_rules_absent", "routes_absent", "packages_absent"} {
			if _, ok := value[class].([]any); !ok {
				t.Errorf("%s.%s is not an array", role, class)
			}
		}
	}
	for _, required := range []string{
		"/etc/vpnctl-v2-capacity", "/var/lib/vpnctl", "vpnctl-v2-task86-standard.service",
		"vpnctl-v2-watchdog-test", "vpnctl-v2-spike-tunnel-auth.service", "vpnctl_v2_capacity_clients",
		"v2capwg", "v2capc5", "vpnctl-v2-pc-clash", "vpnctl-v2-rnode", "vpnctl-v2-dns-gateway",
		"nginx-common",
	} {
		if !strings.Contains(data, required) {
			t.Errorf("clean-state manifest is missing %q", required)
		}
	}
	for _, forbidden := range []string{`"/"`, `"*"`, `"?"`, `..`} {
		if strings.Contains(data, forbidden) {
			t.Errorf("clean-state manifest contains broad target %q", forbidden)
		}
	}
}

func TestV2StageTimingHelperWritesBoundedMonotonicPhases(t *testing.T) {
	t.Parallel()
	repositoryRoot := filepath.Join("..", "..")
	helper, err := filepath.Abs(filepath.Join(repositoryRoot, "scripts", "lib", "v2-stage-timing.sh"))
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "child-timing.json")
	command := exec.Command("bash", "-c", `. "$1"; VPNCTL_V2_TIMING_PRODUCER=contract-test; v2_timing_begin; v2_timing_mark setup; v2_timing_finish verification`, "timing-test", helper)
	command.Env = append(os.Environ(), "VPNCTL_V2_TIMING_OUTPUT="+output)
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("timing helper: %v: %s", err, combined)
	}
	var evidence struct {
		SchemaVersion int            `json:"schema_version"`
		Producer      string         `json:"producer"`
		Phases        map[string]int `json:"phases"`
	}
	if err := json.Unmarshal([]byte(readContractFile(t, output)), &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.SchemaVersion != 1 || evidence.Producer != "contract-test" || len(evidence.Phases) != 2 {
		t.Fatalf("timing evidence = %+v", evidence)
	}
	for phase, duration := range evidence.Phases {
		if duration < 0 {
			t.Fatalf("negative %s duration: %d", phase, duration)
		}
	}
}

func TestV2CleanStateWitnessIsReadOnlyAndCoversEveryResourceClass(t *testing.T) {
	t.Parallel()
	script := readContractFile(t, filepath.Join("..", "..", "scripts", "v2release-clean-state.sh"))
	for _, required := range []string{
		"paths_absent", "units_inactive", "process_prefixes_absent", "tcp_ports_free", "udp_ports_free",
		"namespaces_absent", "nftables_absent", "interfaces_absent", "ip_rules_absent", "routes_absent", "packages_absent",
		"sudo test ! -e", "systemctl is-active", "/proc/[0-9]*/exe", "ss -H -ltn", "ss -H -lun",
		"ip netns list", "nft list table", "ip link show", "ip rule show", "ip route show", "dpkg-query -W",
		"owner-marker:", "clean-state witness refuses to replace output",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("clean-state witness is missing %q", required)
		}
	}
	for _, forbidden := range []string{"rm -", "systemctl stop", "systemctl disable", "ip netns delete", "nft delete", "ip link delete", "apt-get"} {
		if strings.Contains(script, forbidden) {
			t.Errorf("clean-state witness contains mutation %q", forbidden)
		}
	}
}

func TestV2SharedSessionHarnessesPreserveAlreadyRunningFixtures(t *testing.T) {
	t.Parallel()
	repositoryRoot := filepath.Join("..", "..")
	for _, name := range []string{"v2node-transport-e2e.sh", "v2fleet-isolation-e2e.sh", "v2adversarial-e2e.sh", "v2capacity-e2e.sh"} {
		script := readContractFile(t, filepath.Join(repositoryRoot, "scripts", name))
		for _, required := range []string{"if instance_running \"$instance\"; then", "printf -v \"$marker\" '%s' true", `if [ "$node_started" = true ]`, `if [ "$gateway_started" = true ]`, "v2_timing_"} {
			if !strings.Contains(script, required) {
				t.Errorf("%s does not preserve shared fixture/timing contract %q", name, required)
			}
		}
	}
}
