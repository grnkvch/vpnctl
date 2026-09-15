package regression

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2GatewayEnrollmentE2EContract(t *testing.T) {
	t.Parallel()
	repositoryRoot := filepath.Join("..", "..")
	scriptPath := filepath.Join(repositoryRoot, "scripts", "v2gateway-enrollment-e2e.sh")
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("gateway enrollment E2E entrypoint is not executable")
	}
	script := readContractFile(t, scriptPath)
	for _, required := range []string{
		"verify <absolute-release-assets-directory>",
		"vpnctl-v2-gateway", "vpnctl-v2-node",
		"sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7",
		"assert_instance_contract \"$gateway_instance\" Stopped",
		"assert_instance_contract \"$node_instance\" Stopped",
		"go run ./cmd/vpnctl-release-verify",
		"gateway-enrollment-e2e-v1", "trap cleanup_on_exit", "write_safe_diagnostics",
		"owned_guest_root", `grep -Fxq "$owner_value" "$guest_root/.owner"`, "assert_final_clean",
		"purge_role \"$node_instance\" purge-node",
		"purge_role \"$gateway_instance\" purge-gateway",
		"vpnctl init --gateway", "vpnctl init --node",
		"pty_secret.py\" invite", "pty_secret.py\" join",
		"systemctl stop nginx", "vpnctl repair --yes --json",
		"ControlMaster=no", "ControlPath=none", "ControlPersist=no",
		"apt-get remove --purge --yes nginx", "systemctl start ufw",
		"selected request did not move WireGuard counters",
		"fixture_state_restored: \"stopped\"",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("gateway enrollment E2E is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"v2deployed-release-gate", "v2capacity-e2e", "v1-migrate",
		"--resume", "git tag", "git push", "curl.*Authorization",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("gateway enrollment E2E contains forbidden expansion %q", forbidden)
		}
	}
	if strings.Index(script, `purge_role "$node_instance" purge-node`) >
		strings.Index(script, `purge_role "$gateway_instance" purge-gateway`) {
		t.Fatal("owner-scoped cleanup must purge Node before Gateway")
	}
	trapIndex := strings.LastIndex(script, "trap cleanup_on_exit EXIT")
	firstStartIndex := strings.LastIndex(script, `start_fixture "$gateway_instance" gateway_started`)
	if trapIndex < 0 || firstStartIndex < 0 || trapIndex > firstStartIndex {
		t.Fatal("cleanup trap must be active before the first fixture starts")
	}
	markerIndex := strings.Index(script, `printf -v "$marker" '%s' true`)
	startCommandIndex := strings.Index(script, `limactl start --tty=false "$instance"`)
	if markerIndex < 0 || startCommandIndex < 0 || markerIndex > startCommandIndex {
		t.Fatal("fixture ownership marker must be set before the fallible start command")
	}
	if strings.Contains(script, `cat "$secret_runtime/invite.token" >`) {
		t.Fatal("invite token must not be redirected into a host artifact")
	}
	if strings.Contains(script, "set -x") {
		t.Fatal("secret-bearing orchestration must not enable shell tracing")
	}

	helperPath := filepath.Join(repositoryRoot, "test", "v2lab", "gateway-enrollment-e2e", "pty_secret.py")
	helper := readContractFile(t, helperPath)
	for _, required := range []string{
		"MAXIMUM_TTY_BYTES", "MAXIMUM_RESULT_BYTES", "termios.ECHO", "os.O_EXCL", "0o600",
		`pathlib.Path("/run/vpnctl/gateway-enrollment-e2e")`,
		`pathlib.Path("/var/lib/vpnctl-v2-gateway-enrollment-e2e/runtime")`,
		"stderr=subprocess.DEVNULL", "result_path.unlink()", "token_path.unlink()",
	} {
		if !strings.Contains(helper, required) {
			t.Errorf("gateway enrollment PTY helper is missing %q", required)
		}
	}
	if strings.Contains(helper, "print(token") || strings.Contains(helper, "capture_output=True") {
		t.Fatal("guest PTY helper contains a token-output or subprocess-capture path")
	}

	syntax := exec.Command("bash", "-n", scriptPath)
	if output, err := syntax.CombinedOutput(); err != nil {
		t.Fatalf("gateway enrollment E2E shell syntax: %v\n%s", err, output)
	}
}

func TestV2GatewayEnrollmentPTYSecretBehavior(t *testing.T) {
	t.Parallel()
	repositoryRoot := filepath.Join("..", "..")
	testPath := filepath.Join(repositoryRoot, "test", "v2lab", "gateway-enrollment-e2e", "test_pty_secret.py")
	command := exec.Command("python3", testPath)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("PTY secret behavior: %v\n%s", err, output)
	}
}
