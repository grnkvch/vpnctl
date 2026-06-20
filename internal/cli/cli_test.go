package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteWithoutArgsPrintsHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute(nil, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "vpnctl manages a personal WireGuard VPN") {
		t.Fatalf("expected help output, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
}

func TestExecuteVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"version"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if got := strings.TrimSpace(stdout.String()); got != "vpnctl 0.1.0-dev" {
		t.Fatalf("unexpected version output: %q", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
}

func TestExecuteUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"wat"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected empty stdout, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "unknown command: wat") {
		t.Fatalf("expected unknown command error, got %q", stderr.String())
	}
}

func TestExecuteInitCreatesStateLayout(t *testing.T) {
	t.Chdir(t.TempDir())

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"init"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "initialized vpnctl state in .vpnctl") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}

	assertExists(t, ".vpnctl/state.json")
	assertExists(t, ".vpnctl/rulesets/default.json")
	assertExists(t, ".vpnctl/secrets/clients")
	assertExists(t, ".vpnctl/generated/wireguard")
	assertExists(t, ".vpnctl/generated/mihomo")
	assertExists(t, ".vpnctl/generated/delivery")
	assertExists(t, ".vpnctl/.gitignore")
}

func TestExecuteInitIsIdempotent(t *testing.T) {
	t.Chdir(t.TempDir())

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := Execute([]string{"init"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected first init to succeed, got %d, stderr %q", code, stderr.String())
	}

	statePath := filepath.Join(".vpnctl", "state.json")
	original, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Execute([]string{"init"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected second init to succeed, got %d, stderr %q", code, stderr.String())
	}

	current, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state after second init: %v", err)
	}
	if string(current) != string(original) {
		t.Fatalf("expected state file to remain unchanged")
	}
}

func TestExecuteInitSupportsCustomStateDir(t *testing.T) {
	t.Chdir(t.TempDir())

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"--state-dir", "custom-state", "init"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr %q", code, stderr.String())
	}
	assertExists(t, "custom-state/state.json")
	assertExists(t, "custom-state/rulesets/default.json")
}

func TestExecuteSetupDryRunPrintsPlanWithoutCreatingState(t *testing.T) {
	t.Chdir(t.TempDir())

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"setup", "--endpoint", "198.211.99.116", "--dry-run"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"setup plan (dry-run)",
		"endpoint: 198.211.99.116",
		"wireguard port: 51820/udp",
		"wireguard subnet: 10.66.0.0/24",
		"would install required VPN packages",
		"would not perform a full system upgrade",
		"would enable firewall",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected setup output to contain %q, got %q", want, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
	if _, err := os.Stat(".vpnctl"); !os.IsNotExist(err) {
		t.Fatalf("expected dry-run not to create .vpnctl, stat err: %v", err)
	}
}

func TestExecuteSetupRequiresEndpoint(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"setup", "--dry-run"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "setup failed: --endpoint is required") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestExecuteSetupDryRunUsesCustomFlags(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{
		"--state-dir", "custom-state",
		"setup",
		"--endpoint", "vpn.example.com",
		"--port", "51821",
		"--interface", "wg-vpn",
		"--subnet", "10.10.10.0/24",
		"--dns", "1.1.1.1, 8.8.8.8",
		"--external-interface", "eth0",
		"--ssh-port", "2222",
		"--no-enable-ufw",
		"--dry-run",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr %q", code, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"state directory: custom-state",
		"endpoint: vpn.example.com",
		"wireguard interface: wg-vpn",
		"wireguard port: 51821/udp",
		"wireguard subnet: 10.10.10.0/24",
		"client dns: 1.1.1.1, 8.8.8.8",
		"external interface: eth0",
		"ssh port allowed in firewall: 2222/tcp",
		"enable firewall: false",
		"would leave firewall disabled",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected setup output to contain %q, got %q", want, output)
		}
	}
}

func TestExecuteSetupWithoutDryRunIsNotImplementedYet(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"setup", "--endpoint", "198.211.99.116"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "setup without --dry-run is not implemented yet") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestExecuteServerInitWritesState(t *testing.T) {
	t.Chdir(t.TempDir())

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{
		"server", "init",
		"--endpoint", "198.211.99.116",
		"--subnet", "10.10.10.0/24",
		"--dns", "1.1.1.1,8.8.8.8",
		"--external-interface", "eth0",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "configured server main in .vpnctl") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}

	data, err := os.ReadFile(filepath.Join(".vpnctl", "state.json"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	for _, want := range []string{
		`"public_endpoint": "198.211.99.116"`,
		`"wireguard_subnet": "10.10.10.0/24"`,
		`"dns_servers": [`,
		`"external_interface": "eth0"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("expected state to contain %q, got %s", want, string(data))
		}
	}
}

func TestExecuteServerInitRequiresForceToOverwrite(t *testing.T) {
	t.Chdir(t.TempDir())

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := Execute([]string{"server", "init", "--endpoint", "198.211.99.116"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected first server init to succeed, got %d, stderr %q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := Execute([]string{"server", "init", "--endpoint", "203.0.113.10"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "server already configured") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"server", "init", "--endpoint", "203.0.113.10", "--force"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected force server init to succeed, got %d, stderr %q", code, stderr.String())
	}
}

func TestExecuteServerInitValidatesEndpoint(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"server", "init"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--endpoint is required") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func assertExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}
