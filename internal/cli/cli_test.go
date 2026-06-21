package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/app"
	"github.com/vgrinkevich/vpnctl/internal/setup"
	"github.com/vgrinkevich/vpnctl/internal/state"
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

func TestExecuteGlobalHelpPrintsHelpOnce(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"--help"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if got := strings.Count(stdout.String(), "vpnctl manages a personal WireGuard VPN"); got != 1 {
		t.Fatalf("expected help once, got %d occurrences in %q", got, stdout.String())
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

func TestExecuteSetupRunsSetup(t *testing.T) {
	restore := stubSetupRunner(func(_ context.Context, opts setup.Options, _ setup.Runtime) (setup.Result, error) {
		if opts.Endpoint != "198.211.99.116" {
			t.Fatalf("unexpected endpoint: %q", opts.Endpoint)
		}
		return setup.Result{
			StateDir:            opts.StateDir,
			ExternalInterface:   "eth0",
			WireGuardConfigPath: "/etc/wireguard/wg0.conf",
		}, nil
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"setup", "--endpoint", "198.211.99.116"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "wireguard config: /etc/wireguard/wg0.conf") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
}

func TestExecuteApplyDryRunRunsApply(t *testing.T) {
	restore := stubApplyRunner(func(_ context.Context, input app.ApplyInput) (app.ApplyResult, error) {
		if input.StateDir != ".vpnctl" {
			t.Fatalf("unexpected state dir: %q", input.StateDir)
		}
		if !input.DryRun {
			t.Fatalf("expected dry-run")
		}
		if input.Stdout == nil {
			t.Fatalf("expected stdout writer")
		}
		return app.ApplyResult{
			StateDir:            input.StateDir,
			ExternalInterface:   "eth0",
			WireGuardConfigPath: "/etc/wireguard/wg0.conf",
			ActivePeers:         1,
		}, nil
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"apply", "--dry-run"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr %q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no CLI summary for dry-run, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
}

func TestExecuteApplyPrintsSummary(t *testing.T) {
	restore := stubApplyRunner(func(_ context.Context, input app.ApplyInput) (app.ApplyResult, error) {
		if input.DryRun {
			t.Fatalf("did not expect dry-run")
		}
		return app.ApplyResult{
			StateDir:            input.StateDir,
			ExternalInterface:   "eth0",
			WireGuardConfigPath: "/etc/wireguard/wg0.conf",
			ActivePeers:         2,
		}, nil
	})
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"apply"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr %q", code, stderr.String())
	}
	for _, want := range []string{
		"applied WireGuard config to /etc/wireguard/wg0.conf",
		"external interface: eth0",
		"active peers: 2",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("expected stdout to contain %q, got %q", want, stdout.String())
		}
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

func TestExecuteClientCreateWritesState(t *testing.T) {
	t.Chdir(t.TempDir())
	restore := stubClientKeyGenerator(validClientKeyGenerator())
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"server", "init", "--endpoint", "198.211.99.116"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected server init to succeed, got %d, stderr %q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := Execute([]string{
		"client", "create", "macbook",
		"--name", "Work MacBook",
		"--platform", "macos",
		"--tags", "laptop,personal",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected client create to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "created client macbook with ip 10.66.0.2") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		t.Fatalf("stdout leaked private key")
	}

	data, err := os.ReadFile(filepath.Join(".vpnctl", "state.json"))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	for _, want := range []string{
		`"id": "macbook"`,
		`"name": "Work MacBook"`,
		`"platform": "macos"`,
		`"assigned_ip": "10.66.0.2"`,
		`"wireguard_public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("expected state to contain %q, got %s", want, string(data))
		}
	}
	assertExists(t, filepath.Join(".vpnctl", "secrets", "clients", "macbook.key"))
}

func TestExecuteClientCreateAllowsFlagsBeforeID(t *testing.T) {
	t.Chdir(t.TempDir())
	restore := stubClientKeyGenerator(validClientKeyGenerator())
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"server", "init", "--endpoint", "198.211.99.116"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected server init to succeed, got %d, stderr %q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := Execute([]string{"client", "create", "--platform", "ios", "iphone"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected client create to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "created client iphone with ip 10.66.0.2") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
}

func TestExecuteClientListShowAndRevoke(t *testing.T) {
	t.Chdir(t.TempDir())
	restore := stubClientKeyGenerator(validClientKeyGenerator())
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"server", "init", "--endpoint", "198.211.99.116"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected server init to succeed, got %d, stderr %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Execute([]string{"client", "create", "iphone", "--platform", "ios", "--tags", "phone,personal"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected iphone create to succeed, got %d, stderr %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Execute([]string{"client", "create", "macbook", "--platform", "macos"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected macbook create to succeed, got %d, stderr %q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := Execute([]string{"client", "list"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected client list to succeed, got %d, stderr %q", code, stderr.String())
	}
	for _, want := range []string{
		"iphone\tactive\t10.66.0.2\tios\tiphone\n",
		"macbook\tactive\t10.66.0.3\tmacos\tmacbook\n",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("expected client list to contain %q, got %q", want, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"client", "show", "iphone"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected client show to succeed, got %d, stderr %q", code, stderr.String())
	}
	for _, want := range []string{
		"id: iphone\n",
		"platform: ios\n",
		"status: active\n",
		"assigned ip: 10.66.0.2\n",
		"wireguard public key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n",
		"tags: phone, personal\n",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("expected client show to contain %q, got %q", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		t.Fatalf("client show leaked private key")
	}

	restoreRotated := stubClientKeyGenerator(rotatedClientKeyGenerator())
	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"client", "rotate-keys", "iphone", "--yes"}, &stdout, &stderr)
	restoreRotated()
	if code != 0 {
		t.Fatalf("expected client rotate-keys to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "rotated keys for client iphone") {
		t.Fatalf("unexpected rotate-keys stdout: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=") {
		t.Fatalf("client rotate-keys leaked private key")
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"client", "show", "iphone"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected rotated client show to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "wireguard public key: AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\n") {
		t.Fatalf("expected rotated public key in show output, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"client", "revoke", "iphone", "--reason", "lost"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected client revoke to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "revoked client iphone") {
		t.Fatalf("unexpected revoke stdout: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"client", "show", "iphone"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected revoked client show to succeed, got %d, stderr %q", code, stderr.String())
	}
	for _, want := range []string{
		"status: revoked\n",
		"revocation reason: lost\n",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("expected revoked client show to contain %q, got %q", want, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"client", "list"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected client list to succeed, got %d, stderr %q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "iphone") {
		t.Fatalf("expected revoked client to be hidden by default, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "macbook\tactive\t10.66.0.3\tmacos\tmacbook\n") {
		t.Fatalf("expected active client in list, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"client", "list", "--all"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected client list --all to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "iphone\trevoked\t10.66.0.2\tios\tiphone\n") {
		t.Fatalf("expected revoked client in list --all, got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"client", "delete", "macbook"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected client delete without --yes to fail, got %d", code)
	}
	if !strings.Contains(stderr.String(), "client delete requires --yes") {
		t.Fatalf("unexpected delete stderr: %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"client", "delete", "macbook", "--yes"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected client delete to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "deleted client macbook") {
		t.Fatalf("unexpected delete stdout: %q", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(".vpnctl", "secrets", "clients", "macbook.key")); !os.IsNotExist(err) {
		t.Fatalf("expected deleted client secret to be removed, stat err: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"client", "list", "--all"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected client list --all after delete to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "macbook\tdeleted\t10.66.0.3\tmacos\tmacbook\n") {
		t.Fatalf("expected deleted client in list --all, got %q", stdout.String())
	}
}

func TestExecuteClientExportWireGuardWritesConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	restore := stubClientKeyGenerator(validClientKeyGenerator())
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"server", "init", "--endpoint", "198.211.99.116"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected server init to succeed, got %d, stderr %q", code, stderr.String())
	}
	st, err := state.Load(".vpnctl")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	st.Server.WireGuardPublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	if err := state.Save(".vpnctl", st); err != nil {
		t.Fatalf("save state: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Execute([]string{"client", "create", "iphone"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected client create to succeed, got %d, stderr %q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := Execute([]string{"client", "export", "iphone", "--type", "wireguard"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected client export to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "wrote wireguard config to .vpnctl/generated/delivery/iphone.conf") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "copy with: scp root@198.211.99.116:") {
		t.Fatalf("expected scp hint, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		t.Fatalf("stdout leaked private key")
	}
	data, err := os.ReadFile(filepath.Join(".vpnctl", "generated", "delivery", "iphone.conf"))
	if err != nil {
		t.Fatalf("read exported config: %v", err)
	}
	if !strings.Contains(string(data), "PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n") {
		t.Fatalf("expected exported config to contain private key")
	}
}

func TestExecuteClientExportClashWritesProfileAndWarning(t *testing.T) {
	t.Chdir(t.TempDir())
	restore := stubClientKeyGenerator(validClientKeyGenerator())
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"server", "init", "--endpoint", "198.211.99.116"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected server init to succeed, got %d, stderr %q", code, stderr.String())
	}
	st, err := state.Load(".vpnctl")
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	st.Server.WireGuardPublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	if err := state.Save(".vpnctl", st); err != nil {
		t.Fatalf("save state: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Execute([]string{"client", "create", "iphone"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected client create to succeed, got %d, stderr %q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := Execute([]string{"client", "export", "iphone", "--type", "clash", "--ruleset", "default"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected clash export to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "wrote clash config to .vpnctl/generated/delivery/iphone.clash.yaml") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		t.Fatalf("stdout leaked private key")
	}
	if !strings.Contains(stderr.String(), "warning: no custom DNS configured") {
		t.Fatalf("expected fallback DNS warning, got %q", stderr.String())
	}
	data, err := os.ReadFile(filepath.Join(".vpnctl", "generated", "delivery", "iphone.clash.yaml"))
	if err != nil {
		t.Fatalf("read clash profile: %v", err)
	}
	for _, want := range []string{
		"mode: rule\n",
		"    private-key: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n",
		"  - DOMAIN-SUFFIX,chatgpt.com,VPN\n",
		"  - MATCH,DIRECT\n",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("expected clash profile to contain %q, got:\n%s", want, string(data))
		}
	}
}

func TestExecuteClientExportRequiresType(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"client", "export", "iphone"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "--type is required") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestExecuteRulesetAddShowAndList(t *testing.T) {
	t.Chdir(t.TempDir())

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute([]string{
		"ruleset", "add", "custom-ai",
		"--domain", "ChatGPT.com, openai.com,claude.ai",
		"--name", "Custom AI",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected ruleset add to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "saved ruleset custom-ai with 3 domains") {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}

	data, err := os.ReadFile(filepath.Join(".vpnctl", "rulesets", "custom-ai.json"))
	if err != nil {
		t.Fatalf("read ruleset: %v", err)
	}
	for _, want := range []string{
		`"id": "custom-ai"`,
		`"name": "Custom AI"`,
		`"type": "domain-suffix"`,
		`"chatgpt.com"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("expected ruleset to contain %q, got %s", want, string(data))
		}
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"ruleset", "show", "custom-ai"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected ruleset show to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "domains: chatgpt.com, openai.com, claude.ai") {
		t.Fatalf("unexpected show output: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Execute([]string{"ruleset", "list"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected ruleset list to succeed, got %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "custom-ai\tdomain-suffix\t3 domains") {
		t.Fatalf("unexpected list output: %q", stdout.String())
	}
}

func TestExecuteRulesetAddRejectsInvalidType(t *testing.T) {
	t.Chdir(t.TempDir())

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := Execute([]string{"ruleset", "add", "bad", "--type", "ip-cidr", "--domain", "chatgpt.com"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unsupported ruleset type: ip-cidr") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestExecuteClientCreateRequiresServer(t *testing.T) {
	t.Chdir(t.TempDir())
	restore := stubClientKeyGenerator(validClientKeyGenerator())
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"init"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected init to succeed, got %d, stderr %q", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := Execute([]string{"client", "create", "iphone"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "server is not configured") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

type stubKeyGenerator struct {
	pair state.ClientKeyPair
}

func (g stubKeyGenerator) GenerateClientKeyPair(context.Context) (state.ClientKeyPair, error) {
	return g.pair, nil
}

func validClientKeyGenerator() state.ClientKeyGenerator {
	return stubKeyGenerator{pair: state.ClientKeyPair{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKey:  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
	}}
}

func rotatedClientKeyGenerator() state.ClientKeyGenerator {
	return stubKeyGenerator{pair: state.ClientKeyPair{
		PrivateKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
		PublicKey:  "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
	}}
}

func stubClientKeyGenerator(generator state.ClientKeyGenerator) func() {
	original := newClientKeyGenerator
	newClientKeyGenerator = func() state.ClientKeyGenerator {
		return generator
	}
	return func() {
		newClientKeyGenerator = original
	}
}

func stubSetupRunner(runner func(context.Context, setup.Options, setup.Runtime) (setup.Result, error)) func() {
	original := runSetup
	runSetup = runner
	return func() {
		runSetup = original
	}
}

func stubApplyRunner(runner func(context.Context, app.ApplyInput) (app.ApplyResult, error)) func() {
	original := runApply
	runApply = runner
	return func() {
		runApply = original
	}
}

func assertExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}
