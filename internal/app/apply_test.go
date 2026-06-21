package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/state"
)

const (
	applyServerPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	applyServerPublicKey  = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	applyClientPublicKey  = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
)

type applyFakeExecutor struct {
	uid      int
	goos     string
	goarch   string
	commands []applyFakeCommand
	outputs  map[string]string
}

type applyFakeCommand struct {
	name string
	args []string
}

func newApplyFakeExecutor() *applyFakeExecutor {
	return &applyFakeExecutor{
		uid:    0,
		goos:   "linux",
		goarch: "amd64",
		outputs: map[string]string{
			"ip route get 1.1.1.1": "1.1.1.1 via 203.0.113.1 dev eth0 src 198.211.99.116 uid 0\n",
		},
	}
}

func (e *applyFakeExecutor) CurrentUID() int { return e.uid }
func (e *applyFakeExecutor) GOOS() string    { return e.goos }
func (e *applyFakeExecutor) GOARCH() string  { return e.goarch }

func (e *applyFakeExecutor) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (e *applyFakeExecutor) WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func (e *applyFakeExecutor) MkdirAll(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

func (e *applyFakeExecutor) Chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

func (e *applyFakeExecutor) Run(_ context.Context, name string, args []string, _ string) (string, error) {
	e.commands = append(e.commands, applyFakeCommand{name: name, args: append([]string(nil), args...)})
	return e.outputs[name+" "+strings.Join(args, " ")], nil
}

func TestApplyWritesServerConfigWithActivePeers(t *testing.T) {
	dir := configuredApplyState(t, "")
	systemRoot := fakeApplyUbuntuRoot(t)
	executor := newApplyFakeExecutor()

	result, err := Apply(context.Background(), ApplyInput{
		StateDir:   dir,
		SystemRoot: systemRoot,
		Executor:   executor,
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	if result.ActivePeers != 1 {
		t.Fatalf("unexpected active peer count: %d", result.ActivePeers)
	}
	if result.ExternalInterface != "eth0" {
		t.Fatalf("unexpected external interface: %q", result.ExternalInterface)
	}
	if result.WireGuardConfigPath != filepath.Join(systemRoot, "etc", "wireguard", "wg0.conf") {
		t.Fatalf("unexpected config path: %q", result.WireGuardConfigPath)
	}

	wantCommands := []applyFakeCommand{
		{name: "ip", args: []string{"route", "get", "1.1.1.1"}},
		{name: "systemctl", args: []string{"enable", "wg-quick@wg0"}},
		{name: "systemctl", args: []string{"restart", "wg-quick@wg0"}},
		{name: "systemctl", args: []string{"is-active", "wg-quick@wg0"}},
		{name: "wg", args: []string{"show"}},
	}
	if !reflect.DeepEqual(executor.commands, wantCommands) {
		t.Fatalf("unexpected commands:\nwant %#v\ngot  %#v", wantCommands, executor.commands)
	}

	data, err := os.ReadFile(result.WireGuardConfigPath)
	if err != nil {
		t.Fatalf("read WireGuard config: %v", err)
	}
	got := string(data)
	for _, want := range []string{
		"Address = 10.66.0.1/24\n",
		"ListenPort = 51820\n",
		"PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
		"PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n",
		"# iphone\n",
		"PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n",
		"AllowedIPs = 10.66.0.2/32\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected config to contain %q, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "revoked") || strings.Contains(got, "10.66.0.3/32") {
		t.Fatalf("config includes revoked peer:\n%s", got)
	}

	info, err := os.Stat(result.WireGuardConfigPath)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected config mode 0600, got %o", got)
	}

	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.Server.ExternalInterface != "eth0" {
		t.Fatalf("expected detected interface to be persisted, got %q", st.Server.ExternalInterface)
	}
}

func TestApplyDryRunPrintsRedactedPlanAndDoesNotWriteSystemConfig(t *testing.T) {
	dir := configuredApplyState(t, "ens3")
	systemRoot := fakeApplyUbuntuRoot(t)
	executor := newApplyFakeExecutor()
	var stdout bytes.Buffer

	result, err := Apply(context.Background(), ApplyInput{
		StateDir:   dir,
		SystemRoot: systemRoot,
		Executor:   executor,
		DryRun:     true,
		Stdout:     &stdout,
	})
	if err != nil {
		t.Fatalf("apply dry-run: %v", err)
	}
	if result.ActivePeers != 1 {
		t.Fatalf("unexpected active peer count: %d", result.ActivePeers)
	}
	if len(executor.commands) != 0 {
		t.Fatalf("dry-run should not run commands, got %#v", executor.commands)
	}
	if _, err := os.Stat(result.WireGuardConfigPath); !os.IsNotExist(err) {
		t.Fatalf("dry-run should not write config, stat err: %v", err)
	}
	output := stdout.String()
	for _, want := range []string{
		"apply plan (dry-run)",
		"wireguard config: " + filepath.Join(systemRoot, "etc", "wireguard", "wg0.conf"),
		"external interface: ens3",
		"active peers: 1",
		"PrivateKey = <redacted>\n",
		"AllowedIPs = 10.66.0.2/32\n",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected dry-run output to contain %q, got:\n%s", want, output)
		}
	}
	if strings.Contains(output, applyServerPrivateKey) {
		t.Fatalf("dry-run leaked server private key:\n%s", output)
	}
}

func TestApplyRejectsNonRoot(t *testing.T) {
	dir := configuredApplyState(t, "ens3")
	executor := newApplyFakeExecutor()
	executor.uid = 1000

	_, err := Apply(context.Background(), ApplyInput{
		StateDir:   dir,
		SystemRoot: fakeApplyUbuntuRoot(t),
		Executor:   executor,
	})
	if err == nil {
		t.Fatalf("expected non-root error")
	}
}

func configuredApplyState(t *testing.T, externalInterface string) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), ".vpnctl")
	cfg := state.DefaultServerConfig()
	cfg.PublicEndpoint = "198.211.99.116"
	cfg.ExternalInterface = externalInterface
	if err := state.ConfigureServer(dir, cfg, false); err != nil {
		t.Fatalf("configure server: %v", err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	st.Server.WireGuardPublicKey = applyServerPublicKey
	st.Clients = []state.ClientState{
		{
			ID:                 "iphone",
			Name:               "iPhone",
			Platform:           state.DefaultClientPlatform,
			Status:             state.ClientStatusActive,
			AssignedIP:         "10.66.0.2",
			WireGuardPublicKey: applyClientPublicKey,
		},
		{
			ID:                 "old-phone",
			Name:               "Old Phone",
			Platform:           state.DefaultClientPlatform,
			Status:             "revoked",
			AssignedIP:         "10.66.0.3",
			WireGuardPublicKey: applyClientPublicKey,
		},
	}
	if err := state.Save(dir, st); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if err := os.WriteFile(state.ServerPrivateKeyPath(dir), []byte(applyServerPrivateKey+"\n"), 0o600); err != nil {
		t.Fatalf("write server private key: %v", err)
	}
	if err := os.Chmod(state.ServerPrivateKeyPath(dir), 0o600); err != nil {
		t.Fatalf("chmod server private key: %v", err)
	}
	return dir
}

func fakeApplyUbuntuRoot(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatalf("create etc: %v", err)
	}
	data := "ID=ubuntu\nVERSION_ID=\"24.04\"\n"
	if err := os.WriteFile(filepath.Join(etc, "os-release"), []byte(data), 0o644); err != nil {
		t.Fatalf("write os-release: %v", err)
	}
	return root
}
