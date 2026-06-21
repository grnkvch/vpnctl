package setup

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/state"
)

const (
	testServerPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	testServerPublicKey  = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
)

type fakeExecutor struct {
	uid      int
	goos     string
	goarch   string
	commands []fakeCommand
	outputs  map[string]string
}

type fakeCommand struct {
	name string
	args []string
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{
		uid:    0,
		goos:   "linux",
		goarch: "amd64",
		outputs: map[string]string{
			"ip route get 1.1.1.1": "1.1.1.1 via 203.0.113.1 dev eth0 src 198.211.99.116 uid 0\n",
		},
	}
}

func (e *fakeExecutor) CurrentUID() int { return e.uid }
func (e *fakeExecutor) GOOS() string    { return e.goos }
func (e *fakeExecutor) GOARCH() string  { return e.goarch }

func (e *fakeExecutor) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (e *fakeExecutor) WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func (e *fakeExecutor) MkdirAll(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

func (e *fakeExecutor) Chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

func (e *fakeExecutor) Run(_ context.Context, name string, args []string, _ string) (string, error) {
	e.commands = append(e.commands, fakeCommand{name: name, args: append([]string(nil), args...)})
	return e.outputs[name+" "+strings.Join(args, " ")], nil
}

type fakeServerKeyGenerator struct{}

func (fakeServerKeyGenerator) GenerateServerKeyPair(context.Context) (state.ServerKeyPair, error) {
	return state.ServerKeyPair{
		PrivateKey: testServerPrivateKey,
		PublicKey:  testServerPublicKey,
	}, nil
}

func TestRunPerformsOneShotSetup(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".vpnctl")
	systemRoot := fakeUbuntuRoot(t)
	executor := newFakeExecutor()
	opts := Defaults(stateDir)
	opts.Endpoint = "198.211.99.116"

	result, err := Run(context.Background(), opts, Runtime{
		Executor:     executor,
		KeyGenerator: fakeServerKeyGenerator{},
		SystemRoot:   systemRoot,
	})
	if err != nil {
		t.Fatalf("run setup: %v", err)
	}

	if result.ExternalInterface != "eth0" {
		t.Fatalf("unexpected external interface: %q", result.ExternalInterface)
	}
	if !result.GeneratedServerKeys {
		t.Fatalf("expected server keys to be generated")
	}

	wantCommands := []fakeCommand{
		{name: "apt", args: []string{"update"}},
		{name: "apt", args: []string{"install", "-y", "wireguard", "qrencode", "ufw"}},
		{name: "ip", args: []string{"route", "get", "1.1.1.1"}},
		{name: "sysctl", args: []string{"--system"}},
		{name: "ufw", args: []string{"allow", "22/tcp"}},
		{name: "ufw", args: []string{"allow", "51820/udp"}},
		{name: "ufw", args: []string{"--force", "enable"}},
		{name: "systemctl", args: []string{"enable", "wg-quick@wg0"}},
		{name: "systemctl", args: []string{"restart", "wg-quick@wg0"}},
		{name: "systemctl", args: []string{"is-active", "wg-quick@wg0"}},
		{name: "wg", args: []string{"show"}},
	}
	if !reflect.DeepEqual(executor.commands, wantCommands) {
		t.Fatalf("unexpected commands:\nwant %#v\ngot  %#v", wantCommands, executor.commands)
	}

	sysctlData, err := os.ReadFile(filepath.Join(systemRoot, "etc", "sysctl.d", "99-vpnctl.conf"))
	if err != nil {
		t.Fatalf("read sysctl config: %v", err)
	}
	if string(sysctlData) != "net.ipv4.ip_forward=1\n" {
		t.Fatalf("unexpected sysctl config: %q", string(sysctlData))
	}

	wgConfig, err := os.ReadFile(filepath.Join(systemRoot, "etc", "wireguard", "wg0.conf"))
	if err != nil {
		t.Fatalf("read wg config: %v", err)
	}
	for _, want := range []string{
		"Address = 10.66.0.1/24\n",
		"ListenPort = 51820\n",
		"PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
		"PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n",
	} {
		if !strings.Contains(string(wgConfig), want) {
			t.Fatalf("expected wg config to contain %q, got:\n%s", want, string(wgConfig))
		}
	}

	st, err := state.Load(stateDir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.Server.ExternalInterface != "eth0" {
		t.Fatalf("expected external interface in state, got %q", st.Server.ExternalInterface)
	}
	if st.Server.WireGuardPublicKey != testServerPublicKey {
		t.Fatalf("expected public key in state")
	}
}

func TestRunUsesConfiguredExternalInterfaceAndCanLeaveUFWDisabled(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".vpnctl")
	systemRoot := fakeUbuntuRoot(t)
	executor := newFakeExecutor()
	opts := Defaults(stateDir)
	opts.Endpoint = "198.211.99.116"
	opts.ExternalInterface = "ens3"
	opts.EnableUFW = false

	if _, err := Run(context.Background(), opts, Runtime{
		Executor:     executor,
		KeyGenerator: fakeServerKeyGenerator{},
		SystemRoot:   systemRoot,
	}); err != nil {
		t.Fatalf("run setup: %v", err)
	}

	for _, cmd := range executor.commands {
		if cmd.name == "ip" {
			t.Fatalf("expected configured external interface to skip ip route detection")
		}
		if cmd.name == "ufw" && reflect.DeepEqual(cmd.args, []string{"--force", "enable"}) {
			t.Fatalf("expected setup not to enable ufw")
		}
	}
}

func TestRunRejectsNonRoot(t *testing.T) {
	executor := newFakeExecutor()
	executor.uid = 1000
	opts := Defaults(filepath.Join(t.TempDir(), ".vpnctl"))
	opts.Endpoint = "198.211.99.116"

	_, err := Run(context.Background(), opts, Runtime{
		Executor:     executor,
		KeyGenerator: fakeServerKeyGenerator{},
		SystemRoot:   fakeUbuntuRoot(t),
	})
	if err == nil {
		t.Fatalf("expected non-root error")
	}
}

func TestRunRejectsUnsupportedPlatform(t *testing.T) {
	executor := newFakeExecutor()
	executor.goos = "darwin"
	opts := Defaults(filepath.Join(t.TempDir(), ".vpnctl"))
	opts.Endpoint = "198.211.99.116"

	_, err := Run(context.Background(), opts, Runtime{
		Executor:     executor,
		KeyGenerator: fakeServerKeyGenerator{},
		SystemRoot:   fakeUbuntuRoot(t),
	})
	if err == nil {
		t.Fatalf("expected unsupported platform error")
	}
}

func fakeUbuntuRoot(t *testing.T) string {
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
