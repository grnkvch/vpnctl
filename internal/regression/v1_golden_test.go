package regression

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/app"
	"github.com/vgrinkevich/vpnctl/internal/setup"
	"github.com/vgrinkevich/vpnctl/internal/state"
)

const (
	v1ServerPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	v1ServerPublicKey  = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	v1ClientPrivateKey = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	v1ClientPublicKey  = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
)

func TestV1GoldenPersonalVPNArtifacts(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".vpnctl")
	cfg := state.DefaultServerConfig()
	cfg.PublicEndpoint = "198.211.99.116"
	cfg.DNSServers = []string{"1.1.1.1", "8.8.8.8"}
	cfg.ExternalInterface = "eth0"
	if err := state.ConfigureServer(stateDir, cfg, false); err != nil {
		t.Fatalf("configure v1 server: %v", err)
	}

	st, err := state.Load(stateDir)
	if err != nil {
		t.Fatalf("load v1 state: %v", err)
	}
	st.Server.WireGuardPublicKey = v1ServerPublicKey
	if err := state.Save(stateDir, st); err != nil {
		t.Fatalf("save v1 server key: %v", err)
	}

	client, err := state.CreateClient(context.Background(), stateDir, state.ClientConfig{
		ID:       "iphone",
		Name:     "iPhone",
		Platform: "ios",
		Tags:     []string{"personal"},
		Now:      time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC),
	}, fixedV1ClientKeyGenerator{})
	if err != nil {
		t.Fatalf("create v1 client: %v", err)
	}
	if client.AssignedIP != "10.66.0.2" || client.WireGuardPublicKey != v1ClientPublicKey {
		t.Fatalf("unexpected v1 client allocation: %#v", client)
	}

	assertFileMatchesFixture(t, filepath.Join(stateDir, "state.json"), "state.json")
	assertFileMatchesFixture(t, filepath.Join(stateDir, "rulesets", "default.json"), "default-ruleset.json")
	assertFileMatchesFixture(t, state.ClientPrivateKeyPath(stateDir, client.ID), "iphone-private.key")

	wgResult, err := app.ExportClient(app.ExportClientInput{
		StateDir: stateDir,
		ClientID: client.ID,
		Type:     app.ExportTypeWireGuard,
	})
	if err != nil {
		t.Fatalf("export v1 WireGuard client: %v", err)
	}
	assertFileMatchesFixture(t, wgResult.Path, "iphone.wireguard.conf")

	clashResult, err := app.ExportClient(app.ExportClientInput{
		StateDir: stateDir,
		ClientID: client.ID,
		Type:     app.ExportTypeClash,
		Ruleset:  app.DefaultRulesetID,
	})
	if err != nil {
		t.Fatalf("export v1 Clash client: %v", err)
	}
	if clashResult.Warning != "" {
		t.Fatalf("unexpected v1 Clash warning: %q", clashResult.Warning)
	}
	assertFileMatchesFixture(t, clashResult.Path, "iphone.clash.yaml")
}

func TestV1GoldenSetupAndUFWArtifacts(t *testing.T) {
	opts := setup.Defaults(".vpnctl")
	opts.Endpoint = "198.211.99.116"

	var dryRun strings.Builder
	setup.PrintDryRun(&dryRun, opts)
	assertTextMatchesFixture(t, dryRun.String(), "setup-dry-run.txt")

	stateDir := filepath.Join(t.TempDir(), ".vpnctl")
	systemRoot := fakeUbuntuRoot(t)
	executor := newGoldenExecutor()
	opts.StateDir = stateDir
	if _, err := setup.Run(context.Background(), opts, setup.Runtime{
		Executor:     executor,
		KeyGenerator: fixedV1ServerKeyGenerator{},
		SystemRoot:   systemRoot,
	}); err != nil {
		t.Fatalf("run v1 setup: %v", err)
	}

	assertTextMatchesFixture(t, executor.commandLog(), "setup-commands.txt")
	assertFileMatchesFixture(t, filepath.Join(systemRoot, "etc", "wireguard", "wg0.conf"), "server.wireguard.conf")
	assertFileMatchesFixture(t, filepath.Join(systemRoot, "etc", "sysctl.d", "99-vpnctl.conf"), "sysctl.conf")
}

func TestV1GoldenInstallerArtifacts(t *testing.T) {
	var contract installerContract
	data := readFixture(t, "installer-contract.json")
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatalf("parse installer contract fixture: %v", err)
	}

	installScript := readRepositoryFile(t, "scripts", "install.sh")
	releaseScript := readRepositoryFile(t, "scripts", "release.sh")
	for _, expected := range contract.InstallScriptContains {
		if !strings.Contains(installScript, expected) {
			t.Errorf("v1 install.sh no longer contains %q", expected)
		}
	}
	for _, expected := range contract.ReleaseScriptContains {
		if !strings.Contains(releaseScript, expected) {
			t.Errorf("v1 release.sh no longer contains %q", expected)
		}
	}
}

type installerContract struct {
	InstallScriptContains []string `json:"install_script_contains"`
	ReleaseScriptContains []string `json:"release_script_contains"`
}

type fixedV1ClientKeyGenerator struct{}

func (fixedV1ClientKeyGenerator) GenerateClientKeyPair(context.Context) (state.ClientKeyPair, error) {
	return state.ClientKeyPair{PrivateKey: v1ClientPrivateKey, PublicKey: v1ClientPublicKey}, nil
}

type fixedV1ServerKeyGenerator struct{}

func (fixedV1ServerKeyGenerator) GenerateServerKeyPair(context.Context) (state.ServerKeyPair, error) {
	return state.ServerKeyPair{PrivateKey: v1ServerPrivateKey, PublicKey: v1ServerPublicKey}, nil
}

type goldenExecutor struct {
	commands []goldenCommand
}

type goldenCommand struct {
	name string
	args []string
}

func newGoldenExecutor() *goldenExecutor {
	return &goldenExecutor{}
}

func (e *goldenExecutor) CurrentUID() int { return 0 }
func (e *goldenExecutor) GOOS() string    { return "linux" }
func (e *goldenExecutor) GOARCH() string  { return "amd64" }

func (e *goldenExecutor) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (e *goldenExecutor) WriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func (e *goldenExecutor) MkdirAll(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

func (e *goldenExecutor) Chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

func (e *goldenExecutor) Run(_ context.Context, name string, args []string, _ string) (string, error) {
	e.commands = append(e.commands, goldenCommand{name: name, args: append([]string(nil), args...)})
	if name == "ip" && strings.Join(args, " ") == "route get 1.1.1.1" {
		return "1.1.1.1 via 203.0.113.1 dev eth0 src 198.211.99.116 uid 0\n", nil
	}
	return "", nil
}

func (e *goldenExecutor) commandLog() string {
	var out strings.Builder
	for _, command := range e.commands {
		fmt.Fprintf(&out, "%s %s\n", command.name, strings.Join(command.args, " "))
	}
	return out.String()
}

func fakeUbuntuRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatalf("create fake /etc: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o644); err != nil {
		t.Fatalf("write fake os-release: %v", err)
	}
	return root
}

func assertFileMatchesFixture(t *testing.T, actualPath string, fixtureName string) {
	t.Helper()
	actual, err := os.ReadFile(actualPath)
	if err != nil {
		t.Fatalf("read actual artifact %s: %v", actualPath, err)
	}
	assertBytesMatchFixture(t, actual, fixtureName)
}

func assertTextMatchesFixture(t *testing.T, actual string, fixtureName string) {
	t.Helper()
	assertBytesMatchFixture(t, []byte(actual), fixtureName)
}

func assertBytesMatchFixture(t *testing.T, actual []byte, fixtureName string) {
	t.Helper()
	expected := readFixture(t, fixtureName)
	if string(actual) != string(expected) {
		t.Fatalf("v1 golden mismatch for %s\n--- expected ---\n%s--- actual ---\n%s", fixtureName, expected, actual)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "v1", name))
	if err != nil {
		t.Fatalf("read v1 fixture %s: %v", name, err)
	}
	return data
}

func readRepositoryFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read repository file %s: %v", path, err)
	}
	return string(data)
}
