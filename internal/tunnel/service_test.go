package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestFRPServicesValidateExactPinnedBinaryAndRun(t *testing.T) {
	t.Parallel()

	for _, role := range []model.Role{model.RoleGateway, model.RoleNode} {
		role := role
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			paths, configPath, binaryPath := frpServiceFixture(t, role)
			probe := &frpServiceProbe{}
			ctx, cancel := context.WithCancel(context.Background())
			process := &frpServiceProcess{cancel: cancel}
			var err error
			if role == model.RoleGateway {
				err = RunFRPServerService(ctx, paths, probe, process)
			} else {
				err = RunFRPClientService(ctx, paths, probe, process)
			}
			if err != nil {
				t.Fatalf("RunFRPService() error = %v", err)
			}
			wantCalls := []string{binaryPath + " --version", binaryPath + " verify -c " + configPath}
			if fmt.Sprint(probe.calls) != fmt.Sprint(wantCalls) {
				t.Fatalf("frp validation calls = %v, want %v", probe.calls, wantCalls)
			}
			if process.name != binaryPath || fmt.Sprint(process.arguments) != fmt.Sprint([]string{"-c", configPath}) {
				t.Fatalf("frp process = %q %v", process.name, process.arguments)
			}
		})
	}
}

func TestFRPServiceRejectsUnsafeFilesBeforeCommands(t *testing.T) {
	t.Parallel()

	paths, configPath, _ := frpServiceFixture(t, model.RoleNode)
	probe := &frpServiceProbe{}
	process := &frpServiceProcess{}
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RunFRPClientService(context.Background(), paths, probe, process); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("public config error = %v", err)
	}
	if len(probe.calls) != 0 || process.called {
		t.Fatalf("unsafe config invoked commands: %v / %t", probe.calls, process.called)
	}

	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(paths.Root, "frp-config-target")
	if err := os.WriteFile(target, []byte("tunnel-secret-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, configPath); err != nil {
		t.Fatal(err)
	}
	if err := RunFRPClientService(context.Background(), paths, probe, process); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink config error = %v", err)
	}
}

func TestFRPServerServiceRequiresRootOnlyPrivateKey(t *testing.T) {
	t.Parallel()

	paths, _, _ := frpServiceFixture(t, model.RoleGateway)
	privateKeyPath := filepath.Join(paths.ConfigDir, "generated", "gateway", FRPServerPrivateKeyName)
	if err := os.Chmod(privateKeyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	probe := &frpServiceProbe{}
	process := &frpServiceProcess{}
	if err := RunFRPServerService(context.Background(), paths, probe, process); err == nil || !strings.Contains(err.Error(), "private key") || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("public private-key error = %v", err)
	}
	if len(probe.calls) != 0 || process.called {
		t.Fatal("unsafe private key invoked frp")
	}
}

func TestFRPServiceRejectsWrongPinAndSanitizesProcessFailure(t *testing.T) {
	t.Parallel()

	paths, _, _ := frpServiceFixture(t, model.RoleGateway)
	wrong := &frpServiceProbe{version: "0.69.00"}
	process := &frpServiceProcess{}
	if err := RunFRPServerService(context.Background(), paths, wrong, process); err == nil || !strings.Contains(err.Error(), "pinned version 0.69.0") {
		t.Fatalf("wrong version error = %v", err)
	}
	if process.called {
		t.Fatal("wrong pinned version started frps")
	}

	failed := &frpServiceProcess{err: errors.New("tunnel-secret-canary")}
	err := RunFRPServerService(context.Background(), paths, &frpServiceProbe{}, failed)
	if err == nil || err.Error() != "frp server process failed" || strings.Contains(err.Error(), "canary") {
		t.Fatalf("process error was not sanitized: %v", err)
	}
}

func TestPinnedFRPVersionOutputIsExact(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"frp 0.69.0", "0.69.00", "0.69.0 warning"} {
		runner := &frpServiceProbe{version: value}
		err := ValidatePinnedFRPConfig(context.Background(), runner, "/frps", "/frps.toml")
		if err == nil || !strings.Contains(err.Error(), "pinned version") {
			t.Errorf("version %q was accepted: %v", value, err)
		}
	}
}

func frpServiceFixture(t *testing.T, role model.Role) (store.Paths, string, string) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directoryRole := "node"
	if role == model.RoleGateway {
		directoryRole = "gateway"
	}
	configDirectory := filepath.Join(paths.ConfigDir, "generated", directoryRole)
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	provider, err := NewFRPProvider(paths.Root, testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{
		HostRole: role, HostID: testGatewayHostID, Generation: 1,
		ServerEndpoint: netipMustParseAddrPort(t, "10.67.0.1:17000"), Nodes: []NodeSession{},
	}
	if role == model.RoleNode {
		plan.HostID = testNodeHostID
		plan.Nodes = []NodeSession{testFRPSession(t)}
	}
	candidate, err := provider.Render(context.Background(), RenderRequest{Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	configPath, binaryPath := frpServicePaths(paths, role)
	if err := os.WriteFile(configPath, candidate.(FRPCandidate).Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	certificateDirectory := filepath.Dir(configPath)
	if err := os.WriteFile(filepath.Join(certificateDirectory, FRPServerCertificateName), []byte("test-certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	if role == model.RoleGateway {
		if err := os.WriteFile(filepath.Join(certificateDirectory, FRPServerPrivateKeyName), []byte("test-private-key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return paths, configPath, binaryPath
}

func netipMustParseAddrPort(t *testing.T, value string) netip.AddrPort {
	t.Helper()
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

type frpServiceProbe struct {
	version        string
	validationCode int
	calls          []string
}

func (runner *frpServiceProbe) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	runner.calls = append(runner.calls, key)
	if len(command.Args) == 1 && command.Args[0] == "--version" {
		version := runner.version
		if version == "" {
			version = FRPProviderVersion
		}
		return linuxplatform.ProbeResult{Stdout: []byte(version + "\n")}, nil
	}
	if len(command.Args) == 3 && command.Args[0] == "verify" && command.Args[1] == "-c" {
		return linuxplatform.ProbeResult{ExitCode: runner.validationCode}, nil
	}
	return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected frp validation command %s", key)
}

type frpServiceProcess struct {
	called    bool
	name      string
	arguments []string
	cancel    context.CancelFunc
	err       error
}

func (runner *frpServiceProcess) Run(ctx context.Context, name string, arguments []string) error {
	runner.called = true
	runner.name = name
	runner.arguments = append([]string(nil), arguments...)
	if runner.cancel != nil {
		runner.cancel()
		return ctx.Err()
	}
	return runner.err
}
