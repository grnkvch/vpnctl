package transport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestRestrictedGatewayServiceValidatesPinnedBinaryAndRunsUntilCancellation(t *testing.T) {
	t.Parallel()
	paths, configPath, stateDirectory := restrictedServicePaths(t)
	probe := &restrictedServiceProbe{}
	ctx, cancel := context.WithCancel(context.Background())
	process := &restrictedServiceProcess{cancel: cancel}
	if err := RunRestrictedGatewayService(ctx, paths, probe, process); err != nil {
		t.Fatalf("RunRestrictedGatewayService() error = %v", err)
	}
	binaryPath := filepath.Join(paths.Root, RestrictedBinaryRelativePath)
	wantProbe := []string{
		binaryPath + " -v",
		binaryPath + " -t -d " + stateDirectory + " -f " + configPath,
	}
	if fmt.Sprint(probe.calls) != fmt.Sprint(wantProbe) {
		t.Fatalf("restricted validation calls = %v, want %v", probe.calls, wantProbe)
	}
	if process.name != binaryPath || fmt.Sprint(process.arguments) != fmt.Sprint([]string{"-d", stateDirectory, "-f", configPath}) {
		t.Fatalf("restricted process = %q %v", process.name, process.arguments)
	}
}

func TestRestrictedGatewayServiceRejectsUnsafeConfigBeforeCommands(t *testing.T) {
	t.Parallel()
	paths, configPath, _ := restrictedServicePaths(t)
	probe := &restrictedServiceProbe{}
	process := &restrictedServiceProcess{}
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RunRestrictedGatewayService(context.Background(), paths, probe, process); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("public config error = %v", err)
	}
	if len(probe.calls) != 0 || process.called {
		t.Fatalf("unsafe config invoked commands: %v / %t", probe.calls, process.called)
	}

	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(paths.Root, "restricted-target.yaml")
	if err := os.WriteFile(target, []byte("secret-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, configPath); err != nil {
		t.Fatal(err)
	}
	if err := RunRestrictedGatewayService(context.Background(), paths, probe, process); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink config error = %v", err)
	}
}

func TestRestrictedGatewayServiceRejectsWrongPinAndSanitizesProcessFailure(t *testing.T) {
	t.Parallel()
	paths, _, _ := restrictedServicePaths(t)
	wrong := &restrictedServiceProbe{version: "Mihomo Meta v1.19.300 linux amd64"}
	process := &restrictedServiceProcess{}
	if err := RunRestrictedGatewayService(context.Background(), paths, wrong, process); err == nil || !strings.Contains(err.Error(), "pinned version v1.19.30") {
		t.Fatalf("wrong version error = %v", err)
	}
	if process.called {
		t.Fatal("wrong pinned version started restricted process")
	}

	failed := &restrictedServiceProcess{err: errors.New("shadowtls-secret-canary")}
	err := RunRestrictedGatewayService(context.Background(), paths, &restrictedServiceProbe{}, failed)
	if err == nil || err.Error() != "restricted gateway process failed" || strings.Contains(err.Error(), "canary") {
		t.Fatalf("process error was not sanitized: %v", err)
	}
}

func TestPinnedMihomoVersionTokenIsExact(t *testing.T) {
	t.Parallel()
	for value, want := range map[string]bool{
		"Mihomo Meta v1.19.30 linux amd64": true,
		"v1.19.30":                         true,
		"Mihomo Meta v1.19.300":            false,
		"Mihomo Meta v1.19.29":             false,
		"prefix-v1.19.30-suffix":           false,
	} {
		if got := hasExactVersionToken(value, RestrictedProviderVersion); got != want {
			t.Errorf("hasExactVersionToken(%q) = %t, want %t", value, got, want)
		}
	}
}

func restrictedServicePaths(t *testing.T) (store.Paths, string, string) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	configDirectory := filepath.Join(paths.ConfigDir, "generated", "gateway")
	stateDirectory := filepath.Join(paths.StateDir, RestrictedStateRelativePath)
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	content := renderGatewayRestrictedYAML(
		restrictedServerPassword(0x71), "www.microsoft.com",
		[]renderedRestrictedUser{{
			descriptor: RestrictedUserDescriptor{Name: RestrictedBootstrapUserName},
			password:   strings.Repeat("72", restrictedSymmetricKeyByteCount),
		}},
	)
	configPath := filepath.Join(configDirectory, RestrictedConfigFileName)
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return paths, configPath, stateDirectory
}

type restrictedServiceProbe struct {
	version        string
	validationCode int
	calls          []string
}

func (runner *restrictedServiceProbe) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	runner.calls = append(runner.calls, key)
	if len(command.Args) == 1 && command.Args[0] == "-v" {
		version := runner.version
		if version == "" {
			version = "Mihomo Meta v1.19.30 linux amd64"
		}
		return linuxplatform.ProbeResult{Stdout: []byte(version + "\n")}, nil
	}
	if len(command.Args) == 5 && command.Args[0] == "-t" && command.Args[1] == "-d" && command.Args[3] == "-f" {
		return linuxplatform.ProbeResult{ExitCode: runner.validationCode}, nil
	}
	return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected restricted validation command %s", key)
}

type restrictedServiceProcess struct {
	called    bool
	name      string
	arguments []string
	cancel    context.CancelFunc
	err       error
}

func (runner *restrictedServiceProcess) Run(ctx context.Context, name string, arguments []string) error {
	runner.called = true
	runner.name = name
	runner.arguments = append([]string(nil), arguments...)
	if runner.cancel != nil {
		runner.cancel()
		return ctx.Err()
	}
	return runner.err
}
