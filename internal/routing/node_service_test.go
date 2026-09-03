package routing

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

func TestNodeRoutingServiceValidatesPinnedBinaryAndRunsUntilCancellation(t *testing.T) {
	t.Parallel()
	paths, configPath, stateDirectory := nodeRoutingServicePaths(t)
	probe := &nodeRoutingServiceProbe{}
	ctx, cancel := context.WithCancel(context.Background())
	process := &nodeRoutingServiceProcess{cancel: cancel}
	if err := RunNodeRoutingService(ctx, paths, probe, process); err != nil {
		t.Fatalf("RunNodeRoutingService() error = %v", err)
	}
	binaryPath := nodeRoutingBinaryPath(paths)
	wantProbe := []string{
		binaryPath + " -v",
		binaryPath + " -t -d " + stateDirectory + " -f " + configPath,
	}
	if fmt.Sprint(probe.calls) != fmt.Sprint(wantProbe) {
		t.Fatalf("node routing validation calls = %v, want %v", probe.calls, wantProbe)
	}
	if process.name != binaryPath || fmt.Sprint(process.arguments) != fmt.Sprint([]string{"-d", stateDirectory, "-f", configPath}) {
		t.Fatalf("node routing process = %q %v", process.name, process.arguments)
	}
}

func TestNodeRoutingServiceAcceptsExplicitDirectDNSArtifact(t *testing.T) {
	t.Parallel()
	paths, configPath, _ := nodeRoutingServicePaths(t)
	candidate, err := RenderNodeRoutingConfig(nodeRoutingRenderFixture(t, NodeRoutingDNSDirect))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, candidate.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	process := &nodeRoutingServiceProcess{cancel: cancel}
	if err := RunNodeRoutingService(ctx, paths, &nodeRoutingServiceProbe{}, process); err != nil || !process.called {
		t.Fatalf("direct-mode service = %v, called=%t", err, process.called)
	}
}

func TestNodeRoutingServiceRejectsUnsafeFilesBeforeCommands(t *testing.T) {
	t.Parallel()
	paths, configPath, stateDirectory := nodeRoutingServicePaths(t)
	probe := &nodeRoutingServiceProbe{}
	process := &nodeRoutingServiceProcess{}
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RunNodeRoutingService(context.Background(), paths, probe, process); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("public config error = %v", err)
	}
	if len(probe.calls) != 0 || process.called {
		t.Fatalf("unsafe config invoked commands: %v / %t", probe.calls, process.called)
	}

	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(stateDirectory); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(paths.Root, "routing-state-target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, stateDirectory); err != nil {
		t.Fatal(err)
	}
	if err := RunNodeRoutingService(context.Background(), paths, probe, process); err == nil || !strings.Contains(err.Error(), "must be a directory") {
		t.Fatalf("symlink state directory error = %v", err)
	}
	if len(probe.calls) != 0 || process.called {
		t.Fatalf("unsafe state path invoked commands: %v / %t", probe.calls, process.called)
	}
}

func TestNodeRoutingServiceRejectsWrongPinAndSanitizesProcessFailure(t *testing.T) {
	t.Parallel()
	paths, _, _ := nodeRoutingServicePaths(t)
	wrong := &nodeRoutingServiceProbe{version: "Mihomo Meta v1.19.300 linux amd64"}
	process := &nodeRoutingServiceProcess{}
	if err := RunNodeRoutingService(context.Background(), paths, wrong, process); err == nil || !strings.Contains(err.Error(), "pinned version v1.19.30") {
		t.Fatalf("wrong version error = %v", err)
	}
	if process.called {
		t.Fatal("wrong pinned version started node routing process")
	}

	failed := &nodeRoutingServiceProcess{err: errors.New("policy-secret-canary")}
	err := RunNodeRoutingService(context.Background(), paths, &nodeRoutingServiceProbe{}, failed)
	if err == nil || err.Error() != "node routing process failed" || strings.Contains(err.Error(), "canary") {
		t.Fatalf("process error was not sanitized: %v", err)
	}
}

func TestPinnedNodeRoutingMihomoVersionTokenIsExact(t *testing.T) {
	t.Parallel()
	for value, want := range map[string]bool{
		"Mihomo Meta v1.19.30 linux amd64": true,
		"v1.19.30":                         true,
		"Mihomo Meta v1.19.300":            false,
		"Mihomo Meta v1.19.29":             false,
		"prefix-v1.19.30-suffix":           false,
	} {
		if got := hasExactNodeRoutingVersionToken(value, NodeRoutingProviderVersion); got != want {
			t.Errorf("hasExactNodeRoutingVersionToken(%q) = %t, want %t", value, got, want)
		}
	}
}

func nodeRoutingServicePaths(t *testing.T) (store.Paths, string, string) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	configDirectory := filepath.Join(paths.ConfigDir, "generated", "node")
	stateDirectory := nodeRoutingStatePath(paths)
	if err := os.MkdirAll(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	candidate, err := RenderNodeRoutingConfig(nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy))
	if err != nil {
		t.Fatal(err)
	}
	configPath := nodeRoutingConfigPath(paths)
	if err := os.WriteFile(configPath, candidate.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return paths, configPath, stateDirectory
}

type nodeRoutingServiceProbe struct {
	version        string
	validationCode int
	calls          []string
}

func (runner *nodeRoutingServiceProbe) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
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
	return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected node routing validation command %s", key)
}

type nodeRoutingServiceProcess struct {
	called    bool
	name      string
	arguments []string
	cancel    context.CancelFunc
	err       error
}

func (runner *nodeRoutingServiceProcess) Run(ctx context.Context, name string, arguments []string) error {
	runner.called = true
	runner.name = name
	runner.arguments = append([]string(nil), arguments...)
	if runner.cancel != nil {
		runner.cancel()
		return ctx.Err()
	}
	return runner.err
}
