package transport

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestStandardServiceValidatesStartsVerifiesAndStops(t *testing.T) {
	t.Parallel()
	paths := standardServicePaths(t, model.RoleGateway, standardTestKey(10))
	runner := &standardServiceRunner{publicKey: standardTestKey(11), interfacePresent: false, listenPort: "51820"}
	ctx, cancel := context.WithCancel(context.Background())
	runner.cancelOnListen = cancel
	if err := RunStandardService(ctx, paths, model.RoleGateway, runner); err != nil {
		t.Fatalf("RunStandardService() error = %v", err)
	}
	want := []string{
		"wg pubkey", "wg-quick strip " + filepath.Join(paths.ConfigDir, "generated", "gateway", StandardConfigFileName),
		"ip -o link show dev vpnctl-wg", "wg-quick up " + filepath.Join(paths.ConfigDir, "generated", "gateway", StandardConfigFileName),
		"wg show vpnctl-wg public-key", "wg show vpnctl-wg listen-port",
		"wg-quick down " + filepath.Join(paths.ConfigDir, "generated", "gateway", StandardConfigFileName),
	}
	if fmt.Sprint(runner.calls) != fmt.Sprint(want) {
		t.Fatalf("service calls =\n%v\nwant\n%v", runner.calls, want)
	}
}

func TestStandardServiceReconcilesOnlyMatchingStaleInterface(t *testing.T) {
	t.Parallel()
	paths := standardServicePaths(t, model.RoleNode, standardTestKey(20))
	runner := &standardServiceRunner{publicKey: standardTestKey(21), interfacePresent: true}
	ctx, cancel := context.WithCancel(context.Background())
	runner.cancelOnPublicCall = 2
	runner.cancel = cancel
	if err := RunStandardService(ctx, paths, model.RoleNode, runner); err != nil {
		t.Fatalf("RunStandardService(stale) error = %v", err)
	}
	joined := strings.Join(runner.calls, "\n")
	if strings.Count(joined, "wg-quick down") != 2 || !strings.Contains(joined, "wg-quick up") {
		t.Fatalf("stale reconciliation calls = %v", runner.calls)
	}

	foreign := &standardServiceRunner{publicKey: standardTestKey(21), interfacePresent: true, actualPublicKey: standardTestKey(22)}
	if err := RunStandardService(context.Background(), paths, model.RoleNode, foreign); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("foreign interface error = %v", err)
	}
	for _, call := range foreign.calls {
		if strings.HasPrefix(call, "wg-quick down") || strings.HasPrefix(call, "wg-quick up") {
			t.Fatalf("foreign interface was mutated: %v", foreign.calls)
		}
	}
}

func TestStandardServiceRejectsNonPrivateOrSymlinkConfigBeforeCommands(t *testing.T) {
	t.Parallel()
	paths := standardServicePaths(t, model.RoleGateway, standardTestKey(30))
	configPath := filepath.Join(paths.ConfigDir, "generated", "gateway", StandardConfigFileName)
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &standardServiceRunner{publicKey: standardTestKey(31)}
	if err := RunStandardService(context.Background(), paths, model.RoleGateway, runner); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("public config error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("unsafe config invoked commands: %v", runner.calls)
	}

	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(paths.Root, "private.conf")
	if err := os.WriteFile(target, []byte("PrivateKey = "+standardTestKey(30)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, configPath); err != nil {
		t.Fatal(err)
	}
	if err := RunStandardService(context.Background(), paths, model.RoleGateway, runner); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink config error = %v", err)
	}
}

type standardServiceRunner struct {
	publicKey          string
	actualPublicKey    string
	interfacePresent   bool
	listenPort         string
	cancel             context.CancelFunc
	cancelOnListen     context.CancelFunc
	cancelOnPublicCall int
	publicCalls        int
	calls              []string
}

func (runner *standardServiceRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	runner.calls = append(runner.calls, key)
	switch key {
	case "wg pubkey":
		return linuxplatform.ProbeResult{Stdout: []byte(runner.publicKey + "\n")}, nil
	case "ip -o link show dev vpnctl-wg":
		if runner.interfacePresent {
			return linuxplatform.ProbeResult{Stdout: []byte("7: vpnctl-wg")}, nil
		}
		return linuxplatform.ProbeResult{ExitCode: 1}, nil
	case "wg show vpnctl-wg public-key":
		runner.publicCalls++
		value := runner.actualPublicKey
		if value == "" {
			value = runner.publicKey
		}
		if runner.cancel != nil && runner.publicCalls == runner.cancelOnPublicCall {
			runner.cancel()
		}
		return linuxplatform.ProbeResult{Stdout: []byte(value + "\n")}, nil
	case "wg show vpnctl-wg listen-port":
		if runner.cancelOnListen != nil {
			runner.cancelOnListen()
		}
		return linuxplatform.ProbeResult{Stdout: []byte(runner.listenPort + "\n")}, nil
	default:
		if strings.HasPrefix(key, "wg-quick strip ") || strings.HasPrefix(key, "wg-quick up ") || strings.HasPrefix(key, "wg-quick down ") {
			return linuxplatform.ProbeResult{}, nil
		}
		return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected command %s", key)
	}
}

func standardServicePaths(t *testing.T, role model.Role, privateKey string) store.Paths {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(paths.ConfigDir, "generated", string(role))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	config := "[Interface]\nPrivateKey = " + privateKey + "\n"
	if err := os.WriteFile(filepath.Join(directory, StandardConfigFileName), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return paths
}
