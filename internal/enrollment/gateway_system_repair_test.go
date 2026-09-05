package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

func TestSystemGatewayRepairCompileReconstructsInitialRuntimeWithoutMutation(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	state, err := fixture.gatewayState.Load()
	if err != nil {
		t.Fatal(err)
	}
	paths, runner, _, _ := newGatewayJoinReadinessFixture(t, fixture.gatewaySecrets)
	runtime, err := newSystemGatewayRepairRuntime(
		paths, fixture.gatewaySecrets, runner, &joinWireGuardRunner{}, linuxplatform.DefaultVPNCTLBinaryPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := runtime.Compile(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Destroy()
	request := candidate.RoleRequest()
	defer clearGatewayJoinRoleRequest(&request)
	if candidate.Generation() != state.Generation || candidate.TunnelActive() || len(request.Units) != 5 || len(request.Configs) != 8 || len(runner.systemctl) != 0 {
		t.Fatalf("initial gateway repair candidate = generation:%d tunnel:%t units:%d configs:%d probes:%v", candidate.Generation(), candidate.TunnelActive(), len(request.Units), len(request.Configs), runner.systemctl)
	}
	encoded, err := json.Marshal(candidate)
	if err != nil || string(encoded) != `{}` || strings.Contains(string(encoded), joinGatewayWireGuardPrivate()) {
		t.Fatalf("serialized gateway repair candidate = %s, %v", encoded, err)
	}
}

func TestSystemGatewayRepairCompileReconstructsActiveTunnelRuntime(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	ensureJoinFixtureFRPComponent(fixture)
	if _, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportRestricted, []string{"telegram"}); err != nil {
		t.Fatal(err)
	}
	state, err := fixture.gatewayState.Load()
	if err != nil {
		t.Fatal(err)
	}
	paths, runner, _, _ := newGatewayJoinReadinessFixture(t, fixture.gatewaySecrets)
	runtime, err := newSystemGatewayRepairRuntime(
		paths, fixture.gatewaySecrets, runner, &joinWireGuardRunner{}, linuxplatform.DefaultVPNCTLBinaryPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := runtime.Compile(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Destroy()
	request := candidate.RoleRequest()
	defer clearGatewayJoinRoleRequest(&request)
	if !candidate.TunnelActive() || len(request.Units) != 5 || len(request.Configs) != 12 || len(runner.systemctl) != 0 {
		t.Fatalf("active gateway repair candidate = tunnel:%t units:%d configs:%d probes:%v", candidate.TunnelActive(), len(request.Units), len(request.Configs), runner.systemctl)
	}
}

func TestSystemGatewayRepairCompileRefusesMissingCreateOnceCredential(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	state, _ := fixture.gatewayState.Load()
	paths, runner, _, _ := newGatewayJoinReadinessFixture(t, fixture.gatewaySecrets)
	runtime, err := newSystemGatewayRepairRuntime(
		paths, fixture.gatewaySecrets, runner, &joinWireGuardRunner{}, linuxplatform.DefaultVPNCTLBinaryPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	removed, err := fixture.gatewaySecrets.Delete(transport.GatewayRestrictedCredentialRef)
	if err != nil || !removed {
		t.Fatalf("remove test restricted credential = %t, %v", removed, err)
	}
	if _, err := runtime.Compile(context.Background(), state); !errors.Is(err, store.ErrSecretNotFound) {
		t.Fatalf("missing gateway repair credential error = %v", err)
	}
	if len(runner.systemctl) != 0 {
		t.Fatalf("failed gateway repair compile mutated services: %v", runner.systemctl)
	}
}

func TestSystemGatewayRepairApplyHidesStaleTunnelMarkerBeforeRoleStart(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	state, _ := fixture.gatewayState.Load()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{paths.ConfigDir, filepath.Join(paths.Root, "etc", "systemd", "system"), filepath.Join(paths.ConfigDir, "generated", "gateway")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tunnelFiles := []string{tunnel.FRPServerConfigFileName, tunnel.FRPServerReadyFileName, tunnel.FRPServerCertificateName, tunnel.FRPServerPrivateKeyName}
	for _, name := range tunnelFiles {
		if err := os.WriteFile(filepath.Join(paths.ConfigDir, "generated", "gateway", name), []byte("stale\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bootstrapPath := filepath.Join(paths.ConfigDir, "generated", "gateway", "bootstrap.conf")
	if err := os.WriteFile(bootstrapPath, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &gatewayRepairApplyRunner{readyPath: filepath.Join(paths.ConfigDir, "generated", "gateway", tunnel.FRPServerReadyFileName)}
	runtime, err := newSystemGatewayRepairRuntime(
		paths, fixture.gatewaySecrets, runner, &joinWireGuardRunner{}, linuxplatform.DefaultVPNCTLBinaryPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := runtime.Compile(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Destroy()
	if err := runtime.Apply(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if !runner.tunnelStartSawMarkerAbsent {
		t.Fatal("inactive tunnel readiness marker was visible when role start ran")
	}
	for _, name := range tunnelFiles {
		if _, err := os.Lstat(filepath.Join(paths.ConfigDir, "generated", "gateway", name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inactive tunnel artifact %s remained: %v", name, err)
		}
	}
	if !sawGatewayRepairSystemctl(runner.systemctl, []string{"stop", "vpnctl-tunnel-server.service"}) {
		t.Fatalf("inactive tunnel was not stopped: %v", runner.systemctl)
	}
	if info, err := os.Stat(bootstrapPath); err != nil || info.Mode().Perm() != 0o600 || info.Size() == 0 {
		t.Fatalf("empty/insecure owned config was not repaired: info=%v err=%v", info, err)
	}
}

func TestSystemGatewayRepairVerifyRejectsUnexpectedWireGuardPeer(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	state, _ := fixture.gatewayState.Load()
	runner := &gatewayRepairApplyRunner{allowedIPs: testNodeWireGuardPublic() + "\t10.67.0.2/32\n"}
	runtime := &SystemGatewayRepairRuntime{runner: runner}
	candidate := &SystemGatewayRepairCandidate{state: state, gatewayWireGuardKey: joinGatewayWireGuardPublic()}
	if err := runtime.verify(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "peer set") {
		t.Fatalf("unexpected WireGuard peer verify error = %v", err)
	}
}

type gatewayRepairApplyRunner struct {
	readyPath                  string
	systemctl                  [][]string
	tunnelStartSawMarkerAbsent bool
	allowedIPs                 string
}

func (runner *gatewayRepairApplyRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	if command.Name == "systemctl" {
		args := append([]string(nil), command.Args...)
		runner.systemctl = append(runner.systemctl, args)
		if reflect.DeepEqual(args, []string{"start", "vpnctl-tunnel-server.service"}) {
			_, err := os.Lstat(runner.readyPath)
			runner.tunnelStartSawMarkerAbsent = errors.Is(err, os.ErrNotExist)
		}
		if reflect.DeepEqual(args, []string{"is-active", "--quiet", "vpnctl-tunnel-server.service"}) {
			return linuxplatform.ProbeResult{ExitCode: 3}, nil
		}
		return linuxplatform.ProbeResult{}, nil
	}
	key := command.Name + " " + strings.Join(command.Args, " ")
	switch key {
	case "wg show vpnctl-wg public-key":
		return linuxplatform.ProbeResult{Stdout: []byte(joinGatewayWireGuardPublic() + "\n")}, nil
	case "wg show vpnctl-wg listen-port":
		return linuxplatform.ProbeResult{Stdout: []byte("51820\n")}, nil
	case "ip -4 -o address show dev vpnctl-wg":
		return linuxplatform.ProbeResult{Stdout: []byte("7: vpnctl-wg inet 10.66.0.1/24 scope global vpnctl-wg\n7: vpnctl-wg inet 10.67.0.1/24 scope global vpnctl-wg\n")}, nil
	case "wg show vpnctl-wg allowed-ips":
		return linuxplatform.ProbeResult{Stdout: []byte(runner.allowedIPs)}, nil
	case "ss -H -lunp sport = :8443":
		return linuxplatform.ProbeResult{}, nil
	case "ss -H -ltnp sport = :8443":
		return linuxplatform.ProbeResult{Stdout: []byte("LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:((\"mihomo\",pid=41,fd=7))\n")}, nil
	default:
		return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected gateway repair command %q", key)
	}
}

func sawGatewayRepairSystemctl(values [][]string, want []string) bool {
	for _, value := range values {
		if reflect.DeepEqual(value, want) {
			return true
		}
	}
	return false
}
