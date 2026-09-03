package transport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestStandardHealthObservesGatewayPeerWithoutChangingRuntimeRole(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	interfaceKey := standardTestKey(1)
	peerKey := standardTestKey(2)
	runner := &standardProbeRunner{results: map[string]linuxplatform.ProbeResult{
		"wg show vpnctl-wg public-key":        {Stdout: []byte(interfaceKey + "\n")},
		"wg show vpnctl-wg listen-port":       {Stdout: []byte("51820\n")},
		"ip -4 -o address show dev vpnctl-wg": {Stdout: []byte("7: vpnctl-wg inet 10.66.0.1/24 scope global vpnctl-wg\n7: vpnctl-wg inet 10.67.0.1/24 scope global vpnctl-wg\n")},
		"wg show vpnctl-wg allowed-ips":       {Stdout: []byte(peerKey + "\t10.67.0.2/32\n")},
		"wg show vpnctl-wg latest-handshakes": {Stdout: []byte(fmt.Sprintf("%s\t%d\n", peerKey, now.Add(-time.Minute).Unix()))},
	}}
	observer, err := NewStandardHealthObserver(runner, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	health, err := observer.Observe(context.Background(), StandardHealthExpectation{
		Identity:    Identity{OwnerKind: model.TargetNode, OwnerID: "20000000-0000-4000-8000-000000000001", CredentialGeneration: 1},
		RuntimeRole: RuntimeActive, HostRole: model.RoleGateway, InterfacePublicKey: interfaceKey,
		LocalAddresses: []string{"10.67.0.1/24", "10.66.0.1/24"}, PeerPublicKey: peerKey,
		PeerAllowedIPs: []string{"10.67.0.2/32"}, RequireHandshake: true,
	})
	if err != nil || health.Condition != HealthHealthy || health.Role != RuntimeActive || health.Code != "wireguard-healthy" {
		t.Fatalf("Observe() = %#v, %v", health, err)
	}
	if len(runner.calls) != 5 {
		t.Fatalf("query count = %d, want 5", len(runner.calls))
	}
}

func TestStandardHealthReportsDegradedActiveWithoutStandbyProbeOrSwitch(t *testing.T) {
	t.Parallel()
	interfaceKey := standardTestKey(3)
	peerKey := standardTestKey(4)
	runner := &standardProbeRunner{results: map[string]linuxplatform.ProbeResult{
		"wg show vpnctl-wg public-key":        {Stdout: []byte(interfaceKey + "\n")},
		"ip -4 -o address show dev vpnctl-wg": {Stdout: []byte("7: vpnctl-wg inet 10.67.0.2/32 scope global vpnctl-wg\n")},
		"wg show vpnctl-wg allowed-ips":       {Stdout: []byte(peerKey + "\t0.0.0.0/0\n")},
		"wg show vpnctl-wg latest-handshakes": {Stdout: []byte(peerKey + "\t0\n")},
	}}
	observer, _ := NewStandardHealthObserver(runner, time.Now)
	health, err := observer.Observe(context.Background(), StandardHealthExpectation{
		Identity:    Identity{OwnerKind: model.TargetNode, OwnerID: "20000000-0000-4000-8000-000000000002", CredentialGeneration: 1},
		RuntimeRole: RuntimeActive, HostRole: model.RoleNode, InterfacePublicKey: interfaceKey,
		LocalAddresses: []string{"10.67.0.2/32"}, PeerPublicKey: peerKey,
		PeerAllowedIPs: []string{"0.0.0.0/0"}, RequireHandshake: true,
	})
	if err != nil || health.Condition != HealthDegraded || health.Role != RuntimeActive || health.Code != "wireguard-handshake-missing" {
		t.Fatalf("Observe() = %#v, %v", health, err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "restricted") || strings.Contains(call, "systemctl") || strings.Contains(call, " up") || strings.Contains(call, " down") {
			t.Fatalf("health observation mutated or inspected another transport: %s", call)
		}
	}
}

func TestStandardHealthUnavailableInterfacePreservesStandbyRole(t *testing.T) {
	t.Parallel()
	runner := &standardProbeRunner{results: map[string]linuxplatform.ProbeResult{
		"wg show vpnctl-wg public-key": {ExitCode: 1},
	}}
	observer, _ := NewStandardHealthObserver(runner, time.Now)
	health, err := observer.Observe(context.Background(), StandardHealthExpectation{
		Identity:    Identity{OwnerKind: model.TargetNode, OwnerID: "20000000-0000-4000-8000-000000000003", CredentialGeneration: 1},
		RuntimeRole: RuntimeStandby, HostRole: model.RoleNode, InterfacePublicKey: standardTestKey(5),
		LocalAddresses: []string{"10.67.0.3/32"}, PeerPublicKey: standardTestKey(6), PeerAllowedIPs: []string{"0.0.0.0/0"},
	})
	if err != nil || health.Condition != HealthUnavailable || health.Role != RuntimeStandby || health.Code != "wireguard-interface-unavailable" {
		t.Fatalf("Observe() = %#v, %v", health, err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unavailable interface queries = %v", runner.calls)
	}
}

func TestStandardHealthRunnerErrorIsSanitizedFromCommandOutput(t *testing.T) {
	t.Parallel()
	runner := &standardProbeRunner{err: errors.New("runner unavailable")}
	observer, _ := NewStandardHealthObserver(runner, time.Now)
	_, err := observer.Observe(context.Background(), StandardHealthExpectation{
		Identity:    Identity{OwnerKind: model.TargetClient, OwnerID: "30000000-0000-4000-8000-000000000001", CredentialGeneration: 1},
		RuntimeRole: RuntimeActive, HostRole: model.RoleGateway, InterfacePublicKey: standardTestKey(7),
		LocalAddresses: []string{"10.66.0.1/24", "10.67.0.1/24"}, PeerPublicKey: standardTestKey(8), PeerAllowedIPs: []string{"10.66.0.2/32"},
	})
	if err == nil || !strings.Contains(err.Error(), "runner unavailable") {
		t.Fatalf("runner error = %v", err)
	}
}

type standardProbeRunner struct {
	results map[string]linuxplatform.ProbeResult
	err     error
	calls   []string
}

func (runner *standardProbeRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	runner.calls = append(runner.calls, key)
	if runner.err != nil {
		return linuxplatform.ProbeResult{}, runner.err
	}
	result, found := runner.results[key]
	if !found {
		return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected command %s", key)
	}
	return result, nil
}
