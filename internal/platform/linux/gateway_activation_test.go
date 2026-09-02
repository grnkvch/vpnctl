package linux

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestActivateGatewayInstallsFirewallBeforeForwarding(t *testing.T) {
	t.Parallel()

	runner := &recordingGatewayActivationRunner{}
	manager, err := NewNetworkManager(runner)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := RenderGatewayFirewall(GatewayFirewallInput{
		ExternalInterface: "eth0", SSHPort: 2222,
		ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ActivateGateway(context.Background(), artifact); err != nil {
		t.Fatalf("ActivateGateway() error = %v", err)
	}

	want := []string{
		"nft --check --file -", "nft --file -",
		"sysctl -q -w net.ipv4.conf.all.accept_redirects=0",
		"sysctl -q -w net.ipv4.conf.all.rp_filter=1",
		"sysctl -q -w net.ipv4.conf.all.src_valid_mark=1",
		"sysctl -q -w net.ipv4.ip_forward=1",
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("activation calls = %v, want %v", runner.calls, want)
	}
	if len(runner.stdins) != 2 || string(runner.stdins[0]) != string(runner.stdins[1]) || !strings.Contains(string(runner.stdins[0]), "table inet vpnctl {") {
		t.Fatalf("nft validation/activation did not use the same owned batch")
	}
	if strings.Contains(string(runner.stdins[0]), "flush ruleset") || strings.Contains(string(runner.stdins[0]), "delete table") {
		t.Fatalf("initial activation touches resources outside a new owned table")
	}
}

func TestActivateGatewayStopsBeforeMutationWhenNFTCheckFails(t *testing.T) {
	t.Parallel()

	runner := &recordingGatewayActivationRunner{failCall: "nft --check --file -"}
	manager, _ := NewNetworkManager(runner)
	artifact, _ := RenderGatewayFirewall(GatewayFirewallInput{
		ExternalInterface: "eth0", SSHPort: 22,
		ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24",
	})
	if err := manager.ActivateGateway(context.Background(), artifact); err == nil {
		t.Fatal("ActivateGateway() succeeded after nft validation failure")
	}
	if !reflect.DeepEqual(runner.calls, []string{"nft --check --file -"}) {
		t.Fatalf("calls after validation failure = %v", runner.calls)
	}
}

func TestGatewayInitNetworkScopeMatchesCandidate(t *testing.T) {
	t.Parallel()

	scope := GatewayInitNetworkScope()
	want := []string{
		"net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.all.src_valid_mark", "net.ipv4.ip_forward",
	}
	if !reflect.DeepEqual(scope.Sysctls, want) {
		t.Fatalf("gateway init scope = %v, want %v", scope.Sysctls, want)
	}
}

type recordingGatewayActivationRunner struct {
	calls    []string
	stdins   [][]byte
	failCall string
}

func (runner *recordingGatewayActivationRunner) Run(_ context.Context, command ProbeCommand) (ProbeResult, error) {
	call := command.Name
	if len(command.Args) != 0 {
		call += " " + strings.Join(command.Args, " ")
	}
	runner.calls = append(runner.calls, call)
	if len(command.Stdin) != 0 {
		runner.stdins = append(runner.stdins, append([]byte(nil), command.Stdin...))
	}
	if call == runner.failCall {
		return ProbeResult{ExitCode: 1, Stderr: []byte("synthetic failure")}, nil
	}
	return ProbeResult{}, nil
}
