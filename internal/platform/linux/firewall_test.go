package linux

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestRenderGatewayFirewallMatchesGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		golden string
		input  GatewayFirewallInput
	}{
		{
			name: "internal services", golden: "gateway.nft",
			input: GatewayFirewallInput{
				ExternalInterface: "eth0", SSHPort: 2222, ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24",
				ClientTCPPorts: []int{53}, ClientUDPPorts: []int{53},
				NodeTCPPorts: []int{17000, 9443, 53, 9443}, NodeUDPPorts: []int{53},
			},
		},
		{
			name: "minimal init", golden: "gateway-minimal.nft",
			input: GatewayFirewallInput{
				ExternalInterface: "eth0", SSHPort: 22, ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24",
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			artifact, err := RenderGatewayFirewall(test.input)
			if err != nil {
				t.Fatalf("RenderGatewayFirewall() error = %v", err)
			}
			want, err := os.ReadFile("testdata/firewall/" + test.golden)
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}
			if !bytes.Equal(artifact.Definition(), want) {
				t.Fatalf("rendered firewall differs from golden:\n--- want ---\n%s--- got ---\n%s", want, artifact.Definition())
			}
			if artifact.Family() != GatewayFirewallFamily || artifact.Table() != GatewayFirewallTable {
				t.Fatalf("artifact ownership = %s/%s", artifact.Family(), artifact.Table())
			}
		})
	}
}

func TestGatewayFirewallTransactionTouchesOnlyOwnedTable(t *testing.T) {
	t.Parallel()

	artifact := mustGatewayFirewall(t, GatewayFirewallInput{
		ExternalInterface: "ens3", SSHPort: 22, ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24",
	})
	install, err := artifact.Transaction(false)
	if err != nil {
		t.Fatalf("install transaction: %v", err)
	}
	replace, err := artifact.Transaction(true)
	if err != nil {
		t.Fatalf("replace transaction: %v", err)
	}
	if bytes.HasPrefix(install, []byte("delete ")) {
		t.Fatalf("initial transaction unexpectedly deletes a table:\n%s", install)
	}
	if !bytes.HasPrefix(replace, []byte("delete table inet vpnctl\ntable inet vpnctl {\n")) {
		t.Fatalf("replacement is not one exact owned-table batch:\n%s", replace)
	}
	for _, transaction := range [][]byte{install, replace} {
		text := string(transaction)
		for _, forbidden := range []string{"flush ruleset", "delete table inet filter", "delete table ip nat", "destroy table"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("transaction contains foreign/global mutation %q", forbidden)
			}
		}
		if strings.Count(text, "table inet vpnctl") != 1+strings.Count(text, "delete table inet vpnctl") {
			t.Errorf("transaction contains an unexpected table declaration:\n%s", text)
		}
	}

	definition := artifact.Definition()
	definition[0] = 'X'
	if bytes.Equal(definition, artifact.Definition()) {
		t.Fatal("Definition exposed mutable renderer storage")
	}
	if _, err := (GatewayFirewallArtifact{}).Transaction(true); err == nil {
		t.Fatal("Transaction accepted an empty artifact")
	}
}

func TestGatewayFirewallEnforcesPublicPortAndIsolationContract(t *testing.T) {
	t.Parallel()

	artifact := mustGatewayFirewall(t, GatewayFirewallInput{
		ExternalInterface: "eth0", SSHPort: 22, ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24",
	})
	rules := string(artifact.Definition())
	required := []string{
		"type filter hook input priority filter; policy drop;",
		"ct state { established, related } accept",
		`iifname "lo" accept`,
		"ip saddr 0.0.0.0/0 tcp dport { 22, 443, 8443 } accept",
		"ip saddr 0.0.0.0/0 udp dport 51820 accept",
		"type filter hook forward priority filter; policy drop;",
		"ip saddr @client_v4 ip daddr @client_v4 drop",
		"ip saddr @client_v4 ip daddr @node_v4 drop",
		"ip saddr @node_v4 ip daddr @client_v4 drop",
		"ip saddr @node_v4 ip daddr @node_v4 drop",
		`iifname "vpnctl-wg" oifname "eth0" ip saddr @overlay_v4 accept`,
		`oifname "eth0" ip saddr @overlay_v4 masquerade`,
	}
	for _, fragment := range required {
		if !strings.Contains(rules, fragment) {
			t.Errorf("firewall is missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"udp dport 443", "udp dport 8443", "policy accept;\n\n    ct state invalid drop"} {
		if strings.Contains(rules, forbidden) {
			t.Errorf("firewall contains forbidden input/forward behavior %q", forbidden)
		}
	}
}

func TestRenderGatewayFirewallIsDeterministicAndDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	input := GatewayFirewallInput{
		ExternalInterface: "eth0", SSHPort: 8443, ClientCIDR: "10.80.0.0/24", NodeCIDR: "10.81.0.0/24",
		ClientTCPPorts: []int{9443, 53, 9443}, ClientUDPPorts: []int{5353, 53},
		NodeTCPPorts: []int{17000, 9443}, NodeUDPPorts: []int{5353},
	}
	beforeClientTCP := append([]int(nil), input.ClientTCPPorts...)
	beforeClientUDP := append([]int(nil), input.ClientUDPPorts...)
	beforeNodeTCP := append([]int(nil), input.NodeTCPPorts...)
	beforeNodeUDP := append([]int(nil), input.NodeUDPPorts...)
	first := mustGatewayFirewall(t, input)
	if !reflect.DeepEqual(input.ClientTCPPorts, beforeClientTCP) || !reflect.DeepEqual(input.ClientUDPPorts, beforeClientUDP) ||
		!reflect.DeepEqual(input.NodeTCPPorts, beforeNodeTCP) || !reflect.DeepEqual(input.NodeUDPPorts, beforeNodeUDP) {
		t.Fatal("RenderGatewayFirewall() mutated its input slices")
	}
	input.ClientTCPPorts = []int{53, 9443}
	input.ClientUDPPorts = []int{53, 5353}
	input.NodeTCPPorts = []int{9443, 17000}
	input.NodeUDPPorts = []int{5353}
	second := mustGatewayFirewall(t, input)
	if !bytes.Equal(first.Definition(), second.Definition()) {
		t.Fatalf("equivalent inputs rendered differently:\n%s\n%s", first.Definition(), second.Definition())
	}
}

func TestRenderGatewayFirewallRejectsInvalidInputsBeforeOutput(t *testing.T) {
	t.Parallel()

	tests := []GatewayFirewallInput{
		{ExternalInterface: "", SSHPort: 22, ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24"},
		{ExternalInterface: "eth0", OverlayInterface: "eth0", SSHPort: 22, ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24"},
		{ExternalInterface: "eth0", SSHPort: 0, ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24"},
		{ExternalInterface: "eth0", SSHPort: 22, ClientCIDR: "10.66.0.1/24", NodeCIDR: "10.67.0.0/24"},
		{ExternalInterface: "eth0", SSHPort: 22, ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.66.0.128/25"},
		{ExternalInterface: "eth0", SSHPort: 22, ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24", NodeTCPPorts: []int{0}},
	}
	for _, input := range tests {
		artifact, err := RenderGatewayFirewall(input)
		if !errors.Is(err, ErrInvalidGatewayFirewall) {
			t.Errorf("RenderGatewayFirewall(%+v) error = %v", input, err)
		}
		if artifact.definition != nil {
			t.Errorf("invalid input produced partial artifact: %+v", artifact)
		}
	}
}

func mustGatewayFirewall(t *testing.T, input GatewayFirewallInput) GatewayFirewallArtifact {
	t.Helper()
	artifact, err := RenderGatewayFirewall(input)
	if err != nil {
		t.Fatalf("RenderGatewayFirewall() error = %v", err)
	}
	return artifact
}
