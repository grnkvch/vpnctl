package lifecycle

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestRenderGatewayIdentityFirewallUsesOnlyActiveIdentities(t *testing.T) {
	t.Parallel()

	state := gatewayIdentityFirewallState(t)
	services := GatewayIdentityFirewallServices{
		ClientTCPPorts: []int{53}, ClientUDPPorts: []int{53},
		NodeTCPPorts: []int{9443, 17000, 53}, NodeUDPPorts: []int{53},
	}
	artifact, err := RenderGatewayIdentityFirewall(state, services)
	if err != nil {
		t.Fatalf("RenderGatewayIdentityFirewall() error = %v", err)
	}
	rules := string(artifact.Definition())
	for _, required := range []string{
		"set active_client_v4 {\n    type ipv4_addr\n    elements = { 10.66.0.2, 10.66.0.3, 10.66.0.4, 10.66.0.5, 10.66.0.6 }",
		"set active_node_v4 {\n    type ipv4_addr\n    elements = { 10.67.0.2, 10.67.0.3 }",
		"set active_overlay_v4 {\n    type ipv4_addr\n    elements = { 10.66.0.2, 10.66.0.3, 10.66.0.4, 10.66.0.5, 10.66.0.6, 10.67.0.2, 10.67.0.3 }",
		`iifname "vpnctl-wg" jump active_identity_guard`,
		`iifname "vpnctl-wg" oifname "eth0" ip saddr @active_overlay_v4 accept`,
		`oifname "eth0" ip saddr @active_overlay_v4 masquerade`,
	} {
		if !strings.Contains(rules, required) {
			t.Errorf("identity firewall is missing %q", required)
		}
	}
	for _, excluded := range []string{"10.66.0.7", "10.66.0.8", "10.67.0.4", "10.67.0.5"} {
		if strings.Contains(activeIdentitySetDefinitions(rules), excluded) {
			t.Errorf("inactive identity %s entered an active firewall set", excluded)
		}
	}

	reordered := state
	reordered.Clients = append([]model.Client(nil), state.Clients...)
	reordered.Nodes = append([]model.Node(nil), state.Nodes...)
	reordered.Transports = append([]model.Transport(nil), state.Transports...)
	slices.Reverse(reordered.Clients)
	slices.Reverse(reordered.Nodes)
	slices.Reverse(reordered.Transports)
	reorderedArtifact, err := RenderGatewayIdentityFirewall(reordered, services)
	if err != nil {
		t.Fatalf("RenderGatewayIdentityFirewall(reordered) error = %v", err)
	}
	if !bytes.Equal(artifact.Definition(), reorderedArtifact.Definition()) {
		t.Fatal("equivalent identity state rendered a different firewall")
	}
}

func TestRenderGatewayIdentityFirewallRejectsInvalidOrNonGatewayState(t *testing.T) {
	t.Parallel()

	state := gatewayIdentityFirewallState(t)
	state.Clients[0].OverlayIPv4 = "10.67.0.20"
	if artifact, err := RenderGatewayIdentityFirewall(state, GatewayIdentityFirewallServices{}); err == nil || len(artifact.Definition()) != 0 {
		t.Fatalf("invalid state rendered a firewall: %q, %v", artifact.Definition(), err)
	}
	node := initialNodeState(identityFirewallID(100), time.Date(2026, time.September, 3, 15, 0, 0, 0, time.UTC), gatewayTestManifest())
	if artifact, err := RenderGatewayIdentityFirewall(node, GatewayIdentityFirewallServices{}); err == nil || len(artifact.Definition()) != 0 {
		t.Fatalf("node state rendered a gateway firewall: %q, %v", artifact.Definition(), err)
	}
}

func gatewayIdentityFirewallState(t *testing.T) model.State {
	t.Helper()
	now := time.Date(2026, time.September, 3, 15, 0, 0, 0, time.UTC)
	revokedAt := now.Add(time.Hour)
	state := initialGatewayState(identityFirewallID(100), now, gatewayNetworkPlanForIdentityFirewall(), 2222, gatewayTestManifest(), model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: now,
	})
	for index := 0; index < 7; index++ {
		lifecycle := model.LifecycleActive
		var revoked *time.Time
		if index == 5 {
			lifecycle, revoked = model.LifecycleRevoked, &revokedAt
		} else if index == 6 {
			lifecycle, revoked = model.LifecycleDeleted, &revokedAt
		}
		id := identityFirewallID(index + 1)
		state.Clients = append(state.Clients, model.Client{
			SchemaVersion: model.ResourceSchemaVersion, ID: id, Name: fmt.Sprintf("client-%d", index+1),
			Platform: "generic", Lifecycle: lifecycle, OverlayIPv4: fmt.Sprintf("10.66.0.%d", index+2),
			CredentialGeneration: 1, AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
			CreatedAt: now, RevokedAt: revoked,
		})
		if lifecycle != model.LifecycleDeleted {
			state.Transports = append(state.Transports, identityFirewallTransport(model.TargetClient, id, lifecycle))
		}
	}
	for index := 0; index < 4; index++ {
		lifecycle := model.LifecycleActive
		var revoked *time.Time
		if index == 2 {
			lifecycle, revoked = model.LifecycleRevoked, &revokedAt
		} else if index == 3 {
			lifecycle, revoked = model.LifecycleDeleted, &revokedAt
		}
		id := identityFirewallID(index + 20)
		state.Nodes = append(state.Nodes, model.Node{
			SchemaVersion: model.ResourceSchemaVersion, ID: id, Name: fmt.Sprintf("node-%d", index+1),
			Lifecycle: lifecycle, OverlayIPv4: fmt.Sprintf("10.67.0.%d", index+2), CredentialGeneration: 1,
			AssignedPresets: []string{}, ActiveTransport: model.TransportStandard, IdempotencyRecords: []model.IdempotencyRecord{},
			CreatedAt: now, RevokedAt: revoked,
		})
		if lifecycle != model.LifecycleDeleted {
			state.Transports = append(state.Transports, identityFirewallTransport(model.TargetNode, id, lifecycle))
		}
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("identity firewall fixture: %v", err)
	}
	return state
}

func identityFirewallTransport(kind model.TargetKind, id string, lifecycle model.Lifecycle) model.Transport {
	state := model.TransportActive
	if lifecycle == model.LifecycleRevoked {
		state = model.TransportDisabled
	}
	return model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: kind, OwnerID: id,
		Kind: model.TransportStandard, State: state, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: 51820,
		CredentialGeneration: 1, CredentialRef: model.SecretRef("wireguard-key:" + id + "-g1"),
		PublicKey: "public-" + id, ConfigHash: strings.Repeat("a", 64),
	}
}

func identityFirewallID(serial int) string {
	return fmt.Sprintf("10000000-0000-4000-8000-%012x", serial)
}

func gatewayNetworkPlanForIdentityFirewall() linuxplatform.GatewayNetworkPlan {
	return linuxplatform.GatewayNetworkPlan{
		PublicIPv4: "203.0.113.10", ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
		ExternalInterface: "eth0", InterfaceSource: "explicit",
	}
}

func activeIdentitySetDefinitions(rules string) string {
	start := strings.Index(rules, "  set active_client_v4")
	end := strings.Index(rules, "  set blocked_egress_v4")
	if start < 0 || end < start {
		return rules
	}
	return rules[start:end]
}
