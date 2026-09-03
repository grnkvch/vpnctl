package lifecycle

import (
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

// GatewayIdentityFirewallServices is the role-scoped gateway service surface.
// It is kept separate from identity addresses so later providers can extend
// their internal ports without weakening active-identity filtering.
type GatewayIdentityFirewallServices struct {
	ClientTCPPorts []int
	ClientUDPPorts []int
	NodeTCPPorts   []int
	NodeUDPPorts   []int
}

// RenderGatewayIdentityFirewall is the authoritative state-to-host boundary
// for the gateway firewall. Revoked/deleted records keep their address history
// in state, but only active identities enter the source allow sets.
func RenderGatewayIdentityFirewall(state model.State, services GatewayIdentityFirewallServices) (linuxplatform.GatewayFirewallArtifact, error) {
	if err := state.Validate(); err != nil {
		return linuxplatform.GatewayFirewallArtifact{}, fmt.Errorf("validate gateway identity firewall state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return linuxplatform.GatewayFirewallArtifact{}, fmt.Errorf("gateway identity firewall requires gateway state")
	}
	clients := make([]string, 0, len(state.Clients))
	for _, client := range state.Clients {
		if client.Lifecycle == model.LifecycleActive {
			clients = append(clients, client.OverlayIPv4)
		}
	}
	nodes := make([]string, 0, len(state.Nodes))
	for _, node := range state.Nodes {
		if node.Lifecycle == model.LifecycleActive {
			nodes = append(nodes, node.OverlayIPv4)
		}
	}
	return linuxplatform.RenderGatewayFirewall(linuxplatform.GatewayFirewallInput{
		ExternalInterface: state.Host.ExternalInterface,
		SSHPort:           state.Host.SSHPort,
		ClientCIDR:        state.Host.ClientCIDR,
		NodeCIDR:          state.Host.NodeCIDR,
		ActiveClientIPv4:  clients,
		ActiveNodeIPv4:    nodes,
		ClientTCPPorts:    append([]int(nil), services.ClientTCPPorts...),
		ClientUDPPorts:    append([]int(nil), services.ClientUDPPorts...),
		NodeTCPPorts:      append([]int(nil), services.NodeTCPPorts...),
		NodeUDPPorts:      append([]int(nil), services.NodeUDPPorts...),
	})
}
