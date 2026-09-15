package lifecycle

import (
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

// GatewayIdentityFirewallServices is the role-scoped gateway service surface.
// It is kept separate from identity addresses so later providers can extend
// their internal ports without weakening active-identity filtering.
type GatewayIdentityFirewallServices = linuxplatform.GatewayIdentityFirewallServices

// RenderGatewayIdentityFirewall is the authoritative state-to-host boundary
// for the gateway firewall. Revoked/deleted records keep their address history
// in state, but only active identities enter the source allow sets.
func RenderGatewayIdentityFirewall(state model.State, services GatewayIdentityFirewallServices) (linuxplatform.GatewayFirewallArtifact, error) {
	return linuxplatform.RenderGatewayIdentityFirewall(state, services)
}
