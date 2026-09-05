package operations

import (
	"fmt"
	"path/filepath"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

// LocalRoleRepairScopeResolver accepts only the unit and generated-config
// namespace owned by one initialized local role. Scope is derived from the
// authoritative role and node identity supplied at construction, never from
// service reachability or an untrusted resource component.
type LocalRoleRepairScopeResolver struct {
	role       model.Role
	nodeID     string
	component  string
	configRoot string
	units      map[string]struct{}
}

func NewLocalRoleRepairScopeResolver(role model.Role, nodeID string) (*LocalRoleRepairScopeResolver, error) {
	resolver := &LocalRoleRepairScopeResolver{role: role, nodeID: nodeID, units: make(map[string]struct{})}
	switch role {
	case model.RoleGateway:
		if nodeID != "" {
			return nil, fmt.Errorf("gateway repair scope cannot contain a node ID")
		}
		resolver.component = gatewayInitConvergenceComponent
		resolver.configRoot = "/etc/vpnctl/generated/gateway"
	case model.RoleNode:
		if err := model.ValidateResourceID(nodeID); err != nil {
			return nil, fmt.Errorf("node repair scope ID: %w", err)
		}
		resolver.component = nodeInitConvergenceComponent
		resolver.configRoot = "/etc/vpnctl/generated/node"
	default:
		return nil, fmt.Errorf("unsupported local repair role %q", role)
	}
	for _, name := range linuxplatform.RoleUnitNames(role) {
		resolver.units[name] = struct{}{}
	}
	return resolver, nil
}

func (resolver *LocalRoleRepairScopeResolver) ResolveRepairScope(action RepairAction) (ApplyScope, error) {
	if resolver == nil || resolver.component == "" || resolver.configRoot == "" || resolver.units == nil {
		return ApplyScope{}, fmt.Errorf("local repair scope resolver is incomplete")
	}
	resource := action.Resource
	if err := resource.validate(); err != nil {
		return ApplyScope{}, fmt.Errorf("invalid local repair resource: %w", err)
	}
	if resource.Component != resolver.component {
		return ApplyScope{}, fmt.Errorf("resource component %q is outside local %s repair ownership", resource.Component, resolver.role)
	}
	switch resource.Kind {
	case ManagedResourceUnit:
		if _, owned := resolver.units[resource.ID]; !owned {
			return ApplyScope{}, fmt.Errorf("unit %q is outside local %s repair ownership", resource.ID, resolver.role)
		}
	case ManagedResourceFile:
		if !filepath.IsAbs(resource.ID) || filepath.Clean(resource.ID) != resource.ID || filepath.Dir(resource.ID) != resolver.configRoot {
			return ApplyScope{}, fmt.Errorf("file %q is outside local %s repair ownership", resource.ID, resolver.role)
		}
	default:
		return ApplyScope{}, fmt.Errorf("resource kind %q is outside local %s repair ownership", resource.Kind, resolver.role)
	}
	return ApplyScope{Role: resolver.role, NodeID: resolver.nodeID}, nil
}

// ResolveRepairRestartUnits makes every service side effect part of the public
// repair action. Marker/bootstrap files need no live reload; service-owned
// configs restart only their exact consumer.
func (resolver *LocalRoleRepairScopeResolver) ResolveRepairRestartUnits(action RepairAction) ([]string, error) {
	if _, err := resolver.ResolveRepairScope(action); err != nil {
		return nil, err
	}
	if action.Resource.Kind == ManagedResourceUnit || action.Action == RepairRemove {
		return []string{}, nil
	}
	name := filepath.Base(action.Resource.ID)
	var unit string
	switch resolver.role {
	case model.RoleGateway:
		switch name {
		case "bootstrap.conf", "gateway-controller.ready":
			return []string{}, nil
		case routing.GatewayDNSConfigFileName, routing.GatewayDNSReadyFileName:
			unit = "vpnctl-dns.service"
		case transport.StandardConfigFileName, transport.GatewayStandardReadyFileName:
			unit = "vpnctl-standard.service"
		case transport.RestrictedConfigFileName, transport.GatewayRestrictedReadyFileName:
			unit = "vpnctl-restricted.service"
		case tunnel.FRPServerConfigFileName, tunnel.FRPServerReadyFileName,
			tunnel.FRPServerCertificateName, tunnel.FRPServerPrivateKeyName:
			unit = "vpnctl-tunnel-server.service"
		default:
			return nil, fmt.Errorf("gateway config %q has no repair restart contract", name)
		}
	case model.RoleNode:
		switch name {
		case "bootstrap.conf":
			return []string{}, nil
		case transport.StandardConfigFileName, "node-standard.ready":
			unit = "vpnctl-standard.service"
		case routing.NodeRoutingConfigFileName, "node-routing.ready":
			unit = "vpnctl-routing.service"
		case routing.NodeRoutingGuardConfigFileName, routing.NodeDNSIntegrationConfigName, "node-routing-guard.ready":
			unit = "vpnctl-routing-guard.service"
		case tunnel.FRPClientConfigFileName, tunnel.FRPClientReadyFileName, tunnel.FRPServerCertificateName:
			unit = "vpnctl-tunnel-client.service"
		default:
			return nil, fmt.Errorf("node config %q has no repair restart contract", name)
		}
	default:
		return nil, fmt.Errorf("unsupported local repair role %q", resolver.role)
	}
	return []string{unit}, nil
}

var _ RepairScopeResolver = (*LocalRoleRepairScopeResolver)(nil)
var _ RepairRestartResolver = (*LocalRoleRepairScopeResolver)(nil)
