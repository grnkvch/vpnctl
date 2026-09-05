package operations

import (
	"fmt"
	"path/filepath"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
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

var _ RepairScopeResolver = (*LocalRoleRepairScopeResolver)(nil)
