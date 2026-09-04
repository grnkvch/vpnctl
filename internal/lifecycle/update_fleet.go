package lifecycle

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

type GatewayUpdateFleetChecker struct{}

type NodeUpdatePreflightClient interface {
	Preflight(context.Context, model.ComponentManifest) (NodeUpdatePreflightPlan, error)
}

type NodeUpdateFleetChecker struct {
	preflighter NodeUpdatePreflightClient
}

func NewNodeUpdateFleetChecker(preflighter NodeUpdatePreflightClient) (*NodeUpdateFleetChecker, error) {
	if preflighter == nil {
		return nil, fmt.Errorf("node update preflighter is required")
	}
	return &NodeUpdateFleetChecker{preflighter: preflighter}, nil
}

func (GatewayUpdateFleetChecker) Check(_ context.Context, state model.State, target model.ComponentManifest) (UpdateFleetCompatibility, error) {
	result := UpdateFleetCompatibility{Role: model.RoleGateway, Compatible: true, Nodes: []UpdateFleetNode{}, RequiresAction: []string{}}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return UpdateFleetCompatibility{}, fmt.Errorf("gateway update fleet requires valid gateway state")
	}
	if err := target.Validate(); err != nil {
		return UpdateFleetCompatibility{}, fmt.Errorf("validate target gateway manifest: %w", err)
	}
	protocolsByNode := observedNodeProtocols(state)
	for _, node := range state.Nodes {
		if node.Lifecycle != model.LifecycleActive {
			continue
		}
		entry := UpdateFleetNode{ID: node.ID, Name: node.Name, ControlProtocol: protocolsByNode[node.ID], Compatible: true}
		if entry.ControlProtocol == "" {
			entry.Compatible, entry.Code, result.Compatible = false, "node_protocol_unknown", false
		} else if _, found := mutuallySupportedProtocol(target.ControlProtocols, []string{entry.ControlProtocol}); !found {
			entry.Compatible, entry.Code, result.Compatible = false, "node_outside_target_window", false
		}
		result.Nodes = append(result.Nodes, entry)
	}
	sort.Slice(result.Nodes, func(left, right int) bool { return result.Nodes[left].ID < result.Nodes[right].ID })
	if !result.Compatible {
		result.RequiresAction = append(result.RequiresAction, "select a gateway release whose compatibility window includes every active node, then update gateway before nodes")
	}
	return result, nil
}

func (checker *NodeUpdateFleetChecker) Check(ctx context.Context, state model.State, target model.ComponentManifest) (UpdateFleetCompatibility, error) {
	result := UpdateFleetCompatibility{Role: model.RoleNode, Compatible: true, Nodes: []UpdateFleetNode{}, RequiresAction: []string{}}
	if ctx == nil || checker == nil || checker.preflighter == nil {
		return UpdateFleetCompatibility{}, fmt.Errorf("node update fleet checker is incomplete")
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleNode {
		return UpdateFleetCompatibility{}, fmt.Errorf("node update fleet requires valid node state")
	}
	if len(state.Nodes) == 0 {
		return result, nil
	}
	plan, err := checker.preflighter.Preflight(ctx, target)
	if err != nil {
		return UpdateFleetCompatibility{}, err
	}
	result.GatewayVersion = plan.GatewayVPNCTLVersion
	result.SelectedProtocol = plan.SelectedProtocol
	result.RequiresAction = append(result.RequiresAction, plan.RequiresAction...)
	result.Compatible = plan.Status == NodeUpdateReady
	if !result.Compatible && len(result.RequiresAction) == 0 {
		result.RequiresAction = append(result.RequiresAction, "restore gateway management connectivity and compatibility before updating this node")
	}
	return result, nil
}

func observedNodeProtocols(state model.State) map[string]string {
	result := make(map[string]string)
	for _, node := range state.Nodes {
		if node.ControlProtocol != "" {
			result[node.ID] = node.ControlProtocol
		}
	}
	for _, invite := range state.Invites {
		if invite.State != model.InviteConsumed {
			continue
		}
		if invite.NodeID != "" {
			if result[invite.NodeID] != "" {
				continue
			}
			result[invite.NodeID] = invite.ControlProtocol
			continue
		}
		for _, node := range state.Nodes {
			if strings.EqualFold(node.Name, invite.NodeName) {
				if result[node.ID] == "" {
					result[node.ID] = invite.ControlProtocol
				}
				break
			}
		}
	}
	return result
}

var _ UpdateFleetChecker = GatewayUpdateFleetChecker{}
var _ UpdateFleetChecker = (*NodeUpdateFleetChecker)(nil)
