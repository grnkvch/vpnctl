package routing

import (
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
)

type NodeRoutingCredentialReader interface {
	Get(model.SecretRef) ([]byte, error)
}

// ResolveNodeRoutingActiveOutbound translates the node's authoritative manual
// active record into the single routing binding. Standard uses no secret at
// this layer; restricted reads only the two exact referenced credentials.
func ResolveNodeRoutingActiveOutbound(state model.State, credentials NodeRoutingCredentialReader) (NodeRoutingActiveOutbound, error) {
	if err := state.Validate(); err != nil {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("validate node state for routing binding: %w", err)
	}
	if state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Lifecycle != model.LifecycleActive || state.Nodes[0].Gateway == nil {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("active routing binding requires one joined active local node")
	}
	node := state.Nodes[0]
	var active model.Transport
	found := false
	for _, candidate := range state.Transports {
		if candidate.OwnerKind == model.TargetNode && candidate.OwnerID == node.ID && candidate.Kind == node.ActiveTransport {
			if found {
				return NodeRoutingActiveOutbound{}, fmt.Errorf("active routing transport is duplicated")
			}
			active, found = candidate, true
		}
	}
	if !found || active.State != model.TransportActive || active.CredentialGeneration != node.CredentialGeneration {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("node active routing transport does not match authoritative identity generation")
	}
	binding := NodeRoutingActiveOutbound{
		Kind: active.Kind, CredentialGeneration: active.CredentialGeneration,
		GatewayPublicIPv4: node.Gateway.PublicIPv4, GatewayOverlayIPv4: node.Gateway.GatewayOverlayIPv4,
	}
	if active.Kind == model.TransportStandard {
		return binding, nil
	}
	if credentials == nil {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("restricted active routing binding requires credential reader")
	}
	gatewayContent, err := credentials.Get(node.Gateway.RestrictedServerCredentialRef)
	if err != nil {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("read restricted gateway routing credential: %w", err)
	}
	gatewaySecret, err := restricted.DecodeGatewaySecret(gatewayContent)
	if err != nil {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("validate restricted gateway routing credential: %w", err)
	}
	identityContent, err := credentials.Get(active.CredentialRef)
	if err != nil {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("read restricted node routing identity: %w", err)
	}
	if _, err := restricted.DecodeIdentitySecret(identityContent); err != nil {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("validate restricted node routing identity: %w", err)
	}
	binding.RestrictedServerPassword = gatewaySecret.ShadowsocksPassword
	binding.RestrictedIdentitySecret = append([]byte(nil), identityContent...)
	binding.RestrictedHandshakeHost = active.HandshakeHost
	return binding, nil
}

// NodeRoutingBundleCandidate is the atomic rendering boundary for the
// userspace engine and its independent kernel guard. Callers cannot bind the
// two artifacts to different transports, gateway addresses, or matcher
// generations.
type NodeRoutingBundleCandidate struct {
	routing NodeRoutingCandidate
	guard   NodeRoutingGuardCandidate
	dns     NodeDNSIntegrationCandidate
}

func (candidate NodeRoutingBundleCandidate) Routing() NodeRoutingCandidate { return candidate.routing }

func (candidate NodeRoutingBundleCandidate) Guard() NodeRoutingGuardCandidate { return candidate.guard }

func (candidate NodeRoutingBundleCandidate) DNS() NodeDNSIntegrationCandidate { return candidate.dns }

// RenderNodeRoutingBundle derives every guard-owned binding field from the
// one explicit active outbound. Direct underlay details and the bounded
// recovery/ingress endpoint lists remain host-discovery inputs.
func RenderNodeRoutingBundle(routingRequest NodeRoutingRenderRequest, guardConfig NodeRoutingGuardConfig) (NodeRoutingBundleCandidate, error) {
	if routingRequest.ActiveOutbound.Kind == "" {
		return NodeRoutingBundleCandidate{}, fmt.Errorf("production node routing bundle requires one active outbound")
	}
	routingCandidate, err := RenderNodeRoutingConfig(routingRequest)
	if err != nil {
		return NodeRoutingBundleCandidate{}, err
	}
	active := routingRequest.ActiveOutbound
	guardConfig.Matcher = cloneNodeRoutingMatcherIR(routingRequest.Matcher)
	guardConfig.GatewayIPv4 = active.GatewayPublicIPv4
	guardConfig.GatewayOverlayIPv4 = active.GatewayOverlayIPv4
	guardConfig.ActiveTransport = active.Kind
	guardCandidate, err := RenderNodeRoutingGuardConfig(guardConfig)
	if err != nil {
		return NodeRoutingBundleCandidate{}, err
	}
	if descriptor := routingCandidate.Descriptor(); descriptor.ActiveTransport != guardCandidate.Config().ActiveTransport {
		return NodeRoutingBundleCandidate{}, fmt.Errorf("node routing engine and guard active transports differ")
	}
	dnsCandidate, err := RenderNodeDNSIntegrationConfig(guardConfig.DirectRoute.Interface)
	if err != nil {
		return NodeRoutingBundleCandidate{}, err
	}
	return NodeRoutingBundleCandidate{routing: routingCandidate, guard: guardCandidate, dns: dnsCandidate}, nil
}
