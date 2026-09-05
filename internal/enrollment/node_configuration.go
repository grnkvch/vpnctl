package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	nodeStandardReadyFileName     = "node-standard.ready"
	nodeRoutingReadyFileName      = "node-routing.ready"
	nodeRoutingGuardReadyFileName = "node-routing-guard.ready"
)

// NodeConfigurationSecretReader is the smallest root-only secret-store
// surface needed to compile a joined node's service configuration.
type NodeConfigurationSecretReader interface {
	Get(model.SecretRef) ([]byte, error)
}

type NodeConfigurationRuntime struct {
	WireGuardRunner wireguard.Runner
	Now             func() time.Time
}

// NodeConfiguration is a complete, generation-bound set of node service
// files. ConfigFiles returns owned copies so validation and publication cannot
// accidentally mutate the compiler's candidate.
type NodeConfiguration struct {
	stateGeneration uint64
	configs         []linuxplatform.RoleConfigFile
	standard        transport.StandardNodeCandidate
	routing         routing.NodeRoutingCandidate
	tunnel          tunnel.FRPCandidate
}

func (configuration NodeConfiguration) StateGeneration() uint64 {
	return configuration.stateGeneration
}

func (configuration NodeConfiguration) ConfigFiles() []linuxplatform.RoleConfigFile {
	result := make([]linuxplatform.RoleConfigFile, len(configuration.configs))
	for index, config := range configuration.configs {
		result[index] = linuxplatform.RoleConfigFile{Name: config.Name, Content: append([]byte(nil), config.Content...)}
	}
	return result
}

func (configuration NodeConfiguration) StandardCandidate() transport.StandardNodeCandidate {
	return configuration.standard
}

func (configuration NodeConfiguration) RoutingCandidate() routing.NodeRoutingCandidate {
	return configuration.routing
}

func (configuration NodeConfiguration) TunnelCandidate() tunnel.FRPCandidate {
	return configuration.tunnel
}

type NodeConfigurationCompiler struct {
	root    string
	secrets NodeConfigurationSecretReader
	runtime NodeConfigurationRuntime
}

func NewNodeConfigurationCompiler(root string, secrets NodeConfigurationSecretReader, runtime NodeConfigurationRuntime) (*NodeConfigurationCompiler, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fmt.Errorf("node configuration root must be clean and absolute")
	}
	if secrets == nil || runtime.WireGuardRunner == nil {
		return nil, fmt.Errorf("node configuration compiler dependencies are incomplete")
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	return &NodeConfigurationCompiler{root: root, secrets: secrets, runtime: runtime}, nil
}

// Compile materializes the authoritative joined-node state into all four
// staged services without changing files, units, routes, or process state.
func (compiler *NodeConfigurationCompiler) Compile(ctx context.Context, state model.State, snapshot linuxplatform.HostSnapshot) (NodeConfiguration, error) {
	if ctx == nil {
		return NodeConfiguration{}, fmt.Errorf("context is required")
	}
	if compiler == nil || compiler.secrets == nil || compiler.runtime.WireGuardRunner == nil || compiler.runtime.Now == nil {
		return NodeConfiguration{}, fmt.Errorf("node configuration compiler is incomplete")
	}
	if err := state.Validate(); err != nil {
		return NodeConfiguration{}, fmt.Errorf("validate node configuration state: %w", err)
	}
	if state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Lifecycle != model.LifecycleActive || state.Nodes[0].Gateway == nil {
		return NodeConfiguration{}, fmt.Errorf("node configuration requires one joined active local node")
	}
	if state.DNS == nil || state.DNS.Scope != model.DNSUpstreamDirect {
		return NodeConfiguration{}, fmt.Errorf("joined node configuration requires direct underlay DNS state")
	}
	node := state.Nodes[0]
	trust := node.Gateway

	standardTransport, err := joinedNodeTransport(state, node, model.TransportStandard)
	if err != nil {
		return NodeConfiguration{}, err
	}
	standardPrivateKey, err := compiler.secrets.Get(standardTransport.CredentialRef)
	if err != nil {
		return NodeConfiguration{}, fmt.Errorf("read node standard credential: %w", err)
	}
	defer clear(standardPrivateKey)
	standardCandidate, err := transport.RenderNodeStandardConfig(ctx, transport.NodeStandardRenderRequest{
		Transport: standardTransport, Node: node, NodeCIDR: trust.NodeCIDR,
		GatewayPublicIPv4: trust.PublicIPv4, GatewayPublicKey: trust.StandardPublicKey,
		PrivateKey: strings.TrimSpace(string(standardPrivateKey)), KeyRunner: compiler.runtime.WireGuardRunner,
	})
	if err != nil {
		return NodeConfiguration{}, fmt.Errorf("render node standard configuration: %w", err)
	}

	matcher, policyGeneration, err := routing.CompileCurrentNodePolicyMatcher(state)
	if err != nil {
		return NodeConfiguration{}, err
	}
	active, err := routing.ResolveNodeRoutingActiveOutbound(state, compiler.secrets)
	if err != nil {
		return NodeConfiguration{}, err
	}
	defer clear(active.RestrictedIdentitySecret)
	mihomoComponent, err := nodeConfigurationComponent(state.Components, routing.NodeRoutingProviderName)
	if err != nil {
		return NodeConfiguration{}, err
	}
	directRoute, err := deriveNodeDirectRoute(snapshot)
	if err != nil {
		return NodeConfiguration{}, err
	}
	routingBundle, err := routing.RenderNodeRoutingBundle(routing.NodeRoutingRenderRequest{
		Matcher: matcher, PolicyGeneration: policyGeneration, DNSMode: routing.NodeRoutingDNSPolicy,
		DirectDNSServers: append([]string(nil), state.DNS.IPv4...), GatewayDNSIPv4: trust.GatewayOverlayIPv4,
		ActiveOutbound: active, Component: mihomoComponent,
	}, routing.NodeRoutingGuardConfig{
		DirectRoute: directRoute,
		RecoveryPorts: []routing.NodeRoutingRecoveryPort{
			{Protocol: routing.NodeRoutingTCP, Port: 443},
			{Protocol: routing.NodeRoutingTCP, Port: 8443},
			{Protocol: routing.NodeRoutingUDP, Port: transport.StandardUDPPort},
		},
		IngressEndpoints: []routing.NodeRoutingIngressEndpoint{},
	})
	if err != nil {
		return NodeConfiguration{}, fmt.Errorf("render node routing configuration: %w", err)
	}

	frpComponent, err := nodeConfigurationComponent(state.Components, tunnel.FRPProviderName)
	if err != nil {
		return NodeConfiguration{}, err
	}
	credentialSource, err := tunnel.NewStoreCredentialSource(compiler.secrets)
	if err != nil {
		return NodeConfiguration{}, err
	}
	frpProvider, err := tunnel.NewFRPProvider(compiler.root, frpComponent, credentialSource)
	if err != nil {
		return NodeConfiguration{}, err
	}
	tunnelPlan, err := tunnel.PlanFromState(state)
	if err != nil {
		return NodeConfiguration{}, err
	}
	tunnelValue, err := frpProvider.Render(ctx, tunnel.RenderRequest{Plan: tunnelPlan})
	if err != nil {
		return NodeConfiguration{}, fmt.Errorf("render node tunnel configuration: %w", err)
	}
	tunnelCandidate, ok := tunnelValue.(tunnel.FRPCandidate)
	if !ok {
		return NodeConfiguration{}, fmt.Errorf("frp provider returned an incompatible node candidate")
	}

	tunnelCertificate, err := compiler.secrets.Get(trust.TunnelCertificateRef)
	if err != nil {
		return NodeConfiguration{}, fmt.Errorf("read trusted gateway tunnel certificate: %w", err)
	}
	defer clear(tunnelCertificate)
	tunnelFingerprint, err := tunnel.ValidateGatewayTLSCertificatePEM(tunnelCertificate, compiler.runtime.Now().UTC())
	if err != nil {
		return NodeConfiguration{}, fmt.Errorf("validate trusted gateway tunnel certificate: %w", err)
	}
	if tunnelFingerprint != trust.TunnelCertificateFingerprint {
		return NodeConfiguration{}, fmt.Errorf("trusted gateway tunnel certificate fingerprint differs from authoritative state")
	}

	routingDescriptor := routingBundle.Routing().Descriptor()
	tunnelDescriptor := tunnelCandidate.Descriptor()
	configs := []linuxplatform.RoleConfigFile{
		{Name: transport.StandardConfigFileName, Content: standardCandidate.Bytes()},
		{Name: routing.NodeRoutingConfigFileName, Content: routingBundle.Routing().Bytes()},
		{Name: routing.NodeRoutingGuardConfigFileName, Content: routingBundle.Guard().Bytes()},
		{Name: routing.NodeDNSIntegrationConfigName, Content: routingBundle.DNS().Bytes()},
		{Name: tunnel.FRPClientConfigFileName, Content: tunnelCandidate.Bytes()},
		{Name: tunnel.FRPServerCertificateName, Content: append([]byte(nil), tunnelCertificate...)},
		{Name: nodeStandardReadyFileName, Content: []byte(fmt.Sprintf(
			"schema_version=1\nstate_generation=%d\ncredential_generation=%d\nconfig_sha256=%s\n",
			state.Generation, node.CredentialGeneration, standardCandidate.Descriptor().ConfigHash,
		))},
		{Name: nodeRoutingReadyFileName, Content: []byte(fmt.Sprintf(
			"schema_version=1\nstate_generation=%d\npolicy_generation=%d\ncredential_generation=%d\nconfig_sha256=%s\n",
			state.Generation, policyGeneration, node.CredentialGeneration, routingDescriptor.ConfigHash,
		))},
		{Name: nodeRoutingGuardReadyFileName, Content: []byte(fmt.Sprintf(
			"schema_version=1\nstate_generation=%d\npolicy_generation=%d\nconfig_sha256=%s\n",
			state.Generation, policyGeneration, contentSHA256(routingBundle.Guard().Bytes()),
		))},
		{Name: tunnel.FRPClientReadyFileName, Content: []byte(fmt.Sprintf(
			"schema_version=1\nstate_generation=%d\ncredential_generation=%d\ntunnel_certificate_fingerprint=%s\nconfig_sha256=%s\n",
			state.Generation, node.CredentialGeneration, tunnelFingerprint, tunnelDescriptor.ConfigHash,
		))},
	}
	sort.Slice(configs, func(left, right int) bool { return configs[left].Name < configs[right].Name })
	return NodeConfiguration{
		stateGeneration: state.Generation, configs: configs,
		standard: standardCandidate, routing: routingBundle.Routing(), tunnel: tunnelCandidate,
	}, nil
}

func joinedNodeTransport(state model.State, node model.Node, kind model.TransportKind) (model.Transport, error) {
	var result model.Transport
	found := false
	for _, candidate := range state.Transports {
		if candidate.OwnerKind != model.TargetNode || candidate.OwnerID != node.ID || candidate.Kind != kind {
			continue
		}
		if found {
			return model.Transport{}, fmt.Errorf("joined node %s transport is duplicated", kind)
		}
		result, found = candidate, true
	}
	if !found || result.State == model.TransportDisabled || result.CredentialGeneration != node.CredentialGeneration {
		return model.Transport{}, fmt.Errorf("joined node %s transport does not match authoritative identity generation", kind)
	}
	return result, nil
}

func nodeConfigurationComponent(manifest model.ComponentManifest, name string) (model.ComponentPin, error) {
	var result model.ComponentPin
	found := false
	for _, component := range manifest.Components {
		if component.Name != name {
			continue
		}
		if found {
			return model.ComponentPin{}, fmt.Errorf("node component %s is duplicated", name)
		}
		result, found = component, true
	}
	if !found {
		return model.ComponentPin{}, fmt.Errorf("joined node component manifest lacks %s", name)
	}
	return result, nil
}

// deriveNodeDirectRoute selects the route Linux actually prefers. Equal-cost
// defaults with different next hops are rejected rather than guessed.
func deriveNodeDirectRoute(snapshot linuxplatform.HostSnapshot) (routing.NodeRoutingDirectRoute, error) {
	type routeKey struct{ device, gateway string }
	minimumMetric := 0
	haveMetric := false
	candidates := make(map[routeKey]struct{})
	for _, route := range snapshot.Routes {
		if route.Family != "ipv4" || route.Destination != "default" || (route.Table != "main" && route.Table != "254") || route.Device == "" ||
			route.Type == "unreachable" || route.Type == "blackhole" || route.Type == "prohibit" {
			continue
		}
		if !haveMetric || route.Metric < minimumMetric {
			minimumMetric, haveMetric = route.Metric, true
			candidates = map[routeKey]struct{}{{device: route.Device, gateway: route.Gateway}: {}}
			continue
		}
		if route.Metric == minimumMetric {
			candidates[routeKey{device: route.Device, gateway: route.Gateway}] = struct{}{}
		}
	}
	if len(candidates) == 0 {
		return routing.NodeRoutingDirectRoute{}, fmt.Errorf("no usable IPv4 main-table default route was found for node recovery traffic")
	}
	if len(candidates) != 1 {
		return routing.NodeRoutingDirectRoute{}, fmt.Errorf("multiple equal-priority IPv4 default routes were found for node recovery traffic")
	}
	for candidate := range candidates {
		if candidate.gateway != "" {
			gateway, err := netip.ParseAddr(candidate.gateway)
			if err != nil || !gateway.Is4() || !gateway.IsGlobalUnicast() || gateway.IsLoopback() || gateway.String() != candidate.gateway {
				return routing.NodeRoutingDirectRoute{}, fmt.Errorf("node recovery default route has an invalid IPv4 next hop")
			}
		}
		return routing.NodeRoutingDirectRoute{Interface: candidate.device, GatewayIPv4: candidate.gateway}, nil
	}
	panic("unreachable")
}

func contentSHA256(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
