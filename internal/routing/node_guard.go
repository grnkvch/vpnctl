package routing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const (
	NodeRoutingGuardSchemaVersion  = 1
	NodeRoutingGuardConfigFileName = "routing-guard.json"
	NodeRoutingGuardOwnerComment   = "vpnctl:v2:node-routing-guard"

	maximumNodeRoutingGuardConfigBytes = 1 << 20
	maximumNodeRecoveryPorts           = 16
	maximumNodeIngressEndpoints        = 64
)

var nodeRoutingInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

type NodeRoutingNetworkProtocol string

const (
	NodeRoutingTCP NodeRoutingNetworkProtocol = "tcp"
	NodeRoutingUDP NodeRoutingNetworkProtocol = "udp"
)

// NodeRoutingDirectRoute is the ordinary underlay route used only by packets
// carrying vpnctl's recovery/active-outbound or ingress-response mark.
type NodeRoutingDirectRoute struct {
	Interface   string `json:"interface"`
	GatewayIPv4 string `json:"gateway_ipv4,omitempty"`
}

type NodeRoutingRecoveryPort struct {
	Protocol NodeRoutingNetworkProtocol `json:"protocol"`
	Port     uint16                     `json:"port"`
}

// NodeRoutingIngressEndpoint identifies a gateway-originated flow whose
// replies must retain the gateway route. It is deliberately exact rather than
// a user-configurable subnet or process scope.
type NodeRoutingIngressEndpoint struct {
	Interface string                     `json:"interface"`
	Protocol  NodeRoutingNetworkProtocol `json:"protocol"`
	Port      uint16                     `json:"port"`
}

// NodeRoutingGuardConfig is the root-only, provider-neutral input consumed by
// the independent systemd guard. It contains no command fragments or raw nft
// syntax.
type NodeRoutingGuardConfig struct {
	SchemaVersion      int                          `json:"schema_version"`
	Matcher            MatcherIR                    `json:"matcher"`
	GatewayIPv4        string                       `json:"gateway_ipv4"`
	GatewayOverlayIPv4 string                       `json:"gateway_overlay_ipv4,omitempty"`
	ActiveTransport    model.TransportKind          `json:"active_transport,omitempty"`
	DirectRoute        NodeRoutingDirectRoute       `json:"direct_route"`
	RecoveryPorts      []NodeRoutingRecoveryPort    `json:"recovery_ports"`
	IngressEndpoints   []NodeRoutingIngressEndpoint `json:"ingress_endpoints"`
}

type NodeRoutingGuardCandidate struct {
	config   NodeRoutingGuardConfig
	content  []byte
	nftables []byte
}

func (candidate NodeRoutingGuardCandidate) Config() NodeRoutingGuardConfig {
	result := candidate.config
	result.Matcher = cloneNodeRoutingMatcherIR(candidate.config.Matcher)
	result.RecoveryPorts = cloneNodeRoutingRecoveryPorts(candidate.config.RecoveryPorts)
	result.IngressEndpoints = cloneNodeRoutingIngressEndpoints(candidate.config.IngressEndpoints)
	return result
}

func (candidate NodeRoutingGuardCandidate) Bytes() []byte {
	return append([]byte(nil), candidate.content...)
}

func (candidate NodeRoutingGuardCandidate) NFTablesDefinition() []byte {
	return append([]byte(nil), candidate.nftables...)
}

// RenderNodeRoutingGuardConfig normalizes exact recovery/ingress endpoints and
// compiles matcher IR into the owned nftables table. The returned JSON is the
// only persisted input required to reproduce the table after reboot.
func RenderNodeRoutingGuardConfig(config NodeRoutingGuardConfig) (NodeRoutingGuardCandidate, error) {
	config.SchemaVersion = NodeRoutingGuardSchemaVersion
	config.Matcher = cloneNodeRoutingMatcherIR(config.Matcher)
	config.RecoveryPorts = cloneNodeRoutingRecoveryPorts(config.RecoveryPorts)
	config.IngressEndpoints = cloneNodeRoutingIngressEndpoints(config.IngressEndpoints)
	if config.RecoveryPorts == nil {
		config.RecoveryPorts = []NodeRoutingRecoveryPort{}
	}
	if config.IngressEndpoints == nil {
		config.IngressEndpoints = []NodeRoutingIngressEndpoint{}
	}
	sort.Slice(config.RecoveryPorts, func(left, right int) bool {
		if config.RecoveryPorts[left].Protocol != config.RecoveryPorts[right].Protocol {
			return config.RecoveryPorts[left].Protocol < config.RecoveryPorts[right].Protocol
		}
		return config.RecoveryPorts[left].Port < config.RecoveryPorts[right].Port
	})
	sort.Slice(config.IngressEndpoints, func(left, right int) bool {
		leftEndpoint := config.IngressEndpoints[left]
		rightEndpoint := config.IngressEndpoints[right]
		if leftEndpoint.Interface != rightEndpoint.Interface {
			return leftEndpoint.Interface < rightEndpoint.Interface
		}
		if leftEndpoint.Protocol != rightEndpoint.Protocol {
			return leftEndpoint.Protocol < rightEndpoint.Protocol
		}
		return leftEndpoint.Port < rightEndpoint.Port
	})
	if err := config.Validate(); err != nil {
		return NodeRoutingGuardCandidate{}, err
	}
	matchers, err := CompileNFTablesLeakGuardMatchers(config.Matcher)
	if err != nil {
		return NodeRoutingGuardCandidate{}, err
	}
	nftables := renderNodeRoutingGuardNFTables(config, matchers)
	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return NodeRoutingGuardCandidate{}, fmt.Errorf("encode node routing guard config: %w", err)
	}
	content = append(content, '\n')
	if len(content) == 0 || len(content) > maximumNodeRoutingGuardConfigBytes {
		return NodeRoutingGuardCandidate{}, fmt.Errorf("node routing guard config has invalid size")
	}
	return NodeRoutingGuardCandidate{config: config, content: content, nftables: nftables}, nil
}

func (config NodeRoutingGuardConfig) Validate() error {
	issues := make([]string, 0)
	if config.SchemaVersion != NodeRoutingGuardSchemaVersion {
		issues = append(issues, fmt.Sprintf("schema_version must be %d", NodeRoutingGuardSchemaVersion))
	}
	if err := config.Matcher.Validate(); err != nil {
		issues = append(issues, "matcher: "+err.Error())
	}
	gateway, err := netip.ParseAddr(config.GatewayIPv4)
	if err != nil || !gateway.Is4() || !gateway.IsGlobalUnicast() || gateway.IsLoopback() || gateway.String() != config.GatewayIPv4 {
		issues = append(issues, "gateway_ipv4 must be a canonical non-loopback unicast IPv4 address")
	}
	if config.ActiveTransport == "" {
		if config.GatewayOverlayIPv4 != "" {
			issues = append(issues, "unbound guard cannot contain gateway_overlay_ipv4")
		}
	} else {
		if config.ActiveTransport != model.TransportStandard && config.ActiveTransport != model.TransportRestricted {
			issues = append(issues, "active_transport must be standard or restricted")
		}
		overlay, parseErr := netip.ParseAddr(config.GatewayOverlayIPv4)
		if parseErr != nil || !overlay.Is4() || !overlay.IsGlobalUnicast() || overlay.IsLoopback() || overlay.String() != config.GatewayOverlayIPv4 || overlay == gateway {
			issues = append(issues, "gateway_overlay_ipv4 must be a distinct canonical non-loopback unicast IPv4 address")
		}
	}
	if !nodeRoutingInterfacePattern.MatchString(config.DirectRoute.Interface) {
		issues = append(issues, "direct_route.interface must be a valid Linux interface name")
	}
	if config.ActiveTransport == model.TransportStandard && config.DirectRoute.Interface == NodeRoutingStandardInterface {
		issues = append(issues, "standard direct_route.interface must be the underlay, not vpnctl-wg")
	}
	if config.DirectRoute.GatewayIPv4 != "" {
		nextHop, parseErr := netip.ParseAddr(config.DirectRoute.GatewayIPv4)
		if parseErr != nil || !nextHop.Is4() || !nextHop.IsGlobalUnicast() || nextHop.IsLoopback() || nextHop.String() != config.DirectRoute.GatewayIPv4 {
			issues = append(issues, "direct_route.gateway_ipv4 must be empty or a canonical non-loopback unicast IPv4 address")
		}
	}
	if config.RecoveryPorts == nil || len(config.RecoveryPorts) == 0 || len(config.RecoveryPorts) > maximumNodeRecoveryPorts {
		issues = append(issues, fmt.Sprintf("recovery_ports must contain between 1 and %d exact ports", maximumNodeRecoveryPorts))
	}
	for index, endpoint := range config.RecoveryPorts {
		if err := validateNodeRoutingProtocolPort(endpoint.Protocol, endpoint.Port); err != nil {
			issues = append(issues, fmt.Sprintf("recovery_ports[%d]: %v", index, err))
		}
		if index > 0 && endpoint == config.RecoveryPorts[index-1] {
			issues = append(issues, "recovery_ports must be sorted and unique")
		}
		if index > 0 && nodeRoutingRecoveryPortLess(endpoint, config.RecoveryPorts[index-1]) {
			issues = append(issues, "recovery_ports must be sorted and unique")
		}
	}
	if config.IngressEndpoints == nil || len(config.IngressEndpoints) > maximumNodeIngressEndpoints {
		issues = append(issues, fmt.Sprintf("ingress_endpoints must be a present array of at most %d entries", maximumNodeIngressEndpoints))
	}
	for index, endpoint := range config.IngressEndpoints {
		if !nodeRoutingInterfacePattern.MatchString(endpoint.Interface) {
			issues = append(issues, fmt.Sprintf("ingress_endpoints[%d].interface is invalid", index))
		}
		if err := validateNodeRoutingProtocolPort(endpoint.Protocol, endpoint.Port); err != nil {
			issues = append(issues, fmt.Sprintf("ingress_endpoints[%d]: %v", index, err))
		}
		if index > 0 {
			previous := config.IngressEndpoints[index-1]
			if endpoint == previous || nodeRoutingIngressEndpointLess(endpoint, previous) {
				issues = append(issues, "ingress_endpoints must be sorted and unique")
			}
		}
	}
	if len(issues) != 0 {
		sort.Strings(issues)
		return fmt.Errorf("invalid node routing guard config: %s", strings.Join(issues, "; "))
	}
	return nil
}

func nodeRoutingRecoveryPortLess(left, right NodeRoutingRecoveryPort) bool {
	return left.Protocol < right.Protocol || left.Protocol == right.Protocol && left.Port < right.Port
}

func nodeRoutingIngressEndpointLess(left, right NodeRoutingIngressEndpoint) bool {
	return left.Interface < right.Interface || left.Interface == right.Interface &&
		(left.Protocol < right.Protocol || left.Protocol == right.Protocol && left.Port < right.Port)
}

func validateNodeRoutingProtocolPort(protocol NodeRoutingNetworkProtocol, port uint16) error {
	if protocol != NodeRoutingTCP && protocol != NodeRoutingUDP {
		return fmt.Errorf("protocol must be tcp or udp")
	}
	if port == 0 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func decodeNodeRoutingGuardConfig(content []byte) (NodeRoutingGuardConfig, error) {
	if len(content) == 0 || len(content) > maximumNodeRoutingGuardConfigBytes {
		return NodeRoutingGuardConfig{}, fmt.Errorf("node routing guard config has invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var config NodeRoutingGuardConfig
	if err := decoder.Decode(&config); err != nil {
		return NodeRoutingGuardConfig{}, fmt.Errorf("decode node routing guard config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return NodeRoutingGuardConfig{}, fmt.Errorf("decode node routing guard config: trailing data")
	}
	if err := config.Validate(); err != nil {
		return NodeRoutingGuardConfig{}, err
	}
	return config, nil
}

func renderNodeRoutingGuardNFTables(config NodeRoutingGuardConfig, matchers NFTablesLeakGuardMatchers) []byte {
	mask := nftMark(linuxplatform.VPNCTLMarkMask)
	preserved := nftMark(linuxplatform.VPNCTLPreservedMarkMask)
	direct := nftMark(linuxplatform.VPNCTLDirectMark)
	selected := nftMark(linuxplatform.VPNCTLSelectedMark)
	recovery := nftMark(linuxplatform.VPNCTLRecoveryMark)
	ingress := nftMark(linuxplatform.VPNCTLIngressResponseMark)
	var rules strings.Builder
	fmt.Fprintf(&rules, "table %s %s {\n", linuxplatform.VPNCTLNFTablesFamily, linuxplatform.VPNCTLNFTablesTable)
	fmt.Fprintf(&rules, "  comment %s\n\n", strconv.Quote(NodeRoutingGuardOwnerComment))
	rules.WriteString("  set selected_resolved_v4 {\n    type ipv4_addr\n    flags interval\n  }\n\n")
	rules.WriteString("  set selected_resolved_v6 {\n    type ipv6_addr\n    flags interval\n  }\n\n")
	rules.WriteString("  chain prerouting_mangle {\n")
	fmt.Fprintf(&rules, "    type filter hook prerouting priority %d; policy accept;\n\n", linuxplatform.VPNCTLNFTablesManglePriority)
	writeNodeRoutingConntrackRestore(&rules, mask)
	for _, endpoint := range config.IngressEndpoints {
		fmt.Fprintf(&rules, "    iifname %s ct state new %s dport %d meta mark set (meta mark & %s) | %s ct mark set meta mark return\n",
			strconv.Quote(endpoint.Interface), endpoint.Protocol, endpoint.Port, preserved, ingress)
	}
	rules.WriteString("  }\n\n")
	rules.WriteString("  chain output_mangle {\n")
	fmt.Fprintf(&rules, "    type route hook output priority %d; policy accept;\n\n", linuxplatform.VPNCTLNFTablesManglePriority)
	rules.WriteString("    oifname \"lo\" return\n")
	fmt.Fprintf(&rules, "    meta mark & %s == %s ct mark set meta mark return\n\n", mask, recovery)
	writeNodeRoutingConntrackRestore(&rules, mask)
	fmt.Fprintf(&rules, "    meta mark & %s == %s return\n", mask, ingress)
	fmt.Fprintf(&rules, "    meta mark & %s == %s return\n", mask, recovery)
	for _, endpoint := range config.RecoveryPorts {
		fmt.Fprintf(&rules, "    ip daddr %s %s dport %d meta mark set (meta mark & %s) | %s ct mark set meta mark return\n",
			config.GatewayIPv4, endpoint.Protocol, endpoint.Port, preserved, recovery)
	}
	rules.WriteString("    jump readiness\n")
	rules.WriteString("  }\n\n")
	rules.WriteString("  chain readiness {\n    jump not_ready\n  }\n\n")
	rules.WriteString("  chain not_ready {\n")
	fmt.Fprintf(&rules, "    ct state established,related meta mark & %s == %s return\n", mask, direct)
	rules.WriteString("    drop\n  }\n\n")
	rules.WriteString("  chain ready {\n")
	fmt.Fprintf(&rules, "    ct state established,related meta mark & %s == %s return\n", mask, selected)
	fmt.Fprintf(&rules, "    ct state established,related meta mark & %s == %s return\n\n", mask, direct)
	if config.ActiveTransport != "" {
		fmt.Fprintf(&rules, "    ip daddr %s meta mark set (meta mark & %s) | %s ct mark set meta mark return\n", config.GatewayOverlayIPv4, preserved, selected)
	}
	fmt.Fprintf(&rules, "    ip6 daddr @selected_resolved_v6 meta mark set (meta mark & %s) | %s ct mark set meta mark drop\n", preserved, selected)
	for _, decision := range matchers.program.ipv6 {
		writeNodeRoutingIPv6Decision(&rules, decision, preserved, direct, selected)
	}
	fmt.Fprintf(&rules, "    ip daddr @selected_resolved_v4 meta mark set (meta mark & %s) | %s ct mark set meta mark return\n", preserved, selected)
	for _, decision := range matchers.program.ipv4 {
		writeNodeRoutingIPv4Decision(&rules, decision, preserved, direct, selected)
	}
	fmt.Fprintf(&rules, "    meta mark set (meta mark & %s) | %s\n", preserved, direct)
	rules.WriteString("    ct mark set meta mark\n")
	rules.WriteString("    return\n  }\n")
	rules.WriteString("}\n")
	return []byte(rules.String())
}

func writeNodeRoutingConntrackRestore(rules *strings.Builder, mask string) {
	for _, mark := range []uint64{
		linuxplatform.VPNCTLDirectMark,
		linuxplatform.VPNCTLSelectedMark,
		linuxplatform.VPNCTLRecoveryMark,
		linuxplatform.VPNCTLIngressResponseMark,
	} {
		fmt.Fprintf(rules, "    ct mark & %s == %s meta mark set ct mark\n", mask, nftMark(mark))
	}
	rules.WriteByte('\n')
}

func writeNodeRoutingIPv4Decision(rules *strings.Builder, decision MatcherDecisionRule, preserved, direct, selected string) {
	mark := direct
	if decision.Selected {
		mark = selected
	}
	fmt.Fprintf(rules, "    ip daddr %s meta mark set (meta mark & %s) | %s ct mark set meta mark return\n",
		decision.Value, preserved, mark)
}

func writeNodeRoutingIPv6Decision(rules *strings.Builder, decision MatcherDecisionRule, preserved, direct, selected string) {
	mark := direct
	verdict := "return"
	if decision.Selected {
		mark = selected
		verdict = "drop"
	}
	fmt.Fprintf(rules, "    ip6 daddr %s meta mark set (meta mark & %s) | %s ct mark set meta mark %s\n",
		decision.Value, preserved, mark, verdict)
}

func nftMark(mark uint64) string { return fmt.Sprintf("0x%08x", mark) }

func cloneNodeRoutingMatcherIR(ir MatcherIR) MatcherIR {
	result := MatcherIR{SchemaVersion: ir.SchemaVersion}
	if ir.Clauses == nil {
		return result
	}
	result.Clauses = make([]MatcherClause, len(ir.Clauses))
	for index, clause := range ir.Clauses {
		result.Clauses[index] = MatcherClause{
			Name: clause.Name,
			Includes: MatcherTerms{
				Domains: cloneStringSlice(clause.Includes.Domains), DomainSuffixes: cloneStringSlice(clause.Includes.DomainSuffixes),
				IPv4CIDRs: cloneStringSlice(clause.Includes.IPv4CIDRs), IPv6CIDRs: cloneStringSlice(clause.Includes.IPv6CIDRs),
			},
			Excludes: MatcherTerms{
				Domains: cloneStringSlice(clause.Excludes.Domains), DomainSuffixes: cloneStringSlice(clause.Excludes.DomainSuffixes),
				IPv4CIDRs: cloneStringSlice(clause.Excludes.IPv4CIDRs), IPv6CIDRs: cloneStringSlice(clause.Excludes.IPv6CIDRs),
			},
		}
	}
	return result
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func cloneNodeRoutingRecoveryPorts(values []NodeRoutingRecoveryPort) []NodeRoutingRecoveryPort {
	if values == nil {
		return nil
	}
	result := make([]NodeRoutingRecoveryPort, len(values))
	copy(result, values)
	return result
}

func cloneNodeRoutingIngressEndpoints(values []NodeRoutingIngressEndpoint) []NodeRoutingIngressEndpoint {
	if values == nil {
		return nil
	}
	result := make([]NodeRoutingIngressEndpoint, len(values))
	copy(result, values)
	return result
}
