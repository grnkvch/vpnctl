package routing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"go.yaml.in/yaml/v3"
)

const (
	NodeRoutingDNSPolicy RoutingDNSMode = "policy"
	NodeRoutingDNSDirect RoutingDNSMode = "direct"

	NodeRoutingProviderName       = "mihomo"
	NodeRoutingProviderVersion    = "v1.19.30"
	NodeRoutingProviderSHA256     = "cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84"
	NodeRoutingBinaryRelativePath = "usr/local/libexec/vpnctl/mihomo"
	NodeRoutingStateRelativePath  = "routing"
	NodeRoutingConfigFileName     = "routing.yaml"
	NodeRoutingTUNDevice          = "vpnctl0"
	NodeRoutingDNSListener        = "127.0.0.1:1053"
	NodeRoutingGatewayGroup       = "VPNCTL-GATEWAY"
	NodeRoutingUnboundTarget      = "REJECT-DROP"
	NodeRoutingTUNMTU             = 1400

	maximumNodeRoutingConfigBytes = 1 << 20
	maximumNodeDirectDNSServers   = 8
)

type RoutingDNSMode string

type NodeRoutingRenderRequest struct {
	Matcher          MatcherIR
	PolicyGeneration uint64
	DNSMode          RoutingDNSMode
	DirectDNSServers []string
	GatewayDNSIPv4   string
	Component        model.ComponentPin
}

type NodeRoutingDescriptor struct {
	MatcherSchemaVersion int
	PolicyGeneration     uint64
	DNSMode              RoutingDNSMode
	ConfigHash           string
}

func (descriptor NodeRoutingDescriptor) Validate() error {
	if descriptor.MatcherSchemaVersion != MatcherIRSchemaVersion {
		return fmt.Errorf("node routing descriptor has unsupported matcher schema")
	}
	if descriptor.DNSMode != NodeRoutingDNSPolicy && descriptor.DNSMode != NodeRoutingDNSDirect {
		return fmt.Errorf("node routing descriptor has unsupported DNS mode")
	}
	if len(descriptor.ConfigHash) != sha256.Size*2 {
		return fmt.Errorf("node routing descriptor has invalid config hash")
	}
	decoded, err := hex.DecodeString(descriptor.ConfigHash)
	if err != nil || hex.EncodeToString(decoded) != descriptor.ConfigHash {
		return fmt.Errorf("node routing descriptor has invalid config hash")
	}
	return nil
}

type NodeRoutingCandidate struct {
	content    []byte
	descriptor NodeRoutingDescriptor
}

func (candidate NodeRoutingCandidate) Bytes() []byte {
	return append([]byte(nil), candidate.content...)
}

func (candidate NodeRoutingCandidate) Descriptor() NodeRoutingDescriptor {
	return candidate.descriptor
}

// RenderNodeRoutingConfig emits the task-10.2 routing-engine base. The only
// gateway group member is REJECT-DROP until task 10.4 binds the manually active
// transport; selected traffic therefore cannot become direct in an unbound
// intermediate generation.
func RenderNodeRoutingConfig(request NodeRoutingRenderRequest) (NodeRoutingCandidate, error) {
	if err := request.Matcher.Validate(); err != nil {
		return NodeRoutingCandidate{}, fmt.Errorf("validate node routing matcher: %w", err)
	}
	if (len(request.Matcher.Clauses) == 0) != (request.PolicyGeneration == 0) {
		return NodeRoutingCandidate{}, fmt.Errorf("node routing policy generation does not match matcher assignment")
	}
	if request.DNSMode == "" {
		request.DNSMode = NodeRoutingDNSPolicy
	}
	if request.DNSMode != NodeRoutingDNSPolicy && request.DNSMode != NodeRoutingDNSDirect {
		return NodeRoutingCandidate{}, fmt.Errorf("unsupported node routing DNS mode %q", request.DNSMode)
	}
	directDNS, err := normalizeNodeDirectDNS(request.DirectDNSServers)
	if err != nil {
		return NodeRoutingCandidate{}, err
	}
	gatewayDNS, err := normalizeNodeGatewayDNS(request.GatewayDNSIPv4)
	if err != nil {
		return NodeRoutingCandidate{}, err
	}
	if err := validateNodeRoutingComponent(request.Component); err != nil {
		return NodeRoutingCandidate{}, err
	}
	matchers, err := CompileNodeRoutingMatchers(request.Matcher)
	if err != nil {
		return NodeRoutingCandidate{}, err
	}
	content := renderNodeRoutingYAML(matchers, request.DNSMode, directDNS, gatewayDNS)
	if len(content) == 0 || len(content) > maximumNodeRoutingConfigBytes {
		return NodeRoutingCandidate{}, fmt.Errorf("node routing config has invalid size")
	}
	if err := ValidateNodeRoutingConfig(content, request.DNSMode); err != nil {
		return NodeRoutingCandidate{}, fmt.Errorf("validate rendered node routing config: %w", err)
	}
	digest := sha256.Sum256(content)
	return NodeRoutingCandidate{
		content: content,
		descriptor: NodeRoutingDescriptor{
			MatcherSchemaVersion: MatcherIRSchemaVersion,
			PolicyGeneration:     request.PolicyGeneration,
			DNSMode:              request.DNSMode,
			ConfigHash:           hex.EncodeToString(digest[:]),
		},
	}, nil
}

func normalizeNodeDirectDNS(values []string) ([]string, error) {
	if values == nil || len(values) == 0 || len(values) > maximumNodeDirectDNSServers {
		return nil, fmt.Errorf("node direct DNS must contain between 1 and %d IPv4 servers", maximumNodeDirectDNSServers)
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		address, err := parseNodeRoutingIPv4(value)
		if err != nil || address.IsLoopback() {
			return nil, fmt.Errorf("node direct DNS %q must be a canonical non-loopback unicast IPv4 address", value)
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, fmt.Errorf("node direct DNS duplicates %s", value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func normalizeNodeGatewayDNS(value string) (string, error) {
	address, err := parseNodeRoutingIPv4(value)
	if err != nil || address.IsLoopback() {
		return "", fmt.Errorf("gateway DNS must be a canonical non-loopback unicast IPv4 address")
	}
	return value, nil
}

func parseNodeRoutingIPv4(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.String() != value {
		return netip.Addr{}, fmt.Errorf("invalid canonical unicast IPv4 address")
	}
	return address, nil
}

func validateNodeRoutingComponent(component model.ComponentPin) error {
	if err := component.Validate(); err != nil {
		return fmt.Errorf("validate node routing component: %w", err)
	}
	if component.Name != NodeRoutingProviderName || component.Version != NodeRoutingProviderVersion ||
		component.SHA256 != NodeRoutingProviderSHA256 || !component.Bundled {
		return fmt.Errorf("node routing provider does not match the pinned Mihomo artifact")
	}
	required := map[string]bool{"tun-routing": false, "redir-host-split-dns": false}
	for _, capability := range component.Capabilities {
		if _, known := required[capability]; known {
			required[capability] = true
		}
	}
	for capability, present := range required {
		if !present {
			return fmt.Errorf("pinned Mihomo component lacks %s capability", capability)
		}
	}
	return nil
}

func renderNodeRoutingYAML(matchers NodeRoutingMatchers, mode RoutingDNSMode, directDNS []string, gatewayDNS string) []byte {
	var config strings.Builder
	config.WriteString("allow-lan: false\n")
	config.WriteString("bind-address: 127.0.0.1\n")
	config.WriteString("mode: rule\n")
	config.WriteString("log-level: silent\n")
	config.WriteString("ipv6: false\n")
	config.WriteString("geodata-loader: memconservative\n")
	config.WriteString("geo-auto-update: false\n\n")
	config.WriteString("tun:\n")
	config.WriteString("  enable: true\n")
	fmt.Fprintf(&config, "  device: %s\n", NodeRoutingTUNDevice)
	config.WriteString("  stack: system\n")
	config.WriteString("  auto-route: false\n")
	config.WriteString("  auto-detect-interface: false\n")
	config.WriteString("  dns-hijack: []\n")
	fmt.Fprintf(&config, "  mtu: %d\n\n", NodeRoutingTUNMTU)
	config.WriteString("dns:\n")
	config.WriteString("  enable: true\n")
	fmt.Fprintf(&config, "  listen: %s\n", NodeRoutingDNSListener)
	config.WriteString("  ipv6: false\n")
	config.WriteString("  cache-algorithm: arc\n")
	config.WriteString("  enhanced-mode: redir-host\n")
	config.WriteString("  use-hosts: false\n")
	config.WriteString("  use-system-hosts: false\n")
	config.WriteString("  respect-rules: false\n")
	config.WriteString("  default-nameserver:\n")
	for _, server := range directDNS {
		fmt.Fprintf(&config, "    - %s\n", server)
	}
	config.WriteString("  nameserver:\n")
	for _, server := range directDNS {
		fmt.Fprintf(&config, "    - %s\n", strconv.Quote(nodeDirectDNSURI(server)))
	}
	if mode == NodeRoutingDNSPolicy {
		if len(matchers.program.domain) == 0 {
			config.WriteString("  nameserver-policy: {}\n")
		} else {
			config.WriteString("  nameserver-policy:\n")
			for _, rule := range matchers.program.domain {
				pattern := rule.Value
				if rule.Kind == model.SelectorDomainSuffix {
					pattern = "+." + pattern
				}
				fmt.Fprintf(&config, "    %s:\n", strconv.Quote(pattern))
				if rule.Selected {
					fmt.Fprintf(&config, "      - %s\n", strconv.Quote(nodeGatewayDNSURI(gatewayDNS)))
					continue
				}
				for _, server := range directDNS {
					fmt.Fprintf(&config, "      - %s\n", strconv.Quote(nodeDirectDNSURI(server)))
				}
			}
		}
	}
	config.WriteString("\nproxy-groups:\n")
	fmt.Fprintf(&config, "  - name: %s\n", NodeRoutingGatewayGroup)
	config.WriteString("    type: select\n")
	config.WriteString("    proxies:\n")
	fmt.Fprintf(&config, "      - %s\n", NodeRoutingUnboundTarget)
	config.WriteString("\nrules:\n")
	for _, rule := range appendMatcherPrograms(matchers.program) {
		target := "DIRECT"
		if rule.Selected {
			target = NodeRoutingGatewayGroup
		}
		switch rule.Kind {
		case model.SelectorDomain:
			fmt.Fprintf(&config, "  - DOMAIN,%s,%s\n", rule.Value, target)
		case model.SelectorDomainSuffix:
			fmt.Fprintf(&config, "  - DOMAIN-SUFFIX,%s,%s\n", rule.Value, target)
		case model.SelectorIPCIDR:
			kind := "IP-CIDR"
			if netip.MustParsePrefix(rule.Value).Addr().Is6() {
				kind = "IP-CIDR6"
			}
			fmt.Fprintf(&config, "  - %s,%s,%s\n", kind, rule.Value, target)
		}
	}
	config.WriteString("  - MATCH,DIRECT\n")
	return []byte(config.String())
}

func appendMatcherPrograms(program matcherDecisionProgram) []MatcherDecisionRule {
	rules := make([]MatcherDecisionRule, 0, len(program.domain)+len(program.ipv4)+len(program.ipv6))
	rules = append(rules, program.domain...)
	rules = append(rules, program.ipv4...)
	rules = append(rules, program.ipv6...)
	return rules
}

func nodeDirectDNSURI(server string) string {
	return "udp://" + server + ":53#DIRECT"
}

func nodeGatewayDNSURI(server string) string {
	return "udp://" + server + ":53#" + NodeRoutingGatewayGroup
}

type nodeRoutingDocument struct {
	AllowLAN      *bool                   `yaml:"allow-lan"`
	BindAddress   string                  `yaml:"bind-address"`
	Mode          string                  `yaml:"mode"`
	LogLevel      string                  `yaml:"log-level"`
	IPv6          *bool                   `yaml:"ipv6"`
	GeodataLoader string                  `yaml:"geodata-loader"`
	GeoAutoUpdate *bool                   `yaml:"geo-auto-update"`
	TUN           nodeRoutingTUNDocument  `yaml:"tun"`
	DNS           nodeRoutingDNSDocument  `yaml:"dns"`
	ProxyGroups   []nodeRoutingProxyGroup `yaml:"proxy-groups"`
	Rules         []string                `yaml:"rules"`
}

type nodeRoutingTUNDocument struct {
	Enable              *bool    `yaml:"enable"`
	Device              string   `yaml:"device"`
	Stack               string   `yaml:"stack"`
	AutoRoute           *bool    `yaml:"auto-route"`
	AutoDetectInterface *bool    `yaml:"auto-detect-interface"`
	DNSHijack           []string `yaml:"dns-hijack"`
	MTU                 *int     `yaml:"mtu"`
}

type nodeRoutingDNSDocument struct {
	Enable            *bool               `yaml:"enable"`
	Listen            string              `yaml:"listen"`
	IPv6              *bool               `yaml:"ipv6"`
	CacheAlgorithm    string              `yaml:"cache-algorithm"`
	EnhancedMode      string              `yaml:"enhanced-mode"`
	UseHosts          *bool               `yaml:"use-hosts"`
	UseSystemHosts    *bool               `yaml:"use-system-hosts"`
	RespectRules      *bool               `yaml:"respect-rules"`
	DefaultNameserver []string            `yaml:"default-nameserver"`
	Nameserver        []string            `yaml:"nameserver"`
	NameserverPolicy  map[string][]string `yaml:"nameserver-policy"`
}

type nodeRoutingProxyGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
}

func ValidateNodeRoutingConfig(content []byte, mode RoutingDNSMode) error {
	if len(content) == 0 || len(content) > maximumNodeRoutingConfigBytes {
		return fmt.Errorf("node routing config has invalid size")
	}
	if mode != NodeRoutingDNSPolicy && mode != NodeRoutingDNSDirect {
		return fmt.Errorf("node routing config requires an explicit supported DNS mode")
	}
	var document nodeRoutingDocument
	if err := decodeNodeRoutingYAML(content, &document); err != nil {
		return err
	}
	if !routingFalse(document.AllowLAN) || document.BindAddress != "127.0.0.1" || document.Mode != "rule" ||
		document.LogLevel != "silent" || !routingFalse(document.IPv6) || document.GeodataLoader != "memconservative" ||
		!routingFalse(document.GeoAutoUpdate) {
		return fmt.Errorf("node routing config has unsupported global behavior")
	}
	tun := document.TUN
	if !routingTrue(tun.Enable) || tun.Device != NodeRoutingTUNDevice || tun.Stack != "system" || !routingFalse(tun.AutoRoute) ||
		!routingFalse(tun.AutoDetectInterface) || tun.DNSHijack == nil || len(tun.DNSHijack) != 0 || tun.MTU == nil || *tun.MTU != NodeRoutingTUNMTU {
		return fmt.Errorf("node routing TUN does not match the host-wide managed contract")
	}
	if len(document.ProxyGroups) != 1 || document.ProxyGroups[0].Name != NodeRoutingGatewayGroup ||
		document.ProxyGroups[0].Type != "select" || len(document.ProxyGroups[0].Proxies) != 1 ||
		document.ProxyGroups[0].Proxies[0] != NodeRoutingUnboundTarget {
		return fmt.Errorf("node routing gateway group is not fail-closed while unbound")
	}
	directDNS, err := validateNodeRoutingDNS(document.DNS, mode)
	if err != nil {
		return err
	}
	return validateNodeRoutingRules(document.Rules, document.DNS.NameserverPolicy, mode, directDNS)
}

func validateNodeRoutingDNS(document nodeRoutingDNSDocument, mode RoutingDNSMode) ([]string, error) {
	if !routingTrue(document.Enable) || document.Listen != NodeRoutingDNSListener || !routingFalse(document.IPv6) ||
		document.CacheAlgorithm != "arc" || document.EnhancedMode != "redir-host" || !routingFalse(document.UseHosts) ||
		!routingFalse(document.UseSystemHosts) || !routingFalse(document.RespectRules) {
		return nil, fmt.Errorf("node routing DNS does not match the pinned redir-host mode")
	}
	directDNS, err := normalizeNodeDirectDNS(document.DefaultNameserver)
	if err != nil {
		return nil, err
	}
	if len(document.Nameserver) != len(directDNS) {
		return nil, fmt.Errorf("node routing direct DNS paths differ")
	}
	for index, server := range directDNS {
		if document.Nameserver[index] != nodeDirectDNSURI(server) {
			return nil, fmt.Errorf("node routing direct DNS path can fall through another outbound")
		}
	}
	if mode == NodeRoutingDNSPolicy && document.NameserverPolicy == nil {
		return nil, fmt.Errorf("policy DNS mode requires a present nameserver-policy map")
	}
	if mode == NodeRoutingDNSDirect && document.NameserverPolicy != nil {
		return nil, fmt.Errorf("direct DNS mode cannot contain nameserver-policy")
	}
	return directDNS, nil
}

func validateNodeRoutingRules(rules []string, policies map[string][]string, mode RoutingDNSMode, directDNS []string) error {
	if len(rules) == 0 || rules[len(rules)-1] != "MATCH,DIRECT" {
		return fmt.Errorf("node routing rules must end in direct for unmatched traffic")
	}
	wantPolicies := make(map[string][]string)
	decisions := make([]MatcherDecisionRule, 0, len(rules)-1)
	for index, value := range rules[:len(rules)-1] {
		parts := strings.Split(value, ",")
		if len(parts) != 3 || parts[2] != "DIRECT" && parts[2] != NodeRoutingGatewayGroup {
			return fmt.Errorf("node routing rule %d has unsupported action", index)
		}
		kind, matcher := parts[0], parts[1]
		switch kind {
		case "DOMAIN", "DOMAIN-SUFFIX":
			selectorKind := model.SelectorDomain
			pattern := matcher
			if kind == "DOMAIN-SUFFIX" {
				selectorKind = model.SelectorDomainSuffix
				pattern = "+." + matcher
			}
			if err := (model.Selector{Kind: selectorKind, Value: matcher}).Validate(); err != nil {
				return fmt.Errorf("node routing rule %d: %w", index, err)
			}
			decisions = append(decisions, MatcherDecisionRule{Kind: selectorKind, Value: matcher, Selected: parts[2] == NodeRoutingGatewayGroup})
			if _, duplicate := wantPolicies[pattern]; duplicate {
				return fmt.Errorf("node routing domain rules must be unique")
			}
			if parts[2] == NodeRoutingGatewayGroup {
				wantPolicies[pattern] = nil
			} else {
				values := make([]string, len(directDNS))
				for index, server := range directDNS {
					values[index] = nodeDirectDNSURI(server)
				}
				wantPolicies[pattern] = values
			}
		case "IP-CIDR", "IP-CIDR6":
			prefix, err := netip.ParsePrefix(matcher)
			if err != nil || prefix.String() != matcher || prefix.Masked() != prefix || (kind == "IP-CIDR") != prefix.Addr().Is4() {
				return fmt.Errorf("node routing rule %d has invalid address family", index)
			}
			decisions = append(decisions, MatcherDecisionRule{Kind: model.SelectorIPCIDR, Value: matcher, Selected: parts[2] == NodeRoutingGatewayGroup})
		default:
			return fmt.Errorf("node routing rule %d has unsupported matcher", index)
		}
	}
	if !canonicalNodeRoutingDecisions(decisions) {
		return fmt.Errorf("node routing matcher decisions must be canonical, ordered, and unique")
	}
	if mode == NodeRoutingDNSDirect {
		return nil
	}
	if len(policies) != len(wantPolicies) {
		return fmt.Errorf("node routing nameserver-policy differs from domain rules")
	}
	var gatewayDNS string
	for pattern, target := range wantPolicies {
		actual, found := policies[pattern]
		if !found || len(actual) == 0 {
			return fmt.Errorf("node routing nameserver-policy lacks %s", pattern)
		}
		if target != nil {
			if !equalStrings(actual, target) {
				return fmt.Errorf("node routing direct DNS exception differs from direct path")
			}
			continue
		}
		if len(actual) != 1 {
			return fmt.Errorf("selected DNS must have exactly one gateway path")
		}
		server, err := parseNodeGatewayDNSURI(actual[0])
		if err != nil {
			return err
		}
		if gatewayDNS != "" && gatewayDNS != server {
			return fmt.Errorf("selected DNS rules disagree on gateway endpoint")
		}
		gatewayDNS = server
	}
	return nil
}

func canonicalNodeRoutingDecisions(rules []MatcherDecisionRule) bool {
	seen := make(map[string]struct{}, len(rules))
	previousPhase := -1
	var previous MatcherDecisionRule
	for index, rule := range rules {
		phase := matcherDecisionPhase(rule)
		if phase < 0 || phase < previousPhase {
			return false
		}
		key := string(rule.Kind) + "\x00" + rule.Value
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		if index > 0 && phase == previousPhase && !matcherDecisionLess(previous, rule, phase) {
			return false
		}
		previousPhase = phase
		previous = rule
	}
	return true
}

func matcherDecisionPhase(rule MatcherDecisionRule) int {
	switch rule.Kind {
	case model.SelectorDomain:
		return 0
	case model.SelectorDomainSuffix:
		return 1
	case model.SelectorIPCIDR:
		prefix, err := netip.ParsePrefix(rule.Value)
		if err != nil {
			return -1
		}
		if prefix.Addr().Is4() {
			return 2
		}
		return 3
	default:
		return -1
	}
}

func matcherDecisionLess(left, right MatcherDecisionRule, phase int) bool {
	switch phase {
	case 0:
		return left.Value < right.Value
	case 1:
		leftLabels, rightLabels := strings.Count(left.Value, "."), strings.Count(right.Value, ".")
		if leftLabels != rightLabels {
			return leftLabels > rightLabels
		}
		if len(left.Value) != len(right.Value) {
			return len(left.Value) > len(right.Value)
		}
		return left.Value < right.Value
	case 2, 3:
		leftPrefix, rightPrefix := netip.MustParsePrefix(left.Value), netip.MustParsePrefix(right.Value)
		if leftPrefix.Bits() != rightPrefix.Bits() {
			return leftPrefix.Bits() > rightPrefix.Bits()
		}
		return leftPrefix.Addr().Compare(rightPrefix.Addr()) < 0
	default:
		return false
	}
}

func parseNodeGatewayDNSURI(value string) (string, error) {
	prefix, suffix := "udp://", ":53#"+NodeRoutingGatewayGroup
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) {
		return "", fmt.Errorf("selected DNS path does not use the gateway-only outbound")
	}
	server := strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix)
	if _, err := normalizeNodeGatewayDNS(server); err != nil {
		return "", err
	}
	return server, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func routingTrue(value *bool) bool  { return value != nil && *value }
func routingFalse(value *bool) bool { return value != nil && !*value }

func decodeNodeRoutingYAML(content []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode node routing config: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("node routing config must contain exactly one document")
		}
		return fmt.Errorf("decode trailing node routing config: %w", err)
	}
	return nil
}
