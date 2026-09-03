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
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
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
	NodeRoutingDirectDNSProxy     = "VPNCTL-DIRECT-DNS"
	NodeRoutingStandardProxy      = "VPNCTL-STANDARD"
	NodeRoutingRestrictedProxy    = "VPNCTL-RESTRICTED"
	NodeRoutingStandardInterface  = "vpnctl-wg"
	NodeRoutingTUNMTU             = 1400

	maximumNodeRoutingConfigBytes = 1 << 20
	maximumNodeDirectDNSServers   = 8
)

type RoutingDNSMode string

// NodeRoutingActiveOutbound is the one production binding shared by selected
// application traffic, gateway DNS, control, and the reverse tunnel. Empty is
// a valid fail-closed staging state; a production binding is always exactly
// one standard or restricted transport generation.
type NodeRoutingActiveOutbound struct {
	Kind                     model.TransportKind
	CredentialGeneration     uint64
	GatewayPublicIPv4        string
	GatewayOverlayIPv4       string
	RestrictedServerPassword string
	RestrictedIdentitySecret []byte
	RestrictedHandshakeHost  string
}

type NodeRoutingRenderRequest struct {
	Matcher          MatcherIR
	PolicyGeneration uint64
	DNSMode          RoutingDNSMode
	DirectDNSServers []string
	GatewayDNSIPv4   string
	ActiveOutbound   NodeRoutingActiveOutbound
	Component        model.ComponentPin
}

type NodeRoutingDescriptor struct {
	MatcherSchemaVersion int
	PolicyGeneration     uint64
	DNSMode              RoutingDNSMode
	ActiveTransport      model.TransportKind
	CredentialGeneration uint64
	ConfigHash           string
}

func (descriptor NodeRoutingDescriptor) Validate() error {
	if descriptor.MatcherSchemaVersion != MatcherIRSchemaVersion {
		return fmt.Errorf("node routing descriptor has unsupported matcher schema")
	}
	if descriptor.DNSMode != NodeRoutingDNSPolicy && descriptor.DNSMode != NodeRoutingDNSDirect {
		return fmt.Errorf("node routing descriptor has unsupported DNS mode")
	}
	if descriptor.ActiveTransport == "" {
		if descriptor.CredentialGeneration != 0 {
			return fmt.Errorf("unbound node routing descriptor has a credential generation")
		}
	} else if (descriptor.ActiveTransport != model.TransportStandard && descriptor.ActiveTransport != model.TransportRestricted) || descriptor.CredentialGeneration == 0 {
		return fmt.Errorf("node routing descriptor has invalid active transport")
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

// RenderNodeRoutingConfig emits the host-wide routing-engine configuration.
// VPNCTL-DIRECT-DNS is a non-selectable provider outbound whose socket mark
// prevents resolver recursion. The only gateway group member is REJECT-DROP
// until a manually active transport is bound, so selected traffic cannot
// become direct in an unbound intermediate generation.
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
	active, err := normalizeNodeRoutingActiveOutbound(request.ActiveOutbound, request.GatewayDNSIPv4, request.Component)
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
	content := renderNodeRoutingYAML(matchers, request.DNSMode, directDNS, gatewayDNS, active)
	if len(content) == 0 || len(content) > maximumNodeRoutingConfigBytes {
		return NodeRoutingCandidate{}, fmt.Errorf("node routing config has invalid size")
	}
	if err := validateNodeRoutingConfig(content, request.DNSMode, active); err != nil {
		return NodeRoutingCandidate{}, fmt.Errorf("validate rendered node routing config: %w", err)
	}
	digest := sha256.Sum256(content)
	return NodeRoutingCandidate{
		content: content,
		descriptor: NodeRoutingDescriptor{
			MatcherSchemaVersion: MatcherIRSchemaVersion,
			PolicyGeneration:     request.PolicyGeneration,
			DNSMode:              request.DNSMode,
			ActiveTransport:      active.Kind,
			CredentialGeneration: active.CredentialGeneration,
			ConfigHash:           hex.EncodeToString(digest[:]),
		},
	}, nil
}

func normalizeNodeRoutingActiveOutbound(value NodeRoutingActiveOutbound, gatewayDNS string, component model.ComponentPin) (NodeRoutingActiveOutbound, error) {
	value.RestrictedIdentitySecret = append([]byte(nil), value.RestrictedIdentitySecret...)
	if value.Kind == "" {
		if value.CredentialGeneration != 0 || value.GatewayPublicIPv4 != "" || value.GatewayOverlayIPv4 != "" ||
			value.RestrictedServerPassword != "" || value.RestrictedIdentitySecret != nil || value.RestrictedHandshakeHost != "" {
			return NodeRoutingActiveOutbound{}, fmt.Errorf("unbound node routing outbound contains transport data")
		}
		return value, nil
	}
	if value.Kind != model.TransportStandard && value.Kind != model.TransportRestricted {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("unsupported node routing active transport %q", value.Kind)
	}
	if value.CredentialGeneration == 0 {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("node routing active transport generation must be positive")
	}
	public, err := parseNodeRoutingIPv4(value.GatewayPublicIPv4)
	if err != nil || public.IsPrivate() || public.IsLoopback() {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("node routing gateway public endpoint must be a canonical public IPv4 address")
	}
	overlay, err := parseNodeRoutingIPv4(value.GatewayOverlayIPv4)
	if err != nil || overlay.IsLoopback() || value.GatewayOverlayIPv4 != gatewayDNS {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("node routing gateway overlay must equal the gateway DNS IPv4 address")
	}
	if value.Kind == model.TransportStandard {
		if value.RestrictedServerPassword != "" || value.RestrictedIdentitySecret != nil || value.RestrictedHandshakeHost != "" {
			return NodeRoutingActiveOutbound{}, fmt.Errorf("standard node routing outbound contains restricted transport data")
		}
		return value, nil
	}
	if err := validateNodeRoutingRestrictedCapabilities(component); err != nil {
		return NodeRoutingActiveOutbound{}, err
	}
	if err := restricted.ValidateServerPassword(value.RestrictedServerPassword); err != nil {
		return NodeRoutingActiveOutbound{}, err
	}
	identity, err := restricted.DecodeIdentitySecret(value.RestrictedIdentitySecret)
	if err != nil {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("validate node routing restricted identity: %w", err)
	}
	if !validNodeRoutingHostname(value.RestrictedHandshakeHost) {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("node routing restricted handshake host is invalid")
	}
	encoded, err := restricted.EncodeSecret(identity)
	if err != nil {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("normalize node routing restricted identity: %w", err)
	}
	value.RestrictedIdentitySecret = encoded
	return value, nil
}

func validateNodeRoutingRestrictedCapabilities(component model.ComponentPin) error {
	required := map[string]bool{
		"shadowsocks-2022-blake3-aes-256-gcm": false,
		"shadowtls-v3-strict":                 false,
		"uot-v2":                              false,
	}
	for _, capability := range component.Capabilities {
		if _, known := required[capability]; known {
			required[capability] = true
		}
	}
	for capability, present := range required {
		if !present {
			return fmt.Errorf("pinned Mihomo component lacks %s capability for restricted node routing", capability)
		}
	}
	return nil
}

func validNodeRoutingHostname(value string) bool {
	if value == "" || value != strings.ToLower(value) || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
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

func renderNodeRoutingYAML(matchers NodeRoutingMatchers, mode RoutingDNSMode, directDNS []string, gatewayDNS string, active NodeRoutingActiveOutbound) []byte {
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
	config.WriteString("\nproxies:\n")
	renderNodeRoutingDirectDNSProxy(&config)
	if active.Kind != "" {
		renderNodeRoutingActiveProxy(&config, active)
	}
	config.WriteString("\nproxy-groups:\n")
	fmt.Fprintf(&config, "  - name: %s\n", NodeRoutingGatewayGroup)
	config.WriteString("    type: select\n")
	config.WriteString("    proxies:\n")
	target := NodeRoutingUnboundTarget
	if active.Kind == model.TransportStandard {
		target = NodeRoutingStandardProxy
	} else if active.Kind == model.TransportRestricted {
		target = NodeRoutingRestrictedProxy
	}
	fmt.Fprintf(&config, "      - %s\n", target)
	config.WriteString("\nrules:\n")
	if active.Kind != "" {
		fmt.Fprintf(&config, "  - IP-CIDR,%s/32,%s,no-resolve\n", active.GatewayOverlayIPv4, NodeRoutingGatewayGroup)
	}
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

func renderNodeRoutingDirectDNSProxy(config *strings.Builder) {
	fmt.Fprintf(config, "  - name: %s\n", NodeRoutingDirectDNSProxy)
	config.WriteString("    type: direct\n")
	config.WriteString("    udp: true\n")
	fmt.Fprintf(config, "    routing-mark: %d\n", linuxplatform.VPNCTLDirectMark)
}

func renderNodeRoutingActiveProxy(config *strings.Builder, active NodeRoutingActiveOutbound) {
	if active.Kind == model.TransportStandard {
		fmt.Fprintf(config, "  - name: %s\n", NodeRoutingStandardProxy)
		config.WriteString("    type: direct\n")
		config.WriteString("    udp: true\n")
		fmt.Fprintf(config, "    interface-name: %s\n", NodeRoutingStandardInterface)
		fmt.Fprintf(config, "    routing-mark: %d\n", linuxplatform.VPNCTLRecoveryMark)
		return
	}
	identity, _ := restricted.DecodeIdentitySecret(active.RestrictedIdentitySecret)
	fmt.Fprintf(config, "  - name: %s\n", NodeRoutingRestrictedProxy)
	config.WriteString("    type: ss\n")
	fmt.Fprintf(config, "    server: %s\n", active.GatewayPublicIPv4)
	fmt.Fprintf(config, "    port: %d\n", restricted.TCPPort)
	fmt.Fprintf(config, "    cipher: %s\n", restricted.Cipher)
	fmt.Fprintf(config, "    password: %s\n", strconv.Quote(active.RestrictedServerPassword))
	config.WriteString("    ip-version: ipv4\n")
	config.WriteString("    udp: true\n")
	config.WriteString("    udp-over-tcp: true\n")
	fmt.Fprintf(config, "    udp-over-tcp-version: %d\n", restricted.UDPOverTCPVersion)
	fmt.Fprintf(config, "    routing-mark: %d\n", linuxplatform.VPNCTLRecoveryMark)
	config.WriteString("    plugin: shadow-tls\n")
	config.WriteString("    client-fingerprint: chrome\n")
	config.WriteString("    plugin-opts:\n")
	fmt.Fprintf(config, "      host: %s\n", strconv.Quote(active.RestrictedHandshakeHost))
	fmt.Fprintf(config, "      password: %s\n", strconv.Quote(identity.ShadowTLSPassword))
	fmt.Fprintf(config, "      version: %d\n", restricted.ShadowTLSVersion)
	config.WriteString("      strict-mode: true\n")
}

func appendMatcherPrograms(program matcherDecisionProgram) []MatcherDecisionRule {
	rules := make([]MatcherDecisionRule, 0, len(program.domain)+len(program.ipv4)+len(program.ipv6))
	rules = append(rules, program.domain...)
	rules = append(rules, program.ipv4...)
	rules = append(rules, program.ipv6...)
	return rules
}

func nodeDirectDNSURI(server string) string {
	return "udp://" + server + ":53#" + NodeRoutingDirectDNSProxy
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
	Proxies       []nodeRoutingProxy      `yaml:"proxies"`
	ProxyGroups   []nodeRoutingProxyGroup `yaml:"proxy-groups"`
	Rules         []string                `yaml:"rules"`
}

type nodeRoutingProxy struct {
	Name              string                          `yaml:"name"`
	Type              string                          `yaml:"type"`
	Server            string                          `yaml:"server"`
	Port              *int                            `yaml:"port"`
	Cipher            string                          `yaml:"cipher"`
	Password          string                          `yaml:"password"`
	IPVersion         string                          `yaml:"ip-version"`
	UDP               *bool                           `yaml:"udp"`
	UDPOverTCP        *bool                           `yaml:"udp-over-tcp"`
	UDPOverTCPVersion *int                            `yaml:"udp-over-tcp-version"`
	InterfaceName     string                          `yaml:"interface-name"`
	RoutingMark       *uint64                         `yaml:"routing-mark"`
	Plugin            string                          `yaml:"plugin"`
	ClientFingerprint string                          `yaml:"client-fingerprint"`
	PluginOptions     nodeRoutingRestrictedPluginOpts `yaml:"plugin-opts"`
}

type nodeRoutingRestrictedPluginOpts struct {
	Host       string `yaml:"host"`
	Password   string `yaml:"password"`
	Version    *int   `yaml:"version"`
	StrictMode *bool  `yaml:"strict-mode"`
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
	var document nodeRoutingDocument
	if err := decodeNodeRoutingYAML(content, &document); err != nil {
		return err
	}
	active, err := inferNodeRoutingActiveOutbound(document)
	if err != nil {
		return err
	}
	return validateNodeRoutingConfig(content, mode, active)
}

// ValidateBoundNodeRoutingConfig additionally enforces the exact manually
// active transport generation and all of its provider-specific safety fields.
func ValidateBoundNodeRoutingConfig(content []byte, mode RoutingDNSMode, active NodeRoutingActiveOutbound, component model.ComponentPin, gatewayDNS string) error {
	normalized, err := normalizeNodeRoutingActiveOutbound(active, gatewayDNS, component)
	if err != nil {
		return err
	}
	return validateNodeRoutingConfig(content, mode, normalized)
}

func validateNodeRoutingConfig(content []byte, mode RoutingDNSMode, active NodeRoutingActiveOutbound) error {
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
	if err := validateNodeRoutingActiveProxy(document.Proxies, document.ProxyGroups, active); err != nil {
		return err
	}
	directDNS, err := validateNodeRoutingDNS(document.DNS, mode)
	if err != nil {
		return err
	}
	return validateNodeRoutingRules(document.Rules, document.DNS.NameserverPolicy, mode, directDNS, active)
}

func inferNodeRoutingActiveOutbound(document nodeRoutingDocument) (NodeRoutingActiveOutbound, error) {
	if len(document.Proxies) == 1 && document.Proxies[0].Name == NodeRoutingDirectDNSProxy {
		return NodeRoutingActiveOutbound{}, nil
	}
	if len(document.Proxies) != 2 || document.Proxies[0].Name != NodeRoutingDirectDNSProxy || len(document.Rules) == 0 {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("node routing config must contain direct DNS and at most one active outbound")
	}
	parts := strings.Split(document.Rules[0], ",")
	if len(parts) != 4 || parts[0] != "IP-CIDR" || parts[2] != NodeRoutingGatewayGroup || parts[3] != "no-resolve" || !strings.HasSuffix(parts[1], "/32") {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("node routing active outbound lacks its internal gateway rule")
	}
	overlay := strings.TrimSuffix(parts[1], "/32")
	proxy := document.Proxies[1]
	if proxy.Name == NodeRoutingStandardProxy && proxy.Type == "direct" {
		return NodeRoutingActiveOutbound{Kind: model.TransportStandard, GatewayOverlayIPv4: overlay}, nil
	}
	if proxy.Name != NodeRoutingRestrictedProxy || proxy.Type != "ss" {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("node routing config contains an unsupported active outbound")
	}
	identity, err := restricted.EncodeSecret(restricted.IdentitySecret{
		SchemaVersion: restricted.SecretSchemaVersion, ShadowTLSPassword: proxy.PluginOptions.Password,
	})
	if err != nil {
		return NodeRoutingActiveOutbound{}, fmt.Errorf("decode node routing restricted identity: %w", err)
	}
	return NodeRoutingActiveOutbound{
		Kind: model.TransportRestricted, GatewayPublicIPv4: proxy.Server, GatewayOverlayIPv4: overlay,
		RestrictedServerPassword: proxy.Password, RestrictedIdentitySecret: identity, RestrictedHandshakeHost: proxy.PluginOptions.Host,
	}, nil
}

func validateNodeRoutingActiveProxy(proxies []nodeRoutingProxy, groups []nodeRoutingProxyGroup, active NodeRoutingActiveOutbound) error {
	if len(groups) != 1 || groups[0].Name != NodeRoutingGatewayGroup || groups[0].Type != "select" || len(groups[0].Proxies) != 1 {
		return fmt.Errorf("node routing gateway group must contain exactly one explicit target")
	}
	if len(proxies) == 0 || !validNodeRoutingDirectDNSProxy(proxies[0]) {
		return fmt.Errorf("node routing direct DNS outbound does not enforce the bypass mark")
	}
	if active.Kind == "" {
		if len(proxies) != 1 || groups[0].Proxies[0] != NodeRoutingUnboundTarget {
			return fmt.Errorf("node routing gateway group is not fail-closed while unbound")
		}
		return nil
	}
	if len(proxies) != 2 || groups[0].Proxies[0] == "DIRECT" || groups[0].Proxies[0] == NodeRoutingUnboundTarget {
		return fmt.Errorf("bound node routing gateway group must select exactly one active provider")
	}
	proxy := proxies[1]
	if active.Kind == model.TransportStandard {
		if groups[0].Proxies[0] != NodeRoutingStandardProxy || proxy.Name != NodeRoutingStandardProxy || proxy.Type != "direct" ||
			!routingTrue(proxy.UDP) || proxy.InterfaceName != NodeRoutingStandardInterface || proxy.RoutingMark == nil || *proxy.RoutingMark != linuxplatform.VPNCTLRecoveryMark ||
			proxy.Server != "" || proxy.Port != nil || proxy.Cipher != "" || proxy.Password != "" || proxy.IPVersion != "" ||
			proxy.UDPOverTCP != nil || proxy.UDPOverTCPVersion != nil || proxy.Plugin != "" || proxy.ClientFingerprint != "" || proxy.PluginOptions != (nodeRoutingRestrictedPluginOpts{}) {
			return fmt.Errorf("standard node routing outbound does not match the pinned WireGuard binding")
		}
		return nil
	}
	if groups[0].Proxies[0] != NodeRoutingRestrictedProxy || proxy.Name != NodeRoutingRestrictedProxy || proxy.Type != "ss" ||
		proxy.Server != active.GatewayPublicIPv4 || proxy.Port == nil || *proxy.Port != restricted.TCPPort || proxy.Cipher != restricted.Cipher ||
		proxy.Password != active.RestrictedServerPassword || proxy.IPVersion != "ipv4" || !routingTrue(proxy.UDP) || !routingTrue(proxy.UDPOverTCP) ||
		proxy.UDPOverTCPVersion == nil || *proxy.UDPOverTCPVersion != restricted.UDPOverTCPVersion || proxy.InterfaceName != "" ||
		proxy.RoutingMark == nil || *proxy.RoutingMark != linuxplatform.VPNCTLRecoveryMark || proxy.Plugin != "shadow-tls" || proxy.ClientFingerprint != "chrome" {
		return fmt.Errorf("restricted node routing outbound does not match the pinned UoT binding")
	}
	identity, err := restricted.DecodeIdentitySecret(active.RestrictedIdentitySecret)
	if err != nil {
		return err
	}
	options := proxy.PluginOptions
	if options.Host != active.RestrictedHandshakeHost || options.Password != identity.ShadowTLSPassword ||
		options.Version == nil || *options.Version != restricted.ShadowTLSVersion || !routingTrue(options.StrictMode) {
		return fmt.Errorf("restricted node routing outbound does not enforce strict ShadowTLS v3")
	}
	return nil
}

func validNodeRoutingDirectDNSProxy(proxy nodeRoutingProxy) bool {
	return proxy.Name == NodeRoutingDirectDNSProxy && proxy.Type == "direct" && routingTrue(proxy.UDP) &&
		proxy.RoutingMark != nil && *proxy.RoutingMark == linuxplatform.VPNCTLDirectMark &&
		proxy.Server == "" && proxy.Port == nil && proxy.Cipher == "" && proxy.Password == "" && proxy.IPVersion == "" &&
		proxy.UDPOverTCP == nil && proxy.UDPOverTCPVersion == nil && proxy.InterfaceName == "" && proxy.Plugin == "" &&
		proxy.ClientFingerprint == "" && proxy.PluginOptions == (nodeRoutingRestrictedPluginOpts{})
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

func validateNodeRoutingRules(rules []string, policies map[string][]string, mode RoutingDNSMode, directDNS []string, active NodeRoutingActiveOutbound) error {
	if len(rules) == 0 || rules[len(rules)-1] != "MATCH,DIRECT" {
		return fmt.Errorf("node routing rules must end in direct for unmatched traffic")
	}
	start := 0
	if active.Kind != "" {
		want := "IP-CIDR," + active.GatewayOverlayIPv4 + "/32," + NodeRoutingGatewayGroup + ",no-resolve"
		if rules[0] != want {
			return fmt.Errorf("node routing internal gateway must be first and use the active outbound")
		}
		start = 1
	}
	wantPolicies := make(map[string][]string)
	decisions := make([]MatcherDecisionRule, 0, len(rules)-1-start)
	for index, value := range rules[start : len(rules)-1] {
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
