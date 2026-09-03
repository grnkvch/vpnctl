package routing

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	ClashDNSPolicy ClashDNSMode = "policy"
	ClashDNSDirect ClashDNSMode = "direct"

	clashStandardProxyName   = "VPNCTL-STANDARD"
	clashRestrictedProxyName = "VPNCTL-RESTRICTED"
	clashGatewayGroupName    = "VPNCTL-GATEWAY"
)

var defaultClashDirectDNS = []string{"1.1.1.1", "8.8.8.8"}

type ClashDNSMode string

type ClashProfileRequest struct {
	ClientReference  string
	GatewayPublicKey string
	DNSMode          ClashDNSMode
	DirectDNSServers []string
}

type ClashProfile struct {
	ClientID              string
	ClientName            string
	SourceStateGeneration uint64
	PolicyGeneration      uint64
	CredentialGeneration  uint64
	HandshakeHostID       string
	HandshakeHostVersion  int
	DNSMode               ClashDNSMode
	content               []byte
}

func (profile ClashProfile) Bytes() []byte {
	return append([]byte(nil), profile.content...)
}

type ClashProfileRenderer struct {
	state       ClientStateStore
	credentials ClientCredentialReader
}

func NewClashProfileRenderer(state ClientStateStore, credentials ClientCredentialReader) (*ClashProfileRenderer, error) {
	if state == nil || credentials == nil {
		return nil, fmt.Errorf("Clash profile renderer state and credential reader are required")
	}
	return &ClashProfileRenderer{state: state, credentials: credentials}, nil
}

func (renderer *ClashProfileRenderer) Render(request ClashProfileRequest) (ClashProfile, error) {
	if renderer == nil {
		return ClashProfile{}, fmt.Errorf("Clash profile renderer is required")
	}
	state, err := renderer.state.Load()
	if err != nil {
		return ClashProfile{}, fmt.Errorf("load Clash profile state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return ClashProfile{}, fmt.Errorf("validate Clash profile state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return ClashProfile{}, fmt.Errorf("Clash client profiles require gateway state")
	}
	client, err := resolveVisibleClient(state.Clients, request.ClientReference)
	if err != nil {
		return ClashProfile{}, err
	}
	if client.Lifecycle != model.LifecycleActive {
		return ClashProfile{}, fmt.Errorf("client %s is not active", client.Name)
	}
	standard, found := findClientStandardTransport(state.Transports, client.ID)
	if !found || standard.State == model.TransportDisabled {
		return ClashProfile{}, fmt.Errorf("client %s has no exportable standard transport", client.Name)
	}
	privateKeyBytes, err := renderer.credentials.Get(standard.CredentialRef)
	if err != nil {
		return ClashProfile{}, fmt.Errorf("read client standard credential: %w", err)
	}
	privateKey := strings.TrimSpace(string(privateKeyBytes))
	if err := wireguard.ValidateKey(privateKey); err != nil {
		return ClashProfile{}, fmt.Errorf("client standard credential is invalid: %w", err)
	}
	gatewayPublicKey := strings.TrimSpace(request.GatewayPublicKey)
	if err := wireguard.ValidateKey(gatewayPublicKey); err != nil {
		return ClashProfile{}, fmt.Errorf("gateway WireGuard public key is invalid: %w", err)
	}
	dnsMode, directDNS, err := normalizeClashDNS(request.DNSMode, request.DirectDNSServers)
	if err != nil {
		return ClashProfile{}, err
	}
	gatewayDNS, err := clashGatewayDNSAddress(state.Host.ClientCIDR)
	if err != nil {
		return ClashProfile{}, err
	}
	composition, policyGeneration, err := clientPresetComposition(state, client)
	if err != nil {
		return ClashProfile{}, err
	}
	rules, err := compileClashRules(composition)
	if err != nil {
		return ClashProfile{}, fmt.Errorf("compile Clash policy: %w", err)
	}
	handshakeHostID := ""
	handshakeHostVersion := 0
	var restrictedInput *clashRestrictedRenderInput
	if restrictedTransport, found := findClientRestrictedTransport(state.Transports, client.ID); found && restrictedTransport.State != model.TransportDisabled {
		if state.HandshakeHost == nil {
			return ClashProfile{}, fmt.Errorf("client %s restricted transport has no authoritative handshake host", client.Name)
		}
		identityContent, err := renderer.credentials.Get(restrictedTransport.CredentialRef)
		if err != nil {
			return ClashProfile{}, fmt.Errorf("read client restricted credential: %w", err)
		}
		identitySecret, err := restricted.DecodeIdentitySecret(identityContent)
		if err != nil {
			return ClashProfile{}, fmt.Errorf("client restricted credential is invalid: %w", err)
		}
		gatewayContent, err := renderer.credentials.Get(restricted.GatewayCredentialRef)
		if err != nil {
			return ClashProfile{}, fmt.Errorf("read gateway restricted credential: %w", err)
		}
		gatewaySecret, err := restricted.DecodeGatewaySecret(gatewayContent)
		if err != nil {
			return ClashProfile{}, fmt.Errorf("gateway restricted credential is invalid: %w", err)
		}
		handshakeHostID = state.HandshakeHost.CandidateID
		handshakeHostVersion = state.HandshakeHost.ListVersion
		restrictedInput = &clashRestrictedRenderInput{
			ServerPassword:   gatewaySecret.ShadowsocksPassword,
			IdentityPassword: identitySecret.ShadowTLSPassword,
			HandshakeHost:    restrictedTransport.HandshakeHost,
		}
	}
	content, err := renderClashProfile(clashRenderInput{
		Server: state.Host.PublicIPv4, ClientIP: client.OverlayIPv4,
		PrivateKey: privateKey, GatewayPublicKey: gatewayPublicKey,
		Restricted: restrictedInput,
		DNSMode:    dnsMode, DirectDNS: directDNS, GatewayDNS: gatewayDNS, Rules: rules,
	})
	if err != nil {
		return ClashProfile{}, err
	}
	return ClashProfile{
		ClientID: client.ID, ClientName: client.Name, SourceStateGeneration: state.Generation,
		PolicyGeneration: policyGeneration, CredentialGeneration: client.CredentialGeneration,
		HandshakeHostID: handshakeHostID, HandshakeHostVersion: handshakeHostVersion,
		DNSMode: dnsMode, content: content,
	}, nil
}

func clientHasRestrictedTransport(transports []model.Transport, clientID string) bool {
	transport, found := findClientRestrictedTransport(transports, clientID)
	return found && transport.State != model.TransportDisabled
}

func findClientRestrictedTransport(transports []model.Transport, clientID string) (model.Transport, bool) {
	for _, transport := range transports {
		if transport.OwnerKind == model.TargetClient && transport.OwnerID == clientID &&
			transport.Kind == model.TransportRestricted {
			return transport, true
		}
	}
	return model.Transport{}, false
}

func normalizeClashDNS(mode ClashDNSMode, requested []string) (ClashDNSMode, []string, error) {
	if mode == "" {
		mode = ClashDNSPolicy
	}
	if mode != ClashDNSPolicy && mode != ClashDNSDirect {
		return "", nil, fmt.Errorf("unsupported Clash DNS mode %q", mode)
	}
	values := requested
	if values == nil {
		values = defaultClashDirectDNS
	}
	if len(values) == 0 {
		return "", nil, fmt.Errorf("Clash direct DNS must contain at least one IPv4 server")
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || address.String() != value {
			return "", nil, fmt.Errorf("Clash direct DNS %q must be a canonical IPv4 address", value)
		}
		if _, duplicate := seen[value]; duplicate {
			return "", nil, fmt.Errorf("Clash direct DNS duplicates %s", value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return mode, result, nil
}

func clashGatewayDNSAddress(clientCIDR string) (string, error) {
	prefix, err := netip.ParsePrefix(clientCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.String() != clientCIDR || prefix.Masked() != prefix {
		return "", fmt.Errorf("client CIDR %q cannot provide the Clash gateway DNS address", clientCIDR)
	}
	address := prefix.Addr().Next()
	if !address.IsValid() || !prefix.Contains(address) {
		return "", fmt.Errorf("client CIDR %s has no gateway DNS address", clientCIDR)
	}
	return address.String(), nil
}

func clientPresetComposition(state model.State, client model.Client) (PresetComposition, uint64, error) {
	policy, found := findTargetPolicy(state.Policies, model.TargetClient, client.ID)
	if !found {
		if len(client.AssignedPresets) != 0 {
			return PresetComposition{}, 0, fmt.Errorf("client %s has assignments without an effective policy", client.Name)
		}
		composition, err := NormalizePresetComposition([]PresetAST{})
		return composition, 0, err
	}
	if !equalPolicyPresetNames(policy.PresetNames, client.AssignedPresets) {
		return PresetComposition{}, 0, fmt.Errorf("client %s policy assignment differs from its identity", client.Name)
	}

	presets := make(map[string]model.Preset, len(state.Presets))
	for _, preset := range state.Presets {
		presets[strings.ToLower(preset.Name)] = preset
	}
	expectedSelectors, expectedHash, err := effectivePolicy(policy.PresetNames, presets)
	if err != nil {
		return PresetComposition{}, 0, fmt.Errorf("resolve client %s effective policy: %w", client.Name, err)
	}
	if !presetSelectorsEqual(policy.Selectors, expectedSelectors) || policy.EffectiveHash != expectedHash {
		return PresetComposition{}, 0, fmt.Errorf("client %s effective policy does not match its active preset generations", client.Name)
	}

	asts := make([]PresetAST, 0, len(policy.PresetNames))
	for _, name := range policy.PresetNames {
		preset := presets[strings.ToLower(name)]
		asts = append(asts, PresetAST{
			SchemaVersion: PresetDocumentSchemaVersion,
			Name:          preset.Name,
			Selectors:     canonicalPresetSelectors(preset.Selectors),
		})
	}
	composition, err := NormalizePresetComposition(asts)
	if err != nil {
		return PresetComposition{}, 0, fmt.Errorf("normalize client %s preset composition: %w", client.Name, err)
	}
	return composition, policy.Generation, nil
}

type clashRule struct {
	Kind     model.SelectorKind
	Value    string
	Selected bool
}

func compileClashRules(composition PresetComposition) ([]clashRule, error) {
	if err := composition.Validate(); err != nil {
		return nil, err
	}
	domains := make(map[string]struct{})
	suffixes := make(map[string]struct{})
	prefixSet := make(map[string]netip.Prefix)
	for _, preset := range composition.Presets {
		for _, selector := range append(append([]model.Selector{}, preset.Includes...), preset.Excludes...) {
			switch selector.Kind {
			case model.SelectorDomain:
				domains[selector.Value] = struct{}{}
			case model.SelectorDomainSuffix:
				suffixes[selector.Value] = struct{}{}
			case model.SelectorIPCIDR:
				prefix := netip.MustParsePrefix(selector.Value)
				prefixSet[prefix.String()] = prefix
			}
		}
	}

	exactValues := sortedStringKeys(domains)
	suffixValues := sortedStringKeys(suffixes)
	sort.Slice(suffixValues, func(left, right int) bool {
		leftLabels := strings.Count(suffixValues[left], ".")
		rightLabels := strings.Count(suffixValues[right], ".")
		if leftLabels != rightLabels {
			return leftLabels > rightLabels
		}
		if len(suffixValues[left]) != len(suffixValues[right]) {
			return len(suffixValues[left]) > len(suffixValues[right])
		}
		return suffixValues[left] < suffixValues[right]
	})

	rules := make([]clashRule, 0, len(domains)+len(suffixes)+len(prefixSet))
	for _, domain := range exactValues {
		selected, err := composition.SelectsDomain(domain)
		if err != nil {
			return nil, err
		}
		rules = append(rules, clashRule{Kind: model.SelectorDomain, Value: domain, Selected: selected})
	}
	for _, suffix := range suffixValues {
		probe, found := uncoveredDomainForSuffix(suffix, domains, suffixes)
		if !found {
			continue
		}
		selected, err := composition.SelectsDomain(probe)
		if err != nil {
			return nil, err
		}
		rules = append(rules, clashRule{Kind: model.SelectorDomainSuffix, Value: suffix, Selected: selected})
	}

	prefixes := make([]netip.Prefix, 0, len(prefixSet))
	for _, prefix := range prefixSet {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(left, right int) bool {
		if prefixes[left].Addr().BitLen() != prefixes[right].Addr().BitLen() {
			return prefixes[left].Addr().BitLen() < prefixes[right].Addr().BitLen()
		}
		if prefixes[left].Bits() != prefixes[right].Bits() {
			return prefixes[left].Bits() > prefixes[right].Bits()
		}
		return prefixes[left].Addr().Compare(prefixes[right].Addr()) < 0
	})
	for _, prefix := range prefixes {
		covered := make([]netip.Prefix, 0)
		for _, candidate := range prefixes {
			if candidate.Addr().BitLen() == prefix.Addr().BitLen() && candidate.Bits() > prefix.Bits() && prefix.Contains(candidate.Addr()) {
				covered = append(covered, candidate)
			}
		}
		probe, found := uncoveredAddress(prefix, covered)
		if !found {
			continue
		}
		selected, err := composition.SelectsIP(probe)
		if err != nil {
			return nil, err
		}
		rules = append(rules, clashRule{Kind: model.SelectorIPCIDR, Value: prefix.String(), Selected: selected})
	}
	return rules, nil
}

func sortedStringKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uncoveredDomainForSuffix(suffix string, exact, suffixes map[string]struct{}) (string, bool) {
	if _, covered := exact[suffix]; !covered {
		return suffix, true
	}
	labels := make([]string, 0, len(exact)+len(suffixes)+36)
	for character := 'a'; character <= 'z'; character++ {
		labels = append(labels, string(character))
	}
	for character := '0'; character <= '9'; character++ {
		labels = append(labels, string(character))
	}
	for index := 0; index <= len(exact)+len(suffixes); index++ {
		labels = append(labels, "v"+strconv.Itoa(index))
	}
	for _, label := range labels {
		candidate := label + "." + suffix
		if err := (model.Selector{Kind: model.SelectorDomain, Value: candidate}).Validate(); err != nil {
			continue
		}
		if _, covered := exact[candidate]; covered {
			continue
		}
		covered := false
		for descendant := range suffixes {
			if descendant != suffix && (candidate == descendant || strings.HasSuffix(candidate, "."+descendant)) {
				covered = true
				break
			}
		}
		if !covered {
			return candidate, true
		}
	}
	return "", false
}

func uncoveredAddress(prefix netip.Prefix, covered []netip.Prefix) (netip.Addr, bool) {
	if len(covered) == 0 {
		return prefix.Addr(), true
	}
	if prefix.Bits() == prefix.Addr().BitLen() {
		return netip.Addr{}, false
	}
	left, right := splitPrefix(prefix)
	for _, half := range []netip.Prefix{left, right} {
		descendants := make([]netip.Prefix, 0, len(covered))
		fullyCovered := false
		for _, candidate := range covered {
			if candidate == half {
				fullyCovered = true
				break
			}
			if candidate.Bits() > half.Bits() && half.Contains(candidate.Addr()) {
				descendants = append(descendants, candidate)
			}
		}
		if fullyCovered {
			continue
		}
		if address, found := uncoveredAddress(half, descendants); found {
			return address, true
		}
	}
	return netip.Addr{}, false
}

func splitPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := prefix.Bits() + 1
	address := prefix.Addr()
	if address.Is4() {
		raw := address.As4()
		raw[(bits-1)/8] |= byte(1 << (7 - ((bits - 1) % 8)))
		return netip.PrefixFrom(address, bits).Masked(), netip.PrefixFrom(netip.AddrFrom4(raw), bits).Masked()
	}
	raw := address.As16()
	raw[(bits-1)/8] |= byte(1 << (7 - ((bits - 1) % 8)))
	return netip.PrefixFrom(address, bits).Masked(), netip.PrefixFrom(netip.AddrFrom16(raw), bits).Masked()
}

type clashRenderInput struct {
	Server           string
	ClientIP         string
	PrivateKey       string
	GatewayPublicKey string
	Restricted       *clashRestrictedRenderInput
	DNSMode          ClashDNSMode
	DirectDNS        []string
	GatewayDNS       string
	Rules            []clashRule
}

type clashRestrictedRenderInput struct {
	ServerPassword   string
	IdentityPassword string
	HandshakeHost    string
}

func renderClashProfile(input clashRenderInput) ([]byte, error) {
	server, err := netip.ParseAddr(input.Server)
	if err != nil || !server.Is4() || server.String() != input.Server {
		return nil, fmt.Errorf("Clash gateway server must be a canonical IPv4 address")
	}
	clientIP, err := netip.ParseAddr(input.ClientIP)
	if err != nil || !clientIP.Is4() || clientIP.String() != input.ClientIP {
		return nil, fmt.Errorf("Clash client IP must be a canonical IPv4 address")
	}
	gatewayDNS, err := netip.ParseAddr(input.GatewayDNS)
	if err != nil || !gatewayDNS.Is4() || gatewayDNS.String() != input.GatewayDNS {
		return nil, fmt.Errorf("Clash gateway DNS must be a canonical IPv4 address")
	}

	var profile strings.Builder
	profile.WriteString("mode: rule\n")
	profile.WriteString("log-level: silent\n")
	profile.WriteString("ipv6: false\n")
	profile.WriteString("geodata-loader: memconservative\n")
	profile.WriteString("geo-auto-update: false\n\n")
	profile.WriteString("dns:\n")
	profile.WriteString("  enable: true\n")
	profile.WriteString("  ipv6: false\n")
	profile.WriteString("  cache-algorithm: arc\n")
	profile.WriteString("  enhanced-mode: redir-host\n")
	profile.WriteString("  use-hosts: false\n")
	profile.WriteString("  use-system-hosts: false\n")
	profile.WriteString("  respect-rules: false\n")
	profile.WriteString("  default-nameserver:\n")
	for _, server := range input.DirectDNS {
		fmt.Fprintf(&profile, "    - %s\n", server)
	}
	profile.WriteString("  nameserver:\n")
	for _, server := range input.DirectDNS {
		fmt.Fprintf(&profile, "    - %s\n", strconv.Quote("udp://"+server+":53#DIRECT"))
	}
	if input.DNSMode == ClashDNSPolicy {
		domainRules := clashDomainRules(input.Rules)
		if len(domainRules) > 0 {
			profile.WriteString("  nameserver-policy:\n")
			for _, rule := range domainRules {
				pattern := rule.Value
				if rule.Kind == model.SelectorDomainSuffix {
					pattern = "+." + pattern
				}
				fmt.Fprintf(&profile, "    %s:\n", strconv.Quote(pattern))
				if rule.Selected {
					resolver := "udp://" + input.GatewayDNS + ":53#" + clashGatewayGroupName
					fmt.Fprintf(&profile, "      - %s\n", strconv.Quote(resolver))
					continue
				}
				for _, server := range input.DirectDNS {
					resolver := "udp://" + server + ":53#DIRECT"
					fmt.Fprintf(&profile, "      - %s\n", strconv.Quote(resolver))
				}
			}
		}
	}
	profile.WriteString("\nproxies:\n")
	fmt.Fprintf(&profile, "  - name: %s\n", clashStandardProxyName)
	profile.WriteString("    type: wireguard\n")
	fmt.Fprintf(&profile, "    server: %s\n", input.Server)
	profile.WriteString("    port: 51820\n")
	fmt.Fprintf(&profile, "    ip: %s\n", input.ClientIP)
	fmt.Fprintf(&profile, "    private-key: %s\n", strconv.Quote(input.PrivateKey))
	fmt.Fprintf(&profile, "    public-key: %s\n", strconv.Quote(input.GatewayPublicKey))
	profile.WriteString("    mtu: 1420\n")
	profile.WriteString("    udp: true\n")
	profile.WriteString("    allowed-ips:\n")
	profile.WriteString("      - 0.0.0.0/0\n")
	if input.Restricted != nil {
		if err := restricted.ValidateServerPassword(input.Restricted.ServerPassword); err != nil {
			return nil, err
		}
		if err := restricted.ValidateIdentityPassword(input.Restricted.IdentityPassword); err != nil {
			return nil, err
		}
		profile.WriteString("\n")
		fmt.Fprintf(&profile, "  - name: %s\n", clashRestrictedProxyName)
		profile.WriteString("    type: ss\n")
		fmt.Fprintf(&profile, "    server: %s\n", input.Server)
		fmt.Fprintf(&profile, "    port: %d\n", restricted.TCPPort)
		fmt.Fprintf(&profile, "    cipher: %s\n", restricted.Cipher)
		fmt.Fprintf(&profile, "    password: %s\n", strconv.Quote(input.Restricted.ServerPassword))
		profile.WriteString("    ip-version: ipv4\n")
		profile.WriteString("    udp: true\n")
		profile.WriteString("    udp-over-tcp: true\n")
		fmt.Fprintf(&profile, "    udp-over-tcp-version: %d\n", restricted.UDPOverTCPVersion)
		profile.WriteString("    plugin: shadow-tls\n")
		profile.WriteString("    client-fingerprint: chrome\n")
		profile.WriteString("    plugin-opts:\n")
		fmt.Fprintf(&profile, "      host: %s\n", strconv.Quote(input.Restricted.HandshakeHost))
		fmt.Fprintf(&profile, "      password: %s\n", strconv.Quote(input.Restricted.IdentityPassword))
		fmt.Fprintf(&profile, "      version: %d\n", restricted.ShadowTLSVersion)
		profile.WriteString("      strict-mode: true\n")
	}
	profile.WriteString("\nproxy-groups:\n")
	fmt.Fprintf(&profile, "  - name: %s\n", clashGatewayGroupName)
	profile.WriteString("    type: select\n")
	profile.WriteString("    proxies:\n")
	fmt.Fprintf(&profile, "      - %s\n", clashStandardProxyName)
	if input.Restricted != nil {
		fmt.Fprintf(&profile, "      - %s\n", clashRestrictedProxyName)
	}
	profile.WriteString("\nrules:\n")
	for _, rule := range input.Rules {
		target := "DIRECT"
		if rule.Selected {
			target = clashGatewayGroupName
		}
		switch rule.Kind {
		case model.SelectorDomain:
			fmt.Fprintf(&profile, "  - DOMAIN,%s,%s\n", rule.Value, target)
		case model.SelectorDomainSuffix:
			fmt.Fprintf(&profile, "  - DOMAIN-SUFFIX,%s,%s\n", rule.Value, target)
		case model.SelectorIPCIDR:
			prefix := netip.MustParsePrefix(rule.Value)
			kind := "IP-CIDR"
			if prefix.Addr().Is6() {
				kind = "IP-CIDR6"
			}
			fmt.Fprintf(&profile, "  - %s,%s,%s\n", kind, rule.Value, target)
		default:
			return nil, fmt.Errorf("unsupported Clash rule selector %q", rule.Kind)
		}
	}
	profile.WriteString("  - MATCH,DIRECT\n")
	return []byte(profile.String()), nil
}

func clashDomainRules(rules []clashRule) []clashRule {
	result := make([]clashRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Kind == model.SelectorDomain || rule.Kind == model.SelectorDomainSuffix {
			result = append(result, rule)
		}
	}
	return result
}
