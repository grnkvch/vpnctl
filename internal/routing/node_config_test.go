package routing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
)

func TestRenderNodeRoutingConfigUsesHostWideTUNPolicyDNSAndFailClosedUnboundTarget(t *testing.T) {
	t.Parallel()

	request := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy)
	candidate, err := RenderNodeRoutingConfig(request)
	if err != nil {
		t.Fatalf("RenderNodeRoutingConfig() error = %v", err)
	}
	content := string(candidate.Bytes())
	for _, expected := range []string{
		"allow-lan: false\n",
		"bind-address: 127.0.0.1\n",
		"log-level: silent\n",
		"tun:\n  enable: true\n  device: vpnctl0\n  stack: system\n  auto-route: false\n  auto-detect-interface: false\n  dns-hijack: []\n  mtu: 1400\n",
		"listen: 127.0.0.1:1053\n",
		"enhanced-mode: redir-host\n",
		"\"api.private.example.com\":\n      - \"udp://10.67.0.1:53#VPNCTL-GATEWAY\"\n",
		"\"example.com\":\n      - \"udp://192.0.2.53:53#DIRECT\"\n      - \"udp://198.51.100.53:53#DIRECT\"\n",
		"\"+.private.example.com\":\n      - \"udp://192.0.2.53:53#DIRECT\"\n",
		"\"+.example.com\":\n      - \"udp://10.67.0.1:53#VPNCTL-GATEWAY\"\n",
		"  - name: VPNCTL-GATEWAY\n    type: select\n    proxies:\n      - REJECT-DROP\n",
		"  - DOMAIN,api.private.example.com,VPNCTL-GATEWAY\n",
		"  - DOMAIN,example.com,DIRECT\n",
		"  - DOMAIN-SUFFIX,private.example.com,DIRECT\n",
		"  - DOMAIN-SUFFIX,example.com,VPNCTL-GATEWAY\n",
		"  - IP-CIDR,10.1.2.0/24,VPNCTL-GATEWAY\n",
		"  - IP-CIDR,10.1.0.0/16,DIRECT\n",
		"  - IP-CIDR,10.0.0.0/8,VPNCTL-GATEWAY\n",
		"  - IP-CIDR6,2001:db8:1:2::/64,VPNCTL-GATEWAY\n",
		"  - MATCH,DIRECT\n",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("node routing config lacks %q:\n%s", expected, content)
		}
	}
	for _, forbidden := range []string{
		"mixed-port:", "socks-port:", "redir-port:", "tproxy-port:", "external-controller:",
		"find-process-mode:", "process-name", "process-path", "uid:", "user:", "cgroup", "package-name",
		"include-interface:", "exclude-interface:", "auto-redirect: true", "auto-route: true",
	} {
		if strings.Contains(content, forbidden) {
			t.Errorf("host-wide node config contains scoped/unsafe field %q:\n%s", forbidden, content)
		}
	}
	if err := ValidateNodeRoutingConfig(candidate.Bytes(), NodeRoutingDNSPolicy); err != nil {
		t.Fatalf("ValidateNodeRoutingConfig() error = %v", err)
	}
	descriptor := candidate.Descriptor()
	if err := descriptor.Validate(); err != nil || descriptor.PolicyGeneration != 9 || descriptor.DNSMode != NodeRoutingDNSPolicy {
		t.Fatalf("descriptor = %#v, %v", descriptor, err)
	}
	defensive := candidate.Bytes()
	defensive[0] = 'X'
	if bytes.Equal(defensive, candidate.Bytes()) {
		t.Fatal("NodeRoutingCandidate.Bytes() exposed mutable storage")
	}
	repeated, err := RenderNodeRoutingConfig(request)
	if err != nil || !reflect.DeepEqual(repeated, candidate) {
		t.Fatalf("repeated render = %#v, %v; want deterministic %#v", repeated, err, candidate)
	}
}

func TestRenderNodeRoutingConfigSupportsExplicitDirectDNSAndAllDirectPolicy(t *testing.T) {
	t.Parallel()

	request := nodeRoutingRenderFixture(t, NodeRoutingDNSDirect)
	direct, err := RenderNodeRoutingConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	content := string(direct.Bytes())
	if strings.Contains(content, "nameserver-policy:") || !strings.Contains(content, "DOMAIN-SUFFIX,example.com,VPNCTL-GATEWAY") {
		t.Fatalf("direct DNS compatibility changed routing or retained split DNS:\n%s", content)
	}
	if err := ValidateNodeRoutingConfig(direct.Bytes(), NodeRoutingDNSDirect); err != nil {
		t.Fatal(err)
	}
	if err := ValidateNodeRoutingConfig(direct.Bytes(), NodeRoutingDNSPolicy); err == nil {
		t.Fatal("direct DNS artifact passed policy-mode validation")
	}

	empty, err := NormalizePresetComposition([]PresetAST{})
	if err != nil {
		t.Fatal(err)
	}
	emptyIR, err := CompileMatcherIR(empty)
	if err != nil {
		t.Fatal(err)
	}
	request.Matcher = emptyIR
	request.PolicyGeneration = 0
	request.DNSMode = NodeRoutingDNSPolicy
	allDirect, err := RenderNodeRoutingConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	allDirectText := string(allDirect.Bytes())
	if !strings.Contains(allDirectText, "nameserver-policy: {}") || strings.Count(allDirectText, "  - MATCH,DIRECT\n") != 1 ||
		strings.Contains(allDirectText, "DOMAIN,") || strings.Contains(allDirectText, "IP-CIDR") {
		t.Fatalf("empty policy did not render an explicit all-direct base:\n%s", allDirectText)
	}
}

func TestRenderNodeRoutingConfigBindsEverySelectedAndInternalPathToOneStandardOutbound(t *testing.T) {
	t.Parallel()
	request := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy)
	request.ActiveOutbound = nodeRoutingStandardBinding()
	candidate, err := RenderNodeRoutingConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	content := string(candidate.Bytes())
	for _, required := range []string{
		"proxies:\n  - name: VPNCTL-STANDARD\n    type: direct\n    udp: true\n    interface-name: vpnctl-wg\n    routing-mark: 50331648\n",
		"  - name: VPNCTL-GATEWAY\n    type: select\n    proxies:\n      - VPNCTL-STANDARD\n",
		"  - IP-CIDR,10.67.0.1/32,VPNCTL-GATEWAY,no-resolve\n",
		"  - DOMAIN,api.private.example.com,VPNCTL-GATEWAY\n",
		"  - MATCH,DIRECT\n",
	} {
		if !strings.Contains(content, required) {
			t.Errorf("standard-bound node routing config lacks %q:\n%s", required, content)
		}
	}
	for _, forbidden := range []string{"VPNCTL-RESTRICTED", "      - DIRECT\n", "fallback", "url-test"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("standard-bound node routing config contains %q:\n%s", forbidden, content)
		}
	}
	if err := ValidateNodeRoutingConfig(candidate.Bytes(), NodeRoutingDNSPolicy); err != nil {
		t.Fatal(err)
	}
	descriptor := candidate.Descriptor()
	if descriptor.ActiveTransport != model.TransportStandard || descriptor.CredentialGeneration != 7 {
		t.Fatalf("standard descriptor = %+v", descriptor)
	}
}

func TestRenderNodeRoutingConfigBindsSelectedUDPControlAndTunnelToOneRestrictedOutbound(t *testing.T) {
	t.Parallel()
	request := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy)
	request.ActiveOutbound = nodeRoutingRestrictedBinding(t)
	candidate, err := RenderNodeRoutingConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	content := string(candidate.Bytes())
	for _, required := range []string{
		"proxies:\n  - name: VPNCTL-RESTRICTED\n    type: ss\n    server: 203.0.113.44\n    port: 8443\n",
		"    udp: true\n    udp-over-tcp: true\n    udp-over-tcp-version: 2\n    routing-mark: 50331648\n",
		"    plugin: shadow-tls\n    client-fingerprint: chrome\n",
		"      host: \"www.cloudflare.com\"\n",
		"      version: 3\n      strict-mode: true\n",
		"  - name: VPNCTL-GATEWAY\n    type: select\n    proxies:\n      - VPNCTL-RESTRICTED\n",
		"  - IP-CIDR,10.67.0.1/32,VPNCTL-GATEWAY,no-resolve\n",
		"  - MATCH,DIRECT\n",
	} {
		if !strings.Contains(content, required) {
			t.Errorf("restricted-bound node routing config lacks %q:\n%s", required, content)
		}
	}
	for _, forbidden := range []string{"VPNCTL-STANDARD", "VPNCTL-RESTRICTED-UDP", "      - REJECT-DROP\n", "      - DIRECT\n", "fallback", "url-test"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("restricted-bound node routing config contains %q:\n%s", forbidden, content)
		}
	}
	if err := ValidateBoundNodeRoutingConfig(candidate.Bytes(), request.DNSMode, request.ActiveOutbound, request.Component, request.GatewayDNSIPv4); err != nil {
		t.Fatal(err)
	}
	descriptor := candidate.Descriptor()
	if descriptor.ActiveTransport != model.TransportRestricted || descriptor.CredentialGeneration != 7 {
		t.Fatalf("restricted descriptor = %+v", descriptor)
	}

	tampered := map[string]string{
		"native UDP disabled": strings.Replace(content, "    udp-over-tcp: true", "    udp-over-tcp: false", 1),
		"direct fallback":     strings.Replace(content, "      - VPNCTL-RESTRICTED", "      - DIRECT", 1),
		"different internal path": strings.Replace(
			content, "IP-CIDR,10.67.0.1/32,VPNCTL-GATEWAY,no-resolve", "IP-CIDR,10.67.0.1/32,DIRECT,no-resolve", 1,
		),
		"second transport": strings.Replace(content, "      - VPNCTL-RESTRICTED\n", "      - VPNCTL-RESTRICTED\n      - VPNCTL-STANDARD\n", 1),
	}
	for name, value := range tampered {
		if err := ValidateNodeRoutingConfig([]byte(value), NodeRoutingDNSPolicy); err == nil {
			t.Errorf("%s config passed validation", name)
		}
	}
}

func TestNodeRoutingConfigRejectsScopedFallbackAndSemanticTampering(t *testing.T) {
	t.Parallel()

	candidate, err := RenderNodeRoutingConfig(nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy))
	if err != nil {
		t.Fatal(err)
	}
	base := string(candidate.Bytes())
	cases := map[string]string{
		"automatic route":       strings.Replace(base, "auto-route: false", "auto-route: true", 1),
		"process scope":         strings.Replace(base, "mode: rule", "mode: rule\nfind-process-mode: always", 1),
		"public listener":       strings.Replace(base, "mode: rule", "mode: rule\nmixed-port: 7890", 1),
		"logging":               strings.Replace(base, "log-level: silent", "log-level: info", 1),
		"direct unbound target": strings.Replace(base, "      - REJECT-DROP", "      - DIRECT", 1),
		"selected fail-direct": strings.Replace(
			base, "DOMAIN,api.private.example.com,VPNCTL-GATEWAY", "DOMAIN,api.private.example.com,DIRECT", 1,
		),
		"gateway DNS fallback": strings.Replace(
			base, "      - \"udp://10.67.0.1:53#VPNCTL-GATEWAY\"", "      - \"udp://192.0.2.53:53#DIRECT\"", 1,
		),
		"rule reorder": strings.Replace(
			base,
			"  - IP-CIDR,10.1.2.0/24,VPNCTL-GATEWAY\n  - IP-CIDR,10.1.0.0/16,DIRECT\n",
			"  - IP-CIDR,10.1.0.0/16,DIRECT\n  - IP-CIDR,10.1.2.0/24,VPNCTL-GATEWAY\n", 1,
		),
		"trailing document": base + "---\nmode: direct\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateNodeRoutingConfig([]byte(content), NodeRoutingDNSPolicy); err == nil {
				t.Fatal("tampered node routing config passed validation")
			}
		})
	}
}

func TestRenderNodeRoutingConfigRejectsInvalidInputsAndHasNoScopeAPI(t *testing.T) {
	t.Parallel()

	requestType := reflect.TypeOf(NodeRoutingRenderRequest{})
	wantFields := []string{"Matcher", "PolicyGeneration", "DNSMode", "DirectDNSServers", "GatewayDNSIPv4", "ActiveOutbound", "Component"}
	gotFields := make([]string, requestType.NumField())
	for index := range gotFields {
		gotFields[index] = requestType.Field(index).Name
	}
	if !reflect.DeepEqual(gotFields, wantFields) {
		t.Fatalf("node routing request fields = %v, want scope-free %v", gotFields, wantFields)
	}

	base := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy)
	for name, mutate := range map[string]func(*NodeRoutingRenderRequest){
		"unknown DNS mode":       func(value *NodeRoutingRenderRequest) { value.DNSMode = "automatic" },
		"missing direct DNS":     func(value *NodeRoutingRenderRequest) { value.DirectDNSServers = nil },
		"duplicate direct DNS":   func(value *NodeRoutingRenderRequest) { value.DirectDNSServers = []string{"192.0.2.53", "192.0.2.53"} },
		"IPv6 direct DNS":        func(value *NodeRoutingRenderRequest) { value.DirectDNSServers = []string{"2001:db8::53"} },
		"local stub as upstream": func(value *NodeRoutingRenderRequest) { value.DirectDNSServers = []string{"127.0.0.53"} },
		"IPv6 gateway DNS":       func(value *NodeRoutingRenderRequest) { value.GatewayDNSIPv4 = "2001:db8::53" },
		"missing policy generation": func(value *NodeRoutingRenderRequest) {
			value.PolicyGeneration = 0
		},
		"wrong component": func(value *NodeRoutingRenderRequest) { value.Component.Version = "v1.19.31" },
		"missing capability": func(value *NodeRoutingRenderRequest) {
			value.Component.Capabilities = []string{"tun-routing"}
		},
		"invalid matcher": func(value *NodeRoutingRenderRequest) { value.Matcher.SchemaVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := base
			request.DirectDNSServers = append([]string(nil), base.DirectDNSServers...)
			request.Component.Capabilities = append([]string(nil), base.Component.Capabilities...)
			mutate(&request)
			if _, err := RenderNodeRoutingConfig(request); err == nil {
				t.Fatal("invalid node routing input rendered a candidate")
			}
		})
	}
}

func TestRenderNodeRoutingConfigRejectsAmbiguousOrWeakenedActiveBindings(t *testing.T) {
	t.Parallel()
	standard := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy)
	standard.ActiveOutbound = nodeRoutingStandardBinding()
	restrictedRequest := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy)
	restrictedRequest.ActiveOutbound = nodeRoutingRestrictedBinding(t)
	for name, request := range map[string]NodeRoutingRenderRequest{
		"unbound with endpoint": func() NodeRoutingRenderRequest {
			value := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy)
			value.ActiveOutbound.GatewayPublicIPv4 = "203.0.113.44"
			return value
		}(),
		"unknown kind": func() NodeRoutingRenderRequest {
			value := standard
			value.ActiveOutbound.Kind = "automatic"
			return value
		}(),
		"zero generation": func() NodeRoutingRenderRequest {
			value := standard
			value.ActiveOutbound.CredentialGeneration = 0
			return value
		}(),
		"private public endpoint": func() NodeRoutingRenderRequest {
			value := standard
			value.ActiveOutbound.GatewayPublicIPv4 = "10.0.0.1"
			return value
		}(),
		"different gateway DNS": func() NodeRoutingRenderRequest {
			value := standard
			value.ActiveOutbound.GatewayOverlayIPv4 = "10.67.0.2"
			return value
		}(),
		"standard with restricted secret": func() NodeRoutingRenderRequest {
			value := standard
			value.ActiveOutbound.RestrictedIdentitySecret = []byte("secret")
			return value
		}(),
		"restricted without UoT capability": func() NodeRoutingRenderRequest {
			value := restrictedRequest
			value.Component.Capabilities = []string{"tun-routing", "redir-host-split-dns", "shadowtls-v3-strict", "shadowsocks-2022-blake3-aes-256-gcm"}
			return value
		}(),
		"restricted invalid identity": func() NodeRoutingRenderRequest {
			value := restrictedRequest
			value.ActiveOutbound.RestrictedIdentitySecret = []byte(`{"schema_version":1,"shadowtls_password":"short"}`)
			return value
		}(),
		"restricted invalid host": func() NodeRoutingRenderRequest {
			value := restrictedRequest
			value.ActiveOutbound.RestrictedHandshakeHost = "EXAMPLE.COM"
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := RenderNodeRoutingConfig(request); err == nil {
				t.Fatal("unsafe active binding rendered")
			}
		})
	}
}

func TestNodeRoutingConfigParsesWithPinnedMihomo(t *testing.T) {
	binary := os.Getenv("VPNCTL_PINNED_MIHOMO")
	if binary == "" {
		t.Skip("set VPNCTL_PINNED_MIHOMO to the v1.19.30 Linux/amd64 binary")
	}
	version, err := exec.Command(binary, "-v").CombinedOutput()
	if err != nil || !strings.Contains(string(version), NodeRoutingProviderVersion) {
		t.Fatalf("pinned Mihomo version is unavailable: %v: %s", err, version)
	}
	requests := map[string]NodeRoutingRenderRequest{
		"policy":            nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy),
		"direct":            nodeRoutingRenderFixture(t, NodeRoutingDNSDirect),
		"standard-active":   nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy),
		"restricted-active": nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy),
	}
	standard := requests["standard-active"]
	standard.ActiveOutbound = nodeRoutingStandardBinding()
	requests["standard-active"] = standard
	restrictedActive := requests["restricted-active"]
	restrictedActive.ActiveOutbound = nodeRoutingRestrictedBinding(t)
	requests["restricted-active"] = restrictedActive
	emptyComposition, err := NormalizePresetComposition([]PresetAST{})
	if err != nil {
		t.Fatal(err)
	}
	emptyIR, err := CompileMatcherIR(emptyComposition)
	if err != nil {
		t.Fatal(err)
	}
	emptyRequest := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy)
	emptyRequest.Matcher = emptyIR
	emptyRequest.PolicyGeneration = 0
	requests["empty-policy"] = emptyRequest
	for name, request := range requests {
		t.Run(name, func(t *testing.T) {
			candidate, err := RenderNodeRoutingConfig(request)
			if err != nil {
				t.Fatal(err)
			}
			directory := t.TempDir()
			path := filepath.Join(directory, NodeRoutingConfigFileName)
			if err := os.WriteFile(path, candidate.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.Command(binary, "-t", "-d", directory, "-f", path).CombinedOutput()
			if err != nil {
				t.Fatalf("pinned Mihomo rejected node routing config: %v:\n%s\nconfig:\n%s", err, output, candidate.Bytes())
			}
		})
	}
}

func TestNodeRoutingConstantsMatchAcceptedComponentManifest(t *testing.T) {
	t.Parallel()
	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "v2", "COMPONENT_LIMITS.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Components struct {
			Mihomo struct {
				Version      string   `json:"version"`
				SHA256       string   `json:"sha256"`
				Capabilities []string `json:"capabilities"`
			} `json:"mihomo"`
		} `json:"components"`
		Limits struct {
			DNS struct {
				PolicyMode        string `json:"policy_mode"`
				CompatibilityMode string `json:"compatibility_mode"`
				LocalListener     string `json:"local_listener"`
				FakeIPSelected    bool   `json:"fake_ip_mode_selected"`
			} `json:"dns"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	capabilities := make(map[string]bool)
	for _, capability := range manifest.Components.Mihomo.Capabilities {
		capabilities[capability] = true
	}
	if manifest.Components.Mihomo.Version != NodeRoutingProviderVersion ||
		manifest.Components.Mihomo.SHA256 != NodeRoutingProviderSHA256 ||
		!capabilities["tun-routing"] || !capabilities["redir-host-split-dns"] ||
		manifest.Limits.DNS.PolicyMode != "policy-redir-host" ||
		manifest.Limits.DNS.CompatibilityMode != "direct-redir-host" ||
		manifest.Limits.DNS.LocalListener != NodeRoutingDNSListener || manifest.Limits.DNS.FakeIPSelected {
		t.Fatalf("node routing constants drifted from accepted manifest: %+v", manifest)
	}
}

func nodeRoutingRenderFixture(t *testing.T, mode RoutingDNSMode) NodeRoutingRenderRequest {
	t.Helper()
	ir, err := CompileMatcherIR(clashTestComposition(t))
	if err != nil {
		t.Fatal(err)
	}
	return NodeRoutingRenderRequest{
		Matcher: ir, PolicyGeneration: 9, DNSMode: mode,
		DirectDNSServers: []string{"192.0.2.53", "198.51.100.53"}, GatewayDNSIPv4: "10.67.0.1",
		Component: model.ComponentPin{
			Name: NodeRoutingProviderName, Version: NodeRoutingProviderVersion, Source: "bundle", Bundled: true,
			SHA256: NodeRoutingProviderSHA256, Capabilities: []string{
				"tun-routing", "redir-host-split-dns", "shadowsocks-2022-blake3-aes-256-gcm", "shadowtls-v3-strict", "uot-v2",
			},
		},
	}
}

func nodeRoutingStandardBinding() NodeRoutingActiveOutbound {
	return NodeRoutingActiveOutbound{
		Kind: model.TransportStandard, CredentialGeneration: 7,
		GatewayPublicIPv4: "203.0.113.44", GatewayOverlayIPv4: "10.67.0.1",
	}
}

func nodeRoutingRestrictedBinding(t *testing.T) NodeRoutingActiveOutbound {
	t.Helper()
	identity, err := restricted.EncodeSecret(restricted.IdentitySecret{
		SchemaVersion: restricted.SecretSchemaVersion, ShadowTLSPassword: strings.Repeat("61", restricted.SymmetricKeyByteCount),
	})
	if err != nil {
		t.Fatal(err)
	}
	return NodeRoutingActiveOutbound{
		Kind: model.TransportRestricted, CredentialGeneration: 7,
		GatewayPublicIPv4: "203.0.113.44", GatewayOverlayIPv4: "10.67.0.1",
		RestrictedServerPassword: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, restricted.SymmetricKeyByteCount)),
		RestrictedIdentitySecret: identity, RestrictedHandshakeHost: "www.cloudflare.com",
	}
}
