package routing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	restrictedcodec "github.com/vgrinkevich/vpnctl/internal/restricted"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestClashProfileRendererCompilesPolicySplitDNSAndManualTransportAlternatives(t *testing.T) {
	t.Parallel()

	renderer, _, _, _ := newClashProfileRendererFixture(t)
	profile, err := renderer.Render(ClashProfileRequest{
		ClientReference: "IPHONE", GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	content := string(profile.Bytes())
	for _, expected := range []string{
		"mode: rule\n",
		"log-level: silent\n",
		"geo-auto-update: false\n",
		"  enhanced-mode: redir-host\n",
		"    - \"udp://1.1.1.1:53#DIRECT\"\n",
		"    \"api.private.example.com\":\n      - \"udp://10.66.0.1:53#VPNCTL-GATEWAY\"\n",
		"    \"example.com\":\n      - \"udp://1.1.1.1:53#DIRECT\"\n      - \"udp://8.8.8.8:53#DIRECT\"\n",
		"    \"+.private.example.com\":\n      - \"udp://1.1.1.1:53#DIRECT\"\n      - \"udp://8.8.8.8:53#DIRECT\"\n",
		"    \"+.example.com\":\n      - \"udp://10.66.0.1:53#VPNCTL-GATEWAY\"\n",
		"  - name: VPNCTL-STANDARD\n",
		"    type: wireguard\n",
		"    server: 198.211.99.116\n",
		"    port: 51820\n",
		"    ip: 10.66.0.2\n",
		"    private-key: \"" + v1CompatibleClientPrivateKey + "\"\n",
		"    public-key: \"" + v1CompatibleServerPublicKey + "\"\n",
		"    udp: true\n",
		"  - name: VPNCTL-RESTRICTED\n",
		"    type: ss\n",
		"    port: 8443\n",
		"    cipher: 2022-blake3-aes-256-gcm\n",
		"    password: \"" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32)) + "\"\n",
		"    ip-version: ipv4\n",
		"    udp-over-tcp: true\n",
		"    udp-over-tcp-version: 2\n",
		"    plugin: shadow-tls\n",
		"    client-fingerprint: chrome\n",
		"      host: \"www.microsoft.com\"\n",
		"      password: \"" + strings.Repeat("52", 32) + "\"\n",
		"      version: 3\n",
		"      strict-mode: true\n",
		"  - DOMAIN,api.private.example.com,VPNCTL-GATEWAY\n",
		"  - DOMAIN,example.com,DIRECT\n",
		"  - DOMAIN-SUFFIX,private.example.com,DIRECT\n",
		"  - DOMAIN-SUFFIX,example.com,VPNCTL-GATEWAY\n",
		"  - IP-CIDR,10.1.2.0/24,VPNCTL-GATEWAY\n",
		"  - IP-CIDR,10.1.0.0/16,DIRECT\n",
		"  - IP-CIDR,10.0.0.0/8,VPNCTL-GATEWAY\n",
		"  - IP-CIDR6,2001:db8:1:2::/64,VPNCTL-GATEWAY\n",
		"  - IP-CIDR6,2001:db8:1::/48,DIRECT\n",
		"  - IP-CIDR6,2001:db8::/32,VPNCTL-GATEWAY\n",
		"  - MATCH,DIRECT\n",
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("profile is missing %q:\n%s", expected, content)
		}
	}
	groupStart := strings.Index(content, "proxy-groups:\n")
	rulesStart := strings.Index(content, "\nrules:\n")
	if groupStart < 0 || rulesStart <= groupStart {
		t.Fatalf("profile group/rules layout is invalid:\n%s", content)
	}
	group := content[groupStart:rulesStart]
	if strings.Contains(group, "DIRECT") || strings.Contains(group, "fallback") || strings.Contains(group, "url-test") ||
		strings.Contains(group, "interval:") || strings.Contains(group, "tolerance:") {
		t.Fatalf("selected gateway group can fail direct or switch automatically:\n%s", group)
	}
	if got := strings.Count(group, "      - VPNCTL-STANDARD\n"); got != 1 {
		t.Fatalf("manual gateway group contains %d standard alternatives:\n%s", got, group)
	}
	if got := strings.Count(group, "      - VPNCTL-RESTRICTED\n"); got != 1 {
		t.Fatalf("manual gateway group contains %d restricted alternatives:\n%s", got, group)
	}
	if strings.Index(group, "      - VPNCTL-STANDARD\n") > strings.Index(group, "      - VPNCTL-RESTRICTED\n") {
		t.Fatalf("manual gateway group changed the compatibility default away from standard:\n%s", group)
	}
	if profile.ClientID != v1CompatibleClientID || profile.ClientName != "iphone" ||
		profile.SourceStateGeneration != 2 || profile.PolicyGeneration != 1 ||
		profile.CredentialGeneration != 1 || profile.DNSMode != ClashDNSPolicy {
		t.Fatalf("profile metadata = %#v", profile)
	}
	metadataJSON, err := json.Marshal(profile)
	metadata := string(metadataJSON)
	if err != nil || strings.Contains(metadata, v1CompatibleClientPrivateKey) ||
		strings.Contains(metadata, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))) ||
		strings.Contains(metadata, strings.Repeat("52", 32)) || strings.Contains(metadata, "content") {
		t.Fatalf("Clash profile metadata JSON exposed content: %s, %v", metadataJSON, err)
	}
	defensive := profile.Bytes()
	defensive[0] = 'X'
	if bytes.Equal(defensive, profile.Bytes()) {
		t.Fatal("ClashProfile.Bytes() exposed mutable secret-bearing storage")
	}
	repeated, err := renderer.Render(ClashProfileRequest{ClientReference: v1CompatibleClientID, GatewayPublicKey: v1CompatibleServerPublicKey})
	if err != nil || !reflect.DeepEqual(repeated, profile) {
		t.Fatalf("repeated Render() = %#v, %v; want deterministic %#v", repeated, err, profile)
	}
}

func TestClashProfileRendererSupportsDirectCompatibilityModeAndAllDirectPolicy(t *testing.T) {
	t.Parallel()

	renderer, stateStore, _, _ := newClashProfileRendererFixture(t)
	direct, err := renderer.Render(ClashProfileRequest{
		ClientReference: "iphone", GatewayPublicKey: v1CompatibleServerPublicKey,
		DNSMode: ClashDNSDirect, DirectDNSServers: []string{"9.9.9.9"},
	})
	if err != nil {
		t.Fatalf("Render(direct DNS) error = %v", err)
	}
	if direct.DNSMode != ClashDNSDirect || strings.Contains(string(direct.Bytes()), "nameserver-policy:") ||
		!strings.Contains(string(direct.Bytes()), "    - \"udp://9.9.9.9:53#DIRECT\"\n") ||
		!strings.Contains(string(direct.Bytes()), "DOMAIN-SUFFIX,example.com,VPNCTL-GATEWAY") {
		t.Fatalf("direct compatibility profile is invalid:\n%s", direct.Bytes())
	}

	state := loadPolicyState(t, stateStore)
	candidate := state
	candidate.Generation++
	candidate.Clients = append([]model.Client{}, state.Clients...)
	candidate.Clients[0].AssignedPresets = []string{}
	candidate.Policies = []model.Policy{}
	if err := stateStore.Save(state.Generation, candidate); err != nil {
		t.Fatalf("Save(all-direct policy) error = %v", err)
	}
	allDirect, err := renderer.Render(ClashProfileRequest{
		ClientReference: "iphone", GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatalf("Render(all-direct policy) error = %v", err)
	}
	content := string(allDirect.Bytes())
	rules := content[strings.Index(content, "rules:\n"):]
	if rules != "rules:\n  - MATCH,DIRECT\n" || strings.Contains(content, "nameserver-policy:") || allDirect.PolicyGeneration != 0 {
		t.Fatalf("empty explicit assignment was not all-direct:\n%s", content)
	}
}

func TestClashProfileRendererNeverChangesManualChoiceFromTransportHealth(t *testing.T) {
	t.Parallel()

	renderer, stateStore, secretStore, _ := newClashProfileRendererFixture(t)
	request := ClashProfileRequest{ClientReference: "iphone", GatewayPublicKey: v1CompatibleServerPublicKey}
	baseline, err := renderer.Render(request)
	if err != nil {
		t.Fatalf("Render(baseline) error = %v", err)
	}
	state := loadPolicyState(t, stateStore)
	state.Generation++
	state.Transports = append([]model.Transport(nil), state.Transports...)
	for index := range state.Transports {
		if state.Transports[index].OwnerKind == model.TargetClient && state.Transports[index].Kind == model.TransportStandard {
			state.Transports[index].State = model.TransportDegraded
		}
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("Validate(degraded active transport) error = %v", err)
	}
	degraded, err := NewClashProfileRenderer(&clientExportStaticStateStore{state: state}, secretStore)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := degraded.Render(request)
	if err != nil {
		t.Fatalf("Render(degraded active transport) error = %v", err)
	}
	if !bytes.Equal(profile.Bytes(), baseline.Bytes()) {
		t.Fatalf("passive health changed the user's manual transport choices:\nbaseline:\n%s\ndegraded:\n%s", baseline.Bytes(), profile.Bytes())
	}
	content := string(profile.Bytes())
	for _, forbidden := range []string{"fallback", "url-test", "load-balance", "health-check", "external-controller", "proxy-providers:"} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("manual-only profile contains %q:\n%s", forbidden, content)
		}
	}
}

func TestClashProfileRendererRequiresValidRestrictedMaterial(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*store.SecretStore, model.State) error{
		"missing identity": func(secrets *store.SecretStore, state model.State) error {
			transport, _ := findClientRestrictedTransport(state.Transports, v1CompatibleClientID)
			_, err := secrets.Delete(transport.CredentialRef)
			return err
		},
		"missing gateway": func(secrets *store.SecretStore, _ model.State) error {
			_, err := secrets.Delete(restrictedcodec.GatewayCredentialRef)
			return err
		},
		"malformed identity": func(secrets *store.SecretStore, state model.State) error {
			transport, _ := findClientRestrictedTransport(state.Transports, v1CompatibleClientID)
			if _, err := secrets.Delete(transport.CredentialRef); err != nil {
				return err
			}
			return secrets.PutIfAbsent(transport.CredentialRef, []byte("{}\n"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			renderer, stateStore, secrets, _ := newClashProfileRendererFixture(t)
			state := loadPolicyState(t, stateStore)
			if err := mutate(secrets, state); err != nil {
				t.Fatal(err)
			}
			if _, err := renderer.Render(ClashProfileRequest{ClientReference: "iphone", GatewayPublicKey: v1CompatibleServerPublicKey}); err == nil {
				t.Fatalf("Render(%s) succeeded", name)
			}
		})
	}
}

func TestClashRuleCompilerPreservesPresetExclusionsAndCrossPresetReselection(t *testing.T) {
	t.Parallel()

	composition := clashTestComposition(t)
	rules, err := compileClashRules(composition)
	if err != nil {
		t.Fatalf("compileClashRules() error = %v", err)
	}
	domainCases := map[string]bool{
		"example.com": false, "www.example.com": true, "other.private.example.com": false,
		"api.private.example.com": true, "unmatched.test": false,
	}
	for domain, want := range domainCases {
		if got := clashRulesSelectDomain(rules, domain); got != want {
			t.Errorf("rendered rules select domain %q = %t, want %t", domain, got, want)
		}
	}
	ipCases := map[string]bool{
		"10.2.3.4": true, "10.1.3.4": false, "10.1.2.3": true, "11.0.0.1": false,
		"2001:db8:2::1": true, "2001:db8:1:3::1": false, "2001:db8:1:2::1": true,
	}
	for address, want := range ipCases {
		if got := clashRulesSelectIP(rules, address); got != want {
			t.Errorf("rendered rules select IP %q = %t, want %t", address, got, want)
		}
	}

	covered := mustNormalizePresetDocument(t, PresetDocument{
		SchemaVersion: PresetDocumentSchemaVersion, Name: "covered",
		Include: []PresetDocumentSelector{{Type: model.SelectorIPCIDR, Value: "10.0.0.0/8"}},
		Exclude: []PresetDocumentSelector{
			{Type: model.SelectorIPCIDR, Value: "10.0.0.0/9"},
			{Type: model.SelectorIPCIDR, Value: "10.128.0.0/9"},
		},
	})
	coveredComposition, err := NormalizePresetComposition([]PresetAST{covered})
	if err != nil {
		t.Fatal(err)
	}
	coveredRules, err := compileClashRules(coveredComposition)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range coveredRules {
		if rule.Value == "10.0.0.0/8" {
			t.Fatalf("fully shadowed parent prefix was emitted with an arbitrary action: %#v", coveredRules)
		}
	}
}

func TestClashProfileRendererRejectsWeakOrInconsistentInputs(t *testing.T) {
	t.Parallel()

	if _, err := NewClashProfileRenderer(nil, nil); err == nil {
		t.Fatal("NewClashProfileRenderer(nil, nil) succeeded")
	}
	var nilRenderer *ClashProfileRenderer
	if _, err := nilRenderer.Render(ClashProfileRequest{}); err == nil {
		t.Fatal("nil Render() succeeded")
	}
	renderer, stateStore, _, _ := newClashProfileRendererFixture(t)
	base := ClashProfileRequest{ClientReference: "iphone", GatewayPublicKey: v1CompatibleServerPublicKey}
	for name, mutate := range map[string]func(*ClashProfileRequest){
		"unknown DNS mode": func(request *ClashProfileRequest) { request.DNSMode = "automatic" },
		"empty direct DNS": func(request *ClashProfileRequest) { request.DirectDNSServers = []string{} },
		"IPv6 direct DNS":  func(request *ClashProfileRequest) { request.DirectDNSServers = []string{"2001:db8::1"} },
		"duplicate DNS":    func(request *ClashProfileRequest) { request.DirectDNSServers = []string{"1.1.1.1", "1.1.1.1"} },
		"invalid key":      func(request *ClashProfileRequest) { request.GatewayPublicKey = "not-a-key" },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if _, err := renderer.Render(request); err == nil {
				t.Fatalf("Render(%s) succeeded", name)
			}
		})
	}

	state := loadPolicyState(t, stateStore)
	candidate := state
	candidate.Generation++
	candidate.Policies = append([]model.Policy{}, state.Policies...)
	candidate.Policies[0].Generation++
	candidate.Policies[0].EffectiveHash = strings.Repeat("f", 64)
	if err := stateStore.Save(state.Generation, candidate); err != nil {
		t.Fatalf("Save(inconsistent policy) error = %v", err)
	}
	if _, err := renderer.Render(base); err == nil || !strings.Contains(err.Error(), "does not match its active preset generations") {
		t.Fatalf("Render(inconsistent policy) error = %v", err)
	}
}

// This test is opt-in because the exact pinned binary is a Linux/amd64 release
// artifact. The task-7.9 and task-8.10 acceptance runs cross-compile this
// package's test binary for the disposable Ubuntu fixture and supply
// VPNCTL_PINNED_MIHOMO.
func TestClashProfileParsesWithPinnedMihomo(t *testing.T) {
	binary := os.Getenv("VPNCTL_PINNED_MIHOMO")
	if binary == "" {
		t.Skip("set VPNCTL_PINNED_MIHOMO to the v1.19.30 Linux/amd64 binary")
	}
	version, err := exec.Command(binary, "-v").CombinedOutput()
	if err != nil {
		t.Fatalf("read pinned Mihomo version: %v: %s", err, version)
	}
	if !strings.Contains(string(version), "v1.19.30") {
		t.Fatalf("Mihomo version is not pinned v1.19.30: %s", version)
	}
	renderer, _, _, _ := newClashProfileRendererFixture(t)
	profile, err := renderer.Render(ClashProfileRequest{
		ClientReference: "iphone", GatewayPublicKey: v1CompatibleServerPublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "iphone.clash.yaml")
	if err := os.WriteFile(path, profile.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(binary, "-t", "-d", directory, "-f", path).CombinedOutput()
	if err != nil {
		t.Fatalf("pinned Mihomo rejected rendered profile: %v:\n%s\nprofile:\n%s", err, output, profile.Bytes())
	}
}

func newClashProfileRendererFixture(t *testing.T) (*ClashProfileRenderer, *store.StateStore, *store.SecretStore, PresetComposition) {
	t.Helper()
	_, stateStore, secretStore, _ := newGoldenWireGuardRenderer(t)
	state := loadPolicyState(t, stateStore)
	composition := clashTestComposition(t)
	presets := make([]model.Preset, 0, len(composition.Presets))
	for _, selection := range composition.Presets {
		selectors := append(append([]model.Selector{}, selection.Includes...), selection.Excludes...)
		presets = append(presets, catalogEffectivePreset(selection.Name, []byte(selection.Name+"-source"), canonicalPresetSelectors(selectors)))
	}
	presetMap := make(map[string]model.Preset, len(presets))
	for _, preset := range presets {
		presetMap[strings.ToLower(preset.Name)] = preset
	}
	names := []string{"alpha", "beta"}
	selectors, effectiveHash, err := effectivePolicy(names, presetMap)
	if err != nil {
		t.Fatal(err)
	}
	candidate := state
	candidate.Generation = 2
	candidate.Presets = presets
	candidate.Clients = append([]model.Client{}, state.Clients...)
	candidate.Clients[0].AssignedPresets = names
	candidate.Policies = []model.Policy{{
		SchemaVersion: model.ResourceSchemaVersion, TargetKind: model.TargetClient, TargetID: v1CompatibleClientID,
		PresetNames: names, Selectors: selectors, EffectiveHash: effectiveHash, Generation: 1,
	}}
	restrictedReference, err := clientRestrictedCredentialReference(v1CompatibleClientID, 1)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Transports = append(append([]model.Transport(nil), state.Transports...), model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetClient, OwnerID: v1CompatibleClientID,
		Kind: model.TransportRestricted, State: model.TransportStandby, Provider: "mihomo", Protocol: model.ProtocolTCP,
		Port: 8443, CredentialGeneration: 1, CredentialRef: restrictedReference,
		HandshakeHost: candidate.HandshakeHost.Hostname,
		ConfigHash:    clientRestrictedTransportHash(v1CompatibleClientID, 1, restrictedReference),
	})
	putGatewayRestrictedTestSecret(t, secretStore)
	putRestrictedIdentityTestSecret(t, secretStore, restrictedReference, 0x52)
	if err := stateStore.Save(state.Generation, candidate); err != nil {
		t.Fatalf("Save(Clash fixture state) error = %v", err)
	}
	renderer, err := NewClashProfileRenderer(stateStore, secretStore)
	if err != nil {
		t.Fatal(err)
	}
	return renderer, stateStore, secretStore, composition
}

func clashTestComposition(t *testing.T) PresetComposition {
	t.Helper()
	alpha := mustNormalizePresetDocument(t, PresetDocument{
		SchemaVersion: PresetDocumentSchemaVersion, Name: "alpha",
		Include: []PresetDocumentSelector{
			{Type: model.SelectorDomainSuffix, Value: "example.com"},
			{Type: model.SelectorIPCIDR, Value: "10.0.0.0/8"},
			{Type: model.SelectorIPCIDR, Value: "2001:db8::/32"},
		},
		Exclude: []PresetDocumentSelector{
			{Type: model.SelectorDomain, Value: "example.com"},
			{Type: model.SelectorDomainSuffix, Value: "private.example.com"},
			{Type: model.SelectorIPCIDR, Value: "10.1.0.0/16"},
			{Type: model.SelectorIPCIDR, Value: "2001:db8:1::/48"},
		},
	})
	beta := mustNormalizePresetDocument(t, PresetDocument{
		SchemaVersion: PresetDocumentSchemaVersion, Name: "beta",
		Include: []PresetDocumentSelector{
			{Type: model.SelectorDomain, Value: "api.private.example.com"},
			{Type: model.SelectorIPCIDR, Value: "10.1.2.0/24"},
			{Type: model.SelectorIPCIDR, Value: "2001:db8:1:2::/64"},
		},
		Exclude: []PresetDocumentSelector{},
	})
	composition, err := NormalizePresetComposition([]PresetAST{beta, alpha})
	if err != nil {
		t.Fatal(err)
	}
	return composition
}

func clashRulesSelectDomain(rules []clashRule, domain string) bool {
	for _, rule := range rules {
		switch rule.Kind {
		case model.SelectorDomain:
			if domain == rule.Value {
				return rule.Selected
			}
		case model.SelectorDomainSuffix:
			if domain == rule.Value || strings.HasSuffix(domain, "."+rule.Value) {
				return rule.Selected
			}
		}
	}
	return false
}

func clashRulesSelectIP(rules []clashRule, value string) bool {
	address := netipMustParseAddr(value)
	for _, rule := range rules {
		if rule.Kind == model.SelectorIPCIDR && netipMustParsePrefix(rule.Value).Contains(address) {
			return rule.Selected
		}
	}
	return false
}

func netipMustParseAddr(value string) netip.Addr {
	return netip.MustParseAddr(value)
}

func netipMustParsePrefix(value string) netip.Prefix {
	return netip.MustParsePrefix(value)
}
