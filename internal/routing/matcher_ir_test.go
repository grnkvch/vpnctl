package routing

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestMatcherIRTargetsProduceEquivalentSelectedSets(t *testing.T) {
	t.Parallel()

	composition := clashTestComposition(t)
	ir, err := CompileMatcherIR(composition)
	if err != nil {
		t.Fatalf("CompileMatcherIR() error = %v", err)
	}
	node, err := CompileNodeRoutingMatchers(ir)
	if err != nil {
		t.Fatalf("CompileNodeRoutingMatchers() error = %v", err)
	}
	guard, err := CompileNFTablesLeakGuardMatchers(ir)
	if err != nil {
		t.Fatalf("CompileNFTablesLeakGuardMatchers() error = %v", err)
	}
	dns, err := CompileGatewayDNSMatchers(ir)
	if err != nil {
		t.Fatalf("CompileGatewayDNSMatchers() error = %v", err)
	}
	clash, err := CompileClashMatchers(ir)
	if err != nil {
		t.Fatalf("CompileClashMatchers() error = %v", err)
	}

	domains := []string{
		"example.com",
		"www.example.com",
		"other.private.example.com",
		"api.private.example.com",
		"sub.api.private.example.com",
		"unrelated.example.net",
	}
	for _, domain := range domains {
		want, err := composition.SelectsDomain(domain)
		if err != nil {
			t.Fatalf("composition.SelectsDomain(%q) error = %v", domain, err)
		}
		assertDomainDecision(t, "IR", domain, want, ir.SelectsDomain)
		assertDomainDecision(t, "node", domain, want, node.SelectsDomain)
		assertDomainDecision(t, "nftables-resolved", domain, want, guard.SelectsResolvedDomain)
		assertDomainDecision(t, "gateway-dns", domain, want, dns.SelectsDomain)
		assertDomainDecision(t, "Clash", domain, want, clash.SelectsDomain)
	}

	addresses := []string{
		"10.2.3.4",
		"10.1.3.4",
		"10.1.2.3",
		"11.1.2.3",
		"2001:db8:2::1",
		"2001:db8:1:3::1",
		"2001:db8:1:2::1",
		"2001:db9::1",
		"::ffff:10.1.2.3",
	}
	for _, value := range addresses {
		address := netip.MustParseAddr(value)
		want, err := composition.SelectsIP(address)
		if err != nil {
			t.Fatalf("composition.SelectsIP(%q) error = %v", value, err)
		}
		assertIPDecision(t, "IR", address, want, ir.SelectsIP)
		assertIPDecision(t, "node", address, want, node.SelectsIP)
		assertIPDecision(t, "nftables", address, want, guard.SelectsIP)
		assertIPDecision(t, "Clash", address, want, clash.SelectsIP)
	}

	if got := len(dns.domain); got == 0 {
		t.Fatal("gateway DNS projection unexpectedly contains no domain decisions")
	}
	if len(node.program.ipv4) == 0 || len(node.program.ipv6) == 0 ||
		len(guard.program.ipv4) == 0 || len(guard.program.ipv6) == 0 ||
		len(clash.program.ipv4) == 0 || len(clash.program.ipv6) == 0 {
		t.Fatal("IP-capable target projection omitted an address family")
	}
}

func TestMatcherIRIsVersionedCanonicalActionFreeAndDefensivelyOwned(t *testing.T) {
	t.Parallel()

	composition := clashTestComposition(t)
	ir, err := CompileMatcherIR(composition)
	if err != nil {
		t.Fatal(err)
	}
	if ir.SchemaVersion != MatcherIRSchemaVersion || len(ir.Clauses) != 2 || ir.Clauses[0].Name != "alpha" || ir.Clauses[1].Name != "beta" {
		t.Fatalf("compiled matcher IR is not canonical: %#v", ir)
	}
	encoded, err := json.Marshal(ir)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"action"`, `"outbound"`, `"selected"`, `"direct"`, "VPNCTL-GATEWAY"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("matcher IR contains provider action %q: %s", forbidden, encoded)
		}
	}
	var decoded MatcherIR
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil || !reflect.DeepEqual(decoded, ir) {
		t.Fatalf("matcher IR JSON round trip = %#v, %v; want %#v", decoded, err, ir)
	}

	composition.Presets[0].Includes[0].Value = "mutated.example"
	if selected, err := ir.SelectsDomain("www.example.com"); err != nil || !selected {
		t.Fatalf("source mutation changed compiled IR: selected=%t err=%v", selected, err)
	}

	node, err := CompileNodeRoutingMatchers(ir)
	if err != nil {
		t.Fatal(err)
	}
	clash, err := CompileClashMatchers(ir)
	if err != nil {
		t.Fatal(err)
	}
	node.program.domain[0].Selected = !node.program.domain[0].Selected
	if selected, err := clash.SelectsDomain("api.private.example.com"); err != nil || !selected {
		t.Fatalf("one target mutated another target's rules: selected=%t err=%v", selected, err)
	}
}

func TestMatcherIRRejectsMalformedStateAndSupportsAllDirect(t *testing.T) {
	t.Parallel()

	emptyComposition, err := NormalizePresetComposition([]PresetAST{})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := CompileMatcherIR(emptyComposition)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Clauses == nil {
		t.Fatal("empty matcher IR lost its present clauses array")
	}
	for name, compile := range map[string]func(MatcherIR) error{
		"node": func(ir MatcherIR) error { _, err := CompileNodeRoutingMatchers(ir); return err },
		"nftables": func(ir MatcherIR) error {
			_, err := CompileNFTablesLeakGuardMatchers(ir)
			return err
		},
		"gateway DNS": func(ir MatcherIR) error { _, err := CompileGatewayDNSMatchers(ir); return err },
		"Clash":       func(ir MatcherIR) error { _, err := CompileClashMatchers(ir); return err },
	} {
		if err := compile(empty); err != nil {
			t.Fatalf("%s rejected all-direct IR: %v", name, err)
		}
	}
	if selected, err := empty.SelectsDomain("example.com"); err != nil || selected {
		t.Fatalf("empty IR domain decision = %t, %v", selected, err)
	}
	if _, err := (NodeRoutingMatchers{}).SelectsDomain("example.com"); err == nil {
		t.Fatal("zero-value node target silently classified traffic as direct")
	}
	if _, err := (NFTablesLeakGuardMatchers{}).SelectsIP(netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Fatal("zero-value nftables target silently classified traffic as direct")
	}
	if _, err := (GatewayDNSMatchers{}).SelectsDomain("example.com"); err == nil {
		t.Fatal("zero-value gateway DNS target silently classified traffic as direct")
	}
	if _, err := (ClashMatchers{}).SelectsIP(netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Fatal("zero-value Clash target silently classified traffic as direct")
	}

	valid, err := CompileMatcherIR(clashTestComposition(t))
	if err != nil {
		t.Fatal(err)
	}
	malformed := []MatcherIR{
		{SchemaVersion: MatcherIRSchemaVersion},
		{SchemaVersion: MatcherIRSchemaVersion + 1, Clauses: []MatcherClause{}},
		func() MatcherIR {
			candidate := cloneMatcherIR(valid)
			candidate.Clauses[0].Includes.IPv4CIDRs[0] = "2001:db8::/32"
			return candidate
		}(),
		func() MatcherIR {
			candidate := cloneMatcherIR(valid)
			candidate.Clauses[0].Includes.Domains = nil
			return candidate
		}(),
		func() MatcherIR {
			candidate := cloneMatcherIR(valid)
			candidate.Clauses[0], candidate.Clauses[1] = candidate.Clauses[1], candidate.Clauses[0]
			return candidate
		}(),
	}
	for index, candidate := range malformed {
		if err := candidate.Validate(); err == nil {
			t.Errorf("malformed matcher IR %d passed validation", index)
		}
		if _, err := CompileNodeRoutingMatchers(candidate); err == nil {
			t.Errorf("node compiler accepted malformed matcher IR %d", index)
		}
	}
	if _, err := valid.SelectsDomain("Example.com"); err == nil {
		t.Fatal("matcher accepted a non-canonical domain")
	}
	if _, err := valid.SelectsIP(netip.Addr{}); err == nil {
		t.Fatal("matcher accepted an invalid IP address")
	}
}

func assertDomainDecision(t *testing.T, target, domain string, want bool, classify func(string) (bool, error)) {
	t.Helper()
	got, err := classify(domain)
	if err != nil || got != want {
		t.Errorf("%s domain %q = %t, %v; want %t", target, domain, got, err, want)
	}
}

func assertIPDecision(t *testing.T, target string, address netip.Addr, want bool, classify func(netip.Addr) (bool, error)) {
	t.Helper()
	got, err := classify(address)
	if err != nil || got != want {
		t.Errorf("%s IP %s = %t, %v; want %t", target, address, got, err, want)
	}
}

func cloneMatcherIR(ir MatcherIR) MatcherIR {
	encoded, err := json.Marshal(ir)
	if err != nil {
		panic(err)
	}
	var cloned MatcherIR
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		panic(err)
	}
	return cloned
}
