package regression

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestV2GatewayFirewallNamespaceContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	rules := readContractFile(t, filepath.Join(repositoryRoot, "internal", "platform", "linux", "testdata", "firewall", "gateway.nft"))
	minimalRules := readContractFile(t, filepath.Join(repositoryRoot, "internal", "platform", "linux", "testdata", "firewall", "gateway-minimal.nft"))
	for _, required := range []string{
		"table inet vpnctl", "type filter hook input priority filter; policy drop;",
		"ip saddr 0.0.0.0/0 tcp dport { 443, 2222, 8443 } accept",
		"ip saddr 0.0.0.0/0 udp dport 51820 accept",
		"ip saddr @client_v4 tcp dport @client_tcp_ports accept",
		"ip saddr @node_v4 tcp dport @node_tcp_ports accept",
		"type filter hook forward priority filter; policy drop;",
		"ip saddr @client_v4 ip daddr @client_v4 drop",
		"ip saddr @client_v4 ip daddr @node_v4 drop",
		"ip saddr @node_v4 ip daddr @client_v4 drop",
		"ip saddr @node_v4 ip daddr @node_v4 drop",
		"ip daddr @blocked_egress_v4 drop", "ip saddr @overlay_v4 masquerade",
	} {
		if !strings.Contains(rules, required) {
			t.Errorf("gateway firewall golden is missing %q", required)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "udp dport 443", "udp dport 8443", "policy accept;\n\n    ct state invalid drop"} {
		if strings.Contains(rules, forbidden) || strings.Contains(minimalRules, forbidden) {
			t.Errorf("gateway firewall golden contains forbidden behavior %q", forbidden)
		}
	}

	namespaceHarness := readContractFile(t, filepath.Join(repositoryRoot, "test", "v2lab", "firewall", "namespace.sh"))
	for _, required := range []string{
		"vpnctl-v2-fw-gateway", "vpnctl-v2-fw-overlay", "vpnctl-v2-fw-wan", "vpnctl-v2-fw-victim",
		"trap cleanup EXIT INT TERM", "nft --check --file \"$minimal_rules_path\"", "table inet foreign_keep",
		"delete table inet vpnctl", "cmp -s \"$foreign_before\" \"$foreign_after\"",
		"blocked \"$wan_ns\" udp 192.0.2.1 443", "blocked \"$wan_ns\" udp 192.0.2.1 8443",
		"blocked \"$wan_ns\" tcp 192.0.2.1 17000", "blocked \"$wan_ns\" tcp 192.0.2.1 53",
		"internal-control --bind 10.67.0.2", "9443 --bind 10.66.0.2",
		"blocked \"$overlay_ns\" tcp 169.254.50.2 18081",
		"blocked \"$overlay_ns\" tcp 10.66.0.3 18082 --bind 10.66.0.2",
		"blocked \"$overlay_ns\" tcp 10.67.0.3 18082 --bind 10.67.0.2",
		"blocked \"$wan_ns\" tcp 2001:db8:100::1 443",
		"blocked \"$overlay_ns\" tcp 2001:db8:100::2 18080",
	} {
		if !strings.Contains(namespaceHarness, required) {
			t.Errorf("firewall namespace harness is missing %q", required)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2firewall-test.sh"))
	for _, required := range []string{
		"assert_lab_instance", "assert_spikes_inactive", "vpnctl-v2-firewall-test-v1",
		"assert_owned_runtime", "refusing to operate on unowned firewall test runtime",
		"refusing to delete firewall namespaces without the owned runtime marker",
		"trap cleanup EXIT INT TERM", "go test ./internal/platform/linux",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("firewall test orchestrator is missing %q", required)
		}
	}
	for _, forbidden := range []string{"journalctl", "flush ruleset", "rm -rf /etc", "rm -rf /run", "rm -rf -- /tmp"} {
		if strings.Contains(namespaceHarness, forbidden) || strings.Contains(orchestrator, forbidden) {
			t.Errorf("firewall test contains unsafe logging/deletion surface %q", forbidden)
		}
	}

	journal := readContractFile(t, filepath.Join(repositoryRoot, "docs", "v2", "HOST_CHANGELOG.md"))
	for _, required := range []string{
		"production gateway firewall renderer namespace gate",
		"vpnctl-v2-firewall-test-v1", "all four namespaces and runtime absent",
	} {
		if !strings.Contains(journal, required) {
			t.Errorf("host changelog is missing firewall gate evidence %q", required)
		}
	}
}
