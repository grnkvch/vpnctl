package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2DNSSpikeContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "dns")
	manifestData := readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))
	var manifest struct {
		Status string `json:"status"`
		Mihomo struct {
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
		} `json:"mihomo"`
		Systemd struct {
			VersionPrefix    string `json:"version_prefix"`
			ResolvedDropin   string `json:"resolved_dropin"`
			ManagedServer    string `json:"managed_server"`
			ManagedDomain    string `json:"managed_domain"`
			UnderlayHoldName string `json:"underlay_hold_domain"`
		} `json:"systemd"`
		Policy struct {
			SelectedSuffix     string `json:"selected_suffix"`
			DirectSuffix       string `json:"direct_suffix"`
			FakeIPRange        string `json:"fake_ip_range"`
			RejectedDefault    string `json:"rejected_default_fake_ip_range"`
			DirectAnswer       string `json:"direct_answer"`
			GatewayAnswer      string `json:"gateway_answer"`
			UpstreamTTLSeconds int    `json:"upstream_ttl_seconds"`
			FakeIPTTLSeconds   int    `json:"fake_ip_ttl_seconds"`
			AcceptedMode       string `json:"accepted_mode"`
		} `json:"policy"`
		NFTables struct {
			Family         string `json:"family"`
			Table          string `json:"table"`
			OutputPriority int    `json:"output_priority"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(manifestData), &manifest); err != nil {
		t.Fatalf("decode DNS spike manifest: %v", err)
	}
	if manifest.Status != "spike-only" || manifest.Mihomo.Version != "v1.19.30" || len(manifest.Mihomo.SHA256) != 64 {
		t.Fatalf("unexpected DNS provider candidate: %+v", manifest.Mihomo)
	}
	if manifest.Systemd.VersionPrefix != "255" || manifest.Systemd.ManagedServer != "127.0.0.1:1053" ||
		manifest.Systemd.ManagedDomain != "~." || manifest.Systemd.ResolvedDropin != "/etc/systemd/resolved.conf.d/vpnctl-v2-dns-spike.conf" ||
		manifest.Systemd.UnderlayHoldName != "~vpnctl-v2-underlay.invalid" {
		t.Fatalf("unexpected systemd-resolved contract: %+v", manifest.Systemd)
	}
	if manifest.Policy.SelectedSuffix != "selected.test" || manifest.Policy.DirectSuffix != "direct.test" ||
		manifest.Policy.FakeIPRange != "198.19.0.1/16" || manifest.Policy.RejectedDefault != "198.18.0.1/16" ||
		manifest.Policy.DirectAnswer != "192.0.2.77" || manifest.Policy.GatewayAnswer != "203.0.113.77" ||
		manifest.Policy.UpstreamTTLSeconds != 2 || manifest.Policy.FakeIPTTLSeconds != 2 ||
		manifest.Policy.AcceptedMode != "policy-redir-host" {
		t.Fatalf("unexpected DNS mode candidate: %+v", manifest.Policy)
	}
	if manifest.NFTables.Family != "inet" || manifest.NFTables.Table != "vpnctl_v2_spike_dns" || manifest.NFTables.OutputPriority != -100 {
		t.Fatalf("unexpected DNS nftables contract: %+v", manifest.NFTables)
	}

	fakeConfig := readContractFile(t, filepath.Join(fixtureRoot, "config", "policy-fake-ip.yaml"))
	for _, required := range []string{
		"log-level: silent", "listen: 127.0.0.1:1053", "enhanced-mode: fake-ip",
		"fake-ip-range: 198.19.0.1/16", "fake-ip-filter-mode: whitelist", `"+.selected.test"`,
		`"udp://10.211.0.1:53"`, `"+.selected.test": "udp://10.212.0.1:53"`,
		"use-system-hosts: false", "DOMAIN-SUFFIX,selected.test,GATEWAY-DNS", "MATCH,DIRECT",
	} {
		if !strings.Contains(fakeConfig, required) {
			t.Errorf("policy fake-IP config is missing %q", required)
		}
	}
	redirConfig := readContractFile(t, filepath.Join(fixtureRoot, "config", "policy-redir-host.yaml"))
	directConfig := readContractFile(t, filepath.Join(fixtureRoot, "config", "direct-redir-host.yaml"))
	if !strings.Contains(redirConfig, "enhanced-mode: redir-host") || !strings.Contains(redirConfig, "nameserver-policy:") {
		t.Error("policy redir-host candidate lacks split upstream policy")
	}
	if !strings.Contains(directConfig, "enhanced-mode: redir-host") || strings.Contains(directConfig, "nameserver-policy:") {
		t.Error("direct compatibility candidate must use only direct redir-host DNS")
	}
	for name, contents := range map[string]string{"fake": fakeConfig, "redir": redirConfig, "direct": directConfig} {
		for _, forbidden := range []string{"fallback:", "\n    - system", "log-level: info", "198.18.0.1/16"} {
			if strings.Contains(contents, forbidden) {
				t.Errorf("%s DNS config contains forbidden fallback/conflict surface %q", name, forbidden)
			}
		}
	}

	resolved := readContractFile(t, filepath.Join(fixtureRoot, "resolved.conf"))
	for _, required := range []string{"DNS=127.0.0.1:1053", "FallbackDNS=", "Domains=~.", "Cache=no"} {
		if !strings.Contains(resolved, required) {
			t.Errorf("resolved drop-in fixture is missing %q", required)
		}
	}
	capture := readContractFile(t, filepath.Join(fixtureRoot, "capture.nft.tmpl"))
	for _, required := range []string{
		"table inet vpnctl_v2_spike_dns", "type nat hook output priority dstnat",
		"meta skuid @DNS_UID@", "ip daddr 127.0.0.0/8 udp dport 53",
		"udp dport 53 counter name classic_udp_captured redirect to :1053",
		"tcp dport 53 counter name classic_tcp_captured redirect to :1053",
	} {
		if !strings.Contains(capture, required) {
			t.Errorf("classic DNS capture fixture is missing %q", required)
		}
	}

	policy := readContractFile(t, filepath.Join(fixtureRoot, "policy.sh"))
	for _, required := range []string{
		"ORIGINAL_DNS", "ORIGINAL_DOMAINS", "ORIGINAL_DEFAULT_ROUTE", "nft -c -f",
		"systemctl restart systemd-resolved.service", "resolvectl domain \"$link_name\" \"$hold_domain\"",
		"restore_link_values", "nft delete table inet \"$table_name\"", "assert_clean",
	} {
		if !strings.Contains(policy, required) {
			t.Errorf("DNS integration policy is missing %q", required)
		}
	}

	resolverUnit := readContractFile(t, filepath.Join(fixtureRoot, "systemd", "vpnctl-v2-spike-dns-resolver.service"))
	for _, required := range []string{
		"Wants=vpnctl-v2-spike-dns-direct.service vpnctl-v2-spike-dns-gateway.service",
		"User=vpnctl-v2-dns-spike", "StandardOutput=null", "StandardError=null", "MemoryMax=96M",
	} {
		if !strings.Contains(resolverUnit, required) {
			t.Errorf("DNS resolver unit is missing %q", required)
		}
	}
	if strings.Contains(resolverUnit, "Requires=vpnctl-v2-spike-dns-gateway.service") {
		t.Error("local resolver must survive a shared gateway DNS outage")
	}
	for _, unit := range []string{"vpnctl-v2-spike-dns-direct.service", "vpnctl-v2-spike-dns-gateway.service"} {
		contents := readContractFile(t, filepath.Join(fixtureRoot, "systemd", unit))
		if !strings.Contains(contents, "StandardOutput=null") || !strings.Contains(contents, "StandardError=null") || !strings.Contains(contents, "MemoryMax=32M") {
			t.Errorf("DNS upstream fixture unit %s lacks no-log/resource bounds", unit)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2dns-spike.sh"))
	for _, required := range []string{
		"assert_lab_instance", "assert_other_spikes_inactive", "assert_owned_or_absent",
		"refusing to overwrite unowned DNS spike path", "root_network_snapshot", "node_policy apply",
		"expect_dns_blocked", "classic_udp_captured", "switch_mode direct-redir-host",
		"assert_fake_ip_candidate_behavior", "selected_stale_while_revalidate",
		"selected_direct_fallback_queries", "resolver-loss-fail-closed", "resolver-loss-recovery",
		"upstream_bypass_queries", "task_16_11", "uninstall_internal true", "remove_dns_user",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("DNS spike orchestrator is missing %q", required)
		}
	}
}
