package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2RoutingSpikeContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "routing")
	manifestData := readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))
	var manifest struct {
		Status string `json:"status"`
		Mihomo struct {
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
		} `json:"mihomo"`
		Marks struct {
			Mask            string `json:"mask"`
			Direct          string `json:"direct"`
			Selected        string `json:"selected"`
			Recovery        string `json:"recovery"`
			IngressResponse string `json:"ingress_response"`
			PreservedMask   string `json:"preserved_mask"`
		} `json:"marks"`
		Routing struct {
			RecoveryPriority int `json:"recovery_rule_priority"`
			IngressPriority  int `json:"ingress_rule_priority"`
			SelectedPriority int `json:"selected_rule_priority"`
			SelectedTable    int `json:"selected_table"`
			GatewayTable     int `json:"gateway_table"`
			Unreachable      int `json:"unreachable_metric"`
			TUN              int `json:"tun_metric"`
		} `json:"routing"`
		NFTables struct {
			Family             string `json:"family"`
			Table              string `json:"table"`
			PreroutingPriority int    `json:"prerouting_priority"`
			OutputPriority     int    `json:"output_priority"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(manifestData), &manifest); err != nil {
		t.Fatalf("decode routing spike manifest: %v", err)
	}
	if manifest.Status != "spike-only" || manifest.Mihomo.Version != "v1.19.30" || len(manifest.Mihomo.SHA256) != 64 {
		t.Fatalf("unexpected routing provider candidate: %+v", manifest.Mihomo)
	}
	if manifest.Marks.Mask != "0xff000000" || manifest.Marks.Direct != "0x01000000" ||
		manifest.Marks.Selected != "0x02000000" || manifest.Marks.Recovery != "0x03000000" ||
		manifest.Marks.IngressResponse != "0x04000000" || manifest.Marks.PreservedMask != "0x00ffffff" {
		t.Fatalf("unexpected routing mark allocation: %+v", manifest.Marks)
	}
	if manifest.Routing.RecoveryPriority != 10000 || manifest.Routing.IngressPriority != 10010 ||
		manifest.Routing.SelectedPriority != 10020 || manifest.Routing.SelectedTable != 20001 ||
		manifest.Routing.GatewayTable != 20002 || manifest.Routing.Unreachable != 42760 || manifest.Routing.TUN != 10 {
		t.Fatalf("unexpected routing policy allocation: %+v", manifest.Routing)
	}
	if manifest.NFTables.Family != "inet" || manifest.NFTables.Table != "vpnctl_v2_spike_routing" ||
		manifest.NFTables.PreroutingPriority != -150 || manifest.NFTables.OutputPriority != -150 {
		t.Fatalf("unexpected nftables allocation: %+v", manifest.NFTables)
	}

	nftables := readContractFile(t, filepath.Join(fixtureRoot, "base.nft"))
	for _, required := range []string{
		"table inet vpnctl_v2_spike_routing", "type filter hook prerouting priority mangle",
		"type route hook output priority mangle", "ct mark & 0xff000000 == 0x01000000",
		"meta mark set ct mark", "ct mark set meta mark",
		"iifname \"v2gateway0\" ct state new tcp dport 18082", "jump readiness",
		"ct state established,related meta mark & 0xff000000 == 0x01000000",
		"ip6 daddr @selected_v6 counter name selected_ipv6_drop drop",
		"counter name not_ready_drop drop", "counter name foreign_bits_preserved",
	} {
		if !strings.Contains(nftables, required) {
			t.Errorf("routing nftables fixture is missing %q", required)
		}
	}

	policy := readContractFile(t, filepath.Join(fixtureRoot, "policy.sh"))
	for _, required := range []string{
		"assert_no_mark_overlap", "ip route add unreachable default metric 42760 table \"$selected_table\"",
		"ip rule add priority 10000 fwmark \"$recovery_mark/$mark_mask\" table \"$gateway_table\"",
		"ip rule add priority 10010 fwmark \"$ingress_mark/$mark_mask\" table \"$gateway_table\"",
		"ip rule add priority 10020 fwmark \"$selected_mark/$mark_mask\" table \"$selected_table\"",
		"ip route replace default dev v2tun0 metric 10 table \"$selected_table\"",
		"flush chain inet $table_name readiness", "add rule inet $table_name readiness jump $target",
		"restore_sysctls", "routes_for_table", "nft delete table inet \"$table_name\"",
	} {
		if !strings.Contains(policy, required) {
			t.Errorf("routing policy fixture is missing %q", required)
		}
	}

	mihomo := readContractFile(t, filepath.Join(fixtureRoot, "mihomo.yaml"))
	for _, required := range []string{
		"log-level: silent", "device: v2tun0", "auto-route: false", "interface-name: v2gateway0", "routing-mark: 50331648",
	} {
		if !strings.Contains(mihomo, required) {
			t.Errorf("routing Mihomo fixture is missing %q", required)
		}
	}

	guardUnit := readContractFile(t, filepath.Join(fixtureRoot, "systemd", "vpnctl-v2-spike-routing-guard.service"))
	engineUnit := readContractFile(t, filepath.Join(fixtureRoot, "systemd", "vpnctl-v2-spike-routing-engine.service"))
	for _, required := range []string{"Type=oneshot", "ExecStart=/usr/local/libexec/vpnctl-v2-spike-routing/policy guard", "RemainAfterExit=yes"} {
		if !strings.Contains(guardUnit, required) {
			t.Errorf("routing guard unit is missing %q", required)
		}
	}
	for _, required := range []string{
		"Requires=vpnctl-v2-spike-routing-guard.service", "ExecStartPre=/usr/local/libexec/vpnctl-v2-spike-routing/policy not-ready",
		"ExecStartPost=/usr/local/libexec/vpnctl-v2-spike-routing/policy wait-ready",
		"ExecStopPost=/usr/local/libexec/vpnctl-v2-spike-routing/policy not-ready", "Restart=on-failure",
		"DeviceAllow=/dev/net/tun rw", "MemoryMax=128M",
	} {
		if !strings.Contains(engineUnit, required) {
			t.Errorf("routing engine unit is missing %q", required)
		}
	}
	for _, unit := range []string{
		"vpnctl-v2-spike-routing-guard.service", "vpnctl-v2-spike-routing-engine.service",
		"vpnctl-v2-spike-routing-direct.service", "vpnctl-v2-spike-routing-gateway.service",
		"vpnctl-v2-spike-routing-node.service",
	} {
		contents := readContractFile(t, filepath.Join(fixtureRoot, "systemd", unit))
		if !strings.Contains(contents, "StandardOutput=null") || !strings.Contains(contents, "StandardError=null") {
			t.Errorf("routing unit %s does not enforce the no-log default", unit)
		}
	}

	fault := readContractFile(t, filepath.Join(fixtureRoot, "fault.sh"))
	for _, required := range []string{
		"systemctl kill --kill-who=main --signal=KILL", "established_direct_retained",
		"--protocol tcp --host 203.0.113.10", "--protocol udp --host 203.0.113.10",
		"--protocol udp --host 2001:db8:1::10", "forbidden == 0",
		"systemctl stop \"$gateway_unit\"", "table inet $transport_outage_table",
		"oifname \"v2gateway0\" drop", "assert_selected_path_failure",
		"request tcp 203.0.113.20 18080 direct-unmatched", "request udp 203.0.113.20 18080 direct-unmatched",
		"active_transport_preserved: true", "automatic_fallback: false", "recovered_without_engine_restart: true",
	} {
		if !strings.Contains(fault, required) {
			t.Errorf("routing fault fixture is missing %q", required)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2routing-spike.sh"))
	for _, required := range []string{
		"assert_lab_instance", "assert_other_spikes_inactive", "assert_owned_or_absent",
		"refusing to overwrite unowned routing spike path", "node_policy guard after-nft",
		"node_policy assert-clean", "root_network_snapshot", "foreign_snapshot",
		"gateway-outage", "transport-outage", "outages: {gateway: $gateway_outage[0], transport: $transport_outage[0]}",
		"trap 'clean_runtime_best_effort' EXIT", "uninstall_internal true", "owner-checked routing spike resources removed",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("routing spike orchestrator is missing %q", required)
		}
	}
	for _, forbidden := range []string{"log-level: info", "journalctl", "rm -rf /etc", "rm -rf /run"} {
		if strings.Contains(orchestrator, forbidden) {
			t.Errorf("routing spike orchestrator contains unsafe logging/deletion surface %q", forbidden)
		}
	}
}
