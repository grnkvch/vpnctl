package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2NodeTransportE2EContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "node-transport")
	var manifest struct {
		Status            string `json:"status"`
		Scope             string `json:"scope"`
		ActualGatewayNode string `json:"actual_gateway_node"`
		ManualFlow        struct {
			ToRestricted   bool `json:"standard_to_restricted_test_switch"`
			ToStandard     bool `json:"restricted_to_standard_test_switch"`
			Deferred       bool `json:"deferred_without_local_apply"`
			FailedPreserve bool `json:"failed_target_preserves_active"`
			AutoFallback   bool `json:"automatic_fallback"`
			OneActive      bool `json:"one_active_transport"`
		} `json:"manual_flow"`
		Standard struct {
			WireGuard         bool `json:"wireguard_udp_51820"`
			Selected          bool `json:"selected_tcp_udp_gateway"`
			ProbeGatewayOnly  bool `json:"probe_gateway_only"`
			ProbeMissingRoute bool `json:"probe_missing_route_blocked"`
		} `json:"standard"`
		Restricted struct {
			ShadowTLS bool `json:"shadowtls_tcp_8443"`
			TCP       bool `json:"selected_tcp"`
			UoT       bool `json:"selected_udp_over_tcp"`
			NativeUDP bool `json:"native_udp"`
		} `json:"restricted"`
		Routing struct {
			TCPFailClosed   bool `json:"selected_tcp_fail_closed"`
			UDPFailClosed   bool `json:"selected_udp_fail_closed"`
			TCPDirect       bool `json:"unrelated_tcp_direct"`
			UDPDirect       bool `json:"unrelated_udp_direct"`
			ActivePreserved bool `json:"active_transport_preserved"`
			AutoFallback    bool `json:"automatic_fallback"`
		} `json:"routing"`
		ReverseTunnel struct {
			StandardObserved   bool `json:"standard_path_observed"`
			RestrictedObserved bool `json:"restricted_path_observed"`
			IdentityPreserved  bool `json:"logical_identity_preserved"`
		} `json:"reverse_tunnel"`
		Cleanup struct {
			OwnerScoped     bool `json:"owner_scoped"`
			ResourcesAbsent bool `json:"temporary_resources_absent"`
			FixturesStopped bool `json:"fixtures_restored_stopped"`
		} `json:"cleanup"`
	}
	if err := json.Unmarshal([]byte(readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))), &manifest); err != nil {
		t.Fatalf("decode node-transport E2E manifest: %v", err)
	}
	if manifest.Status != "accepted" || manifest.Scope != "automated-linux-node" ||
		manifest.ActualGatewayNode != "deferred-to-task-16.11" {
		t.Fatalf("node-transport acceptance identity is incomplete: %+v", manifest)
	}
	if !manifest.ManualFlow.ToRestricted || !manifest.ManualFlow.ToStandard || !manifest.ManualFlow.Deferred ||
		!manifest.ManualFlow.FailedPreserve || manifest.ManualFlow.AutoFallback || !manifest.ManualFlow.OneActive {
		t.Fatalf("manual transport flow evidence = %+v", manifest.ManualFlow)
	}
	if !manifest.Standard.WireGuard || !manifest.Standard.Selected || !manifest.Standard.ProbeGatewayOnly ||
		!manifest.Standard.ProbeMissingRoute || !manifest.Restricted.ShadowTLS ||
		!manifest.Restricted.TCP || !manifest.Restricted.UoT || manifest.Restricted.NativeUDP {
		t.Fatalf("transport data-path evidence = standard=%+v restricted=%+v", manifest.Standard, manifest.Restricted)
	}
	if !manifest.Routing.TCPFailClosed || !manifest.Routing.UDPFailClosed || !manifest.Routing.TCPDirect ||
		!manifest.Routing.UDPDirect || !manifest.Routing.ActivePreserved || manifest.Routing.AutoFallback {
		t.Fatalf("routing evidence = %+v", manifest.Routing)
	}
	if !manifest.ReverseTunnel.StandardObserved || !manifest.ReverseTunnel.RestrictedObserved ||
		!manifest.ReverseTunnel.IdentityPreserved || !manifest.Cleanup.OwnerScoped ||
		!manifest.Cleanup.ResourcesAbsent || !manifest.Cleanup.FixturesStopped {
		t.Fatalf("switch/cleanup evidence = tunnel=%+v cleanup=%+v", manifest.ReverseTunnel, manifest.Cleanup)
	}

	sourceFlow := readContractFile(t, filepath.Join(repositoryRoot, "internal", "transport", "v2_manual_flow_test.go"))
	for _, required := range []string{
		"TestV2ManualTransportRoundTrip", "tester.Test(context.Background(), model.TransportRestricted)",
		"switcher.Apply(context.Background(), toRestricted)", "tester.Test(context.Background(), model.TransportStandard)",
		"switcher.Apply(context.Background(), toStandard)", "ErrTransportSwitchTargetNotReady", "ObserveActive",
	} {
		if !strings.Contains(sourceFlow, required) {
			t.Errorf("node-transport source acceptance is missing %q", required)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2node-transport-e2e.sh"))
	for _, required := range []string{
		"assert_instance_contract", "cleanup_harnesses", "assert_preflight_clean", "restore_fixture_states",
		"vpnctl-v2-restricted-spike-v1", "vpnctl-v2-tunnel-spike-v1", "vpnctl-v2-routing-spike-v1",
		"v2standard-test.sh", "v2restricted-uot-test.sh", "v2routing-spike.sh", "v2tunnel-spike.sh",
		"TestV2ManualTransportRoundTrip|TestTransportSwitchWorkflowDefer", "selected_tcp_fail_closed",
		"selected_udp_fail_closed", "probe_gateway_only", "probe_missing_route_blocked",
		"automatic_fallback", "temporary_resources_absent",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("node-transport E2E orchestrator is missing %q", required)
		}
	}

	standardHarness := readContractFile(t, filepath.Join(repositoryRoot, "test", "v2lab", "standard", "namespace.sh"))
	for _, required := range []string{
		"fwmark 0x05000000/0xff000000 table 20003", "unreachable default metric 42760 table 20003",
		"10.67.0.1/32 dev vpnctl-wg table 20003", "marked_request", "marked_blocked",
		"standard_probe_gateway_only", "standard_probe_missing_route_blocked",
	} {
		if !strings.Contains(standardHarness, required) {
			t.Errorf("standard probe packet harness is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"curl http://github.com", "curl https://github.com", "rm -rf", "limactl delete",
	} {
		if strings.Contains(orchestrator, forbidden) {
			t.Errorf("node-transport E2E contains unsafe or network-fetch surface %q", forbidden)
		}
	}
}
