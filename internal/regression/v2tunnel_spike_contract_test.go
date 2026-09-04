package regression

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2TunnelSpikeContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "tunnel")
	manifestData := readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))
	var manifest struct {
		Status string `json:"status"`
		FRP    struct {
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
		} `json:"frp"`
		Ports struct {
			Server              int   `json:"server"`
			ClientAdmin         int   `json:"client_admin"`
			GatewayExposes      []int `json:"gateway_exposes"`
			NodeBackends        []int `json:"node_backends"`
			AuthorizationPlugin int   `json:"authorization_plugin"`
		} `json:"ports"`
		Transport struct {
			WireProtocol             string `json:"wire_protocol"`
			TCPMux                   bool   `json:"tcp_mux"`
			PoolCount                int    `json:"pool_count"`
			NormalizedLoginPoolCount int    `json:"normalized_login_pool_count"`
			PoolEnforcement          string `json:"pool_enforcement"`
			TLSServer                string `json:"tls_server_name"`
			RevokeBound              int    `json:"revoke_bound_seconds"`
		} `json:"transport"`
	}
	if err := json.Unmarshal([]byte(manifestData), &manifest); err != nil {
		t.Fatalf("decode tunnel spike manifest: %v", err)
	}
	if manifest.Status != "spike-only" || manifest.FRP.Version != "0.69.0" || len(manifest.FRP.SHA256) != 64 {
		t.Fatalf("unexpected frp candidate: %+v", manifest.FRP)
	}
	if manifest.Ports.Server != 17000 || manifest.Ports.ClientAdmin != 17400 ||
		manifest.Ports.AuthorizationPlugin != 19091 || len(manifest.Ports.GatewayExposes) != 2 ||
		len(manifest.Ports.NodeBackends) != 2 {
		t.Fatalf("unexpected tunnel listener contract: %+v", manifest.Ports)
	}
	if !manifest.Transport.TCPMux || manifest.Transport.PoolCount != 0 ||
		manifest.Transport.NormalizedLoginPoolCount != 1 || manifest.Transport.PoolEnforcement != "login-plugin-rewrite" ||
		manifest.Transport.WireProtocol != "v1" || manifest.Transport.TLSServer != "vpnctl-tunnel-gateway" ||
		manifest.Transport.RevokeBound <= 0 {
		t.Fatalf("unexpected tunnel transport contract: %+v", manifest.Transport)
	}

	frps := readContractFile(t, filepath.Join(fixtureRoot, "frps.toml.tmpl"))
	for _, required := range []string{
		`bindAddr = "@GATEWAY_IP@"`, `proxyBindAddr = "127.0.0.1"`,
		`transport.tcpMux = true`, `transport.tls.force = true`,
		`auth.tokenSource.type = "file"`, `ops = ["Login", "NewProxy", "Ping"]`,
		`{ single = 18111 }`, `{ single = 18112 }`,
	} {
		if !strings.Contains(frps, required) {
			t.Errorf("frps fixture is missing %q", required)
		}
	}
	for _, forbidden := range []string{"webServer.port", "kcpBindPort", "quicBindPort", "vhostHTTPPort", "vhostHTTPSPort"} {
		if strings.Contains(frps, forbidden) {
			t.Errorf("frps fixture enables forbidden surface %q", forbidden)
		}
	}

	frpc := readContractFile(t, filepath.Join(fixtureRoot, "frpc.toml.tmpl"))
	for _, required := range []string{
		`webServer.addr = "127.0.0.1"`, `transport.poolCount = 0`, `transport.tcpMux = true`,
		`transport.tls.trustedCaFile`, `transport.tls.serverName = "vpnctl-tunnel-gateway"`,
		`metadatas.node_id = "node-a"`, `metadatas.generation = "1"`, `@TUNNEL_TOKEN@`, `@PROXY_URL@`,
	} {
		if !strings.Contains(frpc, required) {
			t.Errorf("frpc fixture is missing %q", required)
		}
	}

	authorizer := readContractFile(t, filepath.Join(fixtureRoot, "auth_plugin.py"))
	for _, required := range []string{
		"hmac.compare_digest", "pool_input_not_one", `normalized["pool_count"] = 0`,
		`"unchange": False`, `"last_by_operation"`, "generation_mismatch", "mapping_mismatch",
		"MAX_REQUEST_BYTES", "atomic_json", "def log_message", "set-active",
	} {
		if !strings.Contains(authorizer, required) {
			t.Errorf("tunnel authorizer is missing %q", required)
		}
	}

	report := readContractFile(t, filepath.Join(repositoryRoot, "docs", "v2", "TUNNEL_SPIKE.md"))
	for _, required := range []string{
		"frp `v0.69.0`", "effective work-connection pool of zero",
		"Login `pool_count = 1`", "one persistent TLS/tcpMux connection",
		"OpenSSH reverse forwarding remains the fallback adapter",
	} {
		if !strings.Contains(report, required) {
			t.Errorf("tunnel spike report is missing %q", required)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2tunnel-spike.sh"))
	for _, required := range []string{
		"assert_forward_ignored", "assert_owned_or_absent", "frpc reload", "direct_control_connections",
		"proxies-malicious.toml", "proxies-stale-generation.toml", "frpc-untrusted-server.toml",
		"frpc-pool-negative.toml", "hide_auth_state", "controller_error", "set_node_active false", "revoke_bound_seconds",
		"[.requests.Login.rejected, .requests.NewProxy.rejected, .requests.Ping.rejected] | add",
		"[.last_by_operation[] | select(.reason == \"controller_error\")] | length > 0",
		"transport.proxyURL", "mihomo_mode global", "capture_table=vpnctl_v2_spike_tunnel_capture",
		"restricted_shadowtls_packets", "owner-checked tunnel spike resources removed",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("tunnel spike orchestrator is missing %q", required)
		}
	}
	for _, forbidden := range []string{`echo "$TUNNEL_TOKEN"`, `echo "$BOOTSTRAP_TOKEN"`, "log.level = \"debug\""} {
		if strings.Contains(orchestrator, forbidden) {
			t.Errorf("tunnel spike orchestrator contains forbidden secret/logging surface %q", forbidden)
		}
	}

	capture := readContractFile(t, filepath.Join(fixtureRoot, "capture.nft.tmpl"))
	for _, required := range []string{"table inet vpnctl_v2_spike_tunnel_capture", "direct-frp", "restricted-shadowtls", "dport 17000", "dport 8443"} {
		if !strings.Contains(capture, required) {
			t.Errorf("tunnel capture fixture is missing %q", required)
		}
	}

	for _, unit := range []string{
		"vpnctl-v2-spike-tunnel-auth.service", "vpnctl-v2-spike-tunnel-server.service",
		"vpnctl-v2-spike-tunnel-client.service", "vpnctl-v2-spike-tunnel-backend.service",
	} {
		contents := readContractFile(t, filepath.Join(fixtureRoot, "systemd", unit))
		for _, required := range []string{"NoNewPrivileges=true", "ProtectSystem=strict", "MemoryMax=", "TasksMax="} {
			if !strings.Contains(contents, required) {
				t.Errorf("tunnel unit %s lacks %q", unit, required)
			}
		}
	}

	limaTemplate := readContractFile(t, filepath.Join(repositoryRoot, "test", "v2lab", "lima.yaml"))
	for _, port := range []string{"17000", "17400", "18111", "18112", "18121", "18122", "19091"} {
		if !strings.Contains(limaTemplate, "guestPort: "+port) {
			t.Errorf("Lima template is missing tunnel forwarding isolation for %s", port)
		}
	}
}

func TestV2TunnelReleaseGateContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	harnessPath := filepath.Join(repositoryRoot, "scripts", "v2tunnel-release-gate.sh")
	info, err := os.Stat(harnessPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("tunnel release gate is not executable")
	}
	harness := readContractFile(t, harnessPath)
	for _, required := range []string{
		"release gate requires a clean source tree",
		"assert_lab_instance", "assert_tunnel_fixture_absent", "assert_owned_path",
		"TestFRPNativeConfigsWithPinnedBinaries",
		"TestFRPNativeLoginUsesProductionAuthorizerAndEffectiveZeroPool",
		"TestFRPNativeNewProxyUsesProductionAuthoritativeMapping",
		"TestFRPNativeRejectedPingClosesRevokedSessionAndRejectsReconnect",
		"TestFRPNativeReadinessRecoversWithoutStandbyAfterGatewayUpstreamAndClientRestarts",
		"TestFRPNativeDynamicMappingReloadKeepsProcessConnectionAndStream",
		"v2tunnel-spike.sh", "validate_spike_summary", "minimum_mem_available_kib",
		"controller_unavailable_rejected", "revoke_reconnect_rejected",
		"logical_identity_preserved", "resources.oom_kills == 0",
		"cleanup_native_guest", "tunnel_cleanup", "restricted_cleanup",
		"release gate refuses to replace evidence", "source_commit",
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("tunnel release gate is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"VPNCTL_RELEASE_GATE_ALLOW_DIRTY", "--force", "rm -rf /etc", "log.level = \"debug\"",
	} {
		if strings.Contains(harness, forbidden) {
			t.Errorf("tunnel release gate contains forbidden behavior %q", forbidden)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2tunnel-spike.sh"))
	if !strings.Contains(orchestrator, "scripts/v2tunnel-spike.sh fetch") ||
		!strings.Contains(orchestrator, "pinned frp cache ready") {
		t.Fatal("tunnel spike does not expose checksum-verified provider fetch for the release gate")
	}
}
