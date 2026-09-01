package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2RestrictedSpikeContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "restricted")
	manifestData := readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))
	var manifest struct {
		Status string `json:"status"`
		Mihomo struct {
			Version string `json:"version"`
			SHA256  string `json:"sha256"`
		} `json:"mihomo"`
		Transport struct {
			Port              int  `json:"port"`
			ShadowTLSVersion  int  `json:"shadow_tls_version"`
			StrictMode        bool `json:"strict_mode"`
			UDPOverTCP        bool `json:"udp_over_tcp"`
			UDPOverTCPVersion int  `json:"udp_over_tcp_version"`
			NativeUDPListener bool `json:"native_udp_listener"`
		} `json:"transport"`
	}
	if err := json.Unmarshal([]byte(manifestData), &manifest); err != nil {
		t.Fatalf("decode restricted spike manifest: %v", err)
	}
	if manifest.Status != "spike-only" || manifest.Mihomo.Version != "v1.19.30" {
		t.Fatalf("unexpected restricted candidate: %+v", manifest)
	}
	if len(manifest.Mihomo.SHA256) != 64 {
		t.Fatalf("restricted candidate SHA-256 is not pinned: %q", manifest.Mihomo.SHA256)
	}
	if manifest.Transport.Port != 8443 || manifest.Transport.ShadowTLSVersion != 3 || !manifest.Transport.StrictMode ||
		!manifest.Transport.UDPOverTCP || manifest.Transport.UDPOverTCPVersion != 2 || manifest.Transport.NativeUDPListener {
		t.Fatalf("unexpected restricted transport contract: %+v", manifest.Transport)
	}

	gateway := readContractFile(t, filepath.Join(fixtureRoot, "gateway.yaml.tmpl"))
	for _, required := range []string{
		"type: shadowsocks", "port: 8443", "udp: false", "version: 3",
		"users:", "handshake:", `dest: "@HANDSHAKE_HOST@:443"`,
	} {
		if !strings.Contains(gateway, required) {
			t.Errorf("gateway restricted template is missing %q", required)
		}
	}

	node := readContractFile(t, filepath.Join(fixtureRoot, "node.yaml.tmpl"))
	for _, required := range []string{
		"bind-address: 127.0.0.1", "https://1.1.1.1/dns-query#RESTRICTED",
		"plugin: shadow-tls", "strict-mode: true", "RESTRICTED-WRONG-HOST",
		"udp-over-tcp: true", "udp-over-tcp-version: 2", "RESTRICTED-UOT-BLOCKED", "RESTRICTED-UDP",
		"REJECT-DROP", "AND,((NETWORK,UDP),(IP-CIDR,127.0.0.1/32)),RESTRICTED-UDP",
		"IP-CIDR,127.0.0.1/32,RESTRICTED,no-resolve", "MATCH,DIRECT",
	} {
		if !strings.Contains(node, required) {
			t.Errorf("node restricted template is missing %q", required)
		}
	}

	client := readContractFile(t, filepath.Join(fixtureRoot, "clash-mi.yaml.tmpl"))
	for _, required := range []string{
		"@CLIENT_GATEWAY_ADDRESS@", "strict-mode: true", "udp-over-tcp: true", "udp-over-tcp-version: 2",
		"DOMAIN-SUFFIX,example.com,RESTRICTED", "MATCH,DIRECT",
	} {
		if !strings.Contains(client, required) {
			t.Errorf("Clash Mi restricted template is missing %q", required)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2restricted-spike.sh"))
	for _, guard := range []string{
		"assert_forward_ignored", "assert_owned_or_absent", "assert_port_free_or_owned",
		"strict ShadowTLS unexpectedly accepted", "mihomo --> 1.1.1.1:443 using RESTRICTED[RESTRICTED-VALID]",
		"capture_table=vpnctl_v2_spike_uot_capture", "selected UDP unexpectedly succeeded while UoT was disabled",
		"select_udp_guard REJECT-DROP", "broken-uot-proxy.json", "native UDP while UoT was disabled",
		"clash-mi-mihomo-validation.txt", "outage_probe_failed", "udp_over_tcp_recovered", "uninstall_role",
		"benchmark) benchmark", "hol-250ms-peer-partition", "no_performance_guarantee", "fault node clear",
	} {
		if !strings.Contains(orchestrator, guard) {
			t.Errorf("restricted spike orchestrator is missing %q", guard)
		}
	}

	udpProbe := readContractFile(t, filepath.Join(fixtureRoot, "udp_probe.py"))
	for _, required := range []string{"SOCKS_VERSION = 5", "SOCKS5 UDP associate", "parse_udp_response"} {
		if !strings.Contains(udpProbe, required) {
			t.Errorf("UDP-over-TCP probe is missing %q", required)
		}
	}

	udpBenchmark := readContractFile(t, filepath.Join(fixtureRoot, "udp_benchmark.py"))
	for _, required := range []string{
		"SOCKS5 UDP associate", "PAYLOAD_HEADER", "responses_over_100ms", "out_of_order", "rtt_ms",
	} {
		if !strings.Contains(udpBenchmark, required) {
			t.Errorf("UDP-over-TCP benchmark is missing %q", required)
		}
	}

	httpBenchmark := readContractFile(t, filepath.Join(fixtureRoot, "http_benchmark.py"))
	for _, required := range []string{"HTTPConnection", "expected-sha256", "requests_per_second", "latency_ms"} {
		if !strings.Contains(httpBenchmark, required) {
			t.Errorf("API-like TCP benchmark is missing %q", required)
		}
	}
	if telegramFixture := readContractFile(t, filepath.Join(fixtureRoot, "telegram-api.json")); !strings.Contains(telegramFixture, "vpnctl-v2-telegram-bot-api-like-response") {
		t.Error("Telegram Bot API-like fixture does not identify its synthetic scope")
	}

	for _, fixture := range []string{"node-uot-capture.nft.tmpl", "gateway-uot-capture.nft.tmpl"} {
		capture := readContractFile(t, filepath.Join(fixtureRoot, fixture))
		if !strings.Contains(capture, "table inet vpnctl_v2_spike_uot_capture") || !strings.Contains(capture, "counter") {
			t.Errorf("UoT capture fixture %s does not have an owned counter table", fixture)
		}
	}
	if capture := readContractFile(t, filepath.Join(fixtureRoot, "node-uot-capture.nft.tmpl")); !strings.Contains(capture, "direct-loopback-leak") {
		t.Error("node UoT capture does not detect direct fallback to the loopback test target")
	}
	for _, unit := range []string{"vpnctl-v2-spike-restricted-gateway.service", "vpnctl-v2-spike-restricted-node.service"} {
		contents := readContractFile(t, filepath.Join(fixtureRoot, "systemd", unit))
		if !strings.Contains(contents, "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK") {
			t.Errorf("restricted unit %s does not permit Mihomo route lookup via AF_NETLINK", unit)
		}
	}

	limaTemplate := readContractFile(t, filepath.Join(repositoryRoot, "test", "v2lab", "lima.yaml"))
	if strings.Count(limaTemplate, "guestIP: 0.0.0.0") != 5 || strings.Count(limaTemplate, "guestIPMustBeZero: false") != 5 {
		t.Error("Lima template must ignore wildcard-bound spike listeners without forwarding them to the host")
	}
	for _, port := range []string{"guestPort: 1053", "guestPort: 8443", "guestPort: 17890", "guestPort: 18080", "guestPort: 19090"} {
		if !strings.Contains(limaTemplate, port) {
			t.Errorf("Lima template is missing forwarding isolation for %q", port)
		}
	}
}
