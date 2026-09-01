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
	if manifest.Transport.Port != 8443 || manifest.Transport.ShadowTLSVersion != 3 || !manifest.Transport.StrictMode || manifest.Transport.NativeUDPListener {
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
		"IP-CIDR,127.0.0.1/32,RESTRICTED,no-resolve", "MATCH,DIRECT",
	} {
		if !strings.Contains(node, required) {
			t.Errorf("node restricted template is missing %q", required)
		}
	}

	client := readContractFile(t, filepath.Join(fixtureRoot, "clash-mi.yaml.tmpl"))
	for _, required := range []string{
		"@CLIENT_GATEWAY_ADDRESS@", "strict-mode: true", "DOMAIN-SUFFIX,example.com,RESTRICTED", "MATCH,DIRECT",
	} {
		if !strings.Contains(client, required) {
			t.Errorf("Clash Mi restricted template is missing %q", required)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2restricted-spike.sh"))
	for _, guard := range []string{
		"assert_forward_ignored", "assert_owned_or_absent", "assert_port_free_or_owned",
		"strict ShadowTLS unexpectedly accepted", "mihomo --> 1.1.1.1:443 using RESTRICTED[RESTRICTED-VALID]",
		"clash-mi-mihomo-validation.txt", "outage_probe_failed", "uninstall_role",
	} {
		if !strings.Contains(orchestrator, guard) {
			t.Errorf("restricted spike orchestrator is missing %q", guard)
		}
	}

	limaTemplate := readContractFile(t, filepath.Join(repositoryRoot, "test", "v2lab", "lima.yaml"))
	for _, port := range []string{"guestPort: 1053", "guestPort: 8443", "guestPort: 17890", "guestPort: 18080", "guestPort: 19090"} {
		if !strings.Contains(limaTemplate, port) {
			t.Errorf("Lima template is missing forwarding isolation for %q", port)
		}
	}
}
