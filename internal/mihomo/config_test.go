package mihomo

import (
	"strings"
	"testing"
)

func TestRenderConfig(t *testing.T) {
	got, err := RenderConfig(Config{
		DNSServers:      []string{"1.1.1.1", "8.8.8.8"},
		Server:          "198.211.99.116",
		Port:            51820,
		ClientIP:        "10.66.0.2",
		PrivateKey:      "client-private",
		ServerPublicKey: "server-public",
		Domains:         []string{"chatgpt.com", "openai.com"},
	})
	if err != nil {
		t.Fatalf("render mihomo config: %v", err)
	}

	want := `mode: rule

dns:
  enable: true
  nameserver:
    - 1.1.1.1
    - 8.8.8.8

proxies:
  - name: DO-WG
    type: wireguard
    server: 198.211.99.116
    port: 51820
    ip: 10.66.0.2
    private-key: "client-private"
    public-key: "server-public"
    mtu: 1420
    udp: true
    allowed-ips:
      - 0.0.0.0/0

proxy-groups:
  - name: VPN
    type: select
    proxies:
      - DO-WG

rules:
  - DOMAIN-SUFFIX,chatgpt.com,VPN
  - DOMAIN-SUFFIX,openai.com,VPN
  - MATCH,DIRECT
`
	if got != want {
		t.Fatalf("unexpected config:\n%s", got)
	}
}

func TestRenderConfigRequiresDNSAndDomains(t *testing.T) {
	_, err := RenderConfig(Config{
		Server:          "198.211.99.116",
		Port:            51820,
		ClientIP:        "10.66.0.2",
		PrivateKey:      "client-private",
		ServerPublicKey: "server-public",
		Domains:         []string{"chatgpt.com"},
	})
	if err == nil {
		t.Fatalf("expected missing DNS error")
	}

	_, err = RenderConfig(Config{
		DNSServers:      []string{"1.1.1.1"},
		Server:          "198.211.99.116",
		Port:            51820,
		ClientIP:        "10.66.0.2",
		PrivateKey:      "client-private",
		ServerPublicKey: "server-public",
	})
	if err == nil {
		t.Fatalf("expected missing domains error")
	}
}

func TestRenderConfigUsesDomainSuffixRulesForAllDomains(t *testing.T) {
	got, err := RenderConfig(Config{
		DNSServers:      []string{"1.1.1.1"},
		Server:          "198.211.99.116",
		Port:            51820,
		ClientIP:        "10.66.0.2",
		PrivateKey:      "client-private",
		ServerPublicKey: "server-public",
		Domains:         []string{"chatgpt.com", "openai.com", "claude.ai"},
	})
	if err != nil {
		t.Fatalf("render mihomo config: %v", err)
	}
	if strings.Contains(got, "MATCH,VPN") {
		t.Fatalf("config should not route all traffic through VPN:\n%s", got)
	}
	if !strings.Contains(got, "  - MATCH,DIRECT\n") {
		t.Fatalf("config should end with MATCH,DIRECT:\n%s", got)
	}
}
