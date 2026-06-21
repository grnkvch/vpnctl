package wireguard

import (
	"strings"
	"testing"
)

func TestRenderServerConfig(t *testing.T) {
	got, err := RenderServerConfig(ServerConfig{
		InterfaceName:     "wg0",
		Address:           "10.66.0.1/24",
		ListenPort:        51820,
		PrivateKey:        testPrivateKey,
		ExternalInterface: "eth0",
		Peers: []ServerPeer{
			{
				Name:       "revoked",
				PublicKey:  testPublicKey,
				AllowedIPs: "10.66.0.3/32",
				Status:     "revoked",
			},
			{
				Name:       "iphone",
				PublicKey:  testPublicKey,
				AllowedIPs: "10.66.0.2/32",
				Status:     ActivePeerStatus,
			},
		},
	})
	if err != nil {
		t.Fatalf("render server config: %v", err)
	}

	want := `[Interface]
Address = 10.66.0.1/24
ListenPort = 51820
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# iphone
[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
AllowedIPs = 10.66.0.2/32
`
	if got != want {
		t.Fatalf("unexpected server config:\n%s", got)
	}
	if strings.Contains(got, "revoked") || strings.Contains(got, "10.66.0.3/32") {
		t.Fatalf("server config includes revoked peer:\n%s", got)
	}
}

func TestRenderClientConfigDefaults(t *testing.T) {
	got, err := RenderClientConfig(ClientConfig{
		PrivateKey:      testPrivateKey,
		Address:         "10.66.0.2/24",
		ServerPublicKey: testPublicKey,
		Endpoint:        "198.211.99.116:51820",
	})
	if err != nil {
		t.Fatalf("render client config: %v", err)
	}

	want := `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.66.0.2/24

[Peer]
PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
Endpoint = 198.211.99.116:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`
	if got != want {
		t.Fatalf("unexpected client config:\n%s", got)
	}
	if strings.Contains(got, "DNS =") {
		t.Fatalf("client config should omit DNS by default:\n%s", got)
	}
}

func TestRenderClientConfigWithDNS(t *testing.T) {
	got, err := RenderClientConfig(ClientConfig{
		PrivateKey:      testPrivateKey,
		Address:         "10.66.0.2/24",
		DNSServers:      []string{"1.1.1.1", "8.8.8.8"},
		ServerPublicKey: testPublicKey,
		Endpoint:        "vpn.example.com:51820",
	})
	if err != nil {
		t.Fatalf("render client config: %v", err)
	}
	if !strings.Contains(got, "DNS = 1.1.1.1, 8.8.8.8\n") {
		t.Fatalf("expected DNS line, got:\n%s", got)
	}
}

func TestAddressHelpers(t *testing.T) {
	serverAddress, err := ServerAddress("10.66.0.0/24")
	if err != nil {
		t.Fatalf("server address: %v", err)
	}
	if serverAddress != "10.66.0.1/24" {
		t.Fatalf("unexpected server address: %s", serverAddress)
	}

	clientAddress, err := ClientAddress("10.66.0.2", "10.66.0.0/24")
	if err != nil {
		t.Fatalf("client address: %v", err)
	}
	if clientAddress != "10.66.0.2/24" {
		t.Fatalf("unexpected client address: %s", clientAddress)
	}

	if _, err := ClientAddress("10.10.10.2", "10.66.0.0/24"); err == nil {
		t.Fatalf("expected outside subnet error")
	}
}

func TestEndpointFormatsIPv6(t *testing.T) {
	got := Endpoint("2001:db8::1", 51820)
	if got != "[2001:db8::1]:51820" {
		t.Fatalf("unexpected endpoint: %s", got)
	}
}
