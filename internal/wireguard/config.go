package wireguard

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	DefaultClientAllowedIPs          = "0.0.0.0/0"
	DefaultClientPersistentKeepalive = 25
	ActivePeerStatus                 = "active"
)

type ServerConfig struct {
	InterfaceName     string
	Address           string
	ListenPort        int
	PrivateKey        string
	ExternalInterface string
	Peers             []ServerPeer
}

type ServerPeer struct {
	Name       string
	PublicKey  string
	AllowedIPs string
	Status     string
}

type ClientConfig struct {
	PrivateKey          string
	Address             string
	DNSServers          []string
	ServerPublicKey     string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepalive int
}

func RenderServerConfig(cfg ServerConfig) (string, error) {
	if strings.TrimSpace(cfg.InterfaceName) == "" {
		return "", fmt.Errorf("wireguard interface is required")
	}
	if strings.TrimSpace(cfg.Address) == "" {
		return "", fmt.Errorf("server address is required")
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return "", fmt.Errorf("listen port must be between 1 and 65535")
	}
	if err := ValidateKey(cfg.PrivateKey); err != nil {
		return "", fmt.Errorf("server private key is invalid: %w", err)
	}
	if strings.TrimSpace(cfg.ExternalInterface) == "" {
		return "", fmt.Errorf("external interface is required")
	}

	peers := append([]ServerPeer(nil), cfg.Peers...)
	sort.SliceStable(peers, func(i, j int) bool {
		return peers[i].Name < peers[j].Name
	})

	var b strings.Builder
	fmt.Fprintln(&b, "[Interface]")
	fmt.Fprintf(&b, "Address = %s\n", cfg.Address)
	fmt.Fprintf(&b, "ListenPort = %d\n", cfg.ListenPort)
	fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.PrivateKey)
	fmt.Fprintf(&b, "PostUp = iptables -A FORWARD -i %s -j ACCEPT\n", cfg.InterfaceName)
	fmt.Fprintf(&b, "PostUp = iptables -A FORWARD -o %s -j ACCEPT\n", cfg.InterfaceName)
	fmt.Fprintf(&b, "PostUp = iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n", cfg.ExternalInterface)
	fmt.Fprintf(&b, "PostDown = iptables -D FORWARD -i %s -j ACCEPT\n", cfg.InterfaceName)
	fmt.Fprintf(&b, "PostDown = iptables -D FORWARD -o %s -j ACCEPT\n", cfg.InterfaceName)
	fmt.Fprintf(&b, "PostDown = iptables -t nat -D POSTROUTING -o %s -j MASQUERADE\n", cfg.ExternalInterface)

	for _, peer := range peers {
		if !includePeer(peer) {
			continue
		}
		if err := validateServerPeer(peer); err != nil {
			return "", err
		}
		fmt.Fprintln(&b)
		if strings.TrimSpace(peer.Name) != "" {
			fmt.Fprintf(&b, "# %s\n", peer.Name)
		}
		fmt.Fprintln(&b, "[Peer]")
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", peer.AllowedIPs)
	}

	return b.String(), nil
}

func RenderClientConfig(cfg ClientConfig) (string, error) {
	if err := ValidateKey(cfg.PrivateKey); err != nil {
		return "", fmt.Errorf("client private key is invalid: %w", err)
	}
	if strings.TrimSpace(cfg.Address) == "" {
		return "", fmt.Errorf("client address is required")
	}
	if err := ValidateKey(cfg.ServerPublicKey); err != nil {
		return "", fmt.Errorf("server public key is invalid: %w", err)
	}
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return "", fmt.Errorf("endpoint is required")
	}

	allowedIPs := cfg.AllowedIPs
	if len(allowedIPs) == 0 {
		allowedIPs = []string{DefaultClientAllowedIPs}
	}
	keepalive := cfg.PersistentKeepalive
	if keepalive == 0 {
		keepalive = DefaultClientPersistentKeepalive
	}

	var b strings.Builder
	fmt.Fprintln(&b, "[Interface]")
	fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", cfg.Address)
	if len(cfg.DNSServers) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(cfg.DNSServers, ", "))
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "[Peer]")
	fmt.Fprintf(&b, "PublicKey = %s\n", cfg.ServerPublicKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", cfg.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowedIPs, ", "))
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keepalive)

	return b.String(), nil
}

func ServerAddress(cidr string) (string, error) {
	ip, subnet, err := parseIPv4CIDR(cidr)
	if err != nil {
		return "", err
	}
	ones, _ := subnet.Mask.Size()
	network := binary.BigEndian.Uint32(ip.Mask(subnet.Mask))
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], network+1)
	return fmt.Sprintf("%s/%d", net.IP(out[:]).String(), ones), nil
}

func ClientAddress(ip string, cidr string) (string, error) {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return "", fmt.Errorf("client IP must be IPv4")
	}
	_, subnet, err := parseIPv4CIDR(cidr)
	if err != nil {
		return "", err
	}
	if !subnet.Contains(parsed) {
		return "", fmt.Errorf("client IP is outside server subnet")
	}
	ones, _ := subnet.Mask.Size()
	return fmt.Sprintf("%s/%d", parsed.String(), ones), nil
}

func Endpoint(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func validateServerPeer(peer ServerPeer) error {
	if err := ValidateKey(peer.PublicKey); err != nil {
		return fmt.Errorf("peer %q public key is invalid: %w", peer.Name, err)
	}
	if strings.TrimSpace(peer.AllowedIPs) == "" {
		return fmt.Errorf("peer %q allowed IPs are required", peer.Name)
	}
	return nil
}

func includePeer(peer ServerPeer) bool {
	status := strings.TrimSpace(peer.Status)
	return status == "" || status == ActivePeerStatus
}

func parseIPv4CIDR(cidr string) (net.IP, *net.IPNet, error) {
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("CIDR must be valid: %w", err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, nil, fmt.Errorf("CIDR must be IPv4")
	}
	return ip4, subnet, nil
}
