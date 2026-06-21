package state

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	ClientStatusActive    = "active"
	DefaultClientPlatform = "generic"
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type ClientConfig struct {
	ID       string
	Name     string
	Platform string
	Tags     []string
	Now      time.Time
}

type ClientKeyPair struct {
	PrivateKey string
	PublicKey  string
}

type ClientKeyGenerator interface {
	GenerateClientKeyPair(ctx context.Context) (ClientKeyPair, error)
}

func CreateClient(ctx context.Context, dir string, cfg ClientConfig, generator ClientKeyGenerator) (ClientState, error) {
	if dir == "" {
		dir = DefaultDir
	}
	if err := ValidateClientConfig(cfg); err != nil {
		return ClientState{}, err
	}
	if generator == nil {
		return ClientState{}, fmt.Errorf("client key generator is required")
	}
	if _, err := Init(dir, false); err != nil {
		return ClientState{}, err
	}
	st, err := Load(dir)
	if err != nil {
		return ClientState{}, err
	}
	if st.Server == nil {
		return ClientState{}, fmt.Errorf("server is not configured")
	}
	for _, client := range st.Clients {
		if client.ID == cfg.ID {
			return ClientState{}, fmt.Errorf("client %q already exists", cfg.ID)
		}
	}

	assignedIP, err := NextClientIP(st.Server.WireGuardSubnet, st.Clients)
	if err != nil {
		return ClientState{}, err
	}
	keyPair, err := generator.GenerateClientKeyPair(ctx)
	if err != nil {
		return ClientState{}, err
	}
	if err := wireguard.ValidateKey(keyPair.PrivateKey); err != nil {
		return ClientState{}, fmt.Errorf("generated client private key is invalid: %w", err)
	}
	if err := wireguard.ValidateKey(keyPair.PublicKey); err != nil {
		return ClientState{}, fmt.Errorf("generated client public key is invalid: %w", err)
	}

	privateKeyPath := ClientPrivateKeyPath(dir, cfg.ID)
	if err := writeSecret(privateKeyPath, keyPair.PrivateKey); err != nil {
		return ClientState{}, err
	}

	createdAt := cfg.Now
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	client := ClientState{
		ID:                 cfg.ID,
		Name:               clientName(cfg),
		Platform:           clientPlatform(cfg),
		Status:             ClientStatusActive,
		AssignedIP:         assignedIP,
		WireGuardPublicKey: keyPair.PublicKey,
		Tags:               append([]string(nil), cfg.Tags...),
		CreatedAt:          createdAt.UTC(),
	}
	st.Clients = append(st.Clients, client)
	if err := Save(dir, st); err != nil {
		_ = removeSecret(privateKeyPath)
		return ClientState{}, err
	}
	return client, nil
}

func ValidateClientConfig(cfg ClientConfig) error {
	if strings.TrimSpace(cfg.ID) == "" {
		return fmt.Errorf("client id is required")
	}
	if !clientIDPattern.MatchString(cfg.ID) {
		return fmt.Errorf("client id may contain only letters, digits, dots, underscores, and dashes")
	}
	if strings.TrimSpace(clientName(cfg)) == "" {
		return fmt.Errorf("client name is required")
	}
	switch clientPlatform(cfg) {
	case "ios", "macos", "arch", "ubuntu", "linux-vm", "generic":
		return nil
	default:
		return fmt.Errorf("unsupported client platform: %s", cfg.Platform)
	}
}

func NextClientIP(cidr string, clients []ClientState) (string, error) {
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid server subnet: %w", err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("server subnet must be IPv4")
	}
	ones, bits := subnet.Mask.Size()
	if bits != 32 {
		return "", fmt.Errorf("server subnet must be IPv4")
	}

	network := uint64(binary.BigEndian.Uint32(ip4.Mask(subnet.Mask)))
	size := uint64(1) << uint(32-ones)
	firstClient := network + 2
	lastUsable := network + size - 2
	if firstClient > lastUsable {
		return "", fmt.Errorf("server subnet has no client addresses")
	}

	used := map[uint64]bool{}
	for _, client := range clients {
		parsed := net.ParseIP(client.AssignedIP).To4()
		if parsed == nil {
			return "", fmt.Errorf("client %q has invalid assigned IP: %s", client.ID, client.AssignedIP)
		}
		used[uint64(binary.BigEndian.Uint32(parsed))] = true
	}

	for candidate := firstClient; candidate <= lastUsable; candidate++ {
		if !used[candidate] {
			var out [4]byte
			binary.BigEndian.PutUint32(out[:], uint32(candidate))
			return net.IP(out[:]).String(), nil
		}
	}
	return "", fmt.Errorf("server subnet has no available client addresses")
}

func clientName(cfg ClientConfig) string {
	if strings.TrimSpace(cfg.Name) == "" {
		return cfg.ID
	}
	return strings.TrimSpace(cfg.Name)
}

func clientPlatform(cfg ClientConfig) string {
	if strings.TrimSpace(cfg.Platform) == "" {
		return DefaultClientPlatform
	}
	return strings.TrimSpace(cfg.Platform)
}
