package state

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultServerID    = "main"
	DefaultServerName  = "main"
	DefaultWGPort      = 51820
	DefaultWGInterface = "wg0"
	DefaultWGSubnet    = "10.66.0.0/24"
)

type ServerConfig struct {
	ID                 string
	Name               string
	PublicEndpoint     string
	WireGuardPort      int
	WireGuardInterface string
	WireGuardSubnet    string
	DNSServers         []string
	ExternalInterface  string
}

func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		ID:                 DefaultServerID,
		Name:               DefaultServerName,
		WireGuardPort:      DefaultWGPort,
		WireGuardInterface: DefaultWGInterface,
		WireGuardSubnet:    DefaultWGSubnet,
	}
}

func ConfigureServer(dir string, cfg ServerConfig, force bool) error {
	if dir == "" {
		dir = DefaultDir
	}
	if err := ValidateServerConfig(cfg); err != nil {
		return err
	}
	if _, err := Init(dir, false); err != nil {
		return err
	}

	st, err := Load(dir)
	if err != nil {
		return err
	}
	if st.Server != nil && !force {
		return fmt.Errorf("server already configured; use --force to replace it")
	}
	wireGuardPublicKey := ""
	if st.Server != nil {
		wireGuardPublicKey = st.Server.WireGuardPublicKey
	}

	st.Server = &ServerState{
		ID:                 cfg.ID,
		Name:               cfg.Name,
		PublicEndpoint:     cfg.PublicEndpoint,
		WireGuardInterface: cfg.WireGuardInterface,
		WireGuardPort:      cfg.WireGuardPort,
		WireGuardSubnet:    cfg.WireGuardSubnet,
		WireGuardPublicKey: wireGuardPublicKey,
		DNSServers:         append([]string(nil), cfg.DNSServers...),
		ExternalInterface:  cfg.ExternalInterface,
	}
	return Save(dir, st)
}

func Load(dir string) (State, error) {
	if dir == "" {
		dir = DefaultDir
	}

	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return State{}, fmt.Errorf("read state: %w", err)
	}

	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, fmt.Errorf("parse state: %w", err)
	}
	if st.SchemaVersion != SchemaVersion {
		return State{}, fmt.Errorf("unsupported state schema version %d", st.SchemaVersion)
	}
	if st.Clients == nil {
		st.Clients = []ClientState{}
	}
	return st, nil
}

func Save(dir string, st State) error {
	if dir == "" {
		dir = DefaultDir
	}
	st.SchemaVersion = SchemaVersion
	if st.Clients == nil {
		st.Clients = []ClientState{}
	}
	result := InitResult{StateDir: dir}
	return writeJSON(filepath.Join(dir, "state.json"), st, 0o644, true, &result)
}

func ValidateServerConfig(cfg ServerConfig) error {
	if strings.TrimSpace(cfg.ID) == "" {
		return fmt.Errorf("server id is required")
	}
	if strings.TrimSpace(cfg.Name) == "" {
		return fmt.Errorf("server name is required")
	}
	if strings.TrimSpace(cfg.PublicEndpoint) == "" {
		return fmt.Errorf("--endpoint is required")
	}
	if cfg.WireGuardPort <= 0 || cfg.WireGuardPort > 65535 {
		return fmt.Errorf("--port must be between 1 and 65535")
	}
	if strings.TrimSpace(cfg.WireGuardInterface) == "" {
		return fmt.Errorf("--interface is required")
	}
	ip, subnet, err := net.ParseCIDR(cfg.WireGuardSubnet)
	if err != nil {
		return fmt.Errorf("--subnet must be valid CIDR: %w", err)
	}
	if ip.To4() == nil {
		return fmt.Errorf("--subnet must be an IPv4 CIDR")
	}
	ones, bits := subnet.Mask.Size()
	if bits != 32 || ones > 30 {
		return fmt.Errorf("--subnet must provide at least two usable addresses")
	}
	for _, dns := range cfg.DNSServers {
		if net.ParseIP(dns) == nil {
			return fmt.Errorf("--dns contains invalid IP address: %s", dns)
		}
	}
	return nil
}
