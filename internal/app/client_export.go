package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/mihomo"
	"github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	ExportTypeWireGuard = "wireguard"
	ExportTypeClash     = "clash"

	DefaultRulesetID = "default"
	ClashDNSWarning  = "warning: no custom DNS configured; Clash Mi profile uses default DNS servers 1.1.1.1, 8.8.8.8"
)

var fallbackClashDNS = []string{"1.1.1.1", "8.8.8.8"}

type ExportClientInput struct {
	StateDir string
	ClientID string
	Type     string
	Output   string
	SCPHint  bool
	Ruleset  string
}

type ExportClientResult struct {
	Path    string
	SCPHint string
	Warning string
}

func ExportClient(input ExportClientInput) (ExportClientResult, error) {
	if strings.TrimSpace(input.ClientID) == "" {
		return ExportClientResult{}, fmt.Errorf("client id is required")
	}
	if input.Type != ExportTypeWireGuard && input.Type != ExportTypeClash {
		return ExportClientResult{}, fmt.Errorf("unsupported export type: %s", input.Type)
	}
	dir := input.StateDir
	if dir == "" {
		dir = state.DefaultDir
	}

	st, err := state.Load(dir)
	if err != nil {
		return ExportClientResult{}, err
	}
	if st.Server == nil {
		return ExportClientResult{}, fmt.Errorf("server is not configured")
	}
	if strings.TrimSpace(st.Server.WireGuardPublicKey) == "" {
		return ExportClientResult{}, fmt.Errorf("server WireGuard public key is missing")
	}
	client, err := findActiveClient(st.Clients, input.ClientID)
	if err != nil {
		return ExportClientResult{}, err
	}
	privateKey, err := state.ReadClientPrivateKey(dir, client.ID)
	if err != nil {
		return ExportClientResult{}, err
	}
	address, err := wireguard.ClientAddress(client.AssignedIP, st.Server.WireGuardSubnet)
	if err != nil {
		return ExportClientResult{}, err
	}

	config, outputPath, warning, err := renderExport(renderInput{
		Dir:        dir,
		Input:      input,
		State:      st,
		Client:     client,
		PrivateKey: privateKey,
		Address:    address,
	})
	if err != nil {
		return ExportClientResult{}, err
	}
	if err := writeExport(outputPath, config); err != nil {
		return ExportClientResult{}, err
	}

	result := ExportClientResult{Path: outputPath, Warning: warning}
	if input.SCPHint {
		result.SCPHint = scpHint(st.Server.PublicEndpoint, outputPath)
	}
	return result, nil
}

type renderInput struct {
	Dir        string
	Input      ExportClientInput
	State      state.State
	Client     state.ClientState
	PrivateKey string
	Address    string
}

func renderExport(input renderInput) (string, string, string, error) {
	switch input.Input.Type {
	case ExportTypeWireGuard:
		return renderWireGuardExport(input)
	case ExportTypeClash:
		return renderClashExport(input)
	default:
		return "", "", "", fmt.Errorf("unsupported export type: %s", input.Input.Type)
	}
}

func renderWireGuardExport(input renderInput) (string, string, string, error) {
	config, err := wireguard.RenderClientConfig(wireguard.ClientConfig{
		PrivateKey:      input.PrivateKey,
		Address:         input.Address,
		DNSServers:      append([]string(nil), input.State.Server.DNSServers...),
		ServerPublicKey: input.State.Server.WireGuardPublicKey,
		Endpoint:        wireguard.Endpoint(input.State.Server.PublicEndpoint, input.State.Server.WireGuardPort),
	})
	if err != nil {
		return "", "", "", err
	}

	outputPath := input.Input.Output
	if outputPath == "" {
		outputPath = filepath.Join(input.Dir, "generated", "delivery", input.Client.ID+".conf")
	}
	return config, outputPath, "", nil
}

func renderClashExport(input renderInput) (string, string, string, error) {
	rulesetID := input.Input.Ruleset
	if strings.TrimSpace(rulesetID) == "" {
		rulesetID = DefaultRulesetID
	}
	ruleset, err := state.LoadRuleset(input.Dir, rulesetID)
	if err != nil {
		return "", "", "", err
	}

	dns := append([]string(nil), input.State.Server.DNSServers...)
	warning := ""
	if len(dns) == 0 {
		dns = append([]string(nil), fallbackClashDNS...)
		warning = ClashDNSWarning
	}

	config, err := mihomo.RenderConfig(mihomo.Config{
		DNSServers:      dns,
		Server:          input.State.Server.PublicEndpoint,
		Port:            input.State.Server.WireGuardPort,
		ClientIP:        input.Client.AssignedIP,
		PrivateKey:      input.PrivateKey,
		ServerPublicKey: input.State.Server.WireGuardPublicKey,
		RulesetType:     ruleset.Type,
		Domains:         append([]string(nil), ruleset.Domains...),
	})
	if err != nil {
		return "", "", "", err
	}

	outputPath := input.Input.Output
	if outputPath == "" {
		outputPath = filepath.Join(input.Dir, "generated", "delivery", input.Client.ID+".clash.yaml")
	}
	return config, outputPath, warning, nil
}

func findActiveClient(clients []state.ClientState, id string) (state.ClientState, error) {
	for _, client := range clients {
		if client.ID == id {
			if client.Status != state.ClientStatusActive {
				return state.ClientState{}, fmt.Errorf("client %q is not active", id)
			}
			return client, nil
		}
	}
	return state.ClientState{}, fmt.Errorf("client %q does not exist", id)
}

func writeExport(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create export directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set export permissions: %w", err)
	}
	return nil
}

func scpHint(endpoint string, path string) string {
	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}
	return fmt.Sprintf("scp root@%s:%s .", endpoint, absPath)
}
