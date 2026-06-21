package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const ExportTypeWireGuard = "wireguard"

type ExportClientInput struct {
	StateDir string
	ClientID string
	Type     string
	Output   string
	SCPHint  bool
}

type ExportClientResult struct {
	Path    string
	SCPHint string
}

func ExportClient(input ExportClientInput) (ExportClientResult, error) {
	if strings.TrimSpace(input.ClientID) == "" {
		return ExportClientResult{}, fmt.Errorf("client id is required")
	}
	if input.Type != ExportTypeWireGuard {
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

	config, err := wireguard.RenderClientConfig(wireguard.ClientConfig{
		PrivateKey:      privateKey,
		Address:         address,
		DNSServers:      append([]string(nil), st.Server.DNSServers...),
		ServerPublicKey: st.Server.WireGuardPublicKey,
		Endpoint:        wireguard.Endpoint(st.Server.PublicEndpoint, st.Server.WireGuardPort),
	})
	if err != nil {
		return ExportClientResult{}, err
	}

	outputPath := input.Output
	if outputPath == "" {
		outputPath = filepath.Join(dir, "generated", "delivery", client.ID+".conf")
	}
	if err := writeExport(outputPath, config); err != nil {
		return ExportClientResult{}, err
	}

	result := ExportClientResult{Path: outputPath}
	if input.SCPHint {
		result.SCPHint = scpHint(st.Server.PublicEndpoint, outputPath)
	}
	return result, nil
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
