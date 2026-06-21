package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/setup"
	"github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const defaultSystemRoot = "/"

type ApplyInput struct {
	StateDir   string
	DryRun     bool
	SystemRoot string
	Executor   setup.Executor
	Stdout     io.Writer
}

type ApplyResult struct {
	StateDir            string
	ExternalInterface   string
	WireGuardConfigPath string
	ActivePeers         int
}

func Apply(ctx context.Context, input ApplyInput) (ApplyResult, error) {
	dir := input.StateDir
	if dir == "" {
		dir = state.DefaultDir
	}
	executor := input.Executor
	if executor == nil {
		executor = setup.SystemExecutor{}
	}
	systemRoot := input.SystemRoot
	if systemRoot == "" {
		systemRoot = defaultSystemRoot
	}

	st, err := state.Load(dir)
	if err != nil {
		return ApplyResult{}, err
	}
	if st.Server == nil {
		return ApplyResult{}, fmt.Errorf("server is not configured")
	}
	if err := verifyApplyRootAndPlatform(executor, systemRoot); err != nil {
		return ApplyResult{}, err
	}

	privateKey, err := readServerPrivateKey(dir)
	if err != nil {
		return ApplyResult{}, err
	}
	externalInterface := strings.TrimSpace(st.Server.ExternalInterface)
	if externalInterface == "" {
		externalInterface, err = detectApplyExternalInterface(ctx, executor)
		if err != nil {
			return ApplyResult{}, err
		}
		st.Server.ExternalInterface = externalInterface
		if !input.DryRun {
			if err := state.Save(dir, st); err != nil {
				return ApplyResult{}, err
			}
		}
	}

	config, activePeers, err := renderApplyConfig(st, privateKey, externalInterface)
	if err != nil {
		return ApplyResult{}, err
	}
	configPath := wireGuardConfigPath(systemRoot, st.Server.WireGuardInterface)

	if input.DryRun {
		printApplyDryRun(input.Stdout, dir, configPath, st.Server.WireGuardInterface, externalInterface, activePeers, redactPrivateKey(config, privateKey))
		return ApplyResult{
			StateDir:            dir,
			ExternalInterface:   externalInterface,
			WireGuardConfigPath: configPath,
			ActivePeers:         activePeers,
		}, nil
	}

	if err := writeApplyConfig(executor, configPath, config); err != nil {
		return ApplyResult{}, err
	}
	service := fmt.Sprintf("wg-quick@%s", st.Server.WireGuardInterface)
	if _, err := executor.Run(ctx, "systemctl", []string{"enable", service}, ""); err != nil {
		return ApplyResult{}, err
	}
	if _, err := executor.Run(ctx, "systemctl", []string{"restart", service}, ""); err != nil {
		return ApplyResult{}, err
	}
	if _, err := executor.Run(ctx, "systemctl", []string{"is-active", service}, ""); err != nil {
		return ApplyResult{}, err
	}
	if _, err := executor.Run(ctx, "wg", []string{"show"}, ""); err != nil {
		return ApplyResult{}, err
	}

	return ApplyResult{
		StateDir:            dir,
		ExternalInterface:   externalInterface,
		WireGuardConfigPath: configPath,
		ActivePeers:         activePeers,
	}, nil
}

func renderApplyConfig(st state.State, privateKey string, externalInterface string) (string, int, error) {
	serverAddress, err := wireguard.ServerAddress(st.Server.WireGuardSubnet)
	if err != nil {
		return "", 0, err
	}
	peers := make([]wireguard.ServerPeer, 0, len(st.Clients))
	activePeers := 0
	for _, client := range st.Clients {
		if client.Status == state.ClientStatusActive {
			activePeers++
		}
		peers = append(peers, wireguard.ServerPeer{
			Name:       client.ID,
			PublicKey:  client.WireGuardPublicKey,
			AllowedIPs: client.AssignedIP + "/32",
			Status:     client.Status,
		})
	}
	config, err := wireguard.RenderServerConfig(wireguard.ServerConfig{
		InterfaceName:     st.Server.WireGuardInterface,
		Address:           serverAddress,
		ListenPort:        st.Server.WireGuardPort,
		PrivateKey:        privateKey,
		ExternalInterface: externalInterface,
		Peers:             peers,
	})
	if err != nil {
		return "", 0, err
	}
	return config, activePeers, nil
}

func readServerPrivateKey(dir string) (string, error) {
	data, err := os.ReadFile(state.ServerPrivateKeyPath(dir))
	if err != nil {
		return "", fmt.Errorf("read server private key: %w", err)
	}
	privateKey := strings.TrimSpace(string(data))
	if err := wireguard.ValidateKey(privateKey); err != nil {
		return "", fmt.Errorf("stored server private key is invalid: %w", err)
	}
	return privateKey, nil
}

func verifyApplyRootAndPlatform(executor setup.Executor, systemRoot string) error {
	if executor.CurrentUID() != 0 {
		return fmt.Errorf("apply must be run as root")
	}
	if executor.GOOS() != "linux" {
		return fmt.Errorf("apply supports Linux only, got %s", executor.GOOS())
	}
	if executor.GOARCH() != "amd64" {
		return fmt.Errorf("apply supports x64/amd64 only, got %s", executor.GOARCH())
	}

	data, err := executor.ReadFile(systemPath(systemRoot, "/etc/os-release"))
	if err != nil {
		return fmt.Errorf("read os-release: %w", err)
	}
	values := parseOSRelease(string(data))
	if values["ID"] != "ubuntu" || values["VERSION_ID"] != "24.04" {
		return fmt.Errorf("apply supports Ubuntu 24.04 LTS x64 only")
	}
	return nil
}

func detectApplyExternalInterface(ctx context.Context, executor setup.Executor) (string, error) {
	out, err := executor.Run(ctx, "ip", []string{"route", "get", "1.1.1.1"}, "")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("could not detect external interface")
}

func writeApplyConfig(executor setup.Executor, path string, config string) error {
	if err := executor.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create WireGuard config directory: %w", err)
	}
	if err := executor.WriteFile(path, []byte(config), 0o600); err != nil {
		return fmt.Errorf("write WireGuard config: %w", err)
	}
	if err := executor.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("set WireGuard config permissions: %w", err)
	}
	return nil
}

func printApplyDryRun(w io.Writer, stateDir string, configPath string, interfaceName string, externalInterface string, activePeers int, config string) {
	if w == nil {
		return
	}
	fmt.Fprintln(w, "apply plan (dry-run)")
	fmt.Fprintf(w, "state directory: %s\n", stateDir)
	fmt.Fprintf(w, "wireguard config: %s\n", configPath)
	fmt.Fprintf(w, "wireguard interface: %s\n", interfaceName)
	fmt.Fprintf(w, "external interface: %s\n", externalInterface)
	fmt.Fprintf(w, "active peers: %d\n", activePeers)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "would write WireGuard server configuration")
	fmt.Fprintf(w, "would enable and restart wg-quick@%s\n", interfaceName)
	fmt.Fprintf(w, "would verify wg-quick@%s and wg show\n", interfaceName)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "rendered server config:")
	fmt.Fprint(w, config)
}

func redactPrivateKey(config string, privateKey string) string {
	return strings.ReplaceAll(config, "PrivateKey = "+privateKey, "PrivateKey = <redacted>")
}

func wireGuardConfigPath(systemRoot string, interfaceName string) string {
	return filepath.Join(systemPath(systemRoot, "/etc/wireguard"), interfaceName+".conf")
}

func systemPath(root string, path string) string {
	if root == "" || root == defaultSystemRoot {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}

func parseOSRelease(data string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return out
}
