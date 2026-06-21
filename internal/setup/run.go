package setup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	defaultSystemRoot = "/"
)

type Runtime struct {
	Executor     Executor
	KeyGenerator state.ServerKeyGenerator
	SystemRoot   string
}

type Executor interface {
	CurrentUID() int
	GOOS() string
	GOARCH() string
	ReadFile(path string) ([]byte, error)
	WriteFile(path string, data []byte, mode os.FileMode) error
	MkdirAll(path string, mode os.FileMode) error
	Chmod(path string, mode os.FileMode) error
	Run(ctx context.Context, name string, args []string, stdin string) (string, error)
}

type SystemExecutor struct{}

type Result struct {
	StateDir            string
	ExternalInterface   string
	WireGuardConfigPath string
	GeneratedServerKeys bool
}

func Run(ctx context.Context, opts Options, rt Runtime) (Result, error) {
	if opts.StateDir == "" {
		opts.StateDir = DefaultStateDir
	}
	if err := opts.Validate(); err != nil {
		return Result{}, err
	}
	executor := rt.Executor
	if executor == nil {
		executor = SystemExecutor{}
	}
	systemRoot := rt.SystemRoot
	if systemRoot == "" {
		systemRoot = defaultSystemRoot
	}
	keyGenerator := rt.KeyGenerator
	if keyGenerator == nil {
		keyGenerator = ServerKeyGenerator{}
	}

	if err := verifyRootAndPlatform(executor, systemRoot); err != nil {
		return Result{}, err
	}
	if err := state.ConfigureServer(opts.StateDir, ServerConfig(opts), true); err != nil {
		return Result{}, err
	}

	if _, err := executor.Run(ctx, "apt", []string{"update"}, ""); err != nil {
		return Result{}, err
	}
	if _, err := executor.Run(ctx, "apt", []string{"install", "-y", "wireguard", "qrencode", "ufw"}, ""); err != nil {
		return Result{}, err
	}

	keyPair, generatedKeys, err := state.EnsureServerKeyPair(ctx, opts.StateDir, keyGenerator)
	if err != nil {
		return Result{}, err
	}

	externalInterface := opts.ExternalInterface
	if externalInterface == "" {
		externalInterface, err = detectExternalInterface(ctx, executor)
		if err != nil {
			return Result{}, err
		}
	}
	if err := persistExternalInterface(opts.StateDir, externalInterface); err != nil {
		return Result{}, err
	}

	if err := enableIPv4Forwarding(ctx, executor, systemRoot); err != nil {
		return Result{}, err
	}

	configPath, err := writeWireGuardConfig(executor, systemRoot, opts, keyPair, externalInterface)
	if err != nil {
		return Result{}, err
	}

	if _, err := executor.Run(ctx, "ufw", []string{"allow", fmt.Sprintf("%d/tcp", opts.SSHPort)}, ""); err != nil {
		return Result{}, err
	}
	if _, err := executor.Run(ctx, "ufw", []string{"allow", fmt.Sprintf("%d/udp", opts.Port)}, ""); err != nil {
		return Result{}, err
	}
	if opts.EnableUFW {
		if _, err := executor.Run(ctx, "ufw", []string{"--force", "enable"}, ""); err != nil {
			return Result{}, err
		}
	}

	service := fmt.Sprintf("wg-quick@%s", opts.Interface)
	if _, err := executor.Run(ctx, "systemctl", []string{"enable", service}, ""); err != nil {
		return Result{}, err
	}
	if _, err := executor.Run(ctx, "systemctl", []string{"restart", service}, ""); err != nil {
		return Result{}, err
	}
	if _, err := executor.Run(ctx, "systemctl", []string{"is-active", service}, ""); err != nil {
		return Result{}, err
	}
	if _, err := executor.Run(ctx, "wg", []string{"show"}, ""); err != nil {
		return Result{}, err
	}

	return Result{
		StateDir:            opts.StateDir,
		ExternalInterface:   externalInterface,
		WireGuardConfigPath: configPath,
		GeneratedServerKeys: generatedKeys,
	}, nil
}

func (SystemExecutor) CurrentUID() int {
	return os.Geteuid()
}

func (SystemExecutor) GOOS() string {
	return runtime.GOOS
}

func (SystemExecutor) GOARCH() string {
	return runtime.GOARCH
}

func (SystemExecutor) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (SystemExecutor) WriteFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}

func (SystemExecutor) MkdirAll(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

func (SystemExecutor) Chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

func (SystemExecutor) Run(ctx context.Context, name string, args []string, stdin string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func verifyRootAndPlatform(executor Executor, systemRoot string) error {
	if executor.CurrentUID() != 0 {
		return fmt.Errorf("setup must be run as root")
	}
	if executor.GOOS() != "linux" {
		return fmt.Errorf("setup supports Linux only, got %s", executor.GOOS())
	}
	if executor.GOARCH() != "amd64" {
		return fmt.Errorf("setup supports x64/amd64 only, got %s", executor.GOARCH())
	}

	data, err := executor.ReadFile(systemPath(systemRoot, "/etc/os-release"))
	if err != nil {
		return fmt.Errorf("read os-release: %w", err)
	}
	values := parseOSRelease(string(data))
	if values["ID"] != "ubuntu" || values["VERSION_ID"] != "24.04" {
		return fmt.Errorf("setup supports Ubuntu 24.04 LTS x64 only")
	}
	return nil
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

func detectExternalInterface(ctx context.Context, executor Executor) (string, error) {
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

func persistExternalInterface(stateDir string, externalInterface string) error {
	st, err := state.Load(stateDir)
	if err != nil {
		return err
	}
	if st.Server == nil {
		return fmt.Errorf("server is not configured")
	}
	st.Server.ExternalInterface = externalInterface
	return state.Save(stateDir, st)
}

func enableIPv4Forwarding(ctx context.Context, executor Executor, systemRoot string) error {
	path := systemPath(systemRoot, "/etc/sysctl.d/99-vpnctl.conf")
	if err := executor.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create sysctl directory: %w", err)
	}
	if err := executor.WriteFile(path, []byte("net.ipv4.ip_forward=1\n"), 0o644); err != nil {
		return fmt.Errorf("write sysctl config: %w", err)
	}
	if _, err := executor.Run(ctx, "sysctl", []string{"--system"}, ""); err != nil {
		return err
	}
	return nil
}

func writeWireGuardConfig(executor Executor, systemRoot string, opts Options, keyPair state.ServerKeyPair, externalInterface string) (string, error) {
	serverAddress, err := wireguard.ServerAddress(opts.Subnet)
	if err != nil {
		return "", err
	}
	config, err := wireguard.RenderServerConfig(wireguard.ServerConfig{
		InterfaceName:     opts.Interface,
		Address:           serverAddress,
		ListenPort:        opts.Port,
		PrivateKey:        keyPair.PrivateKey,
		ExternalInterface: externalInterface,
	})
	if err != nil {
		return "", err
	}

	configDir := systemPath(systemRoot, "/etc/wireguard")
	if err := executor.MkdirAll(configDir, 0o700); err != nil {
		return "", fmt.Errorf("create WireGuard config directory: %w", err)
	}
	configPath := filepath.Join(configDir, opts.Interface+".conf")
	if err := executor.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return "", fmt.Errorf("write WireGuard config: %w", err)
	}
	if err := executor.Chmod(configPath, 0o600); err != nil {
		return "", fmt.Errorf("set WireGuard config permissions: %w", err)
	}
	return configPath, nil
}

func systemPath(root string, path string) string {
	if root == "" || root == defaultSystemRoot {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}
