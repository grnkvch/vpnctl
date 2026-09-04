package transport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/observability"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const StandardConfigFileName = StandardInterfaceName + ".conf"

type StandardService struct {
	paths  store.Paths
	role   model.Role
	runner linuxplatform.ProbeRunner
}

func NewStandardService(paths store.Paths, role model.Role, runner linuxplatform.ProbeRunner) (*StandardService, error) {
	if role != model.RoleGateway && role != model.RoleNode {
		return nil, fmt.Errorf("standard service role must be gateway or node")
	}
	if runner == nil {
		return nil, fmt.Errorf("standard service runner is required")
	}
	wantConfigDir := filepath.Join(paths.Root, "etc", "vpnctl")
	if paths.Root == "" || !filepath.IsAbs(paths.Root) || filepath.Clean(paths.Root) != paths.Root || paths.ConfigDir != wantConfigDir {
		return nil, fmt.Errorf("standard service paths are invalid")
	}
	return &StandardService{paths: paths, role: role, runner: runner}, nil
}

func RunStandardService(ctx context.Context, paths store.Paths, role model.Role, runner linuxplatform.ProbeRunner) error {
	service, err := NewStandardService(paths, role, runner)
	if err != nil {
		return err
	}
	return service.Run(ctx)
}

// Run validates the root-only rendered config, reconciles only an interface
// whose public key proves vpnctl ownership, brings the kernel interface up,
// and keeps systemd's service process alive until cancellation.
func (service *StandardService) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if service == nil || service.runner == nil {
		return fmt.Errorf("standard service is incomplete")
	}
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	configPath := filepath.Join(service.paths.ConfigDir, "generated", string(service.role), StandardConfigFileName)
	privateKey, err := readStandardServicePrivateKey(configPath)
	if err != nil {
		return err
	}
	expectedPublicKey, err := service.publicKey(ctx, privateKey)
	if err != nil {
		return err
	}
	if err := service.success(ctx, "wg-quick", "strip", configPath); err != nil {
		return fmt.Errorf("validate standard WireGuard config: %w", err)
	}
	_ = observability.EmitCode(ctx, observability.TransportServiceStarted)
	terminalEvent := observability.TransportRuntimeFailed
	defer func() {
		_ = observability.EmitCode(context.WithoutCancel(ctx), terminalEvent)
	}()
	present, err := service.interfacePresent(ctx)
	if err != nil {
		return err
	}
	if present {
		actual, err := service.output(ctx, "wg", "show", StandardInterfaceName, "public-key")
		if err != nil {
			return fmt.Errorf("inspect existing standard interface: %w", err)
		}
		if strings.TrimSpace(actual) != expectedPublicKey {
			return fmt.Errorf("existing %s interface is not owned by the rendered standard credential", StandardInterfaceName)
		}
		if err := service.success(ctx, "wg-quick", "down", configPath); err != nil {
			return fmt.Errorf("remove stale standard interface: %w", err)
		}
	}
	if err := service.success(ctx, "wg-quick", "up", configPath); err != nil {
		return fmt.Errorf("start standard WireGuard interface: %w", err)
	}
	started := true
	cleanup := func() error {
		if !started {
			return nil
		}
		started = false
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := service.success(cleanupCtx, "wg-quick", "down", configPath); err != nil {
			return fmt.Errorf("stop standard WireGuard interface: %w", err)
		}
		return nil
	}
	defer func() { _ = cleanup() }()
	actual, err := service.output(ctx, "wg", "show", StandardInterfaceName, "public-key")
	if err != nil {
		return errors.Join(fmt.Errorf("verify started standard interface: %w", err), cleanup())
	}
	if strings.TrimSpace(actual) != expectedPublicKey {
		return errors.Join(fmt.Errorf("started standard interface has unexpected public key"), cleanup())
	}
	if service.role == model.RoleGateway {
		port, err := service.output(ctx, "wg", "show", StandardInterfaceName, "listen-port")
		if err != nil || strings.TrimSpace(port) != fmt.Sprint(StandardUDPPort) {
			return errors.Join(fmt.Errorf("gateway standard interface is not listening on UDP/%d", StandardUDPPort), cleanup())
		}
	}
	_ = observability.EmitCode(ctx, observability.TransportServiceReady)
	<-ctx.Done()
	if err := cleanup(); err != nil {
		return err
	}
	terminalEvent = observability.TransportServiceStopped
	return nil
}

func readStandardServicePrivateKey(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect standard WireGuard config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("standard WireGuard config must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("standard WireGuard config must not be accessible by group or other")
	}
	if info.Size() <= 0 || info.Size() > maximumStandardConfigBytes {
		return "", fmt.Errorf("standard WireGuard config has invalid size")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read standard WireGuard config: %w", err)
	}
	privateKey := ""
	for _, raw := range strings.Split(string(content), "\n") {
		key, value, found := strings.Cut(raw, "=")
		if !found || strings.TrimSpace(key) != "PrivateKey" {
			continue
		}
		if privateKey != "" {
			return "", fmt.Errorf("standard WireGuard config contains multiple private keys")
		}
		privateKey = strings.TrimSpace(value)
	}
	if privateKey == "" {
		return "", fmt.Errorf("standard WireGuard config contains no private key")
	}
	if err := wireguard.ValidateKey(privateKey); err != nil {
		return "", fmt.Errorf("standard WireGuard config contains an invalid private key: %w", err)
	}
	return privateKey, nil
}

func (service *StandardService) publicKey(ctx context.Context, privateKey string) (string, error) {
	result, err := service.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "wg", Args: []string{"pubkey"}, Stdin: []byte(privateKey + "\n")})
	if err != nil {
		return "", fmt.Errorf("derive standard interface public key: %w", err)
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("derive standard interface public key: command failed")
	}
	publicKey := strings.TrimSpace(string(result.Stdout))
	if err := wireguard.ValidateKey(publicKey); err != nil {
		return "", fmt.Errorf("derive standard interface public key: invalid result")
	}
	return publicKey, nil
}

func (service *StandardService) interfacePresent(ctx context.Context) (bool, error) {
	result, err := service.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "ip", Args: []string{"-o", "link", "show", "dev", StandardInterfaceName}})
	if err != nil {
		return false, fmt.Errorf("inspect standard interface: %w", err)
	}
	switch result.ExitCode {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, fmt.Errorf("inspect standard interface: command failed")
	}
}

func (service *StandardService) success(ctx context.Context, name string, arguments ...string) error {
	_, err := service.output(ctx, name, arguments...)
	return err
}

func (service *StandardService) output(ctx context.Context, name string, arguments ...string) (string, error) {
	result, err := service.runner.Run(ctx, linuxplatform.ProbeCommand{Name: name, Args: arguments})
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("command failed")
	}
	return string(result.Stdout), nil
}
