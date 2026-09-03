package tunnel

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type FRPProcessRunner interface {
	Run(context.Context, string, []string) error
}

type OSFRPProcessRunner struct{}

func (OSFRPProcessRunner) Run(ctx context.Context, name string, arguments []string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if name == "" {
		return fmt.Errorf("frp process name is required")
	}
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

type FRPService struct {
	paths   store.Paths
	role    model.Role
	probe   linuxplatform.ProbeRunner
	process FRPProcessRunner
}

func NewFRPService(paths store.Paths, role model.Role, probe linuxplatform.ProbeRunner, process FRPProcessRunner) (*FRPService, error) {
	if role != model.RoleGateway && role != model.RoleNode {
		return nil, fmt.Errorf("frp service role must be gateway or node")
	}
	if probe == nil {
		return nil, fmt.Errorf("frp service probe runner is required")
	}
	if process == nil {
		return nil, fmt.Errorf("frp service process runner is required")
	}
	wantConfigDir := filepath.Join(paths.Root, "etc", "vpnctl")
	wantStateDir := filepath.Join(paths.Root, "var", "lib", "vpnctl")
	if paths.Root == "" || !filepath.IsAbs(paths.Root) || filepath.Clean(paths.Root) != paths.Root ||
		paths.ConfigDir != wantConfigDir || paths.StateDir != wantStateDir {
		return nil, fmt.Errorf("frp service paths are invalid")
	}
	return &FRPService{paths: paths, role: role, probe: probe, process: process}, nil
}

func RunFRPServerService(ctx context.Context, paths store.Paths, probe linuxplatform.ProbeRunner, process FRPProcessRunner) error {
	service, err := NewFRPService(paths, model.RoleGateway, probe, process)
	if err != nil {
		return err
	}
	return service.Run(ctx)
}

func RunFRPClientService(ctx context.Context, paths store.Paths, probe linuxplatform.ProbeRunner, process FRPProcessRunner) error {
	service, err := NewFRPService(paths, model.RoleNode, probe, process)
	if err != nil {
		return err
	}
	return service.Run(ctx)
}

// Run accepts only vpnctl's canonical configuration and an exact pinned frp
// binary before replacing the service process. frp output is discarded because
// tunnel logging is disabled unless a later temporary logging opt-in enables it.
func (service *FRPService) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if service == nil || service.probe == nil || service.process == nil {
		return fmt.Errorf("frp service is incomplete")
	}
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	configPath, binaryPath := frpServicePaths(service.paths, service.role)
	content, err := readFRPServiceFile(configPath, true, maximumFRPConfigBytes, "config")
	if err != nil {
		return err
	}
	if service.role == model.RoleGateway {
		if err := ValidateFRPServerConfig(content); err != nil {
			return fmt.Errorf("validate frp server config: %w", err)
		}
		certificatePath := filepath.Join(service.paths.ConfigDir, "generated", "gateway", FRPServerCertificateName)
		privateKeyPath := filepath.Join(service.paths.ConfigDir, "generated", "gateway", FRPServerPrivateKeyName)
		if _, err := readFRPServiceFile(certificatePath, false, 64<<10, "server certificate"); err != nil {
			return err
		}
		if _, err := readFRPServiceFile(privateKeyPath, true, 64<<10, "server private key"); err != nil {
			return err
		}
	} else {
		if err := ValidateFRPClientConfig(content); err != nil {
			return fmt.Errorf("validate frp client config: %w", err)
		}
		certificatePath := filepath.Join(service.paths.ConfigDir, "generated", "node", FRPServerCertificateName)
		if _, err := readFRPServiceFile(certificatePath, false, 64<<10, "trusted certificate"); err != nil {
			return err
		}
	}
	if err := ValidatePinnedFRPConfig(ctx, service.probe, binaryPath, configPath); err != nil {
		return err
	}
	err = service.process.Run(ctx, binaryPath, []string{"-c", configPath})
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("frp %s process failed", frpRoleName(service.role))
	}
	return fmt.Errorf("frp %s process exited unexpectedly", frpRoleName(service.role))
}

func ValidatePinnedFRPConfig(ctx context.Context, runner linuxplatform.ProbeRunner, binaryPath, configPath string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if runner == nil {
		return fmt.Errorf("frp validation runner is required")
	}
	for name, value := range map[string]string{"binary": binaryPath, "config": configPath} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("frp %s path must be clean and absolute", name)
		}
	}
	version, err := runner.Run(ctx, linuxplatform.ProbeCommand{Name: binaryPath, Args: []string{"--version"}})
	if err != nil {
		return fmt.Errorf("inspect pinned frp version: %w", err)
	}
	if version.ExitCode != 0 || strings.TrimSpace(string(version.Stdout)) != FRPProviderVersion || len(version.Stderr) != 0 {
		return fmt.Errorf("installed frp does not match pinned version %s", FRPProviderVersion)
	}
	validation, err := runner.Run(ctx, linuxplatform.ProbeCommand{Name: binaryPath, Args: []string{"verify", "-c", configPath}})
	if err != nil {
		return fmt.Errorf("validate config with pinned frp: %w", err)
	}
	if validation.ExitCode != 0 {
		return fmt.Errorf("pinned frp rejected config")
	}
	return nil
}

func readFRPServiceFile(path string, rootOnly bool, maximumBytes int64, label string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect frp %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("frp %s must be a regular file", label)
	}
	if rootOnly && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("frp %s must not be accessible by group or other", label)
	}
	if info.Size() <= 0 || info.Size() > maximumBytes {
		return nil, fmt.Errorf("frp %s has invalid size", label)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read frp %s: %w", label, err)
	}
	return content, nil
}

func frpServicePaths(paths store.Paths, role model.Role) (configPath, binaryPath string) {
	if role == model.RoleGateway {
		return filepath.Join(paths.ConfigDir, "generated", "gateway", FRPServerConfigFileName), filepath.Join(paths.Root, FRPServerBinaryRelativePath)
	}
	return filepath.Join(paths.ConfigDir, "generated", "node", FRPClientConfigFileName), filepath.Join(paths.Root, FRPClientBinaryRelativePath)
}

func frpRoleName(role model.Role) string {
	if role == model.RoleGateway {
		return "server"
	}
	return "client"
}

var _ FRPProcessRunner = OSFRPProcessRunner{}
