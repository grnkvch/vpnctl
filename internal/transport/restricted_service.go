package transport

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type RestrictedProcessRunner interface {
	Run(context.Context, string, []string) error
}

type OSRestrictedProcessRunner struct{}

func (OSRestrictedProcessRunner) Run(ctx context.Context, name string, arguments []string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if name == "" {
		return fmt.Errorf("restricted process name is required")
	}
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

type RestrictedGatewayService struct {
	paths   store.Paths
	probe   linuxplatform.ProbeRunner
	process RestrictedProcessRunner
}

func NewRestrictedGatewayService(paths store.Paths, probe linuxplatform.ProbeRunner, process RestrictedProcessRunner) (*RestrictedGatewayService, error) {
	if probe == nil {
		return nil, fmt.Errorf("restricted service probe runner is required")
	}
	if process == nil {
		return nil, fmt.Errorf("restricted service process runner is required")
	}
	wantConfigDir := filepath.Join(paths.Root, "etc", "vpnctl")
	wantStateDir := filepath.Join(paths.Root, "var", "lib", "vpnctl")
	if paths.Root == "" || !filepath.IsAbs(paths.Root) || filepath.Clean(paths.Root) != paths.Root ||
		paths.ConfigDir != wantConfigDir || paths.StateDir != wantStateDir {
		return nil, fmt.Errorf("restricted service paths are invalid")
	}
	return &RestrictedGatewayService{paths: paths, probe: probe, process: process}, nil
}

func RunRestrictedGatewayService(ctx context.Context, paths store.Paths, probe linuxplatform.ProbeRunner, process RestrictedProcessRunner) error {
	service, err := NewRestrictedGatewayService(paths, probe, process)
	if err != nil {
		return err
	}
	return service.Run(ctx)
}

// Run validates both vpnctl's strict schema and the exact pinned Mihomo parser
// before entering the long-lived process. Mihomo output is discarded because
// expanded transport logging is opt-in and disabled by default.
func (service *RestrictedGatewayService) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if service == nil || service.probe == nil || service.process == nil {
		return fmt.Errorf("restricted gateway service is incomplete")
	}
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	configPath := filepath.Join(service.paths.ConfigDir, "generated", "gateway", RestrictedConfigFileName)
	stateDirectory := filepath.Join(service.paths.StateDir, RestrictedStateRelativePath)
	binaryPath := filepath.Join(service.paths.Root, RestrictedBinaryRelativePath)
	content, err := readRestrictedServiceConfig(configPath)
	if err != nil {
		return err
	}
	if err := ValidateGatewayRestrictedConfig(content); err != nil {
		return fmt.Errorf("validate restricted gateway config: %w", err)
	}
	if err := validateRestrictedStateDirectory(stateDirectory); err != nil {
		return err
	}
	if err := ValidatePinnedMihomoConfig(ctx, service.probe, binaryPath, stateDirectory, configPath); err != nil {
		return err
	}
	err = service.process.Run(ctx, binaryPath, []string{"-d", stateDirectory, "-f", configPath})
	if ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("restricted gateway process failed")
	}
	return fmt.Errorf("restricted gateway process exited unexpectedly")
}

func ValidatePinnedMihomoConfig(ctx context.Context, runner linuxplatform.ProbeRunner, binaryPath, stateDirectory, configPath string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if runner == nil {
		return fmt.Errorf("Mihomo validation runner is required")
	}
	for name, value := range map[string]string{"binary": binaryPath, "state directory": stateDirectory, "config": configPath} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("Mihomo %s path must be clean and absolute", name)
		}
	}
	version, err := runner.Run(ctx, linuxplatform.ProbeCommand{Name: binaryPath, Args: []string{"-v"}})
	if err != nil {
		return fmt.Errorf("inspect pinned Mihomo version: %w", err)
	}
	if version.ExitCode != 0 || !hasExactVersionToken(string(version.Stdout)+" "+string(version.Stderr), RestrictedProviderVersion) {
		return fmt.Errorf("installed Mihomo does not match pinned version %s", RestrictedProviderVersion)
	}
	validation, err := runner.Run(ctx, linuxplatform.ProbeCommand{
		Name: binaryPath, Args: []string{"-t", "-d", stateDirectory, "-f", configPath},
	})
	if err != nil {
		return fmt.Errorf("validate restricted config with pinned Mihomo: %w", err)
	}
	if validation.ExitCode != 0 {
		return fmt.Errorf("pinned Mihomo rejected restricted config")
	}
	return nil
}

func hasExactVersionToken(output, version string) bool {
	for _, field := range strings.FieldsFunc(output, func(character rune) bool {
		return !(character == '.' || character == '-' || character == '_' || character >= '0' && character <= '9' || character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z')
	}) {
		if field == version {
			return true
		}
	}
	return false
}

func readRestrictedServiceConfig(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect restricted gateway config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("restricted gateway config must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("restricted gateway config must not be accessible by group or other")
	}
	if info.Size() <= 0 || info.Size() > maximumRestrictedConfigBytes {
		return nil, fmt.Errorf("restricted gateway config has invalid size")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read restricted gateway config: %w", err)
	}
	return content, nil
}

func validateRestrictedStateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect restricted state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("restricted state path must be a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("restricted state directory must not be accessible by group or other")
	}
	return nil
}

var _ RestrictedProcessRunner = OSRestrictedProcessRunner{}
