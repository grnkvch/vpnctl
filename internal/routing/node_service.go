package routing

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/observability"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type NodeRoutingProcessRunner interface {
	Run(context.Context, string, []string) error
}

type OSNodeRoutingProcessRunner struct{}

func (OSNodeRoutingProcessRunner) Run(ctx context.Context, name string, arguments []string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if name == "" {
		return fmt.Errorf("node routing process name is required")
	}
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

type NodeRoutingService struct {
	paths   store.Paths
	probe   linuxplatform.ProbeRunner
	process NodeRoutingProcessRunner
}

func NewNodeRoutingService(paths store.Paths, probe linuxplatform.ProbeRunner, process NodeRoutingProcessRunner) (*NodeRoutingService, error) {
	if probe == nil {
		return nil, fmt.Errorf("node routing service probe runner is required")
	}
	if process == nil {
		return nil, fmt.Errorf("node routing service process runner is required")
	}
	wantConfigDir := filepath.Join(paths.Root, "etc", "vpnctl")
	wantStateDir := filepath.Join(paths.Root, "var", "lib", "vpnctl")
	if paths.Root == "" || !filepath.IsAbs(paths.Root) || filepath.Clean(paths.Root) != paths.Root ||
		paths.ConfigDir != wantConfigDir || paths.StateDir != wantStateDir {
		return nil, fmt.Errorf("node routing service paths are invalid")
	}
	return &NodeRoutingService{paths: paths, probe: probe, process: process}, nil
}

func RunNodeRoutingService(ctx context.Context, paths store.Paths, probe linuxplatform.ProbeRunner, process NodeRoutingProcessRunner) error {
	service, err := NewNodeRoutingService(paths, probe, process)
	if err != nil {
		return err
	}
	return service.Run(ctx)
}

// Run validates the strict vpnctl schema and exact pinned Mihomo parser before
// entering the long-lived process. Default output is discarded; temporary
// routing/DNS logging remains an explicit later opt-in.
func (service *NodeRoutingService) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if service == nil || service.probe == nil || service.process == nil {
		return fmt.Errorf("node routing service is incomplete")
	}
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	configPath := nodeRoutingConfigPath(service.paths)
	stateDirectory := nodeRoutingStatePath(service.paths)
	binaryPath := nodeRoutingBinaryPath(service.paths)
	content, err := readNodeRoutingServiceConfig(configPath)
	if err != nil {
		return err
	}
	mode, err := nodeRoutingConfigDNSMode(content)
	if err != nil {
		return err
	}
	if err := ValidateNodeRoutingConfig(content, mode); err != nil {
		return fmt.Errorf("validate node routing service config: %w", err)
	}
	if err := validateNodeRoutingStateDirectory(stateDirectory); err != nil {
		return err
	}
	if err := ValidatePinnedNodeRoutingMihomo(ctx, service.probe, binaryPath, stateDirectory, configPath); err != nil {
		return err
	}
	_ = observability.EmitCode(ctx, observability.RoutingServiceStarted)
	err = service.process.Run(ctx, binaryPath, []string{"-d", stateDirectory, "-f", configPath})
	if ctx.Err() != nil {
		_ = observability.EmitCode(context.WithoutCancel(ctx), observability.RoutingServiceStopped)
		return nil
	}
	_ = observability.EmitCode(context.WithoutCancel(ctx), observability.RoutingRuntimeFailed)
	if err != nil {
		return fmt.Errorf("node routing process failed")
	}
	return fmt.Errorf("node routing process exited unexpectedly")
}

func ValidatePinnedNodeRoutingMihomo(ctx context.Context, runner linuxplatform.ProbeRunner, binaryPath, stateDirectory, configPath string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if runner == nil {
		return fmt.Errorf("node routing Mihomo validation runner is required")
	}
	for name, value := range map[string]string{"binary": binaryPath, "state directory": stateDirectory, "config": configPath} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("node routing Mihomo %s path must be clean and absolute", name)
		}
	}
	version, err := runner.Run(ctx, linuxplatform.ProbeCommand{Name: binaryPath, Args: []string{"-v"}})
	if err != nil {
		return fmt.Errorf("inspect node routing Mihomo version: %w", err)
	}
	if version.ExitCode != 0 || !hasExactNodeRoutingVersionToken(string(version.Stdout)+" "+string(version.Stderr), NodeRoutingProviderVersion) {
		return fmt.Errorf("installed node routing Mihomo does not match pinned version %s", NodeRoutingProviderVersion)
	}
	validation, err := runner.Run(ctx, linuxplatform.ProbeCommand{
		Name: binaryPath, Args: []string{"-t", "-d", stateDirectory, "-f", configPath},
	})
	if err != nil {
		return fmt.Errorf("validate node routing config with pinned Mihomo: %w", err)
	}
	if validation.ExitCode != 0 {
		return fmt.Errorf("pinned Mihomo rejected node routing config")
	}
	return nil
}

func hasExactNodeRoutingVersionToken(output, version string) bool {
	for _, field := range strings.FieldsFunc(output, func(character rune) bool {
		return !(character == '.' || character == '-' || character == '_' || character >= '0' && character <= '9' ||
			character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z')
	}) {
		if field == version {
			return true
		}
	}
	return false
}

func readNodeRoutingServiceConfig(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect node routing config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("node routing config must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("node routing config must not be accessible by group or other")
	}
	if info.Size() <= 0 || info.Size() > maximumNodeRoutingConfigBytes {
		return nil, fmt.Errorf("node routing config has invalid size")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read node routing config: %w", err)
	}
	return content, nil
}

func validateNodeRoutingStateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect node routing state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("node routing state path must be a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("node routing state directory must not be accessible by group or other")
	}
	return nil
}

func nodeRoutingConfigDNSMode(content []byte) (RoutingDNSMode, error) {
	var document nodeRoutingDocument
	if err := decodeNodeRoutingYAML(content, &document); err != nil {
		return "", err
	}
	if document.DNS.NameserverPolicy == nil {
		return NodeRoutingDNSDirect, nil
	}
	return NodeRoutingDNSPolicy, nil
}

func nodeRoutingConfigPath(paths store.Paths) string {
	return filepath.Join(paths.ConfigDir, "generated", "node", NodeRoutingConfigFileName)
}

func nodeRoutingStatePath(paths store.Paths) string {
	return filepath.Join(paths.StateDir, NodeRoutingStateRelativePath)
}

func nodeRoutingBinaryPath(paths store.Paths) string {
	return filepath.Join(paths.Root, NodeRoutingBinaryRelativePath)
}
