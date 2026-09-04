package tunnel

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"golang.org/x/sys/unix"
)

const (
	FRPClientConfigurationLockName = "tunnel-client.lock"
	frpClientRollbackTimeout       = 5 * time.Second
)

var (
	ErrFRPClientConfigurationConflict = errors.New("tunnel client configuration conflict")
	ErrFRPClientActivation            = errors.New("tunnel client configuration activation failed")
	ErrFRPClientReload                = errors.New("tunnel client reload failed")
	ErrFRPClientRollback              = errors.New("tunnel client rollback failed")
)

type FRPClientReloadRunner interface {
	Reload(context.Context, string, string) error
}

type OSFRPClientReloadRunner struct{}

func (OSFRPClientReloadRunner) Reload(ctx context.Context, binaryPath, configPath string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	command := exec.CommandContext(ctx, binaryPath, "reload", "-c", configPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

type FRPClientConfigurationResult struct {
	Changed              bool
	Initial              bool
	Reloaded             bool
	PreviousMappingCount int
	MappingCount         int
	ConfigHash           string
}

// FRPClientConfigurationManager owns the node's complete generated frpc file.
// It permits dynamic activation only when common connection and identity
// settings are unchanged, leaving transport/credential changes to their
// dedicated workflows.
type FRPClientConfigurationManager struct {
	paths    store.Paths
	provider *FRPProvider
	probe    linuxplatform.ProbeRunner
	reloader FRPClientReloadRunner
}

func NewFRPClientConfigurationManager(
	paths store.Paths,
	provider *FRPProvider,
	probe linuxplatform.ProbeRunner,
	reloader FRPClientReloadRunner,
) (*FRPClientConfigurationManager, error) {
	if provider == nil || probe == nil || reloader == nil {
		return nil, fmt.Errorf("tunnel client configuration dependencies are incomplete")
	}
	wantConfigDir := filepath.Join(paths.Root, "etc", "vpnctl")
	wantStateDir := filepath.Join(paths.Root, "var", "lib", "vpnctl")
	wantRuntimeDir := filepath.Join(paths.Root, "run", "vpnctl")
	if paths.Root == "" || !filepath.IsAbs(paths.Root) || filepath.Clean(paths.Root) != paths.Root ||
		paths.ConfigDir != wantConfigDir || paths.StateDir != wantStateDir || paths.RuntimeDir != wantRuntimeDir {
		return nil, fmt.Errorf("tunnel client configuration paths are invalid")
	}
	return &FRPClientConfigurationManager{paths: paths, provider: provider, probe: probe, reloader: reloader}, nil
}

func (manager *FRPClientConfigurationManager) Apply(ctx context.Context, request RenderRequest) (FRPClientConfigurationResult, error) {
	if ctx == nil {
		return FRPClientConfigurationResult{}, fmt.Errorf("context is required")
	}
	if manager == nil || manager.provider == nil || manager.probe == nil || manager.reloader == nil {
		return FRPClientConfigurationResult{}, fmt.Errorf("tunnel client configuration manager is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return FRPClientConfigurationResult{}, err
	}
	candidate, err := manager.provider.Render(ctx, request)
	if err != nil {
		return FRPClientConfigurationResult{}, fmt.Errorf("render tunnel client configuration: %w", err)
	}
	if err := manager.provider.Validate(ctx, candidate); err != nil {
		return FRPClientConfigurationResult{}, fmt.Errorf("validate tunnel client candidate: %w", err)
	}
	frpCandidate, ok := candidate.(FRPCandidate)
	if !ok || frpCandidate.Descriptor().HostRole != model.RoleNode {
		return FRPClientConfigurationResult{}, fmt.Errorf("tunnel client candidate has the wrong role")
	}
	nextContent := frpCandidate.Bytes()
	defer clear(nextContent)
	nextDocument, err := parseFRPClientConfig(nextContent)
	if err != nil {
		return FRPClientConfigurationResult{}, fmt.Errorf("parse tunnel client candidate: %w", err)
	}
	result := FRPClientConfigurationResult{
		MappingCount: len(nextDocument.Mappings), ConfigHash: frpCandidate.Descriptor().ConfigHash,
	}
	if err := ensureFRPClientOwnedDirectories(manager.paths); err != nil {
		return FRPClientConfigurationResult{}, err
	}
	lock, err := acquireFRPClientConfigurationLock(ctx, manager.paths)
	if err != nil {
		return FRPClientConfigurationResult{}, err
	}
	defer releaseFRPClientConfigurationLock(lock)

	configPath, binaryPath := frpServicePaths(manager.paths, model.RoleNode)
	backupPath := configPath + ".previous"
	if _, err := os.Lstat(backupPath); err == nil {
		return FRPClientConfigurationResult{}, fmt.Errorf("%w: a previous tunnel client snapshot requires reconciliation", ErrFRPClientConfigurationConflict)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return FRPClientConfigurationResult{}, fmt.Errorf("inspect tunnel client rollback snapshot: %w", err)
	}

	currentContent, currentPresent, err := readCurrentFRPClientConfiguration(configPath)
	if err != nil {
		return FRPClientConfigurationResult{}, err
	}
	defer clear(currentContent)
	if currentPresent {
		currentDocument, err := parseFRPClientConfig(currentContent)
		if err != nil {
			return FRPClientConfigurationResult{}, fmt.Errorf("validate current tunnel client configuration: %w", err)
		}
		result.PreviousMappingCount = len(currentDocument.Mappings)
		if err := validateFRPClientMappingOnlyChange(currentDocument, nextDocument); err != nil {
			return FRPClientConfigurationResult{}, err
		}
		if bytes.Equal(currentContent, nextContent) {
			return result, nil
		}
	}

	stagedPath, err := stageFRPClientConfiguration(configPath, nextContent)
	if err != nil {
		return FRPClientConfigurationResult{}, err
	}
	defer func() {
		if stagedPath != "" {
			_ = os.Remove(stagedPath)
		}
	}()
	if err := ValidatePinnedFRPConfig(ctx, manager.probe, binaryPath, stagedPath); err != nil {
		return FRPClientConfigurationResult{}, fmt.Errorf("validate staged tunnel client configuration")
	}

	if !currentPresent {
		if err := activateStagedFRPClientConfiguration(stagedPath, configPath); err != nil {
			_ = removeFRPClientConfiguration(configPath)
			return FRPClientConfigurationResult{}, errors.Join(ErrFRPClientActivation, err)
		}
		stagedPath = ""
		result.Changed = true
		result.Initial = true
		return result, nil
	}

	if err := writeAtomicFRPClientConfiguration(backupPath, currentContent); err != nil {
		return FRPClientConfigurationResult{}, fmt.Errorf("persist tunnel client rollback snapshot: %w", err)
	}
	if err := activateStagedFRPClientConfiguration(stagedPath, configPath); err != nil {
		return FRPClientConfigurationResult{}, manager.rollback(currentContent, configPath, backupPath, binaryPath, ErrFRPClientActivation)
	}
	stagedPath = ""
	if err := manager.reloader.Reload(ctx, binaryPath, configPath); err != nil {
		return FRPClientConfigurationResult{}, manager.rollback(currentContent, configPath, backupPath, binaryPath, ErrFRPClientReload)
	}
	if err := removeFRPClientConfiguration(backupPath); err != nil {
		return FRPClientConfigurationResult{}, manager.rollback(currentContent, configPath, backupPath, binaryPath, fmt.Errorf("finalize tunnel client reload"))
	}
	result.Changed = true
	result.Reloaded = true
	return result, nil
}

func (manager *FRPClientConfigurationManager) rollback(currentContent []byte, configPath, backupPath, binaryPath string, cause error) error {
	rollbackContext, cancel := context.WithTimeout(context.Background(), frpClientRollbackTimeout)
	defer cancel()
	if err := writeAtomicFRPClientConfiguration(configPath, currentContent); err != nil {
		return errors.Join(cause, ErrFRPClientRollback)
	}
	if err := manager.reloader.Reload(rollbackContext, binaryPath, configPath); err != nil {
		return errors.Join(cause, ErrFRPClientRollback)
	}
	if err := removeFRPClientConfiguration(backupPath); err != nil {
		return errors.Join(cause, ErrFRPClientRollback)
	}
	return cause
}

func validateFRPClientMappingOnlyChange(current, next frpClientDocument) error {
	if current.NodeID != next.NodeID || current.CredentialGeneration != next.CredentialGeneration ||
		current.ServerEndpoint != next.ServerEndpoint || current.CertificatePath != next.CertificatePath ||
		subtle.ConstantTimeCompare([]byte(current.TunnelCredential), []byte(next.TunnelCredential)) != 1 {
		return fmt.Errorf("%w: dynamic reload may change mappings only", ErrFRPClientConfigurationConflict)
	}
	return nil
}

func ensureFRPClientOwnedDirectories(paths store.Paths) error {
	if err := validateFRPClientDirectory(paths.ConfigDir, true); err != nil {
		return fmt.Errorf("validate vpnctl config directory: %w", err)
	}
	generated := filepath.Join(paths.ConfigDir, "generated")
	if err := ensureFRPClientDirectory(generated); err != nil {
		return err
	}
	if err := ensureFRPClientDirectory(filepath.Join(generated, "node")); err != nil {
		return err
	}
	if err := ensureFRPClientDirectory(paths.RuntimeDir); err != nil {
		return err
	}
	return nil
}

func ensureFRPClientDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create tunnel client directory: %w", err)
	}
	return validateFRPClientDirectory(path, true)
}

func validateFRPClientDirectory(path string, rootOnly bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("tunnel client path %s must be a real directory", path)
	}
	if rootOnly && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("tunnel client directory %s must be root-only", path)
	}
	return nil
}

func acquireFRPClientConfigurationLock(ctx context.Context, paths store.Paths) (*os.File, error) {
	path := filepath.Join(paths.RuntimeDir, FRPClientConfigurationLockName)
	descriptor, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open tunnel client configuration lock: %w", err)
	}
	lock := os.NewFile(uintptr(descriptor), path)
	if lock == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("open tunnel client configuration lock")
	}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 {
		_ = lock.Close()
		return nil, fmt.Errorf("tunnel client configuration lock is unsafe")
	}
	for {
		err = unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = lock.Close()
			return nil, fmt.Errorf("lock tunnel client configuration: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = lock.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func releaseFRPClientConfigurationLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}

func readCurrentFRPClientConfiguration(path string) ([]byte, bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, fmt.Errorf("inspect tunnel client configuration: %w", err)
	}
	content, err := readFRPServiceFile(path, true, maximumFRPConfigBytes, "client config")
	if err != nil {
		return nil, false, err
	}
	return content, true, nil
}

func stageFRPClientConfiguration(target string, content []byte) (string, error) {
	directory := filepath.Dir(target)
	temporary, err := os.CreateTemp(directory, ".vpnctl-tunnel-client-*.next")
	if err != nil {
		return "", fmt.Errorf("create staged tunnel client configuration: %w", err)
	}
	path := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := temporary.Write(content); err != nil {
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	keep = true
	return path, nil
}

func activateStagedFRPClientConfiguration(stagedPath, targetPath string) error {
	if filepath.Dir(stagedPath) != filepath.Dir(targetPath) {
		return fmt.Errorf("staged tunnel client configuration is on a different filesystem")
	}
	if err := os.Rename(stagedPath, targetPath); err != nil {
		return fmt.Errorf("activate tunnel client configuration: %w", err)
	}
	if err := syncFRPClientDirectory(filepath.Dir(targetPath)); err != nil {
		return fmt.Errorf("sync tunnel client configuration: %w", err)
	}
	return nil
}

func writeAtomicFRPClientConfiguration(path string, content []byte) error {
	staged, err := stageFRPClientConfiguration(path, content)
	if err != nil {
		return err
	}
	defer os.Remove(staged)
	return activateStagedFRPClientConfiguration(staged, path)
}

func removeFRPClientConfiguration(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncFRPClientDirectory(filepath.Dir(path))
}

func syncFRPClientDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

var _ FRPClientReloadRunner = OSFRPClientReloadRunner{}
