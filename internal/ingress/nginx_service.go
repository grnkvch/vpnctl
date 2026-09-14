package ingress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"golang.org/x/sys/unix"
)

const (
	NginxServiceUnit       = "nginx.service"
	NginxServiceDropInName = "vpnctl.conf"

	nginxServiceMaximumDropInBytes = 32 << 10
)

var (
	ErrNginxServiceConflict = errors.New("nginx service ownership conflict")
	ErrNginxServiceHealth   = errors.New("nginx service is not active")
)

// NginxServicePlan is a read-only declaration of vpnctl's narrow systemd
// ownership boundary. The distribution unit itself remains package-owned.
type NginxServicePlan struct {
	DropInPath string
	Changed    bool
}

// NginxServiceRemovalPlan binds uninstall to the exact narrow drop-in
// ownership observed before service shutdown. The Ubuntu nginx unit and
// package are deliberately outside this removal boundary.
type NginxServiceRemovalPlan struct {
	DropInPath string
	Present    bool
}

func (plan NginxServiceRemovalPlan) Validate() error {
	if !filepath.IsAbs(plan.DropInPath) || filepath.Clean(plan.DropInPath) != plan.DropInPath ||
		filepath.Base(plan.DropInPath) != NginxServiceDropInName || filepath.Base(filepath.Dir(plan.DropInPath)) != NginxServiceUnit+".d" {
		return fmt.Errorf("nginx service removal plan is invalid")
	}
	return nil
}

// NginxServiceInstallation retains the exact pre-activation service state so
// a failed gateway transaction can restore it. Private fields prevent callers
// from fabricating a rollback receipt.
type NginxServiceInstallation struct {
	mu                  sync.Mutex
	managerRoot         string
	dropInInstalled     bool
	previousEnablement  string
	previousActiveState string
	activated           bool
	finished            bool
}

type NginxServiceManager struct {
	paths  store.Paths
	runner linuxplatform.ProbeRunner
}

func NewNginxServiceManager(paths store.Paths, runner linuxplatform.ProbeRunner) (*NginxServiceManager, error) {
	if runner == nil {
		return nil, fmt.Errorf("nginx service runner is required")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil || paths != want {
		return nil, fmt.Errorf("nginx service paths are invalid")
	}
	return &NginxServiceManager{paths: paths, runner: runner}, nil
}

func NginxServiceDropInPath(paths store.Paths) string {
	return filepath.Join(paths.Root, "etc", "systemd", "system", NginxServiceUnit+".d", NginxServiceDropInName)
}

func RenderNginxServiceDropIn(paths store.Paths) []byte {
	return []byte(fmt.Sprintf(`[Service]
Type=simple
PIDFile=
ExecStartPre=
ExecStart=
ExecStart=%s -p %s/ -c %s
ExecReload=
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=
ExecStop=/bin/kill -QUIT $MAINPID
`, NginxBinaryPath(paths), NginxActiveRoot(paths), NginxMainConfigPath))
}

// Plan inspects only vpnctl's drop-in path. Package/service state is captured
// after package installation by Apply, so a package-supplied unit does not
// invalidate an approved clean-host plan.
func (manager *NginxServiceManager) Plan() (NginxServicePlan, error) {
	if manager == nil || manager.runner == nil {
		return NginxServicePlan{}, fmt.Errorf("nginx service manager is incomplete")
	}
	path := NginxServiceDropInPath(manager.paths)
	present, err := inspectNginxServiceDropIn(path, RenderNginxServiceDropIn(manager.paths))
	if err != nil {
		return NginxServicePlan{}, err
	}
	return NginxServicePlan{DropInPath: path, Changed: !present}, nil
}

func (manager *NginxServiceManager) PlanRemoval() (NginxServiceRemovalPlan, error) {
	plan, err := manager.Plan()
	if err != nil {
		return NginxServiceRemovalPlan{}, err
	}
	result := NginxServiceRemovalPlan{DropInPath: plan.DropInPath, Present: !plan.Changed}
	return result, result.Validate()
}

// RemoveStopped removes only the exact vpnctl drop-in after nginx has been
// stopped. It revalidates the retained plan before mutation and leaves the
// package-owned unit and package installed.
func (manager *NginxServiceManager) RemoveStopped(ctx context.Context, approved NginxServiceRemovalPlan) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil || approved.Validate() != nil {
		return fmt.Errorf("nginx service removal is invalid")
	}
	lock, err := acquireNginxServiceLock(manager.paths)
	if err != nil {
		return err
	}
	defer releaseNginxServiceLock(lock)
	fresh, err := manager.PlanRemoval()
	if err != nil {
		return err
	}
	if fresh != approved {
		return fmt.Errorf("%w: nginx service removal plan changed", ErrNginxServiceConflict)
	}
	if !approved.Present {
		return nil
	}
	if err := os.Remove(approved.DropInPath); err != nil {
		return fmt.Errorf("remove nginx service drop-in: %w", err)
	}
	if err := syncNginxServiceDirectory(filepath.Dir(approved.DropInPath)); err != nil {
		return err
	}
	return manager.systemctl(ctx, "daemon-reload")
}

// Apply atomically publishes only vpnctl's drop-in and reloads systemd. nginx
// remains stopped/masked until Activate, which keeps initial serving atomic.
func (manager *NginxServiceManager) Apply(ctx context.Context, approved NginxServicePlan) (*NginxServiceInstallation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil {
		return nil, fmt.Errorf("nginx service manager is incomplete")
	}
	lock, err := acquireNginxServiceLock(manager.paths)
	if err != nil {
		return nil, err
	}
	defer releaseNginxServiceLock(lock)
	fresh, err := manager.Plan()
	if err != nil {
		return nil, err
	}
	if fresh != approved {
		return nil, fmt.Errorf("%w: nginx service plan changed", ErrNginxServiceConflict)
	}
	enablement, err := manager.serviceState(ctx, "is-enabled")
	if err != nil {
		return nil, err
	}
	active, err := manager.serviceState(ctx, "is-active")
	if err != nil {
		return nil, err
	}
	receipt := &NginxServiceInstallation{
		managerRoot: manager.paths.Root, previousEnablement: enablement, previousActiveState: active,
	}
	if approved.Changed {
		if err := installNginxServiceDropIn(approved.DropInPath, RenderNginxServiceDropIn(manager.paths)); err != nil {
			return nil, err
		}
		receipt.dropInInstalled = true
	}
	if err := manager.systemctl(ctx, "daemon-reload"); err != nil {
		rollbackErr := manager.rollbackDropIn(ctx, receipt)
		return nil, errors.Join(err, rollbackErr)
	}
	return receipt, nil
}

func (manager *NginxServiceManager) Activate(ctx context.Context, installation *NginxServiceInstallation) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := manager.validateInstallation(installation); err != nil {
		return err
	}
	installation.mu.Lock()
	defer installation.mu.Unlock()
	if installation.finished || installation.activated {
		return fmt.Errorf("nginx service installation is already finished or active")
	}
	for _, operation := range [][]string{{"unmask", NginxServiceUnit}, {"enable", NginxServiceUnit}, {"start", NginxServiceUnit}} {
		if err := manager.systemctl(ctx, operation...); err != nil {
			return err
		}
	}
	state, err := manager.serviceState(ctx, "is-active")
	if err != nil {
		return err
	}
	if state != "active" {
		return fmt.Errorf("%w: observed %s", ErrNginxServiceHealth, state)
	}
	installation.activated = true
	return nil
}

func (manager *NginxServiceManager) Commit(installation *NginxServiceInstallation) error {
	if err := manager.validateInstallation(installation); err != nil {
		return err
	}
	installation.mu.Lock()
	defer installation.mu.Unlock()
	if installation.finished || !installation.activated {
		return fmt.Errorf("nginx service installation cannot be committed")
	}
	installation.finished = true
	return nil
}

func (manager *NginxServiceManager) Rollback(ctx context.Context, installation *NginxServiceInstallation) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := manager.validateInstallation(installation); err != nil {
		return err
	}
	installation.mu.Lock()
	defer installation.mu.Unlock()
	if installation.finished {
		return fmt.Errorf("nginx service installation is already finished")
	}
	var result error
	if installation.previousActiveState != "active" {
		result = errors.Join(result, manager.systemctl(ctx, "stop", NginxServiceUnit))
	}
	if !nginxServiceWasEnabled(installation.previousEnablement) {
		result = errors.Join(result, manager.systemctl(ctx, "disable", NginxServiceUnit))
	}
	result = errors.Join(result, manager.rollbackDropIn(ctx, installation))
	if nginxServiceWasMasked(installation.previousEnablement) {
		result = errors.Join(result, manager.systemctl(ctx, "mask", NginxServiceUnit))
	} else {
		result = errors.Join(result, manager.systemctl(ctx, "unmask", NginxServiceUnit))
	}
	if nginxServiceWasEnabled(installation.previousEnablement) {
		result = errors.Join(result, manager.systemctl(ctx, "enable", NginxServiceUnit))
	}
	if installation.previousActiveState == "active" {
		result = errors.Join(result, manager.systemctl(ctx, "start", NginxServiceUnit))
	}
	if result == nil {
		installation.finished = true
	}
	return result
}

func (manager *NginxServiceManager) validateInstallation(installation *NginxServiceInstallation) error {
	if manager == nil || manager.runner == nil || installation == nil || installation.managerRoot != manager.paths.Root {
		return fmt.Errorf("nginx service installation is invalid")
	}
	return nil
}

func (manager *NginxServiceManager) rollbackDropIn(ctx context.Context, installation *NginxServiceInstallation) error {
	var result error
	if installation.dropInInstalled {
		path := NginxServiceDropInPath(manager.paths)
		present, err := inspectNginxServiceDropIn(path, RenderNginxServiceDropIn(manager.paths))
		if err != nil {
			return err
		}
		if !present {
			return fmt.Errorf("%w: owned nginx service drop-in disappeared", ErrNginxServiceConflict)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove nginx service drop-in: %w", err)
		}
		if err := syncNginxServiceDirectory(filepath.Dir(path)); err != nil {
			return err
		}
	}
	result = errors.Join(result, manager.systemctl(ctx, "daemon-reload"))
	return result
}

func (manager *NginxServiceManager) serviceState(ctx context.Context, verb string) (string, error) {
	result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{verb, NginxServiceUnit}})
	if err != nil {
		return "", err
	}
	state := strings.TrimSpace(string(result.Stdout))
	if strings.ContainsAny(state, " \t\r\n\x00") || state == "" {
		return "", fmt.Errorf("systemctl %s returned an invalid nginx state", verb)
	}
	if result.ExitCode != 0 && state != "disabled" && state != "masked" && state != "masked-runtime" && state != "inactive" && state != "failed" && state != "not-found" && state != "unknown" {
		return "", fmt.Errorf("systemctl %s nginx failed with exit code %d", verb, result.ExitCode)
	}
	return state, nil
}

func (manager *NginxServiceManager) systemctl(ctx context.Context, arguments ...string) error {
	result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: arguments})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("systemctl %s failed with exit code %d", strings.Join(arguments, " "), result.ExitCode)
	}
	return nil
}

func inspectNginxServiceDropIn(path string, expected []byte) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || info.Size() <= 0 || info.Size() > nginxServiceMaximumDropInBytes {
		return false, fmt.Errorf("%w: nginx service drop-in is unsafe", ErrNginxServiceConflict)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(content, expected) {
		return false, fmt.Errorf("%w: nginx service drop-in is foreign or changed", ErrNginxServiceConflict)
	}
	return true, nil
}

func installNginxServiceDropIn(path string, content []byte) error {
	directory := filepath.Dir(path)
	parent := filepath.Dir(directory)
	if info, err := os.Lstat(parent); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: systemd unit directory is unsafe", ErrNginxServiceConflict)
	}
	if err := os.Mkdir(directory, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if info, err := os.Lstat(directory); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: nginx service drop-in directory is unsafe", ErrNginxServiceConflict)
	}
	temporary, err := os.CreateTemp(directory, ".vpnctl-service-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: nginx service drop-in appeared during installation", ErrNginxServiceConflict)
		}
		return err
	}
	return syncNginxServiceDirectory(directory)
}

func acquireNginxServiceLock(paths store.Paths) (*os.File, error) {
	if info, err := os.Lstat(paths.RuntimeDir); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("nginx service runtime directory is unsafe")
	}
	path := filepath.Join(paths.RuntimeDir, "nginx-service.lock")
	descriptor, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(descriptor), path)
	if lock == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("open nginx service lock")
	}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 {
		_ = lock.Close()
		return nil, fmt.Errorf("nginx service lock is unsafe")
	}
	if err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock nginx service transaction: %w", err)
	}
	return lock, nil
}

func releaseNginxServiceLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}

func syncNginxServiceDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func nginxServiceWasMasked(state string) bool {
	return state == "masked" || state == "masked-runtime"
}

func nginxServiceWasEnabled(state string) bool {
	return state == "enabled" || state == "enabled-runtime"
}
