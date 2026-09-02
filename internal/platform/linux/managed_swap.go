package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	ManagedSwapSizeBytes       uint64 = 1 << 30
	ManagedSwapMemoryThreshold uint64 = 1 << 30
	ManagedSwapDiskReserve     uint64 = 512 << 20
	ManagedSwapLogicalPath            = "/var/lib/vpnctl/swapfile"
	ManagedSwapUnitName               = "vpnctl-managed-swap.service"
)

var (
	ErrManagedSwapConflict = errors.New("managed swap target conflicts with an existing resource")
	ErrManagedSwapPlan     = errors.New("invalid managed swap plan")
)

type ManagedSwapDisposition string

const (
	ManagedSwapOffered             ManagedSwapDisposition = "offered"
	ManagedSwapNotLowMemory        ManagedSwapDisposition = "not_low_memory"
	ManagedSwapExistingAdequate    ManagedSwapDisposition = "existing_swap_adequate"
	ManagedSwapUnknownResources    ManagedSwapDisposition = "resource_capacity_unknown"
	ManagedSwapInsufficientDisk    ManagedSwapDisposition = "insufficient_disk"
	ManagedSwapAlreadyOwnedEnabled ManagedSwapDisposition = "managed_enabled"
	ManagedSwapAlreadyOwnedStopped ManagedSwapDisposition = "managed_stopped"
)

type ManagedSwapPlan struct {
	Disposition   ManagedSwapDisposition
	Offered       bool
	Path          string
	SizeBytes     uint64
	MemoryBytes   uint64
	ExistingBytes uint64
	DiskFreeBytes uint64
	DiskReserve   uint64
	PhysicalPath  string
	PhysicalUnit  string
}

type ManagedSwapStatus struct {
	Owned       bool
	Path        string
	SizeBytes   uint64
	FilePresent bool
	UnitPresent bool
	Enabled     bool
	Active      bool
	Healthy     bool
	Drift       []string
}

type ManagedSwapManager struct {
	stateDir     string
	physicalPath string
	unitDir      string
	unitPath     string
	runner       ProbeRunner
}

func NewManagedSwapManager(root, stateDir string, runner ProbeRunner) (*ManagedSwapManager, error) {
	if runner == nil {
		return nil, fmt.Errorf("managed swap runner is required")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, fmt.Errorf("managed swap paths must be clean and absolute")
	}
	if stateDir != filepath.Join(root, "var", "lib", "vpnctl") {
		return nil, fmt.Errorf("managed swap state directory is outside the system root")
	}
	return &ManagedSwapManager{
		stateDir:     stateDir,
		physicalPath: filepath.Join(stateDir, "swapfile"),
		unitDir:      filepath.Join(root, "etc", "systemd", "system"),
		unitPath:     filepath.Join(root, "etc", "systemd", "system", ManagedSwapUnitName),
		runner:       runner,
	}, nil
}

// Plan is read-only and never adopts an existing path or unit. Unknown
// capacity and insufficient free disk make the optional action unavailable;
// they do not make otherwise valid gateway initialization fail.
func (manager *ManagedSwapManager) Plan(resources HostResources) (ManagedSwapPlan, error) {
	if manager == nil || manager.runner == nil {
		return ManagedSwapPlan{}, fmt.Errorf("managed swap manager is incomplete")
	}
	plan := ManagedSwapPlan{
		Path: ManagedSwapLogicalPath, SizeBytes: ManagedSwapSizeBytes,
		MemoryBytes: resources.MemoryTotalBytes, ExistingBytes: resources.SwapTotalBytes,
		DiskFreeBytes: resources.DiskFreeBytes, DiskReserve: ManagedSwapDiskReserve,
		PhysicalPath: manager.physicalPath, PhysicalUnit: manager.unitPath,
	}
	switch {
	case resources.MemoryTotalBytes == 0 || resources.DiskFreeBytes == 0:
		plan.Disposition = ManagedSwapUnknownResources
		return plan, nil
	case resources.MemoryTotalBytes >= ManagedSwapMemoryThreshold:
		plan.Disposition = ManagedSwapNotLowMemory
		return plan, nil
	case resources.SwapTotalBytes >= ManagedSwapSizeBytes:
		plan.Disposition = ManagedSwapExistingAdequate
		return plan, nil
	case resources.DiskFreeBytes < ManagedSwapSizeBytes+ManagedSwapDiskReserve:
		plan.Disposition = ManagedSwapInsufficientDisk
		return plan, nil
	}
	for _, target := range []string{manager.physicalPath, manager.unitPath} {
		if _, err := os.Lstat(target); err == nil {
			return ManagedSwapPlan{}, fmt.Errorf("%w: %s", ErrManagedSwapConflict, target)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return ManagedSwapPlan{}, fmt.Errorf("inspect managed swap target %s: %w", target, err)
		}
	}
	plan.Disposition = ManagedSwapOffered
	plan.Offered = true
	return plan, nil
}

func (manager *ManagedSwapManager) Apply(ctx context.Context, plan ManagedSwapPlan) (model.ManagedSwap, error) {
	if ctx == nil {
		return model.ManagedSwap{}, fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil {
		return model.ManagedSwap{}, fmt.Errorf("managed swap manager is incomplete")
	}
	if err := manager.validateOfferedPlan(plan); err != nil {
		return model.ManagedSwap{}, err
	}
	if err := validateRealDirectory(manager.stateDir); err != nil {
		return model.ManagedSwap{}, fmt.Errorf("validate managed swap state directory: %w", err)
	}
	stateInfo, err := os.Stat(manager.stateDir)
	if err != nil || stateInfo.Mode().Perm()&0o077 != 0 {
		return model.ManagedSwap{}, fmt.Errorf("managed swap state directory must be root-only")
	}
	if err := validateRealDirectory(manager.unitDir); err != nil {
		return model.ManagedSwap{}, fmt.Errorf("validate managed swap unit directory: %w", err)
	}
	for _, target := range []string{manager.physicalPath, manager.unitPath} {
		if _, err := os.Lstat(target); err == nil {
			return model.ManagedSwap{}, fmt.Errorf("%w: %s", ErrManagedSwapConflict, target)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return model.ManagedSwap{}, err
		}
	}

	file, err := os.OpenFile(manager.physicalPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return model.ManagedSwap{}, fmt.Errorf("create managed swap file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(manager.physicalPath)
		return model.ManagedSwap{}, fmt.Errorf("sync managed swap file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(manager.physicalPath)
		return model.ManagedSwap{}, fmt.Errorf("close managed swap file: %w", err)
	}
	unitInstalled := false
	cleanup := func() {
		if unitInstalled {
			_ = manager.systemctl(context.Background(), "stop", ManagedSwapUnitName)
			_ = manager.systemctl(context.Background(), "disable", ManagedSwapUnitName)
			_ = os.Remove(manager.unitPath)
			_ = manager.systemctl(context.Background(), "daemon-reload")
		}
		_ = os.Remove(manager.physicalPath)
	}
	if err := manager.command(ctx, "fallocate", "--length", fmt.Sprintf("%d", ManagedSwapSizeBytes), manager.physicalPath); err != nil {
		cleanup()
		return model.ManagedSwap{}, err
	}
	if err := os.Chmod(manager.physicalPath, 0o600); err != nil {
		cleanup()
		return model.ManagedSwap{}, fmt.Errorf("set managed swap permissions: %w", err)
	}
	info, err := os.Lstat(manager.physicalPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || uint64(info.Size()) != ManagedSwapSizeBytes {
		cleanup()
		return model.ManagedSwap{}, fmt.Errorf("managed swap allocation did not create an exact mode-0600 %d-byte regular file", ManagedSwapSizeBytes)
	}
	if err := manager.command(ctx, "mkswap", manager.physicalPath); err != nil {
		cleanup()
		return model.ManagedSwap{}, err
	}
	if _, err := installAtomicRoleFile(manager.unitPath, renderManagedSwapUnit(), 0o644); err != nil {
		cleanup()
		return model.ManagedSwap{}, fmt.Errorf("install managed swap unit: %w", err)
	}
	unitInstalled = true
	for _, arguments := range [][]string{{"daemon-reload"}, {"enable", ManagedSwapUnitName}, {"start", ManagedSwapUnitName}} {
		if err := manager.systemctl(ctx, arguments...); err != nil {
			cleanup()
			return model.ManagedSwap{}, err
		}
	}
	return model.ManagedSwap{Path: ManagedSwapLogicalPath, SizeBytes: int64(ManagedSwapSizeBytes), Enabled: true}, nil
}

func (manager *ManagedSwapManager) Status(ctx context.Context, owned *model.ManagedSwap) (ManagedSwapStatus, error) {
	if ctx == nil {
		return ManagedSwapStatus{}, fmt.Errorf("context is required")
	}
	status := ManagedSwapStatus{Drift: []string{}}
	if owned == nil {
		return status, nil
	}
	if err := validateManagedSwapOwnership(*owned); err != nil {
		return ManagedSwapStatus{}, err
	}
	status.Owned = true
	status.Path = owned.Path
	status.SizeBytes = uint64(owned.SizeBytes)
	if info, err := os.Lstat(manager.physicalPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			status.Drift = append(status.Drift, "swap_file_type")
		} else {
			status.FilePresent = true
			if info.Mode().Perm() != 0o600 {
				status.Drift = append(status.Drift, "swap_file_mode")
			}
			if uint64(info.Size()) != ManagedSwapSizeBytes {
				status.Drift = append(status.Drift, "swap_file_size")
			}
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		status.Drift = append(status.Drift, "swap_file_missing")
	} else {
		return ManagedSwapStatus{}, err
	}
	if data, err := readManagedSwapUnit(manager.unitPath); err == nil {
		status.UnitPresent = true
		if !bytes.Equal(data, renderManagedSwapUnit()) {
			status.Drift = append(status.Drift, "swap_unit_content")
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		if owned.Enabled {
			status.Drift = append(status.Drift, "swap_unit_missing")
		}
	} else {
		return ManagedSwapStatus{}, err
	}
	if status.UnitPresent {
		enabled, err := manager.systemctlState(ctx, "is-enabled", ManagedSwapUnitName)
		if err != nil {
			return ManagedSwapStatus{}, err
		}
		active, err := manager.systemctlState(ctx, "is-active", ManagedSwapUnitName)
		if err != nil {
			return ManagedSwapStatus{}, err
		}
		status.Enabled, status.Active = enabled, active
	}
	if owned.Enabled && (!status.Enabled || !status.Active) {
		status.Drift = append(status.Drift, "swap_not_active")
	}
	if !owned.Enabled && (status.Enabled || status.Active) {
		status.Drift = append(status.Drift, "swap_unexpectedly_active")
	}
	status.Healthy = status.FilePresent && len(status.Drift) == 0
	return status, nil
}

// Deactivate removes runtime activation and persistence. uninstall preserves
// the allocation file for recoverability; purge additionally removes it.
func (manager *ManagedSwapManager) Deactivate(ctx context.Context, owned model.ManagedSwap, purge bool) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := validateManagedSwapOwnership(owned); err != nil {
		return err
	}
	unitPresent := false
	if data, err := readManagedSwapUnit(manager.unitPath); err == nil {
		if !bytes.Equal(data, renderManagedSwapUnit()) {
			return fmt.Errorf("%w: managed swap unit content differs", ErrManagedSwapConflict)
		}
		unitPresent = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if unitPresent {
		if err := manager.systemctl(ctx, "stop", ManagedSwapUnitName); err != nil {
			return err
		}
	}
	if unitPresent || owned.Enabled {
		if err := manager.systemctl(ctx, "disable", ManagedSwapUnitName); err != nil {
			return err
		}
	}
	if unitPresent {
		if err := os.Remove(manager.unitPath); err != nil {
			return fmt.Errorf("remove managed swap unit: %w", err)
		}
		if err := syncManagedSwapDirectory(manager.unitDir); err != nil {
			return err
		}
		if err := manager.systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
	}
	active, err := manager.activeSwapPath(ctx)
	if err != nil {
		return err
	}
	if active {
		if err := manager.command(ctx, "swapoff", manager.physicalPath); err != nil {
			return err
		}
	}
	if !purge {
		return nil
	}
	if info, err := os.Lstat(manager.physicalPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: managed swap file is not a regular file", ErrManagedSwapConflict)
		}
		if err := os.Remove(manager.physicalPath); err != nil {
			return fmt.Errorf("remove managed swap file: %w", err)
		}
		return syncManagedSwapDirectory(manager.stateDir)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (manager *ManagedSwapManager) validateOfferedPlan(plan ManagedSwapPlan) error {
	if !plan.Offered || plan.Disposition != ManagedSwapOffered || plan.Path != ManagedSwapLogicalPath ||
		plan.SizeBytes != ManagedSwapSizeBytes || plan.DiskReserve != ManagedSwapDiskReserve ||
		plan.PhysicalPath != manager.physicalPath || plan.PhysicalUnit != manager.unitPath ||
		plan.MemoryBytes == 0 || plan.MemoryBytes >= ManagedSwapMemoryThreshold ||
		plan.ExistingBytes >= ManagedSwapSizeBytes || plan.DiskFreeBytes < ManagedSwapSizeBytes+ManagedSwapDiskReserve {
		return fmt.Errorf("%w: offered plan does not match manager ownership", ErrManagedSwapPlan)
	}
	return nil
}

func validateManagedSwapOwnership(owned model.ManagedSwap) error {
	if owned.Path != ManagedSwapLogicalPath || owned.SizeBytes != int64(ManagedSwapSizeBytes) {
		return fmt.Errorf("%w: state does not identify the fixed vpnctl swap resource", ErrManagedSwapConflict)
	}
	return nil
}

func (manager *ManagedSwapManager) command(ctx context.Context, name string, arguments ...string) error {
	result, err := manager.runner.Run(ctx, ProbeCommand{Name: name, Args: arguments})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		detail := strings.TrimSpace(string(result.Stderr))
		if detail == "" {
			detail = fmt.Sprintf("exit code %d", result.ExitCode)
		}
		return fmt.Errorf("%s: %s", name, detail)
	}
	return nil
}

func (manager *ManagedSwapManager) systemctl(ctx context.Context, arguments ...string) error {
	return manager.command(ctx, "systemctl", arguments...)
}

func (manager *ManagedSwapManager) systemctlState(ctx context.Context, verb, unit string) (bool, error) {
	result, err := manager.runner.Run(ctx, ProbeCommand{Name: "systemctl", Args: []string{verb, unit}})
	if err != nil {
		return false, err
	}
	switch result.ExitCode {
	case 0:
		return true, nil
	case 1, 3, 4:
		return false, nil
	default:
		return false, fmt.Errorf("systemctl %s %s: exit code %d", verb, unit, result.ExitCode)
	}
}

func (manager *ManagedSwapManager) activeSwapPath(ctx context.Context) (bool, error) {
	result, err := manager.runner.Run(ctx, ProbeCommand{Name: "swapon", Args: []string{"--noheadings", "--raw", "--show=NAME"}})
	if err != nil {
		return false, err
	}
	if result.ExitCode != 0 {
		return false, fmt.Errorf("inspect active swap: exit code %d", result.ExitCode)
	}
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if strings.TrimSpace(line) == manager.physicalPath {
			return true, nil
		}
	}
	return false, nil
}

func renderManagedSwapUnit() []byte {
	return []byte(`[Unit]
Description=vpnctl managed swap
After=local-fs.target
ConditionPathIsReadWrite=/var/lib/vpnctl/swapfile

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/swapon /var/lib/vpnctl/swapfile
ExecStop=/usr/sbin/swapoff /var/lib/vpnctl/swapfile
StandardOutput=null
StandardError=null
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/vpnctl
CapabilityBoundingSet=CAP_SYS_ADMIN

[Install]
WantedBy=multi-user.target
`)
}

func readManagedSwapUnit(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: managed swap unit is not a regular file", ErrManagedSwapConflict)
	}
	return os.ReadFile(path)
}

func syncManagedSwapDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
