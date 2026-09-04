package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func (runtime *SystemUninstallRuntime) InspectPurge(ctx context.Context, state model.State, includeBackups bool) (PurgeHostPlan, error) {
	if ctx == nil || runtime == nil || runtime.state == nil {
		return PurgeHostPlan{}, fmt.Errorf("system purge runtime is incomplete")
	}
	if err := state.Validate(); err != nil {
		return PurgeHostPlan{}, err
	}
	if _, err := validateOwnedUninstallTree(runtime.paths.ConfigDir, true); err != nil {
		return PurgeHostPlan{}, fmt.Errorf("preflight purge config ownership: %w", err)
	}
	if _, err := validateOwnedUninstallTree(runtime.paths.StateDir, false); err != nil {
		return PurgeHostPlan{}, fmt.Errorf("preflight purge state ownership: %w", err)
	}
	archives, err := inspectManagedBackupArchives(runtime.paths.BackupsDir)
	if err != nil {
		return PurgeHostPlan{}, err
	}
	plan := PurgeHostPlan{
		StateGeneration: state.Generation, ConfigDir: runtime.paths.ConfigDir, StateDir: runtime.paths.StateDir,
		BackupsDir: runtime.paths.BackupsDir, IncludeBackups: includeBackups, BackupArchives: archives,
	}
	return plan, plan.Validate()
}

func (runtime *SystemUninstallRuntime) PurgeManagedSwap(ctx context.Context, plan UninstallHostPlan) (bool, error) {
	if !plan.ManagedSwapOwned {
		return false, nil
	}
	result, err := runtime.swap.Purge(ctx)
	return result.Changed, err
}

func (runtime *SystemUninstallRuntime) RemovePurgedData(ctx context.Context, plan PurgeHostPlan) (bool, bool, error) {
	if ctx == nil {
		return false, false, fmt.Errorf("context is required")
	}
	if err := plan.Validate(); err != nil {
		return false, false, err
	}
	if plan.ConfigDir != runtime.paths.ConfigDir || plan.StateDir != runtime.paths.StateDir || plan.BackupsDir != runtime.paths.BackupsDir {
		return false, false, ErrUninstallPlanStale
	}
	state, err := runtime.state.Load()
	if err != nil || state.Generation != plan.StateGeneration {
		return false, false, ErrUninstallPlanStale
	}
	fresh, err := runtime.InspectPurge(ctx, state, plan.IncludeBackups)
	if err != nil || !reflect.DeepEqual(fresh, plan) {
		return false, false, ErrUninstallPlanStale
	}
	if err := os.RemoveAll(plan.ConfigDir); err != nil {
		return false, false, err
	}
	if err := syncUninstallDirectory(filepath.Dir(plan.ConfigDir)); err != nil {
		return false, false, err
	}
	entries, err := os.ReadDir(plan.StateDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, false, err
	}
	for _, entry := range entries {
		path := filepath.Join(plan.StateDir, entry.Name())
		if !plan.IncludeBackups && plan.BackupArchives > 0 && path == plan.BackupsDir {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return true, false, err
		}
	}
	backupsRemoved := plan.IncludeBackups && plan.BackupArchives > 0
	if plan.IncludeBackups || plan.BackupArchives == 0 {
		if err := os.Remove(plan.StateDir); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return true, backupsRemoved, err
		}
	}
	if err := syncUninstallDirectory(filepath.Dir(plan.StateDir)); err != nil {
		return true, backupsRemoved, err
	}
	return true, backupsRemoved, nil
}

func inspectManagedBackupArchives(path string) (int, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return 0, fmt.Errorf("managed backup path is not a real directory")
	}
	count := 0
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || current == path {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("managed backup path contains an unsupported entry")
		}
		if info.Mode().IsRegular() {
			count++
		}
		return nil
	})
	return count, err
}

func syncUninstallDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
