package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

type UninstallNodeGateway interface {
	RevokeForUninstall(context.Context, model.State) (UninstallNodeRevocation, error)
}

type UninstallWatchdogStore interface {
	TransactionIDs() ([]string, error)
	InitialNetworkSnapshot() (linuxplatform.NetworkSnapshot, error)
}

type SystemUninstallRuntime struct {
	paths      store.Paths
	state      *store.StateStore
	runner     linuxplatform.ProbeRunner
	roles      *linuxplatform.RoleSystemdInstaller
	watchdog   *linuxplatform.WatchdogUnitInstaller
	watchdogDB UninstallWatchdogStore
	network    *linuxplatform.NetworkManager
	dns        *routing.NodeDNSIntegrationManager
	guard      *routing.NodeRoutingGuardManager
	swap       *ManagedSwapLifecycle
	gateway    UninstallNodeGateway
	binaryPath string
}

func NewSystemUninstallRuntime(paths store.Paths, gateway UninstallNodeGateway, watchdogDB UninstallWatchdogStore) (*SystemUninstallRuntime, error) {
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths {
		return nil, fmt.Errorf("uninstall paths do not match the system root")
	}
	runner := linuxplatform.OSProbeRunner{}
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	roles, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, runner)
	if err != nil {
		return nil, err
	}
	watchdog, err := linuxplatform.NewWatchdogUnitInstaller(paths.Root, runner)
	if err != nil {
		return nil, err
	}
	if watchdogDB == nil {
		return nil, fmt.Errorf("uninstall watchdog store is required")
	}
	dns, err := routing.NewNodeDNSIntegrationManager(paths, runner)
	if err != nil {
		return nil, err
	}
	guard, err := routing.NewPersistentNodeRoutingGuardManager(paths, runner)
	if err != nil {
		return nil, err
	}
	swapPlatform, err := linuxplatform.NewManagedSwapManager(paths.Root, paths.StateDir, runner)
	if err != nil {
		return nil, err
	}
	swap, err := NewManagedSwapLifecycle(state, swapPlatform)
	if err != nil {
		return nil, err
	}
	return &SystemUninstallRuntime{
		paths: paths, state: state, runner: runner, roles: roles, watchdog: watchdog, watchdogDB: watchdogDB,
		network: linuxplatform.NewOSNetworkManager(), dns: dns, guard: guard, swap: swap, gateway: gateway,
		binaryPath: linuxplatform.DefaultVPNCTLBinaryPath,
	}, nil
}

func (runtime *SystemUninstallRuntime) Inspect(ctx context.Context, state model.State) (UninstallHostPlan, error) {
	if ctx == nil || runtime == nil || runtime.state == nil {
		return UninstallHostPlan{}, fmt.Errorf("system uninstall runtime is incomplete")
	}
	rolePlan, err := runtime.roles.PlanRemoval(state.Host.Role, runtime.binaryPath)
	if err != nil {
		return UninstallHostPlan{}, err
	}
	plan := UninstallHostPlan{
		StateGeneration: state.Generation,
		Units:           append([]string(nil), rolePlan.PresentUnits...), AuxiliaryUnits: []string{}, GeneratedPaths: []string{}, RuntimePaths: []string{},
		ComponentPaths: []string{}, WatchdogTransactionIDs: []string{}, WatchdogUnitFiles: []string{},
		ManagedSwapOwned: state.Host.ManagedSwap != nil,
	}
	if present, err := validateOwnedUninstallTree(rolePlan.GeneratedRoleDir, true); err != nil {
		return UninstallHostPlan{}, err
	} else if present {
		plan.GeneratedPaths = append(plan.GeneratedPaths, rolePlan.GeneratedRoleDir)
	}
	if state.Host.Role == model.RoleGateway {
		if present, err := validateOwnedUninstallTree(ingress.NginxGeneratedRoot(runtime.paths), false); err != nil {
			return UninstallHostPlan{}, err
		} else if present {
			plan.AuxiliaryUnits = append(plan.AuxiliaryUnits, "nginx.service")
		}
	}
	for _, path := range runtimePathsForRole(runtime.paths, state.Host.Role) {
		present, err := validateOwnedUninstallTree(path, true)
		if err != nil {
			return UninstallHostPlan{}, err
		}
		if present {
			plan.RuntimePaths = append(plan.RuntimePaths, path)
		}
	}
	components, binary, binarySHA256, err := runtime.installedReleaseFiles(ctx, state)
	if err != nil {
		return UninstallHostPlan{}, err
	}
	plan.ComponentPaths, plan.BinaryPath, plan.BinarySHA256 = components, binary, binarySHA256
	if state.Host.Role == model.RoleGateway {
		if _, err := runtime.watchdogDB.InitialNetworkSnapshot(); err != nil {
			return UninstallHostPlan{}, fmt.Errorf("preflight gateway network restoration: %w", err)
		}
		plan.NetworkRestoreRequired = true
		watchdogPlan, err := runtime.watchdog.PlanRemoval(runtime.binaryPath)
		if err != nil {
			return UninstallHostPlan{}, err
		}
		plan.WatchdogUnitFiles = append(plan.WatchdogUnitFiles, watchdogPlan.UnitFiles...)
		plan.WatchdogTransactionIDs, err = runtime.watchdogDB.TransactionIDs()
		if err != nil {
			return UninstallHostPlan{}, err
		}
	} else {
		plan.DNSRestorationRequired, err = runtime.dns.CanRestore(ctx)
		if err != nil {
			return UninstallHostPlan{}, fmt.Errorf("preflight node DNS restoration: %w", err)
		}
		plan.NetworkRestoreRequired, err = runtime.guard.CanRestore(ctx)
		if err != nil {
			return UninstallHostPlan{}, fmt.Errorf("preflight node network restoration: %w", err)
		}
	}
	if state.Host.ManagedSwap != nil {
		status, err := runtime.swap.Status(ctx)
		if err != nil || !status.Healthy {
			return UninstallHostPlan{}, fmt.Errorf("preflight managed swap ownership: unhealthy or drifted")
		}
	}
	for _, values := range [][]string{plan.Units, plan.AuxiliaryUnits, plan.GeneratedPaths, plan.RuntimePaths, plan.ComponentPaths, plan.WatchdogTransactionIDs, plan.WatchdogUnitFiles} {
		sort.Strings(values)
	}
	return plan, plan.Validate(state.Host.Role)
}

func (runtime *SystemUninstallRuntime) RevokeNode(ctx context.Context, state model.State) (UninstallNodeRevocation, error) {
	if runtime == nil || runtime.gateway == nil {
		return UninstallNodeRevocation{}, ErrUninstallGatewayUnavailable
	}
	return runtime.gateway.RevokeForUninstall(ctx, state)
}

func (runtime *SystemUninstallRuntime) StopServices(ctx context.Context, plan UninstallHostPlan) error {
	state, err := runtime.state.Load()
	if err != nil {
		return err
	}
	if state.Generation != plan.StateGeneration {
		return ErrUninstallPlanStale
	}
	rolePlan, err := runtime.roles.PlanRemoval(state.Host.Role, runtime.binaryPath)
	if err != nil || !reflect.DeepEqual(rolePlan.PresentUnits, plan.Units) {
		return ErrUninstallPlanStale
	}
	if state.Host.Role == model.RoleGateway {
		watchdogPlan, err := runtime.watchdog.PlanRemoval(runtime.binaryPath)
		if err != nil || !reflect.DeepEqual(watchdogPlan.UnitFiles, plan.WatchdogUnitFiles) {
			return ErrUninstallPlanStale
		}
		if err := runtime.watchdog.StopInstances(ctx, watchdogPlan, plan.WatchdogTransactionIDs); err != nil {
			return err
		}
	}
	if err := runtime.roles.StopRemoval(ctx, rolePlan); err != nil {
		return err
	}
	for _, unit := range plan.AuxiliaryUnits {
		for _, action := range []string{"stop", "disable"} {
			result, err := runtime.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{action, unit}})
			if err != nil || result.ExitCode != 0 {
				return fmt.Errorf("systemctl %s %s during uninstall", action, unit)
			}
		}
	}
	state, err = runtime.state.Load()
	if err != nil || state.Generation != plan.StateGeneration {
		return ErrUninstallPlanStale
	}
	return nil
}

func (runtime *SystemUninstallRuntime) RestoreDNS(ctx context.Context, plan UninstallHostPlan) (bool, error) {
	if !plan.DNSRestorationRequired {
		return false, nil
	}
	if err := runtime.dns.Restore(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (runtime *SystemUninstallRuntime) RestoreNetwork(ctx context.Context, plan UninstallHostPlan) (bool, error) {
	if !plan.NetworkRestoreRequired {
		return false, nil
	}
	state, err := runtime.state.Load()
	if err != nil {
		return false, err
	}
	if state.Host.Role == model.RoleNode {
		if err := runtime.guard.Restore(ctx); err != nil {
			return false, err
		}
		return true, nil
	}
	snapshot, err := runtime.watchdogDB.InitialNetworkSnapshot()
	if err != nil {
		return false, err
	}
	if err := runtime.network.Restore(ctx, snapshot); err != nil {
		return false, err
	}
	return true, nil
}

func (runtime *SystemUninstallRuntime) DisableManagedSwap(ctx context.Context, plan UninstallHostPlan) (bool, uint64, error) {
	if !plan.ManagedSwapOwned {
		state, err := runtime.state.Load()
		if err != nil {
			return false, 0, err
		}
		return false, state.Generation, nil
	}
	result, err := runtime.swap.Uninstall(ctx)
	return result.Changed, result.Generation, err
}

func (runtime *SystemUninstallRuntime) RemoveManagedRuntime(ctx context.Context, plan UninstallHostPlan) error {
	state, err := runtime.state.Load()
	if err != nil {
		return err
	}
	rolePlan, err := runtime.roles.PlanRemoval(state.Host.Role, runtime.binaryPath)
	if err != nil {
		return err
	}
	if err := runtime.roles.RemoveStopped(ctx, rolePlan); err != nil {
		return err
	}
	if state.Host.Role == model.RoleGateway {
		watchdogPlan, err := runtime.watchdog.PlanRemoval(runtime.binaryPath)
		if err != nil {
			return err
		}
		if err := runtime.watchdog.RemoveTemplates(ctx, watchdogPlan); err != nil {
			return err
		}
	}
	for _, path := range plan.RuntimePaths {
		if _, err := validateOwnedUninstallTree(path, true); err != nil {
			return err
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	components, binary, binarySHA256, err := runtime.installedReleaseFiles(ctx, state)
	if err != nil || binary != plan.BinaryPath || binarySHA256 != plan.BinarySHA256 || !reflect.DeepEqual(components, plan.ComponentPaths) {
		return ErrUninstallPlanStale
	}
	for _, path := range components {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	libexec := filepath.Join(runtime.paths.Root, "usr", "local", "libexec", "vpnctl")
	if err := os.Remove(libexec); err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTEMPTY) {
		return err
	}
	return nil
}

func (runtime *SystemUninstallRuntime) RemoveBinary(ctx context.Context, plan UninstallHostPlan) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("context is required")
	}
	if plan.BinaryPath == "" {
		return false, nil
	}
	physicalBinary := filepath.Join(runtime.paths.Root, strings.TrimPrefix(runtime.binaryPath, "/"))
	if plan.BinaryPath != physicalBinary || !validReleaseSHA256(plan.BinarySHA256) {
		return false, ErrUninstallPlanStale
	}
	digest, err := hashUninstallBinary(ctx, plan.BinaryPath)
	if err != nil || digest != plan.BinarySHA256 {
		return false, ErrUninstallPlanStale
	}
	if err := os.Remove(plan.BinaryPath); err != nil {
		return false, err
	}
	if err := syncUninstallDirectory(filepath.Dir(plan.BinaryPath)); err != nil {
		return true, err
	}
	return true, nil
}

func (runtime *SystemUninstallRuntime) installedReleaseFiles(ctx context.Context, state model.State) ([]string, string, string, error) {
	hasBundled := false
	for _, component := range state.Components.Components {
		hasBundled = hasBundled || component.Bundled
	}
	if !hasBundled {
		return []string{}, "", "", nil
	}
	installer, err := NewReleaseBundleInstaller(runtime.paths.Root, ReleasePlatform{
		OperatingSystem: state.Host.OS, Version: state.Host.OSVersion, Architecture: state.Host.Architecture,
	})
	if err != nil {
		return nil, "", "", err
	}
	bundle := filepath.Join(runtime.paths.Root, strings.TrimPrefix(ReleaseInstalledBundlePath, "/"))
	staged, err := installer.stage(ctx, bundle)
	if err != nil {
		return nil, "", "", fmt.Errorf("verify installed release bundle for uninstall: %w", err)
	}
	defer os.RemoveAll(staged.root)
	if !reflect.DeepEqual(staged.manifest.ComponentManifest, state.Components) {
		return nil, "", "", fmt.Errorf("installed release metadata differs from authoritative state")
	}
	candidates, err := installer.prepareCandidates(ctx, staged, state.Host.Role)
	if err != nil || preflightReleaseCandidates(candidates) != nil {
		return nil, "", "", fmt.Errorf("installed release files drifted before uninstall")
	}
	components := make([]string, 0, len(candidates))
	binary := ""
	binarySHA256 := ""
	physicalBinary := filepath.Join(runtime.paths.Root, strings.TrimPrefix(runtime.binaryPath, "/"))
	for _, candidate := range candidates {
		if _, err := os.Lstat(candidate.target); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if candidate.target == physicalBinary {
			binary = candidate.target
			binarySHA256, err = hashUninstallBinary(ctx, candidate.target)
			if err != nil {
				return nil, "", "", err
			}
		} else {
			components = append(components, candidate.target)
		}
	}
	sort.Strings(components)
	return components, binary, binarySHA256, nil
}

func hashUninstallBinary(ctx context.Context, path string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 || info.Size() <= 0 || info.Size() > MaximumStandaloneVPNCTLBytes {
		return "", fmt.Errorf("uninstall binary is not an owned bounded mode-0755 regular file")
	}
	input, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer input.Close()
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(input, MaximumStandaloneVPNCTLBytes+1))
	if err != nil || written != info.Size() {
		return "", fmt.Errorf("read uninstall binary")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func runtimePathsForRole(paths store.Paths, role model.Role) []string {
	result := []string{paths.RuntimeDir}
	if role == model.RoleGateway {
		result = append(result, ingress.NginxRuntimeDirectory(paths), filepath.Join(paths.StateDir, transport.RestrictedStateRelativePath))
	} else {
		result = append(result, filepath.Join(paths.StateDir, routing.NodeRoutingStateRelativePath))
	}
	sort.Strings(result)
	return result
}

func validateOwnedUninstallTree(path string, allowSpecial bool) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("uninstall target %s is not a real directory", path)
	}
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || current == path {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(current)
			if err != nil || filepath.IsAbs(target) {
				return fmt.Errorf("uninstall target contains unsafe symlink %s", current)
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(current), target))
			relative, err := filepath.Rel(path, resolved)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return fmt.Errorf("uninstall target symlink escapes owner tree: %s", current)
			}
			return nil
		}
		if !info.IsDir() && !info.Mode().IsRegular() && !(allowSpecial && info.Mode()&(os.ModeSocket|os.ModeNamedPipe) != 0) {
			return fmt.Errorf("uninstall target contains unsupported entry %s", current)
		}
		return nil
	})
	return true, err
}
