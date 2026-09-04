package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const (
	v1MigrationRecoveryJournalName = "recovery.json"
	v1MigrationRecoveryMaxBytes    = 64 << 10
)

var ErrV1MigrationTerminal = errors.New("v1 migration already has a terminal recovery action")

type V1MigrationRecoveryAction string

const (
	V1MigrationRecoveryRollback V1MigrationRecoveryAction = "rollback"
	V1MigrationRecoveryAccept   V1MigrationRecoveryAction = "accept"
)

type V1MigrationRecoveryPhase string

const (
	V1MigrationRecoveryServicesStopped  V1MigrationRecoveryPhase = "v2_services_stopped"
	V1MigrationRecoveryNetworkRestored  V1MigrationRecoveryPhase = "pre_migration_network_restored"
	V1MigrationRecoveryV2Removed        V1MigrationRecoveryPhase = "v2_owned_resources_removed"
	V1MigrationRecoverySnapshotRestored V1MigrationRecoveryPhase = "v1_snapshot_restored"
	V1MigrationRecoveryUFWRestored      V1MigrationRecoveryPhase = "v1_ufw_restored"
	V1MigrationRecoveryServiceRestored  V1MigrationRecoveryPhase = "v1_wireguard_service_restored"
	V1MigrationRecoveryPayloadRemoved   V1MigrationRecoveryPhase = "rollback_payload_removed"
)

var v1MigrationRollbackPhaseOrder = []V1MigrationRecoveryPhase{
	V1MigrationRecoveryServicesStopped,
	V1MigrationRecoveryNetworkRestored,
	V1MigrationRecoveryV2Removed,
	V1MigrationRecoverySnapshotRestored,
	V1MigrationRecoveryUFWRestored,
	V1MigrationRecoveryServiceRestored,
	V1MigrationRecoveryPayloadRemoved,
}

var v1MigrationAcceptPhaseOrder = []V1MigrationRecoveryPhase{V1MigrationRecoveryPayloadRemoved}

type V1MigrationRecoveryInput struct {
	MaintenanceRoot string
	WorkspaceRoot   string
	Action          V1MigrationRecoveryAction
	Confirmed       bool
}

type V1MigrationRecoveryResult struct {
	SchemaVersion   int                        `json:"schema_version"`
	MigrationID     string                     `json:"migration_id"`
	Action          V1MigrationRecoveryAction  `json:"action"`
	Status          string                     `json:"status"`
	CompletedPhases []V1MigrationRecoveryPhase `json:"completed_phases"`
	RequiresAction  []string                   `json:"requires_action"`
}

type v1MigrationRecoveryJournal struct {
	SchemaVersion   int                        `json:"schema_version"`
	MigrationID     string                     `json:"migration_id"`
	Action          V1MigrationRecoveryAction  `json:"action"`
	StartedAt       time.Time                  `json:"started_at"`
	CompletedPhases []V1MigrationRecoveryPhase `json:"completed_phases"`
}

// RecoverV1Migration either restores the bounded v1 maintenance package or
// irreversibly accepts a completed v2 migration and removes only that package.
// Creating recovery.json is the terminal choice: rollback and acceptance can
// never race or be selected after one another.
func (driver *SystemV1MigrationDriver) RecoverV1Migration(ctx context.Context, input V1MigrationRecoveryInput) (V1MigrationRecoveryResult, error) {
	if ctx == nil || driver == nil || driver.runner == nil || driver.watchdog == nil || driver.bundles == nil {
		return V1MigrationRecoveryResult{}, fmt.Errorf("v1 migration recovery driver is incomplete")
	}
	if !input.Confirmed {
		return V1MigrationRecoveryResult{}, fmt.Errorf("v1 migration recovery requires explicit confirmation")
	}
	if input.Action != V1MigrationRecoveryRollback && input.Action != V1MigrationRecoveryAccept {
		return V1MigrationRecoveryResult{}, fmt.Errorf("v1 migration recovery action is invalid")
	}
	if !filepath.IsAbs(input.MaintenanceRoot) || filepath.Clean(input.MaintenanceRoot) != input.MaintenanceRoot || input.MaintenanceRoot == string(filepath.Separator) {
		return V1MigrationRecoveryResult{}, fmt.Errorf("maintenance root must be a clean absolute non-root path")
	}
	if err := validateV1MigrationRecoveryRoot(input.MaintenanceRoot); err != nil {
		return V1MigrationRecoveryResult{}, err
	}
	workspaceRoot, err := canonicalV1Root(input.WorkspaceRoot)
	if err != nil {
		return V1MigrationRecoveryResult{}, fmt.Errorf("resolve v1 recovery workspace: %w", err)
	}
	migration, err := loadV1MigrationJournal(input.MaintenanceRoot)
	if err != nil {
		return V1MigrationRecoveryResult{}, err
	}
	systemRoot, err := canonicalV1Root(driver.root)
	if err != nil {
		return V1MigrationRecoveryResult{}, fmt.Errorf("resolve v1 recovery system root: %w", err)
	}
	if workspaceRoot != migration.SourceWorkspace || systemRoot != migration.SourceSystemRoot {
		return V1MigrationRecoveryResult{}, fmt.Errorf("%w: recovery roots differ from the migration source", ErrV1MigrationConflict)
	}
	recovery, err := loadV1MigrationRecoveryJournal(input.MaintenanceRoot)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return V1MigrationRecoveryResult{}, err
	}
	var rollbackSnapshot V1MaintenanceSnapshot
	if recovery == nil {
		if input.Action == V1MigrationRecoveryAccept && !v1MigrationPhaseDone(migration.CompletedPhases, V1MigrationClientsValidated) {
			return V1MigrationRecoveryResult{}, fmt.Errorf("v2 migration must complete client validation before acceptance")
		}
		rollbackSnapshot, err = loadAndVerifyV1MaintenanceSnapshot(filepath.Join(input.MaintenanceRoot, v1MigrationSnapshotName))
		if err != nil {
			return V1MigrationRecoveryResult{}, fmt.Errorf("verify migration rollback package: %w", err)
		}
		candidate := v1MigrationRecoveryJournal{
			SchemaVersion: V1MigrationSchemaVersion, MigrationID: migration.MigrationID,
			Action: input.Action, StartedAt: time.Now().UTC().Truncate(time.Second),
			CompletedPhases: []V1MigrationRecoveryPhase{},
		}
		if input.Action == V1MigrationRecoveryRollback {
			err = driver.preflightV1MigrationRollback(ctx, input.MaintenanceRoot, migration)
		} else {
			err = driver.preflightV1MigrationAcceptance(ctx, input.MaintenanceRoot, migration)
		}
		if err != nil {
			return V1MigrationRecoveryResult{}, fmt.Errorf("preflight v1 migration %s: %w", input.Action, err)
		}
		recovery, err = createOrLoadV1MigrationRecoveryJournal(input.MaintenanceRoot, candidate)
		if err != nil {
			return V1MigrationRecoveryResult{}, err
		}
	}
	if recovery.MigrationID != migration.MigrationID || recovery.Action != input.Action {
		return recovery.result("conflict"), ErrV1MigrationTerminal
	}
	if v1MigrationRecoveryPhaseDone(recovery.CompletedPhases, V1MigrationRecoveryPayloadRemoved) {
		if recovery.Action == V1MigrationRecoveryAccept {
			return recovery.result("accepted"), nil
		}
		return recovery.result("rolled_back"), nil
	}
	if recovery.Action == V1MigrationRecoveryRollback && !v1MigrationRecoveryPhaseDone(recovery.CompletedPhases, V1MigrationRecoveryServiceRestored) {
		rollbackSnapshot, err = loadAndVerifyV1MaintenanceSnapshot(filepath.Join(input.MaintenanceRoot, v1MigrationSnapshotName))
		if err != nil {
			return recovery.result("failed"), fmt.Errorf("verify migration rollback package: %w", err)
		}
	}

	phaseOrder := v1MigrationRollbackPhaseOrder
	if recovery.Action == V1MigrationRecoveryAccept {
		phaseOrder = v1MigrationAcceptPhaseOrder
	}
	runPhase := func(phase V1MigrationRecoveryPhase, effect func() error) error {
		if v1MigrationRecoveryPhaseDone(recovery.CompletedPhases, phase) {
			return nil
		}
		if err := effect(); err != nil {
			return err
		}
		if driver.recoveryHook != nil {
			if err := driver.recoveryHook(phase); err != nil {
				return err
			}
		}
		recovery.CompletedPhases = append(recovery.CompletedPhases, phase)
		return writeV1MigrationRecoveryJournal(input.MaintenanceRoot, *recovery)
	}

	if recovery.Action == V1MigrationRecoveryAccept {
		if err := runPhase(V1MigrationRecoveryPayloadRemoved, func() error {
			return driver.removeV1MigrationRollbackPayload(ctx, input.MaintenanceRoot, false)
		}); err != nil {
			return recovery.result("failed"), err
		}
		return recovery.result("accepted"), nil
	}

	if err := runPhase(V1MigrationRecoveryServicesStopped, func() error {
		return driver.stopV1MigrationV2Services(ctx, migration.WatchdogTransactionID)
	}); err != nil {
		return recovery.result("failed"), err
	}
	if err := runPhase(V1MigrationRecoveryNetworkRestored, func() error {
		if migration.WatchdogTransactionID == "" {
			return nil
		}
		return driver.watchdog.Restore(ctx, migration.WatchdogTransactionID)
	}); err != nil {
		return recovery.result("failed"), err
	}
	if err := runPhase(V1MigrationRecoveryV2Removed, func() error {
		return driver.removeV1MigrationV2Resources(ctx, input.MaintenanceRoot, migration)
	}); err != nil {
		return recovery.result("failed"), err
	}
	if err := runPhase(V1MigrationRecoverySnapshotRestored, func() error {
		return driver.restoreV1MigrationSnapshot(ctx, input.MaintenanceRoot, workspaceRoot)
	}); err != nil {
		return recovery.result("failed"), err
	}
	if err := runPhase(V1MigrationRecoveryUFWRestored, func() error {
		return driver.restoreV1MigrationUFW(ctx, workspaceRoot, migration.SourceUFW)
	}); err != nil {
		return recovery.result("failed"), err
	}
	if err := runPhase(V1MigrationRecoveryServiceRestored, func() error {
		return driver.restoreV1MigrationWireGuardService(ctx, rollbackSnapshot.WireGuardUnit)
	}); err != nil {
		return recovery.result("failed"), err
	}
	if err := runPhase(V1MigrationRecoveryPayloadRemoved, func() error {
		return driver.removeV1MigrationRollbackPayload(ctx, input.MaintenanceRoot, true)
	}); err != nil {
		return recovery.result("failed"), err
	}
	if len(recovery.CompletedPhases) != len(phaseOrder) {
		return recovery.result("failed"), fmt.Errorf("v1 migration recovery phase sequence is incomplete")
	}
	return recovery.result("rolled_back"), nil
}

func (driver *SystemV1MigrationDriver) preflightV1MigrationRollback(ctx context.Context, maintenanceRoot string, migration *v1MigrationJournal) error {
	if migration == nil {
		return fmt.Errorf("migration journal is required")
	}
	recoveryBundle := filepath.Join(maintenanceRoot, v1MigrationRecoveryBundleName)
	if _, err := os.Lstat(recoveryBundle); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: retained v2 recovery bundle is missing", ErrV1MigrationConflict)
		}
		return err
	}
	manifest, err := driver.bundles.PreflightV1MigrationRemoval(
		ctx, recoveryBundle, model.RoleGateway,
		filepath.Join(maintenanceRoot, v1MigrationSnapshotName), driver.binaryPath,
	)
	if err != nil {
		return err
	}
	if manifest.ComponentManifest.VPNCTLVersion != migration.ReleaseVersion {
		return fmt.Errorf("%w: recovery bundle release changed", ErrV1MigrationConflict)
	}
	roles, err := linuxplatform.NewRoleSystemdInstaller(driver.root, driver.paths.ConfigDir, driver.runner)
	if err != nil {
		return err
	}
	if _, err := roles.PlanRemoval(model.RoleGateway, driver.binaryPath); err != nil {
		return err
	}
	watchdogUnits, err := linuxplatform.NewWatchdogUnitInstaller(driver.root, driver.runner)
	if err != nil {
		return err
	}
	if _, err := watchdogUnits.PlanRemoval(driver.binaryPath); err != nil {
		return err
	}
	for _, target := range []struct {
		path         string
		allowSockets bool
	}{
		{driver.paths.ConfigDir, false}, {driver.paths.StateDir, false}, {driver.paths.RuntimeDir, true},
	} {
		if err := validateBoundedV1MigrationOwnedTree(target.path, target.allowSockets); err != nil {
			return err
		}
	}
	return nil
}

func (driver *SystemV1MigrationDriver) preflightV1MigrationAcceptance(ctx context.Context, maintenanceRoot string, migration *v1MigrationJournal) error {
	if migration == nil {
		return fmt.Errorf("migration journal is required")
	}
	recoveryBundle := filepath.Join(maintenanceRoot, v1MigrationRecoveryBundleName)
	manifest, err := driver.bundles.Inspect(ctx, recoveryBundle)
	if err != nil {
		return err
	}
	if manifest.ComponentManifest.VPNCTLVersion != migration.ReleaseVersion {
		return fmt.Errorf("%w: recovery bundle release changed", ErrV1MigrationConflict)
	}
	standardBundle := filepath.Join(driver.root, strings.TrimPrefix(ReleaseInstalledBundlePath, "/"))
	if err := preflightEqualV1MigrationBundle(standardBundle, recoveryBundle); err != nil {
		return err
	}
	return validateBoundedV1MigrationStage(filepath.Join(maintenanceRoot, v1MigrationStageName))
}

func (journal v1MigrationRecoveryJournal) result(status string) V1MigrationRecoveryResult {
	result := V1MigrationRecoveryResult{
		SchemaVersion: V1MigrationSchemaVersion, MigrationID: journal.MigrationID,
		Action: journal.Action, Status: status,
		CompletedPhases: append([]V1MigrationRecoveryPhase(nil), journal.CompletedPhases...),
		RequiresAction:  []string{},
	}
	if status == "rolled_back" {
		result.RequiresAction = append(result.RequiresAction, "validate v1 clients after the restored WireGuard service is active")
	}
	return result
}

func (driver *SystemV1MigrationDriver) stopV1MigrationV2Services(ctx context.Context, transactionID string) error {
	roles, err := linuxplatform.NewRoleSystemdInstaller(driver.root, driver.paths.ConfigDir, driver.runner)
	if err != nil {
		return err
	}
	rolePlan, err := roles.PlanRemoval(model.RoleGateway, driver.binaryPath)
	if err != nil {
		return err
	}
	watchdogUnits, err := linuxplatform.NewWatchdogUnitInstaller(driver.root, driver.runner)
	if err != nil {
		return err
	}
	watchdogPlan, err := watchdogUnits.PlanRemoval(driver.binaryPath)
	if err != nil {
		return err
	}
	if transactionID != "" {
		if err := watchdogUnits.StopInstances(ctx, watchdogPlan, []string{transactionID}); err != nil {
			return err
		}
	}
	return roles.StopRemoval(ctx, rolePlan)
}

func (driver *SystemV1MigrationDriver) removeV1MigrationV2Resources(ctx context.Context, maintenanceRoot string, migration *v1MigrationJournal) error {
	recoveryBundle := filepath.Join(maintenanceRoot, v1MigrationRecoveryBundleName)
	if _, err := os.Lstat(recoveryBundle); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: retained v2 recovery bundle is missing", ErrV1MigrationConflict)
		}
		return err
	}
	manifest, err := driver.bundles.RemoveV1MigrationComponents(
		ctx, recoveryBundle, model.RoleGateway,
		filepath.Join(maintenanceRoot, v1MigrationSnapshotName), driver.binaryPath,
	)
	if err != nil {
		return err
	}
	if manifest.ComponentManifest.VPNCTLVersion != migration.ReleaseVersion {
		return fmt.Errorf("%w: recovery bundle release changed", ErrV1MigrationConflict)
	}
	roles, err := linuxplatform.NewRoleSystemdInstaller(driver.root, driver.paths.ConfigDir, driver.runner)
	if err != nil {
		return err
	}
	rolePlan, err := roles.PlanRemoval(model.RoleGateway, driver.binaryPath)
	if err != nil {
		return err
	}
	if err := roles.RemoveStopped(ctx, rolePlan); err != nil {
		return err
	}
	watchdogUnits, err := linuxplatform.NewWatchdogUnitInstaller(driver.root, driver.runner)
	if err != nil {
		return err
	}
	watchdogPlan, err := watchdogUnits.PlanRemoval(driver.binaryPath)
	if err != nil {
		return err
	}
	if err := watchdogUnits.RemoveTemplates(ctx, watchdogPlan); err != nil {
		return err
	}
	for _, target := range []struct {
		path         string
		allowSockets bool
	}{
		{driver.paths.ConfigDir, false}, {driver.paths.StateDir, false}, {driver.paths.RuntimeDir, true},
	} {
		if err := removeBoundedV1MigrationOwnedTree(target.path, target.allowSockets); err != nil {
			return err
		}
	}
	return nil
}

func removeBoundedV1MigrationOwnedTree(root string, allowSockets bool) error {
	if err := validateBoundedV1MigrationOwnedTree(root, allowSockets); err != nil {
		return err
	}
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return os.RemoveAll(root)
}

func validateBoundedV1MigrationOwnedTree(root string, allowSockets bool) error {
	info, err := os.Lstat(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: v2 rollback target is unsafe", ErrV1MigrationConflict)
	}
	entries := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > v1MigrationMaximumSnapshotFiles*4 {
			return fmt.Errorf("v2 rollback target exceeds the entry bound")
		}
		metadata, err := entry.Info()
		if err != nil || metadata.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("v2 rollback target contains an unsafe entry")
		}
		if metadata.IsDir() || metadata.Mode().IsRegular() || allowSockets && metadata.Mode()&os.ModeSocket != 0 {
			return nil
		}
		return fmt.Errorf("v2 rollback target contains an unsupported entry")
	})
	if err != nil {
		return err
	}
	return nil
}

func (driver *SystemV1MigrationDriver) restoreV1MigrationSnapshot(ctx context.Context, maintenanceRoot, workspaceRoot string) error {
	snapshotRoot := filepath.Join(maintenanceRoot, v1MigrationSnapshotName)
	manifest, err := loadV1MaintenanceSnapshotManifest(snapshotRoot)
	if err != nil {
		return err
	}
	entries := append([]v1MaintenanceSnapshotEntry(nil), manifest.Entries...)
	sort.Slice(entries, func(i, j int) bool {
		leftBinary := strings.HasSuffix(entries[i].Path, "/usr/local/bin/vpnctl")
		rightBinary := strings.HasSuffix(entries[j].Path, "/usr/local/bin/vpnctl")
		if leftBinary != rightBinary {
			return !leftBinary
		}
		return entries[i].Path < entries[j].Path
	})
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		source := filepath.Join(snapshotRoot, filepath.FromSlash(entry.Path))
		var target string
		var targetRoot string
		switch {
		case strings.HasPrefix(entry.Path, "v1-workspace/.vpnctl/"):
			targetRoot = workspaceRoot
			target = filepath.Join(workspaceRoot, filepath.FromSlash(strings.TrimPrefix(entry.Path, "v1-workspace/")))
		case strings.HasPrefix(entry.Path, "v1-system/"):
			if !allowedV1MigrationSystemRestorePath(strings.TrimPrefix(entry.Path, "v1-system/"), driver.binaryPath) {
				return fmt.Errorf("%w: snapshot system target is outside the rollback allowlist", ErrV1MigrationConflict)
			}
			targetRoot = driver.root
			target = filepath.Join(driver.root, filepath.FromSlash(strings.TrimPrefix(entry.Path, "v1-system/")))
		default:
			return fmt.Errorf("%w: snapshot target is outside the bounded roots", ErrV1MigrationConflict)
		}
		content, _, err := readV1RegularFile(ctx, source, v1MigrationMaximumSnapshotBytes)
		if err != nil {
			return err
		}
		if err := restoreV1MigrationFile(targetRoot, target, content, os.FileMode(entry.Mode)); err != nil {
			return err
		}
	}
	return nil
}

func restoreV1MigrationFile(root, target string, content []byte, mode os.FileMode) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: v1 restore target escapes its root", ErrV1MigrationConflict)
	}
	parent := filepath.Dir(target)
	current := root
	for _, part := range strings.Split(filepath.Dir(relative), string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if info, err := os.Lstat(current); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: v1 restore parent is unsafe", ErrV1MigrationConflict)
		}
	}
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: v1 restore target is unsafe", ErrV1MigrationConflict)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".vpnctl-v1-restore-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		return err
	}
	keep = true
	return syncLifecycleDirectory(parent)
}

func allowedV1MigrationSystemRestorePath(relative, binaryPath string) bool {
	relative = filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative)))
	wantedBinary := strings.TrimPrefix(filepath.ToSlash(binaryPath), "/")
	if binaryPath == "" {
		wantedBinary = strings.TrimPrefix(linuxplatform.DefaultVPNCTLBinaryPath, "/")
	}
	if relative == wantedBinary || relative == "etc/sysctl.d/99-vpnctl.conf" || relative == "etc/ufw/ufw.conf" ||
		relative == "etc/ufw/user.rules" || relative == "etc/ufw/user6.rules" {
		return true
	}
	if !strings.HasPrefix(relative, "etc/wireguard/") || !strings.HasSuffix(relative, ".conf") {
		return false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(relative, "etc/wireguard/"), ".conf")
	return v1InterfacePattern.MatchString(name)
}

func (driver *SystemV1MigrationDriver) restoreV1MigrationUFW(ctx context.Context, workspaceRoot string, source V1UFWReport) error {
	if source.Enabled == nil {
		return fmt.Errorf("original UFW state is unavailable")
	}
	action := "disable"
	if *source.Enabled {
		action = "enable"
	}
	result, err := driver.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "ufw", Args: []string{"--force", action}})
	if err != nil || result.ExitCode != 0 {
		return fmt.Errorf("restore v1 UFW %s failed", action)
	}
	inspector, err := NewV1InstallationInspector(workspaceRoot, driver.root)
	if err != nil {
		return err
	}
	inspection, err := inspector.Inspect(ctx)
	if err != nil {
		return err
	}
	defer inspection.Destroy()
	if inspection.Report.UFW.Enabled == nil || *inspection.Report.UFW.Enabled != *source.Enabled ||
		inspection.Report.UFW.ConfigPresent != source.ConfigPresent || !reflect.DeepEqual(inspection.Report.UFW.Rules, source.Rules) {
		return fmt.Errorf("%w: restored v1 UFW state did not verify", ErrV1MigrationConflict)
	}
	return nil
}

func (driver *SystemV1MigrationDriver) restoreV1MigrationWireGuardService(ctx context.Context, source V1MigrationUnitSnapshot) error {
	enableAction := "disable"
	if source.Enabled {
		enableAction = "enable"
	}
	activeAction := "stop"
	if source.Active {
		activeAction = "restart"
	}
	for _, action := range []string{enableAction, activeAction} {
		result, err := driver.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{action, source.Name}})
		if err != nil || result.ExitCode != 0 {
			return fmt.Errorf("restore v1 WireGuard unit action %s failed", action)
		}
	}
	interfaceName := strings.TrimSuffix(strings.TrimPrefix(source.Name, "wg-quick@"), ".service")
	verified, err := inspectV1MigrationWireGuardUnit(ctx, driver.runner, interfaceName)
	if err != nil || verified != source {
		return fmt.Errorf("%w: restored v1 WireGuard unit state did not verify", ErrV1MigrationConflict)
	}
	return nil
}

func (driver *SystemV1MigrationDriver) removeV1MigrationRollbackPayload(ctx context.Context, maintenanceRoot string, rollback bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	stageRoot := filepath.Join(maintenanceRoot, v1MigrationStageName)
	if err := removeBoundedV1MigrationStage(stageRoot); err != nil {
		return err
	}
	recoveryBundle := filepath.Join(maintenanceRoot, v1MigrationRecoveryBundleName)
	standardBundle := filepath.Join(driver.root, strings.TrimPrefix(ReleaseInstalledBundlePath, "/"))
	if rollback {
		if err := removeEqualV1MigrationBundle(standardBundle, recoveryBundle); err != nil {
			return err
		}
	}
	if err := removePrivateV1MigrationFile(recoveryBundle); err != nil {
		return err
	}
	snapshotRoot := filepath.Join(maintenanceRoot, v1MigrationSnapshotName)
	if _, err := os.Lstat(snapshotRoot); err == nil {
		if _, err := loadAndVerifyV1MaintenanceSnapshot(snapshotRoot); err != nil {
			return err
		}
		if err := os.RemoveAll(snapshotRoot); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncLifecycleDirectory(maintenanceRoot)
}

func removeBoundedV1MigrationStage(root string) error {
	if err := validateBoundedV1MigrationStage(root); err != nil {
		return err
	}
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return os.RemoveAll(root)
}

func validateBoundedV1MigrationStage(root string) error {
	info, err := os.Lstat(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: migration stage is unsafe", ErrV1MigrationConflict)
	}
	allowed := map[string]struct{}{"etc": {}, "var": {}, "run": {}}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, ok := allowed[entry.Name()]; !ok {
			return fmt.Errorf("%w: migration stage contains a foreign top-level entry", ErrV1MigrationConflict)
		}
	}
	return validateBoundedV1MigrationOwnedTree(root, true)
}

func removeEqualV1MigrationBundle(target, recovery string) error {
	if _, err := os.Lstat(target); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := preflightEqualV1MigrationBundle(target, recovery); err != nil {
		return err
	}
	if err := os.Remove(target); err != nil {
		return err
	}
	return syncLifecycleDirectory(filepath.Dir(target))
}

func preflightEqualV1MigrationBundle(target, recovery string) error {
	targetInfo, err := os.Lstat(target)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: installed v2 bundle is missing", ErrV1MigrationConflict)
		}
		return err
	}
	if targetInfo.Mode()&os.ModeSymlink != 0 || !targetInfo.Mode().IsRegular() || targetInfo.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: installed v2 bundle is unsafe", ErrV1MigrationConflict)
	}
	recoveryInfo, err := os.Lstat(recovery)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: cannot verify retained v2 bundle before removal", ErrV1MigrationConflict)
	} else if err != nil {
		return err
	}
	if recoveryInfo.Mode()&os.ModeSymlink != 0 || !recoveryInfo.Mode().IsRegular() || recoveryInfo.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: retained v2 bundle is unsafe", ErrV1MigrationConflict)
	}
	equal, err := equalReleaseFiles(target, recovery)
	if err != nil || !equal {
		return fmt.Errorf("%w: retained v2 bundle changed before rollback", ErrV1MigrationConflict)
	}
	return nil
}

func validateV1MigrationRecoveryRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: migration recovery root is unsafe", ErrV1MigrationConflict)
	}
	return nil
}

func removePrivateV1MigrationFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: migration payload file is unsafe", ErrV1MigrationConflict)
	}
	return os.Remove(path)
}

func loadV1MaintenanceSnapshotManifest(root string) (v1MaintenanceSnapshotManifest, error) {
	if _, err := loadAndVerifyV1MaintenanceSnapshot(root); err != nil {
		return v1MaintenanceSnapshotManifest{}, err
	}
	data, _, err := readV1RegularFile(context.Background(), filepath.Join(root, v1MigrationSnapshotManifestName), 64<<10)
	if err != nil {
		return v1MaintenanceSnapshotManifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest v1MaintenanceSnapshotManifest
	if err := decoder.Decode(&manifest); err != nil {
		return v1MaintenanceSnapshotManifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return v1MaintenanceSnapshotManifest{}, fmt.Errorf("snapshot manifest has trailing data")
	}
	return manifest, nil
}

func loadV1MigrationRecoveryJournal(root string) (*v1MigrationRecoveryJournal, error) {
	path := filepath.Join(root, v1MigrationRecoveryJournalName)
	data, metadata, err := readV1RegularFile(context.Background(), path, v1MigrationRecoveryMaxBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fs.ErrNotExist
	}
	if err != nil || metadata.Mode.Perm() != 0o600 {
		return nil, fmt.Errorf("%w: migration recovery journal is unsafe", ErrV1MigrationConflict)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal v1MigrationRecoveryJournal
	if err := decoder.Decode(&journal); err != nil {
		return nil, fmt.Errorf("%w: migration recovery journal is invalid", ErrV1MigrationConflict)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("%w: migration recovery journal has trailing data", ErrV1MigrationConflict)
	}
	if err := validateV1MigrationRecoveryJournal(journal); err != nil {
		return nil, err
	}
	return &journal, nil
}

func writeV1MigrationRecoveryJournal(root string, journal v1MigrationRecoveryJournal) error {
	data, err := marshalV1MigrationRecoveryJournal(journal)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(root, ".recovery-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(root, v1MigrationRecoveryJournalName)); err != nil {
		return err
	}
	keep = true
	return syncLifecycleDirectory(root)
}

func createOrLoadV1MigrationRecoveryJournal(root string, journal v1MigrationRecoveryJournal) (*v1MigrationRecoveryJournal, error) {
	data, err := marshalV1MigrationRecoveryJournal(journal)
	if err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp(root, ".recovery-select-*.tmp")
	if err != nil {
		return nil, err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return nil, err
	}
	if _, err := temporary.Write(data); err != nil {
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	target := filepath.Join(root, v1MigrationRecoveryJournalName)
	if err := os.Link(temporaryPath, target); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return loadV1MigrationRecoveryJournal(root)
		}
		return nil, err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return nil, err
	}
	if err := syncLifecycleDirectory(root); err != nil {
		return nil, err
	}
	copy := journal
	return &copy, nil
}

func marshalV1MigrationRecoveryJournal(journal v1MigrationRecoveryJournal) ([]byte, error) {
	if err := validateV1MigrationRecoveryJournal(journal); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > v1MigrationRecoveryMaxBytes {
		return nil, fmt.Errorf("migration recovery journal is too large")
	}
	return data, nil
}

func validateV1MigrationRecoveryJournal(journal v1MigrationRecoveryJournal) error {
	if journal.SchemaVersion != V1MigrationSchemaVersion || !strings.HasPrefix(journal.MigrationID, "mig-") || len(journal.MigrationID) != 20 ||
		journal.StartedAt.IsZero() || journal.StartedAt.Location() != time.UTC || journal.CompletedPhases == nil {
		return fmt.Errorf("%w: migration recovery journal metadata is invalid", ErrV1MigrationConflict)
	}
	order := v1MigrationRollbackPhaseOrder
	if journal.Action == V1MigrationRecoveryAccept {
		order = v1MigrationAcceptPhaseOrder
	} else if journal.Action != V1MigrationRecoveryRollback {
		return fmt.Errorf("%w: migration recovery action is invalid", ErrV1MigrationConflict)
	}
	position := make(map[V1MigrationRecoveryPhase]int, len(order))
	for index, phase := range order {
		position[phase] = index
	}
	for completedIndex, phase := range journal.CompletedPhases {
		index, found := position[phase]
		if !found || index != completedIndex {
			return fmt.Errorf("%w: migration recovery phases are invalid", ErrV1MigrationConflict)
		}
	}
	return nil
}

func v1MigrationRecoveryPhaseDone(phases []V1MigrationRecoveryPhase, wanted V1MigrationRecoveryPhase) bool {
	for _, phase := range phases {
		if phase == wanted {
			return true
		}
	}
	return false
}
