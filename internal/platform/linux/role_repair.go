package linux

import (
	"bytes"
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
	"strings"
	"syscall"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"golang.org/x/sys/unix"
)

type RoleRepairResourceKind string

const (
	RoleRepairUnit   RoleRepairResourceKind = "unit"
	RoleRepairConfig RoleRepairResourceKind = "config"
)

type RoleRepairUnitTarget struct {
	LoadState   string
	ActiveState string
	SubState    string
	Enablement  string
}

// RoleRepairResource contains internal restore material. It must never be
// serialized into public output; callers expose only its name and hashes.
type RoleRepairResource struct {
	Kind          RoleRepairResourceKind
	Name          string
	Content       []byte
	ContentSHA256 string
	UnitTarget    *RoleRepairUnitTarget
}

// RoleRepairRequest is deliberately action-scoped. Resources retain caller
// order, and RestartUnits names only explicit dependent services for selected
// config changes.
type RoleRepairRequest struct {
	Role         model.Role
	Resources    []RoleRepairResource
	RestartUnits []string
}

type RoleRepairResourceResult struct {
	Kind          RoleRepairResourceKind
	Name          string
	Changed       bool
	ContentSHA256 string
}

type RoleRepairResult struct {
	Resources []RoleRepairResourceResult
}

type roleRepairUnitObservation struct {
	LoadState   string
	ActiveState string
	SubState    string
	Enablement  string
}

type roleRepairFileSnapshot struct {
	resource   RoleRepairResource
	path       string
	mode       fs.FileMode
	beforeMode fs.FileMode
	present    bool
	content    []byte
	changed    bool
}

type roleRepairUnitAttempt struct {
	enablement bool
	runtime    bool
	material   bool
}

type roleRepairUnitMutation struct {
	name   string
	action string
}

// RoleRepairPlan is an opaque in-memory prepared transaction. It retains prior
// selected file bytes only for bounded rollback and has no exported fields.
type RoleRepairPlan struct {
	request   RoleRepairRequest
	files     []roleRepairFileSnapshot
	units     []string
	unitState []roleRepairUnitObservation
}

func (installer *RoleSystemdInstaller) PlanRepair(ctx context.Context, request RoleRepairRequest) (*RoleRepairPlan, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if installer == nil || installer.runner == nil || installer.repairFileWriter == nil {
		return nil, fmt.Errorf("role repair installer is incomplete")
	}
	canonical, err := validateRoleRepairRequest(request)
	if err != nil {
		return nil, err
	}
	plan := &RoleRepairPlan{request: canonical, files: make([]roleRepairFileSnapshot, len(canonical.Resources))}
	keep := false
	defer func() {
		if !keep {
			plan.Destroy()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ownerUID, err := roleRepairDirectoryOwner(installer.root)
	if err != nil {
		return nil, fmt.Errorf("validate repair system root: %w", err)
	}
	if err := validateRoleRepairDirectory(installer.unitDir, ownerUID, false); err != nil {
		return nil, fmt.Errorf("validate repair unit directory: %w", err)
	}
	if err := validateRoleRepairDirectory(installer.configDir, ownerUID, false); err != nil {
		return nil, err
	}
	if err := validateRoleRepairDirectory(installer.configRoot, ownerUID, true); err != nil {
		return nil, err
	}
	roleConfigDir := filepath.Join(installer.configRoot, string(canonical.Role))
	if err := validateRoleRepairDirectory(roleConfigDir, ownerUID, true); err != nil {
		return nil, err
	}

	selectedUnits := make(map[string]struct{})
	selectedUnitSnapshots := make(map[string]roleRepairFileSnapshot)
	for index, resource := range canonical.Resources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path, mode := filepath.Join(roleConfigDir, resource.Name), fs.FileMode(0o600)
		if resource.Kind == RoleRepairUnit {
			path, mode = filepath.Join(installer.unitDir, resource.Name), 0o644
			selectedUnits[resource.Name] = struct{}{}
		}
		snapshot, err := inspectRoleRepairFile(path, mode, resource)
		if err != nil {
			return nil, err
		}
		plan.files[index] = snapshot
		if resource.Kind == RoleRepairUnit {
			selectedUnitSnapshots[resource.Name] = snapshot
		}
	}

	plan.units = make([]string, 0, len(selectedUnits)+len(canonical.RestartUnits))
	for _, resource := range canonical.Resources {
		if resource.Kind == RoleRepairUnit {
			plan.units = append(plan.units, resource.Name)
		}
	}
	plan.units = append(plan.units, canonical.RestartUnits...)
	plan.unitState = make([]roleRepairUnitObservation, len(plan.units))
	for index, name := range plan.units {
		observed, err := installer.observeRoleRepairUnit(ctx, name)
		if err != nil {
			return nil, err
		}
		if _, selected := selectedUnits[name]; selected {
			snapshot := selectedUnitSnapshots[name]
			if snapshot.present && (observed.LoadState == "not-found" || observed.Enablement == "not-found" ||
				(observed.ActiveState != "active" && observed.ActiveState != "inactive")) {
				return nil, fmt.Errorf("selected repair unit %s has unsafe current runtime state", name)
			}
			if snapshot.present && !snapshot.changed && observed.LoadState != snapshot.resource.UnitTarget.LoadState {
				return nil, fmt.Errorf("selected repair unit %s load-state drift requires file repair", name)
			}
			if !snapshot.present && (observed.LoadState != "not-found" || observed.ActiveState != "inactive" || observed.Enablement != "not-found") {
				return nil, fmt.Errorf("missing selected repair unit %s has inconsistent runtime state", name)
			}
		} else if observed.LoadState != "loaded" || observed.ActiveState != "active" {
			return nil, fmt.Errorf("explicit repair restart unit %s is not loaded and active", name)
		}
		plan.unitState[index] = observed
	}
	keep = true
	return plan, nil
}

// ApplyRepair consumes approved on every success or failure path.
func (installer *RoleSystemdInstaller) ApplyRepair(ctx context.Context, approved *RoleRepairPlan) (RoleRepairResult, error) {
	if ctx == nil {
		return RoleRepairResult{}, fmt.Errorf("context is required")
	}
	if installer == nil || installer.runner == nil || installer.repairFileWriter == nil || approved == nil {
		return RoleRepairResult{}, fmt.Errorf("role repair apply is incomplete")
	}
	defer approved.Destroy()
	fresh, err := installer.PlanRepair(ctx, approved.request)
	if err != nil {
		return RoleRepairResult{}, err
	}
	if !equalRoleRepairPlans(fresh, approved) {
		fresh.Destroy()
		return RoleRepairResult{}, fmt.Errorf("role repair plan changed before apply")
	}
	fresh.Destroy()

	changedFiles := make([]bool, len(approved.files))
	attemptedFiles := make([]bool, len(approved.files))
	unitFileChanged := false
	attemptedUnits := make([]roleRepairUnitAttempt, len(approved.units))
	unitMutations := make([]roleRepairUnitMutation, 0, len(approved.units)*2)
	fail := func(cause error) (RoleRepairResult, error) {
		rollbackContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return RoleRepairResult{}, errors.Join(cause, installer.rollbackRoleRepair(
			rollbackContext, approved, attemptedFiles, unitFileChanged, attemptedUnits, unitMutations,
		))
	}
	for index, snapshot := range approved.files {
		if !snapshot.changed {
			continue
		}
		// installAtomicRoleFile can report an error after rename while syncing
		// the parent directory. Mark the file first so that uncertain outcomes
		// are restored as well as confirmed writes.
		attemptedFiles[index] = true
		unitFileChanged = unitFileChanged || snapshot.resource.Kind == RoleRepairUnit
		if snapshot.resource.Kind == RoleRepairUnit {
			approved.markUnitMaterial(attemptedUnits, snapshot.resource.Name)
		}
		changed, err := installer.repairFileWriter(snapshot.path, snapshot.resource.Content, snapshot.mode)
		if err != nil {
			return fail(fmt.Errorf("repair selected %s %s: %w", snapshot.resource.Kind, snapshot.resource.Name, err))
		}
		changedFiles[index] = changed
	}
	if unitFileChanged {
		if err := installer.systemctl(ctx, "daemon-reload"); err != nil {
			unitFileChanged = true
			return fail(err)
		}
		unitFileChanged = true
	}
	for _, resource := range approved.request.Resources {
		if resource.Kind != RoleRepairUnit {
			continue
		}
		before, ok := approved.unitObservation(resource.Name)
		if !ok {
			return fail(fmt.Errorf("selected unit observation is missing"))
		}
		for _, action := range roleRepairUnitActions(before, *resource.UnitTarget, approved.fileChanged(resource.Name)) {
			approved.markUnitAction(attemptedUnits, resource.Name, action)
			unitMutations = append(unitMutations, roleRepairUnitMutation{name: resource.Name, action: action})
			if err := installer.systemctl(ctx, action, resource.Name); err != nil {
				return fail(err)
			}
		}
	}
	configMaterialChanged := approved.configMaterialChanged(attemptedFiles)
	for _, name := range approved.request.RestartUnits {
		if configMaterialChanged {
			approved.markUnitMaterial(attemptedUnits, name)
		}
		approved.markUnitAction(attemptedUnits, name, "restart")
		unitMutations = append(unitMutations, roleRepairUnitMutation{name: name, action: "restart"})
		if err := installer.systemctl(ctx, "restart", name); err != nil {
			return fail(err)
		}
	}
	if err := installer.verifyRoleRepair(ctx, approved); err != nil {
		return fail(err)
	}

	result := RoleRepairResult{Resources: make([]RoleRepairResourceResult, len(approved.request.Resources))}
	for index, resource := range approved.request.Resources {
		changed := changedFiles[index]
		if resource.Kind == RoleRepairUnit {
			before, _ := approved.unitObservation(resource.Name)
			changed = changed || !roleRepairUnitAtTarget(before, *resource.UnitTarget)
		}
		result.Resources[index] = RoleRepairResourceResult{
			Kind: resource.Kind, Name: resource.Name, Changed: changed, ContentSHA256: resource.ContentSHA256,
		}
	}
	return result, nil
}

func validateRoleRepairRequest(request RoleRepairRequest) (RoleRepairRequest, error) {
	if request.Role != model.RoleGateway && request.Role != model.RoleNode {
		return RoleRepairRequest{}, fmt.Errorf("role repair requires gateway or node role")
	}
	if request.Resources == nil || len(request.Resources) == 0 || request.RestartUnits == nil {
		return RoleRepairRequest{}, fmt.Errorf("role repair resources and restart units must be present")
	}
	allowedUnits := make(map[string]struct{})
	for _, name := range RoleUnitNames(request.Role) {
		allowedUnits[name] = struct{}{}
	}
	result := RoleRepairRequest{
		Role:         request.Role,
		Resources:    make([]RoleRepairResource, len(request.Resources)),
		RestartUnits: append(make([]string, 0, len(request.RestartUnits)), request.RestartUnits...),
	}
	keep := false
	defer func() {
		if !keep {
			wipeRoleRepairRequest(&result)
		}
	}()
	seen := make(map[string]struct{}, len(request.Resources))
	selectedUnits := make(map[string]struct{})
	for index, resource := range request.Resources {
		key := string(resource.Kind) + "\x00" + resource.Name
		if _, duplicate := seen[key]; duplicate {
			return RoleRepairRequest{}, fmt.Errorf("role repair resource %s is duplicated", resource.Name)
		}
		seen[key] = struct{}{}
		canonical, err := canonicalRoleRepairResource(resource, allowedUnits)
		if err != nil {
			return RoleRepairRequest{}, err
		}
		if canonical.Kind == RoleRepairUnit {
			selectedUnits[canonical.Name] = struct{}{}
		}
		result.Resources[index] = canonical
	}
	seenRestart := make(map[string]struct{}, len(result.RestartUnits))
	for _, name := range result.RestartUnits {
		if _, allowed := allowedUnits[name]; !allowed {
			return RoleRepairRequest{}, fmt.Errorf("restart unit %q is outside role repair ownership", name)
		}
		if _, selected := selectedUnits[name]; selected {
			return RoleRepairRequest{}, fmt.Errorf("restart unit %q is already a selected unit resource", name)
		}
		if _, duplicate := seenRestart[name]; duplicate {
			return RoleRepairRequest{}, fmt.Errorf("restart unit %q is duplicated", name)
		}
		seenRestart[name] = struct{}{}
	}
	keep = true
	return result, nil
}

func canonicalRoleRepairResource(resource RoleRepairResource, allowedUnits map[string]struct{}) (RoleRepairResource, error) {
	if len(resource.Content) == 0 || len(resource.Content) > maximumRoleConfigBytes {
		return RoleRepairResource{}, fmt.Errorf("role repair resource %s has invalid content size", resource.Name)
	}
	content := append([]byte(nil), resource.Content...)
	keep := false
	defer func() {
		if !keep {
			clear(content)
		}
	}()
	switch resource.Kind {
	case RoleRepairUnit:
		if _, allowed := allowedUnits[resource.Name]; !allowed || resource.UnitTarget == nil {
			return RoleRepairResource{}, fmt.Errorf("unit %q is outside role repair ownership", resource.Name)
		}
		normalized := normalizedText(content)
		clear(content)
		content = normalized
		if err := validateRoleServiceUnit(resource.Name, content); err != nil {
			return RoleRepairResource{}, fmt.Errorf("invalid repair unit %s: %w", resource.Name, err)
		}
		if err := validateRoleRepairUnitTarget(*resource.UnitTarget); err != nil {
			return RoleRepairResource{}, fmt.Errorf("invalid repair unit %s target: %w", resource.Name, err)
		}
	case RoleRepairConfig:
		if !roleConfigNamePattern.MatchString(resource.Name) || filepath.Base(resource.Name) != resource.Name || resource.UnitTarget != nil {
			return RoleRepairResource{}, fmt.Errorf("config %q is outside role repair ownership", resource.Name)
		}
	default:
		return RoleRepairResource{}, fmt.Errorf("unsupported role repair resource kind %q", resource.Kind)
	}
	digest := sha256.Sum256(content)
	if resource.ContentSHA256 != hex.EncodeToString(digest[:]) {
		return RoleRepairResource{}, fmt.Errorf("role repair resource %s material hash mismatch", resource.Name)
	}
	resource.Content = content
	if resource.UnitTarget != nil {
		target := *resource.UnitTarget
		resource.UnitTarget = &target
	}
	keep = true
	return resource, nil
}

func validateRoleRepairUnitTarget(target RoleRepairUnitTarget) error {
	if target.LoadState != "loaded" ||
		(target.ActiveState != "active" && target.ActiveState != "inactive") ||
		(target.Enablement != "enabled" && target.Enablement != "disabled") ||
		!roleRepairSystemdValue(target.SubState) {
		return fmt.Errorf("unsupported systemd target")
	}
	if target.ActiveState == "active" && target.SubState != "running" && target.SubState != "exited" {
		return fmt.Errorf("active unit target must be running or exited")
	}
	if target.ActiveState == "inactive" && target.SubState != "dead" {
		return fmt.Errorf("inactive unit target must be dead")
	}
	return nil
}

func roleRepairSystemdValue(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func inspectRoleRepairFile(path string, mode fs.FileMode, resource RoleRepairResource) (roleRepairFileSnapshot, error) {
	snapshot := roleRepairFileSnapshot{resource: resource, path: path, mode: mode}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		snapshot.changed = true
		return snapshot, nil
	}
	if err != nil {
		return roleRepairFileSnapshot{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximumRoleConfigBytes {
		return roleRepairFileSnapshot{}, fmt.Errorf("role repair target %s is not a bounded regular file", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return roleRepairFileSnapshot{}, fmt.Errorf("role repair target %s must have one filesystem link", path)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return roleRepairFileSnapshot{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return roleRepairFileSnapshot{}, fmt.Errorf("wrap role repair target %s", path)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() < 0 || openedInfo.Size() > maximumRoleConfigBytes {
		return roleRepairFileSnapshot{}, errors.Join(fmt.Errorf("role repair target %s changed identity or size during observation", path), err)
	}
	if stat, ok := openedInfo.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return roleRepairFileSnapshot{}, fmt.Errorf("role repair target %s must retain one filesystem link", path)
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumRoleConfigBytes+1))
	if err != nil {
		return roleRepairFileSnapshot{}, err
	}
	if int64(len(content)) != openedInfo.Size() || len(content) > maximumRoleConfigBytes {
		clear(content)
		return roleRepairFileSnapshot{}, fmt.Errorf("role repair target %s changed size during observation", path)
	}
	snapshot.present = true
	snapshot.beforeMode = info.Mode().Perm()
	snapshot.content = content
	snapshot.changed = info.Mode().Perm() != mode || !bytes.Equal(content, resource.Content)
	return snapshot, nil
}

func roleRepairDirectoryOwner(path string) (uint32, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !ok {
		return 0, fmt.Errorf("role repair directory %s must be a real directory", path)
	}
	return stat.Uid, nil
}

func validateRoleRepairDirectory(path string, ownerUID uint32, private bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !ok || stat.Uid != ownerUID {
		return fmt.Errorf("role repair directory %s must be a same-owner real directory", path)
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("role repair directory %s must be owner-only", path)
	}
	if !private && info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("role repair directory %s must not be group/world writable", path)
	}
	return nil
}

func (installer *RoleSystemdInstaller) observeRoleRepairUnit(ctx context.Context, name string) (roleRepairUnitObservation, error) {
	properties, err := installer.runner.Run(ctx, ProbeCommand{Name: "systemctl", Args: []string{
		"show", "--no-pager", "--property=LoadState", "--property=ActiveState", "--property=SubState", name,
	}})
	if err != nil || properties.ExitCode != 0 {
		return roleRepairUnitObservation{}, errors.Join(fmt.Errorf("observe repair unit %s", name), err)
	}
	values := make(map[string]string, 3)
	for _, raw := range strings.Split(string(properties.Stdout), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || value == "" || values[key] != "" {
			return roleRepairUnitObservation{}, fmt.Errorf("invalid repair unit %s observation", name)
		}
		switch key {
		case "LoadState", "ActiveState", "SubState":
			values[key] = value
		default:
			return roleRepairUnitObservation{}, fmt.Errorf("unexpected repair unit %s observation", name)
		}
	}
	if values["LoadState"] == "" || values["ActiveState"] == "" || values["SubState"] == "" ||
		!roleRepairSystemdValue(values["LoadState"]) || !roleRepairSystemdValue(values["ActiveState"]) ||
		!roleRepairSystemdValue(values["SubState"]) {
		return roleRepairUnitObservation{}, fmt.Errorf("incomplete repair unit %s observation", name)
	}
	enablement, err := installer.runner.Run(ctx, ProbeCommand{Name: "systemctl", Args: []string{"is-enabled", name}})
	if err != nil {
		return roleRepairUnitObservation{}, fmt.Errorf("observe repair unit %s enablement: %w", name, err)
	}
	enabledText := strings.TrimSpace(string(enablement.Stdout))
	if !roleRepairSystemdValue(enabledText) {
		return roleRepairUnitObservation{}, fmt.Errorf("unsupported repair unit %s enablement %q", name, enabledText)
	}
	if (enabledText == "enabled" && enablement.ExitCode != 0) || (enabledText != "enabled" && enablement.ExitCode == 0) {
		return roleRepairUnitObservation{}, fmt.Errorf("inconsistent repair unit %s enablement result", name)
	}
	return roleRepairUnitObservation{
		LoadState: values["LoadState"], ActiveState: values["ActiveState"],
		SubState: values["SubState"], Enablement: enabledText,
	}, nil
}

func roleRepairUnitActions(
	before roleRepairUnitObservation,
	target RoleRepairUnitTarget,
	fileChanged bool,
) []string {
	actions := make([]string, 0, 2)
	if before.Enablement != target.Enablement {
		if target.Enablement == "enabled" {
			actions = append(actions, "enable")
		} else if before.Enablement == "enabled" {
			actions = append(actions, "disable")
		}
	}
	switch {
	case target.ActiveState == "active" && before.ActiveState == "active" &&
		(fileChanged || before.LoadState != target.LoadState || before.SubState != target.SubState):
		actions = append(actions, "restart")
	case target.ActiveState == "active" && before.ActiveState != "active":
		actions = append(actions, "start")
	case target.ActiveState == "inactive" &&
		(before.ActiveState != "inactive" || before.SubState != target.SubState):
		actions = append(actions, "stop")
	}
	return actions
}

func (installer *RoleSystemdInstaller) verifyRoleRepair(ctx context.Context, plan *RoleRepairPlan) error {
	for _, snapshot := range plan.files {
		current, err := inspectRoleRepairFile(snapshot.path, snapshot.mode, snapshot.resource)
		changed := current.changed
		clear(current.content)
		if err != nil || changed {
			return errors.Join(fmt.Errorf("repaired %s %s did not reach target content", snapshot.resource.Kind, snapshot.resource.Name), err)
		}
	}
	for _, resource := range plan.request.Resources {
		if resource.Kind != RoleRepairUnit {
			continue
		}
		observed, err := installer.observeRoleRepairUnit(ctx, resource.Name)
		if err != nil || !roleRepairUnitAtTarget(observed, *resource.UnitTarget) {
			return errors.Join(fmt.Errorf("repaired unit %s did not reach target runtime state", resource.Name), err)
		}
	}
	for _, name := range plan.request.RestartUnits {
		observed, err := installer.observeRoleRepairUnit(ctx, name)
		if err != nil || observed.LoadState != "loaded" || observed.ActiveState != "active" {
			return errors.Join(fmt.Errorf("restarted dependent unit %s is not active", name), err)
		}
	}
	return nil
}

func (installer *RoleSystemdInstaller) rollbackRoleRepair(
	ctx context.Context,
	plan *RoleRepairPlan,
	attemptedFiles []bool,
	unitFileChanged bool,
	attemptedUnits []roleRepairUnitAttempt,
	unitMutations []roleRepairUnitMutation,
) error {
	var result error
	rollbackOrder := plan.roleRepairRollbackOrder(attemptedUnits, unitMutations)
	// A unit that did not exist before repair must be stopped and disabled
	// before its temporary restored file is removed and systemd is reloaded.
	for _, index := range rollbackOrder {
		name := plan.units[index]
		if !attemptedUnits[index].any() || !plan.selectedUnitWasMissing(name) {
			continue
		}
		current, err := installer.observeRoleRepairUnit(ctx, name)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if current.ActiveState != "inactive" {
			result = errors.Join(result, installer.systemctl(ctx, "stop", name))
		}
		if current.Enablement == "enabled" {
			result = errors.Join(result, installer.systemctl(ctx, "disable", name))
		}
	}
	for index := len(plan.files) - 1; index >= 0; index-- {
		if !attemptedFiles[index] {
			continue
		}
		snapshot := plan.files[index]
		if snapshot.present {
			_, err := installer.repairFileWriter(snapshot.path, snapshot.content, snapshot.beforeMode)
			result = errors.Join(result, err)
		} else {
			err := os.Remove(snapshot.path)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				result = errors.Join(result, err)
			}
			result = errors.Join(result, syncRoleRepairDirectory(filepath.Dir(snapshot.path)))
		}
	}
	if unitFileChanged {
		result = errors.Join(result, installer.systemctl(ctx, "daemon-reload"))
	}
	for _, index := range rollbackOrder {
		name := plan.units[index]
		attempt := attemptedUnits[index]
		if !attempt.any() || plan.selectedUnitWasMissing(name) {
			continue
		}
		before := plan.unitState[index]
		current, err := installer.observeRoleRepairUnit(ctx, name)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if current.Enablement != before.Enablement && (attempt.enablement || attempt.material) {
			action := "disable"
			if before.Enablement == "enabled" {
				action = "enable"
			} else if before.Enablement != "disabled" {
				result = errors.Join(result, fmt.Errorf("cannot restore unit %s enablement %s", name, before.Enablement))
				action = ""
			}
			if action != "" {
				result = errors.Join(result, installer.systemctl(ctx, action, name))
			}
		}
		switch {
		case attempt.material && before.LoadState == "loaded" && before.ActiveState == "active":
			action := "restart"
			if current.ActiveState != "active" {
				action = "start"
			}
			result = errors.Join(result, installer.systemctl(ctx, action, name))
		case attempt.runtime && before.ActiveState == "active" && current.ActiveState != "active":
			result = errors.Join(result, installer.systemctl(ctx, "start", name))
		case attempt.runtime && before.ActiveState == "inactive" && current.ActiveState == "failed":
			result = errors.Join(result, installer.systemctl(ctx, "reset-failed", name))
		case attempt.runtime && before.ActiveState == "inactive" && current.ActiveState != "inactive":
			result = errors.Join(result, installer.systemctl(ctx, "stop", name))
		}
	}
	for index, name := range plan.units {
		if !attemptedUnits[index].any() {
			continue
		}
		observed, err := installer.observeRoleRepairUnit(ctx, name)
		if err != nil || !reflect.DeepEqual(observed, plan.unitState[index]) {
			result = errors.Join(result, fmt.Errorf("unit %s did not return to its complete pre-repair runtime state", name), err)
		}
	}
	for index, snapshot := range plan.files {
		if !attemptedFiles[index] {
			continue
		}
		if !snapshot.present {
			if _, err := os.Lstat(snapshot.path); !errors.Is(err, fs.ErrNotExist) {
				result = errors.Join(result, fmt.Errorf("new repair target %s remains after rollback", snapshot.path), err)
			}
			continue
		}
		previous := snapshot.resource
		previous.Content = snapshot.content
		observed, err := inspectRoleRepairFile(snapshot.path, snapshot.beforeMode, previous)
		if err != nil || observed.changed {
			result = errors.Join(result, fmt.Errorf("repair target %s did not return to its pre-repair content and mode", snapshot.path), err)
		}
		clear(observed.content)
	}
	return result
}

func (plan *RoleRepairPlan) roleRepairRollbackOrder(
	attempted []roleRepairUnitAttempt,
	mutations []roleRepairUnitMutation,
) []int {
	order := make([]int, 0, len(plan.units))
	seen := make(map[int]struct{}, len(plan.units))
	appendName := func(name string) {
		for index, candidate := range plan.units {
			if candidate != name || !attempted[index].any() {
				continue
			}
			if _, duplicate := seen[index]; !duplicate {
				seen[index] = struct{}{}
				order = append(order, index)
			}
			return
		}
	}
	for index := len(mutations) - 1; index >= 0; index-- {
		appendName(mutations[index].name)
	}
	for index := len(plan.units) - 1; index >= 0; index-- {
		if attempted[index].any() {
			appendName(plan.units[index])
		}
	}
	return order
}

func (plan *RoleRepairPlan) unitObservation(name string) (roleRepairUnitObservation, bool) {
	for index, candidate := range plan.units {
		if candidate == name {
			return plan.unitState[index], true
		}
	}
	return roleRepairUnitObservation{}, false
}

func (plan *RoleRepairPlan) markUnitAction(attempted []roleRepairUnitAttempt, name, action string) {
	for index, candidate := range plan.units {
		if candidate == name {
			switch action {
			case "enable", "disable":
				attempted[index].enablement = true
			case "start", "stop", "restart", "reset-failed":
				attempted[index].runtime = true
			}
			return
		}
	}
}

func (plan *RoleRepairPlan) markUnitMaterial(attempted []roleRepairUnitAttempt, name string) {
	for index, candidate := range plan.units {
		if candidate == name {
			attempted[index].material = true
			return
		}
	}
}

func (attempt roleRepairUnitAttempt) any() bool {
	return attempt.enablement || attempt.runtime || attempt.material
}

func (plan *RoleRepairPlan) configMaterialChanged(attemptedFiles []bool) bool {
	for index, snapshot := range plan.files {
		if attemptedFiles[index] && snapshot.resource.Kind == RoleRepairConfig {
			return true
		}
	}
	return false
}

func (plan *RoleRepairPlan) fileChanged(name string) bool {
	for _, snapshot := range plan.files {
		if snapshot.resource.Kind == RoleRepairUnit && snapshot.resource.Name == name {
			return snapshot.changed
		}
	}
	return false
}

func (plan *RoleRepairPlan) selectedUnitWasMissing(name string) bool {
	for _, snapshot := range plan.files {
		if snapshot.resource.Kind == RoleRepairUnit && snapshot.resource.Name == name {
			return !snapshot.present
		}
	}
	return false
}

func roleRepairUnitAtTarget(observed roleRepairUnitObservation, target RoleRepairUnitTarget) bool {
	return observed.LoadState == target.LoadState && observed.ActiveState == target.ActiveState &&
		observed.SubState == target.SubState && observed.Enablement == target.Enablement
}

func equalRoleRepairPlans(left, right *RoleRepairPlan) bool {
	return left != nil && right != nil && reflect.DeepEqual(left.request, right.request) &&
		reflect.DeepEqual(left.files, right.files) && reflect.DeepEqual(left.units, right.units) &&
		reflect.DeepEqual(left.unitState, right.unitState)
}

// Destroy wipes retained current and target bytes after the bounded repair
// transaction finishes. It is safe to call repeatedly.
func (plan *RoleRepairPlan) Destroy() {
	if plan == nil {
		return
	}
	for index := range plan.request.Resources {
		clear(plan.request.Resources[index].Content)
		plan.request.Resources[index].Content = nil
	}
	for index := range plan.files {
		clear(plan.files[index].resource.Content)
		clear(plan.files[index].content)
		plan.files[index].resource.Content = nil
		plan.files[index].content = nil
	}
	plan.request = RoleRepairRequest{}
	plan.files = nil
	plan.units = nil
	plan.unitState = nil
}

func wipeRoleRepairRequest(request *RoleRepairRequest) {
	if request == nil {
		return
	}
	for index := range request.Resources {
		clear(request.Resources[index].Content)
		request.Resources[index].Content = nil
	}
	*request = RoleRepairRequest{}
}

func syncRoleRepairDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
