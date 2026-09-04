package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	maximumRoleUnitBytes   = 256 << 10
	maximumRoleConfigBytes = 8 << 20
)

var (
	ErrInvalidRoleInstallation = errors.New("invalid role-scoped systemd installation")
	roleConfigNamePattern      = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	roleUnitCatalog            = map[string]map[model.Role]struct{}{
		"vpnctl-controller.service":    {model.RoleGateway: {}},
		"vpnctl-standard.service":      {model.RoleGateway: {}, model.RoleNode: {}},
		"vpnctl-restricted.service":    {model.RoleGateway: {}},
		"vpnctl-dns.service":           {model.RoleGateway: {}},
		"vpnctl-tunnel-server.service": {model.RoleGateway: {}},
		"vpnctl-routing-guard.service": {model.RoleNode: {}},
		"vpnctl-routing.service":       {model.RoleNode: {}},
		"vpnctl-tunnel-client.service": {model.RoleNode: {}},
	}
)

type RoleUnitFile struct {
	Name    string
	Content []byte
	Enable  bool
	Start   bool
}

type RoleConfigFile struct {
	Name    string
	Content []byte
}

type RoleInstallationRequest struct {
	Role    model.Role
	Units   []RoleUnitFile
	Configs []RoleConfigFile
}

type RoleInstallationPlan struct {
	Role          model.Role
	UnitFiles     []string
	ConfigFiles   []string
	UnitsToEnable []string
	UnitsToStart  []string
}

type RoleInstallationResult struct {
	Plan         RoleInstallationPlan
	ChangedFiles []string
}

type RoleRemovalPlan struct {
	Role             model.Role
	BinaryPath       string
	UnitFiles        []string
	PresentUnits     []string
	GeneratedRoleDir string
}

type RoleSystemdInstaller struct {
	configDir  string
	unitDir    string
	configRoot string
	runner     ProbeRunner
}

func NewRoleSystemdInstaller(root, configDir string, runner ProbeRunner) (*RoleSystemdInstaller, error) {
	if runner == nil {
		return nil, fmt.Errorf("role installer runner is required")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!filepath.IsAbs(configDir) || filepath.Clean(configDir) != configDir {
		return nil, fmt.Errorf("role installer paths must be clean and absolute")
	}
	if configDir != filepath.Join(root, "etc", "vpnctl") {
		return nil, fmt.Errorf("role installer config directory is outside the system root")
	}
	return &RoleSystemdInstaller{
		configDir: configDir, unitDir: filepath.Join(root, "etc", "systemd", "system"),
		configRoot: filepath.Join(configDir, "generated"), runner: runner,
	}, nil
}

func (installer *RoleSystemdInstaller) Plan(request RoleInstallationRequest) (RoleInstallationPlan, error) {
	if installer == nil || installer.runner == nil {
		return RoleInstallationPlan{}, fmt.Errorf("role installer is incomplete")
	}
	if request.Role != model.RoleGateway && request.Role != model.RoleNode {
		return RoleInstallationPlan{}, fmt.Errorf("%w: unsupported role %q", ErrInvalidRoleInstallation, request.Role)
	}
	if request.Units == nil || request.Configs == nil {
		return RoleInstallationPlan{}, fmt.Errorf("%w: units and configs must be present as arrays", ErrInvalidRoleInstallation)
	}
	if len(request.Units) == 0 {
		return RoleInstallationPlan{}, fmt.Errorf("%w: at least one unit is required", ErrInvalidRoleInstallation)
	}
	plan := RoleInstallationPlan{Role: request.Role, UnitFiles: []string{}, ConfigFiles: []string{}, UnitsToEnable: []string{}, UnitsToStart: []string{}}
	seenUnits := make(map[string]struct{}, len(request.Units))
	for _, unit := range request.Units {
		roles, known := roleUnitCatalog[unit.Name]
		_, allowed := roles[request.Role]
		if !known || !allowed {
			return RoleInstallationPlan{}, fmt.Errorf("%w: unit %q is not owned by role %s", ErrInvalidRoleInstallation, unit.Name, request.Role)
		}
		if _, duplicate := seenUnits[unit.Name]; duplicate {
			return RoleInstallationPlan{}, fmt.Errorf("%w: duplicate unit %q", ErrInvalidRoleInstallation, unit.Name)
		}
		seenUnits[unit.Name] = struct{}{}
		if unit.Start && !unit.Enable {
			return RoleInstallationPlan{}, fmt.Errorf("%w: started unit %q must also be enabled", ErrInvalidRoleInstallation, unit.Name)
		}
		if err := validateRoleServiceUnit(unit.Name, unit.Content); err != nil {
			return RoleInstallationPlan{}, fmt.Errorf("%w: unit %s: %v", ErrInvalidRoleInstallation, unit.Name, err)
		}
		plan.UnitFiles = append(plan.UnitFiles, filepath.Join(installer.unitDir, unit.Name))
		if unit.Enable {
			plan.UnitsToEnable = append(plan.UnitsToEnable, unit.Name)
		}
		if unit.Start {
			plan.UnitsToStart = append(plan.UnitsToStart, unit.Name)
		}
	}
	seenConfigs := make(map[string]struct{}, len(request.Configs))
	for _, config := range request.Configs {
		if !roleConfigNamePattern.MatchString(config.Name) || filepath.Base(config.Name) != config.Name {
			return RoleInstallationPlan{}, fmt.Errorf("%w: invalid config name %q", ErrInvalidRoleInstallation, config.Name)
		}
		if _, duplicate := seenConfigs[config.Name]; duplicate {
			return RoleInstallationPlan{}, fmt.Errorf("%w: duplicate config %q", ErrInvalidRoleInstallation, config.Name)
		}
		seenConfigs[config.Name] = struct{}{}
		if len(config.Content) == 0 || len(config.Content) > maximumRoleConfigBytes {
			return RoleInstallationPlan{}, fmt.Errorf("%w: config %q has invalid size", ErrInvalidRoleInstallation, config.Name)
		}
		plan.ConfigFiles = append(plan.ConfigFiles, filepath.Join(installer.configRoot, string(request.Role), config.Name))
	}
	for _, values := range [][]string{plan.UnitFiles, plan.ConfigFiles, plan.UnitsToEnable, plan.UnitsToStart} {
		sort.Strings(values)
	}
	return plan, nil
}

func (installer *RoleSystemdInstaller) Apply(ctx context.Context, request RoleInstallationRequest) (RoleInstallationResult, error) {
	if ctx == nil {
		return RoleInstallationResult{}, fmt.Errorf("context is required")
	}
	plan, err := installer.Plan(request)
	if err != nil {
		return RoleInstallationResult{}, err
	}
	if err := validateRealDirectory(installer.unitDir); err != nil {
		return RoleInstallationResult{}, fmt.Errorf("validate systemd unit directory: %w", err)
	}
	if err := validateRealDirectory(installer.configDir); err != nil {
		return RoleInstallationResult{}, fmt.Errorf("validate vpnctl config directory: %w", err)
	}
	if err := ensurePrivateDirectory(installer.configRoot); err != nil {
		return RoleInstallationResult{}, err
	}
	roleConfigDir := filepath.Join(installer.configRoot, string(request.Role))
	if err := ensurePrivateDirectory(roleConfigDir); err != nil {
		return RoleInstallationResult{}, err
	}

	changed := make([]string, 0, len(request.Units)+len(request.Configs))
	units := append([]RoleUnitFile(nil), request.Units...)
	sort.Slice(units, func(i, j int) bool { return units[i].Name < units[j].Name })
	for _, unit := range units {
		path := filepath.Join(installer.unitDir, unit.Name)
		updated, err := installAtomicRoleFile(path, normalizedText(unit.Content), 0o644)
		if err != nil {
			return RoleInstallationResult{}, err
		}
		if updated {
			changed = append(changed, path)
		}
	}
	configs := append([]RoleConfigFile(nil), request.Configs...)
	sort.Slice(configs, func(i, j int) bool { return roleConfigLess(configs[i].Name, configs[j].Name) })
	for _, config := range configs {
		path := filepath.Join(roleConfigDir, config.Name)
		updated, err := installAtomicRoleFile(path, config.Content, 0o600)
		if err != nil {
			return RoleInstallationResult{}, err
		}
		if updated {
			changed = append(changed, path)
		}
	}
	if err := installer.systemctl(ctx, "daemon-reload"); err != nil {
		return RoleInstallationResult{}, err
	}
	for _, unit := range plan.UnitsToEnable {
		if err := installer.systemctl(ctx, "enable", unit); err != nil {
			return RoleInstallationResult{}, err
		}
	}
	for _, unit := range plan.UnitsToStart {
		if err := installer.systemctl(ctx, "start", unit); err != nil {
			return RoleInstallationResult{}, err
		}
	}
	return RoleInstallationResult{Plan: plan, ChangedFiles: changed}, nil
}

// PlanRemoval proves ownership of every present role unit and the narrow
// generated role tree without changing service or filesystem state.
func (installer *RoleSystemdInstaller) PlanRemoval(role model.Role, binaryPath string) (RoleRemovalPlan, error) {
	if installer == nil || installer.runner == nil {
		return RoleRemovalPlan{}, fmt.Errorf("role installer is incomplete")
	}
	request, err := renderRoleInstallation(role, binaryPath)
	if err != nil {
		return RoleRemovalPlan{}, err
	}
	plan, err := installer.Plan(request)
	if err != nil {
		return RoleRemovalPlan{}, err
	}
	removal := RoleRemovalPlan{
		Role: role, BinaryPath: binaryPath, UnitFiles: append([]string(nil), plan.UnitFiles...),
		PresentUnits: []string{}, GeneratedRoleDir: filepath.Join(installer.configRoot, string(role)),
	}
	for _, unit := range request.Units {
		path := filepath.Join(installer.unitDir, unit.Name)
		content, present, err := readExactRoleFile(path, 0o644)
		if err != nil {
			return RoleRemovalPlan{}, err
		}
		if !present {
			continue
		}
		if !bytes.Equal(content, normalizedText(unit.Content)) {
			return RoleRemovalPlan{}, fmt.Errorf("%w: role unit %s differs from the vpnctl template", ErrInvalidRoleInstallation, path)
		}
		removal.PresentUnits = append(removal.PresentUnits, unit.Name)
	}
	if err := validateOwnedRoleTree(removal.GeneratedRoleDir); err != nil {
		return RoleRemovalPlan{}, err
	}
	sort.Strings(removal.PresentUnits)
	return removal, nil
}

// StopRemoval disables and stops only units proven by PlanRemoval. Unit files
// stay in place until DNS/network restoration has completed.
func (installer *RoleSystemdInstaller) StopRemoval(ctx context.Context, plan RoleRemovalPlan) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	fresh, err := installer.PlanRemoval(plan.Role, plan.BinaryPath)
	if err != nil || !reflect.DeepEqual(fresh, plan) {
		return fmt.Errorf("%w: role removal plan changed", ErrInvalidRoleInstallation)
	}
	for _, unit := range roleRemovalStopOrder(plan.Role, plan.PresentUnits) {
		if err := installer.systemctl(ctx, "stop", unit); err != nil {
			return err
		}
		if err := installer.systemctl(ctx, "disable", unit); err != nil {
			return err
		}
	}
	return nil
}

func roleRemovalStopOrder(role model.Role, present []string) []string {
	remaining := append([]string(nil), present...)
	sort.Sort(sort.Reverse(sort.StringSlice(remaining)))
	result := make([]string, 0, len(remaining))
	move := func(name string, first bool) {
		for index, unit := range remaining {
			if unit != name {
				continue
			}
			remaining = append(remaining[:index], remaining[index+1:]...)
			if first {
				result = append(result, name)
			}
			return
		}
	}
	if role == model.RoleGateway {
		move("vpnctl-controller.service", true)
	}
	guard := ""
	if role == model.RoleNode {
		guard = "vpnctl-routing-guard.service"
		move(guard, false)
	}
	result = append(result, remaining...)
	if guard != "" {
		for _, unit := range present {
			if unit == guard {
				result = append(result, guard)
				break
			}
		}
	}
	return result
}

// RemoveStopped removes the exact unit files and generated role tree after
// controlled restoration. Durable state and presets are outside its paths.
func (installer *RoleSystemdInstaller) RemoveStopped(ctx context.Context, plan RoleRemovalPlan) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	fresh, err := installer.PlanRemoval(plan.Role, plan.BinaryPath)
	if err != nil || !reflect.DeepEqual(fresh, plan) {
		return fmt.Errorf("%w: role removal plan changed", ErrInvalidRoleInstallation)
	}
	for _, path := range plan.UnitFiles {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove role unit %s: %w", path, err)
		}
	}
	if err := removeOwnedRoleTree(plan.GeneratedRoleDir); err != nil {
		return err
	}
	if err := os.Remove(installer.configRoot); err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTEMPTY) {
		return err
	}
	return installer.systemctl(ctx, "daemon-reload")
}

func renderRoleInstallation(role model.Role, binaryPath string) (RoleInstallationRequest, error) {
	switch role {
	case model.RoleGateway:
		return RenderGatewayRoleInstallation(binaryPath)
	case model.RoleNode:
		return RenderNodeRoleInstallation(binaryPath)
	default:
		return RoleInstallationRequest{}, fmt.Errorf("%w: unsupported role %q", ErrInvalidRoleInstallation, role)
	}
}

func readExactRoleFile(path string, mode os.FileMode) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Size() <= 0 || info.Size() > maximumRoleUnitBytes {
		return nil, false, fmt.Errorf("%w: role file %s is not an owned regular file", ErrInvalidRoleInstallation, path)
	}
	content, err := os.ReadFile(path)
	return content, true, err
}

func validateOwnedRoleTree(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: generated role path %s is not a real directory", ErrInvalidRoleInstallation, path)
	}
	return filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == path {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(current)
			if err != nil || filepath.IsAbs(target) {
				return fmt.Errorf("%w: generated role entry %s has an unsafe symlink", ErrInvalidRoleInstallation, current)
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(current), target))
			relative, err := filepath.Rel(path, resolved)
			if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return fmt.Errorf("%w: generated role symlink %s escapes its owner tree", ErrInvalidRoleInstallation, current)
			}
			return nil
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("%w: generated role entry %s is not an owned regular file or directory", ErrInvalidRoleInstallation, current)
		}
		return nil
	})
}

func removeOwnedRoleTree(path string) error {
	if err := validateOwnedRoleTree(path); err != nil {
		return err
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove generated role tree %s: %w", path, err)
	}
	return nil
}

func roleConfigLess(left, right string) bool {
	leftReady := strings.HasSuffix(left, ".ready")
	rightReady := strings.HasSuffix(right, ".ready")
	if leftReady != rightReady {
		return !leftReady
	}
	return left < right
}

func (installer *RoleSystemdInstaller) systemctl(ctx context.Context, arguments ...string) error {
	result, err := installer.runner.Run(ctx, ProbeCommand{Name: "systemctl", Args: arguments})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		detail := strings.TrimSpace(string(result.Stderr))
		if detail == "" {
			detail = fmt.Sprintf("exit code %d", result.ExitCode)
		}
		return fmt.Errorf("systemctl %s: %s", strings.Join(arguments, " "), detail)
	}
	return nil
}

func RoleUnitNames(role model.Role) []string {
	result := make([]string, 0)
	for name, roles := range roleUnitCatalog {
		if _, allowed := roles[role]; allowed {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result
}

func validateRoleServiceUnit(name string, content []byte) error {
	if len(content) == 0 || len(content) > maximumRoleUnitBytes || !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 {
		return fmt.Errorf("content must be non-empty UTF-8 within %d bytes", maximumRoleUnitBytes)
	}
	section := ""
	restarts := make([]string, 0, 1)
	types := make([]string, 0, 1)
	remainAfterExit := make([]string, 0, 1)
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}
		if section != "[Service]" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Restart":
			restarts = append(restarts, strings.TrimSpace(value))
		case "Type":
			types = append(types, strings.TrimSpace(value))
		case "RemainAfterExit":
			remainAfterExit = append(remainAfterExit, strings.TrimSpace(value))
		}
	}
	if len(restarts) != 1 || restarts[0] != "on-failure" {
		return fmt.Errorf("[Service] must contain exactly Restart=on-failure")
	}
	if name == "vpnctl-routing-guard.service" {
		if len(types) != 1 || types[0] != "oneshot" || len(remainAfterExit) != 1 || remainAfterExit[0] != "yes" {
			return fmt.Errorf("node routing guard must be Type=oneshot with RemainAfterExit=yes")
		}
		return nil
	}
	if len(types) > 1 || (len(types) == 1 && types[0] == "oneshot") {
		return fmt.Errorf("role data-plane unit must be long-running")
	}
	return nil
}

func validateRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be a real directory", path)
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create role config directory %s: %w", path, err)
	}
	if err := validateRealDirectory(path); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("role config directory %s is not root-only", path)
	}
	return nil
}

func installAtomicRoleFile(path string, content []byte, mode os.FileMode) (bool, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return false, fmt.Errorf("role install target %s must be a regular file", path)
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		if bytes.Equal(existing, content) && info.Mode().Perm() == mode {
			return false, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".vpnctl-role-*.tmp")
	if err != nil {
		return false, err
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
		return false, err
	}
	if _, err := temporary.Write(content); err != nil {
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return false, err
	}
	keep = true
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return false, err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return false, err
	}
	return true, nil
}

func normalizedText(content []byte) []byte {
	result := append([]byte(nil), content...)
	if len(result) != 0 && result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	return result
}
