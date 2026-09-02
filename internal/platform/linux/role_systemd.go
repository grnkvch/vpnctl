package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
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
		if err := validateRoleServiceUnit(unit.Content); err != nil {
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
	sort.Slice(configs, func(i, j int) bool { return configs[i].Name < configs[j].Name })
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

func validateRoleServiceUnit(content []byte) error {
	if len(content) == 0 || len(content) > maximumRoleUnitBytes || !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 {
		return fmt.Errorf("content must be non-empty UTF-8 within %d bytes", maximumRoleUnitBytes)
	}
	section := ""
	restarts := make([]string, 0, 1)
	types := make([]string, 0, 1)
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
		}
	}
	if len(restarts) != 1 || restarts[0] != "on-failure" {
		return fmt.Errorf("[Service] must contain exactly Restart=on-failure")
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
