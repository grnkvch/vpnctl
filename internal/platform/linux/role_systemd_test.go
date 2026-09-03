package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestRoleUnitCatalogMatchesGatewayAndNodeDesign(t *testing.T) {
	t.Parallel()

	wantGateway := []string{
		"vpnctl-controller.service", "vpnctl-dns.service", "vpnctl-restricted.service",
		"vpnctl-standard.service", "vpnctl-tunnel-server.service",
	}
	wantNode := []string{"vpnctl-routing.service", "vpnctl-standard.service", "vpnctl-tunnel-client.service"}
	if got := RoleUnitNames(model.RoleGateway); !reflect.DeepEqual(got, wantGateway) {
		t.Fatalf("gateway units = %v, want %v", got, wantGateway)
	}
	if got := RoleUnitNames(model.RoleNode); !reflect.DeepEqual(got, wantNode) {
		t.Fatalf("node units = %v, want %v", got, wantNode)
	}
}

func TestRoleSystemdInstallerWritesStartsOnlySelectedRole(t *testing.T) {
	t.Parallel()

	for _, role := range []model.Role{model.RoleGateway, model.RoleNode} {
		role := role
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			paths := newRoleInstallerTestPaths(t)
			runner := &roleSystemdRunner{}
			installer, err := NewRoleSystemdInstaller(paths.root, paths.configDir, runner)
			if err != nil {
				t.Fatal(err)
			}
			foreignRole := model.RoleGateway
			foreignUnit := "vpnctl-controller.service"
			if role == model.RoleGateway {
				foreignRole = model.RoleNode
				foreignUnit = "vpnctl-routing.service"
			}
			foreignPath := filepath.Join(paths.root, "etc", "systemd", "system", foreignUnit)
			if err := os.WriteFile(foreignPath, []byte("foreign sentinel\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			foreignConfigDir := filepath.Join(paths.configDir, "generated", string(foreignRole))
			if err := os.MkdirAll(foreignConfigDir, 0o700); err != nil {
				t.Fatal(err)
			}
			foreignConfig := filepath.Join(foreignConfigDir, "sentinel.conf")
			if err := os.WriteFile(foreignConfig, []byte("foreign\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			request := roleInstallRequest(role, true)
			result, err := installer.Apply(context.Background(), request)
			if err != nil {
				t.Fatalf("Apply() error = %v", err)
			}
			if len(result.ChangedFiles) != len(request.Units)+len(request.Configs) {
				t.Fatalf("changed files = %v", result.ChangedFiles)
			}
			for _, unit := range RoleUnitNames(role) {
				unitPath := filepath.Join(paths.root, "etc", "systemd", "system", unit)
				data, err := os.ReadFile(unitPath)
				if err != nil || !strings.Contains(string(data), "Restart=on-failure") {
					t.Fatalf("installed unit %s = %q, %v", unit, data, err)
				}
				if info, err := os.Stat(unitPath); err != nil || info.Mode().Perm() != 0o644 {
					t.Fatalf("installed unit %s mode = %v, %v", unit, info, err)
				}
			}
			ownConfig := filepath.Join(paths.configDir, "generated", string(role), "runtime.conf")
			if data, err := os.ReadFile(ownConfig); err != nil || string(data) != "role="+string(role)+"\n" {
				t.Fatalf("selected role config = %q, %v", data, err)
			}
			if info, err := os.Stat(ownConfig); err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("selected role config mode = %v, %v", info, err)
			}
			if data, err := os.ReadFile(foreignPath); err != nil || string(data) != "foreign sentinel\n" {
				t.Fatalf("foreign role unit changed: %q, %v", data, err)
			}
			if data, err := os.ReadFile(foreignConfig); err != nil || string(data) != "foreign\n" {
				t.Fatalf("foreign role config changed: %q, %v", data, err)
			}
			joined := runner.joined()
			if !strings.HasPrefix(joined, "daemon-reload") {
				t.Fatalf("systemctl calls = %s", joined)
			}
			for _, foreign := range RoleUnitNames(foreignRole) {
				if foreign != "vpnctl-standard.service" && strings.Contains(joined, foreign) {
					t.Fatalf("role %s started foreign unit %s: %s", role, foreign, joined)
				}
			}
			for _, unit := range RoleUnitNames(role) {
				if !strings.Contains(joined, "enable "+unit) || !strings.Contains(joined, "start "+unit) {
					t.Errorf("role %s did not enable/start %s: %s", role, unit, joined)
				}
			}

			second, err := installer.Apply(context.Background(), request)
			if err != nil || len(second.ChangedFiles) != 0 {
				t.Fatalf("idempotent Apply() = %+v, %v", second, err)
			}
		})
	}
}

func TestRoleSystemdInstallerRejectsForeignOrUnsafeArtifactsBeforeMutation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*RoleInstallationRequest)
	}{
		{name: "foreign unit", mutate: func(request *RoleInstallationRequest) { request.Units[0].Name = "vpnctl-routing.service" }},
		{name: "missing restart", mutate: func(request *RoleInstallationRequest) {
			request.Units[0].Content = []byte("[Service]\nExecStart=/bin/true\n")
		}},
		{name: "wrong restart", mutate: func(request *RoleInstallationRequest) {
			request.Units[0].Content = []byte("[Service]\nExecStart=/bin/true\nRestart=always\n")
		}},
		{name: "oneshot", mutate: func(request *RoleInstallationRequest) {
			request.Units[0].Content = []byte("[Service]\nType=oneshot\nExecStart=/bin/true\nRestart=on-failure\n")
		}},
		{name: "start without enable", mutate: func(request *RoleInstallationRequest) { request.Units[0].Enable = false }},
		{name: "config traversal", mutate: func(request *RoleInstallationRequest) { request.Configs[0].Name = "../node.conf" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			paths := newRoleInstallerTestPaths(t)
			runner := &roleSystemdRunner{}
			installer, _ := NewRoleSystemdInstaller(paths.root, paths.configDir, runner)
			request := roleInstallRequest(model.RoleGateway, true)
			test.mutate(&request)
			if _, err := installer.Apply(context.Background(), request); !errors.Is(err, ErrInvalidRoleInstallation) {
				t.Fatalf("Apply() error = %v", err)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("invalid plan called systemctl: %v", runner.calls)
			}
			if _, err := os.Lstat(filepath.Join(paths.configDir, "generated")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid plan mutated config tree: %v", err)
			}
		})
	}
}

func TestRoleSystemdInstallerCanStageNodeWithoutEnableOrStart(t *testing.T) {
	t.Parallel()

	paths := newRoleInstallerTestPaths(t)
	runner := &roleSystemdRunner{}
	installer, err := NewRoleSystemdInstaller(paths.root, paths.configDir, runner)
	if err != nil {
		t.Fatal(err)
	}
	request := roleInstallRequest(model.RoleNode, false)
	for index := range request.Units {
		request.Units[index].Enable = false
	}

	result, err := installer.Apply(context.Background(), request)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if len(result.Plan.UnitsToEnable) != 0 || len(result.Plan.UnitsToStart) != 0 {
		t.Fatalf("staged node activation plan = %+v", result.Plan)
	}
	if got := runner.joined(); got != "daemon-reload" {
		t.Fatalf("staged node systemctl calls = %q", got)
	}
	for _, gatewayOnly := range []string{
		"vpnctl-controller.service", "vpnctl-dns.service", "vpnctl-restricted.service", "vpnctl-tunnel-server.service",
	} {
		if _, err := os.Lstat(filepath.Join(paths.root, "etc", "systemd", "system", gatewayOnly)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staged node created gateway unit %s: %v", gatewayOnly, err)
		}
	}
}

func TestRoleConfigPublicationOrdersReadinessMarkersLast(t *testing.T) {
	t.Parallel()

	configs := []RoleConfigFile{
		{Name: "gateway-standard.ready"},
		{Name: "restricted.yaml"},
		{Name: "gateway-restricted.ready"},
		{Name: "vpnctl-wg.conf"},
	}
	sort.Slice(configs, func(i, j int) bool { return roleConfigLess(configs[i].Name, configs[j].Name) })

	want := []string{"restricted.yaml", "vpnctl-wg.conf", "gateway-restricted.ready", "gateway-standard.ready"}
	for index, config := range configs {
		if config.Name != want[index] {
			t.Fatalf("publication order[%d] = %q, want %q", index, config.Name, want[index])
		}
	}
}

func TestRoleSystemdInstallerRefusesSymlinkTarget(t *testing.T) {
	t.Parallel()

	paths := newRoleInstallerTestPaths(t)
	installer, _ := NewRoleSystemdInstaller(paths.root, paths.configDir, &roleSystemdRunner{})
	target := filepath.Join(paths.root, "etc", "systemd", "system", "vpnctl-controller.service")
	if err := os.Symlink("/tmp/foreign", target); err != nil {
		t.Fatal(err)
	}
	request := roleInstallRequest(model.RoleGateway, false)
	if _, err := installer.Apply(context.Background(), request); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Apply(symlink) error = %v", err)
	}
}

type roleInstallerTestPaths struct {
	root      string
	configDir string
}

func newRoleInstallerTestPaths(t *testing.T) roleInstallerTestPaths {
	t.Helper()
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "vpnctl")
	if err := os.MkdirAll(filepath.Join(root, "etc", "systemd", "system"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return roleInstallerTestPaths{root: root, configDir: configDir}
}

func roleInstallRequest(role model.Role, start bool) RoleInstallationRequest {
	units := make([]RoleUnitFile, 0)
	for _, name := range RoleUnitNames(role) {
		units = append(units, RoleUnitFile{Name: name, Content: roleTestUnit(name), Enable: true, Start: start})
	}
	return RoleInstallationRequest{
		Role: role, Units: units,
		Configs: []RoleConfigFile{{Name: "runtime.conf", Content: []byte("role=" + string(role) + "\n")}},
	}
}

func roleTestUnit(name string) []byte {
	return []byte("[Unit]\nDescription=" + name + "\n[Service]\nExecStart=/bin/sleep infinity\nRestart=on-failure\nStandardOutput=null\nStandardError=null\n[Install]\nWantedBy=multi-user.target\n")
}

type roleSystemdRunner struct {
	calls   [][]string
	results map[string]ProbeResult
}

func (runner *roleSystemdRunner) Run(_ context.Context, command ProbeCommand) (ProbeResult, error) {
	if command.Name != "systemctl" {
		return ProbeResult{}, errors.New("unexpected command")
	}
	args := append([]string(nil), command.Args...)
	runner.calls = append(runner.calls, args)
	if result, found := runner.results[strings.Join(args, " ")]; found {
		return result, nil
	}
	return ProbeResult{}, nil
}

func (runner *roleSystemdRunner) joined() string {
	lines := make([]string, len(runner.calls))
	for index, call := range runner.calls {
		lines[index] = strings.Join(call, " ")
	}
	return strings.Join(lines, "\n")
}
