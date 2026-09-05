package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestRoleRepairAppliesOnlySelectedConfigAndDependentRestart(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	selectedPath := fixture.writeConfig(t, "dns.json", []byte("old\n"), 0o600)
	neighborPath := fixture.writeConfig(t, "standard.json", []byte("neighbor\n"), 0o600)
	fixture.runner.states["vpnctl-dns.service"] = roleRepairFakeUnit{activeState: "active", enablement: "enabled", subState: "running"}

	request := RoleRepairRequest{
		Role: model.RoleGateway,
		Resources: []RoleRepairResource{{
			Kind: RoleRepairConfig, Name: "dns.json", Content: []byte("new\n"), ContentSHA256: roleRepairDigest([]byte("new\n")),
		}},
		RestartUnits: []string{"vpnctl-dns.service"},
	}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Destroy()
	result, err := fixture.installer.ApplyRepair(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if plan.request.Role != "" || plan.files != nil || plan.unitState != nil {
		t.Fatal("ApplyRepair() did not consume the approved material plan")
	}
	if content, err := os.ReadFile(selectedPath); err != nil || string(content) != "new\n" {
		t.Fatalf("selected config = %q, %v", content, err)
	}
	if content, err := os.ReadFile(neighborPath); err != nil || string(content) != "neighbor\n" {
		t.Fatalf("neighbor config changed: %q, %v", content, err)
	}
	if want := [][]string{{"restart", "vpnctl-dns.service"}}; !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
	if len(result.Resources) != 1 || !result.Resources[0].Changed || result.Resources[0].ContentSHA256 != request.Resources[0].ContentSHA256 {
		t.Fatalf("ApplyRepair() result = %+v", result)
	}
}

func TestRoleRepairReplacesOnlySelectedUnitAndReloadsBeforeRestart(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	name := "vpnctl-standard.service"
	target := roleTestUnit(name)
	old := []byte(strings.Replace(string(target), "Description="+name, "Description=old", 1))
	fixture.writeUnit(t, name, old, 0o644)
	fixture.runner.states[name] = roleRepairFakeUnit{activeState: "active", enablement: "enabled", subState: "running"}

	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairUnit, Name: name, Content: target, ContentSHA256: roleRepairDigest(target),
		UnitTarget: roleRepairRunningTarget(),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Destroy()
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"daemon-reload"}, {"restart", name}}; !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
}

func TestRoleRepairCorrectsSelectedUnitRuntimeWithoutRewritingFile(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	name := "vpnctl-standard.service"
	content := roleTestUnit(name)
	path := fixture.writeUnit(t, name, content, 0o644)
	fixture.runner.states[name] = roleRepairFakeUnit{activeState: "inactive", enablement: "disabled", subState: "dead"}

	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairUnit, Name: name, Content: content, ContentSHA256: roleRepairDigest(content),
		UnitTarget: roleRepairRunningTarget(),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Destroy()
	result, err := fixture.installer.ApplyRepair(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"enable", name}, {"start", name}}; !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
	if contentAfter, err := os.ReadFile(path); err != nil || string(contentAfter) != string(content) {
		t.Fatalf("unit content changed: %q, %v", contentAfter, err)
	}
	if len(result.Resources) != 1 || !result.Resources[0].Changed {
		t.Fatalf("ApplyRepair() result = %+v", result)
	}
}

func TestRoleRepairRestartsSelectedUnitForSubStateDrift(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	name := "vpnctl-standard.service"
	content := roleTestUnit(name)
	fixture.writeUnit(t, name, content, 0o644)
	fixture.runner.states[name] = roleRepairFakeUnit{activeState: "active", enablement: "enabled", subState: "exited"}
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairUnit, Name: name, Content: content, ContentSHA256: roleRepairDigest(content),
		UnitTarget: roleRepairRunningTarget(),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	result, err := fixture.installer.ApplyRepair(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"restart", name}}; !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
	if len(result.Resources) != 1 || !result.Resources[0].Changed {
		t.Fatalf("ApplyRepair() result = %+v", result)
	}
}

func TestRoleRepairRestoresMissingSelectedUnit(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	name := "vpnctl-standard.service"
	content := roleTestUnit(name)
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairUnit, Name: name, Content: content, ContentSHA256: roleRepairDigest(content),
		UnitTarget: roleRepairRunningTarget(),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"daemon-reload"}, {"enable", name}, {"start", name}}; !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
	if contentAfter, err := os.ReadFile(filepath.Join(fixture.runner.unitDir, name)); err != nil || string(contentAfter) != string(content) {
		t.Fatalf("restored unit = %q, %v", contentAfter, err)
	}
}

func TestRoleRepairRejectsEntireInvalidBatchBeforeMutation(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	selectedPath := fixture.writeConfig(t, "dns.json", []byte("old\n"), 0o600)
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{
		{Kind: RoleRepairConfig, Name: "dns.json", Content: []byte("new\n"), ContentSHA256: roleRepairDigest([]byte("new\n"))},
		{Kind: RoleRepairConfig, Name: "bad.json", Content: []byte("bad\n"), ContentSHA256: strings.Repeat("0", 64)},
	}, RestartUnits: []string{}}
	if _, err := fixture.installer.PlanRepair(context.Background(), request); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("PlanRepair() error = %v", err)
	}
	if content, err := os.ReadFile(selectedPath); err != nil || string(content) != "old\n" {
		t.Fatalf("valid earlier resource changed: %q, %v", content, err)
	}
	if len(fixture.runner.mutations) != 0 {
		t.Fatalf("invalid batch mutated systemd: %v", fixture.runner.mutations)
	}
}

func TestRoleRepairRestoresEmptyCorruptedConfig(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	path := fixture.writeConfig(t, "dns.json", []byte{}, 0o600)
	target := []byte("restored\n")
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairConfig, Name: "dns.json", Content: target, ContentSHA256: roleRepairDigest(target),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != string(target) {
		t.Fatalf("empty config repair = %q, %v", content, err)
	}
}

func TestRoleRepairRestoresEmptyCorruptedUnit(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	name := "vpnctl-standard.service"
	fixture.writeUnit(t, name, []byte{}, 0o644)
	fixture.runner.states[name] = roleRepairFakeUnit{
		loadState: "bad-setting", activeState: "inactive", enablement: "static", subState: "dead",
	}
	target := roleTestUnit(name)
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairUnit, Name: name, Content: target, ContentSHA256: roleRepairDigest(target),
		UnitTarget: roleRepairRunningTarget(),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"daemon-reload"}, {"enable", name}, {"start", name}}; !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
}

func TestRoleRepairRejectsStalePlanBeforeMutation(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	path := fixture.writeConfig(t, "dns.json", []byte("old\n"), 0o600)
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairConfig, Name: "dns.json", Content: []byte("target\n"), ContentSHA256: roleRepairDigest([]byte("target\n")),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Destroy()
	if err := os.WriteFile(path, []byte("concurrent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "plan changed") {
		t.Fatalf("ApplyRepair(stale) error = %v", err)
	}
	if content, err := os.ReadFile(path); err != nil || string(content) != "concurrent\n" {
		t.Fatalf("stale apply changed file: %q, %v", content, err)
	}
	if len(fixture.runner.mutations) != 0 {
		t.Fatalf("stale apply mutated systemd: %v", fixture.runner.mutations)
	}
}

func TestRoleRepairRollsBackSelectedFileAndModeAfterRestartFailure(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	path := fixture.writeConfig(t, "dns.json", []byte("old\n"), 0o640)
	name := "vpnctl-dns.service"
	fixture.runner.states[name] = roleRepairFakeUnit{activeState: "active", enablement: "enabled", subState: "running"}
	fixture.runner.failOnce["restart "+name] = errors.New("restart failed")
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairConfig, Name: "dns.json", Content: []byte("new\n"), ContentSHA256: roleRepairDigest([]byte("new\n")),
	}}, RestartUnits: []string{name}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Destroy()
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "restart failed") {
		t.Fatalf("ApplyRepair() error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "old\n" {
		t.Fatalf("rollback content = %q, %v", content, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("rollback mode = %v, %v", info.Mode().Perm(), err)
	}
	if want := [][]string{{"restart", name}, {"restart", name}}; !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
}

func TestRoleRepairRollsBackUncertainPostRenameError(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	path := fixture.writeConfig(t, "dns.json", []byte("old\n"), 0o640)
	writes := 0
	fixture.installer.repairFileWriter = func(path string, content []byte, mode os.FileMode) (bool, error) {
		writes++
		changed, err := installAtomicRoleFile(path, content, mode)
		if writes == 1 && err == nil {
			return changed, errors.New("directory sync outcome unknown")
		}
		return changed, err
	}
	target := []byte("new\n")
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairConfig, Name: "dns.json", Content: target, ContentSHA256: roleRepairDigest(target),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("ApplyRepair() error = %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "old\n" {
		t.Fatalf("uncertain write rollback content = %q, %v", content, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("uncertain write rollback mode = %v, %v", info.Mode().Perm(), err)
	}
	if writes != 2 {
		t.Fatalf("repair writes = %d, want apply plus rollback", writes)
	}
}

func TestRoleRepairRollbackTouchesOnlyAttemptedDependentUnit(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	fixture.writeConfig(t, "dns.json", []byte("old\n"), 0o600)
	first, second := "vpnctl-dns.service", "vpnctl-standard.service"
	fixture.runner.states[first] = roleRepairFakeUnit{activeState: "active", enablement: "enabled", subState: "running"}
	fixture.runner.states[second] = roleRepairFakeUnit{activeState: "active", enablement: "enabled", subState: "running"}
	fixture.runner.failOnce["restart "+first] = errors.New("restart failed")
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairConfig, Name: "dns.json", Content: []byte("new\n"), ContentSHA256: roleRepairDigest([]byte("new\n")),
	}}, RestartUnits: []string{first, second}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err == nil {
		t.Fatal("ApplyRepair() unexpectedly succeeded")
	}
	if want := [][]string{{"restart", first}, {"restart", first}}; !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
}

func TestRoleRepairRollbackRestoresAttemptedUnitsInReverseOrder(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	fixture.writeConfig(t, "dns.json", []byte("old\n"), 0o600)
	first, second := "vpnctl-standard.service", "vpnctl-dns.service"
	fixture.runner.states[first] = roleRepairFakeUnit{activeState: "active", enablement: "enabled", subState: "running"}
	fixture.runner.states[second] = roleRepairFakeUnit{activeState: "active", enablement: "enabled", subState: "running"}
	fixture.runner.failOnce["restart "+second] = errors.New("second restart failed")
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairConfig, Name: "dns.json", Content: []byte("new\n"), ContentSHA256: roleRepairDigest([]byte("new\n")),
	}}, RestartUnits: []string{first, second}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err == nil {
		t.Fatal("ApplyRepair() unexpectedly succeeded")
	}
	want := [][]string{
		{"restart", first}, {"restart", second},
		{"restart", second}, {"restart", first},
	}
	if !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want reverse rollback %v", fixture.runner.mutations, want)
	}
}

func TestRoleRepairRollbackReportsUnrestorableCompleteRuntime(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	selected, dependent := "vpnctl-standard.service", "vpnctl-dns.service"
	content := roleTestUnit(selected)
	fixture.writeUnit(t, selected, content, 0o644)
	fixture.runner.states[selected] = roleRepairFakeUnit{activeState: "active", enablement: "enabled", subState: "exited"}
	fixture.runner.states[dependent] = roleRepairFakeUnit{activeState: "active", enablement: "enabled", subState: "running"}
	fixture.runner.failOnce["restart "+dependent] = errors.New("dependent restart failed")
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairUnit, Name: selected, Content: content, ContentSHA256: roleRepairDigest(content),
		UnitTarget: roleRepairRunningTarget(),
	}}, RestartUnits: []string{dependent}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.installer.ApplyRepair(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "dependent restart failed") ||
		!strings.Contains(err.Error(), "complete pre-repair runtime state") {
		t.Fatalf("ApplyRepair() error = %v", err)
	}
	if want := [][]string{{"restart", selected}, {"restart", dependent}}; !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
}

func TestRoleRepairEnableFailureDoesNotRestartUnchangedActiveUnit(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	name := "vpnctl-standard.service"
	content := roleTestUnit(name)
	fixture.writeUnit(t, name, content, 0o644)
	fixture.runner.states[name] = roleRepairFakeUnit{activeState: "active", enablement: "disabled", subState: "running"}
	fixture.runner.failOnce["enable "+name] = errors.New("enable failed")
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairUnit, Name: name, Content: content, ContentSHA256: roleRepairDigest(content),
		UnitTarget: roleRepairRunningTarget(),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "enable failed") {
		t.Fatalf("ApplyRepair() error = %v", err)
	}
	if want := [][]string{{"enable", name}}; !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
}

func TestRoleRepairRollsBackNewUnitBeforeRemovingIt(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	name := "vpnctl-standard.service"
	content := roleTestUnit(name)
	fixture.runner.failOnce["start "+name] = errors.New("start failed")
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairUnit, Name: name, Content: content, ContentSHA256: roleRepairDigest(content),
		UnitTarget: roleRepairRunningTarget(),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err == nil {
		t.Fatal("ApplyRepair() unexpectedly succeeded")
	}
	if _, err := os.Lstat(filepath.Join(fixture.runner.unitDir, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing unit rollback left file: %v", err)
	}
	if state := fixture.runner.states[name]; state.enablement != "not-found" || state.activeState != "inactive" {
		t.Fatalf("missing unit rollback state = %+v", state)
	}
	if want := [][]string{{"daemon-reload"}, {"enable", name}, {"start", name}, {"stop", name}, {"disable", name}, {"daemon-reload"}}; !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
}

func TestRoleRepairRollbackResetsFailureCreatedByAttemptedStart(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	name := "vpnctl-standard.service"
	content := roleTestUnit(name)
	fixture.writeUnit(t, name, content, 0o644)
	fixture.runner.states[name] = roleRepairFakeUnit{activeState: "inactive", enablement: "disabled", subState: "dead"}
	fixture.runner.failOnce["start "+name] = errors.New("start failed")
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairUnit, Name: name, Content: content, ContentSHA256: roleRepairDigest(content),
		UnitTarget: roleRepairRunningTarget(),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.installer.ApplyRepair(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "start failed") {
		t.Fatalf("ApplyRepair() error = %v", err)
	}
	want := [][]string{{"enable", name}, {"start", name}, {"disable", name}, {"reset-failed", name}}
	if !reflect.DeepEqual(fixture.runner.mutations, want) {
		t.Fatalf("systemd mutations = %v, want %v", fixture.runner.mutations, want)
	}
}

func TestRoleRepairRejectsWritableUnitDirectory(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	if err := os.Chmod(fixture.runner.unitDir, 0o777); err != nil {
		t.Fatal(err)
	}
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairConfig, Name: "dns.json", Content: []byte("new\n"), ContentSHA256: roleRepairDigest([]byte("new\n")),
	}}, RestartUnits: []string{}}
	if _, err := fixture.installer.PlanRepair(context.Background(), request); err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("PlanRepair() error = %v", err)
	}
	if len(fixture.runner.mutations) != 0 {
		t.Fatalf("unsafe directory mutated systemd: %v", fixture.runner.mutations)
	}
}

func TestRoleRepairRejectsFailedPreStateAsNonReversible(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	name := "vpnctl-standard.service"
	content := roleTestUnit(name)
	fixture.writeUnit(t, name, content, 0o644)
	fixture.runner.states[name] = roleRepairFakeUnit{activeState: "failed", enablement: "enabled", subState: "failed"}
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairUnit, Name: name, Content: content, ContentSHA256: roleRepairDigest(content),
		UnitTarget: roleRepairRunningTarget(),
	}}, RestartUnits: []string{}}
	if _, err := fixture.installer.PlanRepair(context.Background(), request); err == nil || !strings.Contains(err.Error(), "unsafe current runtime") {
		t.Fatalf("PlanRepair() error = %v", err)
	}
	if len(fixture.runner.mutations) != 0 {
		t.Fatalf("failed pre-state mutated systemd: %v", fixture.runner.mutations)
	}
}

func TestRoleRepairRejectsCrossRoleTraversalSymlinkAndHardlink(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		prepare func(*testing.T, roleRepairFixture) RoleRepairRequest
	}{
		{name: "cross-role unit", prepare: func(t *testing.T, fixture roleRepairFixture) RoleRepairRequest {
			content := roleTestUnit("vpnctl-routing.service")
			return RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
				Kind: RoleRepairUnit, Name: "vpnctl-routing.service", Content: content, ContentSHA256: roleRepairDigest(content),
				UnitTarget: roleRepairRunningTarget(),
			}}, RestartUnits: []string{}}
		}},
		{name: "config traversal", prepare: func(t *testing.T, fixture roleRepairFixture) RoleRepairRequest {
			content := []byte("target\n")
			return RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
				Kind: RoleRepairConfig, Name: "../target", Content: content, ContentSHA256: roleRepairDigest(content),
			}}, RestartUnits: []string{}}
		}},
		{name: "symlink target", prepare: func(t *testing.T, fixture roleRepairFixture) RoleRepairRequest {
			foreign := fixture.writeConfig(t, "foreign.json", []byte("foreign\n"), 0o600)
			if err := os.Symlink(foreign, filepath.Join(fixture.roleDir, "dns.json")); err != nil {
				t.Fatal(err)
			}
			content := []byte("target\n")
			return RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
				Kind: RoleRepairConfig, Name: "dns.json", Content: content, ContentSHA256: roleRepairDigest(content),
			}}, RestartUnits: []string{}}
		}},
		{name: "hardlink target", prepare: func(t *testing.T, fixture roleRepairFixture) RoleRepairRequest {
			foreign := fixture.writeConfig(t, "foreign.json", []byte("foreign\n"), 0o600)
			if err := os.Link(foreign, filepath.Join(fixture.roleDir, "dns.json")); err != nil {
				t.Fatal(err)
			}
			content := []byte("target\n")
			return RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
				Kind: RoleRepairConfig, Name: "dns.json", Content: content, ContentSHA256: roleRepairDigest(content),
			}}, RestartUnits: []string{}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRoleRepairFixture(t, model.RoleGateway)
			request := test.prepare(t, fixture)
			if _, err := fixture.installer.PlanRepair(context.Background(), request); err == nil {
				t.Fatal("PlanRepair() unexpectedly accepted unsafe scope or target")
			}
			if len(fixture.runner.mutations) != 0 {
				t.Fatalf("unsafe plan mutated systemd: %v", fixture.runner.mutations)
			}
		})
	}
}

func TestRoleRepairPlanDestroyWipesRetainedMaterial(t *testing.T) {
	t.Parallel()
	fixture := newRoleRepairFixture(t, model.RoleGateway)
	fixture.writeConfig(t, "dns.json", []byte("old-secret\n"), 0o600)
	request := RoleRepairRequest{Role: model.RoleGateway, Resources: []RoleRepairResource{{
		Kind: RoleRepairConfig, Name: "dns.json", Content: []byte("new-secret\n"), ContentSHA256: roleRepairDigest([]byte("new-secret\n")),
	}}, RestartUnits: []string{}}
	plan, err := fixture.installer.PlanRepair(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	oldBytes := plan.files[0].content
	targetBytes := plan.request.Resources[0].Content
	plan.Destroy()
	if !allZero(oldBytes) || !allZero(targetBytes) {
		t.Fatal("Destroy() did not wipe retained material")
	}
	plan.Destroy()
}

type roleRepairFixture struct {
	root      string
	configDir string
	roleDir   string
	installer *RoleSystemdInstaller
	runner    *roleRepairFakeRunner
}

func newRoleRepairFixture(t *testing.T, role model.Role) roleRepairFixture {
	t.Helper()
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "vpnctl")
	roleDir := filepath.Join(configDir, "generated", string(role))
	if err := os.MkdirAll(filepath.Join(root, "etc", "systemd", "system"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{configDir, filepath.Join(configDir, "generated"), roleDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	runner := &roleRepairFakeRunner{
		unitDir: filepath.Join(root, "etc", "systemd", "system"),
		states:  make(map[string]roleRepairFakeUnit), failOnce: make(map[string]error),
	}
	installer, err := NewRoleSystemdInstaller(root, configDir, runner)
	if err != nil {
		t.Fatal(err)
	}
	return roleRepairFixture{root: root, configDir: configDir, roleDir: roleDir, installer: installer, runner: runner}
}

func (fixture roleRepairFixture) writeConfig(t *testing.T, name string, content []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(fixture.roleDir, name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func (fixture roleRepairFixture) writeUnit(t *testing.T, name string, content []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(fixture.root, "etc", "systemd", "system", name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

type roleRepairFakeUnit struct {
	loadState   string
	activeState string
	enablement  string
	subState    string
}

type roleRepairFakeRunner struct {
	unitDir   string
	states    map[string]roleRepairFakeUnit
	mutations [][]string
	failOnce  map[string]error
}

func (runner *roleRepairFakeRunner) Run(_ context.Context, command ProbeCommand) (ProbeResult, error) {
	if command.Name != "systemctl" || len(command.Args) == 0 {
		return ProbeResult{}, errors.New("unexpected repair command")
	}
	switch command.Args[0] {
	case "show":
		name := command.Args[len(command.Args)-1]
		state, found := runner.states[name]
		if !found {
			state = roleRepairFakeUnit{activeState: "inactive", enablement: "not-found", subState: "dead"}
		}
		loadState := state.loadState
		if loadState == "" {
			loadState = "loaded"
			if state.enablement == "not-found" {
				loadState = "not-found"
			}
		}
		return ProbeResult{Stdout: []byte("LoadState=" + loadState + "\nActiveState=" + state.activeState + "\nSubState=" + state.subState + "\n")}, nil
	case "is-enabled":
		state := runner.states[command.Args[1]]
		if state.enablement == "enabled" {
			return ProbeResult{Stdout: []byte("enabled\n")}, nil
		}
		if state.enablement == "" {
			state.enablement = "not-found"
		}
		return ProbeResult{Stdout: []byte(state.enablement + "\n"), ExitCode: 1}, nil
	case "daemon-reload", "enable", "disable", "start", "stop", "restart", "reset-failed":
		args := append([]string(nil), command.Args...)
		runner.mutations = append(runner.mutations, args)
		key := strings.Join(args, " ")
		if failure := runner.failOnce[key]; failure != nil {
			delete(runner.failOnce, key)
			if args[0] == "start" && len(args) == 2 {
				state := runner.states[args[1]]
				state.activeState, state.subState = "failed", "failed"
				runner.states[args[1]] = state
			}
			return ProbeResult{ExitCode: 1, Stderr: []byte(failure.Error())}, nil
		}
		if args[0] == "daemon-reload" {
			for name, state := range runner.states {
				content, err := os.ReadFile(filepath.Join(runner.unitDir, name))
				if err == nil && len(content) == 0 {
					state.loadState, state.activeState, state.subState, state.enablement = "bad-setting", "inactive", "dead", "static"
				} else if err == nil {
					state.loadState = "loaded"
					if state.enablement == "not-found" || state.enablement == "static" {
						state.enablement = "disabled"
					}
				} else if errors.Is(err, os.ErrNotExist) {
					state.loadState, state.activeState, state.subState, state.enablement = "not-found", "inactive", "dead", "not-found"
				}
				runner.states[name] = state
			}
		}
		if len(args) == 2 {
			state := runner.states[args[1]]
			switch args[0] {
			case "enable":
				state.enablement = "enabled"
				if state.activeState == "" {
					state.activeState, state.subState = "inactive", "dead"
				}
			case "disable":
				state.enablement = "disabled"
			case "start", "restart":
				state.activeState, state.subState = "active", "running"
			case "stop", "reset-failed":
				state.activeState, state.subState = "inactive", "dead"
			}
			runner.states[args[1]] = state
		}
		return ProbeResult{}, nil
	default:
		return ProbeResult{}, errors.New("unexpected systemctl repair operation")
	}
}

func roleRepairDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func roleRepairRunningTarget() *RoleRepairUnitTarget {
	return &RoleRepairUnitTarget{LoadState: "loaded", ActiveState: "active", SubState: "running", Enablement: "enabled"}
}

func allZero(content []byte) bool {
	for _, value := range content {
		if value != 0 {
			return false
		}
	}
	return true
}
