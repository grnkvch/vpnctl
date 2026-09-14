package ingress

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestNginxServicePublishesOwnedDropInAndActivates(t *testing.T) {
	t.Parallel()
	manager, paths, runner := nginxServiceFixture(t, "masked", "inactive")
	plan, err := manager.Plan()
	if err != nil || !plan.Changed || plan.DropInPath != NginxServiceDropInPath(paths) {
		t.Fatalf("Plan() = %+v, %v", plan, err)
	}
	installation, err := manager.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(plan.DropInPath)
	if err != nil || !reflect.DeepEqual(content, RenderNginxServiceDropIn(paths)) {
		t.Fatalf("drop-in = %q, %v", content, err)
	}
	if info, err := os.Lstat(plan.DropInPath); err != nil || info.Mode().Perm() != 0o644 || !info.Mode().IsRegular() {
		t.Fatalf("drop-in metadata = %+v, %v", info, err)
	}
	if err := manager.Activate(context.Background(), installation); err != nil {
		t.Fatal(err)
	}
	if runner.enablement != "enabled" || runner.active != "active" {
		t.Fatalf("service state = %s/%s", runner.enablement, runner.active)
	}
	if err := manager.Commit(installation); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"is-enabled nginx.service", "is-active nginx.service", "daemon-reload",
		"unmask nginx.service", "enable nginx.service", "start nginx.service", "is-active nginx.service",
	}
	if !reflect.DeepEqual(runner.commands, want) {
		t.Fatalf("commands = %#v, want %#v", runner.commands, want)
	}
	if _, err := manager.Plan(); err != nil {
		t.Fatalf("idempotent Plan() error = %v", err)
	}
}

func TestNginxServiceRollbackRestoresMaskedInactivePackageState(t *testing.T) {
	t.Parallel()
	manager, paths, runner := nginxServiceFixture(t, "masked", "inactive")
	plan, err := manager.Plan()
	if err != nil {
		t.Fatal(err)
	}
	installation, err := manager.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Activate(context.Background(), installation); err != nil {
		t.Fatal(err)
	}
	if err := manager.Rollback(context.Background(), installation); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(NginxServiceDropInPath(paths)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rolled-back drop-in error = %v", err)
	}
	if runner.enablement != "masked" || runner.active != "inactive" {
		t.Fatalf("rolled-back service state = %s/%s", runner.enablement, runner.active)
	}
	commands := strings.Join(runner.commands, "\n")
	for _, required := range []string{"stop nginx.service", "disable nginx.service", "daemon-reload", "mask nginx.service"} {
		if !strings.Contains(commands, required) {
			t.Errorf("rollback commands omit %q:\n%s", required, commands)
		}
	}
}

func TestNginxServiceRollbackPreservesPreexistingActiveService(t *testing.T) {
	t.Parallel()
	manager, _, runner := nginxServiceFixture(t, "enabled", "active")
	plan, err := manager.Plan()
	if err != nil {
		t.Fatal(err)
	}
	installation, err := manager.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Activate(context.Background(), installation); err != nil {
		t.Fatal(err)
	}
	if err := manager.Rollback(context.Background(), installation); err != nil {
		t.Fatal(err)
	}
	if runner.enablement != "enabled" || runner.active != "active" {
		t.Fatalf("restored service state = %s/%s", runner.enablement, runner.active)
	}
}

func TestNginxServiceRejectsForeignOrUnsafeDropInWithoutMutation(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct {
		name  string
		setup func(string) error
	}{
		{name: "foreign", setup: func(path string) error {
			return os.WriteFile(path, []byte("[Service]\nEnvironment=FOREIGN=1\n"), 0o644)
		}},
		{name: "symlink", setup: func(path string) error { return os.Symlink("/tmp/foreign", path) }},
	} {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			manager, paths, runner := nginxServiceFixture(t, "disabled", "inactive")
			path := NginxServiceDropInPath(paths)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := fixture.setup(path); err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Plan(); !errors.Is(err, ErrNginxServiceConflict) {
				t.Fatalf("Plan() error = %v", err)
			}
			if len(runner.commands) != 0 {
				t.Fatalf("foreign conflict mutated service: %v", runner.commands)
			}
		})
	}
}

func TestNginxServiceDaemonReloadFailureRemovesOnlyNewDropIn(t *testing.T) {
	t.Parallel()
	manager, paths, runner := nginxServiceFixture(t, "masked", "inactive")
	plan, err := manager.Plan()
	if err != nil {
		t.Fatal(err)
	}
	runner.failDaemonReload = 1
	if _, err := manager.Apply(context.Background(), plan); err == nil {
		t.Fatal("Apply() error = nil")
	}
	if _, err := os.Lstat(NginxServiceDropInPath(paths)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed apply retained drop-in: %v", err)
	}
	if runner.enablement != "masked" || runner.active != "inactive" {
		t.Fatalf("failed apply changed service state = %s/%s", runner.enablement, runner.active)
	}
}

func TestNginxServiceRemovalDeletesOnlyRetainedOwnedDropIn(t *testing.T) {
	t.Parallel()
	manager, paths, runner := nginxServiceFixture(t, "disabled", "inactive")
	path := NginxServiceDropInPath(paths)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, RenderNginxServiceDropIn(paths), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := manager.PlanRemoval()
	if err != nil || !plan.Present {
		t.Fatalf("PlanRemoval() = %+v, %v", plan, err)
	}
	if err := manager.RemoveStopped(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned drop-in remains: %v", err)
	}
	if got := runner.commands[len(runner.commands)-1]; got != "daemon-reload" {
		t.Fatalf("last removal command = %q", got)
	}
}

func TestNginxServiceRemovalRejectsChangedOwnershipBeforeMutation(t *testing.T) {
	t.Parallel()
	manager, paths, runner := nginxServiceFixture(t, "disabled", "inactive")
	path := NginxServiceDropInPath(paths)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, RenderNginxServiceDropIn(paths), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := manager.PlanRemoval()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := manager.RemoveStopped(context.Background(), plan); !errors.Is(err, ErrNginxServiceConflict) {
		t.Fatalf("stale removal = %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("stale removal controlled service: %v", runner.commands)
	}
}

type nginxServiceRunner struct {
	enablement       string
	active           string
	commands         []string
	failDaemonReload int
}

func (runner *nginxServiceRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	joined := strings.Join(append([]string{command.Name}, command.Args...), " ")
	if command.Name != "systemctl" {
		return linuxplatform.ProbeResult{}, errors.New("unexpected command: " + joined)
	}
	runner.commands = append(runner.commands, strings.Join(command.Args, " "))
	verb := command.Args[0]
	switch verb {
	case "is-enabled":
		exit := 0
		if !nginxServiceWasEnabled(runner.enablement) {
			exit = 1
		}
		return linuxplatform.ProbeResult{Stdout: []byte(runner.enablement + "\n"), ExitCode: exit}, nil
	case "is-active":
		exit := 0
		if runner.active != "active" {
			exit = 3
		}
		return linuxplatform.ProbeResult{Stdout: []byte(runner.active + "\n"), ExitCode: exit}, nil
	case "daemon-reload":
		if runner.failDaemonReload > 0 {
			runner.failDaemonReload--
			return linuxplatform.ProbeResult{ExitCode: 1}, nil
		}
	case "unmask":
		if nginxServiceWasMasked(runner.enablement) {
			runner.enablement = "disabled"
		}
	case "mask":
		runner.enablement = "masked"
	case "enable":
		runner.enablement = "enabled"
	case "disable":
		runner.enablement = "disabled"
	case "start":
		runner.active = "active"
	case "stop":
		runner.active = "inactive"
	default:
		return linuxplatform.ProbeResult{}, errors.New("unexpected command: " + joined)
	}
	return linuxplatform.ProbeResult{}, nil
}

func nginxServiceFixture(t *testing.T, enablement, active string) (*NginxServiceManager, store.Paths, *nginxServiceRunner) {
	t.Helper()
	root := t.TempDir()
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Join(root, "etc", "systemd", "system"), paths.RuntimeDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	runner := &nginxServiceRunner{enablement: enablement, active: active}
	manager, err := NewNginxServiceManager(paths, runner)
	if err != nil {
		t.Fatal(err)
	}
	return manager, paths, runner
}
