package linux

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWatchdogUnitInstallerInstallsOnlyTemplatesIdempotently(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	unitDir := filepath.Join(root, "etc", "systemd", "system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &roleSystemdRunner{}
	installer, err := NewWatchdogUnitInstaller(root, runner)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := installer.Plan(DefaultVPNCTLBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := installer.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(changed, plan.UnitFiles) {
		t.Fatalf("changed files = %v, want %v", changed, plan.UnitFiles)
	}
	for _, unit := range []string{WatchdogServiceUnitName, WatchdogTimerUnitName} {
		if info, err := os.Stat(filepath.Join(unitDir, unit)); err != nil || info.Mode().Perm() != 0o644 {
			t.Fatalf("watchdog unit %s = %v, %v", unit, info, err)
		}
	}
	if got := runner.joined(); got != "daemon-reload" {
		t.Fatalf("systemctl calls = %q", got)
	}
	second, err := installer.Apply(context.Background(), plan)
	if err != nil || len(second) != 0 {
		t.Fatalf("idempotent Apply() = %v, %v", second, err)
	}
	if got := runner.joined(); got != "daemon-reload\ndaemon-reload" {
		t.Fatalf("idempotent systemctl calls = %q", got)
	}
}

func TestWatchdogUnitInstallerRejectsModifiedPlanBeforeMutation(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	unitDir := filepath.Join(root, "etc", "systemd", "system")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &roleSystemdRunner{}
	installer, _ := NewWatchdogUnitInstaller(root, runner)
	plan, _ := installer.Plan(DefaultVPNCTLBinaryPath)
	plan.Units[0].Content = []byte("modified")
	if _, err := installer.Apply(context.Background(), plan); err == nil {
		t.Fatal("Apply() accepted a modified watchdog plan")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("modified plan called systemctl: %v", runner.calls)
	}
	if entries, err := os.ReadDir(unitDir); err != nil || len(entries) != 0 {
		t.Fatalf("modified plan wrote units: %v, %v", entries, err)
	}
}
