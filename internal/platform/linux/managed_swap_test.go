package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestManagedSwapAcceptStatusUninstallAndPurgeLifecycle(t *testing.T) {
	t.Parallel()

	manager, runner, paths := newManagedSwapHarness(t)
	plan, err := manager.Plan(lowMemoryResources())
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if !plan.Offered || plan.Disposition != ManagedSwapOffered || plan.Path != ManagedSwapLogicalPath || plan.SizeBytes != ManagedSwapSizeBytes {
		t.Fatalf("offer = %+v", plan)
	}
	if _, err := os.Lstat(plan.PhysicalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only plan created swap: %v", err)
	}

	owned, err := manager.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if owned != (model.ManagedSwap{Path: ManagedSwapLogicalPath, SizeBytes: int64(ManagedSwapSizeBytes), Enabled: true}) {
		t.Fatalf("owned resource = %+v", owned)
	}
	info, err := os.Lstat(plan.PhysicalPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || uint64(info.Size()) != ManagedSwapSizeBytes {
		t.Fatalf("swap file = %v, %v", info, err)
	}
	if data, err := os.ReadFile(plan.PhysicalUnit); err != nil || !reflect.DeepEqual(data, renderManagedSwapUnit()) {
		t.Fatalf("swap unit = %q, %v", data, err)
	}
	status, err := manager.Status(context.Background(), &owned)
	if err != nil || !status.Owned || !status.FilePresent || !status.UnitPresent || !status.Enabled || !status.Active || !status.Healthy || len(status.Drift) != 0 {
		t.Fatalf("active status = %+v, %v", status, err)
	}

	if err := manager.Deactivate(context.Background(), owned, false); err != nil {
		t.Fatalf("Deactivate(uninstall) error = %v", err)
	}
	if _, err := os.Stat(plan.PhysicalPath); err != nil {
		t.Fatalf("uninstall removed recoverable swap file: %v", err)
	}
	if _, err := os.Lstat(plan.PhysicalUnit); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uninstall preserved activation unit: %v", err)
	}
	disabled := owned
	disabled.Enabled = false
	status, err = manager.Status(context.Background(), &disabled)
	if err != nil || !status.Healthy || !status.FilePresent || status.UnitPresent || status.Enabled || status.Active {
		t.Fatalf("uninstalled status = %+v, %v", status, err)
	}

	if err := manager.Deactivate(context.Background(), disabled, true); err != nil {
		t.Fatalf("Deactivate(purge) error = %v", err)
	}
	if _, err := os.Lstat(plan.PhysicalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("purge preserved swap file: %v", err)
	}
	if _, err := os.Lstat(paths.StateDir); err != nil {
		t.Fatalf("purge removed broader state directory: %v", err)
	}
	if runner.active || runner.enabled {
		t.Fatalf("swap remains active after lifecycle: %+v", runner)
	}
	joined := strings.Join(runner.calls, "\n")
	for _, required := range []string{
		"fallocate --length 1073741824 " + plan.PhysicalPath,
		"mkswap " + plan.PhysicalPath,
		"systemctl enable " + ManagedSwapUnitName,
		"systemctl start " + ManagedSwapUnitName,
		"systemctl stop " + ManagedSwapUnitName,
		"systemctl disable " + ManagedSwapUnitName,
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("manager calls lack %q: %v", required, runner.calls)
		}
	}
}

func TestManagedSwapDeclineAndExistingSwapRequireNoMutation(t *testing.T) {
	t.Parallel()

	t.Run("decline", func(t *testing.T) {
		manager, runner, _ := newManagedSwapHarness(t)
		plan, err := manager.Plan(lowMemoryResources())
		if err != nil || !plan.Offered {
			t.Fatalf("Plan() = %+v, %v", plan, err)
		}
		// Declining means the caller deliberately does not invoke Apply.
		if len(runner.calls) != 0 {
			t.Fatalf("declined offer invoked commands: %v", runner.calls)
		}
		if _, err := os.Lstat(plan.PhysicalPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("declined offer created swap: %v", err)
		}
	})

	t.Run("existing adequate swap", func(t *testing.T) {
		manager, runner, _ := newManagedSwapHarness(t)
		resources := lowMemoryResources()
		resources.SwapTotalBytes = ManagedSwapSizeBytes
		plan, err := manager.Plan(resources)
		if err != nil || plan.Offered || plan.Disposition != ManagedSwapExistingAdequate {
			t.Fatalf("Plan() = %+v, %v", plan, err)
		}
		if _, err := manager.Apply(context.Background(), plan); !errors.Is(err, ErrManagedSwapPlan) {
			t.Fatalf("Apply(existing) error = %v", err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("existing swap invoked commands: %v", runner.calls)
		}
	})
}

func TestManagedSwapInsufficientDiskIsUnavailableWithoutMutation(t *testing.T) {
	t.Parallel()

	manager, runner, _ := newManagedSwapHarness(t)
	resources := lowMemoryResources()
	resources.DiskFreeBytes = ManagedSwapSizeBytes + ManagedSwapDiskReserve - 1
	plan, err := manager.Plan(resources)
	if err != nil || plan.Offered || plan.Disposition != ManagedSwapInsufficientDisk {
		t.Fatalf("Plan() = %+v, %v", plan, err)
	}
	if _, err := manager.Apply(context.Background(), plan); !errors.Is(err, ErrManagedSwapPlan) {
		t.Fatalf("Apply(insufficient) error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("insufficient disk invoked commands: %v", runner.calls)
	}
	if _, err := os.Lstat(plan.PhysicalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("insufficient disk created swap: %v", err)
	}
}

func TestManagedSwapRefusesForeignTargetsAndPreservesThem(t *testing.T) {
	t.Parallel()

	t.Run("foreign file during plan", func(t *testing.T) {
		manager, runner, _ := newManagedSwapHarness(t)
		if err := os.WriteFile(manager.physicalPath, []byte("foreign\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Plan(lowMemoryResources()); !errors.Is(err, ErrManagedSwapConflict) {
			t.Fatalf("Plan() error = %v", err)
		}
		if data, err := os.ReadFile(manager.physicalPath); err != nil || string(data) != "foreign\n" {
			t.Fatalf("foreign file changed: %q, %v", data, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("conflict invoked commands: %v", runner.calls)
		}
	})

	t.Run("tampered unit during uninstall", func(t *testing.T) {
		manager, runner, _ := newManagedSwapHarness(t)
		if err := os.WriteFile(manager.unitPath, []byte("foreign\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		owned := model.ManagedSwap{Path: ManagedSwapLogicalPath, SizeBytes: int64(ManagedSwapSizeBytes), Enabled: true}
		if err := manager.Deactivate(context.Background(), owned, true); !errors.Is(err, ErrManagedSwapConflict) {
			t.Fatalf("Deactivate() error = %v", err)
		}
		if data, err := os.ReadFile(manager.unitPath); err != nil || string(data) != "foreign\n" {
			t.Fatalf("foreign unit changed: %q, %v", data, err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("tampered unit invoked commands: %v", runner.calls)
		}
	})

	t.Run("symlink file during purge", func(t *testing.T) {
		manager, runner, _ := newManagedSwapHarness(t)
		target := filepath.Join(filepath.Dir(manager.physicalPath), "foreign-data")
		if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, manager.physicalPath); err != nil {
			t.Fatal(err)
		}
		owned := model.ManagedSwap{Path: ManagedSwapLogicalPath, SizeBytes: int64(ManagedSwapSizeBytes)}
		if err := manager.Deactivate(context.Background(), owned, true); !errors.Is(err, ErrManagedSwapConflict) {
			t.Fatalf("Deactivate() error = %v", err)
		}
		if data, err := os.ReadFile(target); err != nil || string(data) != "keep\n" {
			t.Fatalf("symlink target changed: %q, %v", data, err)
		}
		if len(runner.calls) != 1 || runner.calls[0] != "swapon --noheadings --raw --show=NAME" {
			t.Fatalf("symlink purge calls = %v", runner.calls)
		}
	})
}

func TestManagedSwapApplyFailureRollsBackExactCreatedResources(t *testing.T) {
	t.Parallel()

	manager, runner, _ := newManagedSwapHarness(t)
	runner.failCommand = "mkswap"
	plan, err := manager.Plan(lowMemoryResources())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "synthetic mkswap failure") {
		t.Fatalf("Apply() error = %v", err)
	}
	for _, target := range []string{plan.PhysicalPath, plan.PhysicalUnit} {
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed apply preserved %s: %v", target, err)
		}
	}
}

func lowMemoryResources() HostResources {
	return HostResources{
		MemoryTotalBytes: 512 << 20,
		SwapTotalBytes:   0,
		DiskFreeBytes:    3 << 30,
	}
}

func newManagedSwapHarness(t *testing.T) (*ManagedSwapManager, *managedSwapRunner, store.Paths) {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{
		filepath.Join(root, "etc"), filepath.Join(root, "etc", "systemd"), filepath.Join(root, "etc", "systemd", "system"),
		filepath.Join(root, "var"), filepath.Join(root, "var", "lib"), filepath.Join(root, "var", "lib", "vpnctl"),
	} {
		mode := os.FileMode(0o755)
		if strings.HasSuffix(directory, "vpnctl") {
			mode = 0o700
		}
		if err := os.Mkdir(directory, mode); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	runner := &managedSwapRunner{}
	manager, err := NewManagedSwapManager(paths.Root, paths.StateDir, runner)
	if err != nil {
		t.Fatal(err)
	}
	runner.physicalPath = manager.physicalPath
	return manager, runner, paths
}

type managedSwapRunner struct {
	physicalPath string
	calls        []string
	enabled      bool
	active       bool
	failCommand  string
}

func (runner *managedSwapRunner) Run(_ context.Context, command ProbeCommand) (ProbeResult, error) {
	line := command.Name
	if len(command.Args) != 0 {
		line += " " + strings.Join(command.Args, " ")
	}
	runner.calls = append(runner.calls, line)
	if command.Name == runner.failCommand {
		return ProbeResult{ExitCode: 1, Stderr: []byte("synthetic " + command.Name + " failure")}, nil
	}
	switch command.Name {
	case "fallocate":
		if len(command.Args) != 3 || command.Args[0] != "--length" || command.Args[2] != runner.physicalPath {
			return ProbeResult{}, errors.New("unexpected fallocate arguments")
		}
		size, err := strconv.ParseInt(command.Args[1], 10, 64)
		if err != nil {
			return ProbeResult{}, err
		}
		if err := os.Truncate(runner.physicalPath, size); err != nil {
			return ProbeResult{}, err
		}
	case "systemctl":
		if len(command.Args) == 0 {
			return ProbeResult{}, errors.New("missing systemctl verb")
		}
		switch command.Args[0] {
		case "enable":
			runner.enabled = true
		case "start":
			runner.active = true
		case "stop":
			runner.active = false
		case "disable":
			runner.enabled = false
		case "is-enabled":
			if !runner.enabled {
				return ProbeResult{ExitCode: 1}, nil
			}
		case "is-active":
			if !runner.active {
				return ProbeResult{ExitCode: 3}, nil
			}
		}
	case "swapon":
		if runner.active {
			return ProbeResult{Stdout: []byte(runner.physicalPath + "\n")}, nil
		}
	case "swapoff":
		runner.active = false
	}
	return ProbeResult{}, nil
}
