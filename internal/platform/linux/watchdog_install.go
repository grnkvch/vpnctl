package linux

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
)

type WatchdogUnitInstallationPlan struct {
	BinaryPath string
	UnitFiles  []string
	Units      []WatchdogUnitFile
}

type WatchdogUnitInstaller struct {
	unitDir string
	runner  ProbeRunner
}

func NewWatchdogUnitInstaller(root string, runner ProbeRunner) (*WatchdogUnitInstaller, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fmt.Errorf("watchdog installer root must be clean and absolute")
	}
	if runner == nil {
		return nil, fmt.Errorf("watchdog installer runner is required")
	}
	return &WatchdogUnitInstaller{unitDir: filepath.Join(root, "etc", "systemd", "system"), runner: runner}, nil
}

func (installer *WatchdogUnitInstaller) Plan(binaryPath string) (WatchdogUnitInstallationPlan, error) {
	if installer == nil || installer.runner == nil {
		return WatchdogUnitInstallationPlan{}, fmt.Errorf("watchdog unit installer is incomplete")
	}
	units, err := RenderWatchdogUnits(binaryPath)
	if err != nil {
		return WatchdogUnitInstallationPlan{}, err
	}
	unitFiles := make([]string, len(units))
	for index, unit := range units {
		unitFiles[index] = filepath.Join(installer.unitDir, unit.Name)
	}
	sort.Strings(unitFiles)
	return WatchdogUnitInstallationPlan{BinaryPath: binaryPath, UnitFiles: unitFiles, Units: units}, nil
}

func (installer *WatchdogUnitInstaller) Apply(ctx context.Context, plan WatchdogUnitInstallationPlan) ([]string, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	want, err := installer.Plan(plan.BinaryPath)
	if err != nil {
		return nil, err
	}
	if !equalWatchdogUnitPlans(plan, want) {
		return nil, fmt.Errorf("watchdog unit installation plan was modified")
	}
	if err := validateRealDirectory(installer.unitDir); err != nil {
		return nil, fmt.Errorf("validate systemd unit directory: %w", err)
	}
	changed := make([]string, 0, len(plan.Units))
	for _, unit := range plan.Units {
		path := filepath.Join(installer.unitDir, unit.Name)
		updated, err := installAtomicRoleFile(path, normalizedText(unit.Content), 0o644)
		if err != nil {
			return changed, err
		}
		if updated {
			changed = append(changed, path)
		}
	}
	result, err := installer.runner.Run(ctx, ProbeCommand{Name: "systemctl", Args: []string{"daemon-reload"}})
	if err != nil {
		return changed, err
	}
	if result.ExitCode != 0 {
		return changed, fmt.Errorf("systemctl daemon-reload failed with exit code %d", result.ExitCode)
	}
	return changed, nil
}

func equalWatchdogUnitPlans(left, right WatchdogUnitInstallationPlan) bool {
	if left.BinaryPath != right.BinaryPath || len(left.UnitFiles) != len(right.UnitFiles) || len(left.Units) != len(right.Units) {
		return false
	}
	for index := range left.UnitFiles {
		if left.UnitFiles[index] != right.UnitFiles[index] {
			return false
		}
	}
	for index := range left.Units {
		if left.Units[index].Name != right.Units[index].Name || !bytes.Equal(left.Units[index].Content, right.Units[index].Content) {
			return false
		}
	}
	return true
}
