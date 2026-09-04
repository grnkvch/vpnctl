package lifecycle

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const updateControllerUnit = "vpnctl-controller.service"

// SystemUpdateHostRuntime is deliberately local-only. It may query installed
// Ubuntu package versions and control role-owned systemd units, but it has no
// network client or remote-node execution dependency.
type SystemUpdateHostRuntime struct {
	root   string
	runner linuxplatform.ProbeRunner
}

func NewSystemUpdateHostRuntime(root string, runner linuxplatform.ProbeRunner) (*SystemUpdateHostRuntime, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || runner == nil {
		return nil, fmt.Errorf("system update runtime requires a clean absolute root and command runner")
	}
	return &SystemUpdateHostRuntime{root: root, runner: runner}, nil
}

func (runtime *SystemUpdateHostRuntime) Preflight(ctx context.Context, role model.Role, manifest ReleaseManifest) ([]UpdatePackageCheck, error) {
	if ctx == nil || runtime == nil || runtime.runner == nil {
		return nil, fmt.Errorf("system update preflight is incomplete")
	}
	checks := make([]UpdatePackageCheck, 0)
	for _, compatibility := range manifest.APTPackages {
		if !releaseRolesContain(compatibility.Roles, role) {
			continue
		}
		check := UpdatePackageCheck{Component: compatibility.Component, Package: compatibility.Package}
		result, err := runtime.runner.Run(ctx, linuxplatform.ProbeCommand{
			Name: "dpkg-query", Args: []string{"--show", "--showformat=${Status}\t${Version}\n", compatibility.Package},
		})
		if err != nil {
			return nil, fmt.Errorf("query installed package %s: %w", compatibility.Package, err)
		}
		const prefix = "install ok installed\t"
		output := string(result.Stdout)
		if result.ExitCode == 0 && strings.HasPrefix(output, prefix) && strings.HasSuffix(output, "\n") && strings.Count(output, "\n") == 1 {
			check.InstalledVersion = strings.TrimSuffix(strings.TrimPrefix(output, prefix), "\n")
			check.Compatible, err = runtime.packageVersionCompatible(ctx, check.InstalledVersion, compatibility)
			if err != nil {
				return nil, err
			}
		}
		checks = append(checks, check)
	}
	sort.Slice(checks, func(left, right int) bool { return checks[left].Component < checks[right].Component })
	return checks, nil
}

func (runtime *SystemUpdateHostRuntime) packageVersionCompatible(ctx context.Context, installed string, compatibility APTPackageCompatibility) (bool, error) {
	for _, comparison := range []struct {
		op      string
		version string
	}{{"ge", compatibility.MinimumVersion}, {"lt", compatibility.MaximumVersionExclusive}} {
		result, err := runtime.runner.Run(ctx, linuxplatform.ProbeCommand{
			Name: "dpkg", Args: []string{"--compare-versions", installed, comparison.op, comparison.version},
		})
		if err != nil {
			return false, fmt.Errorf("compare installed package %s version: %w", compatibility.Package, err)
		}
		if result.ExitCode == 1 {
			return false, nil
		}
		if result.ExitCode != 0 {
			return false, fmt.Errorf("compare installed package %s version exited %d", compatibility.Package, result.ExitCode)
		}
	}
	return true, nil
}

func (runtime *SystemUpdateHostRuntime) QuiesceManagement(ctx context.Context, role model.Role) error {
	if role == model.RoleNode {
		return nil
	}
	return runtime.systemctl(ctx, "stop", updateControllerUnit)
}

func (runtime *SystemUpdateHostRuntime) ActivateAndHealth(ctx context.Context, role model.Role, change UpdateComponentChange) error {
	if change.Name == "vpnctl" {
		return runtime.verifyVPNCTL(ctx, change.TargetVersion)
	}
	for _, service := range change.AffectedServices {
		if service == updateControllerUnit {
			continue
		}
		if err := runtime.systemctl(ctx, "restart", service); err != nil {
			return err
		}
		if err := runtime.systemctl(ctx, "is-active", "--quiet", service); err != nil {
			return fmt.Errorf("health check %s: %w", service, err)
		}
	}
	return nil
}

func (runtime *SystemUpdateHostRuntime) RollbackAndHealth(ctx context.Context, role model.Role, change UpdateComponentChange) error {
	if change.Name == "vpnctl" {
		return runtime.verifyVPNCTL(ctx, change.CurrentVersion)
	}
	return runtime.ActivateAndHealth(ctx, role, change)
}

func (runtime *SystemUpdateHostRuntime) ResumeManagement(ctx context.Context, role model.Role) error {
	if role == model.RoleNode {
		return nil
	}
	if err := runtime.systemctl(ctx, "start", updateControllerUnit); err != nil {
		return err
	}
	return runtime.systemctl(ctx, "is-active", "--quiet", updateControllerUnit)
}

func (runtime *SystemUpdateHostRuntime) verifyVPNCTL(ctx context.Context, expectedVersion string) error {
	binary := filepath.Join(runtime.root, strings.TrimPrefix(linuxplatform.DefaultVPNCTLBinaryPath, "/"))
	result, err := runtime.runner.Run(ctx, linuxplatform.ProbeCommand{Name: binary, Args: []string{"version"}})
	if err != nil {
		return fmt.Errorf("execute updated vpnctl: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("updated vpnctl version check exited %d", result.ExitCode)
	}
	if expectedVersion != "" && !bytes.Equal(result.Stdout, []byte("vpnctl "+expectedVersion+"\n")) {
		return fmt.Errorf("updated vpnctl reported an unexpected version")
	}
	return nil
}

func (runtime *SystemUpdateHostRuntime) systemctl(ctx context.Context, arguments ...string) error {
	if ctx == nil || runtime == nil || runtime.runner == nil {
		return fmt.Errorf("system update runtime is incomplete")
	}
	result, err := runtime.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: arguments})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("systemctl %s exited %d", strings.Join(arguments, " "), result.ExitCode)
	}
	return nil
}

var _ UpdateHostRuntime = (*SystemUpdateHostRuntime)(nil)
