package operations

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

// AppliedMaterialEnsurer is the mutation-only half of the immutable archive.
// A convergence publisher must make the complete applied generation durable
// before it makes the matching content-free manifest authoritative.
type AppliedMaterialEnsurer interface {
	Ensure(context.Context, ConvergenceManifest, *AppliedMaterialSet) (AppliedMaterialID, error)
}

type AppliedMaterialArchive interface {
	AppliedMaterialEnsurer
	Discard(context.Context, ConvergenceManifest) (bool, error)
}

func gatewayRoleAppliedMaterial(
	applied ConvergenceManifest,
	request linuxplatform.RoleInstallationRequest,
	activeTunnel bool,
) (*AppliedMaterialSet, error) {
	return roleAppliedMaterial(applied, request, gatewayInitConvergenceComponent, func(name, contentSHA256 string) ManagedUnitRuntime {
		activeState, subState := "active", "running"
		if name == "vpnctl-tunnel-server.service" && !activeTunnel {
			activeState, subState = "inactive", "dead"
		}
		return expectedRoleUnitRuntime(contentSHA256, activeState, subState, "enabled")
	})
}

func nodeRoleAppliedMaterial(
	applied ConvergenceManifest,
	request linuxplatform.RoleInstallationRequest,
	active bool,
) (*AppliedMaterialSet, error) {
	return roleAppliedMaterial(applied, request, nodeInitConvergenceComponent, func(name, contentSHA256 string) ManagedUnitRuntime {
		activeState, subState, enablement := "inactive", "dead", "disabled"
		if active {
			activeState, subState, enablement = "active", "running", "enabled"
			if name == "vpnctl-routing-guard.service" {
				subState = "exited"
			}
		}
		return expectedRoleUnitRuntime(contentSHA256, activeState, subState, enablement)
	})
}

func roleAppliedMaterial(
	applied ConvergenceManifest,
	request linuxplatform.RoleInstallationRequest,
	component string,
	unitRuntime func(string, string) ManagedUnitRuntime,
) (*AppliedMaterialSet, error) {
	if request.Role != model.RoleGateway && request.Role != model.RoleNode || unitRuntime == nil {
		return nil, ErrAppliedMaterialInvalid
	}
	material := make([]AppliedMaterial, 0, len(request.Units)+len(request.Configs))
	defer func() {
		for index := range material {
			material[index].Destroy()
		}
	}()
	for _, unit := range request.Units {
		content := normalizedRoleUnitContent(unit.Content)
		contentSHA256 := ManagedFingerprint(content)
		entry, err := NewAppliedUnitMaterial(
			ManagedResourceKey{Component: component, Kind: ManagedResourceUnit, ID: unit.Name},
			0o644,
			content,
			unitRuntime(unit.Name, contentSHA256),
		)
		clear(content)
		if err != nil {
			return nil, fmt.Errorf("compile applied unit material %s: %w", unit.Name, err)
		}
		material = append(material, entry)
	}
	for _, config := range request.Configs {
		entry, err := NewAppliedFileMaterial(
			ManagedResourceKey{
				Component: component,
				Kind:      ManagedResourceFile,
				ID:        filepath.Join("/etc/vpnctl/generated", string(request.Role), config.Name),
			},
			0o600,
			config.Content,
		)
		if err != nil {
			return nil, fmt.Errorf("compile applied config material %s: %w", config.Name, err)
		}
		material = append(material, entry)
	}
	set, err := NewAppliedMaterialSet(applied, material)
	if err != nil {
		return nil, fmt.Errorf("bind applied role material: %w", err)
	}
	return set, nil
}

func expectedRoleUnitRuntime(
	contentSHA256 string,
	activeState string,
	subState string,
	enablement string,
) ManagedUnitRuntime {
	return ManagedUnitRuntime{
		FileType:      "regular",
		Mode:          "0644",
		ContentSHA256: contentSHA256,
		LoadState:     "loaded",
		ActiveState:   activeState,
		SubState:      subState,
		Enablement:    enablement,
	}
}

func normalizedRoleUnitContent(content []byte) []byte {
	result := append([]byte(nil), content...)
	if len(result) != 0 && result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	return result
}
