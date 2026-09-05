package operations

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const gatewayInitConvergenceComponent = "role.gateway"

type GatewayInitializationConvergenceStore interface {
	EnsureInitialized(context.Context, ConvergenceSnapshot) (bool, error)
}

type GatewayInitializationConvergencePublisher struct {
	store GatewayInitializationConvergenceStore
}

func NewGatewayInitializationConvergencePublisher(store GatewayInitializationConvergenceStore) (*GatewayInitializationConvergencePublisher, error) {
	if store == nil {
		return nil, fmt.Errorf("gateway initialization convergence store is required")
	}
	return &GatewayInitializationConvergencePublisher{store: store}, nil
}

func (publisher *GatewayInitializationConvergencePublisher) PublishGatewayInitialization(
	ctx context.Context,
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
) error {
	if ctx == nil || publisher == nil || publisher.store == nil {
		return fmt.Errorf("gateway initialization convergence publisher is incomplete")
	}
	snapshot, err := InitialGatewayRoleConvergenceSnapshot(generation, request)
	if err != nil {
		return err
	}
	if _, err := publisher.store.EnsureInitialized(ctx, snapshot); err != nil {
		return fmt.Errorf("publish initial gateway convergence snapshot: %w", err)
	}
	return nil
}

// InitialGatewayRoleConvergenceSnapshot describes the exact files and unit
// runtime installed by gateway init. The tunnel-server unit is enabled but
// condition-skipped until a joined node creates its readiness marker; the
// other four initial services are active.
func InitialGatewayRoleConvergenceSnapshot(
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
) (ConvergenceSnapshot, error) {
	if generation == 0 || request.Role != model.RoleGateway || request.Units == nil || request.Configs == nil || len(request.Units) == 0 {
		return ConvergenceSnapshot{}, fmt.Errorf("initial gateway convergence request is invalid")
	}
	wantUnits := linuxplatform.RoleUnitNames(model.RoleGateway)
	sort.Strings(wantUnits)
	gotUnits := make([]string, len(request.Units))
	for index, unit := range request.Units {
		gotUnits[index] = unit.Name
	}
	sort.Strings(gotUnits)
	if !reflect.DeepEqual(gotUnits, wantUnits) {
		return ConvergenceSnapshot{}, fmt.Errorf("gateway convergence unit set is incomplete")
	}
	ready := make(map[string]struct{}, len(request.Configs))
	gotConfigs := make([]string, len(request.Configs))
	for _, config := range request.Configs {
		ready[config.Name] = struct{}{}
	}
	for index, config := range request.Configs {
		gotConfigs[index] = config.Name
	}
	sort.Strings(gotConfigs)
	wantConfigs := append([]string{"bootstrap.conf", "gateway-controller.ready", routing.GatewayDNSConfigFileName, routing.GatewayDNSReadyFileName}, transport.GatewayListenerFileNames()...)
	sort.Strings(wantConfigs)
	if !reflect.DeepEqual(gotConfigs, wantConfigs) {
		return ConvergenceSnapshot{}, fmt.Errorf("initial gateway convergence config set is incomplete")
	}
	if _, present := ready[tunnel.FRPServerReadyFileName]; present {
		return ConvergenceSnapshot{}, fmt.Errorf("initial gateway convergence cannot contain an active tunnel server")
	}
	resources := make([]ManagedResource, 0, len(request.Units)+len(request.Configs))
	for _, unit := range request.Units {
		if unit.Name == "" || filepath.Base(unit.Name) != unit.Name || len(unit.Content) == 0 || !unit.Enable || !unit.Start {
			return ConvergenceSnapshot{}, fmt.Errorf("initial gateway unit %q is invalid", unit.Name)
		}
		content := append([]byte(nil), unit.Content...)
		if content[len(content)-1] != '\n' {
			content = append(content, '\n')
		}
		activeState, subState := "active", "running"
		if unit.Name == "vpnctl-tunnel-server.service" {
			activeState, subState = "inactive", "dead"
		}
		contentSHA256 := ManagedFingerprint(content)
		runtimeSHA256, err := ManagedUnitRuntimeFingerprint(ManagedUnitRuntime{
			FileType: "regular", Mode: "0644", ContentSHA256: contentSHA256,
			LoadState: "loaded", ActiveState: activeState, SubState: subState, Enablement: "enabled",
		})
		if err != nil {
			return ConvergenceSnapshot{}, err
		}
		revisionSHA256, err := roleConvergenceResourceRevision(
			generation, "unit", unit.Name, "0644", contentSHA256, activeState+"/"+subState+"/enabled",
		)
		if err != nil {
			return ConvergenceSnapshot{}, err
		}
		resources = append(resources, ManagedResource{
			Key:            ManagedResourceKey{Component: gatewayInitConvergenceComponent, Kind: ManagedResourceUnit, ID: unit.Name},
			RevisionSHA256: revisionSHA256, RuntimeSHA256: runtimeSHA256,
			ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
		})
	}
	for _, config := range request.Configs {
		if config.Name == "" || filepath.Base(config.Name) != config.Name || len(config.Content) == 0 {
			return ConvergenceSnapshot{}, fmt.Errorf("initial gateway config %q is invalid", config.Name)
		}
		contentSHA256 := ManagedFingerprint(config.Content)
		runtimeSHA256, err := managedFileRuntimeFingerprint("regular", "0600", contentSHA256)
		if err != nil {
			return ConvergenceSnapshot{}, err
		}
		revisionSHA256, err := roleConvergenceResourceRevision(generation, "config", config.Name, "0600", contentSHA256, "present")
		if err != nil {
			return ConvergenceSnapshot{}, err
		}
		resources = append(resources, ManagedResource{
			Key: ManagedResourceKey{
				Component: gatewayInitConvergenceComponent, Kind: ManagedResourceFile,
				ID: filepath.Join("/etc/vpnctl/generated/gateway", config.Name),
			},
			RevisionSHA256: revisionSHA256, RuntimeSHA256: runtimeSHA256,
			ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
		})
	}
	manifest, err := NewConvergenceManifest(generation, resources)
	if err != nil {
		return ConvergenceSnapshot{}, err
	}
	return ConvergenceSnapshot{Desired: cloneManifest(manifest), Applied: cloneManifest(manifest), Pending: []PendingOperation{}}, nil
}

var _ interface {
	PublishGatewayInitialization(context.Context, uint64, linuxplatform.RoleInstallationRequest) error
} = (*GatewayInitializationConvergencePublisher)(nil)
