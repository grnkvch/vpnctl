package operations

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const gatewayInitConvergenceComponent = "role.gateway"

type GatewayInitializationConvergenceStore interface {
	Read(context.Context) (ConvergenceSnapshot, error)
	EnsureInitialized(context.Context, ConvergenceSnapshot) (bool, error)
}

type GatewayServiceConvergenceStore interface {
	Read(context.Context) (ConvergenceSnapshot, error)
	EnsureInitialized(context.Context, ConvergenceSnapshot) (bool, error)
	CompareAndSwap(context.Context, ConvergenceSnapshot, ConvergenceSnapshot) (bool, error)
}

type GatewayInitializationConvergencePublisher struct {
	store    GatewayInitializationConvergenceStore
	material AppliedMaterialEnsurer
}

type GatewayServiceConvergencePublisher struct {
	store    GatewayServiceConvergenceStore
	material AppliedMaterialArchive
}

// GatewayServiceConvergencePreparation is the metadata half of the gateway
// join candidate transaction. Stage advances a clean baseline while the
// controller mutation lock is held; commit retains it after authoritative
// state commits, and rollback restores the exact prior snapshot.
type GatewayServiceConvergencePreparation struct {
	mu        sync.Mutex
	store     GatewayServiceConvergenceStore
	material  AppliedMaterialArchive
	before    ConvergenceSnapshot
	candidate ConvergenceSnapshot
	changed   bool
	finished  bool
}

func NewGatewayInitializationConvergencePublisher(
	store GatewayInitializationConvergenceStore,
	material AppliedMaterialEnsurer,
) (*GatewayInitializationConvergencePublisher, error) {
	if store == nil || material == nil {
		return nil, fmt.Errorf("gateway initialization convergence store and applied material archive are required")
	}
	return &GatewayInitializationConvergencePublisher{store: store, material: material}, nil
}

func NewGatewayServiceConvergencePublisher(
	store GatewayServiceConvergenceStore,
	material AppliedMaterialArchive,
) (*GatewayServiceConvergencePublisher, error) {
	if store == nil || material == nil {
		return nil, fmt.Errorf("gateway service convergence store and applied material archive are required")
	}
	return &GatewayServiceConvergencePublisher{store: store, material: material}, nil
}

func (publisher *GatewayInitializationConvergencePublisher) PublishGatewayInitialization(
	ctx context.Context,
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
) error {
	if ctx == nil || publisher == nil || publisher.store == nil || publisher.material == nil {
		return fmt.Errorf("gateway initialization convergence publisher is incomplete")
	}
	snapshot, err := InitialGatewayRoleConvergenceSnapshot(generation, request)
	if err != nil {
		return err
	}
	material, err := gatewayRoleAppliedMaterial(snapshot.Applied, request, false)
	if err != nil {
		return err
	}
	defer material.Destroy()
	current, err := publisher.store.Read(ctx)
	if err == nil && !reflect.DeepEqual(current, snapshot) {
		return ErrConvergenceSnapshotConflict
	}
	if err != nil && !errors.Is(err, ErrConvergenceSnapshotUnavailable) {
		return fmt.Errorf("read initial gateway convergence snapshot: %w", err)
	}
	if _, err := publisher.material.Ensure(ctx, snapshot.Applied, material); err != nil {
		return fmt.Errorf("publish initial gateway applied material: %w", err)
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
	return gatewayRoleConvergenceSnapshot(generation, request, false)
}

func ActiveGatewayRoleConvergenceSnapshot(
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
) (ConvergenceSnapshot, error) {
	return gatewayRoleConvergenceSnapshot(generation, request, true)
}

func gatewayRoleConvergenceSnapshot(
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
	activeTunnel bool,
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
	if activeTunnel {
		wantConfigs = append(wantConfigs,
			tunnel.FRPServerConfigFileName, tunnel.FRPServerReadyFileName,
			tunnel.FRPServerCertificateName, tunnel.FRPServerPrivateKeyName,
		)
	}
	sort.Strings(wantConfigs)
	if !reflect.DeepEqual(gotConfigs, wantConfigs) {
		return ConvergenceSnapshot{}, fmt.Errorf("initial gateway convergence config set is incomplete")
	}
	_, tunnelReady := ready[tunnel.FRPServerReadyFileName]
	if tunnelReady != activeTunnel {
		return ConvergenceSnapshot{}, fmt.Errorf("gateway convergence tunnel readiness does not match the requested runtime")
	}
	resources := make([]ManagedResource, 0, len(request.Units)+len(request.Configs))
	for _, unit := range request.Units {
		if unit.Name == "" || filepath.Base(unit.Name) != unit.Name || len(unit.Content) == 0 || !unit.Enable || !unit.Start {
			return ConvergenceSnapshot{}, fmt.Errorf("initial gateway unit %q is invalid", unit.Name)
		}
		content := normalizedRoleUnitContent(unit.Content)
		contentSHA256 := ManagedFingerprint(content)
		clear(content)
		activeState, subState := "active", "running"
		if unit.Name == "vpnctl-tunnel-server.service" && !activeTunnel {
			activeState, subState = "inactive", "dead"
		}
		runtimeSHA256, err := ManagedUnitRuntimeFingerprint(expectedRoleUnitRuntime(contentSHA256, activeState, subState, "enabled"))
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

// PrepareActiveGatewayGeneration transactionally stages the exact active
// gateway generation. It deliberately requires an existing clean baseline so
// rollback can restore byte-logically equivalent metadata without inventing a
// delete operation.
func (publisher *GatewayServiceConvergencePublisher) PrepareActiveGatewayGeneration(
	ctx context.Context,
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
) (*GatewayServiceConvergencePreparation, error) {
	if ctx == nil || publisher == nil || publisher.store == nil || publisher.material == nil {
		return nil, fmt.Errorf("gateway service convergence publisher is incomplete")
	}
	candidate, err := ActiveGatewayRoleConvergenceSnapshot(generation, request)
	if err != nil {
		return nil, err
	}
	material, err := gatewayRoleAppliedMaterial(candidate.Applied, request, true)
	if err != nil {
		return nil, err
	}
	defer material.Destroy()
	current, err := publisher.store.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("read prior gateway convergence baseline: %w", err)
	}
	preparation := &GatewayServiceConvergencePreparation{
		store: publisher.store, material: publisher.material, before: current, candidate: candidate,
	}
	if reflect.DeepEqual(current, candidate) {
		if _, err := publisher.material.Ensure(ctx, candidate.Applied, material); err != nil {
			return nil, fmt.Errorf("ensure active gateway applied material: %w", err)
		}
		return preparation, nil
	}
	if err := validatePriorGatewayConvergence(current, generation); err != nil {
		return nil, err
	}
	if _, err := publisher.material.Ensure(ctx, candidate.Applied, material); err != nil {
		return nil, fmt.Errorf("publish active gateway applied material: %w", err)
	}
	changed, err := publisher.store.CompareAndSwap(ctx, current, candidate)
	if err != nil {
		if errors.Is(err, ErrConvergenceSnapshotOutcomeUncertain) {
			observed, readErr := publisher.store.Read(context.Background())
			if readErr == nil && reflect.DeepEqual(observed, candidate) {
				preparation.changed = true
				return preparation, fmt.Errorf("stage active gateway convergence generation: %w", err)
			}
		}
		return nil, fmt.Errorf("stage active gateway convergence generation: %w", err)
	}
	preparation.changed = changed
	return preparation, nil
}

// PublishActiveGatewayGeneration is the recovery form used after an
// authoritative gateway generation is already committed. Unlike transactional
// join staging, it may reconstruct absent metadata from exact state/secrets.
func (publisher *GatewayServiceConvergencePublisher) PublishActiveGatewayGeneration(
	ctx context.Context,
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
) error {
	return publisher.publishGatewayGeneration(ctx, generation, request, true)
}

func (publisher *GatewayServiceConvergencePublisher) PublishInactiveGatewayGeneration(
	ctx context.Context,
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
) error {
	return publisher.publishGatewayGeneration(ctx, generation, request, false)
}

func (publisher *GatewayServiceConvergencePublisher) publishGatewayGeneration(
	ctx context.Context,
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
	activeTunnel bool,
) error {
	if ctx == nil || publisher == nil || publisher.store == nil || publisher.material == nil {
		return fmt.Errorf("gateway service convergence publisher is incomplete")
	}
	var candidate ConvergenceSnapshot
	var err error
	if activeTunnel {
		candidate, err = ActiveGatewayRoleConvergenceSnapshot(generation, request)
	} else {
		candidate, err = InitialGatewayRoleConvergenceSnapshot(generation, request)
	}
	if err != nil {
		return err
	}
	material, err := gatewayRoleAppliedMaterial(candidate.Applied, request, activeTunnel)
	if err != nil {
		return err
	}
	defer material.Destroy()
	current, err := publisher.store.Read(ctx)
	if errors.Is(err, ErrConvergenceSnapshotUnavailable) {
		if _, materialErr := publisher.material.Ensure(ctx, candidate.Applied, material); materialErr != nil {
			return fmt.Errorf("publish recovered gateway applied material: %w", materialErr)
		}
		_, err = publisher.store.EnsureInitialized(ctx, candidate)
		return err
	}
	if err != nil {
		return err
	}
	if reflect.DeepEqual(current, candidate) {
		if _, err := publisher.material.Ensure(ctx, candidate.Applied, material); err != nil {
			return fmt.Errorf("ensure gateway applied material: %w", err)
		}
		return nil
	}
	if err := validatePriorGatewayConvergence(current, generation); err != nil {
		return err
	}
	if _, err := publisher.material.Ensure(ctx, candidate.Applied, material); err != nil {
		return fmt.Errorf("publish gateway applied material: %w", err)
	}
	_, err = publisher.store.CompareAndSwap(ctx, current, candidate)
	return err
}

func validatePriorGatewayConvergence(current ConvergenceSnapshot, generation uint64) error {
	if generation == 0 || current.Applied.Generation >= generation || current.Desired.Generation >= generation ||
		!reflect.DeepEqual(current.Desired, current.Applied) || len(current.Pending) != 0 {
		return fmt.Errorf("%w: prior gateway convergence baseline is not a clean older generation", ErrConvergenceSnapshotConflict)
	}
	return nil
}

func (preparation *GatewayServiceConvergencePreparation) Commit() {
	if preparation == nil {
		return
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	preparation.finished = true
}

func (preparation *GatewayServiceConvergencePreparation) Rollback(ctx context.Context) error {
	if ctx == nil || preparation == nil || preparation.store == nil || preparation.material == nil {
		return fmt.Errorf("gateway convergence rollback is incomplete")
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	if preparation.finished {
		return nil
	}
	preparation.finished = true
	if !preparation.changed {
		return nil
	}
	if _, err := preparation.store.CompareAndSwap(ctx, preparation.candidate, preparation.before); err != nil {
		return fmt.Errorf("rollback active gateway convergence generation: %w", err)
	}
	observed, err := preparation.store.Read(ctx)
	if err != nil || !reflect.DeepEqual(observed, preparation.before) {
		return fmt.Errorf("verify active gateway convergence rollback: %w", errors.Join(err, ErrConvergenceSnapshotConflict))
	}
	if !reflect.DeepEqual(preparation.candidate.Applied, preparation.before.Applied) {
		if _, err := preparation.material.Discard(ctx, preparation.candidate.Applied); err != nil {
			return fmt.Errorf("discard rolled-back gateway applied material: %w", err)
		}
	}
	return nil
}

var _ interface {
	PublishGatewayInitialization(context.Context, uint64, linuxplatform.RoleInstallationRequest) error
} = (*GatewayInitializationConvergencePublisher)(nil)
