package operations

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

// NodeTransportSwitchConvergencePublisher retains the exact final node
// service material before publishing a desired/applied diff. It never changes
// local state, service files, unit state, routes, or the active transport.
type NodeTransportSwitchConvergencePublisher struct {
	store      NodeServiceConvergenceStore
	material   AppliedMaterialEnsurer
	binaryPath string
}

func NewNodeTransportSwitchConvergencePublisher(
	store NodeServiceConvergenceStore,
	material AppliedMaterialEnsurer,
	binaryPath string,
) (*NodeTransportSwitchConvergencePublisher, error) {
	if store == nil || material == nil || !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath {
		return nil, fmt.Errorf("node transport switch convergence dependencies are invalid")
	}
	return &NodeTransportSwitchConvergencePublisher{store: store, material: material, binaryPath: binaryPath}, nil
}

func (publisher *NodeTransportSwitchConvergencePublisher) PublishDesired(
	ctx context.Context,
	operation model.Operation,
	configs []linuxplatform.RoleConfigFile,
) error {
	if ctx == nil || publisher == nil || publisher.store == nil || publisher.material == nil {
		return fmt.Errorf("node transport switch convergence publisher is incomplete")
	}
	if operation.Type != model.OperationTransportSwitch || operation.TargetKind != "transport" || operation.State != model.OperationPending {
		return fmt.Errorf("%w: operation is not a pending transport switch", ErrConvergencePlanInvalid)
	}
	intent, err := transport.ParseSwitchIntentTarget(operation.TargetID)
	if err != nil {
		return fmt.Errorf("%w: parse transport switch target: %v", ErrConvergencePlanInvalid, err)
	}
	request, err := linuxplatform.RenderNodeRoleInstallation(publisher.binaryPath)
	if err != nil {
		return err
	}
	for index := range request.Units {
		request.Units[index].Enable = true
		request.Units[index].Start = false
	}
	request.Configs = append(request.Configs, cloneRoleConfigs(configs)...)
	desiredSnapshot, err := ActiveNodeRoleConvergenceSnapshot(intent.DesiredNodeGeneration, request)
	if err != nil {
		return fmt.Errorf("compile transport switch desired manifest: %w", err)
	}
	current, err := publisher.store.Read(ctx)
	if err != nil {
		return fmt.Errorf("read node convergence baseline: %w", err)
	}
	if current.Applied.Generation != intent.ExpectedNodeGeneration {
		return fmt.Errorf("%w: node applied generation is %d, expected %d", ErrConvergenceSnapshotConflict,
			current.Applied.Generation, intent.ExpectedNodeGeneration)
	}
	changed := changedConvergenceResourceKeys(current.Applied, desiredSnapshot.Desired)
	if len(changed) == 0 {
		return fmt.Errorf("%w: transport switch has no node resource differences", ErrConvergencePlanInvalid)
	}
	binding, err := BindPendingOperationAtGenerations(
		operation, intent.ExpectedNodeGeneration, intent.DesiredNodeGeneration, changed,
	)
	if err != nil {
		return err
	}
	candidate, err := canonicalSnapshot(ConvergenceSnapshot{
		Desired: desiredSnapshot.Desired,
		Applied: cloneManifest(current.Applied),
		Pending: []PendingOperation{binding},
	})
	if err != nil {
		return err
	}
	if _, err := desiredChanges(candidate); err != nil {
		return err
	}
	equal := reflect.DeepEqual(current, candidate)
	clean := reflect.DeepEqual(current.Desired, current.Applied) && len(current.Pending) == 0
	if !equal && !clean {
		return fmt.Errorf("%w: node convergence baseline already has a different pending change", ErrConvergenceSnapshotConflict)
	}
	material, err := nodeRoleAppliedMaterial(candidate.Desired, request, true)
	if err != nil {
		return err
	}
	defer material.Destroy()
	if _, err := publisher.material.Ensure(ctx, candidate.Desired, material); err != nil {
		return fmt.Errorf("stage node transport switch desired material: %w", err)
	}
	if equal {
		return nil
	}
	if _, err := publisher.store.CompareAndSwap(ctx, current, candidate); err != nil {
		return fmt.Errorf("publish node transport switch desired snapshot: %w", err)
	}
	return nil
}

func changedConvergenceResourceKeys(applied, desired ConvergenceManifest) []ManagedResourceKey {
	before := resourcesByKey(applied.Resources)
	after := resourcesByKey(desired.Resources)
	keys := unionResourceKeys(before, after)
	changed := make([]ManagedResourceKey, 0, len(keys))
	for _, key := range keys {
		prior, hadPrior := before[key]
		next, hasNext := after[key]
		if !hadPrior {
			changed = append(changed, next.Key)
		} else if !hasNext || prior.RevisionSHA256 != next.RevisionSHA256 {
			changed = append(changed, prior.Key)
		}
	}
	return changed
}

var _ interface {
	PublishDesired(context.Context, model.Operation, []linuxplatform.RoleConfigFile) error
} = (*NodeTransportSwitchConvergencePublisher)(nil)
