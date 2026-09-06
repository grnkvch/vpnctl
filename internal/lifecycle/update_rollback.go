package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

type UpdateRollbackPlan struct {
	OperationID             string
	SnapshotID              string
	Role                    model.Role
	CurrentVersion          string
	TargetVersion           string
	ExpectedStateGeneration uint64
	Changed                 bool
	Blocked                 bool
	Components              []UpdateComponentChange
	Packages                []UpdatePackageCheck
	Fleet                   UpdateFleetCompatibility
	Migration               UpdateStateMigration
	ExpectedInterruptions   []string
	RequiresAction          []string

	prepared *PreparedReleaseBundleUpdate
	snapshot *LoadedUpdateSnapshot
	state    model.State
}

func (updater *Updater) PlanRollback(ctx context.Context) (UpdateRollbackPlan, error) {
	if ctx == nil {
		return UpdateRollbackPlan{}, fmt.Errorf("context is required")
	}
	if updater == nil || updater.runtime.State == nil || updater.runtime.Snapshots == nil || updater.runtime.Bundles == nil || updater.runtime.Fleet == nil || updater.runtime.Host == nil {
		return UpdateRollbackPlan{}, fmt.Errorf("software update rollback dependencies are incomplete")
	}
	updater.mu.Lock()
	defer updater.mu.Unlock()
	current, err := updater.runtime.State.Load()
	if err != nil || current.Validate() != nil || current.Host.Role != model.RoleGateway && current.Host.Role != model.RoleNode {
		return UpdateRollbackPlan{}, fmt.Errorf("software update rollback requires valid initialized state")
	}
	snapshot, err := updater.runtime.Snapshots.LoadPrevious(ctx)
	if err != nil {
		return UpdateRollbackPlan{}, err
	}
	keepSnapshot := false
	defer func() {
		if !keepSnapshot {
			_ = snapshot.Close()
		}
	}()
	operationID, err := model.AllocateUUID(occupiedUpdateOperationIDs(current), updater.runtime.NewUUID)
	if err != nil {
		return UpdateRollbackPlan{}, fmt.Errorf("allocate update rollback operation ID: %w", err)
	}
	plan := UpdateRollbackPlan{
		OperationID: operationID, SnapshotID: snapshot.Metadata.SnapshotID, Role: current.Host.Role,
		CurrentVersion: current.Components.VPNCTLVersion, TargetVersion: snapshot.Metadata.PreviousVersion,
		ExpectedStateGeneration: current.Generation, Changed: true,
		Components: []UpdateComponentChange{}, Packages: []UpdatePackageCheck{},
		Fleet: UpdateFleetCompatibility{Role: current.Host.Role, Compatible: true, Nodes: []UpdateFleetNode{}, RequiresAction: []string{}},
		Migration: UpdateStateMigration{
			FromSchema: current.SchemaVersion, ToSchema: snapshot.State.SchemaVersion,
			Steps: []string{}, Reversible: snapshot.Metadata.MigrationReversible,
		},
		ExpectedInterruptions: []string{}, RequiresAction: []string{}, snapshot: snapshot, state: current,
	}
	block := func(action string) {
		plan.Blocked = true
		plan.RequiresAction = append(plan.RequiresAction, action)
	}
	currentBytes, encodeErr := model.EncodeState(current)
	switch {
	case snapshot.Metadata.Role != current.Host.Role:
		block("the previous update snapshot belongs to a different host role")
	case snapshot.Metadata.UpdatedToVersion != current.Components.VPNCTLVersion:
		block("the installed version no longer matches the update associated with this snapshot")
	case encodeErr != nil || updateSnapshotBytesSHA256(currentBytes) != snapshot.Metadata.AppliedStateSHA256:
		block("authoritative state changed after the snapshotted update; use restore or a newer migration instead of update rollback")
	case !snapshot.Metadata.MigrationReversible:
		block("the previous update used an irreversible state migration and cannot be rolled back")
	}
	if plan.Blocked {
		if err := plan.Validate(); err != nil {
			return UpdateRollbackPlan{}, err
		}
		keepSnapshot = true
		return plan, nil
	}

	prepared, err := updater.runtime.Bundles.PrepareUpdate(ctx, updater.runtime.CurrentBundlePath, snapshot.Release, current.Host.Role)
	if err != nil {
		return UpdateRollbackPlan{}, err
	}
	keepPrepared := false
	defer func() {
		if !keepPrepared {
			_ = prepared.Close()
		}
	}()
	expectedReversible := true
	if snapshot.Metadata.PreviousStateSchema != snapshot.Metadata.UpdatedStateSchema {
		expectedReversible = prepared.CurrentManifest().ComponentManifest.MigrationReversible
	}
	if snapshot.Metadata.MigrationReversible != expectedReversible {
		return UpdateRollbackPlan{}, fmt.Errorf("%w: migration reversibility differs from the installed release", ErrUpdateSnapshotInvalid)
	}
	targetManifest := prepared.TargetManifest()
	if !reflect.DeepEqual(targetManifest.ComponentManifest, snapshot.State.Components) {
		return UpdateRollbackPlan{}, fmt.Errorf("%w: snapshot state and release component manifests differ", ErrUpdateSnapshotInvalid)
	}
	packages, err := updater.runtime.Host.Preflight(ctx, current.Host.Role, targetManifest)
	if err != nil {
		return UpdateRollbackPlan{}, fmt.Errorf("preflight rollback host packages: %w", err)
	}
	fleet, err := updater.runtime.Fleet.Check(ctx, current, targetManifest.ComponentManifest)
	if err != nil {
		return UpdateRollbackPlan{}, fmt.Errorf("check rollback fleet compatibility: %w", err)
	}
	components, err := planUpdateComponents(current.Host.Role, prepared.CurrentManifest(), targetManifest, prepared.Changes())
	if err != nil {
		return UpdateRollbackPlan{}, err
	}
	plan.Components = components
	plan.Packages = append([]UpdatePackageCheck{}, packages...)
	plan.Fleet = cloneUpdateFleet(fleet)
	plan.ExpectedInterruptions = updateInterruptions(current.Host.Role, components)
	if !fleet.Compatible {
		plan.Blocked = true
		plan.RequiresAction = append(plan.RequiresAction, fleet.RequiresAction...)
	}
	for _, check := range packages {
		if !check.Compatible {
			plan.Blocked = true
			plan.RequiresAction = append(plan.RequiresAction, "install a version of "+check.Package+" compatible with the previous release before rollback")
		}
	}
	if err := plan.Validate(); err != nil {
		return UpdateRollbackPlan{}, err
	}
	plan.prepared = prepared
	keepPrepared, keepSnapshot = true, true
	return plan, nil
}

func (updater *Updater) ApplyRollback(ctx context.Context, plan UpdateRollbackPlan) (UpdateResult, error) {
	if ctx == nil {
		return UpdateResult{}, fmt.Errorf("context is required")
	}
	if err := plan.Validate(); err != nil {
		return UpdateResult{}, err
	}
	if plan.Blocked {
		return UpdateResult{}, ErrUpdateIncompatible
	}
	updater.mu.Lock()
	defer updater.mu.Unlock()
	if plan.prepared == nil || plan.snapshot == nil || !plan.snapshot.Release.valid() {
		return UpdateResult{}, fmt.Errorf("%w: retained rollback snapshot is unavailable", ErrUpdateConflict)
	}
	defer func() { _ = updater.DiscardRollback(plan) }()
	current, err := updater.runtime.State.Load()
	if err != nil || !reflect.DeepEqual(current, plan.state) {
		return UpdateResult{}, fmt.Errorf("%w: authoritative state changed after rollback planning", ErrUpdateConflict)
	}
	if err := plan.prepared.ValidateInstalled(ctx); err != nil {
		return UpdateResult{}, err
	}
	now := updater.runtime.Now().UTC().Truncate(time.Second)
	pending, err := beginUpdateRollbackState(current, plan, now)
	if err != nil {
		return UpdateResult{}, err
	}
	if err := updater.runtime.Host.QuiesceManagement(ctx, plan.Role); err != nil {
		_ = updater.runtime.Host.ResumeManagement(context.Background(), plan.Role)
		return UpdateResult{}, fmt.Errorf("quiesce rollback management: %w", err)
	}
	if _, err := updater.saveState(current, pending); err != nil {
		_ = updater.runtime.Host.ResumeManagement(context.Background(), plan.Role)
		return UpdateResult{}, fmt.Errorf("persist pending update rollback: %w", err)
	}
	persisted := pending
	activated := make([]UpdateComponentChange, 0)
	results := make([]UpdateComponentResult, 0, len(plan.Components))
	metadataActive := false
	managementResumed := false
	rollback := func(cause error) error {
		rollbackContext, cancel := context.WithTimeout(context.Background(), UpdateRollbackTimeout)
		defer cancel()
		var rollbackErrors []error
		if managementResumed {
			rollbackErrors = append(rollbackErrors, updater.runtime.Host.QuiesceManagement(rollbackContext, plan.Role))
		}
		if metadataActive {
			rollbackErrors = append(rollbackErrors, plan.prepared.RollbackMetadata(rollbackContext))
		}
		for index := len(activated) - 1; index >= 0; index-- {
			change := activated[index]
			rollbackErrors = append(rollbackErrors,
				plan.prepared.RollbackComponent(rollbackContext, change.Name),
				updater.runtime.Host.RollbackAndHealth(rollbackContext, plan.Role, change),
			)
		}
		failed, stateErr := failUpdateRollbackState(persisted, plan, updater.runtime.Now().UTC().Truncate(time.Second))
		if stateErr != nil {
			rollbackErrors = append(rollbackErrors, stateErr)
		} else if reconciled, saveErr := updater.saveState(persisted, failed); saveErr != nil {
			rollbackErrors = append(rollbackErrors, saveErr)
		} else {
			persisted = reconciled
		}
		rollbackErrors = append(rollbackErrors, updater.runtime.Host.ResumeManagement(rollbackContext, plan.Role))
		return errors.Join(cause, errors.Join(rollbackErrors...))
	}
	for _, change := range plan.Components {
		result := UpdateComponentResult{Name: change.Name, Changed: change.FileChanged, Healthy: !change.FileChanged}
		if change.FileChanged {
			if err := plan.prepared.ActivateComponent(ctx, change.Name); err != nil {
				return UpdateResult{}, rollback(err)
			}
			activated = append(activated, change)
			if err := updater.runtime.Host.ActivateAndHealth(ctx, plan.Role, change); err != nil {
				result.RolledBack = true
				results = append(results, result)
				return UpdateResult{}, rollback(fmt.Errorf("%w: %s: %v", ErrUpdateHealth, change.Name, err))
			}
			result.Healthy = true
		}
		results = append(results, result)
	}
	if err := plan.prepared.PublishMetadata(ctx); err != nil {
		return UpdateResult{}, rollback(err)
	}
	metadataActive = true
	active, err := activateUpdateRollbackState(persisted, plan, updater.runtime.Now().UTC().Truncate(time.Second))
	if err != nil {
		return UpdateResult{}, rollback(err)
	}
	active, err = updater.saveState(persisted, active)
	if err != nil {
		return UpdateResult{}, rollback(fmt.Errorf("publish restored update state: %w", err))
	}
	persisted = active
	if err := updater.runtime.Host.ResumeManagement(ctx, plan.Role); err != nil {
		return UpdateResult{}, rollback(fmt.Errorf("resume rolled-back management: %w", err))
	}
	managementResumed = true
	completed, err := completeUpdateRollbackState(persisted, plan, updater.runtime.Now().UTC().Truncate(time.Second))
	if err != nil {
		return UpdateResult{}, rollback(err)
	}
	completed, err = updater.saveState(persisted, completed)
	if err != nil {
		return UpdateResult{}, rollback(fmt.Errorf("complete update rollback operation: %w", err))
	}
	persisted = completed
	if err := plan.prepared.Commit(); err != nil {
		return UpdateResult{}, fmt.Errorf("finalize release rollback: %w", err)
	}
	if err := updater.runtime.Snapshots.ConsumePrevious(plan.SnapshotID); err != nil {
		return UpdateResult{}, fmt.Errorf("consume completed update snapshot: %w", err)
	}
	return UpdateResult{
		OperationID: plan.OperationID, Role: plan.Role, PreviousVersion: plan.CurrentVersion, CurrentVersion: plan.TargetVersion,
		Generation: persisted.Generation, Changed: true, ComponentResults: results,
		ExpectedInterruptions: append([]string(nil), plan.ExpectedInterruptions...), RequiresAction: []string{},
	}, nil
}

func (updater *Updater) DiscardRollback(plan UpdateRollbackPlan) error {
	var result []error
	if plan.prepared != nil {
		result = append(result, plan.prepared.Close())
	}
	if plan.snapshot != nil {
		result = append(result, plan.snapshot.Close())
	}
	return errors.Join(result...)
}

func (plan UpdateRollbackPlan) Validate() error {
	if !updateSnapshotIDPattern.MatchString(plan.SnapshotID) || plan.OperationID == "" || plan.Role != model.RoleGateway && plan.Role != model.RoleNode ||
		plan.CurrentVersion == "" || plan.TargetVersion == "" || plan.ExpectedStateGeneration == 0 || !plan.Changed {
		return fmt.Errorf("update rollback plan identity is incomplete")
	}
	if plan.Components == nil || plan.Packages == nil || plan.Fleet.Nodes == nil || plan.Fleet.RequiresAction == nil ||
		plan.Migration.Steps == nil || plan.ExpectedInterruptions == nil || plan.RequiresAction == nil {
		return fmt.Errorf("update rollback plan collections must be present")
	}
	if plan.Fleet.Role != plan.Role || plan.Migration.FromSchema < 1 || plan.Migration.ToSchema < 1 {
		return fmt.Errorf("update rollback plan compatibility metadata is inconsistent")
	}
	if plan.Blocked && len(plan.RequiresAction) == 0 {
		return fmt.Errorf("blocked update rollback plan requires an action")
	}
	return nil
}

func beginUpdateRollbackState(current model.State, plan UpdateRollbackPlan, now time.Time) (model.State, error) {
	nextGeneration, err := model.NextGeneration(current.Generation)
	if err != nil {
		return model.State{}, err
	}
	desiredGeneration := current.Generation
	for range 3 {
		desiredGeneration, err = model.NextGeneration(desiredGeneration)
		if err != nil {
			return model.State{}, err
		}
	}
	steps := make([]model.OperationStep, 0, len(plan.Components)+1)
	for _, component := range plan.Components {
		if component.Changed || component.FileChanged {
			steps = append(steps, model.OperationStep{Name: component.Name, State: model.OperationPending, UpdatedAt: now})
		}
	}
	steps = append(steps, model.OperationStep{Name: "state", State: model.OperationPending, UpdatedAt: now})
	candidate := current
	candidate.Generation = nextGeneration
	candidate.Operations = append(append([]model.Operation{}, current.Operations...), model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: plan.OperationID, Type: model.OperationUpdateRollback, State: model.OperationPending,
		TargetKind: "host", TargetID: current.Host.ID, ExpectedGeneration: current.Generation, DesiredGeneration: desiredGeneration,
		Steps: steps, CreatedAt: now, UpdatedAt: now,
	})
	if err := model.ValidateTransition(current, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate pending update rollback state: %w", err)
	}
	return candidate, nil
}

func activateUpdateRollbackState(pending model.State, plan UpdateRollbackPlan, now time.Time) (model.State, error) {
	nextGeneration, err := model.NextGeneration(pending.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate := plan.snapshot.State
	candidate.Generation = nextGeneration
	candidate.Operations = append([]model.Operation{}, pending.Operations...)
	operationIndex := updateOperationIndex(candidate, plan.OperationID)
	if operationIndex < 0 {
		return model.State{}, fmt.Errorf("pending update rollback operation is missing")
	}
	operation := candidate.Operations[operationIndex]
	for _, step := range operation.Steps {
		operation, err = operation.TransitionStep(step.Name, model.OperationCompleted, now)
		if err != nil {
			return model.State{}, err
		}
	}
	operation, err = operation.Transition(model.OperationActive, now, "")
	if err != nil {
		return model.State{}, err
	}
	candidate.Operations[operationIndex] = operation
	if err := model.ValidateTransition(pending, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate active update rollback state: %w", err)
	}
	return candidate, nil
}

func completeUpdateRollbackState(active model.State, plan UpdateRollbackPlan, now time.Time) (model.State, error) {
	nextGeneration, err := model.NextGeneration(active.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate := active
	candidate.Generation = nextGeneration
	candidate.Operations = append([]model.Operation{}, candidate.Operations...)
	operationIndex := updateOperationIndex(candidate, plan.OperationID)
	if operationIndex < 0 {
		return model.State{}, fmt.Errorf("active update rollback operation is missing")
	}
	operation, err := candidate.Operations[operationIndex].Transition(model.OperationCompleted, now, "")
	if err != nil {
		return model.State{}, err
	}
	candidate.Operations[operationIndex] = operation
	if err := model.ValidateTransition(active, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate completed update rollback state: %w", err)
	}
	return candidate, nil
}

func failUpdateRollbackState(persisted model.State, plan UpdateRollbackPlan, now time.Time) (model.State, error) {
	nextGeneration, err := model.NextGeneration(persisted.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate := plan.state
	candidate.Generation = nextGeneration
	candidate.Operations = append([]model.Operation{}, persisted.Operations...)
	operationIndex := updateOperationIndex(candidate, plan.OperationID)
	if operationIndex < 0 {
		return model.State{}, fmt.Errorf("failed update rollback operation is missing")
	}
	operation, err := candidate.Operations[operationIndex].Transition(model.OperationFailed, now, "update_rollback_failed")
	if err != nil {
		return model.State{}, err
	}
	candidate.Operations[operationIndex] = operation
	if err := model.ValidateTransition(persisted, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate failed update rollback state: %w", err)
	}
	return candidate, nil
}
