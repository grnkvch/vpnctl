package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

var (
	ErrUpdateConflict     = errors.New("software update conflict")
	ErrUpdateIncompatible = errors.New("software update is incompatible")
	ErrUpdateHealth       = errors.New("software update component health check failed")
)

const UpdateRollbackTimeout = 15 * time.Second

type UpdateReleaseStager interface {
	Stage(context.Context, string) (*StagedUpdateRelease, error)
}

type UpdateStateStore interface {
	Load() (model.State, error)
	Save(uint64, model.State) error
}

type UpdateFleetChecker interface {
	Check(context.Context, model.State, model.ComponentManifest) (UpdateFleetCompatibility, error)
}

type UpdateHostRuntime interface {
	Preflight(context.Context, model.Role, ReleaseManifest) ([]UpdatePackageCheck, error)
	QuiesceManagement(context.Context, model.Role) error
	ActivateAndHealth(context.Context, model.Role, UpdateComponentChange) error
	RollbackAndHealth(context.Context, model.Role, UpdateComponentChange) error
	ResumeManagement(context.Context, model.Role) error
}

type UpdateComponentChange struct {
	Name             string
	CurrentVersion   string
	TargetVersion    string
	Bundled          bool
	Changed          bool
	FileChanged      bool
	AffectedServices []string
}

type UpdatePackageCheck struct {
	Component        string
	Package          string
	InstalledVersion string
	Compatible       bool
}

type UpdateFleetNode struct {
	ID              string
	Name            string
	ControlProtocol string
	Compatible      bool
	Code            string
}

type UpdateFleetCompatibility struct {
	Role             model.Role
	Compatible       bool
	SelectedProtocol string
	GatewayVersion   string
	Nodes            []UpdateFleetNode
	RequiresAction   []string
}

type UpdateStateMigration struct {
	FromSchema int
	ToSchema   int
	Steps      []string
	Reversible bool
}

type UpdatePlan struct {
	OperationID             string
	Role                    model.Role
	RequestedVersion        string
	LatestStable            bool
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
	RollbackAvailable       bool
	RequiresAction          []string

	prepared *PreparedReleaseBundleUpdate
	stage    *StagedUpdateRelease
	state    model.State
}

type UpdateResult struct {
	OperationID           string
	Role                  model.Role
	PreviousVersion       string
	CurrentVersion        string
	Generation            uint64
	Changed               bool
	ComponentResults      []UpdateComponentResult
	ExpectedInterruptions []string
	RequiresAction        []string
}

type UpdateComponentResult struct {
	Name       string
	Changed    bool
	Healthy    bool
	RolledBack bool
}

type UpdateRuntime struct {
	State             UpdateStateStore
	Releases          UpdateReleaseStager
	Bundles           *ReleaseBundleInstaller
	Fleet             UpdateFleetChecker
	Host              UpdateHostRuntime
	CurrentBundlePath string
	Now               func() time.Time
	NewUUID           model.UUIDGenerator
}

type Updater struct {
	runtime UpdateRuntime
	mu      sync.Mutex
}

func NewUpdater(runtime UpdateRuntime) (*Updater, error) {
	if runtime.State == nil || runtime.Releases == nil || runtime.Bundles == nil || runtime.Fleet == nil || runtime.Host == nil {
		return nil, fmt.Errorf("software update dependencies are incomplete")
	}
	if runtime.CurrentBundlePath == "" {
		return nil, fmt.Errorf("current release bundle path is required")
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	if runtime.NewUUID == nil {
		runtime.NewUUID = model.NewUUID
	}
	return &Updater{runtime: runtime}, nil
}

func (updater *Updater) Plan(ctx context.Context, requestedVersion string) (UpdatePlan, error) {
	if ctx == nil {
		return UpdatePlan{}, fmt.Errorf("context is required")
	}
	if updater == nil || updater.runtime.State == nil || updater.runtime.Releases == nil || updater.runtime.Bundles == nil || updater.runtime.Fleet == nil || updater.runtime.Host == nil {
		return UpdatePlan{}, fmt.Errorf("software updater is incomplete")
	}
	updater.mu.Lock()
	defer updater.mu.Unlock()
	state, err := updater.runtime.State.Load()
	if err != nil {
		return UpdatePlan{}, fmt.Errorf("load update state: %w", err)
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway && state.Host.Role != model.RoleNode {
		return UpdatePlan{}, fmt.Errorf("software update requires valid initialized state")
	}
	stage, err := updater.runtime.Releases.Stage(ctx, requestedVersion)
	if err != nil {
		return UpdatePlan{}, fmt.Errorf("stage target release: %w", err)
	}
	keepStage := false
	defer func() {
		if !keepStage {
			_ = stage.Close()
		}
	}()
	prepared, err := updater.runtime.Bundles.PrepareUpdate(ctx, updater.runtime.CurrentBundlePath, stage, state.Host.Role)
	if err != nil {
		return UpdatePlan{}, err
	}
	keepPrepared := false
	defer func() {
		if !keepPrepared {
			_ = prepared.Close()
		}
	}()
	currentManifest := prepared.CurrentManifest()
	targetManifest := prepared.TargetManifest()
	if !reflect.DeepEqual(currentManifest.ComponentManifest, state.Components) {
		return UpdatePlan{}, fmt.Errorf("%w: installed bundle differs from authoritative component state", ErrUpdateConflict)
	}
	migration := planUpdateStateMigration(state, targetManifest.ComponentManifest)
	fleet, err := updater.runtime.Fleet.Check(ctx, state, targetManifest.ComponentManifest)
	if err != nil {
		return UpdatePlan{}, fmt.Errorf("check update fleet compatibility: %w", err)
	}
	packages, err := updater.runtime.Host.Preflight(ctx, state.Host.Role, targetManifest)
	if err != nil {
		return UpdatePlan{}, fmt.Errorf("preflight update host packages: %w", err)
	}
	componentChanges, err := planUpdateComponents(state.Host.Role, currentManifest, targetManifest, prepared.Changes())
	if err != nil {
		return UpdatePlan{}, err
	}
	operationID, err := model.AllocateUUID(occupiedUpdateOperationIDs(state), updater.runtime.NewUUID)
	if err != nil {
		return UpdatePlan{}, fmt.Errorf("allocate update operation ID: %w", err)
	}
	plan := UpdatePlan{
		OperationID: operationID, Role: state.Host.Role, RequestedVersion: requestedVersion, LatestStable: requestedVersion == "",
		CurrentVersion: currentManifest.ComponentManifest.VPNCTLVersion, TargetVersion: targetManifest.ComponentManifest.VPNCTLVersion,
		ExpectedStateGeneration: state.Generation, Components: componentChanges, Packages: append([]UpdatePackageCheck{}, packages...),
		Fleet: cloneUpdateFleet(fleet), Migration: migration, ExpectedInterruptions: updateInterruptions(state.Host.Role, componentChanges),
		RollbackAvailable: migration.Reversible, RequiresAction: []string{}, prepared: prepared, stage: stage, state: state,
	}
	for _, component := range plan.Components {
		plan.Changed = plan.Changed || component.Changed || component.FileChanged
	}
	if plan.CurrentVersion != plan.TargetVersion || !reflect.DeepEqual(currentManifest.ComponentManifest, targetManifest.ComponentManifest) {
		plan.Changed = true
	}
	if !fleet.Compatible {
		plan.Blocked = true
		plan.RequiresAction = append(plan.RequiresAction, fleet.RequiresAction...)
	}
	for _, check := range packages {
		if !check.Compatible {
			plan.Blocked = true
			plan.RequiresAction = append(plan.RequiresAction, "install a compatible Ubuntu package "+check.Package+" before updating")
		}
	}
	if migration.ToSchema == 0 {
		plan.Blocked = true
		plan.RequiresAction = append(plan.RequiresAction, "select a release supporting the current state schema")
	}
	if !plan.Changed {
		plan.ExpectedInterruptions = []string{}
	}
	if err := plan.Validate(); err != nil {
		return UpdatePlan{}, err
	}
	keepPrepared, keepStage = true, true
	return plan, nil
}

func (updater *Updater) Apply(ctx context.Context, plan UpdatePlan) (UpdateResult, error) {
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
	if plan.prepared == nil || !plan.stage.valid() {
		return UpdateResult{}, fmt.Errorf("%w: retained release stage is unavailable", ErrUpdateConflict)
	}
	defer func() { _ = updater.Discard(plan) }()
	current, err := updater.runtime.State.Load()
	if err != nil || !reflect.DeepEqual(current, plan.state) {
		return UpdateResult{}, fmt.Errorf("%w: authoritative state changed after update planning", ErrUpdateConflict)
	}
	if !plan.Changed {
		return UpdateResult{
			OperationID: plan.OperationID, Role: plan.Role, PreviousVersion: plan.CurrentVersion,
			CurrentVersion: plan.TargetVersion, Generation: current.Generation, Changed: false,
			ComponentResults: []UpdateComponentResult{}, ExpectedInterruptions: []string{}, RequiresAction: []string{},
		}, nil
	}
	now := updater.runtime.Now().UTC().Truncate(time.Second)
	pending, err := beginUpdateState(current, plan, now)
	if err != nil {
		return UpdateResult{}, err
	}
	if err := updater.runtime.Host.QuiesceManagement(ctx, plan.Role); err != nil {
		_ = updater.runtime.Host.ResumeManagement(context.Background(), plan.Role)
		return UpdateResult{}, fmt.Errorf("quiesce update management: %w", err)
	}
	if _, err := updater.saveState(current, pending); err != nil {
		_ = updater.runtime.Host.ResumeManagement(context.Background(), plan.Role)
		return UpdateResult{}, fmt.Errorf("persist pending update operation: %w", err)
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
			fileErr := plan.prepared.RollbackComponent(rollbackContext, change.Name)
			healthErr := updater.runtime.Host.RollbackAndHealth(rollbackContext, plan.Role, change)
			rollbackErrors = append(rollbackErrors, fileErr, healthErr)
		}
		failed, stateErr := failUpdateState(persisted, plan, updater.runtime.Now().UTC().Truncate(time.Second))
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
	active, err := activateUpdatedState(persisted, plan, updater.runtime.Now().UTC().Truncate(time.Second))
	if err != nil {
		return UpdateResult{}, rollback(err)
	}
	active, err = updater.saveState(persisted, active)
	if err != nil {
		return UpdateResult{}, rollback(fmt.Errorf("publish active update state: %w", err))
	}
	persisted = active
	if err := updater.runtime.Host.ResumeManagement(ctx, plan.Role); err != nil {
		return UpdateResult{}, rollback(fmt.Errorf("resume updated management: %w", err))
	}
	managementResumed = true
	completed, err := completeUpdateState(persisted, plan, updater.runtime.Now().UTC().Truncate(time.Second))
	if err != nil {
		return UpdateResult{}, rollback(err)
	}
	completed, err = updater.saveState(persisted, completed)
	if err != nil {
		return UpdateResult{}, rollback(fmt.Errorf("complete update operation: %w", err))
	}
	persisted = completed
	if err := plan.prepared.Commit(); err != nil {
		return UpdateResult{}, fmt.Errorf("finalize release update: %w", err)
	}
	return UpdateResult{
		OperationID: plan.OperationID, Role: plan.Role, PreviousVersion: plan.CurrentVersion, CurrentVersion: plan.TargetVersion,
		Generation: persisted.Generation, Changed: true, ComponentResults: results,
		ExpectedInterruptions: append([]string(nil), plan.ExpectedInterruptions...),
		RequiresAction:        updatePostActions(plan),
	}, nil
}

func (updater *Updater) saveState(before, candidate model.State) (model.State, error) {
	err := updater.runtime.State.Save(before.Generation, candidate)
	if err == nil {
		return candidate, nil
	}
	observed, loadErr := updater.runtime.State.Load()
	if loadErr == nil && reflect.DeepEqual(observed, candidate) {
		return candidate, nil
	}
	if loadErr != nil {
		return model.State{}, errors.Join(err, fmt.Errorf("reconcile update state write: %w", loadErr))
	}
	if !reflect.DeepEqual(observed, before) {
		return model.State{}, errors.Join(err, fmt.Errorf("%w: state diverged while reconciling update write", ErrUpdateConflict))
	}
	return model.State{}, err
}

func (updater *Updater) Discard(plan UpdatePlan) error {
	if plan.prepared == nil || plan.stage == nil {
		return nil
	}
	return errors.Join(plan.prepared.Close(), plan.stage.Close())
}

func (plan UpdatePlan) Validate() error {
	if plan.OperationID == "" || plan.Role != model.RoleGateway && plan.Role != model.RoleNode || plan.CurrentVersion == "" || plan.TargetVersion == "" || plan.ExpectedStateGeneration == 0 {
		return fmt.Errorf("update plan identity is incomplete")
	}
	if plan.LatestStable != (plan.RequestedVersion == "") {
		return fmt.Errorf("update plan release selection is inconsistent")
	}
	if plan.Components == nil || plan.Packages == nil || plan.Fleet.Nodes == nil || plan.Fleet.RequiresAction == nil || plan.Migration.Steps == nil || plan.ExpectedInterruptions == nil || plan.RequiresAction == nil {
		return fmt.Errorf("update plan collections must be present")
	}
	if plan.Fleet.Role != plan.Role || plan.RollbackAvailable != plan.Migration.Reversible {
		return fmt.Errorf("update plan compatibility metadata is inconsistent")
	}
	if plan.Blocked && len(plan.RequiresAction) == 0 {
		return fmt.Errorf("blocked update plan requires an action")
	}
	return nil
}

func planUpdateStateMigration(state model.State, target model.ComponentManifest) UpdateStateMigration {
	// The current schema needs no migration when it is directly readable by
	// the target release. A manifest's migration reversibility flag applies
	// only when an actual schema migration is planned; it must not disable
	// rollback for an ordinary binary/component-only update.
	plan := UpdateStateMigration{FromSchema: state.SchemaVersion, Steps: []string{}, Reversible: true}
	if state.SchemaVersion >= target.StateSchemaMinimum && state.SchemaVersion <= target.StateSchemaMaximum {
		plan.ToSchema = state.SchemaVersion
	}
	return plan
}

func planUpdateComponents(role model.Role, current, target ReleaseManifest, bundled []ReleaseBundleComponentChange) ([]UpdateComponentChange, error) {
	bundledByName := make(map[string]ReleaseBundleComponentChange, len(bundled))
	for _, change := range bundled {
		bundledByName[change.Name] = change
	}
	currentPins := make(map[string]model.ComponentPin, len(current.ComponentManifest.Components))
	for _, component := range current.ComponentManifest.Components {
		currentPins[component.Name] = component
	}
	result := make([]UpdateComponentChange, 0)
	for _, targetPin := range target.ComponentManifest.Components {
		if !releaseComponentServesRole(target, targetPin.Name, role) {
			continue
		}
		currentPin, found := currentPins[targetPin.Name]
		if !found {
			return nil, fmt.Errorf("%w: installed manifest lacks target component %s", ErrUpdateConflict, targetPin.Name)
		}
		change := UpdateComponentChange{
			Name: targetPin.Name, CurrentVersion: currentPin.Version, TargetVersion: targetPin.Version, Bundled: targetPin.Bundled,
			Changed: !reflect.DeepEqual(currentPin, targetPin),
		}
		if targetPin.Bundled {
			bundleChange, found := bundledByName[targetPin.Name]
			if !found {
				return nil, fmt.Errorf("%w: bundled component %s has no staged role artifact", ErrUpdateConflict, targetPin.Name)
			}
			change.FileChanged = bundleChange.FileChanged
		}
		if change.FileChanged {
			change.AffectedServices = updateComponentServices(role, targetPin.Name)
		} else {
			change.AffectedServices = []string{}
		}
		result = append(result, change)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Name == "vpnctl" {
			return false
		}
		if result[right].Name == "vpnctl" {
			return true
		}
		return result[left].Name < result[right].Name
	})
	return result, nil
}

func releaseComponentServesRole(manifest ReleaseManifest, component string, role model.Role) bool {
	for _, artifact := range manifest.Artifacts {
		if artifact.Component == component {
			return releaseRolesContain(artifact.Roles, role)
		}
	}
	for _, compatibility := range manifest.APTPackages {
		if compatibility.Component == component {
			return releaseRolesContain(compatibility.Roles, role)
		}
	}
	return false
}

func updateComponentServices(role model.Role, component string) []string {
	services := map[model.Role]map[string][]string{
		model.RoleGateway: {
			"frp": {"vpnctl-tunnel-server.service"}, "mihomo": {"vpnctl-restricted.service"},
			"nginx": {"nginx.service"}, "vpnctl": {"vpnctl-controller.service"},
		},
		model.RoleNode: {
			"frp": {"vpnctl-tunnel-client.service"}, "mihomo": {"vpnctl-routing.service"},
		},
	}
	return append([]string(nil), services[role][component]...)
}

func updateInterruptions(role model.Role, changes []UpdateComponentChange) []string {
	changed := make(map[string]bool, len(changes))
	for _, change := range changes {
		changed[change.Name] = change.FileChanged
	}
	result := []string{}
	if role == model.RoleGateway && changed["vpnctl"] {
		result = append(result, "gateway management is briefly unavailable")
	}
	if changed["mihomo"] {
		result = append(result, "active restricted transport may reconnect", "routing engine interruption remains fail-closed")
	}
	if changed["frp"] {
		if role == model.RoleGateway {
			result = append(result, "ingress may return temporary 503", "active ingress requests may be interrupted")
		} else {
			result = append(result, "node webhook tunnel may be temporarily unavailable")
		}
	}
	return result
}

func updatePostActions(plan UpdatePlan) []string {
	result := []string{}
	if plan.Role != model.RoleGateway || !plan.Changed {
		return result
	}
	for _, node := range plan.Fleet.Nodes {
		if node.Compatible {
			result = append(result, fmt.Sprintf("connect to node %s over SSH and run vpnctl update %s locally", node.Name, plan.TargetVersion))
		}
	}
	return result
}

func beginUpdateState(current model.State, plan UpdatePlan, now time.Time) (model.State, error) {
	nextGeneration, err := model.NextGeneration(current.Generation)
	if err != nil {
		return model.State{}, err
	}
	desiredGeneration := current.Generation
	for range 3 {
		desiredGeneration, err = model.NextGeneration(desiredGeneration)
		if err != nil {
			return model.State{}, fmt.Errorf("reserve update state generations: %w", err)
		}
	}
	steps := make([]model.OperationStep, 0)
	for _, component := range plan.Components {
		if component.Changed || component.FileChanged {
			steps = append(steps, model.OperationStep{Name: component.Name, State: model.OperationPending, UpdatedAt: now})
		}
	}
	steps = append(steps, model.OperationStep{Name: "state", State: model.OperationPending, UpdatedAt: now})
	candidate := current
	candidate.Generation = nextGeneration
	candidate.Operations = append(append([]model.Operation{}, current.Operations...), model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: plan.OperationID, Type: model.OperationUpdate, State: model.OperationPending,
		TargetKind: "host", TargetID: current.Host.ID, ExpectedGeneration: current.Generation, DesiredGeneration: desiredGeneration,
		Steps: steps, CreatedAt: now, UpdatedAt: now,
	})
	if err := model.ValidateTransition(current, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate pending update state: %w", err)
	}
	return candidate, nil
}

func activateUpdatedState(pending model.State, plan UpdatePlan, now time.Time) (model.State, error) {
	nextGeneration, err := model.NextGeneration(pending.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate := pending
	candidate.Generation = nextGeneration
	candidate.SchemaVersion = plan.Migration.ToSchema
	candidate.Components = plan.prepared.TargetManifest().ComponentManifest
	if candidate.Host.Role == model.RoleNode && len(candidate.Nodes) == 1 && candidate.Nodes[0].Gateway != nil && plan.Fleet.SelectedProtocol != "" {
		candidate.Nodes = append([]model.Node{}, candidate.Nodes...)
		gateway := *candidate.Nodes[0].Gateway
		gateway.ControlProtocol = plan.Fleet.SelectedProtocol
		candidate.Nodes[0].Gateway = &gateway
	}
	operationIndex := updateOperationIndex(candidate, plan.OperationID)
	if operationIndex < 0 {
		return model.State{}, fmt.Errorf("pending update operation is missing")
	}
	candidate.Operations = append([]model.Operation{}, candidate.Operations...)
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
		return model.State{}, fmt.Errorf("validate active update state: %w", err)
	}
	return candidate, nil
}

func completeUpdateState(active model.State, plan UpdatePlan, now time.Time) (model.State, error) {
	nextGeneration, err := model.NextGeneration(active.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate := active
	candidate.Generation = nextGeneration
	candidate.Operations = append([]model.Operation{}, candidate.Operations...)
	operationIndex := updateOperationIndex(candidate, plan.OperationID)
	if operationIndex < 0 {
		return model.State{}, fmt.Errorf("active update operation is missing")
	}
	operation, err := candidate.Operations[operationIndex].Transition(model.OperationCompleted, now, "")
	if err != nil {
		return model.State{}, err
	}
	candidate.Operations[operationIndex] = operation
	if err := model.ValidateTransition(active, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate completed update state: %w", err)
	}
	return candidate, nil
}

func failUpdateState(persisted model.State, plan UpdatePlan, now time.Time) (model.State, error) {
	nextGeneration, err := model.NextGeneration(persisted.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate := persisted
	candidate.Generation = nextGeneration
	candidate.SchemaVersion = plan.state.SchemaVersion
	candidate.Components = plan.state.Components
	candidate.Nodes = append([]model.Node{}, plan.state.Nodes...)
	candidate.Operations = append([]model.Operation{}, candidate.Operations...)
	operationIndex := updateOperationIndex(candidate, plan.OperationID)
	if operationIndex < 0 {
		return model.State{}, fmt.Errorf("failed update operation is missing")
	}
	operation, err := candidate.Operations[operationIndex].Transition(model.OperationFailed, now, "update_failed")
	if err != nil {
		return model.State{}, err
	}
	candidate.Operations[operationIndex] = operation
	if err := model.ValidateTransition(persisted, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate failed update state: %w", err)
	}
	return candidate, nil
}

func updateOperationIndex(state model.State, operationID string) int {
	for index := range state.Operations {
		if state.Operations[index].ID == operationID {
			return index
		}
	}
	return -1
}

func occupiedUpdateOperationIDs(state model.State) map[string]struct{} {
	occupied := make(map[string]struct{}, len(state.Operations)+1)
	occupied[state.Host.ID] = struct{}{}
	for _, operation := range state.Operations {
		occupied[operation.ID] = struct{}{}
	}
	return occupied
}

func cloneUpdateFleet(value UpdateFleetCompatibility) UpdateFleetCompatibility {
	value.Nodes = append([]UpdateFleetNode{}, value.Nodes...)
	value.RequiresAction = append([]string{}, value.RequiresAction...)
	return value
}
