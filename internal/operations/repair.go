package operations

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

var (
	ErrRepairInvalid              = errors.New("invalid repair request")
	ErrRepairConflict             = errors.New("repair conflicts with current state")
	ErrRepairNodeAgentUnavailable = errors.New("node-local repair requires the node command")
	ErrRepairGatewayUnavailable   = errors.New("authoritative gateway is unavailable")
)

type RepairActionKind string

const (
	RepairRestore RepairActionKind = "restore"
	RepairRemove  RepairActionKind = "remove"
)

// RepairAction contains hashes and stable identifiers only. Restore material
// is rendered by the role-specific executor from the retained applied
// generation; it is never embedded in a plan or generic error.
type RepairAction struct {
	Resource       ManagedResourceKey `json:"resource"`
	DriftKind      OwnedDriftKind     `json:"drift_kind"`
	Action         RepairActionKind   `json:"action"`
	Impact         ConvergenceImpact  `json:"impact"`
	Scope          ApplyScope         `json:"scope"`
	TargetSHA256   string             `json:"target_sha256,omitempty"`
	ObservedSHA256 string             `json:"observed_sha256,omitempty"`
}

type RepairPlan struct {
	Role             model.Role        `json:"role"`
	CurrentNodeID    string            `json:"current_node_id,omitempty"`
	TargetGeneration uint64            `json:"target_generation"`
	Impact           ConvergenceImpact `json:"impact"`
	Actions          []RepairAction    `json:"actions"`
	Convergence      ConvergencePlan   `json:"convergence"`
}

type RepairExecutionBatch struct {
	Role             model.Role     `json:"role"`
	CurrentNodeID    string         `json:"current_node_id,omitempty"`
	TargetGeneration uint64         `json:"target_generation"`
	Actions          []RepairAction `json:"actions"`
}

type RepairResourceResult struct {
	Resource      ManagedResourceKey `json:"resource"`
	Present       bool               `json:"present"`
	RuntimeSHA256 string             `json:"runtime_sha256,omitempty"`
}

type RepairExecutionResult struct {
	Changed          bool                   `json:"changed"`
	TargetGeneration uint64                 `json:"target_generation"`
	Resources        []RepairResourceResult `json:"resources"`
}

type RepairResult struct {
	Changed    bool                   `json:"changed"`
	Generation uint64                 `json:"generation"`
	Actions    []RepairAction         `json:"actions"`
	Resources  []RepairResourceResult `json:"resources"`
}

type RepairScopeResolver interface {
	ResolveRepairScope(RepairAction) (ApplyScope, error)
}

// GatewayRepairExecutor intentionally has no node repair method.
type GatewayRepairExecutor interface {
	RepairGateway(context.Context, RepairExecutionBatch) (RepairExecutionResult, error)
}

// CurrentNodeRepairExecutor is supplied by the current node CLI process, not
// by a permanent remote agent.
type CurrentNodeRepairExecutor interface {
	RequireGateway(context.Context, string) error
	RepairCurrentNode(context.Context, RepairExecutionBatch) (RepairExecutionResult, error)
}

type RepairCoordinator struct {
	role          model.Role
	currentNodeID string
	planner       *ConvergencePlanner
	resolver      RepairScopeResolver
	gateway       GatewayRepairExecutor
	node          CurrentNodeRepairExecutor
}

func NewGatewayRepairCoordinator(
	planner *ConvergencePlanner,
	resolver RepairScopeResolver,
	executor GatewayRepairExecutor,
) (*RepairCoordinator, error) {
	if planner == nil || nilInterface(resolver) || nilInterface(executor) {
		return nil, fmt.Errorf("gateway repair dependencies are incomplete")
	}
	return &RepairCoordinator{role: model.RoleGateway, planner: planner, resolver: resolver, gateway: executor}, nil
}

func NewNodeRepairCoordinator(
	currentNodeID string,
	planner *ConvergencePlanner,
	resolver RepairScopeResolver,
	executor CurrentNodeRepairExecutor,
) (*RepairCoordinator, error) {
	if err := model.ValidateResourceID(currentNodeID); err != nil {
		return nil, fmt.Errorf("current node ID: %w", err)
	}
	if planner == nil || nilInterface(resolver) || nilInterface(executor) {
		return nil, fmt.Errorf("node repair dependencies are incomplete")
	}
	return &RepairCoordinator{
		role: model.RoleNode, currentNodeID: currentNodeID,
		planner: planner, resolver: resolver, node: executor,
	}, nil
}

func (coordinator *RepairCoordinator) Plan(ctx context.Context) (RepairPlan, error) {
	if ctx == nil {
		return RepairPlan{}, fmt.Errorf("context is required")
	}
	if err := coordinator.validate(); err != nil {
		return RepairPlan{}, err
	}
	convergence, err := coordinator.planner.Plan(ctx)
	if err != nil {
		return RepairPlan{}, fmt.Errorf("plan vpnctl-owned repair: %w", err)
	}
	return coordinator.buildPlan(convergence)
}

func (coordinator *RepairCoordinator) Repair(ctx context.Context, approved RepairPlan) (RepairResult, error) {
	if ctx == nil {
		return RepairResult{}, fmt.Errorf("context is required")
	}
	if err := coordinator.validate(); err != nil {
		return RepairResult{}, err
	}
	if err := approved.Validate(); err != nil {
		return RepairResult{}, fmt.Errorf("%w: approved plan: %v", ErrRepairInvalid, err)
	}
	fresh, err := coordinator.Plan(ctx)
	if err != nil {
		return RepairResult{}, err
	}
	if !reflect.DeepEqual(approved, fresh) {
		return RepairResult{}, fmt.Errorf("%w: repair preview is stale; run vpnctl repair --dry-run again", ErrRepairConflict)
	}
	if coordinator.role == model.RoleNode {
		if err := coordinator.node.RequireGateway(ctx, coordinator.currentNodeID); err != nil {
			return RepairResult{}, fmt.Errorf("%w: %v", ErrRepairGatewayUnavailable, err)
		}
	}
	if len(fresh.Actions) == 0 {
		return RepairResult{
			Changed: false, Generation: fresh.TargetGeneration,
			Actions: []RepairAction{}, Resources: []RepairResourceResult{},
		}, nil
	}

	batch := RepairExecutionBatch{
		Role: fresh.Role, CurrentNodeID: fresh.CurrentNodeID,
		TargetGeneration: fresh.TargetGeneration, Actions: cloneRepairActions(fresh.Actions),
	}
	var executed RepairExecutionResult
	switch coordinator.role {
	case model.RoleGateway:
		executed, err = coordinator.gateway.RepairGateway(ctx, batch)
	case model.RoleNode:
		executed, err = coordinator.node.RepairCurrentNode(ctx, batch)
	default:
		return RepairResult{}, fmt.Errorf("%w: unsupported role %q", ErrRepairInvalid, coordinator.role)
	}
	if err != nil {
		return RepairResult{}, fmt.Errorf("execute vpnctl-owned repair: %w", err)
	}
	if err := executed.validate(batch); err != nil {
		return RepairResult{}, fmt.Errorf("%w: executor result: %v", ErrRepairInvalid, err)
	}
	return RepairResult{
		Changed: executed.Changed, Generation: executed.TargetGeneration,
		Actions:   cloneRepairActions(fresh.Actions),
		Resources: append([]RepairResourceResult{}, executed.Resources...),
	}, nil
}

func (coordinator *RepairCoordinator) buildPlan(convergence ConvergencePlan) (RepairPlan, error) {
	if err := convergence.Validate(); err != nil {
		return RepairPlan{}, fmt.Errorf("%w: convergence plan: %v", ErrRepairInvalid, err)
	}
	actions := make([]RepairAction, len(convergence.Drift))
	impact := ConvergenceImpactNone
	for index, drift := range convergence.Drift {
		action, err := repairActionFromDrift(drift)
		if err != nil {
			return RepairPlan{}, err
		}
		scope, err := coordinator.resolver.ResolveRepairScope(action)
		if err != nil {
			return RepairPlan{}, fmt.Errorf("resolve repair scope for %s: %w", resourceOrder(action.Resource), err)
		}
		if err := scope.validate(); err != nil {
			return RepairPlan{}, fmt.Errorf("%w: resource %s scope: %v", ErrRepairInvalid, resourceOrder(action.Resource), err)
		}
		if err := coordinator.acceptScope(action.Resource, scope); err != nil {
			return RepairPlan{}, err
		}
		action.Scope = scope
		actions[index] = action
		impact = maximumConvergenceImpact(impact, action.Impact)
	}
	plan := RepairPlan{
		Role: coordinator.role, CurrentNodeID: coordinator.currentNodeID,
		TargetGeneration: convergence.AppliedGeneration, Impact: impact,
		Actions: actions, Convergence: convergence,
	}
	if err := plan.Validate(); err != nil {
		return RepairPlan{}, fmt.Errorf("%w: result: %v", ErrRepairInvalid, err)
	}
	return plan, nil
}

func (coordinator *RepairCoordinator) validate() error {
	if coordinator == nil || coordinator.planner == nil || nilInterface(coordinator.resolver) {
		return fmt.Errorf("repair coordinator is incomplete")
	}
	switch coordinator.role {
	case model.RoleGateway:
		if coordinator.currentNodeID != "" || nilInterface(coordinator.gateway) || !nilInterface(coordinator.node) {
			return fmt.Errorf("gateway repair coordinator has invalid dependencies")
		}
	case model.RoleNode:
		if model.ValidateResourceID(coordinator.currentNodeID) != nil || nilInterface(coordinator.node) || !nilInterface(coordinator.gateway) {
			return fmt.Errorf("node repair coordinator has invalid dependencies")
		}
	default:
		return fmt.Errorf("repair coordinator role is invalid")
	}
	return nil
}

func (coordinator *RepairCoordinator) acceptScope(resource ManagedResourceKey, scope ApplyScope) error {
	switch coordinator.role {
	case model.RoleGateway:
		if scope.Role == model.RoleNode {
			return fmt.Errorf("%w: resource %s belongs to node %s; run vpnctl repair on that node", ErrRepairNodeAgentUnavailable, resourceOrder(resource), scope.NodeID)
		}
	case model.RoleNode:
		if scope.Role != model.RoleNode || scope.NodeID != coordinator.currentNodeID {
			return fmt.Errorf("%w: resource %s does not belong to current node %s", ErrRepairConflict, resourceOrder(resource), coordinator.currentNodeID)
		}
	}
	return nil
}

func (plan RepairPlan) Validate() error {
	if err := plan.Convergence.Validate(); err != nil {
		return err
	}
	if plan.Role != model.RoleGateway && plan.Role != model.RoleNode {
		return fmt.Errorf("role is invalid")
	}
	if plan.Role == model.RoleGateway && plan.CurrentNodeID != "" {
		return fmt.Errorf("gateway plan cannot contain a current node ID")
	}
	if plan.Role == model.RoleNode && model.ValidateResourceID(plan.CurrentNodeID) != nil {
		return fmt.Errorf("node plan requires a valid current node ID")
	}
	if plan.TargetGeneration != plan.Convergence.AppliedGeneration {
		return fmt.Errorf("repair target must be the last applied generation")
	}
	if plan.Actions == nil || len(plan.Actions) != len(plan.Convergence.Drift) {
		return fmt.Errorf("actions must exactly cover vpnctl-owned drift")
	}
	wantImpact := ConvergenceImpactNone
	for index, action := range plan.Actions {
		if err := action.validate(); err != nil {
			return fmt.Errorf("action %d: %w", index, err)
		}
		want, err := repairActionFromDrift(plan.Convergence.Drift[index])
		if err != nil {
			return err
		}
		withoutScope := action
		withoutScope.Scope = ApplyScope{}
		if !reflect.DeepEqual(withoutScope, want) {
			return fmt.Errorf("action %d differs from owned drift", index)
		}
		if plan.Role == model.RoleGateway && action.Scope.Role != model.RoleGateway {
			return fmt.Errorf("gateway plan contains non-gateway action")
		}
		if plan.Role == model.RoleNode && (action.Scope.Role != model.RoleNode || action.Scope.NodeID != plan.CurrentNodeID) {
			return fmt.Errorf("node plan contains foreign action")
		}
		wantImpact = maximumConvergenceImpact(wantImpact, action.Impact)
	}
	if plan.Impact != wantImpact {
		return fmt.Errorf("repair impact %q does not match %q", plan.Impact, wantImpact)
	}
	return nil
}

func (action RepairAction) validate() error {
	if err := action.Resource.validate(); err != nil {
		return err
	}
	if !validConvergenceImpact(action.Impact) {
		return fmt.Errorf("impact is unsupported")
	}
	if err := action.Scope.validate(); err != nil {
		return err
	}
	switch action.DriftKind {
	case OwnedDriftMissing:
		if action.Action != RepairRestore || validateFingerprint(action.TargetSHA256) != nil || action.ObservedSHA256 != "" {
			return fmt.Errorf("missing-resource repair is invalid")
		}
	case OwnedDriftModified:
		if action.Action != RepairRestore || validateFingerprint(action.TargetSHA256) != nil ||
			validateFingerprint(action.ObservedSHA256) != nil || action.TargetSHA256 == action.ObservedSHA256 {
			return fmt.Errorf("modified-resource repair is invalid")
		}
	case OwnedDriftUnexpected:
		if action.Action != RepairRemove || action.TargetSHA256 != "" || validateFingerprint(action.ObservedSHA256) != nil {
			return fmt.Errorf("unexpected-resource repair is invalid")
		}
	default:
		return fmt.Errorf("drift kind is unsupported")
	}
	return nil
}

func (result RepairExecutionResult) validate(batch RepairExecutionBatch) error {
	if result.TargetGeneration != batch.TargetGeneration || result.Resources == nil || len(result.Resources) != len(batch.Actions) {
		return fmt.Errorf("target generation or resource result count differs from repair batch")
	}
	for index, resource := range result.Resources {
		action := batch.Actions[index]
		if resource.Resource != action.Resource {
			return fmt.Errorf("resource result %d identity differs from repair action", index)
		}
		switch action.Action {
		case RepairRestore:
			if !resource.Present || resource.RuntimeSHA256 != action.TargetSHA256 {
				return fmt.Errorf("resource %s does not match target generation hash", resourceOrder(resource.Resource))
			}
		case RepairRemove:
			if resource.Present || resource.RuntimeSHA256 != "" {
				return fmt.Errorf("unexpected resource %s is still present", resourceOrder(resource.Resource))
			}
		default:
			return fmt.Errorf("resource result %d has unsupported action", index)
		}
	}
	return nil
}

func (result RepairResult) Validate() error {
	if result.Generation == 0 || result.Actions == nil || result.Resources == nil || len(result.Actions) != len(result.Resources) {
		return fmt.Errorf("repair result is incomplete")
	}
	for index, action := range result.Actions {
		if err := action.validate(); err != nil {
			return fmt.Errorf("repair result action %d: %w", index, err)
		}
	}
	batch := RepairExecutionBatch{TargetGeneration: result.Generation, Actions: result.Actions}
	executed := RepairExecutionResult{Changed: result.Changed, TargetGeneration: result.Generation, Resources: result.Resources}
	return executed.validate(batch)
}

func repairActionFromDrift(drift OwnedDrift) (RepairAction, error) {
	if err := drift.validate(); err != nil {
		return RepairAction{}, fmt.Errorf("%w: drift: %v", ErrRepairInvalid, err)
	}
	action := RepairAction{
		Resource: drift.Resource, DriftKind: drift.Kind, Impact: drift.Impact,
		TargetSHA256: drift.ExpectedSHA256, ObservedSHA256: drift.ActualSHA256,
	}
	switch drift.Kind {
	case OwnedDriftMissing, OwnedDriftModified:
		action.Action = RepairRestore
	case OwnedDriftUnexpected:
		action.Action = RepairRemove
	default:
		return RepairAction{}, fmt.Errorf("%w: unsupported drift kind %q", ErrRepairInvalid, drift.Kind)
	}
	return action, nil
}

func cloneRepairActions(actions []RepairAction) []RepairAction {
	return append([]RepairAction{}, actions...)
}
