package operations

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

var (
	ErrApplyInvalid              = errors.New("invalid apply request")
	ErrApplyConflict             = errors.New("apply conflicts with current state")
	ErrApplyNodeAgentUnavailable = errors.New("node-local apply requires the node command")
	ErrApplyGatewayUnavailable   = errors.New("authoritative gateway is unavailable")
)

// ApplyScope identifies the host whose local command must participate in an
// operation. A cross-host operation is node-scoped because the node command
// supplies the otherwise absent node-side agent while coordinating with the
// authoritative gateway.
type ApplyScope struct {
	Role   model.Role `json:"role"`
	NodeID string     `json:"node_id,omitempty"`
}

// ApplyOperation groups every registered desired change belonging to one
// authoritative pending operation. Changes never migrate between operation
// IDs during apply.
type ApplyOperation struct {
	ID                 string            `json:"id"`
	Type               string            `json:"type"`
	ExpectedGeneration uint64            `json:"expected_generation"`
	DesiredGeneration  uint64            `json:"desired_generation"`
	TargetKind         string            `json:"target_kind,omitempty"`
	TargetID           string            `json:"target_id,omitempty"`
	Scope              ApplyScope        `json:"scope"`
	Impact             ConvergenceImpact `json:"impact"`
	Changes            []DesiredChange   `json:"changes"`
}

type ApplyPlan struct {
	Role              model.Role        `json:"role"`
	CurrentNodeID     string            `json:"current_node_id,omitempty"`
	AppliedGeneration uint64            `json:"applied_generation"`
	DesiredGeneration uint64            `json:"desired_generation"`
	Impact            ConvergenceImpact `json:"impact"`
	Operations        []ApplyOperation  `json:"operations"`
	RemainingDrift    []OwnedDrift      `json:"remaining_drift"`
	Convergence       ConvergencePlan   `json:"convergence"`
}

type ApplyExecutionBatch struct {
	Role              model.Role       `json:"role"`
	CurrentNodeID     string           `json:"current_node_id,omitempty"`
	AppliedGeneration uint64           `json:"applied_generation"`
	DesiredGeneration uint64           `json:"desired_generation"`
	Operations        []ApplyOperation `json:"operations"`
}

type ApplyExecutionResult struct {
	Changed           bool     `json:"changed"`
	AppliedGeneration uint64   `json:"applied_generation"`
	OperationIDs      []string `json:"operation_ids"`
}

type ApplyResult struct {
	Changed        bool         `json:"changed"`
	Generation     uint64       `json:"generation"`
	OperationIDs   []string     `json:"operation_ids"`
	RemainingDrift []OwnedDrift `json:"remaining_drift"`
}

// ApplyScopeResolver maps a registered operation to its explicit execution
// host. Implementations use normalized authoritative metadata, never runtime
// guesses based on which services happen to be reachable.
type ApplyScopeResolver interface {
	ResolveApplyScope(ApplyOperation) (ApplyScope, error)
}

// GatewayApplyExecutor has no method for running a node operation. This keeps
// an absent long-running node agent from being simulated by gateway apply.
type GatewayApplyExecutor interface {
	ApplyGateway(context.Context, ApplyExecutionBatch) (ApplyExecutionResult, error)
}

// CurrentNodeApplyExecutor is invoked only by the node-role coordinator. The
// reachability method must verify the authoritative gateway before any local
// candidate is activated; ApplyCurrentNode may compose cross-host sagas.
type CurrentNodeApplyExecutor interface {
	RequireGateway(context.Context, string) error
	ApplyCurrentNode(context.Context, ApplyExecutionBatch) (ApplyExecutionResult, error)
}

type ApplyCoordinator struct {
	role          model.Role
	currentNodeID string
	planner       *ConvergencePlanner
	resolver      ApplyScopeResolver
	gateway       GatewayApplyExecutor
	node          CurrentNodeApplyExecutor
}

func NewGatewayApplyCoordinator(
	planner *ConvergencePlanner,
	resolver ApplyScopeResolver,
	executor GatewayApplyExecutor,
) (*ApplyCoordinator, error) {
	if planner == nil || nilInterface(resolver) || nilInterface(executor) {
		return nil, fmt.Errorf("gateway apply dependencies are incomplete")
	}
	return &ApplyCoordinator{role: model.RoleGateway, planner: planner, resolver: resolver, gateway: executor}, nil
}

func NewNodeApplyCoordinator(
	currentNodeID string,
	planner *ConvergencePlanner,
	resolver ApplyScopeResolver,
	executor CurrentNodeApplyExecutor,
) (*ApplyCoordinator, error) {
	if err := model.ValidateResourceID(currentNodeID); err != nil {
		return nil, fmt.Errorf("current node ID: %w", err)
	}
	if planner == nil || nilInterface(resolver) || nilInterface(executor) {
		return nil, fmt.Errorf("node apply dependencies are incomplete")
	}
	return &ApplyCoordinator{
		role: model.RoleNode, currentNodeID: currentNodeID,
		planner: planner, resolver: resolver, node: executor,
	}, nil
}

// Plan derives an executable batch only from changes emitted by the strict
// registered-pending planner. Conflicting drift and incompatible host scopes
// fail before a mutation-capable dependency is called.
func (coordinator *ApplyCoordinator) Plan(ctx context.Context) (ApplyPlan, error) {
	if ctx == nil {
		return ApplyPlan{}, fmt.Errorf("context is required")
	}
	if err := coordinator.validate(); err != nil {
		return ApplyPlan{}, err
	}
	convergence, err := coordinator.planner.Plan(ctx)
	if err != nil {
		return ApplyPlan{}, fmt.Errorf("plan registered pending changes: %w", err)
	}
	return coordinator.buildPlan(convergence)
}

// Apply re-reads the complete plan after consent. Any changed generation,
// operation, resource hash, scope, or drift observation makes the preview
// stale and prevents execution.
func (coordinator *ApplyCoordinator) Apply(ctx context.Context, approved ApplyPlan) (ApplyResult, error) {
	if ctx == nil {
		return ApplyResult{}, fmt.Errorf("context is required")
	}
	if err := coordinator.validate(); err != nil {
		return ApplyResult{}, err
	}
	if err := approved.Validate(); err != nil {
		return ApplyResult{}, fmt.Errorf("%w: approved plan: %v", ErrApplyInvalid, err)
	}
	fresh, err := coordinator.Plan(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	if !reflect.DeepEqual(approved, fresh) {
		return ApplyResult{}, fmt.Errorf("%w: apply preview is stale; run vpnctl plan again", ErrApplyConflict)
	}
	if coordinator.role == model.RoleNode {
		if err := coordinator.node.RequireGateway(ctx, coordinator.currentNodeID); err != nil {
			return ApplyResult{}, fmt.Errorf("%w: %v", ErrApplyGatewayUnavailable, err)
		}
	}
	if len(fresh.Operations) == 0 {
		return ApplyResult{
			Changed: false, Generation: fresh.AppliedGeneration,
			OperationIDs: []string{}, RemainingDrift: cloneOwnedDrift(fresh.RemainingDrift),
		}, nil
	}

	batch := ApplyExecutionBatch{
		Role: fresh.Role, CurrentNodeID: fresh.CurrentNodeID,
		AppliedGeneration: fresh.AppliedGeneration, DesiredGeneration: fresh.DesiredGeneration,
		Operations: cloneApplyOperations(fresh.Operations),
	}
	var executed ApplyExecutionResult
	switch coordinator.role {
	case model.RoleGateway:
		executed, err = coordinator.gateway.ApplyGateway(ctx, batch)
	case model.RoleNode:
		executed, err = coordinator.node.ApplyCurrentNode(ctx, batch)
	default:
		return ApplyResult{}, fmt.Errorf("%w: unsupported role %q", ErrApplyInvalid, coordinator.role)
	}
	if err != nil {
		return ApplyResult{}, fmt.Errorf("execute registered pending apply: %w", err)
	}
	if err := executed.validate(batch); err != nil {
		return ApplyResult{}, fmt.Errorf("%w: executor result: %v", ErrApplyInvalid, err)
	}
	return ApplyResult{
		Changed: executed.Changed, Generation: executed.AppliedGeneration,
		OperationIDs:   append([]string(nil), executed.OperationIDs...),
		RemainingDrift: cloneOwnedDrift(fresh.RemainingDrift),
	}, nil
}

func (coordinator *ApplyCoordinator) buildPlan(convergence ConvergencePlan) (ApplyPlan, error) {
	if err := convergence.Validate(); err != nil {
		return ApplyPlan{}, fmt.Errorf("%w: convergence plan: %v", ErrApplyInvalid, err)
	}
	if len(convergence.Changes) == 0 && convergence.DesiredGeneration != convergence.AppliedGeneration {
		return ApplyPlan{}, fmt.Errorf("%w: desired generation advanced without registered resource changes", ErrApplyInvalid)
	}
	conflicts := overlappingApplyDrift(convergence.Changes, convergence.Drift)
	if len(conflicts) != 0 {
		return ApplyPlan{}, &ApplyDriftConflictError{Resources: conflicts}
	}
	operations, err := groupApplyOperations(convergence.Changes)
	if err != nil {
		return ApplyPlan{}, err
	}
	impact := ConvergenceImpactNone
	for index := range operations {
		scope, err := coordinator.resolver.ResolveApplyScope(operations[index])
		if err != nil {
			return ApplyPlan{}, fmt.Errorf("resolve apply scope for operation %s: %w", operations[index].ID, err)
		}
		if err := scope.validate(); err != nil {
			return ApplyPlan{}, fmt.Errorf("%w: operation %s scope: %v", ErrApplyInvalid, operations[index].ID, err)
		}
		if err := coordinator.acceptScope(operations[index].ID, scope); err != nil {
			return ApplyPlan{}, err
		}
		operations[index].Scope = scope
		impact = maximumConvergenceImpact(impact, operations[index].Impact)
	}
	plan := ApplyPlan{
		Role: coordinator.role, CurrentNodeID: coordinator.currentNodeID,
		AppliedGeneration: convergence.AppliedGeneration, DesiredGeneration: convergence.DesiredGeneration,
		Impact: impact, Operations: operations,
		RemainingDrift: cloneOwnedDrift(convergence.Drift), Convergence: convergence,
	}
	if err := plan.Validate(); err != nil {
		return ApplyPlan{}, fmt.Errorf("%w: result: %v", ErrApplyInvalid, err)
	}
	return plan, nil
}

func (coordinator *ApplyCoordinator) validate() error {
	if coordinator == nil || coordinator.planner == nil || nilInterface(coordinator.resolver) {
		return fmt.Errorf("apply coordinator is incomplete")
	}
	switch coordinator.role {
	case model.RoleGateway:
		if coordinator.currentNodeID != "" || nilInterface(coordinator.gateway) || !nilInterface(coordinator.node) {
			return fmt.Errorf("gateway apply coordinator has invalid dependencies")
		}
	case model.RoleNode:
		if model.ValidateResourceID(coordinator.currentNodeID) != nil || nilInterface(coordinator.node) || !nilInterface(coordinator.gateway) {
			return fmt.Errorf("node apply coordinator has invalid dependencies")
		}
	default:
		return fmt.Errorf("apply coordinator role is invalid")
	}
	return nil
}

func (coordinator *ApplyCoordinator) acceptScope(operationID string, scope ApplyScope) error {
	switch coordinator.role {
	case model.RoleGateway:
		if scope.Role == model.RoleNode {
			return fmt.Errorf("%w: operation %s belongs to node %s; run vpnctl apply on that node", ErrApplyNodeAgentUnavailable, operationID, scope.NodeID)
		}
	case model.RoleNode:
		if scope.Role != model.RoleNode || scope.NodeID != coordinator.currentNodeID {
			return fmt.Errorf("%w: operation %s does not belong to current node %s", ErrApplyConflict, operationID, coordinator.currentNodeID)
		}
	}
	return nil
}

func (scope ApplyScope) validate() error {
	switch scope.Role {
	case model.RoleGateway:
		if scope.NodeID != "" {
			return fmt.Errorf("gateway scope cannot contain a node ID")
		}
	case model.RoleNode:
		if err := model.ValidateResourceID(scope.NodeID); err != nil {
			return fmt.Errorf("node scope ID: %w", err)
		}
	default:
		return fmt.Errorf("unsupported role %q", scope.Role)
	}
	return nil
}

func (plan ApplyPlan) Validate() error {
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
	if plan.AppliedGeneration != plan.Convergence.AppliedGeneration || plan.DesiredGeneration != plan.Convergence.DesiredGeneration {
		return fmt.Errorf("plan generations differ from convergence input")
	}
	if plan.Operations == nil || plan.RemainingDrift == nil {
		return fmt.Errorf("operations and remaining drift must be present")
	}
	if !reflect.DeepEqual(plan.RemainingDrift, plan.Convergence.Drift) {
		return fmt.Errorf("remaining drift differs from convergence input")
	}
	if len(overlappingApplyDrift(plan.Convergence.Changes, plan.RemainingDrift)) != 0 {
		return fmt.Errorf("remaining drift overlaps pending changes")
	}
	wantOperations, err := groupApplyOperations(plan.Convergence.Changes)
	if err != nil {
		return err
	}
	if len(wantOperations) != len(plan.Operations) {
		return fmt.Errorf("operation grouping differs from convergence input")
	}
	wantImpact := ConvergenceImpactNone
	for index, operation := range plan.Operations {
		if err := operation.validate(); err != nil {
			return fmt.Errorf("operation %d: %w", index, err)
		}
		if index > 0 && operation.ID <= plan.Operations[index-1].ID {
			return fmt.Errorf("operations must be ordered by unique ID")
		}
		withoutScope := operation
		withoutScope.Scope = ApplyScope{}
		if !reflect.DeepEqual(withoutScope, wantOperations[index]) {
			return fmt.Errorf("operation %s differs from convergence input", operation.ID)
		}
		if plan.Role == model.RoleGateway && operation.Scope.Role != model.RoleGateway {
			return fmt.Errorf("gateway plan contains non-gateway operation")
		}
		if plan.Role == model.RoleNode && (operation.Scope.Role != model.RoleNode || operation.Scope.NodeID != plan.CurrentNodeID) {
			return fmt.Errorf("node plan contains foreign operation")
		}
		wantImpact = maximumConvergenceImpact(wantImpact, operation.Impact)
	}
	if plan.Impact != wantImpact {
		return fmt.Errorf("apply impact %q does not match %q", plan.Impact, wantImpact)
	}
	if len(plan.Operations) == 0 && plan.AppliedGeneration != plan.DesiredGeneration {
		return fmt.Errorf("generation gap has no registered operations")
	}
	return nil
}

func (operation ApplyOperation) validate() error {
	if err := validateOperationID(operation.ID); err != nil || !operationTypePattern.MatchString(operation.Type) {
		return fmt.Errorf("operation identity is invalid")
	}
	if err := validateOperationTarget(operation.TargetKind, operation.TargetID); err != nil {
		return err
	}
	if operation.ExpectedGeneration == 0 || operation.DesiredGeneration < operation.ExpectedGeneration {
		return fmt.Errorf("operation generations are invalid")
	}
	if err := operation.Scope.validate(); err != nil {
		return err
	}
	if operation.Changes == nil || len(operation.Changes) == 0 {
		return fmt.Errorf("changes must be present and non-empty")
	}
	wantImpact := ConvergenceImpactNone
	for index, change := range operation.Changes {
		if err := change.validate(); err != nil {
			return fmt.Errorf("change %d: %w", index, err)
		}
		if change.OperationID != operation.ID || change.OperationType != operation.Type ||
			change.OperationExpectedGeneration != operation.ExpectedGeneration ||
			change.OperationDesiredGeneration != operation.DesiredGeneration ||
			change.TargetKind != operation.TargetKind || change.TargetID != operation.TargetID {
			return fmt.Errorf("change %d belongs to another operation", index)
		}
		if index > 0 && resourceOrder(change.Resource) <= resourceOrder(operation.Changes[index-1].Resource) {
			return fmt.Errorf("changes must use unique ascending resource identities")
		}
		wantImpact = maximumConvergenceImpact(wantImpact, change.Impact)
	}
	if operation.Impact != wantImpact {
		return fmt.Errorf("operation impact does not match changes")
	}
	return nil
}

func (result ApplyExecutionResult) validate(batch ApplyExecutionBatch) error {
	if result.AppliedGeneration != batch.DesiredGeneration {
		return fmt.Errorf("applied generation %d does not equal desired %d", result.AppliedGeneration, batch.DesiredGeneration)
	}
	want := make([]string, len(batch.Operations))
	for index, operation := range batch.Operations {
		want[index] = operation.ID
	}
	if result.OperationIDs == nil || !reflect.DeepEqual(result.OperationIDs, want) {
		return fmt.Errorf("operation IDs do not match the applied batch")
	}
	return nil
}

func (result ApplyResult) Validate() error {
	if result.Generation == 0 {
		return fmt.Errorf("generation must be positive")
	}
	if result.OperationIDs == nil || result.RemainingDrift == nil {
		return fmt.Errorf("operation IDs and remaining drift must be present")
	}
	for index, id := range result.OperationIDs {
		if err := validateOperationID(id); err != nil {
			return fmt.Errorf("operation ID %d: %w", index, err)
		}
		if index > 0 && id <= result.OperationIDs[index-1] {
			return fmt.Errorf("operation IDs must be unique and ordered")
		}
	}
	previous := ""
	for index, item := range result.RemainingDrift {
		if err := item.validate(); err != nil {
			return fmt.Errorf("remaining drift %d: %w", index, err)
		}
		order := resourceOrder(item.Resource)
		if index > 0 && order <= previous {
			return fmt.Errorf("remaining drift must use unique ascending resources")
		}
		previous = order
	}
	return nil
}

type ApplyDriftConflictError struct {
	Resources []ManagedResourceKey
}

func (err *ApplyDriftConflictError) Error() string {
	return fmt.Sprintf("%s: pending changes overlap %d drifted vpnctl-owned resource(s); run vpnctl repair first", ErrApplyConflict, len(err.Resources))
}

func (err *ApplyDriftConflictError) Unwrap() error { return ErrApplyConflict }

func overlappingApplyDrift(changes []DesiredChange, drift []OwnedDrift) []ManagedResourceKey {
	changed := make(map[string]ManagedResourceKey, len(changes))
	for _, change := range changes {
		changed[resourceOrder(change.Resource)] = change.Resource
	}
	conflicts := make([]ManagedResourceKey, 0)
	for _, item := range drift {
		if key, overlap := changed[resourceOrder(item.Resource)]; overlap {
			conflicts = append(conflicts, key)
		}
	}
	sort.Slice(conflicts, func(left, right int) bool { return resourceOrder(conflicts[left]) < resourceOrder(conflicts[right]) })
	return conflicts
}

func groupApplyOperations(changes []DesiredChange) ([]ApplyOperation, error) {
	byID := make(map[string]*ApplyOperation)
	for _, change := range changes {
		operation, exists := byID[change.OperationID]
		if !exists {
			operation = &ApplyOperation{
				ID: change.OperationID, Type: change.OperationType,
				ExpectedGeneration: change.OperationExpectedGeneration,
				DesiredGeneration:  change.OperationDesiredGeneration,
				TargetKind:         change.TargetKind, TargetID: change.TargetID,
				Impact: ConvergenceImpactNone, Changes: []DesiredChange{},
			}
			byID[change.OperationID] = operation
		}
		if operation.Type != change.OperationType || operation.ExpectedGeneration != change.OperationExpectedGeneration ||
			operation.DesiredGeneration != change.OperationDesiredGeneration ||
			operation.TargetKind != change.TargetKind || operation.TargetID != change.TargetID {
			return nil, fmt.Errorf("%w: operation %s has inconsistent change identity", ErrApplyInvalid, change.OperationID)
		}
		operation.Changes = append(operation.Changes, change)
		operation.Impact = maximumConvergenceImpact(operation.Impact, change.Impact)
	}
	operations := make([]ApplyOperation, 0, len(byID))
	for _, operation := range byID {
		operations = append(operations, *operation)
	}
	sort.Slice(operations, func(left, right int) bool { return operations[left].ID < operations[right].ID })
	return operations, nil
}

func cloneApplyOperations(operations []ApplyOperation) []ApplyOperation {
	cloned := append([]ApplyOperation(nil), operations...)
	for index := range cloned {
		cloned[index].Changes = append([]DesiredChange(nil), cloned[index].Changes...)
	}
	return cloned
}

func cloneOwnedDrift(drift []OwnedDrift) []OwnedDrift {
	return append([]OwnedDrift{}, drift...)
}
