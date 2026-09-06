package cli

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

var (
	ErrSystemConvergenceApplyUnavailable         = errors.New("system pending convergence apply is unavailable")
	ErrSystemConvergenceApplyExecutorUnavailable = errors.New("system pending convergence executor is unavailable")
)

type convergenceApplyStateReader interface {
	Load() (model.State, error)
}

type convergenceApplyPlanner interface {
	Plan(context.Context) (operations.ConvergencePlan, error)
}

type convergenceApplyGatewayProbe interface {
	RequireGateway(context.Context, string) error
}

type convergenceApplyCurrentNodeExecutor interface {
	ApplyCurrentNode(context.Context, operations.ApplyExecutionBatch) (operations.ApplyExecutionResult, error)
}

// systemConvergenceApply is the fail-closed production command boundary while
// operation-specific pending executors are connected. It fully supports a
// verified no-op, including the mandatory node-to-gateway freshness probe,
// but never reports pending authoritative intent as already applied.
type systemConvergenceApply struct {
	role     model.Role
	nodeID   string
	state    convergenceApplyStateReader
	planner  convergenceApplyPlanner
	probe    convergenceApplyGatewayProbe
	executor convergenceApplyCurrentNodeExecutor

	mu           sync.Mutex
	plannedState model.State
	planned      *operations.ApplyPlan
}

func buildSystemConvergenceApply(paths store.Paths, role HostRole) (ConvergenceApplyOperator, error) {
	modelRole, ok := convergenceApplyModelRole(role)
	if !ok {
		return nil, ErrUnsupportedRole
	}
	stateState, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	current, err := stateState.Load()
	if err != nil {
		return nil, err
	}
	nodeID := ""
	var probe convergenceApplyGatewayProbe
	if modelRole == model.RoleNode {
		if len(current.Nodes) != 1 {
			return nil, operations.ErrApplyInvalid
		}
		nodeID = current.Nodes[0].ID
		probe, err = operations.NewSystemRemoteRepairGatewayProbe(paths, nil)
		if err != nil {
			return nil, err
		}
	}
	planner, err := buildSystemConvergencePlanner(paths)
	if err != nil {
		return nil, err
	}
	operator := &systemConvergenceApply{role: modelRole, nodeID: nodeID, state: stateState, planner: planner, probe: probe}
	if modelRole == model.RoleNode {
		operator.executor, err = buildSystemNodeTransportSwitchApplyExecutor(paths, stateState)
		if err != nil {
			return nil, err
		}
	}
	if _, err := operator.readAuthority(); err != nil {
		return nil, err
	}
	return operator, nil
}

func buildSystemNodeTransportSwitchApplyExecutor(
	paths store.Paths,
	state *store.StateStore,
) (*operations.NodeTransportSwitchApplyExecutor, error) {
	registry, err := buildSystemTransportRegistry()
	if err != nil {
		return nil, err
	}
	runtime, err := transport.NewDeferredNodeRuntime(registry, transport.SwitchLimits{})
	if err != nil {
		return nil, err
	}
	gateway, err := operations.NewSystemRemoteTransportSwitchGateway(paths, nil)
	if err != nil {
		return nil, err
	}
	generation, err := operations.NewSystemRemoteRepairGatewayProbe(paths, nil)
	if err != nil {
		return nil, err
	}
	convergence, err := operations.NewFileConvergenceSnapshotStore(paths.ConvergenceFile)
	if err != nil {
		return nil, err
	}
	return operations.NewNodeTransportSwitchApplyExecutor(
		state, runtime, gateway, generation, convergence, nil,
	)
}

func (operator *systemConvergenceApply) Plan(ctx context.Context) (operations.ApplyPlan, error) {
	if ctx == nil || operator == nil || operator.state == nil || operator.planner == nil {
		return operations.ApplyPlan{}, operations.ErrApplyInvalid
	}
	plan, state, err := operator.planCurrent(ctx)
	if err != nil {
		return operations.ApplyPlan{}, err
	}
	operator.mu.Lock()
	retained := plan
	operator.plannedState = state
	operator.planned = &retained
	operator.mu.Unlock()
	return plan, nil
}

func (operator *systemConvergenceApply) planCurrent(ctx context.Context) (operations.ApplyPlan, model.State, error) {
	before, err := operator.readAuthority()
	if err != nil {
		return operations.ApplyPlan{}, model.State{}, err
	}
	convergence, err := operator.planner.Plan(ctx)
	if err != nil {
		return operations.ApplyPlan{}, model.State{}, err
	}
	after, err := operator.readAuthority()
	if err != nil || !reflect.DeepEqual(before, after) {
		return operations.ApplyPlan{}, model.State{}, errors.Join(operations.ErrApplyConflict, err)
	}
	var plan operations.ApplyPlan
	pendingAfter := pendingStateOperations(after)
	if len(convergence.Changes) == 0 {
		if len(pendingAfter) != 0 {
			return operations.ApplyPlan{}, model.State{}, ErrSystemConvergenceApplyUnavailable
		}
		if convergence.DesiredGeneration != convergence.AppliedGeneration {
			return operations.ApplyPlan{}, model.State{}, operations.ErrApplyInvalid
		}
		plan = operations.ApplyPlan{
			Role: operator.role, CurrentNodeID: operator.nodeID,
			AppliedGeneration: convergence.AppliedGeneration, DesiredGeneration: convergence.DesiredGeneration,
			Impact: operations.ConvergenceImpactNone, Operations: []operations.ApplyOperation{},
			RemainingDrift: append([]operations.OwnedDrift{}, convergence.Drift...), Convergence: convergence,
		}
	} else {
		if operator.role != model.RoleNode {
			return operations.ApplyPlan{}, model.State{}, ErrSystemConvergenceApplyUnavailable
		}
		resolver := currentNodeTransportApplyScopeResolver{nodeID: operator.nodeID}
		plan, err = operations.BuildApplyPlan(operator.role, operator.nodeID, convergence, resolver)
		if err != nil {
			return operations.ApplyPlan{}, model.State{}, err
		}
		if err := validateCurrentNodeTransportApplyAuthority(plan, after); err != nil {
			return operations.ApplyPlan{}, model.State{}, err
		}
	}
	if err := plan.Validate(); err != nil {
		return operations.ApplyPlan{}, model.State{}, errors.Join(operations.ErrApplyInvalid, err)
	}
	return plan, after, nil
}

func (operator *systemConvergenceApply) Apply(ctx context.Context, approved operations.ApplyPlan) (operations.ApplyResult, error) {
	if ctx == nil || operator == nil {
		return operations.ApplyResult{}, operations.ErrApplyInvalid
	}
	if err := approved.Validate(); err != nil || approved.Role != operator.role || approved.CurrentNodeID != operator.nodeID {
		return operations.ApplyResult{}, errors.Join(operations.ErrApplyInvalid, err)
	}
	operator.mu.Lock()
	plannedState, planned := operator.plannedState, operator.planned
	operator.mu.Unlock()
	if planned == nil || !reflect.DeepEqual(approved, *planned) {
		return operations.ApplyResult{}, operations.ErrApplyConflict
	}
	fresh, current, err := operator.planCurrent(ctx)
	if err != nil || !reflect.DeepEqual(approved, fresh) || !reflect.DeepEqual(plannedState, current) {
		return operations.ApplyResult{}, errors.Join(operations.ErrApplyConflict, err)
	}
	if operator.role == model.RoleNode {
		if operator.probe == nil {
			return operations.ApplyResult{}, operations.ErrApplyGatewayUnavailable
		}
		if err := operator.probe.RequireGateway(ctx, operator.nodeID); err != nil {
			return operations.ApplyResult{}, errors.Join(operations.ErrApplyGatewayUnavailable, err)
		}
	}
	final, finalState, err := operator.planCurrent(ctx)
	if err != nil || !reflect.DeepEqual(approved, final) || !reflect.DeepEqual(plannedState, finalState) {
		return operations.ApplyResult{}, errors.Join(operations.ErrApplyConflict, err)
	}
	if len(final.Operations) != 0 {
		if operator.executor == nil {
			return operations.ApplyResult{}, ErrSystemConvergenceApplyExecutorUnavailable
		}
		batch := operations.ApplyExecutionBatch{
			Role: final.Role, CurrentNodeID: final.CurrentNodeID,
			AppliedGeneration: final.AppliedGeneration, DesiredGeneration: final.DesiredGeneration,
			Operations: append([]operations.ApplyOperation(nil), final.Operations...),
		}
		executed, err := operator.executor.ApplyCurrentNode(ctx, batch)
		if err != nil {
			return operations.ApplyResult{}, err
		}
		wantIDs := make([]string, len(final.Operations))
		for index := range final.Operations {
			wantIDs[index] = final.Operations[index].ID
		}
		if executed.AppliedGeneration != final.DesiredGeneration || !reflect.DeepEqual(executed.OperationIDs, wantIDs) {
			return operations.ApplyResult{}, operations.ErrApplyInvalid
		}
		return operations.ApplyResult{
			Changed: executed.Changed, Generation: executed.AppliedGeneration,
			OperationIDs:   append([]string(nil), executed.OperationIDs...),
			RemainingDrift: append([]operations.OwnedDrift{}, final.RemainingDrift...),
		}, nil
	}
	return operations.ApplyResult{
		Changed: false, Generation: fresh.AppliedGeneration,
		OperationIDs: []string{}, RemainingDrift: append([]operations.OwnedDrift{}, fresh.RemainingDrift...),
	}, nil
}

type currentNodeTransportApplyScopeResolver struct{ nodeID string }

func (resolver currentNodeTransportApplyScopeResolver) ResolveApplyScope(operation operations.ApplyOperation) (operations.ApplyScope, error) {
	if operation.Type != string(model.OperationTransportSwitch) || operation.TargetKind != "transport" {
		return operations.ApplyScope{}, ErrSystemConvergenceApplyUnavailable
	}
	intent, err := transport.ParseSwitchIntentTarget(operation.TargetID)
	if err != nil || intent.NodeID != resolver.nodeID || intent.ExpectedNodeGeneration != operation.ExpectedGeneration ||
		intent.DesiredNodeGeneration != operation.DesiredGeneration {
		return operations.ApplyScope{}, fmt.Errorf("%w: pending transport switch does not match current node", operations.ErrApplyConflict)
	}
	return operations.ApplyScope{Role: model.RoleNode, NodeID: resolver.nodeID}, nil
}

func validateCurrentNodeTransportApplyAuthority(plan operations.ApplyPlan, state model.State) error {
	if len(plan.Operations) != 1 {
		return fmt.Errorf("%w: convergence plan does not contain one transport operation", operations.ErrApplyConflict)
	}
	wanted := plan.Operations[0]
	for _, operation := range state.Operations {
		if operation.ID != wanted.ID {
			continue
		}
		if wanted.Type != string(operation.Type) || wanted.TargetKind != operation.TargetKind ||
			wanted.TargetID != operation.TargetID ||
			(operation.State != model.OperationPending && operation.State != model.OperationCompleted) {
			return fmt.Errorf("%w: convergence operation differs from retained node request", operations.ErrApplyConflict)
		}
		return nil
	}
	return fmt.Errorf("%w: convergence operation has no retained node request", operations.ErrApplyConflict)
}

func (operator *systemConvergenceApply) readAuthority() (model.State, error) {
	state, err := operator.state.Load()
	if err != nil {
		return model.State{}, err
	}
	if err := validateRepairAuthority(state, operator.role, operator.nodeID); err != nil {
		return model.State{}, errors.Join(operations.ErrApplyInvalid, err)
	}
	return state, nil
}

func pendingStateOperations(state model.State) []model.Operation {
	pending := make([]model.Operation, 0)
	for _, operation := range state.Operations {
		if operation.State == model.OperationPending {
			pending = append(pending, operation)
		}
	}
	return pending
}

var _ ConvergenceApplyOperator = (*systemConvergenceApply)(nil)
var _ operations.ApplyScopeResolver = currentNodeTransportApplyScopeResolver{}
