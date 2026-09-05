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

// systemConvergenceApply is the fail-closed production command boundary while
// operation-specific pending executors are connected. It fully supports a
// verified no-op, including the mandatory node-to-gateway freshness probe,
// but never reports pending authoritative intent as already applied.
type systemConvergenceApply struct {
	role    model.Role
	nodeID  string
	state   convergenceApplyStateReader
	planner convergenceApplyPlanner
	probe   convergenceApplyGatewayProbe

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
	if _, _, err := operator.readAuthority(); err != nil {
		return nil, err
	}
	return operator, nil
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
	before, pendingBefore, err := operator.readAuthority()
	if err != nil {
		return operations.ApplyPlan{}, model.State{}, err
	}
	convergence, err := operator.planner.Plan(ctx)
	if err != nil {
		return operations.ApplyPlan{}, model.State{}, err
	}
	after, pendingAfter, err := operator.readAuthority()
	if err != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(pendingBefore, pendingAfter) {
		return operations.ApplyPlan{}, model.State{}, errors.Join(operations.ErrApplyConflict, err)
	}
	var plan operations.ApplyPlan
	if len(pendingAfter) == 0 && len(convergence.Changes) == 0 {
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
		if operator.role != model.RoleNode || len(pendingAfter) != 1 || pendingAfter[0].Type != model.OperationTransportSwitch {
			return operations.ApplyPlan{}, model.State{}, ErrSystemConvergenceApplyUnavailable
		}
		resolver := currentNodeTransportApplyScopeResolver{nodeID: operator.nodeID}
		plan, err = operations.BuildApplyPlan(operator.role, operator.nodeID, convergence, resolver)
		if err != nil {
			return operations.ApplyPlan{}, model.State{}, err
		}
		if err := validateCurrentNodeTransportApplyAuthority(plan, pendingAfter[0]); err != nil {
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
		return operations.ApplyResult{}, ErrSystemConvergenceApplyExecutorUnavailable
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

func validateCurrentNodeTransportApplyAuthority(plan operations.ApplyPlan, operation model.Operation) error {
	if len(plan.Operations) != 1 || plan.Operations[0].ID != operation.ID ||
		plan.Operations[0].Type != string(operation.Type) || plan.Operations[0].TargetKind != operation.TargetKind ||
		plan.Operations[0].TargetID != operation.TargetID || operation.State != model.OperationPending {
		return fmt.Errorf("%w: convergence operation differs from retained node request", operations.ErrApplyConflict)
	}
	return nil
}

func (operator *systemConvergenceApply) readAuthority() (model.State, []model.Operation, error) {
	state, err := operator.state.Load()
	if err != nil {
		return model.State{}, nil, err
	}
	if err := validateRepairAuthority(state, operator.role, operator.nodeID); err != nil {
		return model.State{}, nil, errors.Join(operations.ErrApplyInvalid, err)
	}
	pending := make([]model.Operation, 0)
	for _, operation := range state.Operations {
		if operation.State == model.OperationPending {
			pending = append(pending, operation)
		}
	}
	return state, pending, nil
}

var _ ConvergenceApplyOperator = (*systemConvergenceApply)(nil)
var _ operations.ApplyScopeResolver = currentNodeTransportApplyScopeResolver{}
