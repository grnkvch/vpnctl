package operations

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

var ErrTransportSwitchApplyUncertain = errors.New("transport switch apply outcome is uncertain")

type NodeTransportSwitchApplyState interface {
	Load() (model.State, error)
	Save(uint64, model.State) error
}

type NodeTransportSwitchApplyRuntime interface {
	Activate(context.Context, model.State, model.Operation) (transport.DeferredActivation, error)
}

type NodeTransportSwitchApplyGateway interface {
	ReconcileDeferred(context.Context, model.Operation, model.TransportKind) (transport.FinalizedSwitchReceipt, bool, error)
	FinalizeDeferred(context.Context, model.Operation, model.TransportKind, uint64) (transport.FinalizedSwitchReceipt, error)
}

type NodeTransportSwitchGatewayGeneration interface {
	GatewayGeneration(context.Context, string) (uint64, error)
}

// NodeTransportSwitchApplyExecutor coordinates the operation-specific tail of
// a deferred switch. The target runtime is activated first, gateway selection
// is finalized under a fresh CAS, then the node commits its terminal N+2 state
// and promotes the already published convergence Desired snapshot.
type NodeTransportSwitchApplyExecutor struct {
	state       NodeTransportSwitchApplyState
	runtime     NodeTransportSwitchApplyRuntime
	gateway     NodeTransportSwitchApplyGateway
	generation  NodeTransportSwitchGatewayGeneration
	convergence NodeServiceConvergenceStore
	now         func() time.Time
}

func NewNodeTransportSwitchApplyExecutor(
	state NodeTransportSwitchApplyState,
	runtime NodeTransportSwitchApplyRuntime,
	gateway NodeTransportSwitchApplyGateway,
	generation NodeTransportSwitchGatewayGeneration,
	convergence NodeServiceConvergenceStore,
	now func() time.Time,
) (*NodeTransportSwitchApplyExecutor, error) {
	if nilInterface(state) || nilInterface(runtime) || nilInterface(gateway) || nilInterface(generation) || nilInterface(convergence) {
		return nil, fmt.Errorf("node transport switch apply dependencies are incomplete")
	}
	if now == nil {
		now = time.Now
	}
	if now().IsZero() {
		return nil, fmt.Errorf("node transport switch apply clock is invalid")
	}
	return &NodeTransportSwitchApplyExecutor{
		state: state, runtime: runtime, gateway: gateway, generation: generation, convergence: convergence, now: now,
	}, nil
}

func (executor *NodeTransportSwitchApplyExecutor) RequireGateway(ctx context.Context, nodeID string) error {
	if ctx == nil || executor == nil || nilInterface(executor.generation) {
		return ErrApplyGatewayUnavailable
	}
	_, err := executor.generation.GatewayGeneration(ctx, nodeID)
	return err
}

func (executor *NodeTransportSwitchApplyExecutor) ApplyCurrentNode(
	ctx context.Context,
	batch ApplyExecutionBatch,
) (ApplyExecutionResult, error) {
	if ctx == nil || executor == nil || nilInterface(executor.state) || nilInterface(executor.runtime) ||
		nilInterface(executor.gateway) || nilInterface(executor.generation) || nilInterface(executor.convergence) || executor.now == nil {
		return ApplyExecutionResult{}, ErrApplyInvalid
	}
	if batch.Role != model.RoleNode || model.ValidateResourceID(batch.CurrentNodeID) != nil || len(batch.Operations) != 1 {
		return ApplyExecutionResult{}, ErrApplyInvalid
	}
	requested := batch.Operations[0]
	if err := requested.validate(); err != nil || requested.Type != string(model.OperationTransportSwitch) ||
		requested.Scope.Role != model.RoleNode || requested.Scope.NodeID != batch.CurrentNodeID {
		return ApplyExecutionResult{}, errors.Join(ErrApplyInvalid, err)
	}
	current, operation, intent, err := executor.loadOperation(batch, requested)
	if err != nil {
		return ApplyExecutionResult{}, err
	}
	if operation.State == model.OperationCompleted {
		if err := executor.promoteConvergence(ctx, batch, requested); err != nil {
			return ApplyExecutionResult{}, errors.Join(ErrTransportSwitchApplyUncertain, err)
		}
		return transportSwitchApplyResult(batch, requested), nil
	}
	previous := current.Nodes[0].ActiveTransport
	receipt, gatewayComplete, err := executor.gateway.ReconcileDeferred(ctx, operation, previous)
	if err != nil {
		return ApplyExecutionResult{}, fmt.Errorf("reconcile authoritative transport switch: %w", err)
	}
	var expectedGatewayGeneration uint64
	if !gatewayComplete {
		expectedGatewayGeneration, err = executor.generation.GatewayGeneration(ctx, batch.CurrentNodeID)
		if err != nil {
			return ApplyExecutionResult{}, fmt.Errorf("observe authoritative gateway generation: %w", err)
		}
	}
	activation, err := executor.runtime.Activate(ctx, current, operation)
	if err != nil {
		return ApplyExecutionResult{}, fmt.Errorf("activate deferred transport switch runtime: %w", err)
	}
	if latest, loadErr := executor.state.Load(); loadErr != nil || !reflect.DeepEqual(latest, current) {
		rollbackErr := rollbackDeferredActivation(activation)
		return ApplyExecutionResult{}, errors.Join(ErrApplyConflict, loadErr, rollbackErr)
	}
	if !gatewayComplete {
		receipt, err = executor.gateway.FinalizeDeferred(ctx, operation, previous, expectedGatewayGeneration)
		if err != nil {
			reconciled, complete, reconcileErr := executor.gateway.ReconcileDeferred(ctx, operation, previous)
			switch {
			case reconcileErr != nil:
				return ApplyExecutionResult{}, errors.Join(ErrTransportSwitchApplyUncertain, err, reconcileErr)
			case complete:
				receipt = reconciled
			default:
				rollbackErr := rollbackDeferredActivation(activation)
				return ApplyExecutionResult{}, errors.Join(err, rollbackErr)
			}
		}
	}
	final, _, err := transport.FinalizeDeferredSwitchNodeState(current, operation, receipt, executor.now())
	if err != nil {
		return ApplyExecutionResult{}, errors.Join(ErrTransportSwitchApplyUncertain, err)
	}
	if err := executor.commitNodeState(current, final); err != nil {
		return ApplyExecutionResult{}, errors.Join(ErrTransportSwitchApplyUncertain, err)
	}
	if err := executor.promoteConvergence(ctx, batch, requested); err != nil {
		return ApplyExecutionResult{}, errors.Join(ErrTransportSwitchApplyUncertain, err)
	}
	if final.Generation != intent.DesiredNodeGeneration {
		return ApplyExecutionResult{}, ErrApplyInvalid
	}
	return transportSwitchApplyResult(batch, requested), nil
}

func (executor *NodeTransportSwitchApplyExecutor) loadOperation(
	batch ApplyExecutionBatch,
	requested ApplyOperation,
) (model.State, model.Operation, transport.SwitchIntentTarget, error) {
	current, err := executor.state.Load()
	if err != nil {
		return model.State{}, model.Operation{}, transport.SwitchIntentTarget{}, err
	}
	if err := current.Validate(); err != nil || current.Host.Role != model.RoleNode || len(current.Nodes) != 1 ||
		current.Nodes[0].ID != batch.CurrentNodeID {
		return model.State{}, model.Operation{}, transport.SwitchIntentTarget{}, errors.Join(ErrApplyInvalid, err)
	}
	for _, operation := range current.Operations {
		if operation.ID != requested.ID {
			continue
		}
		intent, parseErr := transport.ParseSwitchIntentTarget(operation.TargetID)
		if parseErr != nil || operation.Type != model.OperationTransportSwitch || operation.TargetKind != "transport" ||
			operation.TargetID != requested.TargetID || intent.NodeID != batch.CurrentNodeID ||
			intent.ExpectedNodeGeneration != batch.AppliedGeneration || intent.DesiredNodeGeneration != batch.DesiredGeneration ||
			requested.ExpectedGeneration != intent.ExpectedNodeGeneration || requested.DesiredGeneration != intent.DesiredNodeGeneration {
			return model.State{}, model.Operation{}, transport.SwitchIntentTarget{}, errors.Join(ErrApplyConflict, parseErr)
		}
		switch operation.State {
		case model.OperationPending:
			pendingGeneration, generationErr := model.NextGeneration(intent.ExpectedNodeGeneration)
			if generationErr != nil || current.Generation != pendingGeneration || current.Nodes[0].Gateway == nil ||
				current.Nodes[0].Gateway.PendingRequestID != operation.RequestID || current.Nodes[0].ActiveTransport == intent.Target {
				return model.State{}, model.Operation{}, transport.SwitchIntentTarget{}, errors.Join(ErrApplyConflict, generationErr)
			}
		case model.OperationCompleted:
			if current.Generation != intent.DesiredNodeGeneration || current.Nodes[0].Gateway == nil ||
				current.Nodes[0].Gateway.PendingRequestID != "" || current.Nodes[0].ActiveTransport != intent.Target {
				return model.State{}, model.Operation{}, transport.SwitchIntentTarget{}, ErrApplyConflict
			}
		default:
			return model.State{}, model.Operation{}, transport.SwitchIntentTarget{}, ErrApplyConflict
		}
		return current, operation, intent, nil
	}
	return model.State{}, model.Operation{}, transport.SwitchIntentTarget{}, ErrApplyConflict
}

func (executor *NodeTransportSwitchApplyExecutor) commitNodeState(before, final model.State) error {
	if err := executor.state.Save(before.Generation, final); err == nil {
		return nil
	} else {
		firstErr := err
		loaded, loadErr := executor.state.Load()
		if loadErr == nil && reflect.DeepEqual(loaded, final) {
			return nil
		}
		if loadErr != nil || !reflect.DeepEqual(loaded, before) {
			return errors.Join(firstErr, loadErr)
		}
		if retryErr := executor.state.Save(before.Generation, final); retryErr != nil {
			loaded, loadErr = executor.state.Load()
			if loadErr == nil && reflect.DeepEqual(loaded, final) {
				return nil
			}
			return errors.Join(firstErr, retryErr, loadErr)
		}
		return nil
	}
}

func (executor *NodeTransportSwitchApplyExecutor) promoteConvergence(
	ctx context.Context,
	batch ApplyExecutionBatch,
	requested ApplyOperation,
) error {
	current, err := executor.convergence.Read(ctx)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(current.Desired, current.Applied) && current.Applied.Generation == batch.DesiredGeneration && len(current.Pending) == 0 {
		return nil
	}
	changes, err := desiredChanges(current)
	if err != nil || current.Applied.Generation != batch.AppliedGeneration || current.Desired.Generation != batch.DesiredGeneration ||
		len(current.Pending) != 1 || current.Pending[0].ID != requested.ID || !reflect.DeepEqual(changes, requested.Changes) {
		return errors.Join(ErrConvergenceSnapshotConflict, err)
	}
	candidate, err := canonicalSnapshot(ConvergenceSnapshot{
		Desired: cloneManifest(current.Desired), Applied: cloneManifest(current.Desired), Pending: []PendingOperation{},
	})
	if err != nil {
		return err
	}
	changed, err := executor.convergence.CompareAndSwap(ctx, current, candidate)
	if err == nil && changed {
		return nil
	}
	loaded, loadErr := executor.convergence.Read(ctx)
	if loadErr == nil && reflect.DeepEqual(loaded, candidate) {
		return nil
	}
	if err == nil && !changed {
		err = ErrConvergenceSnapshotConflict
	}
	return errors.Join(err, loadErr)
}

func rollbackDeferredActivation(activation transport.DeferredActivation) error {
	if nilInterface(activation) {
		return fmt.Errorf("deferred transport switch activation is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), transport.DefaultTransportSwitchRollbackTimeout)
	defer cancel()
	return activation.Rollback(ctx)
}

func transportSwitchApplyResult(batch ApplyExecutionBatch, requested ApplyOperation) ApplyExecutionResult {
	return ApplyExecutionResult{
		Changed: true, AppliedGeneration: batch.DesiredGeneration, OperationIDs: []string{requested.ID},
	}
}

var _ CurrentNodeApplyExecutor = (*NodeTransportSwitchApplyExecutor)(nil)
