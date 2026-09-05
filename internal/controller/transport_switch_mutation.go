package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

// TransportSwitchMutationDispatcher owns both authoritative commits of a
// deferred switch. Registration records intent without changing selection;
// finalization changes selection only after the node has staged and proven the
// private path. Both commits are independently generation-guarded.
type TransportSwitchMutationDispatcher struct {
	now func() time.Time
}

func NewTransportSwitchMutationDispatcher(now func() time.Time) (*TransportSwitchMutationDispatcher, error) {
	if now == nil {
		now = time.Now
	}
	if now().IsZero() {
		return nil, fmt.Errorf("transport switch clock is invalid")
	}
	return &TransportSwitchMutationDispatcher{now: now}, nil
}

func (dispatcher *TransportSwitchMutationDispatcher) Dispatch(
	ctx context.Context,
	state model.State,
	request control.RPCRequest,
) (model.State, NodeMutationResult, error) {
	if ctx == nil || dispatcher == nil || dispatcher.now == nil {
		return model.State{}, NodeMutationResult{}, fmt.Errorf("transport switch dispatcher is incomplete")
	}
	if request.Operation != string(model.OperationTransportSwitch) {
		return model.State{}, NodeMutationResult{}, fmt.Errorf("unsupported transport switch operation")
	}
	payload, intent, node, err := validateDeferredTransportSwitchRequest(state, request)
	if err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	switch payload.Action {
	case transport.SwitchMutationRegister:
		return dispatcher.dispatchRegistration(state, request, payload, intent, node)
	case transport.SwitchMutationFinalize:
		return dispatcher.dispatchFinalization(state, request, payload, intent, node)
	default:
		return model.State{}, NodeMutationResult{}, fmt.Errorf("unsupported transport switch mutation action")
	}
}

func (dispatcher *TransportSwitchMutationDispatcher) dispatchRegistration(
	state model.State,
	request control.RPCRequest,
	payload transport.DeferredSwitchRequest,
	intent transport.SwitchIntentTarget,
	node model.Node,
) (model.State, NodeMutationResult, error) {
	if _, err := payload.ValidateRegistration(node.ID, request.ExpectedStateGeneration, request.RequestID); err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	if err := validateTransportSwitchSelection(state, node, payload.Current, payload.Target); err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	operationID, err := transport.SwitchOperationID(request.RequestID)
	if err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	for _, operation := range state.Operations {
		if operation.Type != model.OperationTransportSwitch || operation.State == model.OperationCompleted || operation.State == model.OperationFailed {
			continue
		}
		retained, parseErr := transport.ParseSwitchIntentTarget(operation.TargetID)
		if operation.TargetKind != "transport" || parseErr != nil {
			return model.State{}, NodeMutationResult{}, fmt.Errorf("authoritative transport switch operation is invalid")
		}
		if retained.NodeID == node.ID {
			return model.State{}, NodeMutationResult{}, fmt.Errorf("node already has a non-terminal transport switch")
		}
	}
	registrationGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	desiredGatewayGeneration, err := model.NextGeneration(registrationGeneration)
	if err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	at := dispatcher.now().UTC()
	stepNames := transport.SwitchOperationStepNames()
	steps := make([]model.OperationStep, len(stepNames))
	for index, name := range stepNames {
		steps[index] = model.OperationStep{Name: name, State: model.OperationPending, UpdatedAt: at}
	}
	operation := model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: operationID, Type: model.OperationTransportSwitch,
		State: model.OperationPending, TargetKind: "transport", TargetID: intent.String(), RequestID: request.RequestID,
		ExpectedGeneration: state.Generation, DesiredGeneration: desiredGatewayGeneration,
		Steps: steps, CreatedAt: at, UpdatedAt: at,
	}
	if err := operation.Validate(); err != nil {
		return model.State{}, NodeMutationResult{}, fmt.Errorf("validate transport switch operation: %w", err)
	}
	candidate := state
	candidate.Generation = registrationGeneration
	candidate.Nodes = append([]model.Node(nil), state.Nodes...)
	candidate.Operations = append(append([]model.Operation(nil), state.Operations...), operation)
	if err := model.ValidateTransition(state, candidate); err != nil {
		return model.State{}, NodeMutationResult{}, fmt.Errorf("register transport switch operation: %w", err)
	}
	receipt := transport.DeferredSwitchReceipt{
		OperationID: operation.ID, RequestID: operation.RequestID,
		NodeID: node.ID, Current: payload.Current, Target: payload.Target,
		GatewayGeneration: registrationGeneration, DesiredGatewayGeneration: desiredGatewayGeneration,
		ExpectedNodeGeneration: intent.ExpectedNodeGeneration, DesiredNodeGeneration: intent.DesiredNodeGeneration,
	}
	result, err := transportSwitchMutationResult(receipt, model.ResultPending)
	if err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	return candidate, result, nil
}

func (dispatcher *TransportSwitchMutationDispatcher) dispatchFinalization(
	state model.State,
	request control.RPCRequest,
	payload transport.DeferredSwitchRequest,
	intent transport.SwitchIntentTarget,
	node model.Node,
) (model.State, NodeMutationResult, error) {
	if _, err := payload.ValidateFinalization(node.ID, request.ExpectedStateGeneration, request.RequestID); err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	if err := validateTransportSwitchSelection(state, node, payload.Current, payload.Target); err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	operationIndex, operation, err := retainedTransportSwitchOperation(state, payload.OperationID, intent)
	if err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	if operation.State != model.OperationPending {
		return model.State{}, NodeMutationResult{}, fmt.Errorf("transport switch operation is not pending")
	}
	at := dispatcher.now().UTC()
	completed, err := completeTransportSwitchOperation(operation, at)
	if err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	candidate := state
	candidate.Generation, err = model.NextGeneration(state.Generation)
	if err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	candidate.Nodes = append([]model.Node(nil), state.Nodes...)
	for index := range candidate.Nodes {
		if candidate.Nodes[index].ID == node.ID {
			candidate.Nodes[index].ActiveTransport = payload.Target
		}
	}
	candidate.Transports = append([]model.Transport(nil), state.Transports...)
	for index := range candidate.Transports {
		configured := &candidate.Transports[index]
		if configured.OwnerKind != model.TargetNode || configured.OwnerID != node.ID {
			continue
		}
		switch configured.Kind {
		case payload.Current:
			configured.State = model.TransportStandby
		case payload.Target:
			configured.State = model.TransportActive
		}
	}
	candidate.Operations = append([]model.Operation(nil), state.Operations...)
	candidate.Operations[operationIndex] = completed
	if err := model.ValidateTransition(state, candidate); err != nil {
		return model.State{}, NodeMutationResult{}, fmt.Errorf("finalize transport switch operation: %w", err)
	}
	receipt := transport.FinalizedSwitchReceipt{
		OperationID: operation.ID, RequestID: request.RequestID, NodeID: node.ID,
		Previous: payload.Current, Active: payload.Target,
		ExpectedGatewayGeneration: request.ExpectedStateGeneration, GatewayGeneration: candidate.Generation,
		ExpectedNodeGeneration: intent.ExpectedNodeGeneration, DesiredNodeGeneration: intent.DesiredNodeGeneration,
	}
	result, err := finalizedTransportSwitchMutationResult(receipt)
	if err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	return candidate, result, nil
}

func (dispatcher *TransportSwitchMutationDispatcher) Reconcile(
	ctx context.Context,
	state model.State,
	request control.RPCRequest,
) (NodeMutationResult, bool, error) {
	if ctx == nil || dispatcher == nil {
		return NodeMutationResult{}, false, fmt.Errorf("transport switch dispatcher is incomplete")
	}
	payload, intent, node, err := validateDeferredTransportSwitchRequest(state, request)
	if err != nil {
		return NodeMutationResult{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return NodeMutationResult{}, false, err
	}
	switch payload.Action {
	case transport.SwitchMutationRegister:
		return reconcileTransportSwitchRegistration(state, request, payload, intent, node)
	case transport.SwitchMutationFinalize:
		return reconcileTransportSwitchFinalization(state, request, payload, intent, node)
	default:
		return NodeMutationResult{}, false, fmt.Errorf("unsupported transport switch mutation action")
	}
}

func reconcileTransportSwitchRegistration(
	state model.State,
	request control.RPCRequest,
	payload transport.DeferredSwitchRequest,
	intent transport.SwitchIntentTarget,
	node model.Node,
) (NodeMutationResult, bool, error) {
	if _, err := payload.ValidateRegistration(node.ID, request.ExpectedStateGeneration, request.RequestID); err != nil {
		return NodeMutationResult{}, false, err
	}
	operationID, err := transport.SwitchOperationID(request.RequestID)
	if err != nil {
		return NodeMutationResult{}, false, err
	}
	for _, operation := range state.Operations {
		if operation.ID != operationID {
			continue
		}
		if operation.Type != model.OperationTransportSwitch || operation.TargetKind != "transport" || operation.TargetID != intent.String() ||
			operation.RequestID != request.RequestID || operation.ExpectedGeneration != request.ExpectedStateGeneration {
			return NodeMutationResult{}, false, fmt.Errorf("retained transport switch operation conflicts with the request")
		}
		registrationGeneration, generationErr := model.NextGeneration(operation.ExpectedGeneration)
		desiredGatewayGeneration, desiredErr := model.NextGeneration(registrationGeneration)
		if generationErr != nil || desiredErr != nil || operation.DesiredGeneration != desiredGatewayGeneration {
			return NodeMutationResult{}, false, fmt.Errorf("retained transport switch generations are invalid")
		}
		receipt := transport.DeferredSwitchReceipt{
			OperationID: operation.ID, RequestID: operation.RequestID,
			NodeID: node.ID, Current: payload.Current, Target: payload.Target,
			GatewayGeneration: registrationGeneration, DesiredGatewayGeneration: operation.DesiredGeneration,
			ExpectedNodeGeneration: intent.ExpectedNodeGeneration, DesiredNodeGeneration: intent.DesiredNodeGeneration,
		}
		status := model.ResultPending
		switch operation.State {
		case model.OperationDegraded:
			status = model.ResultDegraded
		case model.OperationFailed:
			status = model.ResultFailed
		case model.OperationCompleted:
			status = model.ResultOK
		}
		result, resultErr := transportSwitchMutationResult(receipt, status)
		return result, true, resultErr
	}
	return NodeMutationResult{}, false, nil
}

func reconcileTransportSwitchFinalization(
	state model.State,
	request control.RPCRequest,
	payload transport.DeferredSwitchRequest,
	intent transport.SwitchIntentTarget,
	node model.Node,
) (NodeMutationResult, bool, error) {
	if _, err := payload.ValidateFinalization(node.ID, request.ExpectedStateGeneration, request.RequestID); err != nil {
		return NodeMutationResult{}, false, err
	}
	_, operation, err := retainedTransportSwitchOperation(state, payload.OperationID, intent)
	if err != nil {
		return NodeMutationResult{}, false, err
	}
	if operation.State != model.OperationCompleted {
		return NodeMutationResult{}, false, nil
	}
	if err := validateTransportSwitchSelection(state, node, payload.Target, payload.Current); err != nil {
		return NodeMutationResult{}, false, fmt.Errorf("completed transport switch selection is invalid: %w", err)
	}
	receipt := transport.FinalizedSwitchReceipt{
		OperationID: operation.ID, RequestID: request.RequestID, NodeID: node.ID,
		Previous: payload.Current, Active: payload.Target,
		ExpectedGatewayGeneration: request.ExpectedStateGeneration, GatewayGeneration: state.Generation,
		ExpectedNodeGeneration: intent.ExpectedNodeGeneration, DesiredNodeGeneration: intent.DesiredNodeGeneration,
	}
	result, err := finalizedTransportSwitchMutationResult(receipt)
	return result, true, err
}

func validateTransportSwitchSelection(
	state model.State,
	node model.Node,
	current model.TransportKind,
	target model.TransportKind,
) error {
	if node.Lifecycle != model.LifecycleActive || node.ActiveTransport != current {
		return fmt.Errorf("authoritative node transport differs from the reviewed plan")
	}
	states := make(map[model.TransportKind]model.TransportState, 2)
	for _, configured := range state.Transports {
		if configured.OwnerKind == model.TargetNode && configured.OwnerID == node.ID && configured.State != model.TransportDisabled {
			if _, duplicate := states[configured.Kind]; duplicate {
				return fmt.Errorf("authoritative node transport set is ambiguous")
			}
			states[configured.Kind] = configured.State
		}
	}
	if len(states) != 2 || states[current] != model.TransportActive || states[target] != model.TransportStandby {
		return fmt.Errorf("transport switch requires one active current and one standby target")
	}
	return nil
}

func validateDeferredTransportSwitchRequest(
	state model.State,
	request control.RPCRequest,
) (transport.DeferredSwitchRequest, transport.SwitchIntentTarget, model.Node, error) {
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return transport.DeferredSwitchRequest{}, transport.SwitchIntentTarget{}, model.Node{}, fmt.Errorf("transport switch requires valid gateway state")
	}
	var payload transport.DeferredSwitchRequest
	if err := control.DecodeRPCPayload(request.Payload, &payload); err != nil {
		return payload, transport.SwitchIntentTarget{}, model.Node{}, fmt.Errorf("transport switch payload is invalid")
	}
	intent, err := payload.IntentTarget(request.NodeID)
	if err != nil {
		return payload, transport.SwitchIntentTarget{}, model.Node{}, err
	}
	for _, node := range state.Nodes {
		if node.ID == request.NodeID {
			return payload, intent, node, nil
		}
	}
	return payload, intent, model.Node{}, fmt.Errorf("transport switch node does not exist")
}

func retainedTransportSwitchOperation(
	state model.State,
	operationID string,
	intent transport.SwitchIntentTarget,
) (int, model.Operation, error) {
	for index, operation := range state.Operations {
		if operation.ID != operationID {
			continue
		}
		registrationGeneration, registrationErr := model.NextGeneration(operation.ExpectedGeneration)
		desiredGatewayGeneration, desiredErr := model.NextGeneration(registrationGeneration)
		derivedOperationID, identityErr := transport.SwitchOperationID(operation.RequestID)
		if operation.Type != model.OperationTransportSwitch || operation.TargetKind != "transport" ||
			operation.TargetID != intent.String() || registrationErr != nil || desiredErr != nil || identityErr != nil ||
			operation.DesiredGeneration != desiredGatewayGeneration || derivedOperationID != operation.ID {
			return -1, model.Operation{}, fmt.Errorf("retained transport switch operation is invalid")
		}
		return index, operation, nil
	}
	return -1, model.Operation{}, fmt.Errorf("transport switch operation does not exist")
}

func completeTransportSwitchOperation(operation model.Operation, at time.Time) (model.Operation, error) {
	completed := operation
	var err error
	for _, step := range operation.Steps {
		completed, err = completed.TransitionStep(step.Name, model.OperationCompleted, at)
		if err != nil {
			return model.Operation{}, fmt.Errorf("complete transport switch step %s: %w", step.Name, err)
		}
	}
	completed, err = completed.Transition(model.OperationCompleted, at, "")
	if err != nil {
		return model.Operation{}, fmt.Errorf("complete transport switch operation: %w", err)
	}
	return completed, nil
}

func transportSwitchMutationResult(receipt transport.DeferredSwitchReceipt, status model.ResultStatus) (NodeMutationResult, error) {
	if err := receipt.Validate(); err != nil {
		return NodeMutationResult{}, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return NodeMutationResult{}, err
	}
	category := "success"
	response := control.NewRPCResponse(category, receipt.GatewayGeneration, encoded)
	response.ResourceIDs["node_id"] = receipt.NodeID
	response.ResourceIDs["operation_id"] = receipt.OperationID
	if status == model.ResultFailed {
		response.Category = "conflict"
		response.ErrorCode = "transport_switch_failed"
		response.Message = "the retained transport switch operation failed"
	}
	return NodeMutationResult{Status: status, Response: response}, nil
}

func finalizedTransportSwitchMutationResult(receipt transport.FinalizedSwitchReceipt) (NodeMutationResult, error) {
	if err := receipt.Validate(); err != nil {
		return NodeMutationResult{}, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return NodeMutationResult{}, err
	}
	response := control.NewRPCResponse("success", receipt.GatewayGeneration, encoded)
	response.ResourceIDs["node_id"] = receipt.NodeID
	response.ResourceIDs["operation_id"] = receipt.OperationID
	return NodeMutationResult{Status: model.ResultOK, Response: response}, nil
}

var _ NodeMutationDispatcher = (*TransportSwitchMutationDispatcher)(nil)
