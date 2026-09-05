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

// TransportSwitchMutationDispatcher registers only gateway-authoritative
// intent. It deliberately does not change the node's active transport: the
// later current-node apply coordinator must stage and prove the private path
// before the gateway selection can be published.
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
	payload, intent, node, err := validateDeferredTransportSwitch(state, request)
	if err != nil {
		return model.State{}, NodeMutationResult{}, err
	}
	if err := ctx.Err(); err != nil {
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

func validateDeferredTransportSwitch(
	state model.State,
	request control.RPCRequest,
) (transport.DeferredSwitchRequest, transport.SwitchIntentTarget, model.Node, error) {
	payload, intent, node, err := validateDeferredTransportSwitchRequest(state, request)
	if err != nil {
		return payload, intent, node, err
	}
	if node.Lifecycle != model.LifecycleActive || node.ActiveTransport != payload.Current {
		return payload, intent, node, fmt.Errorf("authoritative node transport differs from the reviewed plan")
	}
	states := make(map[model.TransportKind]model.TransportState, 2)
	for _, configured := range state.Transports {
		if configured.OwnerKind == model.TargetNode && configured.OwnerID == node.ID && configured.State != model.TransportDisabled {
			if _, duplicate := states[configured.Kind]; duplicate {
				return payload, intent, node, fmt.Errorf("authoritative node transport set is ambiguous")
			}
			states[configured.Kind] = configured.State
		}
	}
	if len(states) != 2 || states[payload.Current] != model.TransportActive || states[payload.Target] != model.TransportStandby {
		return payload, intent, node, fmt.Errorf("transport switch requires one active current and one standby target")
	}
	return payload, intent, node, nil
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

var _ NodeMutationDispatcher = (*TransportSwitchMutationDispatcher)(nil)
