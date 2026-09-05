package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestTransportSwitchMutationRegistersIntentWithoutChangingSelectionAndReplays(t *testing.T) {
	controller, stateStore, now := transportSwitchMutationController(t)
	dispatcher, err := NewTransportSwitchMutationDispatcher(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	handler, err := controller.NewNodeMutationHandler(dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	request := transportSwitchMutationRequest(t, 2, 9)

	first, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request)
	if err != nil || first.StatusCode != http.StatusOK || first.Response.AuthoritativeGeneration != 3 {
		t.Fatalf("first result=%+v err=%v", first, err)
	}
	var receipt transport.DeferredSwitchReceipt
	if err := control.DecodeRPCPayload(first.Response.Data, &receipt); err != nil || receipt.Validate() != nil ||
		receipt.GatewayGeneration != 3 || receipt.DesiredGatewayGeneration != 4 ||
		receipt.ExpectedNodeGeneration != 9 || receipt.DesiredNodeGeneration != 11 {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	state, err := stateStore.Load()
	if err != nil || state.Generation != 3 || state.Nodes[0].ActiveTransport != model.TransportStandard || len(state.Operations) != 1 {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	operation := state.Operations[0]
	intent, parseErr := transport.ParseSwitchIntentTarget(operation.TargetID)
	if parseErr != nil || operation.ID != receipt.OperationID || operation.RequestID != request.RequestID ||
		operation.State != model.OperationPending || operation.ExpectedGeneration != 2 || operation.DesiredGeneration != 4 ||
		intent.NodeID != mutationTestNodeID || intent.Target != model.TransportRestricted || len(operation.Steps) != 6 {
		t.Fatalf("operation=%+v intent=%+v parseErr=%v", operation, intent, parseErr)
	}
	for _, configured := range state.Transports {
		if configured.Kind == model.TransportStandard && configured.State != model.TransportActive ||
			configured.Kind == model.TransportRestricted && configured.State != model.TransportStandby {
			t.Fatalf("transport selection changed: %+v", state.Transports)
		}
	}

	replayed, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request)
	if err != nil || replayed.StatusCode != http.StatusOK || replayed.Response.AuthoritativeGeneration != 3 ||
		replayed.Response.ResultHash != first.Response.ResultHash {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	stateAfterReplay, err := stateStore.Load()
	if err != nil || stateAfterReplay.Generation != 3 || len(stateAfterReplay.Operations) != 1 {
		t.Fatalf("state after replay=%+v err=%v", stateAfterReplay, err)
	}
}

func TestTransportSwitchMutationReconcilesEvictedStableRequestAndRejectsAnotherPendingSwitch(t *testing.T) {
	controller, stateStore, now := transportSwitchMutationController(t)
	dispatcher, _ := NewTransportSwitchMutationDispatcher(func() time.Time { return now })
	handler, _ := controller.NewNodeMutationHandler(dispatcher)
	request := transportSwitchMutationRequest(t, 2, 9)
	if result, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request); err != nil || result.StatusCode != http.StatusOK {
		t.Fatalf("initial result=%+v err=%v", result, err)
	}
	controller.runtime.Now = func() time.Time { return now.Add(model.IdempotencyMaxAge + time.Second) }
	reconciled, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request)
	if err != nil || reconciled.StatusCode != http.StatusOK || reconciled.Response.AuthoritativeGeneration != 3 || len(reconciled.Response.Warnings) != 1 {
		t.Fatalf("reconciled=%+v err=%v", reconciled, err)
	}
	var receipt transport.DeferredSwitchReceipt
	if err := control.DecodeRPCPayload(reconciled.Response.Data, &receipt); err != nil || receipt.OperationID == "" {
		t.Fatalf("reconciled receipt=%+v err=%v", receipt, err)
	}

	second := transportSwitchMutationRequest(t, 3, 9)
	result, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, second)
	if err != nil || result.StatusCode != http.StatusUnprocessableEntity || result.Response.ErrorCode != "mutation_rejected" {
		t.Fatalf("second pending result=%+v err=%v", result, err)
	}
	state, err := stateStore.Load()
	if err != nil || state.Generation != 3 || len(state.Operations) != 1 {
		t.Fatalf("second request changed state=%+v err=%v", state, err)
	}
}

func TestTransportSwitchMutationFinalizesAgainstFreshGatewayGenerationAfterInterleaving(t *testing.T) {
	controller, stateStore, now := transportSwitchMutationController(t)
	dispatcher, _ := NewTransportSwitchMutationDispatcher(func() time.Time { return now })
	handler, _ := controller.NewNodeMutationHandler(dispatcher)
	registration := transportSwitchMutationRequest(t, 2, 9)
	registered, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, registration)
	if err != nil || registered.StatusCode != http.StatusOK {
		t.Fatalf("registration=%+v err=%v", registered, err)
	}
	var pending transport.DeferredSwitchReceipt
	if err := control.DecodeRPCPayload(registered.Response.Data, &pending); err != nil {
		t.Fatal(err)
	}

	// An unrelated authoritative mutation may consume the generation that was
	// anticipated when the deferred intent was registered.
	interleaved, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	interleaved.Generation++
	if err := stateStore.Save(3, interleaved); err != nil {
		t.Fatal(err)
	}

	stale := transportSwitchFinalizationRequest(t, pending, 3)
	staleResult, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, stale)
	if err != nil || staleResult.StatusCode != http.StatusConflict || staleResult.Response.AuthoritativeGeneration != 4 {
		t.Fatalf("stale finalization=%+v err=%v", staleResult, err)
	}
	unchanged, err := stateStore.Load()
	if err != nil || unchanged.Generation != 4 || unchanged.Nodes[0].ActiveTransport != model.TransportStandard ||
		unchanged.Operations[0].State != model.OperationPending {
		t.Fatalf("stale finalization changed state=%+v err=%v", unchanged, err)
	}

	fresh := transportSwitchFinalizationRequest(t, pending, 4)
	finalized, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, fresh)
	if err != nil || finalized.StatusCode != http.StatusOK || finalized.Response.AuthoritativeGeneration != 5 {
		t.Fatalf("fresh finalization=%+v err=%v", finalized, err)
	}
	var receipt transport.FinalizedSwitchReceipt
	if err := control.DecodeRPCPayload(finalized.Response.Data, &receipt); err != nil || receipt.Validate() != nil ||
		receipt.OperationID != pending.OperationID || receipt.ExpectedGatewayGeneration != 4 || receipt.GatewayGeneration != 5 ||
		receipt.ExpectedNodeGeneration != 9 || receipt.DesiredNodeGeneration != 11 {
		t.Fatalf("final receipt=%+v err=%v", receipt, err)
	}
	state, err := stateStore.Load()
	if err != nil || state.Generation != 5 || state.Nodes[0].ActiveTransport != model.TransportRestricted ||
		state.Operations[0].State != model.OperationCompleted || state.Operations[0].DesiredGeneration != 4 {
		t.Fatalf("final state=%+v err=%v", state, err)
	}
	for _, step := range state.Operations[0].Steps {
		if step.State != model.OperationCompleted {
			t.Fatalf("step %s state=%s", step.Name, step.State)
		}
	}
	for _, configured := range state.Transports {
		if configured.Kind == model.TransportStandard && configured.State != model.TransportStandby ||
			configured.Kind == model.TransportRestricted && configured.State != model.TransportActive {
			t.Fatalf("final transport selection=%+v", state.Transports)
		}
	}

	replayed, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, fresh)
	if err != nil || replayed.StatusCode != http.StatusOK || replayed.Response.AuthoritativeGeneration != 5 ||
		replayed.Response.ResultHash != finalized.Response.ResultHash {
		t.Fatalf("final replay=%+v err=%v", replayed, err)
	}
	controller.runtime.Now = func() time.Time { return now.Add(model.IdempotencyMaxAge + time.Second) }
	reconciled, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, fresh)
	if err != nil || reconciled.StatusCode != http.StatusOK || reconciled.Response.AuthoritativeGeneration != 5 ||
		len(reconciled.Response.Warnings) != 1 {
		t.Fatalf("final reconciliation=%+v err=%v", reconciled, err)
	}
	var reconciledReceipt transport.FinalizedSwitchReceipt
	if err := control.DecodeRPCPayload(reconciled.Response.Data, &reconciledReceipt); err != nil || reconciledReceipt.Validate() != nil ||
		reconciledReceipt.OperationID != pending.OperationID || reconciledReceipt.GatewayGeneration != 5 {
		t.Fatalf("final reconciled receipt=%+v err=%v", reconciledReceipt, err)
	}
}

func transportSwitchMutationController(t *testing.T) (*Controller, ControllerStateStore, time.Time) {
	t.Helper()
	return mutationTestController(t)
}

func transportSwitchMutationRequest(t *testing.T, expectedGateway, expectedNode uint64) control.RPCRequest {
	t.Helper()
	payload := transport.DeferredSwitchRequest{
		Action:  transport.SwitchMutationRegister,
		Current: model.TransportStandard, Target: model.TransportRestricted, ExpectedNodeGeneration: expectedNode,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := payload.IntentTarget(mutationTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := transport.SwitchRequestID(intent, payload.Current, expectedGateway)
	if err != nil {
		t.Fatal(err)
	}
	return control.RPCRequest{
		ProtocolMajor: 1, ProtocolMinor: 0, RequestID: requestID,
		ExpectedStateGeneration: expectedGateway, NodeID: mutationTestNodeID, CredentialGeneration: 1,
		Timestamp: time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC), Nonce: "QUFBQUFBQUFBQUFBQUFBQQ",
		Operation: string(model.OperationTransportSwitch), Payload: encoded,
	}
}

func transportSwitchFinalizationRequest(
	t *testing.T,
	receipt transport.DeferredSwitchReceipt,
	expectedGateway uint64,
) control.RPCRequest {
	t.Helper()
	payload := transport.DeferredSwitchRequest{
		Action:  transport.SwitchMutationFinalize,
		Current: receipt.Current, Target: receipt.Target,
		ExpectedNodeGeneration: receipt.ExpectedNodeGeneration,
		DesiredNodeGeneration:  receipt.DesiredNodeGeneration,
		OperationID:            receipt.OperationID,
	}
	requestID, err := transport.SwitchFinalizeRequestID(receipt.OperationID, receipt.DesiredNodeGeneration, expectedGateway)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return control.RPCRequest{
		ProtocolMajor: 1, ProtocolMinor: 0, RequestID: requestID,
		ExpectedStateGeneration: expectedGateway, NodeID: receipt.NodeID, CredentialGeneration: 1,
		Timestamp: time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC), Nonce: "QUFBQUFBQUFBQUFBQUFBQQ",
		Operation: string(model.OperationTransportSwitch), Payload: encoded,
	}
}
