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
	second.RequestID = "71000000-0000-4000-8000-000000000002"
	result, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, second)
	if err != nil || result.StatusCode != http.StatusUnprocessableEntity || result.Response.ErrorCode != "mutation_rejected" {
		t.Fatalf("second pending result=%+v err=%v", result, err)
	}
	state, err := stateStore.Load()
	if err != nil || state.Generation != 3 || len(state.Operations) != 1 {
		t.Fatalf("second request changed state=%+v err=%v", state, err)
	}
}

func transportSwitchMutationController(t *testing.T) (*Controller, ControllerStateStore, time.Time) {
	t.Helper()
	return mutationTestController(t)
}

func transportSwitchMutationRequest(t *testing.T, expectedGateway, expectedNode uint64) control.RPCRequest {
	t.Helper()
	payload := transport.DeferredSwitchRequest{
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
