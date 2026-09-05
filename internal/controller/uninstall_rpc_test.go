package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
)

func TestGatewayNodeUninstallHandlerCommitsUnderExpectedGeneration(t *testing.T) {
	controller, _, _ := mutationTestController(t)
	manager := &recordingGatewayUninstallManager{result: enrollment.NodeLifecycleResult{
		Command: enrollment.NodeRevoke, NodeID: mutationTestNodeID, Changed: true,
		StateGeneration: 3, ConnectionsClosed: true,
	}}
	handler, err := NewGatewayNodeUninstallHandler(controller, manager)
	if err != nil {
		t.Fatal(err)
	}
	request := gatewayUninstallRPCRequest(t, 2)
	result, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request)
	if err != nil || result.StatusCode != http.StatusOK || result.Response.Category != "success" || result.Response.AuthoritativeGeneration != 3 ||
		manager.planCalls != 1 || manager.commitCalls != 1 || manager.reference != mutationTestNodeID {
		t.Fatalf("HandleRPC() = %+v, %v manager=%+v", result, err, manager)
	}
	var confirmation lifecycle.NodeUninstallConfirmation
	if err := control.DecodeRPCPayload(result.Response.Data, &confirmation); err != nil || !confirmation.Confirmed || confirmation.NodeID != mutationTestNodeID {
		t.Fatalf("confirmation = %+v, %v", confirmation, err)
	}
}

func TestGatewayNodeUninstallHandlerReturnsCommittedCleanupActions(t *testing.T) {
	controller, _, _ := mutationTestController(t)
	manager := &recordingGatewayUninstallManager{
		result: enrollment.NodeLifecycleResult{
			Command: enrollment.NodeRevoke, NodeID: mutationTestNodeID, Changed: true, StateGeneration: 3,
			RuntimeReconcileNeeded: true, CredentialCleanupNeeded: true,
		},
		commitErr: errors.Join(enrollment.ErrNodeCleanupPending, enrollment.ErrNodeRevocationIncomplete),
	}
	handler, _ := NewGatewayNodeUninstallHandler(controller, manager)
	result, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, gatewayUninstallRPCRequest(t, 2))
	if err != nil || result.StatusCode != http.StatusOK || len(result.Response.Warnings) != 2 || len(result.Response.RequiresAction) != 2 {
		t.Fatalf("cleanup-pending response = %+v, %v", result, err)
	}
}

func TestGatewayNodeUninstallHandlerRejectsBeforeManagerOnGenerationOrConfirmation(t *testing.T) {
	controller, _, _ := mutationTestController(t)
	manager := &recordingGatewayUninstallManager{}
	handler, _ := NewGatewayNodeUninstallHandler(controller, manager)

	request := gatewayUninstallRPCRequest(t, 1)
	result, err := handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request)
	if err != nil || result.StatusCode != http.StatusConflict || result.Response.ErrorCode != "generation_conflict" || manager.planCalls != 0 {
		t.Fatalf("generation conflict = %+v, %v calls=%d", result, err, manager.planCalls)
	}
	request = gatewayUninstallRPCRequest(t, 2)
	request.Payload = json.RawMessage(`{"confirm_revoke":false}`)
	result, err = handler.HandleRPC(context.Background(), control.RPCPeer{NodeID: mutationTestNodeID}, request)
	if err != nil || result.StatusCode != http.StatusUnprocessableEntity || result.Response.ErrorCode != "revoke_confirmation_required" || manager.planCalls != 0 {
		t.Fatalf("missing confirmation = %+v, %v calls=%d", result, err, manager.planCalls)
	}
}

func TestSystemRPCMuxKeepsUpdateAndUninstallOperationsSeparate(t *testing.T) {
	update := &recordingRPCHandler{status: http.StatusOK}
	uninstall := &recordingRPCHandler{status: http.StatusAccepted}
	repairProbe := &recordingRPCHandler{status: http.StatusNoContent}
	mutation := &recordingRPCHandler{status: http.StatusCreated}
	mux := systemRPCMux{update: update, uninstall: uninstall, mutation: mutation, repairProbe: repairProbe}
	request := control.RPCRequest{Operation: lifecycle.NodeUpdatePreflightOperation}
	result, _ := mux.HandleRPC(context.Background(), control.RPCPeer{}, request)
	if result.StatusCode != http.StatusOK || update.calls != 1 || uninstall.calls != 0 {
		t.Fatalf("update mux result=%+v calls=%d/%d", result, update.calls, uninstall.calls)
	}
	request.Operation = lifecycle.NodeUninstallOperation
	result, _ = mux.HandleRPC(context.Background(), control.RPCPeer{}, request)
	if result.StatusCode != http.StatusAccepted || update.calls != 1 || uninstall.calls != 1 {
		t.Fatalf("uninstall mux result=%+v calls=%d/%d", result, update.calls, uninstall.calls)
	}
	request.Operation = operations.RepairProbeRPCOperation
	result, _ = mux.HandleRPC(context.Background(), control.RPCPeer{}, request)
	if result.StatusCode != http.StatusNoContent || repairProbe.calls != 1 || update.calls != 1 || uninstall.calls != 1 {
		t.Fatalf("repair probe mux result=%+v calls=%d/%d/%d", result, update.calls, uninstall.calls, repairProbe.calls)
	}
	request.Operation = string(model.OperationTransportSwitch)
	result, _ = mux.HandleRPC(context.Background(), control.RPCPeer{}, request)
	if result.StatusCode != http.StatusCreated || mutation.calls != 1 || update.calls != 1 || uninstall.calls != 1 {
		t.Fatalf("transport mutation mux result=%+v calls=%d/%d/%d", result, update.calls, uninstall.calls, mutation.calls)
	}
	request.Operation = "unknown"
	result, _ = mux.HandleRPC(context.Background(), control.RPCPeer{}, request)
	if result.StatusCode != http.StatusUnprocessableEntity || result.Response.ErrorCode != "unsupported_operation" {
		t.Fatalf("unknown mux result=%+v", result)
	}
}

func gatewayUninstallRPCRequest(t *testing.T, generation uint64) control.RPCRequest {
	t.Helper()
	payload, err := json.Marshal(lifecycle.NodeUninstallRequest{ConfirmRevoke: true})
	if err != nil {
		t.Fatal(err)
	}
	return control.RPCRequest{
		ProtocolMajor: 1, ProtocolMinor: 0, RequestID: "93000000-0000-4000-8000-000000000001",
		ExpectedStateGeneration: generation, NodeID: mutationTestNodeID, CredentialGeneration: 1,
		Operation: lifecycle.NodeUninstallOperation, Payload: payload,
	}
}

type recordingGatewayUninstallManager struct {
	result      enrollment.NodeLifecycleResult
	planErr     error
	commitErr   error
	reference   string
	planCalls   int
	commitCalls int
}

func (manager *recordingGatewayUninstallManager) PlanRevoke(reference string) (enrollment.NodeLifecyclePlan, error) {
	manager.planCalls++
	manager.reference = reference
	return enrollment.NodeLifecyclePlan{}, manager.planErr

}

func (manager *recordingGatewayUninstallManager) CommitRevoke(context.Context, enrollment.NodeLifecyclePlan) (enrollment.NodeLifecycleResult, error) {
	manager.commitCalls++
	return manager.result, manager.commitErr
}

type recordingRPCHandler struct {
	status int
	calls  int
}

func (handler *recordingRPCHandler) HandleRPC(context.Context, control.RPCPeer, control.RPCRequest) (control.RPCHandlerResult, error) {
	handler.calls++
	return control.RPCHandlerResult{StatusCode: handler.status}, nil
}
