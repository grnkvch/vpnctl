package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/operations"
)

type gatewayNodeUninstallManager interface {
	PlanRevoke(string) (enrollment.NodeLifecyclePlan, error)
	CommitRevoke(context.Context, enrollment.NodeLifecyclePlan) (enrollment.NodeLifecycleResult, error)
}

// GatewayNodeUninstallHandler is the authenticated one-way handoff from a
// node uninstall to the gateway's authoritative revocation path. It shares
// the controller writer lock, so no local or remote gateway mutation can race
// between the expected-generation check and the revoke commit.
type GatewayNodeUninstallHandler struct {
	controller *Controller
	manager    gatewayNodeUninstallManager
}

func NewGatewayNodeUninstallHandler(controller *Controller, manager gatewayNodeUninstallManager) (*GatewayNodeUninstallHandler, error) {
	if controller == nil || controller.runtime.State == nil || manager == nil {
		return nil, fmt.Errorf("gateway node uninstall dependencies are incomplete")
	}
	return &GatewayNodeUninstallHandler{controller: controller, manager: manager}, nil
}

func (handler *GatewayNodeUninstallHandler) HandleRPC(ctx context.Context, peer control.RPCPeer, request control.RPCRequest) (control.RPCHandlerResult, error) {
	if handler == nil || handler.controller == nil || handler.manager == nil {
		return control.RPCHandlerResult{}, fmt.Errorf("gateway node uninstall handler is incomplete")
	}
	if request.Operation != lifecycle.NodeUninstallOperation {
		return uninstallRPCFailure(request, http.StatusUnprocessableEntity, "validation", 0, "invalid_operation", "the handler accepts only node uninstall"), nil
	}
	if peer.NodeID == "" || peer.NodeID != request.NodeID {
		return uninstallRPCFailure(request, http.StatusForbidden, "validation", 0, "identity_mismatch", "the certificate and request node identities differ"), nil
	}
	var payload lifecycle.NodeUninstallRequest
	if err := control.DecodeRPCPayload(request.Payload, &payload); err != nil || !payload.ConfirmRevoke {
		return uninstallRPCFailure(request, http.StatusUnprocessableEntity, "validation", 0, "revoke_confirmation_required", "node uninstall must explicitly confirm gateway revocation"), nil
	}

	handler.controller.mutationMu.Lock()
	defer handler.controller.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return uninstallRPCFailure(request, http.StatusServiceUnavailable, "unavailable", 0, "request_cancelled", "the uninstall request was cancelled before revocation"), nil
	}
	state, err := handler.controller.runtime.State.Load()
	if err != nil {
		return uninstallRPCFailure(request, http.StatusServiceUnavailable, "unavailable", 0, "state_unavailable", "authoritative gateway state could not be loaded"), nil
	}
	if request.ExpectedStateGeneration == 0 || request.ExpectedStateGeneration != state.Generation {
		return uninstallRPCFailure(request, http.StatusConflict, "conflict", state.Generation, "generation_conflict", "expected_state_generation does not match authoritative state"), nil
	}
	plan, err := handler.manager.PlanRevoke(request.NodeID)
	if err != nil {
		return uninstallRPCFailure(request, http.StatusConflict, "conflict", state.Generation, "node_revoke_conflict", "the authenticated node cannot be revoked from current state"), nil
	}
	result, commitErr := handler.manager.CommitRevoke(ctx, plan)
	if commitErr != nil && !errors.Is(commitErr, enrollment.ErrNodeCleanupPending) {
		return uninstallRPCFailure(request, http.StatusInternalServerError, "internal", state.Generation, "node_revoke_failed", "gateway could not commit node revocation"), nil
	}
	if result.NodeID != request.NodeID || result.StateGeneration == 0 {
		return uninstallRPCFailure(request, http.StatusInternalServerError, "internal", state.Generation, "node_revoke_unconfirmed", "gateway could not confirm authoritative node revocation"), nil
	}
	data, err := json.Marshal(lifecycle.NodeUninstallConfirmation{Confirmed: true, NodeID: result.NodeID})
	if err != nil {
		return control.RPCHandlerResult{}, err
	}
	response := control.NewRPCResponse("success", result.StateGeneration, data)
	response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
	response.ResourceIDs["node_id"] = result.NodeID
	if result.RuntimeReconcileNeeded {
		response.Warnings = append(response.Warnings, "authoritative revocation committed but gateway runtime reconciliation remains pending")
		response.RequiresAction = append(response.RequiresAction, "run vpnctl repair on the gateway to finish closing revoked node runtime")
	}
	if result.CredentialCleanupNeeded {
		response.Warnings = append(response.Warnings, "authoritative revocation committed but revoked gateway credentials remain pending cleanup")
		response.RequiresAction = append(response.RequiresAction, "run vpnctl repair on the gateway to remove retained revoked node credentials")
	}
	if committed, loadErr := handler.controller.runtime.State.Load(); loadErr == nil && committed.Generation == result.StateGeneration {
		handler.controller.recordObservation(ctx, committed)
	}
	return control.RPCHandlerResult{StatusCode: http.StatusOK, Response: response}, nil
}

func uninstallRPCFailure(request control.RPCRequest, status int, category string, generation uint64, code, message string) control.RPCHandlerResult {
	response := control.NewRPCResponse(category, generation, json.RawMessage(`{}`))
	response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
	response.ErrorCode, response.Message = code, message
	return control.RPCHandlerResult{StatusCode: status, Response: response}
}

type systemRPCMux struct {
	update      control.RPCHandler
	uninstall   control.RPCHandler
	expose      control.RPCHandler
	policy      control.RPCHandler
	repairProbe control.RPCHandler
}

func (mux systemRPCMux) HandleRPC(ctx context.Context, peer control.RPCPeer, request control.RPCRequest) (control.RPCHandlerResult, error) {
	switch request.Operation {
	case lifecycle.NodeUpdatePreflightOperation:
		return mux.update.HandleRPC(ctx, peer, request)
	case lifecycle.NodeUninstallOperation:
		return mux.uninstall.HandleRPC(ctx, peer, request)
	case operations.ExposePlanRPCOperation, operations.ExposeReserveRPCOperation, operations.ExposePublishRPCOperation,
		operations.ExposeAbortRPCOperation, operations.ExposeDeferRPCOperation:
		return mux.expose.HandleRPC(ctx, peer, request)
	case operations.PolicyPlanRPCOperation, operations.PolicyCommitRPCOperation:
		return mux.policy.HandleRPC(ctx, peer, request)
	case operations.RepairProbeRPCOperation:
		if mux.repairProbe == nil {
			return uninstallRPCFailure(request, http.StatusUnprocessableEntity, "validation", 0, "unsupported_operation", "the requested control operation is unsupported"), nil
		}
		return mux.repairProbe.HandleRPC(ctx, peer, request)
	default:
		return uninstallRPCFailure(request, http.StatusUnprocessableEntity, "validation", 0, "unsupported_operation", "the requested control operation is unsupported"), nil
	}
}
