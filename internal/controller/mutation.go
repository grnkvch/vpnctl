package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

// NodeMutationResult is the bounded result of a node-owned mutation. The
// response is returned to the caller, while only Status and a SHA-256 digest
// of the normalized response are persisted in the idempotency history.
type NodeMutationResult struct {
	Status   model.ResultStatus
	Response control.RPCResponse
}

// NodeMutationDispatcher owns resource-specific candidate construction and
// reconciliation. Dispatch must not perform an unrecorded host-side effect;
// multi-step system work is represented by persisted saga state. Reconcile
// must only inspect the supplied state. It reports determined when the desired
// effect can be proven present or absent without replaying it.
type NodeMutationDispatcher interface {
	Dispatch(context.Context, model.State, control.RPCRequest) (model.State, NodeMutationResult, error)
	Reconcile(context.Context, model.State, control.RPCRequest) (NodeMutationResult, bool, error)
}

// NodeMutationHandler shares the controller's mutation lock with local
// mutations, so authoritative load, dispatch, idempotency append, and commit
// form one serialized critical section.
type NodeMutationHandler struct {
	controller *Controller
	dispatcher NodeMutationDispatcher
}

func (controller *Controller) NewNodeMutationHandler(dispatcher NodeMutationDispatcher) (*NodeMutationHandler, error) {
	if controller == nil || controller.runtime.State == nil {
		return nil, fmt.Errorf("gateway controller is required")
	}
	if dispatcher == nil {
		return nil, fmt.Errorf("node mutation dispatcher is required")
	}
	return &NodeMutationHandler{controller: controller, dispatcher: dispatcher}, nil
}

func (handler *NodeMutationHandler) HandleRPC(ctx context.Context, _ control.RPCPeer, request control.RPCRequest) (control.RPCHandlerResult, error) {
	if handler == nil || handler.controller == nil || handler.dispatcher == nil {
		return control.RPCHandlerResult{}, fmt.Errorf("node mutation handler is incomplete")
	}
	if request.ExpectedStateGeneration == 0 {
		return mutationFailure(request, http.StatusUnprocessableEntity, "validation", 0, "expected_generation_required", "expected_state_generation must be positive"), nil
	}
	operation := model.OperationType(request.Operation)
	if !validNodeMutationOperation(operation) {
		return mutationFailure(request, http.StatusUnprocessableEntity, "validation", 0, "unsupported_operation", "the requested mutation operation is unsupported"), nil
	}

	handler.controller.mutationMu.Lock()
	defer handler.controller.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return mutationFailure(request, http.StatusServiceUnavailable, "unavailable", 0, "request_cancelled", "the mutation request was cancelled before dispatch"), nil
	}

	state, err := handler.controller.runtime.State.Load()
	if err != nil {
		return mutationFailure(request, http.StatusServiceUnavailable, "unavailable", 0, "state_unavailable", "authoritative state could not be loaded"), nil
	}
	nodeIndex := nodeIndexByID(state, request.NodeID)
	if nodeIndex < 0 {
		return mutationFailure(request, http.StatusConflict, "conflict", state.Generation, "node_not_found", "the node has no authoritative gateway record"), nil
	}
	now := handler.controller.runtime.Now().UTC()
	stored, findErr := state.Nodes[nodeIndex].FindIdempotencyResult(request.RequestID, now)
	switch {
	case findErr == nil:
		if stored.Operation != operation {
			return mutationFailure(request, http.StatusConflict, "conflict", state.Generation, "request_id_conflict", "request_id was already used for another operation"), nil
		}
		return storedMutationResult(request, stored), nil
	case !errors.Is(findErr, model.ErrIdempotencyRecordEvicted):
		return mutationFailure(request, http.StatusInternalServerError, "internal", state.Generation, "idempotency_unavailable", "idempotency history could not be inspected"), nil
	}

	if request.ExpectedStateGeneration != state.Generation {
		if request.ExpectedStateGeneration < state.Generation {
			return handler.reconcileEvicted(ctx, state, request)
		}
		return mutationFailure(request, http.StatusConflict, "conflict", state.Generation, "generation_conflict", "expected_state_generation does not match authoritative state"), nil
	}

	candidate, result, err := handler.dispatcher.Dispatch(ctx, state, request)
	if err != nil {
		return mutationFailure(request, http.StatusUnprocessableEntity, "validation", state.Generation, "mutation_rejected", "the requested mutation was rejected"), nil
	}
	response, err := normalizeMutationResult(request, candidate.Generation, result)
	if err != nil {
		return mutationFailure(request, http.StatusInternalServerError, "internal", state.Generation, "invalid_mutation_result", "the mutation produced an invalid result"), nil
	}
	candidateNodeIndex := nodeIndexByID(candidate, request.NodeID)
	if candidateNodeIndex < 0 {
		return mutationFailure(request, http.StatusInternalServerError, "internal", state.Generation, "invalid_mutation_result", "the mutation removed its idempotency owner"), nil
	}
	record := model.IdempotencyRecord{
		RequestID: request.RequestID, Operation: operation, ResultStatus: result.Status,
		ResultHash: response.ResultHash, StateGeneration: candidate.Generation, RecordedAt: now,
	}
	updatedNode, prior, replayed, err := candidate.Nodes[candidateNodeIndex].StoreIdempotencyResult(record, now)
	if err != nil {
		return mutationFailure(request, http.StatusInternalServerError, "internal", state.Generation, "idempotency_write_failed", "the mutation result could not be recorded"), nil
	}
	if replayed {
		// This is unreachable while the controller lock is held unless a
		// dispatcher returned a candidate containing a conflicting history.
		if prior.Operation != operation {
			return mutationFailure(request, http.StatusConflict, "conflict", state.Generation, "request_id_conflict", "request_id was already used for another operation"), nil
		}
		return storedMutationResult(request, prior), nil
	}
	candidate.Nodes[candidateNodeIndex] = updatedNode
	if err := handler.controller.runtime.State.Save(state.Generation, candidate); err != nil {
		if errors.Is(err, store.ErrStateConflict) {
			return mutationFailure(request, http.StatusConflict, "conflict", state.Generation, "generation_conflict", "authoritative state changed before commit"), nil
		}
		return mutationFailure(request, http.StatusInternalServerError, "internal", state.Generation, "state_write_failed", "authoritative state could not be committed"), nil
	}
	handler.controller.recordObservation(ctx, candidate)
	return control.RPCHandlerResult{StatusCode: mutationHTTPStatus(response.Category), Response: response}, nil
}

func (handler *NodeMutationHandler) reconcileEvicted(ctx context.Context, state model.State, request control.RPCRequest) (control.RPCHandlerResult, error) {
	result, determined, err := handler.dispatcher.Reconcile(ctx, state, request)
	if err != nil {
		return mutationFailure(request, http.StatusServiceUnavailable, "unavailable", state.Generation, "reconciliation_unavailable", "current resource state could not be reconciled"), nil
	}
	if !determined {
		return mutationFailure(request, http.StatusConflict, "conflict", state.Generation, "uncertain_request_conflict", "the stale request is not retained and its effect cannot be proven"), nil
	}
	result.Response.Warnings = append(copyStrings(result.Response.Warnings), "idempotency history was evicted; current resource state was reconciled")
	response, err := normalizeMutationResult(request, state.Generation, result)
	if err != nil {
		return mutationFailure(request, http.StatusInternalServerError, "internal", state.Generation, "invalid_reconciliation_result", "resource reconciliation produced an invalid result"), nil
	}
	return control.RPCHandlerResult{StatusCode: mutationHTTPStatus(response.Category), Response: response}, nil
}

func normalizeMutationResult(request control.RPCRequest, generation uint64, result NodeMutationResult) (control.RPCResponse, error) {
	if generation == 0 {
		return control.RPCResponse{}, fmt.Errorf("result generation must be positive")
	}
	if !validMutationStatus(result.Status) {
		return control.RPCResponse{}, fmt.Errorf("result status is invalid")
	}
	response := result.Response
	if response.SchemaVersion == 0 {
		response.SchemaVersion = control.RPCSchemaVersion
	}
	response.ProtocolMajor = request.ProtocolMajor
	response.ProtocolMinor = request.ProtocolMinor
	response.AuthoritativeGeneration = generation
	response.ResourceIDs = copyStringMap(response.ResourceIDs)
	response.Warnings = copyStrings(response.Warnings)
	response.RequiresAction = copyStrings(response.RequiresAction)
	response.Data = append(json.RawMessage(nil), response.Data...)
	if response.ResourceIDs == nil {
		response.ResourceIDs = map[string]string{}
	}
	if response.Warnings == nil {
		response.Warnings = []string{}
	}
	if response.RequiresAction == nil {
		response.RequiresAction = []string{}
	}
	if len(response.Data) == 0 {
		response.Data = json.RawMessage(`{}`)
	}
	if result.Status == model.ResultFailed && response.Category == "success" {
		return control.RPCResponse{}, fmt.Errorf("failed result cannot use success category")
	}
	if result.Status != model.ResultFailed && response.Category != "success" {
		return control.RPCResponse{}, fmt.Errorf("non-failed result must use success category")
	}
	response.ResultHash = ""
	if err := response.Validate(); err != nil {
		return control.RPCResponse{}, err
	}
	hash, err := mutationResultHash(result.Status, response)
	if err != nil {
		return control.RPCResponse{}, err
	}
	response.ResultHash = hash
	if err := response.Validate(); err != nil {
		return control.RPCResponse{}, err
	}
	return response, nil
}

func mutationResultHash(status model.ResultStatus, response control.RPCResponse) (string, error) {
	material := struct {
		Status         model.ResultStatus `json:"result_status"`
		Category       string             `json:"category"`
		ResourceIDs    map[string]string  `json:"resource_ids"`
		Warnings       []string           `json:"warnings"`
		RequiresAction []string           `json:"requires_action"`
		ErrorCode      string             `json:"error_code,omitempty"`
		Message        string             `json:"message,omitempty"`
		Data           json.RawMessage    `json:"data"`
	}{
		Status: status, Category: response.Category, ResourceIDs: response.ResourceIDs,
		Warnings: response.Warnings, RequiresAction: response.RequiresAction,
		ErrorCode: response.ErrorCode, Message: response.Message, Data: response.Data,
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return "", fmt.Errorf("encode mutation result hash material: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func storedMutationResult(request control.RPCRequest, record model.IdempotencyRecord) control.RPCHandlerResult {
	data, _ := json.Marshal(struct {
		Replayed     bool               `json:"replayed"`
		ResultStatus model.ResultStatus `json:"result_status"`
	}{Replayed: true, ResultStatus: record.ResultStatus})
	category := "success"
	statusCode := http.StatusOK
	response := control.NewRPCResponse(category, record.StateGeneration, data)
	if record.ResultStatus == model.ResultFailed {
		statusCode = http.StatusInternalServerError
		response = control.NewRPCResponse("internal", record.StateGeneration, data)
		response.ErrorCode = "stored_failure"
		response.Message = "the retained mutation result is failed"
	}
	response.ProtocolMajor = request.ProtocolMajor
	response.ProtocolMinor = request.ProtocolMinor
	response.ResultHash = record.ResultHash
	return control.RPCHandlerResult{StatusCode: statusCode, Response: response}
}

func mutationFailure(request control.RPCRequest, statusCode int, category string, generation uint64, code, message string) control.RPCHandlerResult {
	response := control.NewRPCResponse(category, generation, json.RawMessage(`{}`))
	response.ProtocolMajor = request.ProtocolMajor
	response.ProtocolMinor = request.ProtocolMinor
	response.ErrorCode = code
	response.Message = message
	return control.RPCHandlerResult{StatusCode: statusCode, Response: response}
}

func mutationHTTPStatus(category string) int {
	switch category {
	case "success":
		return http.StatusOK
	case "validation":
		return http.StatusUnprocessableEntity
	case "conflict":
		return http.StatusConflict
	case "unavailable":
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func nodeIndexByID(state model.State, nodeID string) int {
	for index := range state.Nodes {
		if state.Nodes[index].ID == nodeID {
			return index
		}
	}
	return -1
}

func validNodeMutationOperation(operation model.OperationType) bool {
	switch operation {
	case model.OperationInit, model.OperationJoin, model.OperationApply, model.OperationRepair, model.OperationRotate,
		model.OperationRevoke, model.OperationDelete, model.OperationTransportSwitch, model.OperationExposeCreate,
		model.OperationExposeRemove, model.OperationCertificateRotate, model.OperationTrustRotate, model.OperationRestore,
		model.OperationUpdate, model.OperationUninstall, model.OperationPurge:
		return true
	default:
		return false
	}
}

func validMutationStatus(status model.ResultStatus) bool {
	return status == model.ResultOK || status == model.ResultPending || status == model.ResultDegraded || status == model.ResultFailed
}

func copyStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func copyStrings(source []string) []string {
	if source == nil {
		return nil
	}
	return append([]string(nil), source...)
}
