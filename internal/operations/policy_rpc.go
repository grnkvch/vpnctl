package operations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	PolicyPlanRPCOperation   = "policy.plan"
	PolicyCommitRPCOperation = "policy.commit"
)

var ErrPolicyGatewayUnavailable = errors.New("policy gateway is unavailable")

type policyRPCRequest struct {
	Command     routing.PolicyCommand `json:"command"`
	PresetNames []string              `json:"preset_names"`
	Deferred    bool                  `json:"deferred"`
	Fingerprint string                `json:"fingerprint,omitempty"`
}

type policyDesiredWire struct {
	TargetKind              model.TargetKind `json:"target_kind"`
	TargetID                string           `json:"target_id"`
	PresetNames             []string         `json:"preset_names"`
	Selectors               []model.Selector `json:"selectors"`
	EffectiveHash           string           `json:"effective_hash"`
	GatewayPolicyGeneration uint64           `json:"gateway_policy_generation"`
	GatewayStateGeneration  uint64           `json:"gateway_state_generation"`
}

type policyPlanWire struct {
	Command                 routing.PolicyCommand `json:"command"`
	TargetID                string                `json:"target_id"`
	TargetName              string                `json:"target_name"`
	PreviousPresetNames     []string              `json:"previous_preset_names"`
	PresetNames             []string              `json:"preset_names"`
	ExpectedStateGeneration uint64                `json:"expected_state_generation"`
	NextStateGeneration     uint64                `json:"next_state_generation"`
	Changed                 bool                  `json:"changed"`
	Deferred                bool                  `json:"deferred"`
	Desired                 policyDesiredWire     `json:"desired"`
	Fingerprint             string                `json:"fingerprint"`
}

type policyCommitWire struct {
	Command         routing.PolicyCommand `json:"command"`
	Changed         bool                  `json:"changed"`
	Pending         bool                  `json:"pending"`
	OperationID     string                `json:"operation_id,omitempty"`
	StateGeneration uint64                `json:"state_generation"`
	Desired         policyDesiredWire     `json:"desired"`
}

type RemotePolicyPlan struct {
	Command                 routing.PolicyCommand
	TargetID                string
	TargetName              string
	PreviousPresetNames     []string
	PresetNames             []string
	ExpectedStateGeneration uint64
	NextStateGeneration     uint64
	Changed                 bool
	Deferred                bool
	Desired                 routing.DesiredPolicy
	Fingerprint             string
}

func desiredPolicyToWire(desired routing.DesiredPolicy) policyDesiredWire {
	return policyDesiredWire{
		TargetKind: desired.TargetKind, TargetID: desired.TargetID,
		PresetNames: append([]string{}, desired.PresetNames...), Selectors: append([]model.Selector{}, desired.Selectors...),
		EffectiveHash: desired.EffectiveHash, GatewayPolicyGeneration: desired.GatewayPolicyGeneration,
		GatewayStateGeneration: desired.GatewayStateGeneration,
	}
}

func (wire policyDesiredWire) domain() routing.DesiredPolicy {
	return routing.DesiredPolicy{
		TargetKind: wire.TargetKind, TargetID: wire.TargetID,
		PresetNames: append([]string{}, wire.PresetNames...), Selectors: append([]model.Selector{}, wire.Selectors...),
		EffectiveHash: wire.EffectiveHash, GatewayPolicyGeneration: wire.GatewayPolicyGeneration,
		GatewayStateGeneration: wire.GatewayStateGeneration,
	}
}

func policyPlanToWire(plan routing.PolicyReplacementPlan) (policyPlanWire, error) {
	fingerprint, err := plan.Fingerprint()
	if err != nil {
		return policyPlanWire{}, err
	}
	return policyPlanWire{
		Command: plan.Command, TargetID: plan.TargetID, TargetName: plan.TargetName,
		PreviousPresetNames: append([]string{}, plan.PreviousPresetNames...), PresetNames: append([]string{}, plan.PresetNames...),
		ExpectedStateGeneration: plan.ExpectedStateGeneration, NextStateGeneration: plan.NextStateGeneration,
		Changed: plan.Changed, Deferred: plan.Deferred, Desired: desiredPolicyToWire(plan.Desired), Fingerprint: fingerprint,
	}, nil
}

func (wire policyPlanWire) remote() (RemotePolicyPlan, error) {
	plan := RemotePolicyPlan{
		Command: wire.Command, TargetID: wire.TargetID, TargetName: wire.TargetName,
		PreviousPresetNames: append([]string{}, wire.PreviousPresetNames...), PresetNames: append([]string{}, wire.PresetNames...),
		ExpectedStateGeneration: wire.ExpectedStateGeneration, NextStateGeneration: wire.NextStateGeneration,
		Changed: wire.Changed, Deferred: wire.Deferred, Desired: wire.Desired.domain(), Fingerprint: wire.Fingerprint,
	}
	if err := plan.Validate(); err != nil {
		return RemotePolicyPlan{}, err
	}
	return plan, nil
}

func (plan RemotePolicyPlan) Validate() error {
	if (plan.Command != routing.PolicySet && plan.Command != routing.PolicyClear) || model.ValidateResourceID(plan.TargetID) != nil ||
		plan.TargetName == "" || plan.PresetNames == nil || plan.PreviousPresetNames == nil ||
		plan.ExpectedStateGeneration == 0 || plan.NextStateGeneration == 0 || len(plan.Fingerprint) != sha256.Size*2 {
		return fmt.Errorf("remote policy plan is invalid")
	}
	if decoded, err := hex.DecodeString(plan.Fingerprint); err != nil || hex.EncodeToString(decoded) != plan.Fingerprint {
		return fmt.Errorf("remote policy plan fingerprint is invalid")
	}
	if plan.Command == routing.PolicySet && len(plan.PresetNames) == 0 {
		return routing.ErrPolicyEmptySet
	}
	if plan.Command == routing.PolicyClear && len(plan.PresetNames) != 0 {
		return fmt.Errorf("remote clear policy contains presets")
	}
	if plan.Desired.TargetKind != model.TargetNode || plan.Desired.TargetID != plan.TargetID ||
		plan.Desired.PresetNames == nil || plan.Desired.Selectors == nil ||
		plan.Desired.GatewayStateGeneration != plan.NextStateGeneration {
		return fmt.Errorf("remote policy desired state is invalid")
	}
	wantNext := plan.ExpectedStateGeneration
	if plan.Changed || plan.Deferred {
		var err error
		wantNext, err = model.NextGeneration(wantNext)
		if err != nil {
			return err
		}
	}
	if wantNext != plan.NextStateGeneration {
		return fmt.Errorf("remote policy generations are inconsistent")
	}
	return routing.ValidateDesiredNodePolicy(plan.Desired)
}

type PolicyGatewayRPCCaller interface {
	CallManagement(context.Context, control.RPCRequest) (control.RPCCallResult, error)
}

type RemotePolicyGateway struct {
	caller               PolicyGatewayRPCCaller
	protocol             control.RPCProtocolVersion
	nodeID               string
	credentialGeneration uint64
	lastKnownGeneration  uint64
	now                  func() time.Time
	newUUID              model.UUIDGenerator
	entropy              io.Reader
}

func NewRemotePolicyGateway(caller PolicyGatewayRPCCaller, protocol control.RPCProtocolVersion, nodeID string,
	credentialGeneration, lastKnownGeneration uint64, now func() time.Time, newUUID model.UUIDGenerator, entropy io.Reader,
) (*RemotePolicyGateway, error) {
	if caller == nil || protocol.Major < 1 || protocol.Minor < 0 || model.ValidateResourceID(nodeID) != nil ||
		credentialGeneration == 0 || lastKnownGeneration == 0 {
		return nil, fmt.Errorf("remote policy gateway identity is invalid")
	}
	if now == nil {
		now = time.Now
	}
	if newUUID == nil {
		newUUID = model.NewUUID
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return &RemotePolicyGateway{
		caller: caller, protocol: protocol, nodeID: nodeID, credentialGeneration: credentialGeneration,
		lastKnownGeneration: lastKnownGeneration, now: now, newUUID: newUUID, entropy: entropy,
	}, nil
}

func NewSystemRemotePolicyGateway(paths store.Paths, now func() time.Time) (*RemotePolicyGateway, error) {
	identity, err := control.NewSystemNodeClient(paths, now)
	if err != nil {
		return nil, err
	}
	return NewRemotePolicyGateway(identity.Client, identity.Protocol, identity.NodeID, identity.CredentialGeneration,
		identity.LastKnownGeneration, now, nil, nil)
}

func (client *RemotePolicyGateway) Plan(ctx context.Context, command routing.PolicyCommand, presets []string, deferred bool) (RemotePolicyPlan, error) {
	var response policyPlanWire
	generation, err := client.call(ctx, PolicyPlanRPCOperation, client.lastKnownGeneration, policyRPCRequest{
		Command: command, PresetNames: append([]string{}, presets...), Deferred: deferred,
	}, &response)
	if err != nil {
		return RemotePolicyPlan{}, err
	}
	plan, err := response.remote()
	if err != nil || generation != plan.ExpectedStateGeneration {
		return RemotePolicyPlan{}, fmt.Errorf("gateway returned an invalid policy plan")
	}
	return plan, nil
}

func (client *RemotePolicyGateway) Commit(ctx context.Context, plan RemotePolicyPlan) (routing.PolicyCommitResult, error) {
	if err := plan.Validate(); err != nil {
		return routing.PolicyCommitResult{}, err
	}
	var response policyCommitWire
	generation, err := client.call(ctx, PolicyCommitRPCOperation, plan.ExpectedStateGeneration, policyRPCRequest{
		Command: plan.Command, PresetNames: append([]string{}, plan.PresetNames...), Deferred: plan.Deferred, Fingerprint: plan.Fingerprint,
	}, &response)
	if err != nil {
		return routing.PolicyCommitResult{}, err
	}
	result := routing.PolicyCommitResult{
		Command: response.Command, Changed: response.Changed, Pending: response.Pending,
		OperationID: response.OperationID, StateGeneration: response.StateGeneration, Desired: response.Desired.domain(),
	}
	if result.Command != plan.Command || result.StateGeneration != generation || result.Desired.TargetID != plan.TargetID ||
		result.Desired.GatewayStateGeneration != generation || result.Pending != plan.Deferred ||
		(result.Pending && model.ValidateResourceID(result.OperationID) != nil) || (!result.Pending && result.OperationID != "") {
		return routing.PolicyCommitResult{}, fmt.Errorf("gateway returned an invalid policy commit result")
	}
	return result, nil
}

func (client *RemotePolicyGateway) call(ctx context.Context, operation string, expected uint64, payload any, destination any) (uint64, error) {
	if ctx == nil || client == nil || client.caller == nil || client.now == nil || client.newUUID == nil || client.entropy == nil {
		return 0, fmt.Errorf("remote policy gateway is incomplete")
	}
	requestID, err := client.newUUID()
	if err != nil || model.ValidateResourceID(requestID) != nil {
		return 0, fmt.Errorf("allocate policy RPC request identity")
	}
	nonce := make([]byte, control.RPCNonceBytes)
	if _, err := io.ReadFull(client.entropy, nonce); err != nil {
		return 0, fmt.Errorf("generate policy RPC nonce: %w", err)
	}
	defer clearPolicyRPCSecret(nonce)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	call, err := client.caller.CallManagement(ctx, control.RPCRequest{
		ProtocolMajor: client.protocol.Major, ProtocolMinor: client.protocol.Minor,
		RequestID: requestID, ExpectedStateGeneration: expected, NodeID: client.nodeID,
		CredentialGeneration: client.credentialGeneration, Timestamp: client.now().UTC(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Operation: operation, Payload: encoded,
	})
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrPolicyGatewayUnavailable, err)
	}
	if call.StatusCode != http.StatusOK || call.Response.Category != "success" {
		switch call.Response.Category {
		case "conflict":
			return 0, routing.ErrPolicyStalePlan
		case "unavailable":
			return 0, ErrPolicyGatewayUnavailable
		case "validation":
			return 0, errors.New("gateway rejected the policy request")
		default:
			return 0, errors.New("gateway policy request failed")
		}
	}
	if call.Response.AuthoritativeGeneration == 0 {
		return 0, errors.New("gateway policy response has no authoritative generation")
	}
	if err := control.DecodeRPCPayload(call.Response.Data, destination); err != nil {
		return 0, err
	}
	return call.Response.AuthoritativeGeneration, nil
}

type PolicyGatewayRPCHandler struct {
	locker  sync.Locker
	manager *routing.PolicyManager
	state   PolicyRPCStateStore
}

type PolicyRPCStateStore interface {
	Load() (model.State, error)
}

func NewPolicyGatewayRPCHandler(locker sync.Locker, manager *routing.PolicyManager, state PolicyRPCStateStore) (*PolicyGatewayRPCHandler, error) {
	if locker == nil || manager == nil || state == nil {
		return nil, fmt.Errorf("gateway policy RPC dependencies are incomplete")
	}
	return &PolicyGatewayRPCHandler{locker: locker, manager: manager, state: state}, nil
}

func (handler *PolicyGatewayRPCHandler) HandleRPC(ctx context.Context, peer control.RPCPeer, request control.RPCRequest) (control.RPCHandlerResult, error) {
	if ctx == nil || handler == nil || handler.locker == nil || handler.manager == nil {
		return control.RPCHandlerResult{}, fmt.Errorf("gateway policy RPC handler is incomplete")
	}
	if peer.NodeID == "" || peer.NodeID != request.NodeID {
		return policyRPCFailure(request, http.StatusForbidden, "validation", 0, "identity_mismatch", "the certificate and request node identities differ"), nil
	}
	handler.locker.Lock()
	defer handler.locker.Unlock()
	if err := ctx.Err(); err != nil {
		return policyRPCFailure(request, http.StatusServiceUnavailable, "unavailable", handler.currentGeneration(), "request_cancelled", "the policy request was cancelled"), nil
	}
	var payload policyRPCRequest
	if control.DecodeRPCPayload(request.Payload, &payload) != nil || payload.PresetNames == nil {
		return policyRPCFailure(request, http.StatusUnprocessableEntity, "validation", handler.currentGeneration(), "invalid_payload", "the policy payload is invalid"), nil
	}
	plan, err := handler.plan(request.NodeID, payload)
	if err != nil {
		if request.Operation == PolicyCommitRPCOperation && payload.Fingerprint != "" {
			return policyRPCFailure(request, http.StatusConflict, "conflict", handler.currentGeneration(), "stale_policy_plan", "the policy plan no longer matches authoritative state"), nil
		}
		return handler.failure(request, err), nil
	}
	switch request.Operation {
	case PolicyPlanRPCOperation:
		if payload.Fingerprint != "" {
			return policyRPCFailure(request, http.StatusUnprocessableEntity, "validation", handler.currentGeneration(), "invalid_payload", "the policy plan payload contains a fingerprint"), nil
		}
		wire, err := policyPlanToWire(plan)
		if err != nil {
			return handler.failure(request, err), nil
		}
		return policyRPCSuccess(request, plan.ExpectedStateGeneration, plan.TargetID, wire)
	case PolicyCommitRPCOperation:
		fingerprint, fingerprintErr := plan.Fingerprint()
		if fingerprintErr != nil || payload.Fingerprint == "" || payload.Fingerprint != fingerprint || request.ExpectedStateGeneration != plan.ExpectedStateGeneration {
			return policyRPCFailure(request, http.StatusConflict, "conflict", handler.currentGeneration(), "stale_policy_plan", "the policy plan no longer matches authoritative state"), nil
		}
		result, err := handler.manager.Commit(plan)
		if err != nil {
			return handler.failure(request, err), nil
		}
		wire := policyCommitWire{
			Command: result.Command, Changed: result.Changed, Pending: result.Pending,
			OperationID: result.OperationID, StateGeneration: result.StateGeneration, Desired: desiredPolicyToWire(result.Desired),
		}
		return policyRPCSuccess(request, result.StateGeneration, plan.TargetID, wire)
	default:
		return policyRPCFailure(request, http.StatusUnprocessableEntity, "validation", handler.currentGeneration(), "invalid_operation", "the handler accepts only policy operations"), nil
	}
}

func (handler *PolicyGatewayRPCHandler) plan(nodeID string, payload policyRPCRequest) (routing.PolicyReplacementPlan, error) {
	switch payload.Command {
	case routing.PolicySet:
		return handler.manager.PlanCurrentNodeSet(nodeID, payload.PresetNames, payload.Deferred)
	case routing.PolicyClear:
		return handler.manager.PlanCurrentNodeClear(nodeID, payload.Deferred)
	default:
		return routing.PolicyReplacementPlan{}, fmt.Errorf("unsupported policy command")
	}
}

func (handler *PolicyGatewayRPCHandler) currentGeneration() uint64 {
	if handler == nil || handler.state == nil {
		return 0
	}
	state, err := handler.state.Load()
	if err != nil {
		return 0
	}
	return state.Generation
}

func (handler *PolicyGatewayRPCHandler) failure(request control.RPCRequest, err error) control.RPCHandlerResult {
	generation := handler.currentGeneration()
	switch {
	case errors.Is(err, routing.ErrPolicyStalePlan), errors.Is(err, store.ErrStateConflict):
		return policyRPCFailure(request, http.StatusConflict, "conflict", generation, "policy_conflict", "the policy conflicts with authoritative state")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return policyRPCFailure(request, http.StatusServiceUnavailable, "unavailable", generation, "policy_unavailable", "the policy operation did not finish before its deadline")
	case errors.Is(err, routing.ErrPolicyTargetNotFound), errors.Is(err, routing.ErrPolicyTargetInactive), errors.Is(err, routing.ErrPolicyEmptySet),
		errors.Is(err, routing.ErrPolicyUnknownPreset), errors.Is(err, routing.ErrPolicyInvalidPreset):
		return policyRPCFailure(request, http.StatusUnprocessableEntity, "validation", generation, "policy_validation", "the policy request is invalid")
	default:
		return policyRPCFailure(request, http.StatusInternalServerError, "internal", generation, "policy_failed", "the gateway could not complete the policy operation")
	}
}

func policyRPCSuccess(request control.RPCRequest, generation uint64, targetID string, payload any) (control.RPCHandlerResult, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return control.RPCHandlerResult{}, err
	}
	response := control.NewRPCResponse("success", generation, encoded)
	response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
	response.ResourceIDs["node_id"] = targetID
	return control.RPCHandlerResult{StatusCode: http.StatusOK, Response: response}, nil
}

func policyRPCFailure(request control.RPCRequest, status int, category string, generation uint64, code, message string) control.RPCHandlerResult {
	response := control.NewRPCResponse(category, generation, json.RawMessage(`{}`))
	response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
	response.ErrorCode, response.Message = code, message
	return control.RPCHandlerResult{StatusCode: status, Response: response}
}

func clearPolicyRPCSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ control.RPCHandler = (*PolicyGatewayRPCHandler)(nil)
