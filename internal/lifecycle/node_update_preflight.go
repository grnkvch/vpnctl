package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

const NodeUpdatePreflightOperation = "update.preflight"

type NodeUpdatePreflightStatus string

const (
	NodeUpdateReady        NodeUpdatePreflightStatus = "ready"
	NodeUpdateUnavailable  NodeUpdatePreflightStatus = "unavailable"
	NodeUpdateIncompatible NodeUpdatePreflightStatus = "incompatible"
	NodeUpdateBlocked      NodeUpdatePreflightStatus = "blocked"
)

type NodeUpdatePreflightPayload struct {
	TargetManifest model.ComponentManifest `json:"target_manifest"`
}

type NodeUpdateCompatibility struct {
	Compatible              bool     `json:"compatible"`
	GatewayVPNCTLVersion    string   `json:"gateway_vpnctl_version"`
	GatewayControlProtocols []string `json:"gateway_control_protocols"`
	SelectedProtocol        string   `json:"selected_protocol,omitempty"`
}

type NodeUpdatePreflightPlan struct {
	Status                  NodeUpdatePreflightStatus
	Code                    string
	Message                 string
	RequiresAction          []string
	TargetVPNCTLVersion     string
	GatewayVPNCTLVersion    string
	SelectedProtocol        string
	AuthoritativeGeneration uint64
}

type NodeUpdateGatewayStateReader interface {
	Load() (model.State, error)
}

type NodeUpdateGatewayCaller interface {
	CallManagement(context.Context, control.RPCRequest) (control.RPCCallResult, error)
}

type NodeUpdatePreflightRuntime struct {
	State   NodeUpdateGatewayStateReader
	Gateway NodeUpdateGatewayCaller
	Now     func() time.Time
	NewUUID model.UUIDGenerator
	Entropy io.Reader
}

type NodeUpdatePreflighter struct {
	runtime NodeUpdatePreflightRuntime
}

type GatewayNodeUpdatePreflightHandler struct {
	state NodeUpdateGatewayStateReader
}

func NewNodeUpdatePreflighter(runtime NodeUpdatePreflightRuntime) (*NodeUpdatePreflighter, error) {
	if runtime.State == nil || runtime.Gateway == nil {
		return nil, fmt.Errorf("node update preflight dependencies are incomplete")
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	if runtime.NewUUID == nil {
		runtime.NewUUID = model.NewUUID
	}
	if runtime.Entropy == nil {
		runtime.Entropy = rand.Reader
	}
	return &NodeUpdatePreflighter{runtime: runtime}, nil
}

func NewGatewayNodeUpdatePreflightHandler(state NodeUpdateGatewayStateReader) (*GatewayNodeUpdatePreflightHandler, error) {
	if state == nil {
		return nil, fmt.Errorf("gateway state reader is required")
	}
	return &GatewayNodeUpdatePreflightHandler{state: state}, nil
}

// Preflight is deliberately read-only: it validates the target against local
// state, makes one short-lived management call, and returns a plan. It has no
// installer, state writer, service manager, or data-plane dependency to invoke.
func (preflighter *NodeUpdatePreflighter) Preflight(ctx context.Context, target model.ComponentManifest) (NodeUpdatePreflightPlan, error) {
	if ctx == nil {
		return NodeUpdatePreflightPlan{}, fmt.Errorf("context is required")
	}
	if preflighter == nil || preflighter.runtime.State == nil || preflighter.runtime.Gateway == nil || preflighter.runtime.NewUUID == nil || preflighter.runtime.Entropy == nil {
		return NodeUpdatePreflightPlan{}, fmt.Errorf("node update preflighter is incomplete")
	}
	if err := target.Validate(); err != nil {
		return NodeUpdatePreflightPlan{}, fmt.Errorf("validate target component manifest: %w", err)
	}
	state, err := preflighter.runtime.State.Load()
	if err != nil {
		return NodeUpdatePreflightPlan{}, fmt.Errorf("load local node state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return NodeUpdatePreflightPlan{}, fmt.Errorf("validate local node state: %w", err)
	}
	if state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Gateway == nil || state.Nodes[0].Lifecycle != model.LifecycleActive {
		return NodeUpdatePreflightPlan{}, fmt.Errorf("node update preflight requires one active enrolled node")
	}
	plan := NodeUpdatePreflightPlan{TargetVPNCTLVersion: target.VPNCTLVersion, RequiresAction: []string{}}
	if state.SchemaVersion < target.StateSchemaMinimum || state.SchemaVersion > target.StateSchemaMaximum {
		plan.Status, plan.Code = NodeUpdateBlocked, "target_state_schema_incompatible"
		plan.Message = "the target release cannot read the current local state schema"
		plan.RequiresAction = []string{"select a release supporting the current state schema before updating"}
		return plan, nil
	}
	node := state.Nodes[0]
	if node.Gateway.PendingRequestID != "" {
		plan.Status, plan.Code = NodeUpdateBlocked, "management_request_pending"
		plan.Message = "a prior node management request still has an uncertain result"
		plan.RequiresAction = []string{"reconcile the retained management request before updating"}
		return plan, nil
	}
	requestVersion, err := control.ParseRPCProtocolVersion(state.Components.ControlProtocols[0])
	if err != nil {
		return NodeUpdatePreflightPlan{}, fmt.Errorf("parse installed node control protocol: %w", err)
	}
	requestID, err := model.AllocateUUID(nodeUpdatePreflightOccupiedIDs(state), preflighter.runtime.NewUUID)
	if err != nil {
		return NodeUpdatePreflightPlan{}, fmt.Errorf("allocate update preflight request ID: %w", err)
	}
	nonce := make([]byte, control.RPCNonceBytes)
	if _, err := io.ReadFull(preflighter.runtime.Entropy, nonce); err != nil {
		return NodeUpdatePreflightPlan{}, fmt.Errorf("generate update preflight nonce: %w", err)
	}
	payload, err := json.Marshal(NodeUpdatePreflightPayload{TargetManifest: target})
	if err != nil {
		return NodeUpdatePreflightPlan{}, fmt.Errorf("encode update preflight payload: %w", err)
	}
	request := control.RPCRequest{
		ProtocolMajor: requestVersion.Major, ProtocolMinor: requestVersion.Minor, RequestID: requestID,
		ExpectedStateGeneration: node.Gateway.LastKnownGatewayGeneration, NodeID: node.ID, CredentialGeneration: node.CredentialGeneration,
		Timestamp: preflighter.runtime.Now().UTC(), Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		Operation: NodeUpdatePreflightOperation, Payload: payload,
	}
	result, err := preflighter.runtime.Gateway.CallManagement(ctx, request)
	if err != nil {
		return NodeUpdatePreflightPlan{}, fmt.Errorf("perform node update preflight: %w", err)
	}
	plan.AuthoritativeGeneration = result.Response.AuthoritativeGeneration
	plan.Code, plan.Message = result.Response.ErrorCode, result.Response.Message
	plan.RequiresAction = append([]string(nil), result.Response.RequiresAction...)
	switch result.Response.Category {
	case "success":
		if result.StatusCode != http.StatusOK {
			return NodeUpdatePreflightPlan{}, fmt.Errorf("successful update preflight returned HTTP %d", result.StatusCode)
		}
		var compatibility NodeUpdateCompatibility
		if err := control.DecodeRPCPayload(result.Response.Data, &compatibility); err != nil {
			return NodeUpdatePreflightPlan{}, fmt.Errorf("decode update preflight result: %w", err)
		}
		if !compatibility.Compatible || compatibility.GatewayVPNCTLVersion == "" || compatibility.SelectedProtocol == "" {
			return NodeUpdatePreflightPlan{}, fmt.Errorf("gateway returned an incomplete compatible update preflight")
		}
		plan.Status, plan.Code, plan.Message = NodeUpdateReady, "", ""
		plan.GatewayVPNCTLVersion = compatibility.GatewayVPNCTLVersion
		plan.SelectedProtocol = compatibility.SelectedProtocol
		return plan, nil
	case "unavailable":
		plan.Status = NodeUpdateUnavailable
		return plan, nil
	case "conflict":
		plan.Status = NodeUpdateIncompatible
		return plan, nil
	default:
		plan.Status = NodeUpdateBlocked
		return plan, nil
	}
}

func (handler *GatewayNodeUpdatePreflightHandler) HandleRPC(_ context.Context, _ control.RPCPeer, request control.RPCRequest) (control.RPCHandlerResult, error) {
	if handler == nil || handler.state == nil {
		return control.RPCHandlerResult{}, fmt.Errorf("gateway update preflight handler is incomplete")
	}
	if request.Operation != NodeUpdatePreflightOperation {
		return updatePreflightFailure(request, http.StatusUnprocessableEntity, "validation", 0, "invalid_operation", "the handler accepts only node update preflight"), nil
	}
	var payload NodeUpdatePreflightPayload
	if err := control.DecodeRPCPayload(request.Payload, &payload); err != nil {
		return updatePreflightFailure(request, http.StatusUnprocessableEntity, "validation", 0, "invalid_target_manifest", "the target release manifest is invalid"), nil
	}
	if err := payload.TargetManifest.Validate(); err != nil {
		return updatePreflightFailure(request, http.StatusUnprocessableEntity, "validation", 0, "invalid_target_manifest", "the target release manifest is invalid"), nil
	}
	state, err := handler.state.Load()
	if err != nil {
		return updatePreflightFailure(request, http.StatusServiceUnavailable, "unavailable", 0, "controller_state_unavailable", "authoritative gateway compatibility state is unavailable"), nil
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return updatePreflightFailure(request, http.StatusServiceUnavailable, "unavailable", 0, "controller_state_unavailable", "authoritative gateway compatibility state is unavailable"), nil
	}
	compatibility, code, message, err := EvaluateNodeUpdateCompatibility(state.Components, payload.TargetManifest)
	if err != nil {
		return control.RPCHandlerResult{}, err
	}
	if !compatibility.Compatible {
		result := updatePreflightFailure(request, http.StatusConflict, "conflict", state.Generation, code, message)
		result.Response.RequiresAction = []string{"update the gateway to a compatible release before updating this node"}
		for _, protocol := range compatibility.GatewayControlProtocols {
			result.Response.Warnings = append(result.Response.Warnings, "gateway-supported:"+protocol)
		}
		return result, nil
	}
	data, err := json.Marshal(compatibility)
	if err != nil {
		return control.RPCHandlerResult{}, fmt.Errorf("encode node update compatibility: %w", err)
	}
	response := control.NewRPCResponse("success", state.Generation, data)
	response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
	return control.RPCHandlerResult{StatusCode: http.StatusOK, Response: response}, nil
}

func EvaluateNodeUpdateCompatibility(gateway, target model.ComponentManifest) (NodeUpdateCompatibility, string, string, error) {
	if err := gateway.Validate(); err != nil {
		return NodeUpdateCompatibility{}, "", "", fmt.Errorf("validate gateway component manifest: %w", err)
	}
	if err := target.Validate(); err != nil {
		return NodeUpdateCompatibility{}, "", "", fmt.Errorf("validate target component manifest: %w", err)
	}
	compatibility := NodeUpdateCompatibility{
		GatewayVPNCTLVersion:    gateway.VPNCTLVersion,
		GatewayControlProtocols: append([]string(nil), gateway.ControlProtocols...),
	}
	gatewayCurrent, _ := control.ParseRPCProtocolVersion(gateway.ControlProtocols[0])
	targetCurrent, _ := control.ParseRPCProtocolVersion(target.ControlProtocols[0])
	if compareProtocolVersions(targetCurrent, gatewayCurrent) > 0 {
		return compatibility, "node_newer_than_gateway", "the target node control protocol is newer than the gateway", nil
	}
	selected, found := mutuallySupportedProtocol(gateway.ControlProtocols, target.ControlProtocols)
	if !found {
		return compatibility, "no_mutual_control_protocol", "the target node release has no control protocol supported by the gateway", nil
	}
	compatibility.Compatible = true
	compatibility.SelectedProtocol = selected.String()
	return compatibility, "", "", nil
}

func mutuallySupportedProtocol(gateway, target []string) (control.RPCProtocolVersion, bool) {
	var selected control.RPCProtocolVersion
	found := false
	for _, gatewayText := range gateway {
		gatewayVersion, err := control.ParseRPCProtocolVersion(gatewayText)
		if err != nil {
			continue
		}
		for _, targetText := range target {
			targetVersion, err := control.ParseRPCProtocolVersion(targetText)
			if err != nil || gatewayVersion.Major != targetVersion.Major {
				continue
			}
			candidate := control.RPCProtocolVersion{Major: gatewayVersion.Major, Minor: min(gatewayVersion.Minor, targetVersion.Minor)}
			if !found || compareProtocolVersions(candidate, selected) > 0 {
				selected, found = candidate, true
			}
		}
	}
	return selected, found
}

func compareProtocolVersions(left, right control.RPCProtocolVersion) int {
	if left.Major != right.Major {
		if left.Major < right.Major {
			return -1
		}
		return 1
	}
	if left.Minor < right.Minor {
		return -1
	}
	if left.Minor > right.Minor {
		return 1
	}
	return 0
}

func updatePreflightFailure(request control.RPCRequest, status int, category string, generation uint64, code, message string) control.RPCHandlerResult {
	response := control.NewRPCResponse(category, generation, json.RawMessage(`{}`))
	response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
	response.ErrorCode, response.Message = code, message
	return control.RPCHandlerResult{StatusCode: status, Response: response}
}

func nodeUpdatePreflightOccupiedIDs(state model.State) map[string]struct{} {
	occupied := map[string]struct{}{state.Host.ID: {}}
	for _, node := range state.Nodes {
		occupied[node.ID] = struct{}{}
		for _, record := range node.IdempotencyRecords {
			occupied[record.RequestID] = struct{}{}
		}
	}
	for _, operation := range state.Operations {
		occupied[operation.ID] = struct{}{}
		if operation.RequestID != "" {
			occupied[operation.RequestID] = struct{}{}
		}
	}
	return occupied
}
