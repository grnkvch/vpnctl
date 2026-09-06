package operations

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const RepairProbeRPCOperation = "repair.probe"

type repairProbePayload struct{}

type repairProbeData struct {
	Reachable bool   `json:"reachable"`
	NodeID    string `json:"node_id"`
}

type RepairProbeRPCCaller interface {
	CallManagement(context.Context, control.RPCRequest) (control.RPCCallResult, error)
}

// RemoteRepairGatewayProbe proves that the current node can authenticate to
// the authoritative gateway immediately before local repair. It never queues
// work and never changes either gateway or node state.
type RemoteRepairGatewayProbe struct {
	caller               RepairProbeRPCCaller
	protocol             control.RPCProtocolVersion
	nodeID               string
	credentialGeneration uint64
	now                  func() time.Time
	newUUID              model.UUIDGenerator
	entropy              io.Reader
}

func NewRemoteRepairGatewayProbe(
	caller RepairProbeRPCCaller,
	protocol control.RPCProtocolVersion,
	nodeID string,
	credentialGeneration uint64,
	now func() time.Time,
	newUUID model.UUIDGenerator,
	entropy io.Reader,
) (*RemoteRepairGatewayProbe, error) {
	if caller == nil || protocol.Major < 1 || protocol.Minor < 0 ||
		model.ValidateResourceID(nodeID) != nil || credentialGeneration == 0 {
		return nil, fmt.Errorf("remote repair gateway identity is invalid")
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
	return &RemoteRepairGatewayProbe{
		caller: caller, protocol: protocol, nodeID: nodeID,
		credentialGeneration: credentialGeneration, now: now, newUUID: newUUID, entropy: entropy,
	}, nil
}

func NewSystemRemoteRepairGatewayProbe(paths store.Paths, now func() time.Time) (*RemoteRepairGatewayProbe, error) {
	identity, err := control.NewSystemNodeClient(paths, now)
	if err != nil {
		return nil, err
	}
	return NewRemoteRepairGatewayProbe(
		identity.Client, identity.Protocol, identity.NodeID, identity.CredentialGeneration, now, nil, nil,
	)
}

func (probe *RemoteRepairGatewayProbe) RequireGateway(ctx context.Context, nodeID string) error {
	_, err := probe.GatewayGeneration(ctx, nodeID)
	return err
}

// GatewayGeneration returns the authoritative generation observed by the
// same authenticated, read-only probe used by apply/repair. Callers that need
// a subsequent mutation must still supply it as an explicit CAS expectation;
// the gateway will reject any intervening change.
func (probe *RemoteRepairGatewayProbe) GatewayGeneration(ctx context.Context, nodeID string) (uint64, error) {
	if ctx == nil || probe == nil || probe.caller == nil || probe.now == nil || probe.newUUID == nil || probe.entropy == nil || nodeID != probe.nodeID {
		return 0, ErrRepairGatewayUnavailable
	}
	requestID, err := probe.newUUID()
	if err != nil || model.ValidateResourceID(requestID) != nil {
		return 0, fmt.Errorf("%w: allocate repair probe identity", ErrRepairGatewayUnavailable)
	}
	nonce := make([]byte, control.RPCNonceBytes)
	if _, err := io.ReadFull(probe.entropy, nonce); err != nil {
		return 0, fmt.Errorf("%w: generate repair probe nonce", ErrRepairGatewayUnavailable)
	}
	defer clearRepairProbeSecret(nonce)
	payload, _ := json.Marshal(repairProbePayload{})
	call, err := probe.caller.CallManagement(ctx, control.RPCRequest{
		ProtocolMajor: probe.protocol.Major, ProtocolMinor: probe.protocol.Minor,
		RequestID: requestID, NodeID: probe.nodeID, CredentialGeneration: probe.credentialGeneration,
		Timestamp: probe.now().UTC(), Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		Operation: RepairProbeRPCOperation, Payload: payload,
	})
	if err != nil || call.StatusCode != http.StatusOK || call.Response.Category != "success" || call.Response.AuthoritativeGeneration == 0 {
		return 0, errors.Join(ErrRepairGatewayUnavailable, err)
	}
	var data repairProbeData
	if err := control.DecodeRPCPayload(call.Response.Data, &data); err != nil || !data.Reachable || data.NodeID != probe.nodeID {
		return 0, errors.Join(ErrRepairGatewayUnavailable, err)
	}
	return call.Response.AuthoritativeGeneration, nil
}

type RepairProbeGatewayState interface {
	Load() (model.State, error)
}

type RepairProbeGatewayRPCHandler struct {
	state RepairProbeGatewayState
}

func NewRepairProbeGatewayRPCHandler(state RepairProbeGatewayState) (*RepairProbeGatewayRPCHandler, error) {
	if state == nil {
		return nil, fmt.Errorf("repair probe gateway state is required")
	}
	return &RepairProbeGatewayRPCHandler{state: state}, nil
}

func (handler *RepairProbeGatewayRPCHandler) HandleRPC(
	ctx context.Context,
	peer control.RPCPeer,
	request control.RPCRequest,
) (control.RPCHandlerResult, error) {
	if ctx == nil || handler == nil || handler.state == nil {
		return control.RPCHandlerResult{}, fmt.Errorf("repair probe handler is incomplete")
	}
	if request.Operation != RepairProbeRPCOperation {
		return repairProbeFailure(request, http.StatusUnprocessableEntity, "validation", 0, "invalid_operation", "the handler accepts only repair probe"), nil
	}
	if peer.NodeID == "" || peer.NodeID != request.NodeID {
		return repairProbeFailure(request, http.StatusForbidden, "validation", 0, "identity_mismatch", "the certificate and request node identities differ"), nil
	}
	var payload repairProbePayload
	if err := control.DecodeRPCPayload(request.Payload, &payload); err != nil {
		return repairProbeFailure(request, http.StatusUnprocessableEntity, "validation", 0, "invalid_payload", "the repair probe payload is invalid"), nil
	}
	if err := ctx.Err(); err != nil {
		return repairProbeFailure(request, http.StatusServiceUnavailable, "unavailable", 0, "request_cancelled", "the repair probe was cancelled"), nil
	}
	state, err := handler.state.Load()
	if err != nil || state.Validate() != nil || state.Host.Role != model.RoleGateway {
		return repairProbeFailure(request, http.StatusServiceUnavailable, "unavailable", 0, "state_unavailable", "authoritative gateway state is unavailable"), nil
	}
	active := false
	for _, node := range state.Nodes {
		if node.ID == request.NodeID && node.Lifecycle == model.LifecycleActive {
			active = true
			break
		}
	}
	if !active {
		return repairProbeFailure(request, http.StatusForbidden, "validation", state.Generation, "node_inactive", "the authenticated node is not active"), nil
	}
	data, err := json.Marshal(repairProbeData{Reachable: true, NodeID: request.NodeID})
	if err != nil {
		return control.RPCHandlerResult{}, err
	}
	response := control.NewRPCResponse("success", state.Generation, data)
	response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
	response.ResourceIDs["node_id"] = request.NodeID
	return control.RPCHandlerResult{StatusCode: http.StatusOK, Response: response}, nil
}

func repairProbeFailure(request control.RPCRequest, status int, category string, generation uint64, code, message string) control.RPCHandlerResult {
	response := control.NewRPCResponse(category, generation, json.RawMessage(`{}`))
	response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
	response.ErrorCode, response.Message = code, message
	return control.RPCHandlerResult{StatusCode: status, Response: response}
}

func clearRepairProbeSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
