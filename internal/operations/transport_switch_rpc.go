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
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

var ErrTransportSwitchGatewayUnavailable = errors.New("transport switch gateway is unavailable")

type TransportSwitchRPCCaller interface {
	CallManagement(context.Context, control.RPCRequest) (control.RPCCallResult, error)
}

type RemoteTransportSwitchGateway struct {
	caller               TransportSwitchRPCCaller
	protocol             control.RPCProtocolVersion
	nodeID               string
	credentialGeneration uint64
	lastKnownGeneration  uint64
	now                  func() time.Time
	entropy              io.Reader
}

func NewRemoteTransportSwitchGateway(
	caller TransportSwitchRPCCaller,
	protocol control.RPCProtocolVersion,
	nodeID string,
	credentialGeneration uint64,
	lastKnownGeneration uint64,
	now func() time.Time,
	entropy io.Reader,
) (*RemoteTransportSwitchGateway, error) {
	if caller == nil || protocol.Major < 1 || protocol.Minor < 0 || model.ValidateResourceID(nodeID) != nil ||
		credentialGeneration == 0 || lastKnownGeneration == 0 {
		return nil, fmt.Errorf("remote transport switch gateway identity is invalid")
	}
	if now == nil {
		now = time.Now
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return &RemoteTransportSwitchGateway{
		caller: caller, protocol: protocol, nodeID: nodeID,
		credentialGeneration: credentialGeneration, lastKnownGeneration: lastKnownGeneration,
		now: now, entropy: entropy,
	}, nil
}

func NewSystemRemoteTransportSwitchGateway(paths store.Paths, now func() time.Time) (*RemoteTransportSwitchGateway, error) {
	identity, err := control.NewSystemNodeClient(paths, now)
	if err != nil {
		return nil, err
	}
	return NewRemoteTransportSwitchGateway(
		identity.Client, identity.Protocol, identity.NodeID, identity.CredentialGeneration,
		identity.LastKnownGeneration, now, nil,
	)
}

func (gateway *RemoteTransportSwitchGateway) RegisterDeferred(
	ctx context.Context,
	current model.TransportKind,
	target model.TransportKind,
	expectedNodeGeneration uint64,
) (transport.DeferredSwitchReceipt, error) {
	if ctx == nil || gateway == nil || gateway.caller == nil || gateway.now == nil || gateway.entropy == nil {
		return transport.DeferredSwitchReceipt{}, fmt.Errorf("remote transport switch gateway is incomplete")
	}
	payload := transport.DeferredSwitchRequest{
		Action:  transport.SwitchMutationRegister,
		Current: current, Target: target, ExpectedNodeGeneration: expectedNodeGeneration,
	}
	intent, err := payload.IntentTarget(gateway.nodeID)
	if err != nil {
		return transport.DeferredSwitchReceipt{}, err
	}
	requestID, err := transport.SwitchRequestID(intent, current, gateway.lastKnownGeneration)
	if err != nil {
		return transport.DeferredSwitchReceipt{}, err
	}
	operationID, err := transport.SwitchOperationID(requestID)
	if err != nil {
		return transport.DeferredSwitchReceipt{}, err
	}
	nonce := make([]byte, control.RPCNonceBytes)
	if _, err := io.ReadFull(gateway.entropy, nonce); err != nil {
		return transport.DeferredSwitchReceipt{}, fmt.Errorf("generate transport switch RPC nonce: %w", err)
	}
	defer clearTransportSwitchRPCSecret(nonce)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return transport.DeferredSwitchReceipt{}, err
	}
	call, err := gateway.caller.CallManagement(ctx, control.RPCRequest{
		ProtocolMajor: gateway.protocol.Major, ProtocolMinor: gateway.protocol.Minor,
		RequestID: requestID, ExpectedStateGeneration: gateway.lastKnownGeneration,
		NodeID: gateway.nodeID, CredentialGeneration: gateway.credentialGeneration,
		Timestamp: gateway.now().UTC(), Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		Operation: string(model.OperationTransportSwitch), Payload: encoded,
	})
	if err != nil {
		return transport.DeferredSwitchReceipt{}, fmt.Errorf("%w: %v", ErrTransportSwitchGatewayUnavailable, err)
	}
	if call.StatusCode != http.StatusOK || call.Response.Category != "success" {
		switch call.Response.Category {
		case "conflict", "validation":
			return transport.DeferredSwitchReceipt{}, transport.ErrTransportSwitchStale
		case "unavailable":
			return transport.DeferredSwitchReceipt{}, ErrTransportSwitchGatewayUnavailable
		default:
			return transport.DeferredSwitchReceipt{}, errors.New("gateway transport switch registration failed")
		}
	}
	if call.Response.AuthoritativeGeneration == 0 {
		return transport.DeferredSwitchReceipt{}, errors.New("gateway transport switch response has no authoritative generation")
	}
	var receipt transport.DeferredSwitchReceipt
	if err := control.DecodeRPCPayload(call.Response.Data, &receipt); err == nil && receipt.OperationID != "" {
		if err := receipt.Validate(); err != nil || receipt.OperationID != operationID || receipt.RequestID != requestID || receipt.NodeID != gateway.nodeID ||
			receipt.Current != current || receipt.Target != target || receipt.ExpectedNodeGeneration != expectedNodeGeneration ||
			receipt.GatewayGeneration > call.Response.AuthoritativeGeneration {
			return transport.DeferredSwitchReceipt{}, errors.New("gateway returned an invalid transport switch receipt")
		}
		return receipt, nil
	}
	var replay struct {
		Replayed     bool               `json:"replayed"`
		ResultStatus model.ResultStatus `json:"result_status"`
	}
	if err := control.DecodeRPCPayload(call.Response.Data, &replay); err != nil || !replay.Replayed || replay.ResultStatus != model.ResultPending {
		return transport.DeferredSwitchReceipt{}, errors.New("gateway returned an invalid transport switch replay receipt")
	}
	desiredGatewayGeneration, err := model.NextGeneration(call.Response.AuthoritativeGeneration)
	if err != nil {
		return transport.DeferredSwitchReceipt{}, err
	}
	receipt = transport.DeferredSwitchReceipt{
		OperationID: operationID, RequestID: requestID,
		NodeID: gateway.nodeID, Current: current, Target: target,
		GatewayGeneration: call.Response.AuthoritativeGeneration, DesiredGatewayGeneration: desiredGatewayGeneration,
		ExpectedNodeGeneration: intent.ExpectedNodeGeneration, DesiredNodeGeneration: intent.DesiredNodeGeneration,
	}
	if err := receipt.Validate(); err != nil {
		return transport.DeferredSwitchReceipt{}, errors.New("gateway returned an invalid transport switch replay receipt")
	}
	return receipt, nil
}

// FinalizeDeferred commits the gateway-side selection for an already retained
// node operation. The expected gateway generation is supplied by the caller's
// immediately preceding authenticated freshness check; it is not inferred
// from the registration receipt because unrelated fleet mutations may have
// advanced the authoritative state in the meantime.
func (gateway *RemoteTransportSwitchGateway) FinalizeDeferred(
	ctx context.Context,
	operation model.Operation,
	current model.TransportKind,
	expectedGatewayGeneration uint64,
) (transport.FinalizedSwitchReceipt, error) {
	if ctx == nil || gateway == nil || gateway.caller == nil || gateway.now == nil || gateway.entropy == nil {
		return transport.FinalizedSwitchReceipt{}, fmt.Errorf("remote transport switch gateway is incomplete")
	}
	intent, err := transport.ParseSwitchIntentTarget(operation.TargetID)
	if err != nil || operation.Type != model.OperationTransportSwitch || operation.TargetKind != "transport" ||
		operation.State != model.OperationPending || operation.ID == "" || intent.NodeID != gateway.nodeID ||
		expectedGatewayGeneration == 0 {
		return transport.FinalizedSwitchReceipt{}, transport.ErrTransportSwitchStale
	}
	requestID, err := transport.SwitchFinalizeRequestID(operation.ID, intent.DesiredNodeGeneration, expectedGatewayGeneration)
	if err != nil {
		return transport.FinalizedSwitchReceipt{}, err
	}
	payload := transport.DeferredSwitchRequest{
		Action:  transport.SwitchMutationFinalize,
		Current: current, Target: intent.Target,
		ExpectedNodeGeneration: intent.ExpectedNodeGeneration,
		DesiredNodeGeneration:  intent.DesiredNodeGeneration,
		OperationID:            operation.ID,
	}
	if _, err := payload.ValidateFinalization(gateway.nodeID, expectedGatewayGeneration, requestID); err != nil {
		return transport.FinalizedSwitchReceipt{}, err
	}
	nonce := make([]byte, control.RPCNonceBytes)
	if _, err := io.ReadFull(gateway.entropy, nonce); err != nil {
		return transport.FinalizedSwitchReceipt{}, fmt.Errorf("generate transport switch finalization RPC nonce: %w", err)
	}
	defer clearTransportSwitchRPCSecret(nonce)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return transport.FinalizedSwitchReceipt{}, err
	}
	call, err := gateway.caller.CallManagement(ctx, control.RPCRequest{
		ProtocolMajor: gateway.protocol.Major, ProtocolMinor: gateway.protocol.Minor,
		RequestID: requestID, ExpectedStateGeneration: expectedGatewayGeneration,
		NodeID: gateway.nodeID, CredentialGeneration: gateway.credentialGeneration,
		Timestamp: gateway.now().UTC(), Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		Operation: string(model.OperationTransportSwitch), Payload: encoded,
	})
	if err != nil {
		return transport.FinalizedSwitchReceipt{}, fmt.Errorf("%w: %v", ErrTransportSwitchGatewayUnavailable, err)
	}
	if call.StatusCode != http.StatusOK || call.Response.Category != "success" {
		switch call.Response.Category {
		case "conflict", "validation":
			return transport.FinalizedSwitchReceipt{}, transport.ErrTransportSwitchStale
		case "unavailable":
			return transport.FinalizedSwitchReceipt{}, ErrTransportSwitchGatewayUnavailable
		default:
			return transport.FinalizedSwitchReceipt{}, errors.New("gateway transport switch finalization failed")
		}
	}
	if call.Response.AuthoritativeGeneration <= expectedGatewayGeneration {
		return transport.FinalizedSwitchReceipt{}, errors.New("gateway transport switch finalization did not advance authoritative generation")
	}
	receipt := transport.FinalizedSwitchReceipt{}
	if err := control.DecodeRPCPayload(call.Response.Data, &receipt); err == nil && receipt.OperationID != "" {
		if err := receipt.Validate(); err != nil || receipt.OperationID != operation.ID || receipt.RequestID != requestID ||
			receipt.NodeID != gateway.nodeID || receipt.Previous != current || receipt.Active != intent.Target ||
			receipt.ExpectedGatewayGeneration != expectedGatewayGeneration ||
			receipt.GatewayGeneration != call.Response.AuthoritativeGeneration ||
			receipt.ExpectedNodeGeneration != intent.ExpectedNodeGeneration ||
			receipt.DesiredNodeGeneration != intent.DesiredNodeGeneration {
			return transport.FinalizedSwitchReceipt{}, errors.New("gateway returned an invalid transport switch finalization receipt")
		}
		return receipt, nil
	}
	var replay struct {
		Replayed     bool               `json:"replayed"`
		ResultStatus model.ResultStatus `json:"result_status"`
	}
	if err := control.DecodeRPCPayload(call.Response.Data, &replay); err != nil || !replay.Replayed || replay.ResultStatus != model.ResultOK {
		return transport.FinalizedSwitchReceipt{}, errors.New("gateway returned an invalid transport switch finalization replay receipt")
	}
	receipt = transport.FinalizedSwitchReceipt{
		OperationID: operation.ID, RequestID: requestID, NodeID: gateway.nodeID,
		Previous: current, Active: intent.Target,
		ExpectedGatewayGeneration: expectedGatewayGeneration,
		GatewayGeneration:         call.Response.AuthoritativeGeneration,
		ExpectedNodeGeneration:    intent.ExpectedNodeGeneration,
		DesiredNodeGeneration:     intent.DesiredNodeGeneration,
	}
	if err := receipt.Validate(); err != nil {
		return transport.FinalizedSwitchReceipt{}, errors.New("gateway returned an invalid transport switch finalization replay receipt")
	}
	return receipt, nil
}

// ReconcileDeferred asks the gateway to prove that the retained operation is
// already complete by deliberately using its pre-registration generation.
// The mutation handler therefore takes its read-only reconciliation path. A
// pending operation is reported as determined=false and is never executed by
// this method.
func (gateway *RemoteTransportSwitchGateway) ReconcileDeferred(
	ctx context.Context,
	operation model.Operation,
	current model.TransportKind,
) (transport.FinalizedSwitchReceipt, bool, error) {
	if operation.ExpectedGeneration == 0 {
		return transport.FinalizedSwitchReceipt{}, false, transport.ErrTransportSwitchStale
	}
	receipt, err := gateway.FinalizeDeferred(ctx, operation, current, operation.ExpectedGeneration)
	if errors.Is(err, transport.ErrTransportSwitchStale) {
		return transport.FinalizedSwitchReceipt{}, false, nil
	}
	if err != nil {
		return transport.FinalizedSwitchReceipt{}, false, err
	}
	return receipt, true, nil
}

func clearTransportSwitchRPCSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
