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
			receipt.GatewayGeneration != call.Response.AuthoritativeGeneration {
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

func clearTransportSwitchRPCSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
