package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

const remoteTransportSwitchNodeID = "72000000-0000-4000-8000-000000000001"

func TestRemoteTransportSwitchGatewayValidatesFullAndReplayReceipts(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(map[bool]string{false: "full", true: "replay"}[replay], func(t *testing.T) {
			caller := &transportSwitchRPCCallerFixture{replay: replay}
			gateway, err := NewRemoteTransportSwitchGateway(
				caller, control.RPCProtocolVersion{Major: 1, Minor: 0}, remoteTransportSwitchNodeID,
				2, 12, func() time.Time { return time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC) },
				bytes.NewReader(bytes.Repeat([]byte{0x41}, control.RPCNonceBytes*2)),
			)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := gateway.RegisterDeferred(context.Background(), model.TransportStandard, model.TransportRestricted, 9)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.NodeID != remoteTransportSwitchNodeID || receipt.Current != model.TransportStandard ||
				receipt.Target != model.TransportRestricted || receipt.GatewayGeneration != 13 ||
				receipt.DesiredGatewayGeneration != 14 || receipt.ExpectedNodeGeneration != 9 || receipt.DesiredNodeGeneration != 11 {
				t.Fatalf("receipt=%+v", receipt)
			}
			if caller.request.Operation != string(model.OperationTransportSwitch) || caller.request.ExpectedStateGeneration != 12 ||
				caller.request.NodeID != remoteTransportSwitchNodeID || caller.request.CredentialGeneration != 2 || caller.request.Validate() != nil {
				t.Fatalf("request=%+v", caller.request)
			}
			firstID := caller.request.RequestID
			caller.replay = true
			if _, err := gateway.RegisterDeferred(context.Background(), model.TransportStandard, model.TransportRestricted, 9); err != nil {
				t.Fatal(err)
			}
			if caller.request.RequestID != firstID {
				t.Fatalf("retry request ID=%q, want %q", caller.request.RequestID, firstID)
			}
		})
	}
}

func TestRemoteTransportSwitchGatewayMapsClosedFailureCategories(t *testing.T) {
	for _, test := range []struct {
		name     string
		category string
		status   int
		want     error
	}{
		{"conflict", "conflict", http.StatusConflict, transport.ErrTransportSwitchStale},
		{"validation", "validation", http.StatusUnprocessableEntity, transport.ErrTransportSwitchStale},
		{"unavailable", "unavailable", http.StatusServiceUnavailable, ErrTransportSwitchGatewayUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			caller := &transportSwitchRPCCallerFixture{category: test.category, status: test.status}
			gateway, err := NewRemoteTransportSwitchGateway(
				caller, control.RPCProtocolVersion{Major: 1}, remoteTransportSwitchNodeID, 1, 12,
				func() time.Time { return time.Now().UTC() }, bytes.NewReader(bytes.Repeat([]byte{0x42}, control.RPCNonceBytes)),
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := gateway.RegisterDeferred(context.Background(), model.TransportStandard, model.TransportRestricted, 9); !errors.Is(err, test.want) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
		})
	}
}

type transportSwitchRPCCallerFixture struct {
	request  control.RPCRequest
	replay   bool
	category string
	status   int
}

func (caller *transportSwitchRPCCallerFixture) CallManagement(_ context.Context, request control.RPCRequest) (control.RPCCallResult, error) {
	caller.request = request
	if caller.category != "" {
		response := control.NewRPCResponse(caller.category, request.ExpectedStateGeneration, json.RawMessage(`{}`))
		response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
		if caller.category != "success" {
			response.ErrorCode, response.Message = "transport_switch_error", "transport switch request failed"
		}
		return control.RPCCallResult{StatusCode: caller.status, Response: response}, nil
	}
	registration, _ := model.NextGeneration(request.ExpectedStateGeneration)
	response := control.NewRPCResponse("success", registration, nil)
	response.ProtocolMajor, response.ProtocolMinor = request.ProtocolMajor, request.ProtocolMinor
	if caller.replay {
		response.Data, _ = json.Marshal(struct {
			Replayed     bool               `json:"replayed"`
			ResultStatus model.ResultStatus `json:"result_status"`
		}{true, model.ResultPending})
	} else {
		var payload transport.DeferredSwitchRequest
		_ = json.Unmarshal(request.Payload, &payload)
		operationID, _ := transport.SwitchOperationID(request.RequestID)
		desiredGateway, _ := model.NextGeneration(registration)
		intent, _ := payload.IntentTarget(request.NodeID)
		receipt := transport.DeferredSwitchReceipt{
			OperationID: operationID, RequestID: request.RequestID,
			NodeID: request.NodeID, Current: payload.Current, Target: payload.Target,
			GatewayGeneration: registration, DesiredGatewayGeneration: desiredGateway,
			ExpectedNodeGeneration: intent.ExpectedNodeGeneration, DesiredNodeGeneration: intent.DesiredNodeGeneration,
		}
		response.Data, _ = json.Marshal(receipt)
	}
	return control.RPCCallResult{StatusCode: http.StatusOK, Response: response}, nil
}

var _ TransportSwitchRPCCaller = (*transportSwitchRPCCallerFixture)(nil)
