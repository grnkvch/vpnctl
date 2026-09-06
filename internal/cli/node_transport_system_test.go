package cli

import (
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestNodeTransportCompilationStatesBuildImmediateActiveAndStandbyGenerations(t *testing.T) {
	state := cliDoctorJoinedNodeState(t)
	state.Generation = 7
	base, alternative, err := nodeTransportCompilationStates(state)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(base, state) || alternative.Generation != state.Generation+1 ||
		base.Nodes[0].ActiveTransport != model.TransportRestricted ||
		alternative.Nodes[0].ActiveTransport != model.TransportStandard {
		t.Fatalf("compilation states base=%d/%s alternative=%d/%s", base.Generation, base.Nodes[0].ActiveTransport, alternative.Generation, alternative.Nodes[0].ActiveTransport)
	}
	if err := model.ValidateTransition(base, alternative); err != nil {
		t.Fatalf("alternative transition: %v", err)
	}
}

func TestNodeTransportCompilationStatesRecoverAppliedSideOfDeferredIntent(t *testing.T) {
	before := cliDoctorJoinedNodeState(t)
	before.Generation = 7
	requestID := "73000000-0000-4000-8000-000000000021"
	operationID, err := transport.SwitchOperationID(requestID)
	if err != nil {
		t.Fatal(err)
	}
	writer := &systemTransportDeferredWriter{now: func() time.Time {
		return time.Date(2026, time.September, 6, 12, 0, 0, 0, time.UTC)
	}}
	pending, err := writer.mirrorGatewayIntent(before, transport.DeferredSwitchReceipt{
		OperationID: operationID, RequestID: requestID, NodeID: before.Nodes[0].ID,
		Current: model.TransportRestricted, Target: model.TransportStandard,
		GatewayGeneration: 11, DesiredGatewayGeneration: 12,
		ExpectedNodeGeneration: before.Generation, DesiredNodeGeneration: before.Generation + 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	base, desired, err := nodeTransportCompilationStates(pending)
	if err != nil {
		t.Fatal(err)
	}
	if base.Generation != before.Generation || base.Nodes[0].ActiveTransport != model.TransportRestricted ||
		desired.Generation != before.Generation+2 || desired.Nodes[0].ActiveTransport != model.TransportStandard ||
		base.Nodes[0].Gateway.PendingRequestID != "" || len(base.Operations) != len(before.Operations) {
		t.Fatalf("deferred compilation base=%+v desired=%+v", base, desired)
	}
	if err := model.ValidateTransition(base, pending); err != nil {
		t.Fatalf("synthetic applied-to-pending transition: %v", err)
	}
}
