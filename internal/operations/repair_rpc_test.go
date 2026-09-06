package operations

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
)

type directRepairProbeCaller struct {
	handler control.RPCHandler
	last    control.RPCRequest
}

func (caller *directRepairProbeCaller) CallManagement(ctx context.Context, request control.RPCRequest) (control.RPCCallResult, error) {
	caller.last = request
	result, err := caller.handler.HandleRPC(ctx, control.RPCPeer{NodeID: request.NodeID}, request)
	return control.RPCCallResult{StatusCode: result.StatusCode, Response: result.Response}, err
}

func TestRemoteRepairGatewayProbeRequiresAuthenticatedActiveGatewayNode(t *testing.T) {
	t.Parallel()

	state := exposeSagaGatewayState(t)
	store := &memoryExposeState{state: state, trace: &[]string{}, label: "gateway"}
	handler, err := NewRepairProbeGatewayRPCHandler(store)
	if err != nil {
		t.Fatal(err)
	}
	caller := &directRepairProbeCaller{handler: handler}
	now := time.Date(2026, time.September, 6, 12, 0, 0, 0, time.UTC)
	probe, err := NewRemoteRepairGatewayProbe(
		caller, control.RPCProtocolVersion{Major: 1}, exposeSagaNodeID, 1,
		func() time.Time { return now },
		func() (string, error) { return "10000000-0000-4000-8000-000000000001", nil },
		bytes.NewReader(bytes.Repeat([]byte{0x61}, control.RPCNonceBytes)),
	)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := probe.GatewayGeneration(context.Background(), exposeSagaNodeID)
	if err != nil || generation != state.Generation {
		t.Fatalf("gateway generation=%d err=%v", generation, err)
	}
	if caller.last.Operation != RepairProbeRPCOperation || caller.last.ExpectedStateGeneration != 0 || caller.last.NodeID != exposeSagaNodeID {
		t.Fatalf("repair probe request = %+v", caller.last)
	}
	if len(store.state.Operations) != len(state.Operations) || store.state.Generation != state.Generation {
		t.Fatal("repair probe changed gateway state")
	}
}

func TestRemoteRepairGatewayProbeFailsClosedForWrongOrInactiveNode(t *testing.T) {
	t.Parallel()

	state := exposeSagaGatewayState(t)
	state.Nodes[0].Lifecycle = "revoked"
	store := &memoryExposeState{state: state, trace: &[]string{}, label: "gateway"}
	handler, _ := NewRepairProbeGatewayRPCHandler(store)
	probe, err := NewRemoteRepairGatewayProbe(
		&directRepairProbeCaller{handler: handler}, control.RPCProtocolVersion{Major: 1}, exposeSagaNodeID, 1,
		func() time.Time { return time.Date(2026, time.September, 6, 12, 0, 0, 0, time.UTC) },
		func() (string, error) { return "20000000-0000-4000-8000-000000000001", nil },
		bytes.NewReader(bytes.Repeat([]byte{0x62}, control.RPCNonceBytes)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.RequireGateway(context.Background(), exposeSagaNodeID); !errors.Is(err, ErrRepairGatewayUnavailable) {
		t.Fatalf("inactive-node repair probe error = %v", err)
	}
	if err := probe.RequireGateway(context.Background(), "30000000-0000-4000-8000-000000000001"); !errors.Is(err, ErrRepairGatewayUnavailable) {
		t.Fatalf("wrong-node repair probe error = %v", err)
	}
}
