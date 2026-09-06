package transport

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestDeferredNodeRuntimeActivatesWithoutStateCommitAndCanRestorePreviousBundle(t *testing.T) {
	t.Parallel()
	state, operation := deferredRuntimePendingState(t)
	before := state
	trace := []string{}
	standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
	restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
	registry, err := NewRegistry(standard, restricted)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewDeferredNodeRuntime(registry, SwitchLimits{})
	if err != nil {
		t.Fatal(err)
	}
	activation, err := runtime.Activate(context.Background(), state, operation)
	if err != nil {
		t.Fatal(err)
	}
	result, err := activation.Result()
	if err != nil || result.Previous != model.TransportStandard || result.Active != model.TransportRestricted ||
		result.StateGeneration != 11 || result.ActiveHealth.Condition != HealthHealthy {
		t.Fatalf("activation result=%+v err=%v", result, err)
	}
	if standard.role != RuntimeStandby || restricted.role != RuntimeActive {
		t.Fatalf("runtime roles after activation=%s/%s", standard.role, restricted.role)
	}
	if !reflect.DeepEqual(state, before) {
		t.Fatal("deferred runtime changed authoritative node state")
	}
	if err := activation.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if standard.role != RuntimeActive || restricted.role != RuntimeStandby {
		t.Fatalf("runtime roles after rollback=%s/%s", standard.role, restricted.role)
	}
	if !reflect.DeepEqual(state, before) {
		t.Fatal("deferred runtime rollback changed authoritative node state")
	}
}

func deferredRuntimePendingState(t *testing.T) (model.State, model.Operation) {
	t.Helper()
	state := nodeTransportTestState(t)
	intent, err := NewSwitchIntentTarget(state.Nodes[0].ID, model.TransportRestricted, state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	registrationID, err := SwitchRequestID(intent, model.TransportStandard, 20)
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := SwitchOperationID(registrationID)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, time.September, 6, 12, 0, 0, 0, time.UTC)
	steps := make([]model.OperationStep, len(SwitchOperationStepNames()))
	for index, name := range SwitchOperationStepNames() {
		steps[index] = model.OperationStep{Name: name, State: model.OperationPending, UpdatedAt: at}
	}
	operation := model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: operationID, Type: model.OperationTransportSwitch,
		State: model.OperationPending, TargetKind: "transport", TargetID: intent.String(), RequestID: registrationID,
		ExpectedGeneration: 20, DesiredGeneration: 22, Steps: steps, CreatedAt: at, UpdatedAt: at,
	}
	state.Generation++
	state.Operations = append(state.Operations, operation)
	state.Nodes[0].Gateway.PendingRequestID = registrationID
	state.Nodes[0].Gateway.LastKnownGatewayGeneration = 21
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	return state, operation
}
