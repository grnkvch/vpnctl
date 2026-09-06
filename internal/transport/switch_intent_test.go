package transport

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestSwitchIntentTargetRoundTripAndStableIdentities(t *testing.T) {
	t.Parallel()
	target, err := NewSwitchIntentTarget("22000000-0000-4000-8000-000000000001", model.TransportRestricted, 9)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSwitchIntentTarget(target.String())
	if err != nil || parsed != target || parsed.DesiredNodeGeneration != 11 {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	first, err := SwitchRequestID(target, model.TransportStandard, 12)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := SwitchRequestID(target, model.TransportStandard, 12)
	changed, _ := SwitchRequestID(target, model.TransportStandard, 13)
	operation, err := SwitchOperationID(first)
	if err != nil || model.ValidateResourceID(first) != nil || model.ValidateResourceID(operation) != nil ||
		first != second || first == changed || first == operation {
		t.Fatalf("request identities first=%q second=%q changed=%q operation=%q err=%v", first, second, changed, operation, err)
	}
}

func TestSwitchIntentTargetRejectsNonCanonicalOrInconsistentValues(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"restricted",
		"v2:22000000-0000-4000-8000-000000000001:restricted:9:11",
		"v1:bad:restricted:9:11",
		"v1:22000000-0000-4000-8000-000000000001:auto:9:11",
		"v1:22000000-0000-4000-8000-000000000001:restricted:09:11",
		"v1:22000000-0000-4000-8000-000000000001:restricted:9:10",
	} {
		if _, err := ParseSwitchIntentTarget(value); err == nil {
			t.Fatalf("ParseSwitchIntentTarget(%q) succeeded", value)
		}
	}
}

func TestDeferredSwitchMutationActionsBindStableRequestIdentities(t *testing.T) {
	t.Parallel()
	nodeID := "22000000-0000-4000-8000-000000000001"
	registration := DeferredSwitchRequest{
		Action: SwitchMutationRegister, Current: model.TransportStandard,
		Target: model.TransportRestricted, ExpectedNodeGeneration: 9,
	}
	intent, err := registration.IntentTarget(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	registrationID, err := SwitchRequestID(intent, registration.Current, 12)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := registration.ValidateRegistration(nodeID, 12, registrationID); err != nil || got != intent {
		t.Fatalf("registration intent=%+v err=%v", got, err)
	}
	operationID, err := SwitchOperationID(registrationID)
	if err != nil {
		t.Fatal(err)
	}
	finalization := DeferredSwitchRequest{
		Action: SwitchMutationFinalize, Current: model.TransportStandard,
		Target: model.TransportRestricted, ExpectedNodeGeneration: 9, DesiredNodeGeneration: 11,
		OperationID: operationID,
	}
	finalizationID, err := SwitchFinalizeRequestID(operationID, 11, 17)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := finalization.ValidateFinalization(nodeID, 17, finalizationID); err != nil || got != intent {
		t.Fatalf("finalization intent=%+v err=%v", got, err)
	}
	if finalizationID == registrationID {
		t.Fatal("registration and finalization request IDs must differ")
	}
	receipt := FinalizedSwitchReceipt{
		OperationID: operationID, RequestID: finalizationID, NodeID: nodeID,
		Previous: model.TransportStandard, Active: model.TransportRestricted,
		ExpectedGatewayGeneration: 17, GatewayGeneration: 18,
		ExpectedNodeGeneration: 9, DesiredNodeGeneration: 11,
	}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	receipt.GatewayGeneration = 17
	if err := receipt.Validate(); err == nil {
		t.Fatal("receipt accepted a non-advancing gateway generation")
	}
}

func TestDeferredSwitchDesiredStateBuildsExactFinalNodeGeneration(t *testing.T) {
	t.Parallel()
	state := nodeTransportTestState(t)
	state.Generation = 10
	requestID := "22000000-0000-4000-8000-000000000010"
	operationID, err := SwitchOperationID(requestID)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := NewSwitchIntentTarget(state.Nodes[0].ID, model.TransportRestricted, 9)
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
		State: model.OperationPending, TargetKind: "transport", TargetID: intent.String(), RequestID: requestID,
		ExpectedGeneration: 20, DesiredGeneration: 22, Steps: steps, CreatedAt: at, UpdatedAt: at,
	}
	state.Operations = append(state.Operations, operation)
	state.Nodes[0].Gateway.PendingRequestID = requestID
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	before := state
	candidate, gotIntent, err := DeferredSwitchDesiredState(state, operation)
	if err != nil {
		t.Fatal(err)
	}
	if gotIntent != intent || candidate.Generation != 11 || candidate.Nodes[0].ActiveTransport != model.TransportRestricted ||
		candidate.Nodes[0].Gateway.PendingRequestID != requestID || candidate.Operations[len(candidate.Operations)-1].State != model.OperationPending {
		t.Fatalf("candidate=%+v intent=%+v", candidate, gotIntent)
	}
	if !reflect.DeepEqual(state, before) {
		t.Fatal("desired-state construction mutated the retained pending state")
	}
	for _, configured := range candidate.Transports {
		if configured.OwnerKind != model.TargetNode || configured.OwnerID != state.Nodes[0].ID {
			continue
		}
		want := model.TransportStandby
		if configured.Kind == model.TransportRestricted {
			want = model.TransportActive
		}
		if configured.State != want {
			t.Fatalf("%s state=%s, want %s", configured.Kind, configured.State, want)
		}
	}
}

func TestDeferredSwitchDesiredStateRejectsStaleMirror(t *testing.T) {
	t.Parallel()
	state := nodeTransportTestState(t)
	if _, _, err := DeferredSwitchDesiredState(state, model.Operation{}); !errors.Is(err, ErrTransportSwitchStale) {
		t.Fatalf("missing retained operation error=%v", err)
	}
}

func TestFinalizeDeferredSwitchNodeStateCommitsSelectionOperationAndTrustAtDesiredGeneration(t *testing.T) {
	t.Parallel()
	state := nodeTransportTestState(t)
	state.Generation = 10
	intent, err := NewSwitchIntentTarget(state.Nodes[0].ID, model.TransportRestricted, 9)
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
	createdAt := time.Date(2026, time.September, 6, 12, 0, 0, 0, time.UTC)
	steps := make([]model.OperationStep, len(SwitchOperationStepNames()))
	for index, name := range SwitchOperationStepNames() {
		steps[index] = model.OperationStep{Name: name, State: model.OperationPending, UpdatedAt: createdAt}
	}
	operation := model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: operationID, Type: model.OperationTransportSwitch,
		State: model.OperationPending, TargetKind: "transport", TargetID: intent.String(), RequestID: registrationID,
		ExpectedGeneration: 20, DesiredGeneration: 22, Steps: steps, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	state.Operations = append(state.Operations, operation)
	state.Nodes[0].Gateway.PendingRequestID = registrationID
	state.Nodes[0].Gateway.LastKnownGatewayGeneration = 21
	finalizationID, err := SwitchFinalizeRequestID(operationID, intent.DesiredNodeGeneration, 27)
	if err != nil {
		t.Fatal(err)
	}
	receipt := FinalizedSwitchReceipt{
		OperationID: operationID, RequestID: finalizationID, NodeID: state.Nodes[0].ID,
		Previous: model.TransportStandard, Active: model.TransportRestricted,
		ExpectedGatewayGeneration: 27, GatewayGeneration: 28,
		ExpectedNodeGeneration: intent.ExpectedNodeGeneration, DesiredNodeGeneration: intent.DesiredNodeGeneration,
	}
	before := state
	final, completed, err := FinalizeDeferredSwitchNodeState(state, operation, receipt, createdAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if final.Generation != 11 || final.Nodes[0].ActiveTransport != model.TransportRestricted ||
		final.Nodes[0].Gateway.PendingRequestID != "" || final.Nodes[0].Gateway.LastKnownGatewayGeneration != 28 ||
		completed.State != model.OperationCompleted || !reflect.DeepEqual(final.Operations[len(final.Operations)-1], completed) {
		t.Fatalf("final=%+v completed=%+v", final, completed)
	}
	for _, step := range completed.Steps {
		if step.State != model.OperationCompleted {
			t.Fatalf("step %s state=%s", step.Name, step.State)
		}
	}
	if !reflect.DeepEqual(state, before) {
		t.Fatal("node finalization mutated the retained pending state")
	}
	if err := model.ValidateTransition(state, final); err != nil {
		t.Fatal(err)
	}
}

func TestFinalizeDeferredSwitchNodeStateRejectsDifferentReceipt(t *testing.T) {
	t.Parallel()
	state := nodeTransportTestState(t)
	if _, _, err := FinalizeDeferredSwitchNodeState(state, model.Operation{}, FinalizedSwitchReceipt{}, time.Now()); err == nil {
		t.Fatal("invalid finalization receipt was accepted")
	}
}
