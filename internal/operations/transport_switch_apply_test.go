package operations

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestNodeTransportSwitchApplyExecutorCommitsGatewayNodeAndConvergence(t *testing.T) {
	t.Parallel()
	state, operation := transportSwitchApplyPendingState(t)
	stateStore := &transportSwitchApplyStateStore{state: state}
	convergence, batch := transportSwitchApplyConvergence(t, operation)
	runtime := &transportSwitchApplyRuntime{}
	gateway := &transportSwitchApplyGateway{finalize: transportSwitchApplyReceipt(t, operation, model.TransportStandard, 27, 28)}
	probe := &transportSwitchApplyGeneration{generation: 27}
	executor, err := NewNodeTransportSwitchApplyExecutor(
		stateStore, runtime, gateway, probe, convergence,
		func() time.Time { return operation.CreatedAt.Add(time.Minute) },
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := executor.ApplyCurrentNode(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if result.AppliedGeneration != 9 || !reflect.DeepEqual(result.OperationIDs, []string{operation.ID}) ||
		runtime.calls != 1 || runtime.activation.rollbacks != 0 || gateway.finalizeCalls != 1 ||
		gateway.reconcileCalls != 1 || probe.calls != 1 {
		t.Fatalf("result=%+v runtime=%+v gateway=%+v probe=%+v", result, runtime, gateway, probe)
	}
	final := stateStore.state
	if final.Generation != 9 || final.Nodes[0].ActiveTransport != model.TransportRestricted ||
		final.Nodes[0].Gateway.PendingRequestID != "" || final.Nodes[0].Gateway.LastKnownGatewayGeneration != 28 ||
		final.Operations[len(final.Operations)-1].State != model.OperationCompleted {
		t.Fatalf("final node state=%+v", final)
	}
	snapshot, err := convergence.Read(context.Background())
	if err != nil || snapshot.Applied.Generation != 9 || !reflect.DeepEqual(snapshot.Desired, snapshot.Applied) || len(snapshot.Pending) != 0 {
		t.Fatalf("final convergence=%+v err=%v", snapshot, err)
	}
}

func TestNodeTransportSwitchApplyExecutorRollsBackOnlyAfterGatewayProvesPending(t *testing.T) {
	t.Parallel()
	state, operation := transportSwitchApplyPendingState(t)
	stateStore := &transportSwitchApplyStateStore{state: state}
	convergence, batch := transportSwitchApplyConvergence(t, operation)
	runtime := &transportSwitchApplyRuntime{}
	gateway := &transportSwitchApplyGateway{finalizeErr: transport.ErrTransportSwitchStale}
	probe := &transportSwitchApplyGeneration{generation: 27}
	executor, _ := NewNodeTransportSwitchApplyExecutor(
		stateStore, runtime, gateway, probe, convergence,
		func() time.Time { return operation.CreatedAt.Add(time.Minute) },
	)
	if _, err := executor.ApplyCurrentNode(context.Background(), batch); !errors.Is(err, transport.ErrTransportSwitchStale) {
		t.Fatalf("apply error=%v", err)
	}
	if runtime.calls != 1 || runtime.activation.rollbacks != 1 || gateway.reconcileCalls != 2 || gateway.finalizeCalls != 1 {
		t.Fatalf("runtime=%+v gateway=%+v", runtime, gateway)
	}
	if !reflect.DeepEqual(stateStore.state, state) {
		t.Fatal("definitively rejected gateway finalization changed node state")
	}
	snapshot, err := convergence.Read(context.Background())
	if err != nil || snapshot.Applied.Generation != 7 || snapshot.Desired.Generation != 9 || len(snapshot.Pending) != 1 {
		t.Fatalf("convergence after rollback=%+v err=%v", snapshot, err)
	}
}

func TestNodeTransportSwitchApplyExecutorResumesGatewayCompletedOperation(t *testing.T) {
	t.Parallel()
	state, operation := transportSwitchApplyPendingState(t)
	stateStore := &transportSwitchApplyStateStore{state: state}
	convergence, batch := transportSwitchApplyConvergence(t, operation)
	runtime := &transportSwitchApplyRuntime{}
	gateway := &transportSwitchApplyGateway{
		reconcileComplete: true,
		reconcile:         transportSwitchApplyReceipt(t, operation, model.TransportStandard, operation.ExpectedGeneration, 31),
	}
	probe := &transportSwitchApplyGeneration{generation: 30}
	executor, _ := NewNodeTransportSwitchApplyExecutor(
		stateStore, runtime, gateway, probe, convergence,
		func() time.Time { return operation.CreatedAt.Add(time.Minute) },
	)
	if _, err := executor.ApplyCurrentNode(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if gateway.finalizeCalls != 0 || probe.calls != 0 || runtime.calls != 1 || stateStore.state.Generation != 9 ||
		stateStore.state.Nodes[0].Gateway.LastKnownGatewayGeneration != 31 {
		t.Fatalf("state=%+v runtime=%+v gateway=%+v probe=%+v", stateStore.state, runtime, gateway, probe)
	}
}

func TestNodeTransportSwitchApplyExecutorDoesNotBlindRollbackUncertainGatewayCommit(t *testing.T) {
	t.Parallel()
	state, operation := transportSwitchApplyPendingState(t)
	stateStore := &transportSwitchApplyStateStore{state: state}
	convergence, batch := transportSwitchApplyConvergence(t, operation)
	runtime := &transportSwitchApplyRuntime{}
	gatewayUnavailable := errors.New("synthetic gateway response loss")
	gateway := &transportSwitchApplyGateway{
		finalizeErr:     gatewayUnavailable,
		reconcileErrors: []error{nil, gatewayUnavailable},
	}
	executor, _ := NewNodeTransportSwitchApplyExecutor(
		stateStore, runtime, gateway, &transportSwitchApplyGeneration{generation: 27}, convergence,
		func() time.Time { return operation.CreatedAt.Add(time.Minute) },
	)
	if _, err := executor.ApplyCurrentNode(context.Background(), batch); !errors.Is(err, ErrTransportSwitchApplyUncertain) {
		t.Fatalf("uncertain apply error=%v", err)
	}
	if runtime.activation.rollbacks != 0 || gateway.finalizeCalls != 1 || gateway.reconcileCalls != 2 ||
		!reflect.DeepEqual(stateStore.state, state) {
		t.Fatalf("runtime=%+v gateway=%+v state=%+v", runtime, gateway, stateStore.state)
	}
}

func TestNodeTransportSwitchApplyExecutorRecoversConvergenceAfterTerminalNodeCommit(t *testing.T) {
	t.Parallel()
	state, operation := transportSwitchApplyPendingState(t)
	stateStore := &transportSwitchApplyStateStore{state: state}
	inner, batch := transportSwitchApplyConvergence(t, operation)
	convergence := &failingTransportSwitchConvergence{inner: inner, failCAS: true}
	runtime := &transportSwitchApplyRuntime{}
	gateway := &transportSwitchApplyGateway{finalize: transportSwitchApplyReceipt(t, operation, model.TransportStandard, 27, 28)}
	executor, _ := NewNodeTransportSwitchApplyExecutor(
		stateStore, runtime, gateway, &transportSwitchApplyGeneration{generation: 27}, convergence,
		func() time.Time { return operation.CreatedAt.Add(time.Minute) },
	)
	if _, err := executor.ApplyCurrentNode(context.Background(), batch); !errors.Is(err, ErrTransportSwitchApplyUncertain) {
		t.Fatalf("first apply error=%v", err)
	}
	if stateStore.state.Operations[len(stateStore.state.Operations)-1].State != model.OperationCompleted || runtime.calls != 1 {
		t.Fatalf("terminal state/runtime=%+v/%+v", stateStore.state, runtime)
	}
	if _, err := executor.ApplyCurrentNode(context.Background(), batch); err != nil {
		t.Fatalf("recovery apply error=%v", err)
	}
	if runtime.calls != 1 || gateway.finalizeCalls != 1 {
		t.Fatalf("recovery repeated runtime/gateway: runtime=%+v gateway=%+v", runtime, gateway)
	}
	snapshot, err := inner.Read(context.Background())
	if err != nil || snapshot.Applied.Generation != 9 || !reflect.DeepEqual(snapshot.Desired, snapshot.Applied) || len(snapshot.Pending) != 0 {
		t.Fatalf("recovered convergence=%+v err=%v", snapshot, err)
	}
}

func transportSwitchApplyPendingState(t *testing.T) (model.State, model.Operation) {
	t.Helper()
	state := exposeSagaNodeState(t)
	intent, err := transport.NewSwitchIntentTarget(state.Nodes[0].ID, model.TransportRestricted, state.Generation)
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := transport.SwitchRequestID(intent, model.TransportStandard, 20)
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := transport.SwitchOperationID(requestID)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, time.September, 6, 12, 0, 0, 0, time.UTC)
	steps := make([]model.OperationStep, len(transport.SwitchOperationStepNames()))
	for index, name := range transport.SwitchOperationStepNames() {
		steps[index] = model.OperationStep{Name: name, State: model.OperationPending, UpdatedAt: at}
	}
	operation := model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: operationID, Type: model.OperationTransportSwitch,
		State: model.OperationPending, TargetKind: "transport", TargetID: intent.String(), RequestID: requestID,
		ExpectedGeneration: 20, DesiredGeneration: 22, Steps: steps, CreatedAt: at, UpdatedAt: at,
	}
	state.Generation++
	state.Operations = append(state.Operations, operation)
	state.Nodes[0].Gateway.PendingRequestID = requestID
	state.Nodes[0].Gateway.LastKnownGatewayGeneration = 21
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	return state, operation
}

func transportSwitchApplyConvergence(
	t *testing.T,
	operation model.Operation,
) (*FileConvergenceSnapshotStore, ApplyExecutionBatch) {
	t.Helper()
	key := ManagedResourceKey{Component: "node-role", Kind: ManagedResourceUnit, ID: "vpnctl-routing.service"}
	applied, err := NewConvergenceManifest(7, []ManagedResource{{
		Key: key, RevisionSHA256: strings.Repeat("a", 64), RuntimeSHA256: strings.Repeat("b", 64),
		ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
	}})
	if err != nil {
		t.Fatal(err)
	}
	desired, err := NewConvergenceManifest(9, []ManagedResource{{
		Key: key, RevisionSHA256: strings.Repeat("c", 64), RuntimeSHA256: strings.Repeat("d", 64),
		ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
	}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := BindPendingOperationAtGenerations(operation, 7, 9, []ManagedResourceKey{key})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := canonicalSnapshot(ConvergenceSnapshot{Desired: desired, Applied: applied, Pending: []PendingOperation{binding}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewFileConvergenceSnapshotStore(newConvergenceSnapshotStorePath(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Initialize(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	changes, err := desiredChanges(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	requested := ApplyOperation{
		ID: operation.ID, Type: string(operation.Type), ExpectedGeneration: 7, DesiredGeneration: 9,
		TargetKind: operation.TargetKind, TargetID: operation.TargetID,
		Scope:  ApplyScope{Role: model.RoleNode, NodeID: exposeSagaNodeID},
		Impact: ConvergenceImpactAvailability, Changes: changes,
	}
	if err := requested.validate(); err != nil {
		t.Fatal(err)
	}
	return store, ApplyExecutionBatch{
		Role: model.RoleNode, CurrentNodeID: exposeSagaNodeID,
		AppliedGeneration: 7, DesiredGeneration: 9, Operations: []ApplyOperation{requested},
	}
}

func transportSwitchApplyReceipt(
	t *testing.T,
	operation model.Operation,
	previous model.TransportKind,
	expectedGatewayGeneration uint64,
	gatewayGeneration uint64,
) transport.FinalizedSwitchReceipt {
	t.Helper()
	intent, err := transport.ParseSwitchIntentTarget(operation.TargetID)
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := transport.SwitchFinalizeRequestID(operation.ID, intent.DesiredNodeGeneration, expectedGatewayGeneration)
	if err != nil {
		t.Fatal(err)
	}
	receipt := transport.FinalizedSwitchReceipt{
		OperationID: operation.ID, RequestID: requestID, NodeID: intent.NodeID,
		Previous: previous, Active: intent.Target,
		ExpectedGatewayGeneration: expectedGatewayGeneration, GatewayGeneration: gatewayGeneration,
		ExpectedNodeGeneration: intent.ExpectedNodeGeneration, DesiredNodeGeneration: intent.DesiredNodeGeneration,
	}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	return receipt
}

type transportSwitchApplyStateStore struct {
	state model.State
}

func (store *transportSwitchApplyStateStore) Load() (model.State, error) { return store.state, nil }

func (store *transportSwitchApplyStateStore) Save(expected uint64, candidate model.State) error {
	if expected != store.state.Generation {
		return errors.New("synthetic state conflict")
	}
	store.state = candidate
	return nil
}

type transportSwitchApplyActivation struct{ rollbacks int }

func (activation *transportSwitchApplyActivation) Result() (transport.SwitchResult, error) {
	return transport.SwitchResult{}, nil
}

func (activation *transportSwitchApplyActivation) Rollback(context.Context) error {
	activation.rollbacks++
	return nil
}

type transportSwitchApplyRuntime struct {
	calls      int
	activation transportSwitchApplyActivation
}

func (runtime *transportSwitchApplyRuntime) Activate(context.Context, model.State, model.Operation) (transport.DeferredActivation, error) {
	runtime.calls++
	return &runtime.activation, nil
}

type transportSwitchApplyGateway struct {
	reconcile         transport.FinalizedSwitchReceipt
	reconcileComplete bool
	reconcileErr      error
	reconcileErrors   []error
	finalize          transport.FinalizedSwitchReceipt
	finalizeErr       error
	reconcileCalls    int
	finalizeCalls     int
}

func (gateway *transportSwitchApplyGateway) ReconcileDeferred(context.Context, model.Operation, model.TransportKind) (transport.FinalizedSwitchReceipt, bool, error) {
	gateway.reconcileCalls++
	if index := gateway.reconcileCalls - 1; index < len(gateway.reconcileErrors) {
		return gateway.reconcile, gateway.reconcileComplete, gateway.reconcileErrors[index]
	}
	return gateway.reconcile, gateway.reconcileComplete, gateway.reconcileErr
}

func (gateway *transportSwitchApplyGateway) FinalizeDeferred(_ context.Context, _ model.Operation, _ model.TransportKind, expected uint64) (transport.FinalizedSwitchReceipt, error) {
	gateway.finalizeCalls++
	if gateway.finalize.ExpectedGatewayGeneration != 0 && gateway.finalize.ExpectedGatewayGeneration != expected {
		return transport.FinalizedSwitchReceipt{}, errors.New("unexpected gateway generation")
	}
	return gateway.finalize, gateway.finalizeErr
}

type transportSwitchApplyGeneration struct {
	generation uint64
	err        error
	calls      int
}

func (probe *transportSwitchApplyGeneration) GatewayGeneration(context.Context, string) (uint64, error) {
	probe.calls++
	return probe.generation, probe.err
}

type failingTransportSwitchConvergence struct {
	inner   *FileConvergenceSnapshotStore
	failCAS bool
}

func (store *failingTransportSwitchConvergence) Read(ctx context.Context) (ConvergenceSnapshot, error) {
	return store.inner.Read(ctx)
}

func (store *failingTransportSwitchConvergence) EnsureInitialized(ctx context.Context, snapshot ConvergenceSnapshot) (bool, error) {
	return store.inner.EnsureInitialized(ctx, snapshot)
}

func (store *failingTransportSwitchConvergence) CompareAndSwap(
	ctx context.Context,
	expected ConvergenceSnapshot,
	candidate ConvergenceSnapshot,
) (bool, error) {
	if store.failCAS {
		store.failCAS = false
		return false, errors.New("synthetic convergence commit failure")
	}
	return store.inner.CompareAndSwap(ctx, expected, candidate)
}
