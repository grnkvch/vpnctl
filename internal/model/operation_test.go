package model

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestOperationSagaTransitions(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	operation := pendingOperation(testUUID(201), testUUID(202), createdAt)
	states := []OperationState{OperationStaging, OperationActive, OperationDegraded, OperationActive, OperationCompleted}
	for index, state := range states {
		at := createdAt.Add(time.Duration(index+1) * time.Minute)
		updated, err := operation.Transition(state, at, "")
		if err != nil {
			t.Fatalf("Transition(%s) error = %v", state, err)
		}
		operation = updated
	}
	if operation.State != OperationCompleted {
		t.Fatalf("final operation state = %s", operation.State)
	}
	if _, err := operation.Transition(OperationActive, createdAt.Add(time.Hour), ""); !errors.Is(err, ErrOperationTransition) {
		t.Fatalf("terminal Transition() error = %v", err)
	}

	failed, err := pendingOperation(testUUID(203), testUUID(204), createdAt).Transition(OperationFailed, createdAt.Add(time.Minute), "gateway_conflict")
	if err != nil || failed.State != OperationFailed || failed.ErrorCode != "gateway_conflict" {
		t.Fatalf("failed Transition() = %#v, %v", failed, err)
	}
	repeated, err := failed.Transition(OperationFailed, createdAt, "gateway_conflict")
	if err != nil || !reflect.DeepEqual(repeated, failed) {
		t.Fatalf("idempotent failed Transition() = %#v, %v", repeated, err)
	}
	if _, err := failed.Transition(OperationFailed, createdAt, "different_error"); !errors.Is(err, ErrOperationTransition) {
		t.Fatalf("changed failed result error = %v", err)
	}
}

func TestOperationStepTransitions(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	operation := pendingOperation(testUUID(210), testUUID(211), createdAt)
	operation.Steps = []OperationStep{{Name: "stage", State: OperationPending, UpdatedAt: createdAt}}
	staged, err := operation.TransitionStep("stage", OperationStaging, createdAt.Add(time.Minute))
	if err != nil || staged.Steps[0].State != OperationStaging {
		t.Fatalf("TransitionStep() = %#v, %v", staged, err)
	}
	if operation.Steps[0].State != OperationPending {
		t.Fatal("TransitionStep() mutated its input")
	}
	if _, err := staged.TransitionStep("missing", OperationActive, createdAt.Add(2*time.Minute)); !errors.Is(err, ErrOperationTransition) {
		t.Fatalf("unknown TransitionStep() error = %v", err)
	}
}

func TestNodeRestartAndLostResponseResumeSameOperation(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	intent := OperationIntent{
		Type:       OperationTransportSwitch,
		TargetKind: "transport",
		TargetID:   "restricted",
		StepNames:  []string{"stage", "activate", "confirm"},
	}
	ids := sequentialUUIDs(300, 301)
	started, operation, resumed, err := nodeState().BeginNodeOperation(intent, createdAt, ids)
	if err != nil || resumed {
		t.Fatalf("BeginNodeOperation() resumed = %t, error = %v", resumed, err)
	}
	if operation.ID != testUUID(300) || operation.RequestID != testUUID(301) || operation.State != OperationPending {
		t.Fatalf("new operation = %#v", operation)
	}
	if got := started.Nodes[0].Gateway.PendingRequestID; got != operation.RequestID {
		t.Fatalf("pending request ID = %q, want %q", got, operation.RequestID)
	}

	// Simulate a node process restart by crossing the durable JSON boundary.
	encoded, err := EncodeState(started)
	if err != nil {
		t.Fatalf("encode started node state: %v", err)
	}
	restarted, err := DecodeState(encoded)
	if err != nil {
		t.Fatalf("decode restarted node state: %v", err)
	}
	generatorCalls := 0
	mustNotGenerate := func() (string, error) {
		generatorCalls++
		return "", errors.New("UUID generator must not run while a request is pending")
	}
	resumedState, replay, resumed, err := restarted.BeginNodeOperation(OperationIntent{}, createdAt.Add(time.Minute), mustNotGenerate)
	if err != nil || !resumed || generatorCalls != 0 {
		t.Fatalf("restarted BeginNodeOperation() resumed = %t, calls = %d, error = %v", resumed, generatorCalls, err)
	}
	if replay.ID != operation.ID || replay.RequestID != operation.RequestID || len(resumedState.Operations) != len(started.Operations) {
		t.Fatalf("restart created or selected a different operation: %#v", replay)
	}
	resumedJSON, err := EncodeState(resumedState)
	if err != nil {
		t.Fatalf("encode resumed state: %v", err)
	}
	if !bytes.Equal(resumedJSON, encoded) {
		t.Fatal("resuming a pending request mutated durable node state")
	}

	// The gateway committed while the response was lost and retained only the
	// redacted result. Replaying the same ID retrieves that result.
	gatewayNode := gatewayState().Nodes[0]
	result := IdempotencyRecord{
		RequestID:       operation.RequestID,
		Operation:       operation.Type,
		ResultStatus:    ResultOK,
		ResultHash:      digest("7"),
		StateGeneration: operation.DesiredGeneration,
		RecordedAt:      createdAt.Add(2 * time.Minute),
	}
	gatewayNode, _, replayed, err := gatewayNode.StoreIdempotencyResult(result, createdAt.Add(2*time.Minute))
	if err != nil || replayed {
		t.Fatalf("gateway StoreIdempotencyResult() replayed = %t, error = %v", replayed, err)
	}
	stored, err := gatewayNode.FindIdempotencyResult(operation.RequestID, createdAt.Add(3*time.Minute))
	if err != nil || stored != result {
		t.Fatalf("gateway FindIdempotencyResult() = %#v, %v", stored, err)
	}

	resolved, completed, err := resumedState.AdvancePendingNodeOperation(operation.RequestID, OperationCompleted, stored.StateGeneration, "", createdAt.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("AdvancePendingNodeOperation(completed) error = %v", err)
	}
	if completed.ID != operation.ID || completed.State != OperationCompleted || resolved.Nodes[0].Gateway.PendingRequestID != "" {
		t.Fatalf("resolved operation/state = %#v / %#v", completed, resolved.Nodes[0].Gateway)
	}
	if resolved.Nodes[0].Gateway.LastKnownGatewayGeneration != operation.DesiredGeneration {
		t.Fatalf("last known gateway generation = %d", resolved.Nodes[0].Gateway.LastKnownGatewayGeneration)
	}

	next, nextOperation, resumed, err := resolved.BeginNodeOperation(
		OperationIntent{Type: OperationApply, TargetKind: "policy", TargetID: nodeID, StepNames: []string{}},
		createdAt.Add(4*time.Minute), sequentialUUIDs(302, 303),
	)
	if err != nil || resumed || nextOperation.RequestID == operation.RequestID || len(next.Operations) != len(resolved.Operations)+1 {
		t.Fatalf("next BeginNodeOperation() = %#v, resumed=%t, error=%v", nextOperation, resumed, err)
	}
}

func TestDegradedNodeOperationRetainsPendingRequest(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	started, operation, _, err := nodeState().BeginNodeOperation(
		OperationIntent{Type: OperationRotate, TargetKind: "node", TargetID: nodeID, StepNames: []string{}},
		createdAt, sequentialUUIDs(320, 321),
	)
	if err != nil {
		t.Fatalf("BeginNodeOperation() error = %v", err)
	}
	degraded, current, err := started.AdvancePendingNodeOperation(operation.RequestID, OperationDegraded, operation.ExpectedGeneration, "", createdAt.Add(time.Minute))
	if err != nil {
		t.Fatalf("AdvancePendingNodeOperation(degraded) error = %v", err)
	}
	if current.State != OperationDegraded || degraded.Nodes[0].Gateway.PendingRequestID != operation.RequestID {
		t.Fatalf("degraded operation lost pending request: %#v", current)
	}
	_, replay, resumed, err := degraded.BeginNodeOperation(OperationIntent{}, createdAt.Add(2*time.Minute), sequentialUUIDs(322))
	if err != nil || !resumed || replay.ID != operation.ID {
		t.Fatalf("degraded BeginNodeOperation() = %#v, resumed=%t, error=%v", replay, resumed, err)
	}
}

func TestStateRejectsInvalidOperationRequestLinks(t *testing.T) {
	t.Parallel()

	state := gatewayState()
	duplicate := state.Operations[0]
	duplicate.ID = testUUID(401)
	state.Operations = append(state.Operations, duplicate)
	if err := state.Validate(); err == nil {
		t.Fatal("State.Validate() accepted duplicate operation request ID")
	}

	state = nodeState()
	state.Operations[0].State = OperationPending
	state.Operations[0].UpdatedAt = state.Operations[0].CreatedAt
	state.Operations[0].Steps[0].State = OperationPending
	state.Operations[0].Steps[0].UpdatedAt = state.Operations[0].CreatedAt
	if err := state.Validate(); err == nil {
		t.Fatal("State.Validate() accepted a non-terminal node request without pending_request_id")
	}

	state.Nodes[0].Gateway.PendingRequestID = state.Operations[0].RequestID
	if err := state.Validate(); err != nil {
		t.Fatalf("State.Validate() rejected linked pending request: %v", err)
	}
	state.Operations[0].State = OperationCompleted
	state.Operations[0].Steps[0].State = OperationCompleted
	if err := state.Validate(); err == nil {
		t.Fatal("State.Validate() accepted pending_request_id linked to a terminal operation")
	}
}

func TestStateTransitionGuardsOperationSaga(t *testing.T) {
	t.Parallel()

	before := gatewayState()
	after := cloneState(t, before)
	after.Generation++
	after.Operations[0].State = OperationActive
	if err := ValidateTransition(before, after); err == nil {
		t.Fatal("ValidateTransition() accepted terminal operation regression")
	}

	after = cloneState(t, before)
	after.Generation++
	after.Operations[0].RequestID = testUUID(410)
	if err := ValidateTransition(before, after); err == nil {
		t.Fatal("ValidateTransition() accepted operation request identity replacement")
	}

	after = cloneState(t, before)
	after.Generation++
	newOperation := pendingOperation(testUUID(411), testUUID(412), before.Host.InitializedAt.Add(time.Hour))
	newOperation.State = OperationActive
	after.Operations = append(after.Operations, newOperation)
	if err := ValidateTransition(before, after); err == nil {
		t.Fatal("ValidateTransition() accepted a new active operation")
	}
}

func pendingOperation(id, requestID string, createdAt time.Time) Operation {
	return Operation{
		SchemaVersion:      ResourceSchemaVersion,
		ID:                 id,
		Type:               OperationApply,
		State:              OperationPending,
		TargetKind:         "policy",
		TargetID:           nodeID,
		RequestID:          requestID,
		ExpectedGeneration: 7,
		DesiredGeneration:  8,
		Steps:              []OperationStep{},
		CreatedAt:          createdAt,
		UpdatedAt:          createdAt,
	}
}

func sequentialUUIDs(values ...uint64) UUIDGenerator {
	index := 0
	return func() (string, error) {
		if index >= len(values) {
			return "", errors.New("UUID fixture exhausted")
		}
		value := testUUID(values[index])
		index++
		return value, nil
	}
}
