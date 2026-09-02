package model

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

var (
	ErrOperationTransition = errors.New("invalid operation transition")
	ErrPendingRequest      = errors.New("another node request is pending")
)

type OperationIntent struct {
	Type       OperationType
	TargetKind string
	TargetID   string
	StepNames  []string
}

// BeginNodeOperation durably registers a node-to-gateway request. If a prior
// request is still uncertain, it returns that operation unchanged and does not
// call the UUID generator. The caller must replay/reconcile the retained ID
// before attempting a different mutation.
func (state State) BeginNodeOperation(intent OperationIntent, at time.Time, generator UUIDGenerator) (State, Operation, bool, error) {
	if err := state.Validate(); err != nil {
		return State{}, Operation{}, false, fmt.Errorf("validate node state: %w", err)
	}
	if state.Host.Role != RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Gateway == nil {
		return State{}, Operation{}, false, fmt.Errorf("begin node operation requires an enrolled node state")
	}
	if pending, found, err := state.PendingNodeOperation(); err != nil {
		return State{}, Operation{}, false, err
	} else if found {
		return state, pending, true, nil
	}
	if err := intent.Validate(); err != nil {
		return State{}, Operation{}, false, err
	}
	if err := validateTime("created_at", at); err != nil {
		return State{}, Operation{}, false, err
	}

	occupied := make(map[string]struct{}, len(state.Operations)*2+2)
	for _, operation := range state.Operations {
		occupied[operation.ID] = struct{}{}
		if operation.RequestID != "" {
			occupied[operation.RequestID] = struct{}{}
		}
	}
	operationID, err := AllocateUUID(occupied, generator)
	if err != nil {
		return State{}, Operation{}, false, fmt.Errorf("allocate operation ID: %w", err)
	}
	requestID, err := AllocateUUID(occupied, generator)
	if err != nil {
		return State{}, Operation{}, false, fmt.Errorf("allocate request ID: %w", err)
	}
	desiredGeneration, err := NextGeneration(state.Nodes[0].Gateway.LastKnownGatewayGeneration)
	if err != nil {
		return State{}, Operation{}, false, fmt.Errorf("desired gateway %w", err)
	}
	localGeneration, err := NextGeneration(state.Generation)
	if err != nil {
		return State{}, Operation{}, false, fmt.Errorf("local state %w", err)
	}

	steps := make([]OperationStep, len(intent.StepNames))
	for index, name := range intent.StepNames {
		steps[index] = OperationStep{Name: name, State: OperationPending, UpdatedAt: at}
	}
	operation := Operation{
		SchemaVersion:      ResourceSchemaVersion,
		ID:                 operationID,
		Type:               intent.Type,
		State:              OperationPending,
		TargetKind:         intent.TargetKind,
		TargetID:           intent.TargetID,
		RequestID:          requestID,
		ExpectedGeneration: state.Nodes[0].Gateway.LastKnownGatewayGeneration,
		DesiredGeneration:  desiredGeneration,
		Steps:              steps,
		CreatedAt:          at,
		UpdatedAt:          at,
	}
	if err := operation.Validate(); err != nil {
		return State{}, Operation{}, false, fmt.Errorf("validate new operation: %w", err)
	}

	candidate := state
	candidate.Generation = localGeneration
	candidate.Operations = append(append([]Operation(nil), state.Operations...), operation)
	candidate.Nodes = append([]Node(nil), state.Nodes...)
	trust := *state.Nodes[0].Gateway
	trust.PendingRequestID = requestID
	candidate.Nodes[0].Gateway = &trust
	if err := ValidateTransition(state, candidate); err != nil {
		return State{}, Operation{}, false, fmt.Errorf("persist pending node operation: %w", err)
	}
	return candidate, operation, false, nil
}

func (state State) PendingNodeOperation() (Operation, bool, error) {
	if err := state.Validate(); err != nil {
		return Operation{}, false, fmt.Errorf("validate node state: %w", err)
	}
	if state.Host.Role != RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Gateway == nil {
		return Operation{}, false, fmt.Errorf("pending node operation requires an enrolled node state")
	}
	requestID := state.Nodes[0].Gateway.PendingRequestID
	if requestID == "" {
		return Operation{}, false, nil
	}
	for _, operation := range state.Operations {
		if operation.RequestID == requestID {
			return operation, true, nil
		}
	}
	return Operation{}, false, fmt.Errorf("%w: request %s has no operation record", ErrPendingRequest, requestID)
}

// AdvancePendingNodeOperation persists a gateway-observed saga phase. The
// request ID remains pinned until a completed or failed result is definitive.
func (state State) AdvancePendingNodeOperation(requestID string, next OperationState, resultingGatewayGeneration uint64, errorCode string, at time.Time) (State, Operation, error) {
	if err := state.Validate(); err != nil {
		return State{}, Operation{}, fmt.Errorf("validate node state: %w", err)
	}
	if state.Host.Role != RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Gateway == nil {
		return State{}, Operation{}, fmt.Errorf("advance node operation requires an enrolled node state")
	}
	if state.Nodes[0].Gateway.PendingRequestID != requestID {
		return State{}, Operation{}, fmt.Errorf("%w: retained request is %q, got %q", ErrPendingRequest, state.Nodes[0].Gateway.PendingRequestID, requestID)
	}
	if resultingGatewayGeneration == 0 {
		return State{}, Operation{}, fmt.Errorf("resulting gateway generation must be positive")
	}

	operationIndex := -1
	for index, operation := range state.Operations {
		if operation.RequestID == requestID {
			operationIndex = index
			break
		}
	}
	if operationIndex < 0 {
		return State{}, Operation{}, fmt.Errorf("%w: request %s has no operation record", ErrPendingRequest, requestID)
	}
	updated, err := state.Operations[operationIndex].Transition(next, at, errorCode)
	if err != nil {
		return State{}, Operation{}, err
	}

	trust := *state.Nodes[0].Gateway
	if resultingGatewayGeneration > trust.LastKnownGatewayGeneration {
		trust.LastKnownGatewayGeneration = resultingGatewayGeneration
	}
	if terminalOperationState(next) {
		trust.PendingRequestID = ""
	}
	if reflect.DeepEqual(updated, state.Operations[operationIndex]) && reflect.DeepEqual(trust, *state.Nodes[0].Gateway) {
		return state, updated, nil
	}

	localGeneration, err := NextGeneration(state.Generation)
	if err != nil {
		return State{}, Operation{}, fmt.Errorf("local state %w", err)
	}
	candidate := state
	candidate.Generation = localGeneration
	candidate.Operations = append([]Operation(nil), state.Operations...)
	candidate.Operations[operationIndex] = updated
	candidate.Nodes = append([]Node(nil), state.Nodes...)
	candidate.Nodes[0].Gateway = &trust
	if err := ValidateTransition(state, candidate); err != nil {
		return State{}, Operation{}, fmt.Errorf("persist node operation phase: %w", err)
	}
	return candidate, updated, nil
}

func (intent OperationIntent) Validate() error {
	if !validOperationType(intent.Type) {
		return invalid("type", "unsupported value %q", intent.Type)
	}
	if (intent.TargetKind == "") != (intent.TargetID == "") {
		return invalid("target", "kind and id must be present together")
	}
	if intent.TargetID != "" {
		if !validOperationTarget(intent.TargetKind) {
			return invalid("target_kind", "unsupported value %q", intent.TargetKind)
		}
		if strings.TrimSpace(intent.TargetID) == "" || len(intent.TargetID) > 128 || strings.ContainsAny(intent.TargetID, "\r\n") {
			return invalid("target_id", "must be a non-empty, single-line resource reference of at most 128 bytes")
		}
	}
	if intent.StepNames == nil {
		return invalid("step_names", "must be present")
	}
	seen := make(map[string]struct{}, len(intent.StepNames))
	for index, name := range intent.StepNames {
		if !componentPattern.MatchString(name) {
			return invalid(indexPath("step_names", index), "must be a stable lower-case identifier")
		}
		if _, duplicate := seen[name]; duplicate {
			return invalid(indexPath("step_names", index), "duplicates a step")
		}
		seen[name] = struct{}{}
	}
	return nil
}

func (operation Operation) Transition(next OperationState, at time.Time, errorCode string) (Operation, error) {
	if err := operation.Validate(); err != nil {
		return Operation{}, fmt.Errorf("validate operation: %w", err)
	}
	if operation.State == next {
		if (next == OperationFailed && operation.ErrorCode == errorCode) || (next != OperationFailed && errorCode == "") {
			return operation, nil
		}
		return Operation{}, fmt.Errorf("%w: repeated %s state has different error metadata", ErrOperationTransition, next)
	}
	if !canTransitionOperation(operation.State, next) {
		return Operation{}, fmt.Errorf("%w: cannot move from %s to %s", ErrOperationTransition, operation.State, next)
	}
	if err := validateTime("updated_at", at); err != nil {
		return Operation{}, err
	}
	if at.Before(operation.UpdatedAt) {
		return Operation{}, fmt.Errorf("%w: update time cannot move backwards", ErrOperationTransition)
	}
	operation.State = next
	operation.UpdatedAt = at
	operation.ErrorCode = errorCode
	if err := operation.Validate(); err != nil {
		return Operation{}, fmt.Errorf("validate transitioned operation: %w", err)
	}
	return operation, nil
}

func (operation Operation) TransitionStep(name string, next OperationState, at time.Time) (Operation, error) {
	if err := operation.Validate(); err != nil {
		return Operation{}, fmt.Errorf("validate operation: %w", err)
	}
	if terminalOperationState(operation.State) {
		return Operation{}, fmt.Errorf("%w: terminal operation steps cannot change", ErrOperationTransition)
	}
	for index, step := range operation.Steps {
		if step.Name != name {
			continue
		}
		if step.State == next {
			return operation, nil
		}
		if !canTransitionOperation(step.State, next) {
			return Operation{}, fmt.Errorf("%w: step %s cannot move from %s to %s", ErrOperationTransition, name, step.State, next)
		}
		if err := validateTime("updated_at", at); err != nil {
			return Operation{}, err
		}
		if at.Before(step.UpdatedAt) || at.Before(operation.UpdatedAt) {
			return Operation{}, fmt.Errorf("%w: update time cannot move backwards", ErrOperationTransition)
		}
		operation.Steps = append([]OperationStep(nil), operation.Steps...)
		operation.Steps[index].State = next
		operation.Steps[index].UpdatedAt = at
		operation.UpdatedAt = at
		return operation, nil
	}
	return Operation{}, fmt.Errorf("%w: unknown step %q", ErrOperationTransition, name)
}

func canTransitionOperation(current, next OperationState) bool {
	switch current {
	case OperationPending:
		return next == OperationStaging || next == OperationActive || next == OperationDegraded || next == OperationFailed || next == OperationCompleted
	case OperationStaging:
		return next == OperationActive || next == OperationDegraded || next == OperationFailed || next == OperationCompleted
	case OperationActive:
		return next == OperationDegraded || next == OperationFailed || next == OperationCompleted
	case OperationDegraded:
		return next == OperationStaging || next == OperationActive || next == OperationFailed || next == OperationCompleted
	default:
		return false
	}
}

func terminalOperationState(state OperationState) bool {
	return state == OperationFailed || state == OperationCompleted
}
