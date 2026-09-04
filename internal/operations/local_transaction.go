package operations

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

const (
	DefaultLocalTransactionStepTimeout     = 30 * time.Second
	DefaultLocalTransactionRollbackTimeout = 15 * time.Second
	minimumLocalTransactionTimeout         = 10 * time.Millisecond
	maximumLocalTransactionTimeout         = 5 * time.Minute
)

var (
	ErrLocalTransactionInvalid   = errors.New("invalid local component transaction")
	ErrLocalTransactionConflict  = errors.New("local component generation conflict")
	ErrLocalTransactionFinalize  = errors.New("local component cleanup remains pending")
	ErrLocalTransactionRollback  = errors.New("local component rollback failed")
	ErrLocalTransactionUncertain = errors.New("local component generation is uncertain")
)

type LocalTransactionPhase string

const (
	LocalPhaseInspect  LocalTransactionPhase = "inspect"
	LocalPhaseValidate LocalTransactionPhase = "validate"
	LocalPhaseStage    LocalTransactionPhase = "stage"
	LocalPhaseActivate LocalTransactionPhase = "activate"
	LocalPhaseHealth   LocalTransactionPhase = "health"
	LocalPhaseCommit   LocalTransactionPhase = "commit"
	LocalPhaseDiscard  LocalTransactionPhase = "discard"
	LocalPhaseRollback LocalTransactionPhase = "rollback"
	LocalPhaseVerify   LocalTransactionPhase = "verify"
)

type LocalTransactionState string

const (
	LocalTransactionPrepared   LocalTransactionState = "prepared"
	LocalTransactionActive     LocalTransactionState = "active"
	LocalTransactionCommitted  LocalTransactionState = "committed"
	LocalTransactionRolledBack LocalTransactionState = "rolled_back"
	LocalTransactionUncertain  LocalTransactionState = "uncertain"
)

// LocalGeneration is the exact non-secret identity of one component runtime.
// Generation zero represents a component that has never been applied. A
// positive generation may intentionally be absent after a managed deletion.
type LocalGeneration struct {
	Generation     uint64 `json:"generation"`
	Present        bool   `json:"present"`
	RevisionSHA256 string `json:"revision_sha256,omitempty"`
	RuntimeSHA256  string `json:"runtime_sha256,omitempty"`
}

type LocalCandidateDescriptor struct {
	Component string          `json:"component"`
	Expected  LocalGeneration `json:"expected"`
	Desired   LocalGeneration `json:"desired"`
}

type LocalActivationDescriptor struct {
	Component string          `json:"component"`
	Previous  LocalGeneration `json:"previous"`
	Active    LocalGeneration `json:"active"`
}

// LocalCandidate, LocalStagedCandidate, and LocalActivation deliberately
// expose only descriptors. Provider-private bytes and rollback handles remain
// opaque to this package and must never be formatted into an error or result.
type LocalCandidate interface {
	LocalCandidateDescriptor() LocalCandidateDescriptor
}

type LocalStagedCandidate interface {
	LocalCandidateDescriptor() LocalCandidateDescriptor
}

type LocalActivation interface {
	LocalActivationDescriptor() LocalActivationDescriptor
}

// LocalComponentAdapter owns all component-specific mutation. Stage and
// Activate may return a handle together with an error when cleanup or rollback
// is required. An error without a handle promises that the prior active
// generation is unchanged. Commit is final cleanup after the caller has
// durably committed authoritative state; its error must keep desired active.
type LocalComponentAdapter interface {
	Component() string
	Current(context.Context) (LocalGeneration, error)
	Validate(context.Context, LocalCandidate) error
	Stage(context.Context, LocalCandidate) (LocalStagedCandidate, error)
	Activate(context.Context, LocalStagedCandidate) (LocalActivation, error)
	Health(context.Context, LocalActivation) error
	Commit(context.Context, LocalActivation) error
	Discard(context.Context, LocalStagedCandidate) error
	Rollback(context.Context, LocalActivation) error
}

type LocalTransactionLimits struct {
	Step     time.Duration
	Rollback time.Duration
}

type LocalTransactionResult struct {
	Component      string                `json:"component"`
	Previous       LocalGeneration       `json:"previous"`
	Candidate      LocalGeneration       `json:"candidate"`
	Active         LocalGeneration       `json:"active"`
	State          LocalTransactionState `json:"state"`
	Changed        bool                  `json:"changed"`
	Healthy        bool                  `json:"healthy"`
	RolledBack     bool                  `json:"rolled_back"`
	CleanupPending bool                  `json:"cleanup_pending"`
}

type LocalTransactionError struct {
	Phase LocalTransactionPhase
	Cause error
}

func (err *LocalTransactionError) Error() string {
	return fmt.Sprintf("local transaction %s failed: %v", err.Phase, err.Cause)
}

func (err *LocalTransactionError) Unwrap() error { return err.Cause }

type PreparedLocalTransaction struct {
	mu         sync.Mutex
	adapter    LocalComponentAdapter
	staged     LocalStagedCandidate
	activation LocalActivation
	descriptor LocalCandidateDescriptor
	limits     LocalTransactionLimits
	result     LocalTransactionResult
}

func PrepareLocalTransaction(
	ctx context.Context,
	adapter LocalComponentAdapter,
	candidate LocalCandidate,
	limits LocalTransactionLimits,
) (*PreparedLocalTransaction, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if nilInterface(adapter) || nilInterface(candidate) {
		return nil, fmt.Errorf("%w: adapter and candidate are required", ErrLocalTransactionInvalid)
	}
	normalized, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	descriptor := candidate.LocalCandidateDescriptor()
	if err := descriptor.Validate(); err != nil {
		return nil, fmt.Errorf("%w: candidate descriptor: %v", ErrLocalTransactionInvalid, err)
	}
	if adapter.Component() != descriptor.Component {
		return nil, fmt.Errorf("%w: adapter component does not match candidate", ErrLocalTransactionInvalid)
	}

	current, err := runLocalStep(ctx, normalized.Step, adapter.Current)
	if err != nil {
		return nil, localTransactionError(LocalPhaseInspect, err)
	}
	if err := current.Validate(); err != nil {
		return nil, localTransactionError(LocalPhaseInspect, fmt.Errorf("%w: current generation: %v", ErrLocalTransactionInvalid, err))
	}
	if current != descriptor.Expected {
		return nil, localTransactionError(LocalPhaseInspect, fmt.Errorf("%w: expected generation %d, observed %d", ErrLocalTransactionConflict, descriptor.Expected.Generation, current.Generation))
	}

	transaction := &PreparedLocalTransaction{
		adapter: adapter, descriptor: descriptor, limits: normalized,
		result: LocalTransactionResult{
			Component: descriptor.Component, Previous: descriptor.Expected, Candidate: descriptor.Desired,
			Active: descriptor.Expected, State: LocalTransactionPrepared,
		},
	}
	if err := runLocalAction(ctx, normalized.Step, func(step context.Context) error {
		return adapter.Validate(step, candidate)
	}); err != nil {
		return nil, transaction.prepareFailure(LocalPhaseValidate, err, nil)
	}
	if descriptor.Expected == descriptor.Desired {
		transaction.result.State = LocalTransactionCommitted
		return transaction, nil
	}

	staged, stageErr := runLocalStep(ctx, normalized.Step, func(step context.Context) (LocalStagedCandidate, error) {
		return adapter.Stage(step, candidate)
	})
	if stageErr != nil {
		return nil, transaction.prepareFailure(LocalPhaseStage, stageErr, staged)
	}
	if nilInterface(staged) {
		return nil, transaction.prepareFailure(LocalPhaseStage, fmt.Errorf("%w: adapter returned no staged candidate", ErrLocalTransactionInvalid), nil)
	}
	if staged.LocalCandidateDescriptor() != descriptor {
		return nil, transaction.prepareFailure(LocalPhaseStage, fmt.Errorf("%w: staged descriptor does not match candidate", ErrLocalTransactionInvalid), staged)
	}
	transaction.staged = staged
	return transaction, nil
}

// Activate switches the staged candidate and checks exact generation plus
// component health. Any confirmed post-switch failure triggers rollback under
// an independent bounded context before the method returns.
func (transaction *PreparedLocalTransaction) Activate(ctx context.Context) (LocalTransactionResult, error) {
	if ctx == nil {
		return LocalTransactionResult{}, fmt.Errorf("context is required")
	}
	if transaction == nil || nilInterface(transaction.adapter) {
		return LocalTransactionResult{}, fmt.Errorf("%w: transaction is incomplete", ErrLocalTransactionInvalid)
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.result.State == LocalTransactionCommitted && !transaction.result.Changed {
		return transaction.result, nil
	}
	if transaction.result.State != LocalTransactionPrepared || nilInterface(transaction.staged) {
		return transaction.result, fmt.Errorf("%w: transaction is not prepared", ErrLocalTransactionInvalid)
	}

	activation, activateErr := runLocalStep(ctx, transaction.limits.Step, func(step context.Context) (LocalActivation, error) {
		return transaction.adapter.Activate(step, transaction.staged)
	})
	if !nilInterface(activation) {
		transaction.activation = activation
		transaction.result.State = LocalTransactionActive
		transaction.result.Active = transaction.descriptor.Desired
		transaction.result.Changed = true
		if activation.LocalActivationDescriptor() != (LocalActivationDescriptor{
			Component: transaction.descriptor.Component,
			Previous:  transaction.descriptor.Expected,
			Active:    transaction.descriptor.Desired,
		}) {
			activateErr = errors.Join(activateErr, fmt.Errorf("%w: activation descriptor does not match candidate", ErrLocalTransactionInvalid))
		}
	}
	if activateErr != nil {
		if nilInterface(transaction.activation) {
			failure := transaction.preActivationFailure(LocalPhaseActivate, activateErr)
			return transaction.result, failure
		}
		failure := transaction.rollbackAfter(LocalPhaseActivate, activateErr)
		return transaction.result, failure
	}
	if nilInterface(transaction.activation) {
		failure := transaction.preActivationFailure(LocalPhaseActivate, fmt.Errorf("%w: adapter returned no activation receipt", ErrLocalTransactionInvalid))
		return transaction.result, failure
	}
	if err := transaction.verify(transaction.descriptor.Desired); err != nil {
		failure := transaction.rollbackAfter(LocalPhaseVerify, err)
		return transaction.result, failure
	}
	if err := runLocalAction(ctx, transaction.limits.Step, func(step context.Context) error {
		return transaction.adapter.Health(step, transaction.activation)
	}); err != nil {
		failure := transaction.rollbackAfter(LocalPhaseHealth, err)
		return transaction.result, failure
	}
	transaction.result.Healthy = true
	return transaction.result, nil
}

// Commit finalizes a healthy candidate after the outer authoritative writer
// has durably committed its matching state generation. From this call onward
// desired is authoritative: cleanup failure is reported for later repair but
// must not roll runtime back behind committed state.
func (transaction *PreparedLocalTransaction) Commit(ctx context.Context) (LocalTransactionResult, error) {
	if ctx == nil {
		return LocalTransactionResult{}, fmt.Errorf("context is required")
	}
	if transaction == nil || nilInterface(transaction.adapter) {
		return LocalTransactionResult{}, fmt.Errorf("%w: transaction is incomplete", ErrLocalTransactionInvalid)
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.result.State == LocalTransactionCommitted && !transaction.result.Changed {
		return transaction.result, nil
	}
	if transaction.result.State != LocalTransactionActive || !transaction.result.Healthy || nilInterface(transaction.activation) {
		return transaction.result, fmt.Errorf("%w: only a healthy active transaction can commit", ErrLocalTransactionInvalid)
	}
	if err := runLocalAction(ctx, transaction.limits.Step, func(step context.Context) error {
		return transaction.adapter.Commit(step, transaction.activation)
	}); err != nil {
		transaction.result.State = LocalTransactionCommitted
		transaction.result.CleanupPending = true
		return transaction.result, localTransactionError(LocalPhaseCommit, errors.Join(ErrLocalTransactionFinalize, err))
	}
	transaction.result.State = LocalTransactionCommitted
	return transaction.result, nil
}

// Rollback is available while staged or active and is intentionally refused
// after successful commit, when the component may have discarded its snapshot.
func (transaction *PreparedLocalTransaction) Rollback() (LocalTransactionResult, error) {
	if transaction == nil || nilInterface(transaction.adapter) {
		return LocalTransactionResult{}, fmt.Errorf("%w: transaction is incomplete", ErrLocalTransactionInvalid)
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	switch transaction.result.State {
	case LocalTransactionPrepared:
		if nilInterface(transaction.staged) {
			return transaction.result, fmt.Errorf("%w: prepared transaction has no staged candidate", ErrLocalTransactionInvalid)
		}
		err := transaction.discardStaged(nil)
		return transaction.result, err
	case LocalTransactionActive:
		err := transaction.rollbackAfter(LocalPhaseRollback, nil)
		return transaction.result, err
	case LocalTransactionRolledBack:
		return transaction.result, nil
	default:
		return transaction.result, fmt.Errorf("%w: transaction in state %s cannot roll back", ErrLocalTransactionInvalid, transaction.result.State)
	}
}

func RunLocalTransaction(
	ctx context.Context,
	adapter LocalComponentAdapter,
	candidate LocalCandidate,
	limits LocalTransactionLimits,
) (LocalTransactionResult, error) {
	transaction, err := PrepareLocalTransaction(ctx, adapter, candidate, limits)
	if err != nil {
		return LocalTransactionResult{}, err
	}
	if transaction.result.State == LocalTransactionCommitted {
		return transaction.result, nil
	}
	if _, err := transaction.Activate(ctx); err != nil {
		return transaction.result, err
	}
	return transaction.Commit(ctx)
}

func (transaction *PreparedLocalTransaction) Result() LocalTransactionResult {
	if transaction == nil {
		return LocalTransactionResult{}
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	return transaction.result
}

func (transaction *PreparedLocalTransaction) prepareFailure(phase LocalTransactionPhase, cause error, staged LocalStagedCandidate) error {
	var cleanupErr error
	if !nilInterface(staged) {
		cleanupErr = transaction.discard(staged)
	}
	verifyErr := transaction.verify(transaction.descriptor.Expected)
	if cleanupErr != nil || verifyErr != nil {
		transaction.result.State = LocalTransactionUncertain
		return localTransactionError(phase, errors.Join(cause, cleanupErr, verifyErr, ErrLocalTransactionUncertain))
	}
	return localTransactionError(phase, cause)
}

func (transaction *PreparedLocalTransaction) preActivationFailure(phase LocalTransactionPhase, cause error) error {
	cleanupErr := transaction.discard(transaction.staged)
	verifyErr := transaction.verify(transaction.descriptor.Expected)
	if cleanupErr != nil || verifyErr != nil {
		transaction.result.State = LocalTransactionUncertain
		return localTransactionError(phase, errors.Join(cause, cleanupErr, verifyErr, ErrLocalTransactionUncertain))
	}
	transaction.result.State = LocalTransactionRolledBack
	transaction.result.RolledBack = true
	return localTransactionError(phase, cause)
}

func (transaction *PreparedLocalTransaction) rollbackAfter(phase LocalTransactionPhase, cause error) error {
	rollbackErr := transaction.rollback()
	if rollbackErr != nil {
		transaction.result.State = LocalTransactionUncertain
		return localTransactionError(phase, errors.Join(cause, rollbackErr, ErrLocalTransactionRollback, ErrLocalTransactionUncertain))
	}
	transaction.result.State = LocalTransactionRolledBack
	transaction.result.Active = transaction.descriptor.Expected
	transaction.result.Healthy = false
	transaction.result.RolledBack = true
	if cause == nil {
		return nil
	}
	return localTransactionError(phase, cause)
}

func (transaction *PreparedLocalTransaction) discardStaged(cause error) error {
	discardErr := transaction.discard(transaction.staged)
	verifyErr := transaction.verify(transaction.descriptor.Expected)
	if discardErr != nil || verifyErr != nil {
		transaction.result.State = LocalTransactionUncertain
		return localTransactionError(LocalPhaseDiscard, errors.Join(cause, discardErr, verifyErr, ErrLocalTransactionUncertain))
	}
	transaction.result.State = LocalTransactionRolledBack
	transaction.result.RolledBack = true
	return cause
}

func (transaction *PreparedLocalTransaction) discard(staged LocalStagedCandidate) error {
	cleanup, cancel := context.WithTimeout(context.Background(), transaction.limits.Rollback)
	defer cancel()
	if err := transaction.adapter.Discard(cleanup, staged); err != nil {
		return fmt.Errorf("discard staged component: %w", err)
	}
	return nil
}

func (transaction *PreparedLocalTransaction) rollback() error {
	cleanup, cancel := context.WithTimeout(context.Background(), transaction.limits.Rollback)
	defer cancel()
	if err := transaction.adapter.Rollback(cleanup, transaction.activation); err != nil {
		return fmt.Errorf("rollback active component: %w", err)
	}
	if err := transaction.verifyWithContext(cleanup, transaction.descriptor.Expected); err != nil {
		return err
	}
	return nil
}

func (transaction *PreparedLocalTransaction) verify(expected LocalGeneration) error {
	verifyContext, cancel := context.WithTimeout(context.Background(), transaction.limits.Rollback)
	defer cancel()
	return transaction.verifyWithContext(verifyContext, expected)
}

func (transaction *PreparedLocalTransaction) verifyWithContext(ctx context.Context, expected LocalGeneration) error {
	observed, err := transaction.adapter.Current(ctx)
	if err != nil {
		return fmt.Errorf("verify active generation: %w", err)
	}
	if err := observed.Validate(); err != nil {
		return fmt.Errorf("verify active generation: %w", err)
	}
	if observed != expected {
		return fmt.Errorf("%w: expected generation %d, observed %d", ErrLocalTransactionUncertain, expected.Generation, observed.Generation)
	}
	return nil
}

func (limits LocalTransactionLimits) normalized() (LocalTransactionLimits, error) {
	if limits.Step == 0 {
		limits.Step = DefaultLocalTransactionStepTimeout
	}
	if limits.Rollback == 0 {
		limits.Rollback = DefaultLocalTransactionRollbackTimeout
	}
	for _, value := range []struct {
		name    string
		timeout time.Duration
	}{{"step", limits.Step}, {"rollback", limits.Rollback}} {
		if value.timeout < minimumLocalTransactionTimeout || value.timeout > maximumLocalTransactionTimeout {
			return LocalTransactionLimits{}, fmt.Errorf("local transaction %s timeout must be between %s and %s", value.name, minimumLocalTransactionTimeout, maximumLocalTransactionTimeout)
		}
	}
	return limits, nil
}

func (generation LocalGeneration) Validate() error {
	if generation.Generation == 0 {
		if generation.Present || generation.RevisionSHA256 != "" || generation.RuntimeSHA256 != "" {
			return fmt.Errorf("generation zero must be absent and unhashed")
		}
		return nil
	}
	if !generation.Present {
		if generation.RevisionSHA256 != "" || generation.RuntimeSHA256 != "" {
			return fmt.Errorf("absent generation must not carry hashes")
		}
		return nil
	}
	if err := validateFingerprint(generation.RevisionSHA256); err != nil {
		return fmt.Errorf("revision: %w", err)
	}
	if err := validateFingerprint(generation.RuntimeSHA256); err != nil {
		return fmt.Errorf("runtime: %w", err)
	}
	return nil
}

func (descriptor LocalCandidateDescriptor) Validate() error {
	if !resourceComponentPattern.MatchString(descriptor.Component) {
		return fmt.Errorf("component must be a stable lower-case identifier")
	}
	if err := descriptor.Expected.Validate(); err != nil {
		return fmt.Errorf("expected generation: %w", err)
	}
	if err := descriptor.Desired.Validate(); err != nil {
		return fmt.Errorf("desired generation: %w", err)
	}
	if descriptor.Desired == descriptor.Expected {
		return nil
	}
	if descriptor.Desired.Generation <= descriptor.Expected.Generation {
		return fmt.Errorf("changed desired generation must advance expected generation")
	}
	return nil
}

func localTransactionError(phase LocalTransactionPhase, cause error) error {
	return &LocalTransactionError{Phase: phase, Cause: cause}
}

func runLocalAction(ctx context.Context, timeout time.Duration, action func(context.Context) error) error {
	_, err := runLocalStep(ctx, timeout, func(step context.Context) (struct{}, error) {
		return struct{}{}, action(step)
	})
	return err
}

func runLocalStep[T any](ctx context.Context, timeout time.Duration, action func(context.Context) (T, error)) (T, error) {
	stepContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return action(stepContext)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
