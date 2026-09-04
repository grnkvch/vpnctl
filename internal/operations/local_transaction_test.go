package operations

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestLocalTransactionFailureMatrixRestoresExactPreviousGeneration(t *testing.T) {
	t.Parallel()

	previous := localGeneration(4, "previous")
	desired := localGeneration(5, "desired")
	tests := []struct {
		name            string
		failPhase       string
		stageHandle     bool
		activateChanged bool
		wrongStage      bool
		wrongActivation bool
		wrongGeneration bool
		wantPhase       LocalTransactionPhase
		wantCalls       []string
	}{
		{name: "validate", failPhase: "validate", wantPhase: LocalPhaseValidate, wantCalls: []string{"current", "validate", "current"}},
		{name: "stage without handle", failPhase: "stage", wantPhase: LocalPhaseStage, wantCalls: []string{"current", "validate", "stage", "current"}},
		{name: "stage with handle", failPhase: "stage", stageHandle: true, wantPhase: LocalPhaseStage, wantCalls: []string{"current", "validate", "stage", "discard", "current"}},
		{name: "stage descriptor", wrongStage: true, wantPhase: LocalPhaseStage, wantCalls: []string{"current", "validate", "stage", "discard", "current"}},
		{name: "activate before switch", failPhase: "activate", wantPhase: LocalPhaseActivate, wantCalls: []string{"current", "validate", "stage", "activate", "discard", "current"}},
		{name: "activate after switch", failPhase: "activate", activateChanged: true, wantPhase: LocalPhaseActivate, wantCalls: []string{"current", "validate", "stage", "activate", "rollback", "current"}},
		{name: "activation descriptor", wrongActivation: true, wantPhase: LocalPhaseActivate, wantCalls: []string{"current", "validate", "stage", "activate", "rollback", "current"}},
		{name: "post activation generation", wrongGeneration: true, wantPhase: LocalPhaseVerify, wantCalls: []string{"current", "validate", "stage", "activate", "current", "rollback", "current"}},
		{name: "health", failPhase: "health", wantPhase: LocalPhaseHealth, wantCalls: []string{"current", "validate", "stage", "activate", "current", "health", "rollback", "current"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := newLocalTransactionAdapter(previous)
			adapter.failPhase = test.failPhase
			adapter.stageHandleOnError = test.stageHandle
			adapter.activateChangedOnError = test.activateChanged
			adapter.wrongStageDescriptor = test.wrongStage
			adapter.wrongActivationDescriptor = test.wrongActivation
			adapter.wrongGenerationAfterActivate = test.wrongGeneration
			result, err := RunLocalTransaction(context.Background(), adapter, fakeLocalCandidate{descriptor: localDescriptor(previous, desired)}, localTestLimits())
			if err == nil {
				t.Fatal("RunLocalTransaction() unexpectedly succeeded")
			}
			var transactionErr *LocalTransactionError
			if !errors.As(err, &transactionErr) || transactionErr.Phase != test.wantPhase {
				t.Fatalf("transaction error = %T %v", err, err)
			}
			if adapter.current != previous {
				t.Fatalf("active generation = %+v, want previous %+v", adapter.current, previous)
			}
			if !reflect.DeepEqual(adapter.calls, test.wantCalls) {
				t.Fatalf("calls = %v, want %v", adapter.calls, test.wantCalls)
			}
			if test.wantPhase == LocalPhaseActivate || test.wantPhase == LocalPhaseVerify || test.wantPhase == LocalPhaseHealth || test.wantPhase == LocalPhaseCommit {
				if result.State != LocalTransactionRolledBack || !result.RolledBack || result.Active != previous {
					t.Fatalf("rollback result = %+v", result)
				}
			}
		})
	}
}

func TestLocalTransactionFinalizeFailureKeepsCommittedDesiredGeneration(t *testing.T) {
	t.Parallel()

	previous := localGeneration(6, "previous")
	desired := localGeneration(7, "desired")
	adapter := newLocalTransactionAdapter(previous)
	adapter.failPhase = "commit"
	result, err := RunLocalTransaction(context.Background(), adapter, fakeLocalCandidate{descriptor: localDescriptor(previous, desired)}, localTestLimits())
	if !errors.Is(err, ErrLocalTransactionFinalize) {
		t.Fatalf("finalize failure = %v", err)
	}
	var transactionErr *LocalTransactionError
	if !errors.As(err, &transactionErr) || transactionErr.Phase != LocalPhaseCommit {
		t.Fatalf("finalize transaction error = %T %v", err, err)
	}
	if result.State != LocalTransactionCommitted || !result.CleanupPending || result.RolledBack || result.Active != desired || adapter.current != desired {
		t.Fatalf("finalize result = %+v current=%+v", result, adapter.current)
	}
	wantCalls := []string{"current", "validate", "stage", "activate", "current", "health", "commit"}
	if !reflect.DeepEqual(adapter.calls, wantCalls) {
		t.Fatalf("finalize calls = %v, want %v", adapter.calls, wantCalls)
	}
}

func TestPreparedLocalTransactionKeepsRollbackUntilCommit(t *testing.T) {
	t.Parallel()

	previous := localGeneration(8, "previous")
	desired := localGeneration(9, "desired")
	adapter := newLocalTransactionAdapter(previous)
	transaction, err := PrepareLocalTransaction(context.Background(), adapter, fakeLocalCandidate{descriptor: localDescriptor(previous, desired)}, localTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result := transaction.Result(); result.State != LocalTransactionPrepared || result.Active != previous {
		t.Fatalf("prepared result = %+v", result)
	}
	activated, err := transaction.Activate(context.Background())
	if err != nil || activated.State != LocalTransactionActive || !activated.Healthy || adapter.current != desired {
		t.Fatalf("Activate() = %+v, %v; current=%+v", activated, err, adapter.current)
	}
	rolledBack, err := transaction.Rollback()
	if err != nil || rolledBack.State != LocalTransactionRolledBack || rolledBack.Active != previous || adapter.current != previous {
		t.Fatalf("Rollback() = %+v, %v; current=%+v", rolledBack, err, adapter.current)
	}

	adapter = newLocalTransactionAdapter(previous)
	transaction, err = PrepareLocalTransaction(context.Background(), adapter, fakeLocalCandidate{descriptor: localDescriptor(previous, desired)}, localTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	committed, err := transaction.Commit(context.Background())
	if err != nil || committed.State != LocalTransactionCommitted || committed.Active != desired || !committed.Changed || !committed.Healthy {
		t.Fatalf("Commit() = %+v, %v", committed, err)
	}
	if _, err := transaction.Rollback(); !errors.Is(err, ErrLocalTransactionInvalid) {
		t.Fatalf("post-commit Rollback() error = %v", err)
	}
}

func TestLocalTransactionSuccessNoopAndManagedDeletion(t *testing.T) {
	t.Parallel()

	present := localGeneration(3, "present")
	adapter := newLocalTransactionAdapter(present)
	result, err := RunLocalTransaction(context.Background(), adapter, fakeLocalCandidate{descriptor: localDescriptor(present, present)}, localTestLimits())
	if err != nil || result.State != LocalTransactionCommitted || result.Changed || result.Healthy || result.Active != present {
		t.Fatalf("no-op transaction = %+v, %v", result, err)
	}
	if !reflect.DeepEqual(adapter.calls, []string{"current", "validate"}) {
		t.Fatalf("no-op calls = %v", adapter.calls)
	}

	absent := LocalGeneration{Generation: 4, Present: false}
	adapter = newLocalTransactionAdapter(present)
	result, err = RunLocalTransaction(context.Background(), adapter, fakeLocalCandidate{descriptor: localDescriptor(present, absent)}, localTestLimits())
	if err != nil || result.State != LocalTransactionCommitted || result.Active != absent || !result.Changed || !result.Healthy {
		t.Fatalf("managed deletion = %+v, %v", result, err)
	}
	if adapter.current != absent {
		t.Fatalf("managed deletion active generation = %+v", adapter.current)
	}
}

func TestLocalTransactionRejectsStaleExpectedGenerationBeforeComponentMutation(t *testing.T) {
	t.Parallel()

	current := localGeneration(7, "current")
	expected := localGeneration(6, "expected")
	desired := localGeneration(8, "desired")
	adapter := newLocalTransactionAdapter(current)
	_, err := PrepareLocalTransaction(context.Background(), adapter, fakeLocalCandidate{descriptor: localDescriptor(expected, desired)}, localTestLimits())
	if !errors.Is(err, ErrLocalTransactionConflict) {
		t.Fatalf("PrepareLocalTransaction() error = %v", err)
	}
	if !reflect.DeepEqual(adapter.calls, []string{"current"}) || adapter.current != current {
		t.Fatalf("stale transaction touched adapter: calls=%v current=%+v", adapter.calls, adapter.current)
	}
}

func TestLocalTransactionRollbackUsesIndependentBoundedContext(t *testing.T) {
	t.Parallel()

	previous := localGeneration(11, "previous")
	desired := localGeneration(12, "desired")
	ctx, cancel := context.WithCancel(context.Background())
	adapter := newLocalTransactionAdapter(previous)
	adapter.cancelOnHealth = cancel
	result, err := RunLocalTransaction(ctx, adapter, fakeLocalCandidate{descriptor: localDescriptor(previous, desired)}, localTestLimits())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled transaction error = %v", err)
	}
	if result.State != LocalTransactionRolledBack || adapter.current != previous || !adapter.rollbackHadDeadline || adapter.rollbackContextCancelled {
		t.Fatalf("cancel rollback = result:%+v adapter:%+v", result, adapter)
	}
}

func TestLocalTransactionReportsUncertainWhenRollbackCannotRestoreGeneration(t *testing.T) {
	t.Parallel()

	previous := localGeneration(13, "previous")
	desired := localGeneration(14, "desired")
	adapter := newLocalTransactionAdapter(previous)
	adapter.failPhase = "health"
	adapter.rollbackFailure = true
	result, err := RunLocalTransaction(context.Background(), adapter, fakeLocalCandidate{descriptor: localDescriptor(previous, desired)}, localTestLimits())
	if !errors.Is(err, ErrLocalTransactionRollback) || !errors.Is(err, ErrLocalTransactionUncertain) {
		t.Fatalf("rollback failure = %v", err)
	}
	if result.State != LocalTransactionUncertain || result.RolledBack || adapter.current != desired {
		t.Fatalf("uncertain result = %+v current=%+v", result, adapter.current)
	}
}

type fakeLocalCandidate struct {
	descriptor LocalCandidateDescriptor
}

func (candidate fakeLocalCandidate) LocalCandidateDescriptor() LocalCandidateDescriptor {
	return candidate.descriptor
}

type fakeLocalStaged struct {
	descriptor LocalCandidateDescriptor
}

func (staged *fakeLocalStaged) LocalCandidateDescriptor() LocalCandidateDescriptor {
	return staged.descriptor
}

type fakeLocalActivation struct {
	descriptor LocalActivationDescriptor
}

func (activation *fakeLocalActivation) LocalActivationDescriptor() LocalActivationDescriptor {
	return activation.descriptor
}

type fakeLocalTransactionAdapter struct {
	current LocalGeneration
	calls   []string

	failPhase                    string
	stageHandleOnError           bool
	activateChangedOnError       bool
	wrongStageDescriptor         bool
	wrongActivationDescriptor    bool
	wrongGenerationAfterActivate bool
	rollbackFailure              bool
	cancelOnHealth               context.CancelFunc
	rollbackHadDeadline          bool
	rollbackContextCancelled     bool
}

func newLocalTransactionAdapter(current LocalGeneration) *fakeLocalTransactionAdapter {
	return &fakeLocalTransactionAdapter{current: current, calls: []string{}}
}

func (adapter *fakeLocalTransactionAdapter) Component() string { return "ingress" }

func (adapter *fakeLocalTransactionAdapter) Current(context.Context) (LocalGeneration, error) {
	adapter.calls = append(adapter.calls, "current")
	return adapter.current, nil
}

func (adapter *fakeLocalTransactionAdapter) Validate(context.Context, LocalCandidate) error {
	adapter.calls = append(adapter.calls, "validate")
	if adapter.failPhase == "validate" {
		return errors.New("validation failure")
	}
	return nil
}

func (adapter *fakeLocalTransactionAdapter) Stage(_ context.Context, candidate LocalCandidate) (LocalStagedCandidate, error) {
	adapter.calls = append(adapter.calls, "stage")
	staged := &fakeLocalStaged{descriptor: candidate.LocalCandidateDescriptor()}
	if adapter.wrongStageDescriptor {
		staged.descriptor.Desired.Generation++
	}
	if adapter.failPhase == "stage" {
		if adapter.stageHandleOnError {
			return staged, errors.New("staging failure")
		}
		return nil, errors.New("staging failure")
	}
	return staged, nil
}

func (adapter *fakeLocalTransactionAdapter) Activate(_ context.Context, staged LocalStagedCandidate) (LocalActivation, error) {
	adapter.calls = append(adapter.calls, "activate")
	descriptor := staged.LocalCandidateDescriptor()
	activation := &fakeLocalActivation{descriptor: LocalActivationDescriptor{
		Component: descriptor.Component, Previous: descriptor.Expected, Active: descriptor.Desired,
	}}
	if adapter.failPhase == "activate" && !adapter.activateChangedOnError {
		return nil, errors.New("activation failure before switch")
	}
	adapter.current = descriptor.Desired
	if adapter.wrongActivationDescriptor {
		activation.descriptor.Active.Generation++
	}
	if adapter.wrongGenerationAfterActivate {
		adapter.current.Generation++
	}
	if adapter.failPhase == "activate" {
		return activation, errors.New("activation failure after switch")
	}
	return activation, nil
}

func (adapter *fakeLocalTransactionAdapter) Health(ctx context.Context, _ LocalActivation) error {
	adapter.calls = append(adapter.calls, "health")
	if adapter.cancelOnHealth != nil {
		adapter.cancelOnHealth()
		return ctx.Err()
	}
	if adapter.failPhase == "health" {
		return errors.New("health failure")
	}
	return nil
}

func (adapter *fakeLocalTransactionAdapter) Commit(context.Context, LocalActivation) error {
	adapter.calls = append(adapter.calls, "commit")
	if adapter.failPhase == "commit" {
		return errors.New("commit failure")
	}
	return nil
}

func (adapter *fakeLocalTransactionAdapter) Discard(ctx context.Context, _ LocalStagedCandidate) error {
	adapter.calls = append(adapter.calls, "discard")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func (adapter *fakeLocalTransactionAdapter) Rollback(ctx context.Context, activation LocalActivation) error {
	adapter.calls = append(adapter.calls, "rollback")
	_, adapter.rollbackHadDeadline = ctx.Deadline()
	adapter.rollbackContextCancelled = ctx.Err() != nil
	if adapter.rollbackFailure {
		return errors.New("rollback failure")
	}
	adapter.current = activation.LocalActivationDescriptor().Previous
	return nil
}

func localGeneration(generation uint64, material string) LocalGeneration {
	fingerprint := ManagedFingerprint([]byte(material))
	return LocalGeneration{Generation: generation, Present: true, RevisionSHA256: fingerprint, RuntimeSHA256: fingerprint}
}

func localDescriptor(previous, desired LocalGeneration) LocalCandidateDescriptor {
	return LocalCandidateDescriptor{Component: "ingress", Expected: previous, Desired: desired}
}

func localTestLimits() LocalTransactionLimits {
	return LocalTransactionLimits{Step: time.Second, Rollback: time.Second}
}
