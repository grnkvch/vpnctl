package operations

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	crossHostSagaID    = "73000000-0000-4000-8000-000000000001"
	crossHostRequestID = "73000000-0000-4000-8000-000000000002"
	crossHostTargetID  = "73000000-0000-4000-8000-000000000003"
)

func TestCrossHostSagaConnectionLossAtEveryPhaseConvergesWithoutBlindReplayOrRollback(t *testing.T) {
	t.Parallel()

	phases := append([]CrossHostSagaPhase{CrossHostPhaseValidate}, crossHostSideEffectPhases...)
	for _, phase := range phases {
		phase := phase
		t.Run(string(phase), func(t *testing.T) {
			coordinator, store, adapter, _ := crossHostSagaFixture(t)
			if phase == CrossHostPhaseValidate {
				adapter.validationFailures = 1
			} else {
				adapter.loseResponse[phase] = true
			}
			record, resumed, err := coordinator.Begin(context.Background(), crossHostIntent())
			if err != nil || resumed || record.ID != crossHostSagaID {
				t.Fatalf("Begin() = %+v, resumed=%t, err=%v", record, resumed, err)
			}
			interrupted, err := coordinator.Resume(context.Background(), record.ID)
			if !errors.Is(err, ErrCrossHostSagaUncertain) || interrupted.State != model.OperationDegraded || interrupted.Phase != phase {
				t.Fatalf("interrupted Resume() = %+v, %v", interrupted, err)
			}
			if phaseBeforePublic(phase) && interrupted.PublicRoutePublished {
				t.Fatal("persisted record published public route before the publish phase was reconciled")
			}
			completed, err := coordinator.Resume(context.Background(), record.ID)
			if err != nil {
				t.Fatalf("resumed saga: %v", err)
			}
			assertCompletedCrossHostSaga(t, completed)
			if phase == CrossHostPhaseValidate {
				if adapter.validationCalls != 2 {
					t.Fatalf("read-only validation calls = %d, want 2", adapter.validationCalls)
				}
			} else if adapter.executions[phase] != 1 || adapter.reconciliations[phase] < 2 {
				t.Fatalf("phase %s execute/reconcile = %d/%d", phase, adapter.executions[phase], adapter.reconciliations[phase])
			}
			for _, sideEffect := range crossHostSideEffectPhases {
				if adapter.executions[sideEffect] != 1 {
					t.Fatalf("phase %s executions = %d, want 1", sideEffect, adapter.executions[sideEffect])
				}
			}
			if adapter.orderingViolations != 0 {
				t.Fatalf("public-route-last violations = %d", adapter.orderingViolations)
			}
			if store.saveConflicts != 0 {
				t.Fatalf("unexpected persistence conflicts = %d", store.saveConflicts)
			}
		})
	}
}

func TestCrossHostSagaLostPersistenceAcknowledgementAtEveryPhaseDoesNotRepeatEffect(t *testing.T) {
	t.Parallel()

	phases := append([]CrossHostSagaPhase{CrossHostPhaseValidate}, crossHostSideEffectPhases...)
	for _, phase := range phases {
		phase := phase
		t.Run(string(phase), func(t *testing.T) {
			coordinator, store, adapter, _ := crossHostSagaFixture(t)
			store.commitThenFailPhase = phase
			record, _, err := coordinator.Begin(context.Background(), crossHostIntent())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.Resume(context.Background(), record.ID); !errors.Is(err, ErrCrossHostSagaUncertain) {
				t.Fatalf("lost persistence acknowledgement error = %v", err)
			}
			completed, err := coordinator.Resume(context.Background(), record.ID)
			if err != nil {
				t.Fatalf("resume after lost persistence acknowledgement: %v", err)
			}
			assertCompletedCrossHostSaga(t, completed)
			if phase == CrossHostPhaseValidate {
				if adapter.validationCalls != 1 {
					t.Fatalf("validation replayed %d times", adapter.validationCalls)
				}
			} else if adapter.executions[phase] != 1 {
				t.Fatalf("phase %s replayed %d times", phase, adapter.executions[phase])
			}
		})
	}
}

func TestCrossHostSagaPublicRouteIsLastAndDrainDeadlineSurvivesResume(t *testing.T) {
	t.Parallel()

	coordinator, _, adapter, clock := crossHostSagaFixture(t)
	adapter.loseResponse[CrossHostPhasePublishPublic] = true
	adapter.unknown[CrossHostPhaseDrain] = true
	record, _, err := coordinator.Begin(context.Background(), crossHostIntent())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Resume(context.Background(), record.ID); !errors.Is(err, ErrCrossHostSagaUncertain) {
		t.Fatalf("publish loss error = %v", err)
	}
	draining, err := coordinator.Resume(context.Background(), record.ID)
	if !errors.Is(err, ErrCrossHostSagaUncertain) || draining.Phase != CrossHostPhaseDrain || !draining.PublicRoutePublished || !draining.PrivateReady {
		t.Fatalf("drain pause = %+v, %v", draining, err)
	}
	wantDeadline := draining.PublishedAt.Add(draining.Drain)
	if !draining.DrainDeadline.Equal(wantDeadline) {
		t.Fatalf("drain deadline = %s, want %s", draining.DrainDeadline, wantDeadline)
	}
	clock.now = wantDeadline.Add(time.Second)
	delete(adapter.unknown, CrossHostPhaseDrain)
	completed, err := coordinator.Resume(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCompletedCrossHostSaga(t, completed)
	if adapter.executions[CrossHostPhaseDrain] != 0 {
		t.Fatalf("expired persisted drain executed again %d times", adapter.executions[CrossHostPhaseDrain])
	}
	wantEffects := []CrossHostSagaPhase{
		CrossHostPhaseStage, CrossHostPhaseActivatePrivate, CrossHostPhaseConfirmPrivate,
		CrossHostPhasePublishPublic, CrossHostPhaseFinalize,
	}
	if !reflect.DeepEqual(adapter.effectOrder, wantEffects) {
		t.Fatalf("effect order = %v, want %v", adapter.effectOrder, wantEffects)
	}
}

func TestCrossHostSagaPersistsFixedPhaseAndStateSequence(t *testing.T) {
	t.Parallel()

	coordinator, store, _, _ := crossHostSagaFixture(t)
	record, _, err := coordinator.Begin(context.Background(), crossHostIntent())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := coordinator.Resume(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCompletedCrossHostSaga(t, completed)

	wantPhases := []CrossHostSagaPhase{
		CrossHostPhaseValidate, CrossHostPhaseStage, CrossHostPhaseActivatePrivate,
		CrossHostPhaseConfirmPrivate, CrossHostPhasePublishPublic, CrossHostPhaseDrain,
		CrossHostPhaseFinalize, CrossHostPhaseComplete,
	}
	wantStates := []model.OperationState{
		model.OperationPending, model.OperationStaging, model.OperationStaging,
		model.OperationStaging, model.OperationStaging, model.OperationActive,
		model.OperationActive, model.OperationCompleted,
	}
	if len(store.history) != len(wantPhases) {
		t.Fatalf("persisted records = %d, want %d: %+v", len(store.history), len(wantPhases), store.history)
	}
	for index, persisted := range store.history {
		if persisted.Revision != uint64(index+1) || persisted.Phase != wantPhases[index] || persisted.State != wantStates[index] {
			t.Fatalf("persisted record %d = revision %d phase %s state %s", index, persisted.Revision, persisted.Phase, persisted.State)
		}
		if index < 5 && persisted.PublicRoutePublished {
			t.Fatalf("public route persisted early at phase %s", persisted.Phase)
		}
	}
}

func TestCrossHostSagaUnknownEvidenceStopsBeforeExecution(t *testing.T) {
	t.Parallel()

	coordinator, _, adapter, _ := crossHostSagaFixture(t)
	adapter.unknown[CrossHostPhaseActivatePrivate] = true
	record, _, err := coordinator.Begin(context.Background(), crossHostIntent())
	if err != nil {
		t.Fatal(err)
	}
	degraded, err := coordinator.Resume(context.Background(), record.ID)
	if !errors.Is(err, ErrCrossHostSagaUncertain) || degraded.Phase != CrossHostPhaseActivatePrivate {
		t.Fatalf("unknown evidence result = %+v, %v", degraded, err)
	}
	if adapter.executions[CrossHostPhaseActivatePrivate] != 0 || adapter.executions[CrossHostPhasePublishPublic] != 0 {
		t.Fatalf("unknown evidence executed effects: %+v", adapter.executions)
	}
	delete(adapter.unknown, CrossHostPhaseActivatePrivate)
	completed, err := coordinator.Resume(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCompletedCrossHostSaga(t, completed)
}

func TestCrossHostSagaBeginIsIdempotentByRequestAndCreateAcknowledgement(t *testing.T) {
	t.Parallel()

	coordinator, store, _, _ := crossHostSagaFixture(t)
	store.createCommitThenFail = true
	created, resumed, err := coordinator.Begin(context.Background(), crossHostIntent())
	if !errors.Is(err, ErrCrossHostSagaUncertain) || resumed || created.ID != crossHostSagaID {
		t.Fatalf("uncertain Begin() = %+v, %t, %v", created, resumed, err)
	}
	replayed, resumed, err := coordinator.Begin(context.Background(), crossHostIntent())
	if err != nil || !resumed || replayed.ID != created.ID || store.createCalls != 1 {
		t.Fatalf("replayed Begin() = %+v, %t, %v; creates=%d", replayed, resumed, err, store.createCalls)
	}
	conflict := crossHostIntent()
	conflict.TargetID = "73000000-0000-4000-8000-000000000004"
	if _, _, err := coordinator.Begin(context.Background(), conflict); !errors.Is(err, ErrCrossHostSagaConflict) {
		t.Fatalf("request reuse conflict = %v", err)
	}
}

func TestCrossHostSagaBeginRejectsDuplicatePersistedIdentity(t *testing.T) {
	t.Parallel()

	coordinator, store, _, _ := crossHostSagaFixture(t)
	first, _, err := coordinator.Begin(context.Background(), crossHostIntent())
	if err != nil {
		t.Fatal(err)
	}
	duplicate := first
	duplicate.ID = "73000000-0000-4000-8000-000000000004"
	store.records[duplicate.ID] = duplicate
	if _, _, err := coordinator.Begin(context.Background(), crossHostIntent()); !errors.Is(err, ErrCrossHostSagaInvalid) {
		t.Fatalf("duplicate request ID validation = %v", err)
	}

	delete(store.records, duplicate.ID)
	crossIdentity := first
	crossIdentity.ID = first.RequestID
	crossIdentity.RequestID = "73000000-0000-4000-8000-000000000005"
	store.records[crossIdentity.ID] = crossIdentity
	if _, _, err := coordinator.Begin(context.Background(), crossHostIntent()); !errors.Is(err, ErrCrossHostSagaInvalid) {
		t.Fatalf("ID/request cross-collision validation = %v", err)
	}
}

func TestCrossHostSagaOperationIDCannotEqualRequestID(t *testing.T) {
	t.Parallel()

	_, store, adapter, clock := crossHostSagaFixture(t)
	generated := []string{crossHostRequestID, crossHostSagaID}
	coordinator, err := NewCrossHostSagaCoordinator(store, adapter, func() (string, error) {
		id := generated[0]
		generated = generated[1:]
		return id, nil
	}, clock.Now, CrossHostSagaLimits{Step: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := coordinator.Begin(context.Background(), crossHostIntent())
	if err != nil {
		t.Fatal(err)
	}
	if record.ID != crossHostSagaID || record.ID == record.RequestID {
		t.Fatalf("operation/request identities = %s/%s", record.ID, record.RequestID)
	}
}

func TestCrossHostSagaDefinitiveValidationConflictIsTerminal(t *testing.T) {
	t.Parallel()

	coordinator, _, adapter, _ := crossHostSagaFixture(t)
	adapter.validationError = fmt.Errorf("stale expected generation: %w", ErrCrossHostSagaConflict)
	record, _, err := coordinator.Begin(context.Background(), crossHostIntent())
	if err != nil {
		t.Fatal(err)
	}
	failed, err := coordinator.Resume(context.Background(), record.ID)
	if !errors.Is(err, ErrCrossHostSagaConflict) || failed.State != model.OperationFailed || failed.LastErrorPhase != CrossHostPhaseValidate {
		t.Fatalf("definitive validation conflict = %+v, %v", failed, err)
	}
	if len(adapter.effectOrder) != 0 {
		t.Fatalf("definitive conflict executed side effects: %+v", adapter.effectOrder)
	}
	again, err := coordinator.Resume(context.Background(), record.ID)
	if !errors.Is(err, ErrCrossHostSagaConflict) || !reflect.DeepEqual(again, failed) || adapter.validationCalls != 1 {
		t.Fatalf("terminal resume = %+v, %v; validation calls=%d", again, err, adapter.validationCalls)
	}
}

func TestCrossHostSagaNormalizesSystemClockAndValidatesReceiptAfterExecution(t *testing.T) {
	t.Parallel()

	coordinator, _, adapter, clock := crossHostSagaFixture(t)
	clock.now = clock.now.Add(123456789 * time.Nanosecond)
	adapter.advanceClockOnPublish = time.Second
	record, _, err := coordinator.Begin(context.Background(), crossHostIntent())
	if err != nil {
		t.Fatal(err)
	}
	completed, err := coordinator.Resume(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertCompletedCrossHostSaga(t, completed)
	if completed.CreatedAt.Nanosecond() != 0 || completed.UpdatedAt.Nanosecond() != 0 {
		t.Fatalf("timestamps were not normalized: %+v", completed)
	}
}

func TestCrossHostSagaRejectsUnboundedDrainAndInvalidPublicReceipt(t *testing.T) {
	t.Parallel()

	invalid := crossHostIntent()
	invalid.Drain = MaximumCrossHostDrain + time.Second
	if err := invalid.Validate(); !errors.Is(err, ErrCrossHostSagaInvalid) {
		t.Fatalf("unbounded drain validation = %v", err)
	}

	coordinator, _, adapter, _ := crossHostSagaFixture(t)
	adapter.invalidPublicPhase = CrossHostPhaseStage
	record, _, err := coordinator.Begin(context.Background(), crossHostIntent())
	if err != nil {
		t.Fatal(err)
	}
	degraded, err := coordinator.Resume(context.Background(), record.ID)
	if !errors.Is(err, ErrCrossHostSagaUncertain) || degraded.Phase != CrossHostPhaseStage || degraded.PublicRoutePublished {
		t.Fatalf("invalid early publication = %+v, %v", degraded, err)
	}
	if adapter.executions[CrossHostPhaseActivatePrivate] != 0 {
		t.Fatal("invalid public receipt advanced to private activation")
	}
	stillDegraded, err := coordinator.Resume(context.Background(), record.ID)
	if !errors.Is(err, ErrCrossHostSagaUncertain) || !errors.Is(err, ErrCrossHostSagaInvalid) ||
		stillDegraded.State != model.OperationDegraded || adapter.executions[CrossHostPhaseStage] != 1 {
		t.Fatalf("invalid reconciled receipt = %+v, %v; executions=%d", stillDegraded, err, adapter.executions[CrossHostPhaseStage])
	}
}

type fakeCrossHostClock struct {
	now time.Time
}

func (clock *fakeCrossHostClock) Now() time.Time { return clock.now }

type fakeCrossHostStore struct {
	records map[string]CrossHostSagaRecord
	history []CrossHostSagaRecord

	createCalls          int
	createCommitThenFail bool
	commitThenFailPhase  CrossHostSagaPhase
	failedSavePhase      bool
	saveConflicts        int
}

func (store *fakeCrossHostStore) ListCrossHostSagas(context.Context) ([]CrossHostSagaRecord, error) {
	result := make([]CrossHostSagaRecord, 0, len(store.records))
	for _, record := range store.records {
		result = append(result, record)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID > result[right].ID })
	return result, nil
}

func (store *fakeCrossHostStore) CreateCrossHostSaga(_ context.Context, record CrossHostSagaRecord) error {
	store.createCalls++
	if _, exists := store.records[record.ID]; exists {
		return errors.New("duplicate saga")
	}
	store.records[record.ID] = record
	store.history = append(store.history, record)
	if store.createCommitThenFail {
		store.createCommitThenFail = false
		return errors.New("create acknowledgement lost")
	}
	return nil
}

func (store *fakeCrossHostStore) LoadCrossHostSaga(_ context.Context, id string) (CrossHostSagaRecord, error) {
	record, exists := store.records[id]
	if !exists {
		return CrossHostSagaRecord{}, errors.New("saga not found")
	}
	return record, nil
}

func (store *fakeCrossHostStore) SaveCrossHostSaga(_ context.Context, expected uint64, candidate CrossHostSagaRecord) error {
	current, exists := store.records[candidate.ID]
	if !exists || current.Revision != expected || candidate.Revision != expected+1 {
		store.saveConflicts++
		return errors.New("saga generation conflict")
	}
	priorPhase := current.Phase
	store.records[candidate.ID] = candidate
	store.history = append(store.history, candidate)
	if store.commitThenFailPhase == priorPhase && !store.failedSavePhase {
		store.failedSavePhase = true
		return errors.New("save acknowledgement lost")
	}
	return nil
}

type fakeCrossHostAdapter struct {
	clock *fakeCrossHostClock

	effects               map[CrossHostSagaPhase]CrossHostStepReceipt
	executions            map[CrossHostSagaPhase]int
	reconciliations       map[CrossHostSagaPhase]int
	loseResponse          map[CrossHostSagaPhase]bool
	lostOnce              map[CrossHostSagaPhase]bool
	unknown               map[CrossHostSagaPhase]bool
	effectOrder           []CrossHostSagaPhase
	validationCalls       int
	validationFailures    int
	validationError       error
	orderingViolations    int
	invalidPublicPhase    CrossHostSagaPhase
	drainDeadlineObserved time.Time
	advanceClockOnPublish time.Duration
}

func (adapter *fakeCrossHostAdapter) ValidateCrossHost(context.Context, CrossHostSagaRecord) error {
	adapter.validationCalls++
	if adapter.validationFailures > 0 {
		adapter.validationFailures--
		return errors.New("validation response lost")
	}
	return adapter.validationError
}

func (adapter *fakeCrossHostAdapter) ReconcileCrossHost(_ context.Context, phase CrossHostSagaPhase, _ CrossHostSagaRecord) (CrossHostStepObservation, error) {
	adapter.reconciliations[phase]++
	if adapter.unknown[phase] {
		return CrossHostStepObservation{Status: CrossHostStepUnknown}, nil
	}
	if receipt, applied := adapter.effects[phase]; applied {
		return CrossHostStepObservation{Status: CrossHostStepApplied, Receipt: receipt}, nil
	}
	return CrossHostStepObservation{Status: CrossHostStepNotApplied}, nil
}

func (adapter *fakeCrossHostAdapter) ExecuteCrossHost(ctx context.Context, phase CrossHostSagaPhase, record CrossHostSagaRecord) (CrossHostStepReceipt, error) {
	adapter.executions[phase]++
	if phase == CrossHostPhasePublishPublic {
		for _, required := range []CrossHostSagaPhase{CrossHostPhaseStage, CrossHostPhaseActivatePrivate, CrossHostPhaseConfirmPrivate} {
			if _, applied := adapter.effects[required]; !applied {
				adapter.orderingViolations++
			}
		}
	}
	if phaseBeforePublic(phase) && phase != CrossHostPhasePublishPublic {
		if _, published := adapter.effects[CrossHostPhasePublishPublic]; published {
			adapter.orderingViolations++
		}
	}
	if phase == CrossHostPhaseDrain {
		adapter.drainDeadlineObserved, _ = ctx.Deadline()
		if !adapter.drainDeadlineObserved.Equal(record.DrainDeadline) {
			return CrossHostStepReceipt{}, errors.New("drain deadline changed")
		}
	}
	receipt := adapter.receipt(phase, record)
	if adapter.invalidPublicPhase == phase {
		receipt.PublicRoutePublished = true
	}
	adapter.effects[phase] = receipt
	adapter.effectOrder = append(adapter.effectOrder, phase)
	if adapter.loseResponse[phase] && !adapter.lostOnce[phase] {
		adapter.lostOnce[phase] = true
		return receipt, errors.New("remote response lost after effect")
	}
	return receipt, nil
}

func (adapter *fakeCrossHostAdapter) receipt(phase CrossHostSagaPhase, record CrossHostSagaRecord) CrossHostStepReceipt {
	receipt := CrossHostStepReceipt{
		OperationID: record.ID, Phase: phase,
		GatewayGeneration: record.GatewayGeneration, NodeGeneration: record.NodeGeneration,
	}
	switch phase {
	case CrossHostPhaseStage:
		receipt.GatewayGeneration++
		receipt.NodeGeneration++
	case CrossHostPhaseActivatePrivate:
		receipt.NodeGeneration++
	case CrossHostPhaseConfirmPrivate:
		receipt.GatewayGeneration++
		receipt.PrivateReady = true
	case CrossHostPhasePublishPublic:
		adapter.clock.now = adapter.clock.now.Add(adapter.advanceClockOnPublish)
		receipt.GatewayGeneration = record.DesiredGatewayGeneration
		receipt.PrivateReady = true
		receipt.PublicRoutePublished = true
		receipt.EffectiveAt = adapter.clock.Now().UTC().Truncate(time.Second)
	case CrossHostPhaseDrain:
		receipt.PrivateReady = true
		receipt.PublicRoutePublished = true
		receipt.Drained = true
	case CrossHostPhaseFinalize:
		receipt.GatewayGeneration = record.DesiredGatewayGeneration
		receipt.NodeGeneration = record.DesiredNodeGeneration
		receipt.PrivateReady = true
		receipt.PublicRoutePublished = true
		receipt.Drained = true
	default:
		panic(fmt.Sprintf("unexpected phase %s", phase))
	}
	return receipt
}

func crossHostSagaFixture(t *testing.T) (*CrossHostSagaCoordinator, *fakeCrossHostStore, *fakeCrossHostAdapter, *fakeCrossHostClock) {
	t.Helper()
	clock := &fakeCrossHostClock{now: time.Date(2035, time.January, 2, 3, 4, 5, 0, time.UTC)}
	store := &fakeCrossHostStore{records: map[string]CrossHostSagaRecord{}}
	adapter := &fakeCrossHostAdapter{
		clock: clock, effects: map[CrossHostSagaPhase]CrossHostStepReceipt{},
		executions: map[CrossHostSagaPhase]int{}, reconciliations: map[CrossHostSagaPhase]int{},
		loseResponse: map[CrossHostSagaPhase]bool{}, lostOnce: map[CrossHostSagaPhase]bool{}, unknown: map[CrossHostSagaPhase]bool{},
		effectOrder: []CrossHostSagaPhase{},
	}
	generated := false
	coordinator, err := NewCrossHostSagaCoordinator(store, adapter, func() (string, error) {
		if generated {
			return "73000000-0000-4000-8000-000000000099", nil
		}
		generated = true
		return crossHostSagaID, nil
	}, clock.Now, CrossHostSagaLimits{Step: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, store, adapter, clock
}

func crossHostIntent() CrossHostSagaIntent {
	return CrossHostSagaIntent{
		RequestID: crossHostRequestID, Type: model.OperationExposeCreate, TargetKind: "expose", TargetID: crossHostTargetID,
		ExpectedGatewayGeneration: 10, DesiredGatewayGeneration: 13,
		ExpectedNodeGeneration: 20, DesiredNodeGeneration: 23,
		Drain: 5 * time.Second,
	}
}

func assertCompletedCrossHostSaga(t *testing.T, record CrossHostSagaRecord) {
	t.Helper()
	if err := record.Validate(); err != nil {
		t.Fatalf("completed record validation: %v", err)
	}
	if record.State != model.OperationCompleted || record.Phase != CrossHostPhaseComplete ||
		record.GatewayGeneration != record.DesiredGatewayGeneration || record.NodeGeneration != record.DesiredNodeGeneration ||
		!record.PrivateReady || !record.PublicRoutePublished || !record.Drained || record.LastErrorPhase != "" {
		t.Fatalf("completed saga = %+v", record)
	}
}
