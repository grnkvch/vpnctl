package operations

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	CrossHostSagaSchemaVersion  = 1
	MaximumCrossHostDrain       = 10 * time.Second
	DefaultCrossHostStepTimeout = 30 * time.Second
	maximumCrossHostResumeSteps = 8
)

var (
	ErrCrossHostSagaInvalid   = errors.New("invalid cross-host saga")
	ErrCrossHostSagaConflict  = errors.New("cross-host saga conflict")
	ErrCrossHostSagaUncertain = errors.New("cross-host saga outcome is uncertain")
)

type CrossHostSagaPhase string

const (
	CrossHostPhaseValidate        CrossHostSagaPhase = "validate"
	CrossHostPhaseStage           CrossHostSagaPhase = "stage"
	CrossHostPhaseActivatePrivate CrossHostSagaPhase = "activate-private"
	CrossHostPhaseConfirmPrivate  CrossHostSagaPhase = "confirm-private"
	CrossHostPhasePublishPublic   CrossHostSagaPhase = "publish-public"
	CrossHostPhaseDrain           CrossHostSagaPhase = "drain"
	CrossHostPhaseFinalize        CrossHostSagaPhase = "finalize"
	CrossHostPhaseComplete        CrossHostSagaPhase = "complete"
)

var crossHostSideEffectPhases = []CrossHostSagaPhase{
	CrossHostPhaseStage,
	CrossHostPhaseActivatePrivate,
	CrossHostPhaseConfirmPrivate,
	CrossHostPhasePublishPublic,
	CrossHostPhaseDrain,
	CrossHostPhaseFinalize,
}

type CrossHostSagaIntent struct {
	RequestID                 string              `json:"request_id"`
	Type                      model.OperationType `json:"type"`
	TargetKind                string              `json:"target_kind"`
	TargetID                  string              `json:"target_id"`
	ExpectedGatewayGeneration uint64              `json:"expected_gateway_generation"`
	DesiredGatewayGeneration  uint64              `json:"desired_gateway_generation"`
	ExpectedNodeGeneration    uint64              `json:"expected_node_generation"`
	DesiredNodeGeneration     uint64              `json:"desired_node_generation"`
	Drain                     time.Duration       `json:"drain"`
}

type CrossHostSagaRecord struct {
	SchemaVersion int                  `json:"schema_version"`
	Revision      uint64               `json:"revision"`
	ID            string               `json:"id"`
	RequestID     string               `json:"request_id"`
	Type          model.OperationType  `json:"type"`
	State         model.OperationState `json:"state"`
	Phase         CrossHostSagaPhase   `json:"phase"`
	TargetKind    string               `json:"target_kind"`
	TargetID      string               `json:"target_id"`

	ExpectedGatewayGeneration uint64 `json:"expected_gateway_generation"`
	DesiredGatewayGeneration  uint64 `json:"desired_gateway_generation"`
	GatewayGeneration         uint64 `json:"gateway_generation"`
	ExpectedNodeGeneration    uint64 `json:"expected_node_generation"`
	DesiredNodeGeneration     uint64 `json:"desired_node_generation"`
	NodeGeneration            uint64 `json:"node_generation"`

	PrivateReady         bool               `json:"private_ready"`
	PublicRoutePublished bool               `json:"public_route_published"`
	Drained              bool               `json:"drained"`
	Drain                time.Duration      `json:"drain"`
	PublishedAt          time.Time          `json:"published_at,omitempty"`
	DrainDeadline        time.Time          `json:"drain_deadline,omitempty"`
	LastErrorPhase       CrossHostSagaPhase `json:"last_error_phase,omitempty"`
	CreatedAt            time.Time          `json:"created_at"`
	UpdatedAt            time.Time          `json:"updated_at"`
}

type CrossHostStepStatus string

const (
	CrossHostStepNotApplied CrossHostStepStatus = "not_applied"
	CrossHostStepApplied    CrossHostStepStatus = "applied"
	CrossHostStepUnknown    CrossHostStepStatus = "unknown"
)

type CrossHostStepReceipt struct {
	OperationID          string             `json:"operation_id"`
	Phase                CrossHostSagaPhase `json:"phase"`
	GatewayGeneration    uint64             `json:"gateway_generation"`
	NodeGeneration       uint64             `json:"node_generation"`
	PrivateReady         bool               `json:"private_ready"`
	PublicRoutePublished bool               `json:"public_route_published"`
	Drained              bool               `json:"drained"`
	EffectiveAt          time.Time          `json:"effective_at,omitempty"`
}

type CrossHostStepObservation struct {
	Status  CrossHostStepStatus  `json:"status"`
	Receipt CrossHostStepReceipt `json:"receipt,omitempty"`
}

// CrossHostSagaStore is a CAS persistence boundary. Implementations backed by
// gateway state remain serialized by the authoritative writer. Save may commit
// and lose its acknowledgement; callers must resume by stable ID.
type CrossHostSagaStore interface {
	ListCrossHostSagas(context.Context) ([]CrossHostSagaRecord, error)
	CreateCrossHostSaga(context.Context, CrossHostSagaRecord) error
	LoadCrossHostSaga(context.Context, string) (CrossHostSagaRecord, error)
	SaveCrossHostSaga(context.Context, uint64, CrossHostSagaRecord) error
}

// CrossHostSagaAdapter intentionally exposes no rollback method. Every
// side-effect is reconciled by stable operation ID and generations before it
// may be executed, making blind rollback or replay structurally unavailable.
type CrossHostSagaAdapter interface {
	ValidateCrossHost(context.Context, CrossHostSagaRecord) error
	ReconcileCrossHost(context.Context, CrossHostSagaPhase, CrossHostSagaRecord) (CrossHostStepObservation, error)
	ExecuteCrossHost(context.Context, CrossHostSagaPhase, CrossHostSagaRecord) (CrossHostStepReceipt, error)
}

type CrossHostSagaLimits struct {
	Step time.Duration
}

type CrossHostSagaCoordinator struct {
	store     CrossHostSagaStore
	adapter   CrossHostSagaAdapter
	generate  model.UUIDGenerator
	now       func() time.Time
	stepLimit time.Duration
}

type CrossHostSagaError struct {
	OperationID string
	Phase       CrossHostSagaPhase
	Cause       error
}

func (err *CrossHostSagaError) Error() string {
	return fmt.Sprintf("cross-host saga %s phase %s: %v", err.OperationID, err.Phase, err.Cause)
}

func (err *CrossHostSagaError) Unwrap() error { return err.Cause }

func NewCrossHostSagaCoordinator(
	store CrossHostSagaStore,
	adapter CrossHostSagaAdapter,
	generate model.UUIDGenerator,
	now func() time.Time,
	limits CrossHostSagaLimits,
) (*CrossHostSagaCoordinator, error) {
	if nilInterface(store) || nilInterface(adapter) {
		return nil, fmt.Errorf("cross-host saga store and adapter are required")
	}
	if generate == nil {
		generate = model.NewUUID
	}
	if now == nil {
		now = time.Now
	}
	step := limits.Step
	if step == 0 {
		step = DefaultCrossHostStepTimeout
	}
	if step < minimumLocalTransactionTimeout || step > maximumLocalTransactionTimeout {
		return nil, fmt.Errorf("cross-host saga step timeout must be between %s and %s", minimumLocalTransactionTimeout, maximumLocalTransactionTimeout)
	}
	return &CrossHostSagaCoordinator{store: store, adapter: adapter, generate: generate, now: now, stepLimit: step}, nil
}

// Begin idempotently persists the initial phase by request ID. A retry returns
// the exact prior operation without allocating another identity.
func (coordinator *CrossHostSagaCoordinator) Begin(ctx context.Context, intent CrossHostSagaIntent) (CrossHostSagaRecord, bool, error) {
	if ctx == nil {
		return CrossHostSagaRecord{}, false, fmt.Errorf("context is required")
	}
	if coordinator == nil || nilInterface(coordinator.store) || nilInterface(coordinator.adapter) {
		return CrossHostSagaRecord{}, false, fmt.Errorf("cross-host saga coordinator is incomplete")
	}
	if err := intent.Validate(); err != nil {
		return CrossHostSagaRecord{}, false, err
	}
	records, err := runLocalStep(ctx, coordinator.stepLimit, coordinator.store.ListCrossHostSagas)
	if err != nil {
		return CrossHostSagaRecord{}, false, fmt.Errorf("list cross-host sagas: %w", err)
	}
	if records == nil {
		return CrossHostSagaRecord{}, false, fmt.Errorf("%w: saga list must be present", ErrCrossHostSagaInvalid)
	}
	occupied := make(map[string]struct{}, len(records)*2)
	var prior *CrossHostSagaRecord
	for index, record := range records {
		if err := record.Validate(); err != nil {
			return CrossHostSagaRecord{}, false, fmt.Errorf("%w: stored saga %d: %v", ErrCrossHostSagaInvalid, index, err)
		}
		if _, duplicate := occupied[record.ID]; duplicate {
			return CrossHostSagaRecord{}, false, fmt.Errorf("%w: duplicate stored saga identity", ErrCrossHostSagaInvalid)
		}
		occupied[record.ID] = struct{}{}
		if _, duplicate := occupied[record.RequestID]; duplicate {
			return CrossHostSagaRecord{}, false, fmt.Errorf("%w: duplicate stored saga identity", ErrCrossHostSagaInvalid)
		}
		occupied[record.RequestID] = struct{}{}
		if record.RequestID == intent.RequestID {
			if !record.matches(intent) {
				return CrossHostSagaRecord{}, false, fmt.Errorf("%w: request ID belongs to different saga intent", ErrCrossHostSagaConflict)
			}
			matched := record
			prior = &matched
		}
	}
	if prior != nil {
		return *prior, true, nil
	}
	occupied[intent.RequestID] = struct{}{}
	id, err := model.AllocateUUID(occupied, coordinator.generate)
	if err != nil {
		return CrossHostSagaRecord{}, false, err
	}
	now, err := coordinator.currentTime()
	if err != nil {
		return CrossHostSagaRecord{}, false, err
	}
	record := CrossHostSagaRecord{
		SchemaVersion: CrossHostSagaSchemaVersion, Revision: 1, ID: id, RequestID: intent.RequestID,
		Type: intent.Type, State: model.OperationPending, Phase: CrossHostPhaseValidate,
		TargetKind: intent.TargetKind, TargetID: intent.TargetID,
		ExpectedGatewayGeneration: intent.ExpectedGatewayGeneration, DesiredGatewayGeneration: intent.DesiredGatewayGeneration,
		GatewayGeneration:      intent.ExpectedGatewayGeneration,
		ExpectedNodeGeneration: intent.ExpectedNodeGeneration, DesiredNodeGeneration: intent.DesiredNodeGeneration,
		NodeGeneration: intent.ExpectedNodeGeneration,
		Drain:          intent.Drain, CreatedAt: now, UpdatedAt: now,
	}
	if err := record.Validate(); err != nil {
		return CrossHostSagaRecord{}, false, fmt.Errorf("%w: initial record: %v", ErrCrossHostSagaInvalid, err)
	}
	if err := runLocalAction(ctx, coordinator.stepLimit, func(step context.Context) error {
		return coordinator.store.CreateCrossHostSaga(step, record)
	}); err != nil {
		return record, false, coordinator.sagaError(record, ErrCrossHostSagaUncertain, err)
	}
	return record, false, nil
}

// Resume converges a persisted operation. It reconciles every side-effect
// phase before execution and stops on unknown evidence without rollback.
func (coordinator *CrossHostSagaCoordinator) Resume(ctx context.Context, operationID string) (CrossHostSagaRecord, error) {
	if ctx == nil {
		return CrossHostSagaRecord{}, fmt.Errorf("context is required")
	}
	if coordinator == nil || nilInterface(coordinator.store) || nilInterface(coordinator.adapter) {
		return CrossHostSagaRecord{}, fmt.Errorf("cross-host saga coordinator is incomplete")
	}
	if err := model.ValidateResourceID(operationID); err != nil {
		return CrossHostSagaRecord{}, fmt.Errorf("%w: operation ID: %v", ErrCrossHostSagaInvalid, err)
	}
	record, err := runLocalStep(ctx, coordinator.stepLimit, func(step context.Context) (CrossHostSagaRecord, error) {
		return coordinator.store.LoadCrossHostSaga(step, operationID)
	})
	if err != nil {
		return CrossHostSagaRecord{}, fmt.Errorf("load cross-host saga: %w", err)
	}
	for attempt := 0; attempt < maximumCrossHostResumeSteps; attempt++ {
		if err := record.Validate(); err != nil {
			return record, fmt.Errorf("%w: stored saga: %v", ErrCrossHostSagaInvalid, err)
		}
		if record.State == model.OperationCompleted && record.Phase == CrossHostPhaseComplete {
			return record, nil
		}
		if record.State == model.OperationFailed {
			return record, coordinator.sagaError(record, ErrCrossHostSagaConflict, errors.New("operation is terminally failed"))
		}
		if record.Phase == CrossHostPhaseValidate {
			next, stepErr := coordinator.validatePhase(ctx, record)
			if stepErr != nil {
				return next, stepErr
			}
			record = next
			continue
		}
		next, stepErr := coordinator.resumeSideEffect(ctx, record)
		if stepErr != nil {
			return next, stepErr
		}
		record = next
	}
	return record, coordinator.sagaError(record, ErrCrossHostSagaInvalid, errors.New("resume exceeded phase bound"))
}

func (coordinator *CrossHostSagaCoordinator) validatePhase(ctx context.Context, record CrossHostSagaRecord) (CrossHostSagaRecord, error) {
	err := runLocalAction(ctx, coordinator.stepLimit, func(step context.Context) error {
		return coordinator.adapter.ValidateCrossHost(step, record)
	})
	if err != nil {
		if errors.Is(err, ErrCrossHostSagaConflict) {
			failed, persistErr := coordinator.markFailed(ctx, record)
			if persistErr != nil {
				return failed, coordinator.sagaError(record, ErrCrossHostSagaConflict, errors.Join(ErrCrossHostSagaUncertain, err, persistErr))
			}
			return failed, coordinator.sagaError(record, ErrCrossHostSagaConflict, err)
		}
		degraded, persistErr := coordinator.markDegraded(ctx, record)
		return degraded, coordinator.sagaError(record, ErrCrossHostSagaUncertain, errors.Join(err, persistErr))
	}
	now, err := coordinator.currentTime()
	if err != nil {
		return record, coordinator.sagaError(record, ErrCrossHostSagaInvalid, err)
	}
	next, err := coordinator.advance(record, CrossHostStepReceipt{}, now)
	if err != nil {
		return record, coordinator.sagaError(record, ErrCrossHostSagaInvalid, err)
	}
	return coordinator.persistAdvance(ctx, record, next)
}

func (coordinator *CrossHostSagaCoordinator) resumeSideEffect(ctx context.Context, record CrossHostSagaRecord) (CrossHostSagaRecord, error) {
	observation, err := runLocalStep(ctx, coordinator.stepLimit, func(step context.Context) (CrossHostStepObservation, error) {
		return coordinator.adapter.ReconcileCrossHost(step, record.Phase, record)
	})
	if err != nil {
		degraded, persistErr := coordinator.markDegraded(ctx, record)
		return degraded, coordinator.sagaError(record, ErrCrossHostSagaUncertain, errors.Join(err, persistErr))
	}
	observedAt, err := coordinator.currentTime()
	if err != nil {
		return record, coordinator.sagaError(record, ErrCrossHostSagaInvalid, err)
	}
	if err := observation.Validate(record, observedAt); err != nil {
		degraded, persistErr := coordinator.markDegraded(ctx, record)
		return degraded, coordinator.sagaError(record, ErrCrossHostSagaUncertain, errors.Join(err, persistErr))
	}
	switch observation.Status {
	case CrossHostStepApplied:
		next, err := coordinator.advance(record, observation.Receipt, observedAt)
		if err != nil {
			degraded, persistErr := coordinator.markDegraded(ctx, record)
			return degraded, coordinator.sagaError(record, ErrCrossHostSagaUncertain, errors.Join(err, persistErr))
		}
		return coordinator.persistAdvance(ctx, record, next)
	case CrossHostStepUnknown:
		degraded, persistErr := coordinator.markDegraded(ctx, record)
		return degraded, coordinator.sagaError(record, ErrCrossHostSagaUncertain, persistErr)
	case CrossHostStepNotApplied:
		// Positive absence is the only state that permits execution.
	default:
		return record, coordinator.sagaError(record, ErrCrossHostSagaInvalid, errors.New("unsupported reconciliation status"))
	}

	now, err := coordinator.currentTime()
	if err != nil {
		return record, coordinator.sagaError(record, ErrCrossHostSagaInvalid, err)
	}
	var receipt CrossHostStepReceipt
	if record.Phase == CrossHostPhaseDrain && !now.Before(record.DrainDeadline) {
		receipt = CrossHostStepReceipt{
			OperationID: record.ID, Phase: record.Phase,
			GatewayGeneration: record.GatewayGeneration, NodeGeneration: record.NodeGeneration,
			PrivateReady: true, PublicRoutePublished: true, Drained: true,
		}
	} else {
		receipt, err = coordinator.executePhase(ctx, record)
		if err != nil {
			degraded, persistErr := coordinator.markDegraded(ctx, record)
			return degraded, coordinator.sagaError(record, ErrCrossHostSagaUncertain, errors.Join(err, persistErr))
		}
		now, err = coordinator.currentTime()
		if err != nil {
			degraded, persistErr := coordinator.markDegraded(ctx, record)
			return degraded, coordinator.sagaError(record, ErrCrossHostSagaUncertain, errors.Join(err, persistErr))
		}
	}
	if err := receipt.Validate(record, now); err != nil {
		degraded, persistErr := coordinator.markDegraded(ctx, record)
		return degraded, coordinator.sagaError(record, ErrCrossHostSagaUncertain, errors.Join(err, persistErr))
	}
	next, err := coordinator.advance(record, receipt, now)
	if err != nil {
		degraded, persistErr := coordinator.markDegraded(ctx, record)
		return degraded, coordinator.sagaError(record, ErrCrossHostSagaUncertain, errors.Join(err, persistErr))
	}
	return coordinator.persistAdvance(ctx, record, next)
}

func (coordinator *CrossHostSagaCoordinator) executePhase(ctx context.Context, record CrossHostSagaRecord) (CrossHostStepReceipt, error) {
	stepContext := ctx
	cancel := func() {}
	if record.Phase == CrossHostPhaseDrain {
		stepContext, cancel = context.WithDeadline(ctx, record.DrainDeadline)
	} else {
		stepContext, cancel = context.WithTimeout(ctx, coordinator.stepLimit)
	}
	defer cancel()
	return coordinator.adapter.ExecuteCrossHost(stepContext, record.Phase, record)
}

func (coordinator *CrossHostSagaCoordinator) advance(record CrossHostSagaRecord, receipt CrossHostStepReceipt, now time.Time) (CrossHostSagaRecord, error) {
	next := record
	next.Revision++
	next.UpdatedAt = now
	next.LastErrorPhase = ""
	if record.Phase != CrossHostPhaseValidate {
		if err := receipt.Validate(record, now); err != nil {
			return CrossHostSagaRecord{}, err
		}
		next.GatewayGeneration = receipt.GatewayGeneration
		next.NodeGeneration = receipt.NodeGeneration
		next.PrivateReady = receipt.PrivateReady
		next.PublicRoutePublished = receipt.PublicRoutePublished
		next.Drained = receipt.Drained
	}
	switch record.Phase {
	case CrossHostPhaseValidate:
		next.Phase = CrossHostPhaseStage
		next.State = model.OperationStaging
	case CrossHostPhaseStage:
		next.Phase = CrossHostPhaseActivatePrivate
		next.State = model.OperationStaging
	case CrossHostPhaseActivatePrivate:
		next.Phase = CrossHostPhaseConfirmPrivate
		next.State = model.OperationStaging
	case CrossHostPhaseConfirmPrivate:
		next.Phase = CrossHostPhasePublishPublic
		next.State = model.OperationStaging
	case CrossHostPhasePublishPublic:
		next.Phase = CrossHostPhaseDrain
		next.State = model.OperationActive
		next.PublishedAt = receipt.EffectiveAt
		next.DrainDeadline = receipt.EffectiveAt.Add(record.Drain)
	case CrossHostPhaseDrain:
		next.Phase = CrossHostPhaseFinalize
		next.State = model.OperationActive
	case CrossHostPhaseFinalize:
		next.Phase = CrossHostPhaseComplete
		next.State = model.OperationCompleted
	default:
		return CrossHostSagaRecord{}, fmt.Errorf("cannot advance phase %s", record.Phase)
	}
	if err := next.Validate(); err != nil {
		return CrossHostSagaRecord{}, err
	}
	return next, nil
}

func (coordinator *CrossHostSagaCoordinator) persistAdvance(ctx context.Context, before, after CrossHostSagaRecord) (CrossHostSagaRecord, error) {
	err := runLocalAction(ctx, coordinator.stepLimit, func(step context.Context) error {
		return coordinator.store.SaveCrossHostSaga(step, before.Revision, after)
	})
	if err != nil {
		return after, coordinator.sagaError(before, ErrCrossHostSagaUncertain, err)
	}
	return after, nil
}

func (coordinator *CrossHostSagaCoordinator) markDegraded(ctx context.Context, record CrossHostSagaRecord) (CrossHostSagaRecord, error) {
	if record.State == model.OperationDegraded && record.LastErrorPhase == record.Phase {
		return record, nil
	}
	now, err := coordinator.currentTime()
	if err != nil {
		return record, err
	}
	degraded := record
	degraded.Revision++
	degraded.State = model.OperationDegraded
	degraded.LastErrorPhase = record.Phase
	degraded.UpdatedAt = now
	if err := degraded.Validate(); err != nil {
		return record, err
	}
	if err := runLocalAction(ctx, coordinator.stepLimit, func(step context.Context) error {
		return coordinator.store.SaveCrossHostSaga(step, record.Revision, degraded)
	}); err != nil {
		return degraded, err
	}
	return degraded, nil
}

func (coordinator *CrossHostSagaCoordinator) markFailed(ctx context.Context, record CrossHostSagaRecord) (CrossHostSagaRecord, error) {
	if record.State == model.OperationFailed && record.LastErrorPhase == record.Phase {
		return record, nil
	}
	now, err := coordinator.currentTime()
	if err != nil {
		return record, err
	}
	failed := record
	failed.Revision++
	failed.State = model.OperationFailed
	failed.LastErrorPhase = record.Phase
	failed.UpdatedAt = now
	if err := failed.Validate(); err != nil {
		return record, err
	}
	if err := runLocalAction(ctx, coordinator.stepLimit, func(step context.Context) error {
		return coordinator.store.SaveCrossHostSaga(step, record.Revision, failed)
	}); err != nil {
		return failed, err
	}
	return failed, nil
}

func (coordinator *CrossHostSagaCoordinator) sagaError(record CrossHostSagaRecord, sentinel error, cause error) error {
	return &CrossHostSagaError{OperationID: record.ID, Phase: record.Phase, Cause: errors.Join(sentinel, cause)}
}

func (coordinator *CrossHostSagaCoordinator) currentTime() (time.Time, error) {
	now := coordinator.now()
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("%w: clock returned zero time", ErrCrossHostSagaInvalid)
	}
	return now.UTC().Truncate(time.Second), nil
}

func (intent CrossHostSagaIntent) Validate() error {
	if err := model.ValidateResourceID(intent.RequestID); err != nil {
		return fmt.Errorf("%w: request ID: %v", ErrCrossHostSagaInvalid, err)
	}
	operationIntent := model.OperationIntent{
		Type: intent.Type, TargetKind: intent.TargetKind, TargetID: intent.TargetID,
		StepNames: []string{"validate", "stage", "activate-private", "confirm-private", "publish-public", "drain", "finalize"},
	}
	if err := operationIntent.Validate(); err != nil {
		return fmt.Errorf("%w: operation intent: %v", ErrCrossHostSagaInvalid, err)
	}
	if intent.ExpectedGatewayGeneration == 0 || intent.DesiredGatewayGeneration <= intent.ExpectedGatewayGeneration ||
		intent.ExpectedNodeGeneration == 0 || intent.DesiredNodeGeneration <= intent.ExpectedNodeGeneration {
		return fmt.Errorf("%w: desired host generations must advance positive expected generations", ErrCrossHostSagaInvalid)
	}
	if intent.Drain < 0 || intent.Drain > MaximumCrossHostDrain {
		return fmt.Errorf("%w: drain must be between zero and %s", ErrCrossHostSagaInvalid, MaximumCrossHostDrain)
	}
	return nil
}

func (record CrossHostSagaRecord) Validate() error {
	if record.SchemaVersion != CrossHostSagaSchemaVersion || record.Revision == 0 {
		return fmt.Errorf("schema version or revision is invalid")
	}
	if err := model.ValidateResourceID(record.ID); err != nil {
		return fmt.Errorf("ID: %w", err)
	}
	intent := CrossHostSagaIntent{
		RequestID: record.RequestID, Type: record.Type, TargetKind: record.TargetKind, TargetID: record.TargetID,
		ExpectedGatewayGeneration: record.ExpectedGatewayGeneration, DesiredGatewayGeneration: record.DesiredGatewayGeneration,
		ExpectedNodeGeneration: record.ExpectedNodeGeneration, DesiredNodeGeneration: record.DesiredNodeGeneration, Drain: record.Drain,
	}
	if err := intent.Validate(); err != nil {
		return err
	}
	if !validCrossHostPhase(record.Phase) || !validCrossHostOperationState(record.State) {
		return fmt.Errorf("phase or operation state is invalid")
	}
	if record.GatewayGeneration < record.ExpectedGatewayGeneration || record.GatewayGeneration > record.DesiredGatewayGeneration ||
		record.NodeGeneration < record.ExpectedNodeGeneration || record.NodeGeneration > record.DesiredNodeGeneration {
		return fmt.Errorf("observed host generation is outside the intent range")
	}
	if !validCrossHostTime(record.CreatedAt) || !validCrossHostTime(record.UpdatedAt) || record.UpdatedAt.Before(record.CreatedAt) {
		return fmt.Errorf("record timestamps are invalid")
	}
	if record.LastErrorPhase != "" && record.LastErrorPhase != record.Phase {
		return fmt.Errorf("last error phase must match current phase")
	}
	isErrorState := record.State == model.OperationDegraded || record.State == model.OperationFailed
	if isErrorState && record.LastErrorPhase == "" || !isErrorState && record.LastErrorPhase != "" {
		return fmt.Errorf("degraded or failed state and last error phase must agree")
	}
	if phaseBeforePublic(record.Phase) {
		if record.PublicRoutePublished || !record.PublishedAt.IsZero() || !record.DrainDeadline.IsZero() || record.Drained {
			return fmt.Errorf("public route or drain metadata appeared before publish phase")
		}
	} else {
		if !record.PublicRoutePublished || !validCrossHostTime(record.PublishedAt) || !validCrossHostTime(record.DrainDeadline) ||
			!record.DrainDeadline.Equal(record.PublishedAt.Add(record.Drain)) {
			return fmt.Errorf("published route deadline metadata is invalid")
		}
	}
	if record.Phase == CrossHostPhaseFinalize || record.Phase == CrossHostPhaseComplete {
		if !record.Drained {
			return fmt.Errorf("finalization requires completed bounded drain")
		}
	} else if record.Drained {
		return fmt.Errorf("drain completed before drain phase advanced")
	}
	if record.PrivateReady != (record.Phase == CrossHostPhasePublishPublic || !phaseBeforePublic(record.Phase)) {
		return fmt.Errorf("private readiness does not match phase")
	}
	switch record.State {
	case model.OperationPending:
		if record.Phase != CrossHostPhaseValidate {
			return fmt.Errorf("pending state requires validate phase")
		}
	case model.OperationStaging:
		if record.Phase == CrossHostPhaseValidate || !phaseBeforePublic(record.Phase) {
			return fmt.Errorf("staging state has invalid phase")
		}
	case model.OperationActive:
		if phaseBeforePublic(record.Phase) || record.Phase == CrossHostPhaseComplete {
			return fmt.Errorf("active state has invalid phase")
		}
	case model.OperationCompleted:
		if record.Phase != CrossHostPhaseComplete || record.GatewayGeneration != record.DesiredGatewayGeneration ||
			record.NodeGeneration != record.DesiredNodeGeneration || !record.PrivateReady || !record.PublicRoutePublished || !record.Drained {
			return fmt.Errorf("completed state is incomplete")
		}
	case model.OperationDegraded:
		if record.Phase == CrossHostPhaseComplete {
			return fmt.Errorf("completed phase cannot be degraded")
		}
	case model.OperationFailed:
		if record.Phase == CrossHostPhaseComplete {
			return fmt.Errorf("completed phase cannot be failed")
		}
	default:
		return fmt.Errorf("unsupported operation state")
	}
	return nil
}

func (observation CrossHostStepObservation) Validate(record CrossHostSagaRecord, now time.Time) error {
	switch observation.Status {
	case CrossHostStepApplied:
		return observation.Receipt.Validate(record, now)
	case CrossHostStepNotApplied, CrossHostStepUnknown:
		if !reflect.DeepEqual(observation.Receipt, CrossHostStepReceipt{}) {
			return fmt.Errorf("%w: non-applied observation must not include a receipt", ErrCrossHostSagaInvalid)
		}
		return nil
	default:
		return fmt.Errorf("%w: reconciliation status is invalid", ErrCrossHostSagaInvalid)
	}
}

func (receipt CrossHostStepReceipt) Validate(record CrossHostSagaRecord, now time.Time) error {
	if receipt.OperationID != record.ID || receipt.Phase != record.Phase {
		return fmt.Errorf("%w: step receipt identity or phase differs", ErrCrossHostSagaInvalid)
	}
	if receipt.GatewayGeneration < record.GatewayGeneration || receipt.GatewayGeneration > record.DesiredGatewayGeneration ||
		receipt.NodeGeneration < record.NodeGeneration || receipt.NodeGeneration > record.DesiredNodeGeneration {
		return fmt.Errorf("%w: step receipt generation is outside the remaining range", ErrCrossHostSagaInvalid)
	}
	wantPrivate := record.Phase == CrossHostPhaseConfirmPrivate || record.Phase == CrossHostPhasePublishPublic ||
		record.Phase == CrossHostPhaseDrain || record.Phase == CrossHostPhaseFinalize
	wantPublic := record.Phase == CrossHostPhasePublishPublic || record.Phase == CrossHostPhaseDrain || record.Phase == CrossHostPhaseFinalize
	wantDrained := record.Phase == CrossHostPhaseDrain || record.Phase == CrossHostPhaseFinalize
	if receipt.PrivateReady != wantPrivate || receipt.PublicRoutePublished != wantPublic || receipt.Drained != wantDrained {
		return fmt.Errorf("%w: step receipt violates private/public/drain phase ordering", ErrCrossHostSagaInvalid)
	}
	if record.Phase == CrossHostPhasePublishPublic {
		if !validCrossHostTime(receipt.EffectiveAt) || receipt.EffectiveAt.After(now) {
			return fmt.Errorf("%w: publication effective time is invalid", ErrCrossHostSagaInvalid)
		}
	} else if !receipt.EffectiveAt.IsZero() {
		return fmt.Errorf("%w: effective time is allowed only for publication", ErrCrossHostSagaInvalid)
	}
	if record.Phase == CrossHostPhaseFinalize &&
		(receipt.GatewayGeneration != record.DesiredGatewayGeneration || receipt.NodeGeneration != record.DesiredNodeGeneration) {
		return fmt.Errorf("%w: final receipt must reach both desired generations", ErrCrossHostSagaInvalid)
	}
	return nil
}

func (record CrossHostSagaRecord) matches(intent CrossHostSagaIntent) bool {
	return record.RequestID == intent.RequestID && record.Type == intent.Type && record.TargetKind == intent.TargetKind && record.TargetID == intent.TargetID &&
		record.ExpectedGatewayGeneration == intent.ExpectedGatewayGeneration && record.DesiredGatewayGeneration == intent.DesiredGatewayGeneration &&
		record.ExpectedNodeGeneration == intent.ExpectedNodeGeneration && record.DesiredNodeGeneration == intent.DesiredNodeGeneration && record.Drain == intent.Drain
}

func validCrossHostPhase(phase CrossHostSagaPhase) bool {
	switch phase {
	case CrossHostPhaseValidate, CrossHostPhaseStage, CrossHostPhaseActivatePrivate, CrossHostPhaseConfirmPrivate,
		CrossHostPhasePublishPublic, CrossHostPhaseDrain, CrossHostPhaseFinalize, CrossHostPhaseComplete:
		return true
	default:
		return false
	}
}

func validCrossHostOperationState(state model.OperationState) bool {
	switch state {
	case model.OperationPending, model.OperationStaging, model.OperationActive, model.OperationDegraded, model.OperationFailed, model.OperationCompleted:
		return true
	default:
		return false
	}
}

func phaseBeforePublic(phase CrossHostSagaPhase) bool {
	return phase == CrossHostPhaseValidate || phase == CrossHostPhaseStage || phase == CrossHostPhaseActivatePrivate ||
		phase == CrossHostPhaseConfirmPrivate || phase == CrossHostPhasePublishPublic
}

func validCrossHostTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}
