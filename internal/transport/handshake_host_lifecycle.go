package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const DefaultHandshakeHostRollbackWindow = 24 * time.Hour

var (
	ErrHandshakeHostChangeExists    = errors.New("a handshake-host replacement is already prepared")
	ErrHandshakeHostChangeNotFound  = errors.New("no prepared handshake-host replacement exists")
	ErrHandshakeHostRollbackPending = errors.New("the previous handshake-host snapshot is still available for rollback")
	ErrHandshakeHostRollbackExpired = errors.New("the handshake-host rollback snapshot has expired")
	ErrHandshakeHostImpactChanged   = errors.New("handshake-host replacement impact changed after prepare")
	ErrHandshakeHostPlanStale       = errors.New("handshake-host replacement plan is stale")
	ErrHandshakeHostCommitUncertain = errors.New("handshake-host state commit is uncertain")
)

type HandshakeHostStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

// HandshakeHostGatewayActivation is prepared and validated without changing
// the live listener. Activate must be an in-memory/atomic publication step
// after the authoritative candidate generation is durably committed.
type HandshakeHostGatewayActivation interface {
	Activate()
}

type HandshakeHostGatewayRuntime interface {
	Prepare(context.Context, model.State) (HandshakeHostGatewayActivation, error)
}

type HandshakeHostImpact struct {
	NodeIDs   []string
	ClientIDs []string
}

type HandshakeHostPreparePlan struct {
	OperationID             string
	Current                 model.HandshakeHost
	Candidate               model.HandshakeHost
	Impact                  HandshakeHostImpact
	ExpectedStateGeneration uint64
	NextStateGeneration     uint64
	SupersedesOperationID   string
	Probe                   HandshakeHostProbeResult

	beforeRaw []byte
}

type HandshakeHostCommitPlan struct {
	OperationID             string
	Current                 model.HandshakeHost
	Candidate               model.HandshakeHost
	Impact                  HandshakeHostImpact
	ExpectedStateGeneration uint64
	NextStateGeneration     uint64

	beforeRaw []byte
}

type HandshakeHostRollbackPlan struct {
	OperationID             string
	Current                 model.HandshakeHost
	Previous                model.HandshakeHost
	Impact                  HandshakeHostImpact
	ExpectedStateGeneration uint64
	NextStateGeneration     uint64
	RollbackExpiresAt       time.Time

	beforeRaw []byte
}

type HandshakeHostChangeResult struct {
	OperationID     string
	StateGeneration uint64
	Active          model.HandshakeHost
	Prepared        *model.HandshakeHost
	RollbackUntil   *time.Time
	StaleNodeIDs    []string
	StaleClientIDs  []string
}

type HandshakeHostView struct {
	State             model.HandshakeHostChangeState
	OperationID       string
	Active            model.HandshakeHost
	Health            HandshakeHostHealth
	Prepared          *model.HandshakeHost
	Impact            HandshakeHostImpact
	RollbackAvailable bool
	RollbackExpiresAt *time.Time
	StateGeneration   uint64
}

type HandshakeHostManager struct {
	state          HandshakeHostStateStore
	prober         HandshakeHostProber
	runtime        HandshakeHostGatewayRuntime
	now            func() time.Time
	newUUID        model.UUIDGenerator
	maximumLatency time.Duration
	rollbackWindow time.Duration
}

func NewHandshakeHostManager(state HandshakeHostStateStore, prober HandshakeHostProber, runtime HandshakeHostGatewayRuntime, now func() time.Time, newUUID model.UUIDGenerator) (*HandshakeHostManager, error) {
	if state == nil || prober == nil || runtime == nil {
		return nil, fmt.Errorf("handshake-host manager dependencies are incomplete")
	}
	if now == nil {
		now = time.Now
	}
	if newUUID == nil {
		newUUID = model.NewUUID
	}
	return &HandshakeHostManager{
		state: state, prober: prober, runtime: runtime, now: now, newUUID: newUUID,
		maximumLatency: DefaultHandshakeHostProbeTimeout, rollbackWindow: DefaultHandshakeHostRollbackWindow,
	}, nil
}

// Show probes only the active pinned host and evaluates that exact observation.
// It never reads the candidate list, probes an alternative, or mutates state.
func (manager *HandshakeHostManager) Show(ctx context.Context) (HandshakeHostView, error) {
	if ctx == nil {
		return HandshakeHostView{}, fmt.Errorf("context is required")
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return HandshakeHostView{}, err
	}
	active := *state.HandshakeHost
	probeContext, cancelProbe := context.WithTimeout(ctx, manager.maximumLatency)
	observation := manager.prober.Probe(probeContext, HandshakeHostCandidate{ID: active.CandidateID, Hostname: active.Hostname})
	cancelProbe()
	health, err := EvaluatePinnedHandshakeHost(active, observation, manager.maximumLatency)
	if err != nil {
		return HandshakeHostView{}, fmt.Errorf("evaluate active handshake host: %w", err)
	}
	view := HandshakeHostView{Active: active, Health: health, StateGeneration: state.Generation}
	if state.HandshakeHostChange == nil {
		return view, nil
	}
	change := state.HandshakeHostChange
	view.State, view.OperationID = change.State, change.OperationID
	view.Impact = cloneHandshakeHostImpact(HandshakeHostImpact{NodeIDs: change.AffectedNodeIDs, ClientIDs: change.AffectedClientIDs})
	if change.State == model.HandshakeHostPrepared {
		candidate := change.Candidate
		view.Prepared = &candidate
	}
	if change.RollbackExpiresAt != nil {
		expires := *change.RollbackExpiresAt
		view.RollbackExpiresAt = &expires
		view.RollbackAvailable = manager.now().UTC().Before(expires)
	}
	return view, nil
}

// PlanPrepare probes exactly the operator-supplied host. It does not scan the
// signed list, alter the listener, write pending state, or choose a fallback.
func (manager *HandshakeHostManager) PlanPrepare(ctx context.Context, hostname string) (HandshakeHostPreparePlan, error) {
	if ctx == nil {
		return HandshakeHostPreparePlan{}, fmt.Errorf("context is required")
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return HandshakeHostPreparePlan{}, err
	}
	now := manager.now().UTC()
	if now.IsZero() {
		return HandshakeHostPreparePlan{}, fmt.Errorf("handshake-host manager time is invalid")
	}
	if change := state.HandshakeHostChange; change != nil {
		switch change.State {
		case model.HandshakeHostPrepared:
			return HandshakeHostPreparePlan{}, ErrHandshakeHostChangeExists
		case model.HandshakeHostCommitted:
			if change.RollbackExpiresAt != nil && now.Before(*change.RollbackExpiresAt) {
				return HandshakeHostPreparePlan{}, ErrHandshakeHostRollbackPending
			}
		}
	}
	candidate, err := explicitHandshakeHostCandidate(hostname)
	if err != nil {
		return HandshakeHostPreparePlan{}, err
	}
	if candidate.Hostname == state.HandshakeHost.Hostname {
		return HandshakeHostPreparePlan{}, fmt.Errorf("handshake-host candidate is already active")
	}
	probeContext, cancelProbe := context.WithTimeout(ctx, manager.maximumLatency)
	probe := manager.prober.Probe(probeContext, candidate)
	cancelProbe()
	if !probe.passes(candidate, manager.maximumLatency) {
		return HandshakeHostPreparePlan{}, fmt.Errorf("%w: explicit candidate %s failed validation (%s)", ErrNoHandshakeHostCandidate, hostname, probe.Code)
	}
	occupied := handshakeHostOccupiedIDs(state)
	operationID, err := model.AllocateUUID(occupied, manager.newUUID)
	if err != nil {
		return HandshakeHostPreparePlan{}, fmt.Errorf("allocate handshake-host replacement operation: %w", err)
	}
	nextGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return HandshakeHostPreparePlan{}, err
	}
	selected := model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: state.HandshakeHost.ListVersion,
		CandidateID: candidate.ID, Hostname: candidate.Hostname, SelectedAt: now,
	}
	beforeRaw, err := model.EncodeState(state)
	if err != nil {
		return HandshakeHostPreparePlan{}, err
	}
	plan := HandshakeHostPreparePlan{
		OperationID: operationID, Current: *state.HandshakeHost, Candidate: selected,
		Impact: handshakeHostImpact(state), ExpectedStateGeneration: state.Generation, NextStateGeneration: nextGeneration,
		Probe: probe, beforeRaw: beforeRaw,
	}
	if state.HandshakeHostChange != nil {
		plan.SupersedesOperationID = state.HandshakeHostChange.OperationID
	}
	return plan, nil
}

func (manager *HandshakeHostManager) Prepare(plan HandshakeHostPreparePlan) (HandshakeHostChangeResult, error) {
	state, err := manager.requirePlanState(plan.beforeRaw, plan.ExpectedStateGeneration)
	if err != nil {
		return HandshakeHostChangeResult{}, err
	}
	if plan.OperationID == "" || plan.NextStateGeneration != state.Generation+1 || plan.Current != *state.HandshakeHost || plan.Candidate.Hostname == plan.Current.Hostname ||
		!reflect.DeepEqual(plan.Impact, handshakeHostImpact(state)) || !plan.Probe.passes(HandshakeHostCandidate{ID: plan.Candidate.CandidateID, Hostname: plan.Candidate.Hostname}, manager.maximumLatency) {
		return HandshakeHostChangeResult{}, fmt.Errorf("handshake-host prepare plan is invalid")
	}
	candidate := state
	candidate.Generation = plan.NextStateGeneration
	candidate.Operations = append([]model.Operation(nil), state.Operations...)
	if state.HandshakeHostChange != nil {
		if plan.SupersedesOperationID != state.HandshakeHostChange.OperationID || state.HandshakeHostChange.State != model.HandshakeHostCommitted ||
			state.HandshakeHostChange.RollbackExpiresAt == nil || manager.now().UTC().Before(*state.HandshakeHostChange.RollbackExpiresAt) {
			return HandshakeHostChangeResult{}, ErrHandshakeHostRollbackPending
		}
		operationIndex := handshakeHostOperationIndex(candidate, state.HandshakeHostChange.OperationID)
		if operationIndex < 0 {
			return HandshakeHostChangeResult{}, fmt.Errorf("expired handshake-host operation is missing")
		}
		completed, transitionErr := candidate.Operations[operationIndex].Transition(model.OperationCompleted, plan.Candidate.SelectedAt, "")
		if transitionErr != nil {
			return HandshakeHostChangeResult{}, transitionErr
		}
		candidate.Operations[operationIndex] = completed
	} else if plan.SupersedesOperationID != "" {
		return HandshakeHostChangeResult{}, fmt.Errorf("handshake-host prepare plan supersedes an absent operation")
	}
	operation := model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: plan.OperationID, Type: model.OperationHandshakeHost, State: model.OperationPending,
		TargetKind: "transport", TargetID: plan.Candidate.CandidateID, ExpectedGeneration: state.Generation, DesiredGeneration: plan.NextStateGeneration,
		Steps: []model.OperationStep{}, CreatedAt: plan.Candidate.SelectedAt, UpdatedAt: plan.Candidate.SelectedAt,
	}
	candidate.Operations = append(candidate.Operations, operation)
	change := model.HandshakeHostChange{
		SchemaVersion: model.ResourceSchemaVersion, OperationID: plan.OperationID, State: model.HandshakeHostPrepared,
		Previous: plan.Current, Candidate: plan.Candidate,
		AffectedNodeIDs: append([]string(nil), plan.Impact.NodeIDs...), AffectedClientIDs: append([]string(nil), plan.Impact.ClientIDs...),
		PreparedAt: plan.Candidate.SelectedAt,
	}
	candidate.HandshakeHostChange = &change
	prepared := plan.Candidate
	result := HandshakeHostChangeResult{
		OperationID: plan.OperationID, StateGeneration: candidate.Generation, Active: plan.Current, Prepared: &prepared,
	}
	if err := manager.state.Save(state.Generation, candidate); err != nil {
		committed, reconcileErr := manager.reconcileStateWrite(state, candidate, nil, err, "prepared handshake-host replacement")
		if committed {
			return result, reconcileErr
		}
		return HandshakeHostChangeResult{}, reconcileErr
	}
	return result, nil
}

func (manager *HandshakeHostManager) PlanCommit() (HandshakeHostCommitPlan, error) {
	state, err := manager.loadGatewayState()
	if err != nil {
		return HandshakeHostCommitPlan{}, err
	}
	change := state.HandshakeHostChange
	if change == nil || change.State != model.HandshakeHostPrepared {
		return HandshakeHostCommitPlan{}, ErrHandshakeHostChangeNotFound
	}
	impact := handshakeHostImpact(state)
	want := HandshakeHostImpact{NodeIDs: change.AffectedNodeIDs, ClientIDs: change.AffectedClientIDs}
	if !reflect.DeepEqual(impact, want) {
		return HandshakeHostCommitPlan{}, ErrHandshakeHostImpactChanged
	}
	nextGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return HandshakeHostCommitPlan{}, err
	}
	raw, err := model.EncodeState(state)
	if err != nil {
		return HandshakeHostCommitPlan{}, err
	}
	return HandshakeHostCommitPlan{
		OperationID: change.OperationID, Current: change.Previous, Candidate: change.Candidate, Impact: cloneHandshakeHostImpact(impact),
		ExpectedStateGeneration: state.Generation, NextStateGeneration: nextGeneration, beforeRaw: raw,
	}, nil
}

func (manager *HandshakeHostManager) Commit(ctx context.Context, plan HandshakeHostCommitPlan) (HandshakeHostChangeResult, error) {
	if ctx == nil {
		return HandshakeHostChangeResult{}, fmt.Errorf("context is required")
	}
	state, err := manager.requirePlanState(plan.beforeRaw, plan.ExpectedStateGeneration)
	if err != nil {
		return HandshakeHostChangeResult{}, err
	}
	change := state.HandshakeHostChange
	if change == nil || change.State != model.HandshakeHostPrepared || change.OperationID != plan.OperationID || change.Previous != plan.Current || change.Candidate != plan.Candidate ||
		plan.NextStateGeneration != state.Generation+1 || !reflect.DeepEqual(plan.Impact, handshakeHostImpact(state)) {
		return HandshakeHostChangeResult{}, ErrHandshakeHostImpactChanged
	}
	candidateDescriptor := HandshakeHostCandidate{ID: plan.Candidate.CandidateID, Hostname: plan.Candidate.Hostname}
	probeContext, cancelProbe := context.WithTimeout(ctx, manager.maximumLatency)
	probe := manager.prober.Probe(probeContext, candidateDescriptor)
	cancelProbe()
	if !probe.passes(candidateDescriptor, manager.maximumLatency) {
		return HandshakeHostChangeResult{}, fmt.Errorf("%w: prepared candidate failed commit validation (%s)", ErrNoHandshakeHostCandidate, probe.Code)
	}
	now := manager.now().UTC()
	expires := now.Add(manager.rollbackWindow)
	candidate := state
	candidate.Generation = plan.NextStateGeneration
	selection := plan.Candidate
	candidate.HandshakeHost = &selection
	candidate.Transports = transportsWithHandshakeHost(state.Transports, selection.Hostname)
	candidate.Operations = append([]model.Operation(nil), state.Operations...)
	operationIndex := handshakeHostOperationIndex(candidate, plan.OperationID)
	if operationIndex < 0 {
		return HandshakeHostChangeResult{}, fmt.Errorf("prepared handshake-host operation is missing")
	}
	activeOperation, err := candidate.Operations[operationIndex].Transition(model.OperationActive, now, "")
	if err != nil {
		return HandshakeHostChangeResult{}, err
	}
	candidate.Operations[operationIndex] = activeOperation
	committed := *change
	committed.State, committed.CommittedAt, committed.RollbackExpiresAt = model.HandshakeHostCommitted, &now, &expires
	candidate.HandshakeHostChange = &committed
	activation, err := manager.runtime.Prepare(ctx, candidate)
	if err != nil {
		return HandshakeHostChangeResult{}, fmt.Errorf("prepare gateway restricted listener for handshake-host commit: %w", err)
	}
	if activation == nil {
		return HandshakeHostChangeResult{}, fmt.Errorf("prepare gateway restricted listener for handshake-host commit: empty activation")
	}
	result := HandshakeHostChangeResult{
		OperationID: plan.OperationID, StateGeneration: candidate.Generation, Active: selection, RollbackUntil: &expires,
		StaleNodeIDs: append([]string(nil), committed.AffectedNodeIDs...), StaleClientIDs: append([]string(nil), committed.AffectedClientIDs...),
	}
	if err := manager.state.Save(state.Generation, candidate); err != nil {
		committedState, reconcileErr := manager.reconcileStateWrite(state, candidate, activation, err, "committed handshake-host replacement")
		if committedState {
			return result, reconcileErr
		}
		return HandshakeHostChangeResult{}, reconcileErr
	}
	activation.Activate()
	return result, nil
}

func (manager *HandshakeHostManager) PlanRollback() (HandshakeHostRollbackPlan, error) {
	state, err := manager.loadGatewayState()
	if err != nil {
		return HandshakeHostRollbackPlan{}, err
	}
	change := state.HandshakeHostChange
	if change == nil || change.State != model.HandshakeHostCommitted || change.RollbackExpiresAt == nil {
		return HandshakeHostRollbackPlan{}, ErrHandshakeHostChangeNotFound
	}
	if !manager.now().UTC().Before(*change.RollbackExpiresAt) {
		return HandshakeHostRollbackPlan{}, ErrHandshakeHostRollbackExpired
	}
	nextGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return HandshakeHostRollbackPlan{}, err
	}
	raw, err := model.EncodeState(state)
	if err != nil {
		return HandshakeHostRollbackPlan{}, err
	}
	return HandshakeHostRollbackPlan{
		OperationID: change.OperationID, Current: change.Candidate, Previous: change.Previous,
		Impact: cloneHandshakeHostImpact(handshakeHostImpact(state)), ExpectedStateGeneration: state.Generation,
		NextStateGeneration: nextGeneration, RollbackExpiresAt: *change.RollbackExpiresAt, beforeRaw: raw,
	}, nil
}

func (manager *HandshakeHostManager) Rollback(ctx context.Context, plan HandshakeHostRollbackPlan) (HandshakeHostChangeResult, error) {
	if ctx == nil {
		return HandshakeHostChangeResult{}, fmt.Errorf("context is required")
	}
	state, err := manager.requirePlanState(plan.beforeRaw, plan.ExpectedStateGeneration)
	if err != nil {
		return HandshakeHostChangeResult{}, err
	}
	change := state.HandshakeHostChange
	if change == nil || change.State != model.HandshakeHostCommitted || change.OperationID != plan.OperationID || change.Candidate != plan.Current || change.Previous != plan.Previous ||
		change.RollbackExpiresAt == nil || !change.RollbackExpiresAt.Equal(plan.RollbackExpiresAt) || plan.NextStateGeneration != state.Generation+1 ||
		!reflect.DeepEqual(plan.Impact, handshakeHostImpact(state)) {
		return HandshakeHostChangeResult{}, fmt.Errorf("handshake-host rollback plan is invalid")
	}
	if !manager.now().UTC().Before(plan.RollbackExpiresAt) {
		return HandshakeHostChangeResult{}, ErrHandshakeHostRollbackExpired
	}
	now := manager.now().UTC()
	candidate := state
	candidate.Generation = plan.NextStateGeneration
	previous := plan.Previous
	candidate.HandshakeHost = &previous
	candidate.HandshakeHostChange = nil
	candidate.Transports = transportsWithHandshakeHost(state.Transports, previous.Hostname)
	candidate.Operations = append([]model.Operation(nil), state.Operations...)
	operationIndex := handshakeHostOperationIndex(candidate, plan.OperationID)
	if operationIndex < 0 {
		return HandshakeHostChangeResult{}, fmt.Errorf("committed handshake-host operation is missing")
	}
	failedOperation, err := candidate.Operations[operationIndex].Transition(model.OperationFailed, now, "operator-rollback")
	if err != nil {
		return HandshakeHostChangeResult{}, err
	}
	candidate.Operations[operationIndex] = failedOperation
	activation, err := manager.runtime.Prepare(ctx, candidate)
	if err != nil {
		return HandshakeHostChangeResult{}, fmt.Errorf("prepare gateway restricted listener for handshake-host rollback: %w", err)
	}
	if activation == nil {
		return HandshakeHostChangeResult{}, fmt.Errorf("prepare gateway restricted listener for handshake-host rollback: empty activation")
	}
	result := HandshakeHostChangeResult{
		OperationID: plan.OperationID, StateGeneration: candidate.Generation, Active: previous,
		StaleNodeIDs: append([]string(nil), plan.Impact.NodeIDs...), StaleClientIDs: append([]string(nil), plan.Impact.ClientIDs...),
	}
	if err := manager.state.Save(state.Generation, candidate); err != nil {
		committedState, reconcileErr := manager.reconcileStateWrite(state, candidate, activation, err, "handshake-host rollback")
		if committedState {
			return result, reconcileErr
		}
		return HandshakeHostChangeResult{}, reconcileErr
	}
	activation.Activate()
	return result, nil
}

func (manager *HandshakeHostManager) loadGatewayState() (model.State, error) {
	if manager == nil || manager.state == nil || manager.prober == nil || manager.runtime == nil || manager.now == nil || manager.newUUID == nil {
		return model.State{}, fmt.Errorf("handshake-host manager is incomplete")
	}
	state, err := manager.state.Load()
	if err != nil {
		return model.State{}, fmt.Errorf("load authoritative handshake-host state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return model.State{}, fmt.Errorf("validate authoritative handshake-host state: %w", err)
	}
	if state.Host.Role != model.RoleGateway || state.HandshakeHost == nil {
		return model.State{}, fmt.Errorf("handshake-host lifecycle requires initialized gateway state")
	}
	return state, nil
}

func (manager *HandshakeHostManager) requirePlanState(want []byte, generation uint64) (model.State, error) {
	state, err := manager.loadGatewayState()
	if err != nil {
		return model.State{}, err
	}
	raw, err := model.EncodeState(state)
	if err != nil {
		return model.State{}, err
	}
	if len(want) == 0 || generation != state.Generation || !bytes.Equal(want, raw) {
		return model.State{}, ErrHandshakeHostPlanStale
	}
	return state, nil
}

func (manager *HandshakeHostManager) reconcileStateWrite(before, candidate model.State, activation HandshakeHostGatewayActivation, saveErr error, operation string) (bool, error) {
	loaded, loadErr := manager.state.Load()
	if loadErr == nil {
		loadedRaw, encodeErr := model.EncodeState(loaded)
		candidateRaw, candidateErr := model.EncodeState(candidate)
		beforeRaw, beforeErr := model.EncodeState(before)
		switch {
		case encodeErr == nil && candidateErr == nil && bytes.Equal(loadedRaw, candidateRaw):
			if activation != nil {
				activation.Activate()
			}
			return true, fmt.Errorf("%w: %s generation is active after save error: %v", ErrHandshakeHostCommitUncertain, operation, saveErr)
		case encodeErr == nil && beforeErr == nil && bytes.Equal(loadedRaw, beforeRaw):
			return false, fmt.Errorf("persist %s: %w", operation, saveErr)
		}
	}
	return false, errors.Join(ErrHandshakeHostCommitUncertain, saveErr, loadErr)
}

func explicitHandshakeHostCandidate(hostname string) (HandshakeHostCandidate, error) {
	publicKey, err := base64.RawURLEncoding.DecodeString(bundledHandshakeHostPublicKey)
	if err != nil {
		return HandshakeHostCandidate{}, err
	}
	bundle, err := DecodeAndVerifyHandshakeHostBundle(bundledHandshakeHostEnvelope, ed25519.PublicKey(publicKey))
	if err != nil {
		return HandshakeHostCandidate{}, err
	}
	for _, candidate := range bundle.Candidates {
		if candidate.Hostname == hostname {
			return candidate, nil
		}
	}
	digest := sha256.Sum256([]byte(hostname))
	candidate := HandshakeHostCandidate{ID: "manual-" + hex.EncodeToString(digest[:])[:16], Hostname: hostname}
	if err := validateHandshakeHostCandidate(candidate); err != nil {
		return HandshakeHostCandidate{}, fmt.Errorf("invalid explicit handshake host: %w", err)
	}
	return candidate, nil
}

func handshakeHostImpact(state model.State) HandshakeHostImpact {
	activeNodes := make(map[string]bool, len(state.Nodes))
	activeClients := make(map[string]bool, len(state.Clients))
	for _, node := range state.Nodes {
		activeNodes[node.ID] = node.Lifecycle == model.LifecycleActive
	}
	for _, client := range state.Clients {
		activeClients[client.ID] = client.Lifecycle == model.LifecycleActive
	}
	impact := HandshakeHostImpact{NodeIDs: []string{}, ClientIDs: []string{}}
	for _, transport := range state.Transports {
		if transport.Kind != model.TransportRestricted || transport.State == model.TransportDisabled {
			continue
		}
		if transport.OwnerKind == model.TargetNode && activeNodes[transport.OwnerID] {
			impact.NodeIDs = append(impact.NodeIDs, transport.OwnerID)
		}
		if transport.OwnerKind == model.TargetClient && activeClients[transport.OwnerID] {
			impact.ClientIDs = append(impact.ClientIDs, transport.OwnerID)
		}
	}
	sort.Strings(impact.NodeIDs)
	sort.Strings(impact.ClientIDs)
	return impact
}

func cloneHandshakeHostImpact(impact HandshakeHostImpact) HandshakeHostImpact {
	return HandshakeHostImpact{NodeIDs: append([]string(nil), impact.NodeIDs...), ClientIDs: append([]string(nil), impact.ClientIDs...)}
}

func transportsWithHandshakeHost(values []model.Transport, hostname string) []model.Transport {
	result := append([]model.Transport(nil), values...)
	for index := range result {
		if result[index].Kind == model.TransportRestricted {
			result[index].HandshakeHost = hostname
		}
	}
	return result
}

func handshakeHostOccupiedIDs(state model.State) map[string]struct{} {
	occupied := make(map[string]struct{}, len(state.Nodes)+len(state.Clients)+len(state.Operations)+1)
	occupied[state.Host.ID] = struct{}{}
	for _, node := range state.Nodes {
		occupied[node.ID] = struct{}{}
	}
	for _, client := range state.Clients {
		occupied[client.ID] = struct{}{}
	}
	for _, operation := range state.Operations {
		occupied[operation.ID] = struct{}{}
	}
	return occupied
}

func handshakeHostOperationIndex(state model.State, operationID string) int {
	for index := range state.Operations {
		if state.Operations[index].ID == operationID {
			return index
		}
	}
	return -1
}
