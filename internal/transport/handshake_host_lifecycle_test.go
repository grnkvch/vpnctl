package transport

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestHandshakeHostPreparePersistsOneValidatedCandidateAndImpact(t *testing.T) {
	t.Parallel()

	fixture := newHandshakeHostLifecycleFixture(t)
	before := fixture.store.state
	plan, err := fixture.manager.PlanPrepare(context.Background(), "www.apple.com")
	if err != nil {
		t.Fatalf("PlanPrepare() error = %v", err)
	}
	if plan.Current.Hostname != "www.microsoft.com" || plan.Candidate.CandidateID != "apple" || plan.Candidate.Hostname != "www.apple.com" ||
		!reflect.DeepEqual(plan.Impact.NodeIDs, []string{lifecycleNodeID}) || !reflect.DeepEqual(plan.Impact.ClientIDs, []string{lifecycleClientID}) {
		t.Fatalf("prepare plan = %+v", plan)
	}
	if fixture.store.saves != 0 || fixture.runtime.prepares != 0 || fixture.store.state.Generation != before.Generation {
		t.Fatal("read-only prepare planning mutated gateway")
	}
	result, err := fixture.manager.Prepare(plan)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	state := fixture.store.state
	if result.Active.Hostname != "www.microsoft.com" || result.Prepared == nil || result.Prepared.Hostname != "www.apple.com" || result.StateGeneration != before.Generation+1 {
		t.Fatalf("prepare result = %+v", result)
	}
	if state.HandshakeHost.Hostname != "www.microsoft.com" || state.HandshakeHostChange == nil || state.HandshakeHostChange.State != model.HandshakeHostPrepared ||
		state.HandshakeHostChange.OperationID != plan.OperationID || state.Operations[len(state.Operations)-1].State != model.OperationPending || fixture.runtime.prepares != 0 {
		t.Fatalf("prepared state/runtime = %+v / %d", state.HandshakeHostChange, fixture.runtime.prepares)
	}
	view, err := fixture.manager.Show(context.Background())
	if err != nil || view.Prepared == nil || view.Prepared.Hostname != "www.apple.com" || view.RollbackAvailable {
		t.Fatalf("prepared Show() = %+v, %v", view, err)
	}
	if view.Health.Condition != HealthHealthy || !reflect.DeepEqual(fixture.prober.calls, []string{"apple", "microsoft"}) {
		t.Fatalf("prepared Show() health/calls = %+v / %v", view.Health, fixture.prober.calls)
	}
	if _, err := fixture.manager.PlanPrepare(context.Background(), "www.cloudflare.com"); !errors.Is(err, ErrHandshakeHostChangeExists) {
		t.Fatalf("second prepare error = %v", err)
	}
}

func TestHandshakeHostPrepareProbesOnlyExplicitCandidateAndFailureIsReadOnly(t *testing.T) {
	t.Parallel()

	fixture := newHandshakeHostLifecycleFixture(t)
	fixture.prober.results["apple"] = HandshakeHostProbeResult{
		CandidateID: "apple", Hostname: "www.apple.com", ObservedAt: fixture.clock.now,
		Reachable: false, TLS13: false, CertificateValid: false, Code: "unavailable",
	}
	before, _ := model.EncodeState(fixture.store.state)
	if _, err := fixture.manager.PlanPrepare(context.Background(), "www.apple.com"); !errors.Is(err, ErrNoHandshakeHostCandidate) {
		t.Fatalf("failed candidate error = %v", err)
	}
	after, _ := model.EncodeState(fixture.store.state)
	if !reflect.DeepEqual(fixture.prober.calls, []string{"apple"}) || !reflect.DeepEqual(before, after) || fixture.store.saves != 0 || fixture.runtime.prepares != 0 {
		t.Fatalf("failed explicit probe had side effects/fallback: calls=%v", fixture.prober.calls)
	}
}

func TestHandshakeHostShowChecksOnlyActiveCandidateAndReportsDegraded(t *testing.T) {
	t.Parallel()

	fixture := newHandshakeHostLifecycleFixture(t)
	fixture.prober.results["microsoft"] = HandshakeHostProbeResult{
		CandidateID: "microsoft", Hostname: "www.microsoft.com", ObservedAt: fixture.clock.now,
		Code: "unavailable",
	}
	view, err := fixture.manager.Show(context.Background())
	if err != nil {
		t.Fatalf("Show() error = %v", err)
	}
	if view.Active.Hostname != "www.microsoft.com" || view.Health.Condition != HealthDegraded || !view.Health.RequiresAction ||
		!reflect.DeepEqual(fixture.prober.calls, []string{"microsoft"}) {
		t.Fatalf("degraded Show() = %+v, calls %v", view, fixture.prober.calls)
	}
	if fixture.store.saves != 0 || fixture.runtime.prepares != 0 || fixture.runtime.activations != 0 {
		t.Fatal("degraded active-host observation mutated state or runtime")
	}
}

func TestHandshakeHostCommitActivatesOneHostAndReportsStaleArtifacts(t *testing.T) {
	t.Parallel()

	fixture := newHandshakeHostLifecycleFixture(t)
	preparePlan, _ := fixture.manager.PlanPrepare(context.Background(), "www.apple.com")
	prepared, err := fixture.manager.Prepare(preparePlan)
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.now = fixture.clock.now.Add(time.Hour)
	commitPlan, err := fixture.manager.PlanCommit()
	if err != nil {
		t.Fatalf("PlanCommit() error = %v", err)
	}
	if commitPlan.OperationID != prepared.OperationID || commitPlan.Current.Hostname != "www.microsoft.com" || commitPlan.Candidate.Hostname != "www.apple.com" {
		t.Fatalf("commit plan = %+v", commitPlan)
	}
	fixture.runtime.trace = nil
	result, err := fixture.manager.Commit(context.Background(), commitPlan)
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	state := fixture.store.state
	if result.Active.Hostname != "www.apple.com" || result.RollbackUntil == nil || result.StateGeneration != commitPlan.NextStateGeneration ||
		!reflect.DeepEqual(result.StaleNodeIDs, []string{lifecycleNodeID}) || !reflect.DeepEqual(result.StaleClientIDs, []string{lifecycleClientID}) {
		t.Fatalf("commit result = %+v", result)
	}
	if state.HandshakeHost.Hostname != "www.apple.com" || state.HandshakeHostChange == nil || state.HandshakeHostChange.State != model.HandshakeHostCommitted ||
		state.Operations[len(state.Operations)-1].State != model.OperationActive {
		t.Fatalf("committed state = %+v", state.HandshakeHostChange)
	}
	for _, transport := range state.Transports {
		if transport.Kind == model.TransportRestricted && transport.HandshakeHost != "www.apple.com" {
			t.Fatalf("restricted transport %s retained old host", transport.OwnerID)
		}
	}
	if fixture.runtime.prepares != 1 || fixture.runtime.activations != 1 || !reflect.DeepEqual(fixture.runtime.trace, []string{"runtime.prepare", "state.save", "runtime.activate"}) {
		t.Fatalf("runtime activation trace = %v", fixture.runtime.trace)
	}
	view, err := fixture.manager.Show(context.Background())
	if err != nil || view.Active.Hostname != "www.apple.com" || !view.RollbackAvailable || view.RollbackExpiresAt == nil || view.Prepared != nil {
		t.Fatalf("committed Show() = %+v, %v", view, err)
	}
	if view.Health.Condition != HealthHealthy || !reflect.DeepEqual(fixture.prober.calls, []string{"apple", "apple", "apple"}) {
		t.Fatalf("prepare/commit probes = %v", fixture.prober.calls)
	}
}

func TestHandshakeHostCommitRejectsChangedImpactAndFailedRevalidation(t *testing.T) {
	t.Parallel()

	t.Run("impact changed", func(t *testing.T) {
		t.Parallel()
		fixture := newHandshakeHostLifecycleFixture(t)
		preparePlan, _ := fixture.manager.PlanPrepare(context.Background(), "www.apple.com")
		_, _ = fixture.manager.Prepare(preparePlan)
		before := fixture.store.state
		candidate := before
		candidate.Generation++
		candidate.Clients = append([]model.Client(nil), before.Clients...)
		candidate.Transports = append([]model.Transport(nil), before.Transports...)
		candidate.Clients[0].Lifecycle = model.LifecycleRevoked
		revoked := fixture.clock.now.Add(time.Minute)
		candidate.Clients[0].RevokedAt = &revoked
		for index := range candidate.Transports {
			if candidate.Transports[index].OwnerKind == model.TargetClient {
				candidate.Transports[index].State = model.TransportDisabled
			}
		}
		if err := fixture.store.Save(before.Generation, candidate); err != nil {
			t.Fatalf("Save(unrelated impact change) error = %v", err)
		}
		if _, err := fixture.manager.PlanCommit(); !errors.Is(err, ErrHandshakeHostImpactChanged) {
			t.Fatalf("changed-impact PlanCommit() error = %v", err)
		}
		if fixture.runtime.prepares != 0 || fixture.store.state.HandshakeHost.Hostname != "www.microsoft.com" {
			t.Fatal("impact conflict activated candidate")
		}
	})

	t.Run("candidate fails fresh probe", func(t *testing.T) {
		t.Parallel()
		fixture := newHandshakeHostLifecycleFixture(t)
		preparePlan, _ := fixture.manager.PlanPrepare(context.Background(), "www.apple.com")
		_, _ = fixture.manager.Prepare(preparePlan)
		plan, _ := fixture.manager.PlanCommit()
		fixture.prober.results["apple"] = HandshakeHostProbeResult{CandidateID: "apple", Hostname: "www.apple.com", ObservedAt: fixture.clock.now, Code: "unavailable"}
		if _, err := fixture.manager.Commit(context.Background(), plan); !errors.Is(err, ErrNoHandshakeHostCandidate) {
			t.Fatalf("failed revalidation Commit() error = %v", err)
		}
		if fixture.runtime.prepares != 0 || fixture.store.state.HandshakeHost.Hostname != "www.microsoft.com" || fixture.store.state.HandshakeHostChange.State != model.HandshakeHostPrepared {
			t.Fatal("failed commit revalidation changed active state")
		}
	})
}

func TestHandshakeHostRollbackRestoresExactSnapshotAndReportsRestaleness(t *testing.T) {
	t.Parallel()

	fixture := newHandshakeHostLifecycleFixture(t)
	preparePlan, _ := fixture.manager.PlanPrepare(context.Background(), "www.apple.com")
	_, _ = fixture.manager.Prepare(preparePlan)
	fixture.clock.now = fixture.clock.now.Add(time.Hour)
	commitPlan, _ := fixture.manager.PlanCommit()
	_, _ = fixture.manager.Commit(context.Background(), commitPlan)
	fixture.clock.now = fixture.clock.now.Add(time.Hour)
	rollbackPlan, err := fixture.manager.PlanRollback()
	if err != nil {
		t.Fatalf("PlanRollback() error = %v", err)
	}
	fixture.runtime.trace = nil
	result, err := fixture.manager.Rollback(context.Background(), rollbackPlan)
	if err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	state := fixture.store.state
	if result.Active != preparePlan.Current || state.HandshakeHost == nil || *state.HandshakeHost != preparePlan.Current || state.HandshakeHostChange != nil ||
		!reflect.DeepEqual(result.StaleNodeIDs, []string{lifecycleNodeID}) || !reflect.DeepEqual(result.StaleClientIDs, []string{lifecycleClientID}) {
		t.Fatalf("rollback result/state = %+v / %+v", result, state.HandshakeHostChange)
	}
	operation := state.Operations[len(state.Operations)-1]
	if operation.State != model.OperationFailed || operation.ErrorCode != "operator-rollback" {
		t.Fatalf("rolled-back operation = %+v", operation)
	}
	if !reflect.DeepEqual(fixture.runtime.trace, []string{"runtime.prepare", "state.save", "runtime.activate"}) {
		t.Fatalf("rollback runtime trace = %v", fixture.runtime.trace)
	}
	for _, transport := range state.Transports {
		if transport.Kind == model.TransportRestricted && transport.HandshakeHost != "www.microsoft.com" {
			t.Fatalf("rollback retained candidate in %s", transport.OwnerID)
		}
	}
}

func TestHandshakeHostRollbackRejectsTamperedImpactBeforeRuntimeMutation(t *testing.T) {
	t.Parallel()

	fixture := newHandshakeHostLifecycleFixture(t)
	preparePlan, _ := fixture.manager.PlanPrepare(context.Background(), "www.apple.com")
	_, _ = fixture.manager.Prepare(preparePlan)
	commitPlan, _ := fixture.manager.PlanCommit()
	_, _ = fixture.manager.Commit(context.Background(), commitPlan)
	rollbackPlan, _ := fixture.manager.PlanRollback()
	rollbackPlan.Impact.ClientIDs = nil
	prepares := fixture.runtime.prepares
	if _, err := fixture.manager.Rollback(context.Background(), rollbackPlan); err == nil || !strings.Contains(err.Error(), "rollback plan is invalid") {
		t.Fatalf("Rollback(tampered impact) error = %v", err)
	}
	if fixture.runtime.prepares != prepares || fixture.store.state.HandshakeHost.Hostname != "www.apple.com" {
		t.Fatal("tampered rollback impact reached runtime or changed active host")
	}
}

func TestHandshakeHostRollbackExpiresAndNextPrepareSupersedesSnapshot(t *testing.T) {
	t.Parallel()

	fixture := newHandshakeHostLifecycleFixture(t)
	preparePlan, _ := fixture.manager.PlanPrepare(context.Background(), "www.apple.com")
	_, _ = fixture.manager.Prepare(preparePlan)
	fixture.clock.now = fixture.clock.now.Add(time.Hour)
	commitPlan, _ := fixture.manager.PlanCommit()
	_, _ = fixture.manager.Commit(context.Background(), commitPlan)

	fixture.clock.now = fixture.clock.now.Add(DefaultHandshakeHostRollbackWindow)
	if _, err := fixture.manager.PlanRollback(); !errors.Is(err, ErrHandshakeHostRollbackExpired) {
		t.Fatalf("expired PlanRollback() error = %v", err)
	}
	plan, err := fixture.manager.PlanPrepare(context.Background(), "www.cloudflare.com")
	if err != nil || plan.SupersedesOperationID != preparePlan.OperationID {
		t.Fatalf("replacement after expiry plan = %+v, %v", plan, err)
	}
	if _, err := fixture.manager.Prepare(plan); err != nil {
		t.Fatalf("replacement after expiry Prepare() error = %v", err)
	}
	state := fixture.store.state
	if state.HandshakeHost.Hostname != "www.apple.com" || state.HandshakeHostChange.Candidate.Hostname != "www.cloudflare.com" ||
		state.Operations[len(state.Operations)-2].State != model.OperationCompleted || state.Operations[len(state.Operations)-1].State != model.OperationPending {
		t.Fatalf("superseded snapshot state = active=%s change=%+v operations=%+v", state.HandshakeHost.Hostname, state.HandshakeHostChange, state.Operations)
	}
}

func TestHandshakeHostCommitRuntimeOrStateFailureNeverActivatesCandidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		runtimeFail bool
		stateFail   bool
	}{
		{name: "runtime prepare", runtimeFail: true},
		{name: "state commit", stateFail: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newHandshakeHostLifecycleFixture(t)
			preparePlan, _ := fixture.manager.PlanPrepare(context.Background(), "www.apple.com")
			_, _ = fixture.manager.Prepare(preparePlan)
			plan, _ := fixture.manager.PlanCommit()
			fixture.runtime.fail = test.runtimeFail
			fixture.store.fail = test.stateFail
			if _, err := fixture.manager.Commit(context.Background(), plan); err == nil {
				t.Fatal("Commit() succeeded with injected failure")
			}
			if fixture.runtime.activations != 0 || fixture.store.state.HandshakeHost.Hostname != "www.microsoft.com" || fixture.store.state.HandshakeHostChange.State != model.HandshakeHostPrepared {
				t.Fatalf("failed commit activated candidate: activations=%d state=%+v", fixture.runtime.activations, fixture.store.state.HandshakeHostChange)
			}
		})
	}
}

func TestHandshakeHostCommitActivatesCandidateAfterCommittedWriteError(t *testing.T) {
	t.Parallel()

	fixture := newHandshakeHostLifecycleFixture(t)
	preparePlan, _ := fixture.manager.PlanPrepare(context.Background(), "www.apple.com")
	_, _ = fixture.manager.Prepare(preparePlan)
	plan, _ := fixture.manager.PlanCommit()
	fixture.store.fail = true
	fixture.store.commitBeforeError = true
	result, err := fixture.manager.Commit(context.Background(), plan)
	if !errors.Is(err, ErrHandshakeHostCommitUncertain) {
		t.Fatalf("committed write error = %v", err)
	}
	if result.Active.Hostname != "www.apple.com" || fixture.store.state.HandshakeHost.Hostname != "www.apple.com" || fixture.runtime.activations != 1 {
		t.Fatalf("committed write was not aligned: result=%+v active=%s activations=%d", result, fixture.store.state.HandshakeHost.Hostname, fixture.runtime.activations)
	}
}

func TestHandshakeHostLifecycleRejectsStaleReviewedPlan(t *testing.T) {
	t.Parallel()

	fixture := newHandshakeHostLifecycleFixture(t)
	plan, _ := fixture.manager.PlanPrepare(context.Background(), "www.apple.com")
	fixture.store.state.Generation++
	fixture.store.state.Host.SSHPort = 2222
	if _, err := fixture.manager.Prepare(plan); !errors.Is(err, ErrHandshakeHostPlanStale) {
		t.Fatalf("stale Prepare() error = %v", err)
	}
	if fixture.runtime.prepares != 0 || fixture.store.saves != 0 {
		t.Fatal("stale plan reached mutation")
	}
}

const (
	lifecycleNodeID   = "20000000-0000-4000-8000-000000000001"
	lifecycleClientID = "30000000-0000-4000-8000-000000000001"
)

type handshakeHostClock struct{ now time.Time }

type handshakeHostLifecycleFixture struct {
	store   *handshakeHostLifecycleStore
	prober  *handshakeHostLifecycleProber
	runtime *handshakeHostLifecycleRuntime
	clock   *handshakeHostClock
	manager *HandshakeHostManager
}

func newHandshakeHostLifecycleFixture(t *testing.T) handshakeHostLifecycleFixture {
	t.Helper()
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	state := handshakeHostGatewayState(t, now)
	trace := []string{}
	store := &handshakeHostLifecycleStore{state: state}
	prober := &handshakeHostLifecycleProber{results: map[string]HandshakeHostProbeResult{
		"microsoft":  passingHandshakeHostProbe("microsoft", "www.microsoft.com", now, 20*time.Millisecond),
		"apple":      passingHandshakeHostProbe("apple", "www.apple.com", now, 20*time.Millisecond),
		"cloudflare": passingHandshakeHostProbe("cloudflare", "www.cloudflare.com", now, 20*time.Millisecond),
	}}
	runtime := &handshakeHostLifecycleRuntime{trace: trace}
	store.runtime = runtime
	clock := &handshakeHostClock{now: now}
	ids := []string{
		"40000000-0000-4000-8000-000000000001",
		"40000000-0000-4000-8000-000000000002",
		"40000000-0000-4000-8000-000000000003",
	}
	index := 0
	newUUID := func() (string, error) {
		if index >= len(ids) {
			return "", errors.New("fixture UUIDs exhausted")
		}
		value := ids[index]
		index++
		return value, nil
	}
	manager, err := NewHandshakeHostManager(store, prober, runtime, func() time.Time { return clock.now }, newUUID)
	if err != nil {
		t.Fatal(err)
	}
	return handshakeHostLifecycleFixture{store: store, prober: prober, runtime: runtime, clock: clock, manager: manager}
}

type handshakeHostLifecycleStore struct {
	state             model.State
	saves             int
	fail              bool
	commitBeforeError bool
	runtime           *handshakeHostLifecycleRuntime
}

func (store *handshakeHostLifecycleStore) Load() (model.State, error) { return store.state, nil }

func (store *handshakeHostLifecycleStore) Save(expected uint64, candidate model.State) error {
	if store.fail {
		if store.commitBeforeError {
			store.state = candidate
		}
		return errors.New("synthetic state failure")
	}
	if expected != store.state.Generation {
		return errors.New("synthetic generation conflict")
	}
	if err := model.ValidateTransition(store.state, candidate); err != nil {
		return err
	}
	store.saves++
	store.state = candidate
	if store.runtime != nil {
		store.runtime.trace = append(store.runtime.trace, "state.save")
	}
	return nil
}

type handshakeHostLifecycleProber struct {
	results map[string]HandshakeHostProbeResult
	calls   []string
}

func (prober *handshakeHostLifecycleProber) Probe(_ context.Context, candidate HandshakeHostCandidate) HandshakeHostProbeResult {
	prober.calls = append(prober.calls, candidate.ID)
	return prober.results[candidate.ID]
}

type handshakeHostLifecycleRuntime struct {
	prepares    int
	activations int
	fail        bool
	prepared    []model.State
	trace       []string
}

func (runtime *handshakeHostLifecycleRuntime) Prepare(_ context.Context, state model.State) (HandshakeHostGatewayActivation, error) {
	runtime.prepares++
	runtime.trace = append(runtime.trace, "runtime.prepare")
	if runtime.fail {
		return nil, errors.New("synthetic runtime failure")
	}
	runtime.prepared = append(runtime.prepared, state)
	return handshakeHostLifecycleActivation{runtime: runtime}, nil
}

type handshakeHostLifecycleActivation struct {
	runtime *handshakeHostLifecycleRuntime
}

func (activation handshakeHostLifecycleActivation) Activate() {
	activation.runtime.activations++
	activation.runtime.trace = append(activation.runtime.trace, "runtime.activate")
}

func handshakeHostGatewayState(t *testing.T, created time.Time) model.State {
	t.Helper()
	state := model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 7,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: "10000000-0000-4000-8000-000000000001", Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: created,
			PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", SSHPort: 22, ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24",
		},
		HandshakeHost: &model.HandshakeHost{
			SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: created,
		},
		Nodes: []model.Node{{
			SchemaVersion: model.ResourceSchemaVersion, ID: lifecycleNodeID, Name: "private-1", Lifecycle: model.LifecycleActive,
			OverlayIPv4: "10.67.0.2", CredentialGeneration: 1, AssignedPresets: []string{}, ActiveTransport: model.TransportRestricted,
			IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: created,
		}},
		Clients: []model.Client{{
			SchemaVersion: model.ResourceSchemaVersion, ID: lifecycleClientID, Name: "iphone", Platform: "ios", Lifecycle: model.LifecycleActive,
			OverlayIPv4: "10.66.0.2", CredentialGeneration: 1, AssignedPresets: []string{}, ActiveTransport: model.TransportStandard, CreatedAt: created,
		}},
		Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports: []model.Transport{
			standardTransportFixture(model.TargetNode, lifecycleNodeID, model.TransportStandby, standardTestKey(0x71), 1),
			restrictedTransportFixture(model.TargetNode, lifecycleNodeID, model.TransportActive, 1, "www.microsoft.com"),
			standardTransportFixture(model.TargetClient, lifecycleClientID, model.TransportActive, standardTestKey(0x72), 1),
			restrictedTransportFixture(model.TargetClient, lifecycleClientID, model.TransportStandby, 1, "www.microsoft.com"),
		},
		Exposes: []model.Expose{}, Certificates: []model.Certificate{}, Operations: []model.Operation{},
		Logging: []model.LoggingSession{}, Backups: []model.Backup{}, Invites: []model.Invite{}, Components: standardComponentManifest(),
	}
	state.Components.Components = append(state.Components.Components, restrictedComponentPin())
	if err := state.Validate(); err != nil {
		t.Fatalf("handshake-host lifecycle gateway fixture: %v", err)
	}
	return state
}

var _ HandshakeHostStateStore = (*handshakeHostLifecycleStore)(nil)
var _ HandshakeHostProber = (*handshakeHostLifecycleProber)(nil)
var _ HandshakeHostGatewayRuntime = (*handshakeHostLifecycleRuntime)(nil)

func TestExplicitHandshakeHostCandidateUsesSignedIDOrStableManualID(t *testing.T) {
	t.Parallel()

	bundled, err := explicitHandshakeHostCandidate("www.apple.com")
	if err != nil || bundled.ID != "apple" {
		t.Fatalf("bundled candidate = %+v, %v", bundled, err)
	}
	manual, err := explicitHandshakeHostCandidate("front.example.com")
	if err != nil || !strings.HasPrefix(manual.ID, "manual-") || manual.Hostname != "front.example.com" {
		t.Fatalf("manual candidate = %+v, %v", manual, err)
	}
	again, _ := explicitHandshakeHostCandidate("front.example.com")
	if again != manual {
		t.Fatalf("manual candidate ID is unstable: %+v / %+v", manual, again)
	}
	if _, err := explicitHandshakeHostCandidate("Front.Example.com"); err == nil {
		t.Fatal("non-canonical manual hostname was accepted")
	}
}
