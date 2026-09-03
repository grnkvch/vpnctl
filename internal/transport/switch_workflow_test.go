package transport

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestNodeTransportSwitchMovesOneProductionBundleThenDrainsAndCommits(t *testing.T) {
	t.Parallel()

	state := nodeTransportTestState(t)
	trace := []string{}
	store := &switchStateStore{state: state, trace: &trace}
	standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
	restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
	registry, _ := NewRegistry(standard, restricted)
	switcher, err := NewNodeSwitcher(store, registry, SwitchLimits{Total: time.Second, Step: 500 * time.Millisecond, Drain: 250 * time.Millisecond, Rollback: 250 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	plan, err := switcher.Plan(model.TransportRestricted)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if !plan.Changed || plan.Current != model.TransportStandard || plan.Target != model.TransportRestricted || plan.ExpectedStateGeneration != 9 || plan.NextStateGeneration != 10 {
		t.Fatalf("switch plan = %+v", plan)
	}
	result, err := switcher.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !result.Changed || result.Previous != model.TransportStandard || result.Active != model.TransportRestricted || result.StateGeneration != 10 || result.ActiveHealth.Condition != HealthHealthy {
		t.Fatalf("switch result = %+v", result)
	}
	wantTrace := []string{
		"standard.render", "restricted.render", "restricted.prepare", "restricted.validate", "restricted.test",
		"restricted.activate", "restricted.health", "standard.drain", "restricted.health", "standard.health", "state.save",
	}
	if !reflect.DeepEqual(trace, wantTrace) {
		t.Fatalf("switch trace = %v, want %v", trace, wantTrace)
	}
	if restricted.bundleActivations != 1 {
		t.Fatalf("target production bundle activations = %d, want one atomic activation", restricted.bundleActivations)
	}
	if standard.lastDrain.Deadline.IsZero() || time.Until(standard.lastDrain.Deadline) > 300*time.Millisecond {
		t.Fatalf("old-path drain is not bounded: %+v", standard.lastDrain)
	}
	assertSwitchState(t, store.state, model.TransportRestricted, 10)
}

func TestNodeTransportSwitchTargetFailurePreservesOldProductionPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		failStage string
		failedUDP bool
		want      string
	}{
		{name: "native validation", failStage: "validate", want: "validate target"},
		{name: "authenticated gateway probes", failedUDP: true, want: ErrTransportSwitchTargetNotReady.Error()},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := nodeTransportTestState(t)
			trace := []string{}
			store := &switchStateStore{state: state, trace: &trace}
			standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
			restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
			restricted.failStage = test.failStage
			if test.failedUDP {
				restricted.result.SelectedUDP = ProbeResult{State: ProbeFailed, Code: "uot-unavailable"}
			}
			registry, _ := NewRegistry(standard, restricted)
			switcher, _ := NewNodeSwitcher(store, registry, SwitchLimits{})
			plan, _ := switcher.Plan(model.TransportRestricted)

			_, err := switcher.Apply(context.Background(), plan)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Apply() error = %v, want %q", err, test.want)
			}
			if standard.role != RuntimeActive || standard.bundleActivations != 0 || standard.drainCalls != 0 {
				t.Fatalf("old production path changed: role=%s activates=%d drains=%d", standard.role, standard.bundleActivations, standard.drainCalls)
			}
			if restricted.role != RuntimeStandby || restricted.rollbackCalls != 1 || store.saves != 0 {
				t.Fatalf("failed target was not isolated: role=%s rollbacks=%d saves=%d", restricted.role, restricted.rollbackCalls, store.saves)
			}
			assertSwitchState(t, store.state, model.TransportStandard, 9)
		})
	}
}

func TestNodeTransportSwitchPostActivationFailureRestoresOldBeforeTargetCleanup(t *testing.T) {
	t.Parallel()

	state := nodeTransportTestState(t)
	trace := []string{}
	store := &switchStateStore{state: state, trace: &trace}
	standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
	restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
	restricted.failStage = "health"
	registry, _ := NewRegistry(standard, restricted)
	switcher, _ := NewNodeSwitcher(store, registry, SwitchLimits{})
	plan, _ := switcher.Plan(model.TransportRestricted)

	_, err := switcher.Apply(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "health-check active target") {
		t.Fatalf("Apply() error = %v", err)
	}
	wantSuffix := []string{"restricted.activate", "restricted.health", "standard.activate", "restricted.rollback"}
	if len(trace) < len(wantSuffix) || !reflect.DeepEqual(trace[len(trace)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("compensation trace = %v, want suffix %v", trace, wantSuffix)
	}
	if standard.role != RuntimeActive || restricted.role != RuntimeStandby || store.saves != 0 {
		t.Fatalf("post-activation compensation failed: old=%s target=%s saves=%d", standard.role, restricted.role, store.saves)
	}
	assertSwitchState(t, store.state, model.TransportStandard, 9)
}

func TestNodeTransportSwitchAlreadyActiveIsHealthOnlyAndIdempotent(t *testing.T) {
	t.Parallel()

	state := nodeTransportTestState(t)
	trace := []string{}
	store := &switchStateStore{state: state, trace: &trace}
	standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
	standard.condition = HealthDegraded
	restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
	registry, _ := NewRegistry(standard, restricted)
	switcher, _ := NewNodeSwitcher(store, registry, SwitchLimits{})

	plan, err := switcher.Plan(model.TransportStandard)
	if err != nil || plan.Changed || plan.NextStateGeneration != state.Generation {
		t.Fatalf("idempotent Plan() = %+v, %v", plan, err)
	}
	result, err := switcher.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("idempotent Apply() error = %v", err)
	}
	if result.Changed || result.ActiveHealth.Condition != HealthDegraded || result.StateGeneration != state.Generation {
		t.Fatalf("idempotent result = %+v", result)
	}
	if !reflect.DeepEqual(trace, []string{"standard.health"}) || store.saves != 0 || len(restricted.calls) != 0 {
		t.Fatalf("idempotent side effects: trace=%v saves=%d standby=%v", trace, store.saves, restricted.calls)
	}
}

func TestNodeTransportSwitchRejectsStaleReviewedPlanBeforeProviders(t *testing.T) {
	t.Parallel()

	state := nodeTransportTestState(t)
	trace := []string{}
	store := &switchStateStore{state: state, trace: &trace}
	standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
	restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
	registry, _ := NewRegistry(standard, restricted)
	switcher, _ := NewNodeSwitcher(store, registry, SwitchLimits{})
	plan, _ := switcher.Plan(model.TransportRestricted)
	store.state.Generation++
	store.state.Nodes[0].Gateway.LastKnownGatewayGeneration++
	if err := store.state.Validate(); err != nil {
		t.Fatal(err)
	}

	if _, err := switcher.Apply(context.Background(), plan); !errors.Is(err, ErrTransportSwitchStale) {
		t.Fatalf("stale Apply() error = %v", err)
	}
	if len(trace) != 0 || store.saves != 0 {
		t.Fatalf("stale plan reached mutation: trace=%v saves=%d", trace, store.saves)
	}
}

func TestNodeTransportSwitchTimeoutUsesIndependentRollback(t *testing.T) {
	t.Parallel()

	state := nodeTransportTestState(t)
	trace := []string{}
	store := &switchStateStore{state: state, trace: &trace}
	standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
	restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
	restricted.blockStage = "prepare"
	registry, _ := NewRegistry(standard, restricted)
	switcher, _ := NewNodeSwitcher(store, registry, SwitchLimits{
		Total: 100 * time.Millisecond, Step: 20 * time.Millisecond, Drain: 20 * time.Millisecond, Rollback: 50 * time.Millisecond,
	})
	plan, _ := switcher.Plan(model.TransportRestricted)

	started := time.Now()
	_, err := switcher.Apply(context.Background(), plan)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("bounded Apply() error = %v elapsed=%s", err, time.Since(started))
	}
	if restricted.rollbackCalls != 1 || restricted.deadlines["rollback"].IsZero() || standard.role != RuntimeActive {
		t.Fatalf("independent rollback missing: calls=%d deadline=%s old=%s", restricted.rollbackCalls, restricted.deadlines["rollback"], standard.role)
	}
}

func TestNodeTransportSwitchDrainTimeoutRestoresOldPath(t *testing.T) {
	t.Parallel()

	state := nodeTransportTestState(t)
	trace := []string{}
	store := &switchStateStore{state: state, trace: &trace}
	standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
	standard.blockStage = "drain"
	restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
	registry, _ := NewRegistry(standard, restricted)
	switcher, _ := NewNodeSwitcher(store, registry, SwitchLimits{
		Total: 200 * time.Millisecond, Step: 50 * time.Millisecond, Drain: 20 * time.Millisecond, Rollback: 50 * time.Millisecond,
	})
	plan, _ := switcher.Plan(model.TransportRestricted)

	_, err := switcher.Apply(context.Background(), plan)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded drain error = %v", err)
	}
	wantSuffix := []string{"standard.drain", "standard.activate", "restricted.rollback"}
	if len(trace) < len(wantSuffix) || !reflect.DeepEqual(trace[len(trace)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("drain compensation trace = %v", trace)
	}
	if standard.role != RuntimeActive || restricted.role != RuntimeStandby || store.saves != 0 {
		t.Fatalf("drain timeout changed selection: roles=%s/%s saves=%d", standard.role, restricted.role, store.saves)
	}
}

func TestNodeTransportSwitchReportsStagedCleanupFailure(t *testing.T) {
	t.Parallel()

	state := nodeTransportTestState(t)
	trace := []string{}
	store := &switchStateStore{state: state, trace: &trace}
	standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
	restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
	restricted.result.SelectedUDP = ProbeResult{State: ProbeFailed, Code: "uot-unavailable"}
	restricted.failStage = "rollback"
	registry, _ := NewRegistry(standard, restricted)
	switcher, _ := NewNodeSwitcher(store, registry, SwitchLimits{})
	plan, _ := switcher.Plan(model.TransportRestricted)

	_, err := switcher.Apply(context.Background(), plan)
	if !errors.Is(err, ErrTransportSwitchTargetNotReady) || !strings.Contains(err.Error(), "remove staged target transport candidate") {
		t.Fatalf("cleanup error = %v", err)
	}
	if standard.role != RuntimeActive || standard.bundleActivations != 0 || store.saves != 0 {
		t.Fatalf("cleanup failure changed old path: role=%s activates=%d saves=%d", standard.role, standard.bundleActivations, store.saves)
	}
}

func TestNodeTransportSwitchDoesNotRemoveTargetWhenOldRestoreFails(t *testing.T) {
	t.Parallel()

	state := nodeTransportTestState(t)
	trace := []string{}
	store := &switchStateStore{state: state, trace: &trace}
	standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
	standard.failStage = "activate"
	restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
	restricted.failStage = "health"
	registry, _ := NewRegistry(standard, restricted)
	switcher, _ := NewNodeSwitcher(store, registry, SwitchLimits{})
	plan, _ := switcher.Plan(model.TransportRestricted)

	_, err := switcher.Apply(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "restore previous transport before target cleanup") {
		t.Fatalf("failed restoration error = %v", err)
	}
	if restricted.rollbackCalls != 0 || restricted.role != RuntimeActive || store.saves != 0 {
		t.Fatalf("unsafe cleanup after failed old restore: rollback=%d role=%s saves=%d", restricted.rollbackCalls, restricted.role, store.saves)
	}
}

func TestNodeTransportSwitchStateSaveFailureIsReconciled(t *testing.T) {
	t.Parallel()

	t.Run("old state proven and runtime compensated", func(t *testing.T) {
		t.Parallel()
		state := nodeTransportTestState(t)
		trace := []string{}
		store := &switchStateStore{state: state, trace: &trace, saveErr: errors.New("synthetic save failure")}
		standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
		restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
		registry, _ := NewRegistry(standard, restricted)
		switcher, _ := NewNodeSwitcher(store, registry, SwitchLimits{})
		plan, _ := switcher.Plan(model.TransportRestricted)

		_, err := switcher.Apply(context.Background(), plan)
		if err == nil || errors.Is(err, ErrTransportSwitchCommitUncertain) {
			t.Fatalf("proven-old save error = %v", err)
		}
		if standard.role != RuntimeActive || restricted.role != RuntimeStandby || restricted.rollbackCalls != 1 {
			t.Fatalf("save compensation roles=%s/%s rollback=%d", standard.role, restricted.role, restricted.rollbackCalls)
		}
		assertSwitchState(t, store.state, model.TransportStandard, 9)
	})

	t.Run("candidate state proven and no blind rollback", func(t *testing.T) {
		t.Parallel()
		state := nodeTransportTestState(t)
		trace := []string{}
		store := &switchStateStore{state: state, trace: &trace, saveErr: errors.New("post-commit fsync failure"), commitBeforeError: true}
		standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
		restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
		registry, _ := NewRegistry(standard, restricted)
		switcher, _ := NewNodeSwitcher(store, registry, SwitchLimits{})
		plan, _ := switcher.Plan(model.TransportRestricted)

		_, err := switcher.Apply(context.Background(), plan)
		if !errors.Is(err, ErrTransportSwitchCommitUncertain) {
			t.Fatalf("committed save error = %v", err)
		}
		if standard.bundleActivations != 0 || restricted.rollbackCalls != 0 || restricted.role != RuntimeActive {
			t.Fatalf("uncertain committed write triggered blind rollback: old activates=%d target rollback=%d role=%s", standard.bundleActivations, restricted.rollbackCalls, restricted.role)
		}
		assertSwitchState(t, store.state, model.TransportRestricted, 10)
	})
}

func TestTransportSwitchLimitsMatchDevelopmentManifest(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "v2", "COMPONENT_LIMITS.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Limits struct {
			TransportSwitch struct {
				TotalSeconds      int  `json:"total_timeout_seconds"`
				StepSeconds       int  `json:"step_timeout_seconds"`
				DrainSeconds      int  `json:"drain_timeout_seconds"`
				RollbackSeconds   int  `json:"rollback_timeout_seconds"`
				RequiresConfirm   bool `json:"requires_confirmation"`
				AutomaticFallback bool `json:"automatic_fallback"`
			} `json:"transport_switch"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	limits := manifest.Limits.TransportSwitch
	if time.Duration(limits.TotalSeconds)*time.Second != DefaultTransportSwitchTimeout ||
		time.Duration(limits.StepSeconds)*time.Second != DefaultTransportSwitchStepTimeout ||
		time.Duration(limits.DrainSeconds)*time.Second != DefaultTransportSwitchDrainTimeout ||
		time.Duration(limits.RollbackSeconds)*time.Second != DefaultTransportSwitchRollbackTimeout ||
		!limits.RequiresConfirm || limits.AutomaticFallback {
		t.Fatalf("transport switch manifest limits drifted: %+v", limits)
	}
}

func assertSwitchState(t *testing.T, state model.State, active model.TransportKind, generation uint64) {
	t.Helper()
	if err := state.Validate(); err != nil {
		t.Fatalf("switch state validation = %v", err)
	}
	if state.Generation != generation || state.Nodes[0].ActiveTransport != active {
		t.Fatalf("switch state generation/active = %d/%s, want %d/%s", state.Generation, state.Nodes[0].ActiveTransport, generation, active)
	}
	for _, transport := range state.Transports {
		if transport.OwnerKind != model.TargetNode || transport.OwnerID != state.Nodes[0].ID {
			continue
		}
		want := model.TransportStandby
		if transport.Kind == active {
			want = model.TransportActive
		}
		if transport.State != want {
			t.Fatalf("%s transport state = %s, want %s", transport.Kind, transport.State, want)
		}
	}
}

type switchStateStore struct {
	state             model.State
	trace             *[]string
	saves             int
	saveErr           error
	commitBeforeError bool
}

func (store *switchStateStore) Load() (model.State, error) { return store.state, nil }

func (store *switchStateStore) Save(expected uint64, candidate model.State) error {
	store.saves++
	if store.trace != nil {
		*store.trace = append(*store.trace, "state.save")
	}
	if expected != store.state.Generation {
		return errors.New("synthetic generation conflict")
	}
	if store.saveErr == nil || store.commitBeforeError {
		store.state = candidate
	}
	return store.saveErr
}

type switchProvider struct {
	kind              model.TransportKind
	role              RuntimeRole
	condition         HealthCondition
	result            TestResult
	failStage         string
	blockStage        string
	trace             *[]string
	calls             []string
	deadlines         map[string]time.Time
	bundleActivations int
	drainCalls        int
	rollbackCalls     int
	lastDrain         DrainRequest
}

func newSwitchProvider(kind model.TransportKind, role RuntimeRole, trace *[]string) *switchProvider {
	passed := ProbeResult{State: ProbePassed, Code: "passed"}
	return &switchProvider{
		kind: kind, role: role, condition: HealthHealthy, trace: trace, deadlines: make(map[string]time.Time),
		result: TestResult{Control: passed, ReverseTunnel: passed, SelectedTCP: passed, SelectedUDP: passed},
	}
}

func (provider *switchProvider) Kind() model.TransportKind { return provider.kind }

func (provider *switchProvider) Render(ctx context.Context, request RenderRequest) (Candidate, error) {
	if err := provider.enter(ctx, "render"); err != nil {
		return nil, err
	}
	return workflowCandidate{descriptor: DescriptorFromTransport(request.Transport)}, nil
}

func (provider *switchProvider) Prepare(ctx context.Context, _ Candidate) error {
	return provider.enter(ctx, "prepare")
}

func (provider *switchProvider) Validate(ctx context.Context, _ Candidate) error {
	return provider.enter(ctx, "validate")
}

func (provider *switchProvider) StartTest(ctx context.Context, _ Candidate) (TestResult, error) {
	if err := provider.enter(ctx, "test"); err != nil {
		return TestResult{}, err
	}
	return provider.result, nil
}

func (provider *switchProvider) Activate(ctx context.Context, _ Candidate) error {
	provider.bundleActivations++
	provider.role = RuntimeActive
	return provider.enter(ctx, "activate")
}

func (provider *switchProvider) Health(ctx context.Context, request HealthRequest) (Health, error) {
	if err := provider.enter(ctx, "health"); err != nil {
		return Health{}, err
	}
	return Health{Identity: request.Identity, Kind: provider.kind, Role: provider.role, Condition: provider.condition, Code: "observed"}, nil
}

func (provider *switchProvider) Drain(ctx context.Context, request DrainRequest) error {
	provider.drainCalls++
	provider.lastDrain = request
	if err := provider.enter(ctx, "drain"); err != nil {
		return err
	}
	provider.role = RuntimeStandby
	return nil
}

func (provider *switchProvider) Rollback(ctx context.Context, _ Candidate) error {
	provider.rollbackCalls++
	provider.role = RuntimeStandby
	return provider.enter(ctx, "rollback")
}

func (provider *switchProvider) enter(ctx context.Context, stage string) error {
	provider.calls = append(provider.calls, stage)
	if provider.trace != nil {
		*provider.trace = append(*provider.trace, string(provider.kind)+"."+stage)
	}
	if deadline, bounded := ctx.Deadline(); bounded {
		provider.deadlines[stage] = deadline
	}
	if provider.blockStage == stage {
		<-ctx.Done()
		return ctx.Err()
	}
	if provider.failStage == stage {
		return errors.New("synthetic " + stage + " failure")
	}
	return nil
}

var _ Provider = (*switchProvider)(nil)
