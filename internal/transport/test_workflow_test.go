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

func TestManagerTransportTestCleansSuccessfulStandbyWithoutChangingIntent(t *testing.T) {
	t.Parallel()

	identity := transportIdentity()
	standard := newFakeProvider(model.TransportStandard, RuntimeActive, HealthHealthy)
	restricted := newWorkflowProvider(model.TransportRestricted)
	manager := newTestManager(t, identity, model.TransportStandard, standard, restricted)
	target := restrictedTransport(identity, model.TransportStandby)
	targetBefore := target
	selectionBefore := manager.Selection()
	limits := TestLimits{Total: time.Second, Step: 500 * time.Millisecond, Cleanup: 250 * time.Millisecond}

	execution, err := manager.TestTransport(context.Background(), target, limits)
	if err != nil {
		t.Fatalf("TestTransport() error = %v", err)
	}
	if !execution.Ready() || !execution.Cleaned || execution.Target != DescriptorFromTransport(target) {
		t.Fatalf("TestTransport() execution = %+v", execution)
	}
	if execution.Selection != selectionBefore || execution.CredentialGeneration != identity.CredentialGeneration || manager.Selection() != selectionBefore || target != targetBefore {
		t.Fatalf("transport test mutated intent/generation: execution=%+v manager=%+v target=%+v", execution, manager.Selection(), target)
	}
	if !reflect.DeepEqual(restricted.calls, []string{"render", "prepare", "validate", "test", "rollback"}) {
		t.Fatalf("restricted calls = %v", restricted.calls)
	}
	if len(standard.calls) != 0 {
		t.Fatalf("active provider was touched while testing standby: %v", standard.calls)
	}
	for _, stage := range restricted.calls {
		if _, bounded := restricted.deadlines[stage]; !bounded {
			t.Fatalf("provider stage %s had no deadline", stage)
		}
	}
}

func TestManagerTransportTestReturnsFailedChecksAndStillCleans(t *testing.T) {
	t.Parallel()

	identity := transportIdentity()
	restricted := newWorkflowProvider(model.TransportRestricted)
	restricted.result.SelectedUDP = ProbeResult{State: ProbeFailed, Code: "restricted-uot-unavailable"}
	manager := newTestManager(t, identity, model.TransportStandard,
		newFakeProvider(model.TransportStandard, RuntimeActive, HealthHealthy), restricted)

	execution, err := manager.TestTransport(context.Background(), restrictedTransport(identity, model.TransportStandby), TestLimits{})
	if err != nil {
		t.Fatalf("TestTransport() error = %v", err)
	}
	if execution.Ready() || !execution.Cleaned || execution.Checks.SelectedUDP.State != ProbeFailed {
		t.Fatalf("failed diagnostic execution = %+v", execution)
	}
	if !reflect.DeepEqual(restricted.calls, []string{"render", "prepare", "validate", "test", "rollback"}) {
		t.Fatalf("restricted calls = %v", restricted.calls)
	}
}

func TestManagerTransportTestCleansEveryPartiallyPreparedFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		failStage string
		result    TestResult
		wantCalls []string
		wantError string
	}{
		{name: "render", failStage: "render", wantCalls: []string{"render"}, wantError: "render restricted"},
		{name: "prepare", failStage: "prepare", wantCalls: []string{"render", "prepare", "rollback"}, wantError: "prepare restricted"},
		{name: "validate", failStage: "validate", wantCalls: []string{"render", "prepare", "validate", "rollback"}, wantError: "validate restricted"},
		{name: "probe runner", failStage: "test", wantCalls: []string{"render", "prepare", "validate", "test", "rollback"}, wantError: "run restricted"},
		{name: "invalid probe result", result: TestResult{}, wantCalls: []string{"render", "prepare", "validate", "test", "rollback"}, wantError: "validate restricted"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			identity := transportIdentity()
			provider := newWorkflowProvider(model.TransportRestricted)
			provider.failStage = test.failStage
			if test.result != (TestResult{}) {
				provider.result = test.result
			} else if test.name == "invalid probe result" {
				provider.result = TestResult{}
			}
			manager := newTestManager(t, identity, model.TransportStandard,
				newFakeProvider(model.TransportStandard, RuntimeActive, HealthHealthy), provider)

			execution, err := manager.TestTransport(context.Background(), restrictedTransport(identity, model.TransportStandby), TestLimits{})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("TestTransport() error = %v, want %q", err, test.wantError)
			}
			if !reflect.DeepEqual(provider.calls, test.wantCalls) {
				t.Fatalf("provider calls = %v, want %v", provider.calls, test.wantCalls)
			}
			wantCleaned := test.failStage != "render"
			if execution.Cleaned != wantCleaned || manager.Selection().Active != model.TransportStandard {
				t.Fatalf("failed execution = %+v selection=%+v", execution, manager.Selection())
			}
		})
	}
}

func TestManagerTransportTestStepTimeoutStillUsesIndependentCleanupDeadline(t *testing.T) {
	t.Parallel()

	identity := transportIdentity()
	provider := newWorkflowProvider(model.TransportRestricted)
	provider.blockStage = "prepare"
	manager := newTestManager(t, identity, model.TransportStandard,
		newFakeProvider(model.TransportStandard, RuntimeActive, HealthHealthy), provider)
	started := time.Now()

	execution, err := manager.TestTransport(context.Background(), restrictedTransport(identity, model.TransportStandby), TestLimits{
		Total: 100 * time.Millisecond, Step: 20 * time.Millisecond, Cleanup: 50 * time.Millisecond,
	})
	if !errors.Is(err, context.DeadlineExceeded) || !execution.Cleaned {
		t.Fatalf("bounded TestTransport() = %+v, %v", execution, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("transport test exceeded bounded deadline: %s", elapsed)
	}
	if !reflect.DeepEqual(provider.calls, []string{"render", "prepare", "rollback"}) {
		t.Fatalf("provider calls = %v", provider.calls)
	}
	if _, bounded := provider.deadlines["rollback"]; !bounded {
		t.Fatal("cleanup did not receive an independent deadline")
	}
}

func TestManagerTransportTestReportsCleanupFailure(t *testing.T) {
	t.Parallel()

	identity := transportIdentity()
	provider := newWorkflowProvider(model.TransportRestricted)
	provider.failStage = "rollback"
	manager := newTestManager(t, identity, model.TransportStandard,
		newFakeProvider(model.TransportStandard, RuntimeActive, HealthHealthy), provider)

	execution, err := manager.TestTransport(context.Background(), restrictedTransport(identity, model.TransportStandby), TestLimits{})
	if err == nil || !strings.Contains(err.Error(), "remove restricted transport test candidate") || execution.Cleaned {
		t.Fatalf("cleanup failure execution = %+v, error = %v", execution, err)
	}
	if manager.Selection().Active != model.TransportStandard {
		t.Fatalf("cleanup failure changed selection: %+v", manager.Selection())
	}
}

func TestManagerTransportTestRejectsInvalidTargetBeforeProvider(t *testing.T) {
	t.Parallel()

	identity := transportIdentity()
	provider := newWorkflowProvider(model.TransportRestricted)
	manager := newTestManager(t, identity, model.TransportStandard,
		newFakeProvider(model.TransportStandard, RuntimeActive, HealthHealthy), provider)
	target := restrictedTransport(identity, model.TransportStandby)
	target.CredentialGeneration++

	if _, err := manager.TestTransport(context.Background(), target, TestLimits{}); err == nil || !strings.Contains(err.Error(), "manager identity") {
		t.Fatalf("invalid target error = %v", err)
	}
	if len(provider.calls) != 0 {
		t.Fatalf("invalid target reached provider: %v", provider.calls)
	}
}

func TestNodeTesterResolvesJoinedStateAndProvesCanonicalStateUnchanged(t *testing.T) {
	t.Parallel()

	state := nodeTransportTestState(t)
	reader := &workflowStateReader{states: []model.State{state, state}}
	standard := newWorkflowProvider(model.TransportStandard)
	restricted := newWorkflowProvider(model.TransportRestricted)
	registry, err := NewRegistry(standard, restricted)
	if err != nil {
		t.Fatal(err)
	}
	tester, err := NewNodeTester(reader, registry, TestLimits{})
	if err != nil {
		t.Fatal(err)
	}

	execution, err := tester.Test(context.Background(), model.TransportRestricted)
	if err != nil {
		t.Fatalf("Test() error = %v", err)
	}
	if !execution.Ready() || execution.StateGeneration != state.Generation || execution.Selection.Active != model.TransportStandard || execution.Target.Kind != model.TransportRestricted {
		t.Fatalf("node transport test execution = %+v", execution)
	}
	if reader.loads != 2 || len(standard.calls) != 0 || !reflect.DeepEqual(restricted.calls, []string{"render", "prepare", "validate", "test", "rollback"}) {
		t.Fatalf("state/provider calls = %d / %v / %v", reader.loads, standard.calls, restricted.calls)
	}
}

func TestNodeTesterDetectsConcurrentStateChangeAfterCleanup(t *testing.T) {
	t.Parallel()

	before := nodeTransportTestState(t)
	after := before
	after.Generation++
	reader := &workflowStateReader{states: []model.State{before, after}}
	standard := newWorkflowProvider(model.TransportStandard)
	restricted := newWorkflowProvider(model.TransportRestricted)
	registry, _ := NewRegistry(standard, restricted)
	tester, _ := NewNodeTester(reader, registry, TestLimits{})

	execution, err := tester.Test(context.Background(), model.TransportRestricted)
	if !errors.Is(err, ErrTransportTestStateChanged) || !execution.Cleaned {
		t.Fatalf("changed-state execution = %+v, error = %v", execution, err)
	}
	if !reflect.DeepEqual(restricted.calls, []string{"render", "prepare", "validate", "test", "rollback"}) {
		t.Fatalf("provider calls = %v", restricted.calls)
	}
}

func TestNodeTesterNegativeDiagnosticAlsoPreservesCanonicalState(t *testing.T) {
	t.Parallel()

	state := nodeTransportTestState(t)
	reader := &workflowStateReader{states: []model.State{state, state}}
	standard := newWorkflowProvider(model.TransportStandard)
	restricted := newWorkflowProvider(model.TransportRestricted)
	restricted.result.Control = ProbeResult{State: ProbeFailed, Code: "control-unavailable"}
	registry, _ := NewRegistry(standard, restricted)
	tester, _ := NewNodeTester(reader, registry, TestLimits{})

	execution, err := tester.Test(context.Background(), model.TransportRestricted)
	if err != nil || execution.Ready() || !execution.Cleaned || execution.StateGeneration != state.Generation {
		t.Fatalf("negative diagnostic execution = %+v, error = %v", execution, err)
	}
	if reader.loads != 2 || execution.Selection.Active != model.TransportStandard || execution.CredentialGeneration != state.Nodes[0].CredentialGeneration {
		t.Fatalf("negative diagnostic changed state evidence: loads=%d execution=%+v", reader.loads, execution)
	}
}

func TestNodeTesterRejectsUnjoinedNodeWithoutTouchingProviders(t *testing.T) {
	t.Parallel()

	state := nodeTransportTestState(t)
	state.Nodes = []model.Node{}
	state.Transports = []model.Transport{}
	state.HandshakeHost = nil
	reader := &workflowStateReader{states: []model.State{state}}
	standard := newWorkflowProvider(model.TransportStandard)
	restricted := newWorkflowProvider(model.TransportRestricted)
	registry, _ := NewRegistry(standard, restricted)
	tester, _ := NewNodeTester(reader, registry, TestLimits{})

	if _, err := tester.Test(context.Background(), model.TransportRestricted); err == nil || !strings.Contains(err.Error(), "joined active local node") {
		t.Fatalf("unjoined Test() error = %v", err)
	}
	if len(standard.calls) != 0 || len(restricted.calls) != 0 {
		t.Fatalf("unjoined test touched providers: %v / %v", standard.calls, restricted.calls)
	}
}

func TestTransportTestLimitsMatchDevelopmentManifest(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "v2", "COMPONENT_LIMITS.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Limits struct {
			TransportTest struct {
				TotalSeconds             int  `json:"total_timeout_seconds"`
				StepSeconds              int  `json:"step_timeout_seconds"`
				CleanupSeconds           int  `json:"cleanup_timeout_seconds"`
				AutomaticFallback        bool `json:"automatic_fallback"`
				WritesAuthoritativeState bool `json:"writes_authoritative_state"`
			} `json:"transport_test"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	limits := manifest.Limits.TransportTest
	if time.Duration(limits.TotalSeconds)*time.Second != DefaultTransportTestTimeout ||
		time.Duration(limits.StepSeconds)*time.Second != DefaultTransportTestStepTimeout ||
		time.Duration(limits.CleanupSeconds)*time.Second != DefaultTransportTestCleanupTimeout ||
		limits.AutomaticFallback || limits.WritesAuthoritativeState {
		t.Fatalf("transport test manifest limits drifted: %+v", limits)
	}
}

func nodeTransportTestState(t *testing.T) model.State {
	t.Helper()
	created := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	nodeID := "20000000-0000-4000-8000-000000000001"
	state := model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 9,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: "90000000-0000-4000-8000-000000000001",
			Role: model.RoleNode, OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: created,
		},
		HandshakeHost: &model.HandshakeHost{
			SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft",
			Hostname: "www.microsoft.com", SelectedAt: created,
		},
		Nodes: []model.Node{{
			SchemaVersion: model.ResourceSchemaVersion, ID: nodeID, Name: "private-node", Lifecycle: model.LifecycleActive,
			OverlayIPv4: "10.67.0.2", CredentialGeneration: 3, AssignedPresets: []string{},
			ActiveTransport: model.TransportStandard, IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: created,
			Gateway: &model.GatewayTrust{
				PublicIPv4: "203.0.113.10", EnrollmentFingerprint: "sha256:" + strings.Repeat("a", 64),
				ControlCAFingerprints: []string{"sha256:" + strings.Repeat("b", 64)}, LastKnownGatewayGeneration: 12,
			},
		}},
		Clients: []model.Client{}, Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports: []model.Transport{
			standardTransportFixture(model.TargetNode, nodeID, model.TransportActive, standardTestKey(0x51), 3),
			restrictedTransportFixture(model.TargetNode, nodeID, model.TransportStandby, 3, "www.microsoft.com"),
		},
		Exposes: []model.Expose{}, Certificates: []model.Certificate{}, Operations: []model.Operation{},
		Logging: []model.LoggingSession{}, Backups: []model.Backup{}, Invites: []model.Invite{}, Components: standardComponentManifest(),
	}
	state.Components.Components = append(state.Components.Components, restrictedComponentPin())
	if err := state.Validate(); err != nil {
		t.Fatalf("node transport test state: %v", err)
	}
	return state
}

type workflowStateReader struct {
	states []model.State
	loads  int
}

func (reader *workflowStateReader) Load() (model.State, error) {
	index := reader.loads
	reader.loads++
	if len(reader.states) == 0 {
		return model.State{}, errors.New("synthetic state failure")
	}
	if index >= len(reader.states) {
		index = len(reader.states) - 1
	}
	return reader.states[index], nil
}

type workflowCandidate struct{ descriptor CandidateDescriptor }

func (candidate workflowCandidate) Descriptor() CandidateDescriptor { return candidate.descriptor }

type workflowProvider struct {
	kind       model.TransportKind
	result     TestResult
	failStage  string
	blockStage string
	calls      []string
	deadlines  map[string]time.Time
}

func newWorkflowProvider(kind model.TransportKind) *workflowProvider {
	passed := ProbeResult{State: ProbePassed, Code: "passed"}
	return &workflowProvider{
		kind: kind, deadlines: make(map[string]time.Time),
		result: TestResult{Control: passed, ReverseTunnel: passed, SelectedTCP: passed, SelectedUDP: passed},
	}
}

func (provider *workflowProvider) Kind() model.TransportKind { return provider.kind }

func (provider *workflowProvider) Render(ctx context.Context, request RenderRequest) (Candidate, error) {
	if err := provider.enter(ctx, "render"); err != nil {
		return nil, err
	}
	return workflowCandidate{descriptor: DescriptorFromTransport(request.Transport)}, nil
}

func (provider *workflowProvider) Prepare(ctx context.Context, _ Candidate) error {
	return provider.enter(ctx, "prepare")
}

func (provider *workflowProvider) Validate(ctx context.Context, _ Candidate) error {
	return provider.enter(ctx, "validate")
}

func (provider *workflowProvider) StartTest(ctx context.Context, _ Candidate) (TestResult, error) {
	if err := provider.enter(ctx, "test"); err != nil {
		return TestResult{}, err
	}
	return provider.result, nil
}

func (provider *workflowProvider) Activate(ctx context.Context, _ Candidate) error {
	return provider.enter(ctx, "activate")
}

func (provider *workflowProvider) Health(ctx context.Context, request HealthRequest) (Health, error) {
	if err := provider.enter(ctx, "health"); err != nil {
		return Health{}, err
	}
	return Health{Identity: request.Identity, Kind: provider.kind, Role: RuntimeStandby, Condition: HealthHealthy, Code: "healthy"}, nil
}

func (provider *workflowProvider) Drain(ctx context.Context, _ DrainRequest) error {
	return provider.enter(ctx, "drain")
}

func (provider *workflowProvider) Rollback(ctx context.Context, _ Candidate) error {
	return provider.enter(ctx, "rollback")
}

func (provider *workflowProvider) enter(ctx context.Context, stage string) error {
	provider.calls = append(provider.calls, stage)
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

var _ Provider = (*workflowProvider)(nil)
