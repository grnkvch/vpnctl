package enrollment

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestNodeTransportProvidersSwitchOneCompleteRuntimeSelection(t *testing.T) {
	state, standardConfiguration, restrictedConfiguration := compiledNodeTransportPairFixture(t)
	replacer := &nodeTransportProviderReplacer{}
	readiness := &nodeTransportProviderReadiness{}
	tester := &nodeTransportProviderTester{result: passedNodeTransportTestResult()}
	registry := nodeTransportProviderRegistry(t, state, standardConfiguration, restrictedConfiguration, replacer, readiness, tester)
	stateStore := &nodeTransportProviderStateStore{state: state}
	switcher, err := transport.NewNodeSwitcher(stateStore, registry, transport.SwitchLimits{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := switcher.Plan(model.TransportRestricted)
	if err != nil {
		t.Fatal(err)
	}
	result, err := switcher.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !result.Changed || result.Previous != model.TransportStandard || result.Active != model.TransportRestricted ||
		stateStore.state.Nodes[0].ActiveTransport != model.TransportRestricted {
		t.Fatalf("switch result=%+v state=%+v", result, stateStore.state.Nodes[0])
	}
	if replacer.prepareCalls != 1 || replacer.activateCalls != 1 || replacer.replaceCalls != 0 ||
		replacer.preparedKind != model.TransportRestricted || tester.calls != 1 || tester.kind != model.TransportRestricted {
		t.Fatalf("replacer=%+v tester=%+v", replacer, tester)
	}
	if readiness.activeCalls < 2 || readiness.lastKind != model.TransportRestricted {
		t.Fatalf("readiness=%+v", readiness)
	}
	manager, err := transport.NewManager(
		transport.IdentityFromTransport(state.Transports[0]),
		transport.Selection{Active: model.TransportRestricted, Standby: model.TransportStandard},
		registry,
	)
	if err != nil {
		t.Fatal(err)
	}
	health, err := manager.CheckSteadyState(context.Background())
	if err != nil || health[0].Role != transport.RuntimeActive || health[1].Role != transport.RuntimeStandby {
		t.Fatalf("steady health=%+v error=%v", health, err)
	}
	back, err := switcher.Plan(model.TransportStandard)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := switcher.Apply(context.Background(), back)
	if err != nil || restored.Active != model.TransportStandard ||
		stateStore.state.Nodes[0].ActiveTransport != model.TransportStandard {
		t.Fatalf("reverse switch=%+v state=%+v error=%v", restored, stateStore.state.Nodes[0], err)
	}
}

func TestNodeTransportProvidersRestorePreviousGenerationAfterTargetHealthFailure(t *testing.T) {
	state, standardConfiguration, restrictedConfiguration := compiledNodeTransportPairFixture(t)
	replacer := &nodeTransportProviderReplacer{}
	readiness := &nodeTransportProviderReadiness{failKind: model.TransportRestricted}
	tester := &nodeTransportProviderTester{result: passedNodeTransportTestResult()}
	registry := nodeTransportProviderRegistry(t, state, standardConfiguration, restrictedConfiguration, replacer, readiness, tester)
	stateStore := &nodeTransportProviderStateStore{state: state}
	switcher, _ := transport.NewNodeSwitcher(stateStore, registry, transport.SwitchLimits{})
	plan, _ := switcher.Plan(model.TransportRestricted)
	_, err := switcher.Apply(context.Background(), plan)
	if !errors.Is(err, transport.ErrTransportSwitchTargetNotReady) {
		t.Fatalf("Apply() error = %v", err)
	}
	if stateStore.saves != 0 || stateStore.state.Nodes[0].ActiveTransport != model.TransportStandard {
		t.Fatalf("failed switch changed state: %+v", stateStore.state)
	}
	if replacer.prepareCalls != 1 || replacer.activateCalls != 1 || replacer.replaceCalls != 1 ||
		replacer.replacedKind != model.TransportStandard {
		t.Fatalf("compensation replacer=%+v", replacer)
	}
	standard, _ := registry.Provider(model.TransportStandard)
	health, healthErr := standard.Health(context.Background(), transport.HealthRequest{
		Identity: transport.IdentityFromTransport(state.Transports[0]),
	})
	if healthErr != nil || health.Role != transport.RuntimeActive || health.Condition != transport.HealthHealthy {
		t.Fatalf("restored health=%+v error=%v", health, healthErr)
	}
}

func TestNodeTransportProvidersNeverActivateCandidateWithFailedIsolatedTest(t *testing.T) {
	state, standardConfiguration, restrictedConfiguration := compiledNodeTransportPairFixture(t)
	replacer := &nodeTransportProviderReplacer{}
	failed := passedNodeTransportTestResult()
	failed.SelectedUDP = transport.ProbeResult{State: transport.ProbeFailed, Code: "restricted-uot-unavailable"}
	registry := nodeTransportProviderRegistry(
		t, state, standardConfiguration, restrictedConfiguration, replacer,
		&nodeTransportProviderReadiness{}, &nodeTransportProviderTester{result: failed},
	)
	stateStore := &nodeTransportProviderStateStore{state: state}
	switcher, _ := transport.NewNodeSwitcher(stateStore, registry, transport.SwitchLimits{})
	plan, _ := switcher.Plan(model.TransportRestricted)
	_, err := switcher.Apply(context.Background(), plan)
	if !errors.Is(err, transport.ErrTransportSwitchTargetNotReady) {
		t.Fatalf("Apply() failed test error = %v", err)
	}
	if replacer.activateCalls != 0 || replacer.replaceCalls != 0 || stateStore.saves != 0 {
		t.Fatalf("failed test crossed activation boundary: replacer=%+v saves=%d", replacer, stateStore.saves)
	}
}

func compiledNodeTransportPairFixture(t *testing.T) (model.State, NodeConfiguration, NodeConfiguration) {
	t.Helper()
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	t.Cleanup(fixture.destroy)
	if _, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportStandard, []string{"telegram"}); err != nil {
		t.Fatal(err)
	}
	state, err := fixture.nodeState.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.DNS = &model.DNSUpstreamState{
		SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamDirect, IPv4: []string{"192.0.2.53"},
	}
	state.Components.Components = append(state.Components.Components, nodeConfigurationFRPPin())
	compiler, err := NewNodeConfigurationCompiler(t.TempDir(), fixture.nodeSecrets, NodeConfigurationRuntime{
		WireGuardRunner: &joinWireGuardRunner{}, Now: func() time.Time { return fixture.now.Add(time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := linuxplatform.HostSnapshot{Routes: []linuxplatform.Route{{
		Family: "ipv4", Destination: "default", Gateway: "192.0.2.1", Device: "ens3", Table: "main",
	}}}
	standard, err := compiler.Compile(context.Background(), state, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	restrictedState := state
	restrictedState.Generation++
	restrictedState.Nodes = append([]model.Node(nil), state.Nodes...)
	restrictedState.Transports = append([]model.Transport(nil), state.Transports...)
	restrictedState.Nodes[0].ActiveTransport = model.TransportRestricted
	for index := range restrictedState.Transports {
		switch restrictedState.Transports[index].Kind {
		case model.TransportStandard:
			restrictedState.Transports[index].State = model.TransportStandby
		case model.TransportRestricted:
			restrictedState.Transports[index].State = model.TransportActive
		}
	}
	if err := model.ValidateTransition(state, restrictedState); err != nil {
		t.Fatal(err)
	}
	restricted, err := compiler.Compile(context.Background(), restrictedState, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return state, standard, restricted
}

func nodeTransportProviderRegistry(
	t *testing.T,
	state model.State,
	standard NodeConfiguration,
	restricted NodeConfiguration,
	replacer NodeTransportGenerationReplacer,
	readiness NodeTransportGenerationReadiness,
	tester NodeTransportCandidateTester,
) *transport.Registry {
	t.Helper()
	var standardTransport, restrictedTransport model.Transport
	for _, candidate := range state.Transports {
		switch candidate.Kind {
		case model.TransportStandard:
			standardTransport = candidate
		case model.TransportRestricted:
			restrictedTransport = candidate
		}
	}
	registry, err := NewNodeTransportRegistry(
		state.Nodes[0].ActiveTransport,
		standardTransport, standard,
		restrictedTransport, restricted,
		replacer, readiness, tester,
	)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

type nodeTransportProviderReplacer struct {
	prepareCalls  int
	activateCalls int
	replaceCalls  int
	preparedKind  model.TransportKind
	replacedKind  model.TransportKind
}

func (replacer *nodeTransportProviderReplacer) Prepare(
	_ context.Context,
	configuration NodeConfiguration,
) (*PreparedNodeConfigurationReplacement, error) {
	replacer.prepareCalls++
	replacer.preparedKind = configuration.RoutingCandidate().Descriptor().ActiveTransport
	return &PreparedNodeConfigurationReplacement{}, nil
}

func (replacer *nodeTransportProviderReplacer) Activate(
	_ context.Context,
	_ *PreparedNodeConfigurationReplacement,
) error {
	replacer.activateCalls++
	return nil
}

func (replacer *nodeTransportProviderReplacer) Replace(_ context.Context, configuration NodeConfiguration) error {
	replacer.replaceCalls++
	replacer.replacedKind = configuration.RoutingCandidate().Descriptor().ActiveTransport
	return nil
}

type nodeTransportProviderReadiness struct {
	activeCalls int
	lastKind    model.TransportKind
	failKind    model.TransportKind
}

func (readiness *nodeTransportProviderReadiness) Check(_ context.Context, configuration NodeConfiguration) error {
	readiness.activeCalls++
	readiness.lastKind = configuration.RoutingCandidate().Descriptor().ActiveTransport
	if readiness.lastKind == readiness.failKind {
		return errors.New("selected generation is unavailable")
	}
	return nil
}

type nodeTransportProviderTester struct {
	calls  int
	kind   model.TransportKind
	result transport.TestResult
}

func (tester *nodeTransportProviderTester) Test(
	_ context.Context,
	kind model.TransportKind,
	_ NodeConfiguration,
) (transport.TestResult, error) {
	tester.calls++
	tester.kind = kind
	return tester.result, nil
}

func passedNodeTransportTestResult() transport.TestResult {
	passed := transport.ProbeResult{State: transport.ProbePassed, Code: "passed"}
	return transport.TestResult{Control: passed, ReverseTunnel: passed, SelectedTCP: passed, SelectedUDP: passed}
}

type nodeTransportProviderStateStore struct {
	state model.State
	saves int
}

func (state *nodeTransportProviderStateStore) Load() (model.State, error) { return state.state, nil }

func (state *nodeTransportProviderStateStore) Save(expected uint64, candidate model.State) error {
	if state.state.Generation != expected {
		return store.ErrStateConflict
	}
	if err := model.ValidateTransition(state.state, candidate); err != nil {
		return err
	}
	state.state = candidate
	state.saves++
	return nil
}
