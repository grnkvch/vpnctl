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

func TestProviderLifecycleContract(t *testing.T) {
	identity := transportIdentity()
	provider := newFakeProvider(model.TransportRestricted, RuntimeStandby, HealthHealthy)
	request := RenderRequest{Transport: restrictedTransport(identity, model.TransportStandby)}
	if err := request.Validate(); err != nil {
		t.Fatalf("RenderRequest.Validate() error = %v", err)
	}

	candidate, err := provider.Render(context.Background(), request)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if err := candidate.Descriptor().Validate(); err != nil {
		t.Fatalf("candidate descriptor error = %v", err)
	}
	if err := provider.Prepare(context.Background(), candidate); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := provider.Validate(context.Background(), candidate); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	result, err := provider.StartTest(context.Background(), candidate)
	if err != nil {
		t.Fatalf("StartTest() error = %v", err)
	}
	if err := result.Validate(); err != nil || !result.Ready() {
		t.Fatalf("test result = %#v, error = %v", result, err)
	}
	if err := provider.Activate(context.Background(), candidate); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	health, err := provider.Health(context.Background(), HealthRequest{Identity: identity})
	if err != nil || health.Role != RuntimeActive {
		t.Fatalf("Health() = %#v, %v", health, err)
	}
	if err := provider.Drain(context.Background(), DrainRequest{Identity: identity, Deadline: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Drain() error = %v", err)
	}
	if err := provider.Rollback(context.Background(), candidate); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}

	wantCalls := []string{"render", "prepare", "validate", "test", "activate", "health", "drain", "rollback"}
	if !reflect.DeepEqual(provider.calls, wantCalls) {
		t.Fatalf("provider calls = %v, want %v", provider.calls, wantCalls)
	}
}

func TestManagerActiveOutageDoesNotProbeOrActivateStandby(t *testing.T) {
	identity := transportIdentity()
	standard := newFakeProvider(model.TransportStandard, RuntimeActive, HealthUnavailable)
	restricted := newFakeProvider(model.TransportRestricted, RuntimeStandby, HealthHealthy)
	manager := newTestManager(t, identity, model.TransportStandard, standard, restricted)
	before := manager.Selection()

	health, err := manager.ObserveActive(context.Background())
	if err != nil {
		t.Fatalf("ObserveActive() error = %v", err)
	}
	if health.Kind != model.TransportStandard || health.Role != RuntimeActive || health.Condition != HealthUnavailable {
		t.Fatalf("ObserveActive() = %#v", health)
	}
	if manager.Selection() != before {
		t.Fatalf("health observation changed selection from %#v to %#v", before, manager.Selection())
	}
	if !reflect.DeepEqual(standard.calls, []string{"health"}) {
		t.Fatalf("active provider calls = %v", standard.calls)
	}
	if len(restricted.calls) != 0 {
		t.Fatalf("standby provider was touched during active outage: %v", restricted.calls)
	}
}

func TestManagerHealthFailureDoesNotFailOver(t *testing.T) {
	identity := transportIdentity()
	standard := newFakeProvider(model.TransportStandard, RuntimeActive, HealthHealthy)
	standard.healthErr = errors.New("synthetic outage")
	restricted := newFakeProvider(model.TransportRestricted, RuntimeStandby, HealthHealthy)
	manager := newTestManager(t, identity, model.TransportStandard, standard, restricted)
	before := manager.Selection()

	if _, err := manager.ObserveActive(context.Background()); err == nil || !strings.Contains(err.Error(), "synthetic outage") {
		t.Fatalf("ObserveActive() error = %v", err)
	}
	if manager.Selection() != before || len(restricted.calls) != 0 {
		t.Fatalf("failed health check changed selection or touched standby: selection=%#v calls=%v", manager.Selection(), restricted.calls)
	}
	assertNoMutationCalls(t, standard, restricted)
}

func TestManagerSteadyStateRequiresExactlySelectedActiveAndStandby(t *testing.T) {
	tests := []struct {
		name           string
		standardRole   RuntimeRole
		restrictedRole RuntimeRole
		wantError      string
	}{
		{name: "selected pair", standardRole: RuntimeActive, restrictedRole: RuntimeStandby},
		{name: "two active", standardRole: RuntimeActive, restrictedRole: RuntimeActive, wantError: "expected standby"},
		{name: "two standby", standardRole: RuntimeStandby, restrictedRole: RuntimeStandby, wantError: "expected active"},
		{name: "roles reversed", standardRole: RuntimeStandby, restrictedRole: RuntimeActive, wantError: "expected active"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := transportIdentity()
			standard := newFakeProvider(model.TransportStandard, test.standardRole, HealthHealthy)
			restricted := newFakeProvider(model.TransportRestricted, test.restrictedRole, HealthHealthy)
			manager := newTestManager(t, identity, model.TransportStandard, standard, restricted)
			before := manager.Selection()

			observations, err := manager.CheckSteadyState(context.Background())
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("CheckSteadyState() error = %v", err)
				}
				if observations[0].Role != RuntimeActive || observations[1].Role != RuntimeStandby {
					t.Fatalf("steady observations = %#v", observations)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("CheckSteadyState() error = %v, want %q", err, test.wantError)
			}
			if manager.Selection() != before {
				t.Fatalf("steady-state validation adopted observed roles: before=%#v after=%#v", before, manager.Selection())
			}
			assertNoMutationCalls(t, standard, restricted)
		})
	}
}

func TestSelectionAndRegistryRejectAmbiguousTransportPairs(t *testing.T) {
	if _, err := NewSelection("automatic"); err == nil {
		t.Fatal("NewSelection() accepted an automatic transport")
	}
	if err := (Selection{Active: model.TransportStandard, Standby: model.TransportStandard}).Validate(); err == nil {
		t.Fatal("Selection.Validate() accepted the same active and standby transport")
	}

	standard := newFakeProvider(model.TransportStandard, RuntimeActive, HealthHealthy)
	restricted := newFakeProvider(model.TransportRestricted, RuntimeStandby, HealthHealthy)
	unknown := newFakeProvider("future", RuntimeStandby, HealthHealthy)
	var nilRestricted *fakeProvider
	tests := []struct {
		name      string
		providers []Provider
		want      string
	}{
		{name: "missing restricted", providers: []Provider{standard}, want: "restricted transport provider is required"},
		{name: "duplicate standard", providers: []Provider{standard, standard, restricted}, want: "duplicate standard"},
		{name: "unknown provider", providers: []Provider{standard, restricted, unknown}, want: "unsupported kind"},
		{name: "typed nil", providers: []Provider{standard, nilRestricted}, want: "is nil"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRegistry(test.providers...); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewRegistry() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestHealthKeepsRuntimeRoleIndependentFromCondition(t *testing.T) {
	identity := transportIdentity()
	for _, condition := range []HealthCondition{HealthHealthy, HealthDegraded, HealthUnavailable} {
		health := Health{
			Identity:  identity,
			Kind:      model.TransportRestricted,
			Role:      RuntimeActive,
			Condition: condition,
			Code:      "synthetic_status",
		}
		if err := health.Validate(); err != nil {
			t.Fatalf("active %s health rejected: %v", condition, err)
		}
	}
}

func newTestManager(t *testing.T, identity Identity, active model.TransportKind, providers ...Provider) *Manager {
	t.Helper()
	registry, err := NewRegistry(providers...)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	selection, err := NewSelection(active)
	if err != nil {
		t.Fatalf("NewSelection() error = %v", err)
	}
	manager, err := NewManager(identity, selection, registry)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return manager
}

func assertNoMutationCalls(t *testing.T, providers ...*fakeProvider) {
	t.Helper()
	for _, provider := range providers {
		for _, call := range provider.calls {
			switch call {
			case "render", "prepare", "validate", "test", "activate", "drain", "rollback":
				t.Fatalf("health observation invoked mutating %s provider method %q", provider.kind, call)
			}
		}
	}
}

func transportIdentity() Identity {
	return Identity{
		OwnerKind:            model.TargetNode,
		OwnerID:              "11111111-1111-4111-8111-111111111111",
		CredentialGeneration: 3,
	}
}

func restrictedTransport(identity Identity, state model.TransportState) model.Transport {
	return model.Transport{
		SchemaVersion:        model.ResourceSchemaVersion,
		OwnerKind:            identity.OwnerKind,
		OwnerID:              identity.OwnerID,
		Kind:                 model.TransportRestricted,
		State:                state,
		Provider:             "mihomo",
		Protocol:             model.ProtocolTCP,
		Port:                 8443,
		CredentialGeneration: identity.CredentialGeneration,
		CredentialRef:        "transport-key:restricted",
		HandshakeHost:        "example.com",
		ConfigHash:           strings.Repeat("a", 64),
	}
}

type fakeCandidate struct {
	descriptor CandidateDescriptor
}

func (candidate fakeCandidate) Descriptor() CandidateDescriptor { return candidate.descriptor }

type fakeProvider struct {
	kind      model.TransportKind
	role      RuntimeRole
	condition HealthCondition
	healthErr error
	calls     []string
}

var _ Provider = (*fakeProvider)(nil)

func newFakeProvider(kind model.TransportKind, role RuntimeRole, condition HealthCondition) *fakeProvider {
	return &fakeProvider{kind: kind, role: role, condition: condition}
}

func (provider *fakeProvider) Kind() model.TransportKind { return provider.kind }

func (provider *fakeProvider) Render(_ context.Context, request RenderRequest) (Candidate, error) {
	provider.calls = append(provider.calls, "render")
	return fakeCandidate{descriptor: DescriptorFromTransport(request.Transport)}, nil
}

func (provider *fakeProvider) Prepare(context.Context, Candidate) error {
	provider.calls = append(provider.calls, "prepare")
	return nil
}

func (provider *fakeProvider) Validate(context.Context, Candidate) error {
	provider.calls = append(provider.calls, "validate")
	return nil
}

func (provider *fakeProvider) StartTest(context.Context, Candidate) (TestResult, error) {
	provider.calls = append(provider.calls, "test")
	passed := ProbeResult{State: ProbePassed, Code: "ok"}
	return TestResult{Control: passed, ReverseTunnel: passed, SelectedTCP: passed, SelectedUDP: passed}, nil
}

func (provider *fakeProvider) Activate(context.Context, Candidate) error {
	provider.calls = append(provider.calls, "activate")
	provider.role = RuntimeActive
	return nil
}

func (provider *fakeProvider) Health(_ context.Context, request HealthRequest) (Health, error) {
	provider.calls = append(provider.calls, "health")
	if provider.healthErr != nil {
		return Health{}, provider.healthErr
	}
	return Health{
		Identity:  request.Identity,
		Kind:      provider.kind,
		Role:      provider.role,
		Condition: provider.condition,
		Code:      "synthetic_status",
	}, nil
}

func (provider *fakeProvider) Drain(context.Context, DrainRequest) error {
	provider.calls = append(provider.calls, "drain")
	provider.role = RuntimeStandby
	return nil
}

func (provider *fakeProvider) Rollback(context.Context, Candidate) error {
	provider.calls = append(provider.calls, "rollback")
	return nil
}
