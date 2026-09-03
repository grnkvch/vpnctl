package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestNodeHandshakeHostRecoveryAuthenticatesAndPreservesIdentity(t *testing.T) {
	t.Parallel()

	state := handshakeHostRecoveryState(t)
	beforeNode := state.Nodes[0]
	store := &handshakeHostRecoveryStore{state: state}
	provider := newHandshakeHostRecoveryProvider(state.Transports[1].ConfigHash)
	recovery, err := NewNodeHandshakeHostRecovery(store, provider, SwitchLimits{}, func() time.Time {
		return time.Date(2026, time.September, 3, 14, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := recovery.Plan(context.Background(), "www.apple.com")
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if plan.Current.Hostname != "www.microsoft.com" || plan.Candidate.CandidateID != "apple" || plan.Candidate.Hostname != "www.apple.com" ||
		plan.CredentialGeneration != beforeNode.CredentialGeneration || !reflect.DeepEqual(provider.calls, []string{"render:old", "render:new"}) || store.saves != 0 {
		t.Fatalf("recovery plan/calls = %+v / %v", plan, provider.calls)
	}
	result, err := recovery.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	wantCalls := []string{"render:old", "render:new", "prepare:new", "validate:new", "test:new", "activate:new", "health:new"}
	if !reflect.DeepEqual(provider.calls, wantCalls) {
		t.Fatalf("recovery calls = %v, want %v", provider.calls, wantCalls)
	}
	if result.Active.Hostname != "www.apple.com" || result.StateGeneration != state.Generation+1 || result.CredentialGeneration != beforeNode.CredentialGeneration || result.Health.Condition != HealthHealthy {
		t.Fatalf("recovery result = %+v", result)
	}
	afterNode := store.state.Nodes[0]
	if afterNode.ID != beforeNode.ID || afterNode.Name != beforeNode.Name || afterNode.OverlayIPv4 != beforeNode.OverlayIPv4 || afterNode.CredentialGeneration != beforeNode.CredentialGeneration ||
		afterNode.ActiveTransport != model.TransportRestricted || store.state.HandshakeHost.Hostname != "www.apple.com" || store.state.HandshakeHostChange != nil {
		t.Fatalf("node identity changed during recovery: before=%+v after=%+v host=%+v", beforeNode, afterNode, store.state.HandshakeHost)
	}
	if store.state.Transports[1].HandshakeHost != "www.apple.com" || store.state.Transports[1].ConfigHash == state.Transports[1].ConfigHash || provider.activeHash != store.state.Transports[1].ConfigHash {
		t.Fatalf("restricted recovery artifact was not activated/persisted: transport=%+v active_hash=%s", store.state.Transports[1], provider.activeHash)
	}
}

func TestNodeHandshakeHostRecoveryFailedGatewayProbeLeavesOldHostActive(t *testing.T) {
	t.Parallel()

	state := handshakeHostRecoveryState(t)
	store := &handshakeHostRecoveryStore{state: state}
	provider := newHandshakeHostRecoveryProvider(state.Transports[1].ConfigHash)
	provider.result.Control = ProbeResult{State: ProbeFailed, Code: "gateway-unauthorized"}
	recovery, _ := NewNodeHandshakeHostRecovery(store, provider, SwitchLimits{}, nil)
	plan, _ := recovery.Plan(context.Background(), "www.apple.com")

	_, err := recovery.Apply(context.Background(), plan)
	if !errors.Is(err, ErrHandshakeHostRecoveryUnauthorized) {
		t.Fatalf("unauthorized Apply() error = %v", err)
	}
	if provider.activations != 0 || provider.rollbacks != 1 || provider.activeHash != state.Transports[1].ConfigHash || store.saves != 0 || store.state.HandshakeHost.Hostname != "www.microsoft.com" {
		t.Fatalf("failed authorization changed recovery state: activations=%d rollbacks=%d hash=%s saves=%d", provider.activations, provider.rollbacks, provider.activeHash, store.saves)
	}
}

func TestNodeHandshakeHostRecoveryPostActivationFailureRestoresOldCandidateFirst(t *testing.T) {
	t.Parallel()

	state := handshakeHostRecoveryState(t)
	store := &handshakeHostRecoveryStore{state: state}
	provider := newHandshakeHostRecoveryProvider(state.Transports[1].ConfigHash)
	provider.failHealth = true
	recovery, _ := NewNodeHandshakeHostRecovery(store, provider, SwitchLimits{}, nil)
	plan, _ := recovery.Plan(context.Background(), "www.apple.com")

	_, err := recovery.Apply(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "health-check recovered") {
		t.Fatalf("post-activation Apply() error = %v", err)
	}
	wantSuffix := []string{"activate:new", "health:new", "activate:old", "rollback:new"}
	if len(provider.calls) < len(wantSuffix) || !reflect.DeepEqual(provider.calls[len(provider.calls)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("recovery compensation calls = %v", provider.calls)
	}
	if provider.activeHash != state.Transports[1].ConfigHash || store.saves != 0 || store.state.HandshakeHost.Hostname != "www.microsoft.com" {
		t.Fatal("failed recovered health did not restore old candidate")
	}
}

func TestNodeHandshakeHostRecoveryRequiresActiveRestrictedAndFreshPlan(t *testing.T) {
	t.Parallel()

	t.Run("standard active", func(t *testing.T) {
		t.Parallel()
		state := nodeTransportTestState(t)
		store := &handshakeHostRecoveryStore{state: state}
		provider := newHandshakeHostRecoveryProvider(state.Transports[1].ConfigHash)
		recovery, _ := NewNodeHandshakeHostRecovery(store, provider, SwitchLimits{}, nil)
		if _, err := recovery.Plan(context.Background(), "www.apple.com"); err == nil || !strings.Contains(err.Error(), "restricted transport active") {
			t.Fatalf("standard-active Plan() error = %v", err)
		}
		if len(provider.calls) != 0 {
			t.Fatalf("standard-active recovery touched provider: %v", provider.calls)
		}
	})

	t.Run("stale state", func(t *testing.T) {
		t.Parallel()
		state := handshakeHostRecoveryState(t)
		store := &handshakeHostRecoveryStore{state: state}
		provider := newHandshakeHostRecoveryProvider(state.Transports[1].ConfigHash)
		recovery, _ := NewNodeHandshakeHostRecovery(store, provider, SwitchLimits{}, nil)
		plan, _ := recovery.Plan(context.Background(), "www.apple.com")
		store.state.Generation++
		store.state.Nodes[0].Gateway.LastKnownGatewayGeneration++
		calls := len(provider.calls)
		if _, err := recovery.Apply(context.Background(), plan); !errors.Is(err, ErrHandshakeHostRecoveryStale) {
			t.Fatalf("stale Apply() error = %v", err)
		}
		if len(provider.calls) != calls || store.saves != 0 {
			t.Fatal("stale recovery reached provider/state mutation")
		}
	})
}

func TestNodeHandshakeHostRecoveryRejectsTamperedIdentityPlanBeforeMutation(t *testing.T) {
	t.Parallel()

	state := handshakeHostRecoveryState(t)
	store := &handshakeHostRecoveryStore{state: state}
	provider := newHandshakeHostRecoveryProvider(state.Transports[1].ConfigHash)
	recovery, _ := NewNodeHandshakeHostRecovery(store, provider, SwitchLimits{}, nil)
	plan, _ := recovery.Plan(context.Background(), "www.apple.com")
	plan.targetCandidate = handshakeHostRecoveryCandidate{descriptor: CandidateDescriptor{
		OwnerKind: model.TargetNode, OwnerID: "20000000-0000-4000-8000-000000000099",
		CredentialGeneration: plan.CredentialGeneration, Kind: model.TransportRestricted,
		ConfigHash: plan.targetCandidate.Descriptor().ConfigHash,
	}}
	calls := len(provider.calls)
	if _, err := recovery.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "changed node identity") {
		t.Fatalf("Apply(tampered identity) error = %v", err)
	}
	if len(provider.calls) != calls || store.saves != 0 {
		t.Fatal("tampered recovery plan reached provider or state mutation")
	}
}

func TestNodeHandshakeHostRecoveryReconcilesStateWriteFailure(t *testing.T) {
	t.Parallel()

	t.Run("old state proven", func(t *testing.T) {
		t.Parallel()
		state := handshakeHostRecoveryState(t)
		store := &handshakeHostRecoveryStore{state: state, saveErr: errors.New("synthetic save failure")}
		provider := newHandshakeHostRecoveryProvider(state.Transports[1].ConfigHash)
		recovery, _ := NewNodeHandshakeHostRecovery(store, provider, SwitchLimits{}, nil)
		plan, _ := recovery.Plan(context.Background(), "www.apple.com")
		_, err := recovery.Apply(context.Background(), plan)
		if err == nil || errors.Is(err, ErrHandshakeHostRecoveryCommitUncertain) {
			t.Fatalf("known-old save error = %v", err)
		}
		if provider.activeHash != state.Transports[1].ConfigHash || provider.rollbacks != 1 || store.state.HandshakeHost.Hostname != "www.microsoft.com" {
			t.Fatal("known-old save failure was not compensated")
		}
	})

	t.Run("candidate committed before error", func(t *testing.T) {
		t.Parallel()
		state := handshakeHostRecoveryState(t)
		store := &handshakeHostRecoveryStore{state: state, saveErr: errors.New("post-commit fsync failure"), commitBeforeError: true}
		provider := newHandshakeHostRecoveryProvider(state.Transports[1].ConfigHash)
		recovery, _ := NewNodeHandshakeHostRecovery(store, provider, SwitchLimits{}, nil)
		plan, _ := recovery.Plan(context.Background(), "www.apple.com")
		_, err := recovery.Apply(context.Background(), plan)
		if !errors.Is(err, ErrHandshakeHostRecoveryCommitUncertain) {
			t.Fatalf("committed recovery error = %v", err)
		}
		if provider.rollbacks != 0 || store.state.HandshakeHost.Hostname != "www.apple.com" || provider.activeHash != store.state.Transports[1].ConfigHash {
			t.Fatal("committed uncertain recovery was blindly rolled back")
		}
	})
}

func handshakeHostRecoveryState(t *testing.T) model.State {
	t.Helper()
	state := nodeTransportTestState(t)
	state.Nodes[0].ActiveTransport = model.TransportRestricted
	for index := range state.Transports {
		switch state.Transports[index].Kind {
		case model.TransportStandard:
			state.Transports[index].State = model.TransportStandby
		case model.TransportRestricted:
			state.Transports[index].State = model.TransportActive
		}
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("handshake-host recovery fixture: %v", err)
	}
	return state
}

type handshakeHostRecoveryStore struct {
	state             model.State
	saves             int
	saveErr           error
	commitBeforeError bool
}

func (store *handshakeHostRecoveryStore) Load() (model.State, error) { return store.state, nil }

func (store *handshakeHostRecoveryStore) Save(expected uint64, candidate model.State) error {
	store.saves++
	if expected != store.state.Generation {
		return errors.New("synthetic generation conflict")
	}
	if store.saveErr == nil || store.commitBeforeError {
		store.state = candidate
	}
	return store.saveErr
}

type handshakeHostRecoveryCandidate struct{ descriptor CandidateDescriptor }

func (candidate handshakeHostRecoveryCandidate) Descriptor() CandidateDescriptor {
	return candidate.descriptor
}

type handshakeHostRecoveryProvider struct {
	oldHash     string
	activeHash  string
	result      TestResult
	calls       []string
	activations int
	rollbacks   int
	failHealth  bool
}

func newHandshakeHostRecoveryProvider(oldHash string) *handshakeHostRecoveryProvider {
	passed := ProbeResult{State: ProbePassed, Code: "passed"}
	return &handshakeHostRecoveryProvider{
		oldHash: oldHash, activeHash: oldHash,
		result: TestResult{Control: passed, ReverseTunnel: passed, SelectedTCP: passed, SelectedUDP: passed},
	}
}

func (provider *handshakeHostRecoveryProvider) Kind() model.TransportKind {
	return model.TransportRestricted
}

func (provider *handshakeHostRecoveryProvider) Render(_ context.Context, request RenderRequest) (Candidate, error) {
	descriptor := DescriptorFromTransport(request.Transport)
	label := "old"
	if request.Transport.HandshakeHost != "www.microsoft.com" {
		label = "new"
		digest := sha256.Sum256([]byte(request.Transport.HandshakeHost))
		descriptor.ConfigHash = hex.EncodeToString(digest[:])
	}
	provider.calls = append(provider.calls, "render:"+label)
	return handshakeHostRecoveryCandidate{descriptor: descriptor}, nil
}

func (provider *handshakeHostRecoveryProvider) Prepare(_ context.Context, candidate Candidate) error {
	provider.calls = append(provider.calls, "prepare:"+provider.label(candidate))
	return nil
}

func (provider *handshakeHostRecoveryProvider) Validate(_ context.Context, candidate Candidate) error {
	provider.calls = append(provider.calls, "validate:"+provider.label(candidate))
	return nil
}

func (provider *handshakeHostRecoveryProvider) StartTest(_ context.Context, candidate Candidate) (TestResult, error) {
	provider.calls = append(provider.calls, "test:"+provider.label(candidate))
	return provider.result, nil
}

func (provider *handshakeHostRecoveryProvider) Activate(_ context.Context, candidate Candidate) error {
	provider.calls = append(provider.calls, "activate:"+provider.label(candidate))
	provider.activations++
	provider.activeHash = candidate.Descriptor().ConfigHash
	return nil
}

func (provider *handshakeHostRecoveryProvider) Health(_ context.Context, request HealthRequest) (Health, error) {
	provider.calls = append(provider.calls, "health:new")
	if provider.failHealth {
		return Health{}, errors.New("synthetic health failure")
	}
	return Health{Identity: request.Identity, Kind: model.TransportRestricted, Role: RuntimeActive, Condition: HealthHealthy, Code: "healthy"}, nil
}

func (provider *handshakeHostRecoveryProvider) Drain(context.Context, DrainRequest) error { return nil }

func (provider *handshakeHostRecoveryProvider) Rollback(_ context.Context, candidate Candidate) error {
	provider.calls = append(provider.calls, "rollback:"+provider.label(candidate))
	provider.rollbacks++
	return nil
}

func (provider *handshakeHostRecoveryProvider) label(candidate Candidate) string {
	if candidate.Descriptor().ConfigHash == provider.oldHash {
		return "old"
	}
	return "new"
}

var _ Provider = (*handshakeHostRecoveryProvider)(nil)
