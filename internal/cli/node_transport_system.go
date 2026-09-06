package cli

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

// systemNodeTransportRuntime delays host discovery, secret reads, native
// rendering, and systemd preflight until a provider method is actually used.
// Consequently transport switch --dry-run remains a state-only operation.
type systemNodeTransportRuntime struct {
	mu       sync.Mutex
	paths    store.Paths
	state    *store.StateStore
	expected model.State
	registry *transport.Registry
}

type systemNodeTransportProvider struct {
	kind    model.TransportKind
	runtime *systemNodeTransportRuntime
}

func buildSystemTransportRegistry(paths store.Paths, state *store.StateStore) (*transport.Registry, error) {
	if state == nil {
		return nil, fmt.Errorf("system node transport state store is required")
	}
	expected, err := state.Load()
	if err != nil {
		return nil, err
	}
	if err := expected.Validate(); err != nil || expected.Host.Role != model.RoleNode || len(expected.Nodes) != 1 {
		return nil, errors.Join(ErrSystemTransportRuntimeUnavailable, err)
	}
	runtime := &systemNodeTransportRuntime{paths: paths, state: state, expected: expected}
	return transport.NewRegistry(
		&systemNodeTransportProvider{kind: model.TransportStandard, runtime: runtime},
		&systemNodeTransportProvider{kind: model.TransportRestricted, runtime: runtime},
	)
}

func (provider *systemNodeTransportProvider) Kind() model.TransportKind {
	if provider == nil {
		return ""
	}
	return provider.kind
}

func (provider *systemNodeTransportProvider) Render(ctx context.Context, request transport.RenderRequest) (transport.Candidate, error) {
	delegate, err := provider.delegate(ctx)
	if err != nil {
		return nil, err
	}
	return delegate.Render(ctx, request)
}

func (provider *systemNodeTransportProvider) Prepare(ctx context.Context, candidate transport.Candidate) error {
	delegate, err := provider.delegate(ctx)
	if err != nil {
		return err
	}
	return delegate.Prepare(ctx, candidate)
}

func (provider *systemNodeTransportProvider) Validate(ctx context.Context, candidate transport.Candidate) error {
	delegate, err := provider.delegate(ctx)
	if err != nil {
		return err
	}
	return delegate.Validate(ctx, candidate)
}

func (provider *systemNodeTransportProvider) StartTest(ctx context.Context, candidate transport.Candidate) (transport.TestResult, error) {
	delegate, err := provider.delegate(ctx)
	if err != nil {
		return transport.TestResult{}, err
	}
	return delegate.StartTest(ctx, candidate)
}

func (provider *systemNodeTransportProvider) Activate(ctx context.Context, candidate transport.Candidate) error {
	delegate, err := provider.delegate(ctx)
	if err != nil {
		return err
	}
	return delegate.Activate(ctx, candidate)
}

func (provider *systemNodeTransportProvider) Health(ctx context.Context, request transport.HealthRequest) (transport.Health, error) {
	delegate, err := provider.delegate(ctx)
	if err != nil {
		return transport.Health{}, err
	}
	return delegate.Health(ctx, request)
}

func (provider *systemNodeTransportProvider) Drain(ctx context.Context, request transport.DrainRequest) error {
	delegate, err := provider.delegate(ctx)
	if err != nil {
		return err
	}
	return delegate.Drain(ctx, request)
}

func (provider *systemNodeTransportProvider) Rollback(ctx context.Context, candidate transport.Candidate) error {
	delegate, err := provider.delegate(ctx)
	if err != nil {
		return err
	}
	return delegate.Rollback(ctx, candidate)
}

func (provider *systemNodeTransportProvider) delegate(ctx context.Context) (transport.Provider, error) {
	if ctx == nil || provider == nil || provider.runtime == nil {
		return nil, ErrSystemTransportRuntimeUnavailable
	}
	registry, err := provider.runtime.load(ctx)
	if err != nil {
		return nil, err
	}
	return registry.Provider(provider.kind)
}

func (runtime *systemNodeTransportRuntime) load(ctx context.Context) (*transport.Registry, error) {
	if ctx == nil || runtime == nil || runtime.state == nil {
		return nil, ErrSystemTransportRuntimeUnavailable
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.registry != nil {
		return runtime.registry, nil
	}
	current, err := runtime.state.Load()
	if err != nil {
		return nil, errors.Join(ErrSystemTransportRuntimeUnavailable, err)
	}
	if !reflect.DeepEqual(current, runtime.expected) {
		return nil, transport.ErrTransportSwitchStale
	}
	registry, err := runtime.compile(ctx, current)
	if err != nil {
		return nil, errors.Join(ErrSystemTransportRuntimeUnavailable, err)
	}
	current, err = runtime.state.Load()
	if err != nil {
		return nil, errors.Join(ErrSystemTransportRuntimeUnavailable, err)
	}
	if !reflect.DeepEqual(current, runtime.expected) {
		return nil, transport.ErrTransportSwitchStale
	}
	runtime.registry = registry
	return registry, nil
}

func (runtime *systemNodeTransportRuntime) compile(ctx context.Context, current model.State) (*transport.Registry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base, alternative, err := nodeTransportCompilationStates(current)
	if err != nil {
		return nil, err
	}
	secrets, err := store.NewSecretStore(runtime.paths)
	if err != nil {
		return nil, err
	}
	discoverer, err := linuxplatform.NewDiscoverer(runtime.paths.Root)
	if err != nil {
		return nil, err
	}
	snapshot, err := discoverer.Discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover node host for transport runtime: %w", err)
	}
	compiler, err := enrollment.NewNodeConfigurationCompiler(
		runtime.paths.Root,
		secrets,
		enrollment.NodeConfigurationRuntime{WireGuardRunner: wireguard.ExecRunner{}},
	)
	if err != nil {
		return nil, err
	}
	baseConfiguration, err := compiler.Compile(ctx, base, snapshot)
	if err != nil {
		return nil, fmt.Errorf("compile active node transport generation: %w", err)
	}
	alternativeConfiguration, err := compiler.Compile(ctx, alternative, snapshot)
	if err != nil {
		return nil, fmt.Errorf("compile standby node transport generation: %w", err)
	}
	configurations := map[model.TransportKind]enrollment.NodeConfiguration{
		base.Nodes[0].ActiveTransport:        baseConfiguration,
		alternative.Nodes[0].ActiveTransport: alternativeConfiguration,
	}
	transports, err := nodeTransportPair(current)
	if err != nil {
		return nil, err
	}
	runner := linuxplatform.OSProbeRunner{}
	host, err := linuxplatform.NewRoleSystemdInstaller(runtime.paths.Root, runtime.paths.ConfigDir, runner)
	if err != nil {
		return nil, err
	}
	readiness, err := enrollment.NewSystemNodeConfigurationReadiness(runtime.paths, runner)
	if err != nil {
		return nil, err
	}
	replacer, err := enrollment.NewNodeConfigurationReplacer(host, readiness)
	if err != nil {
		return nil, err
	}
	pathFactory, err := newSystemNodeTransportCandidatePathFactory(runtime.paths, runner)
	if err != nil {
		return nil, err
	}
	tester, err := enrollment.NewBoundedNodeTransportCandidateTester(
		pathFactory,
		systemNodeTransportControlProbe{paths: runtime.paths},
	)
	if err != nil {
		return nil, err
	}
	return enrollment.NewNodeTransportRegistry(
		current.Nodes[0].ActiveTransport,
		transports[model.TransportStandard], configurations[model.TransportStandard],
		transports[model.TransportRestricted], configurations[model.TransportRestricted],
		replacer, readiness, tester,
	)
}

func nodeTransportCompilationStates(current model.State) (model.State, model.State, error) {
	if err := current.Validate(); err != nil || current.Host.Role != model.RoleNode || len(current.Nodes) != 1 {
		return model.State{}, model.State{}, errors.Join(fmt.Errorf("transport runtime requires one local node"), err)
	}
	operation, pending, err := current.PendingNodeOperation()
	if err != nil {
		return model.State{}, model.State{}, err
	}
	if pending {
		desired, _, err := transport.DeferredSwitchDesiredState(current, operation)
		if err != nil {
			return model.State{}, model.State{}, err
		}
		base, err := nodeTransportStateBeforePending(current, operation)
		if err != nil {
			return model.State{}, model.State{}, err
		}
		return base, desired, nil
	}
	selection, err := transport.NewSelection(current.Nodes[0].ActiveTransport)
	if err != nil {
		return model.State{}, model.State{}, err
	}
	alternative, err := transport.DesiredNodeSwitchState(current, selection.Standby)
	if err != nil {
		return model.State{}, model.State{}, err
	}
	return current, alternative, nil
}

func nodeTransportStateBeforePending(current model.State, operation model.Operation) (model.State, error) {
	intent, err := transport.ParseSwitchIntentTarget(operation.TargetID)
	if err != nil || operation.Type != model.OperationTransportSwitch || operation.State != model.OperationPending ||
		intent.NodeID != current.Nodes[0].ID {
		return model.State{}, errors.Join(transport.ErrTransportSwitchStale, err)
	}
	base := current
	base.Generation = intent.ExpectedNodeGeneration
	base.Operations = make([]model.Operation, 0, len(current.Operations)-1)
	found := false
	for _, candidate := range current.Operations {
		if candidate.ID == operation.ID {
			found = true
			continue
		}
		base.Operations = append(base.Operations, candidate)
	}
	if !found {
		return model.State{}, transport.ErrTransportSwitchStale
	}
	base.Nodes = append([]model.Node(nil), current.Nodes...)
	trust := *current.Nodes[0].Gateway
	trust.PendingRequestID = ""
	trust.LastKnownGatewayGeneration = operation.ExpectedGeneration
	base.Nodes[0].Gateway = &trust
	if err := base.Validate(); err != nil {
		return model.State{}, fmt.Errorf("validate node state before deferred transport intent: %w", err)
	}
	if err := model.ValidateTransition(base, current); err != nil {
		return model.State{}, fmt.Errorf("verify retained deferred transport intent: %w", err)
	}
	return base, nil
}

func nodeTransportPair(state model.State) (map[model.TransportKind]model.Transport, error) {
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleNode || len(state.Nodes) != 1 {
		return nil, errors.Join(fmt.Errorf("transport runtime requires one local node"), err)
	}
	result := make(map[model.TransportKind]model.Transport, 2)
	for _, candidate := range state.Transports {
		if candidate.OwnerKind != model.TargetNode || candidate.OwnerID != state.Nodes[0].ID || candidate.State == model.TransportDisabled {
			continue
		}
		if _, duplicate := result[candidate.Kind]; duplicate {
			return nil, fmt.Errorf("node transport %s is duplicated", candidate.Kind)
		}
		result[candidate.Kind] = candidate
	}
	for _, kind := range []model.TransportKind{model.TransportStandard, model.TransportRestricted} {
		if _, found := result[kind]; !found {
			return nil, fmt.Errorf("node transport %s is not configured", kind)
		}
	}
	return result, nil
}

var _ transport.Provider = (*systemNodeTransportProvider)(nil)
