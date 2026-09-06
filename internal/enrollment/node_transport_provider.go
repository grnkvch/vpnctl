package enrollment

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

type NodeTransportGenerationReplacer interface {
	Prepare(context.Context, NodeConfiguration) (*PreparedNodeConfigurationReplacement, error)
	Activate(context.Context, *PreparedNodeConfigurationReplacement) error
	Replace(context.Context, NodeConfiguration) error
}

type NodeTransportGenerationReadiness interface {
	Check(context.Context, NodeConfiguration) error
}

type NodeTransportCandidateTester interface {
	Test(context.Context, model.TransportKind, NodeConfiguration) (transport.TestResult, error)
}

type nodeTransportBundle struct {
	transport     model.Transport
	configuration NodeConfiguration
}

// nodeTransportCoordinator is shared by both provider adapters. A successful
// activation replaces the complete node generation before it flips the one
// in-memory production selector; no provider can independently move control,
// reverse tunnel, selected TCP, or selected UDP.
type nodeTransportCoordinator struct {
	mu        sync.Mutex
	identity  transport.Identity
	selected  model.TransportKind
	bundles   map[model.TransportKind]nodeTransportBundle
	replacer  NodeTransportGenerationReplacer
	readiness NodeTransportGenerationReadiness
	tester    NodeTransportCandidateTester
}

type nodeTransportProvider struct {
	kind        model.TransportKind
	coordinator *nodeTransportCoordinator
}

type nodeTransportCandidate struct {
	descriptor    transport.CandidateDescriptor
	kind          model.TransportKind
	coordinator   *nodeTransportCoordinator
	configuration NodeConfiguration

	mu       sync.Mutex
	prepared *PreparedNodeConfigurationReplacement
	used     bool
}

func NewNodeTransportRegistry(
	selected model.TransportKind,
	standardTransport model.Transport,
	standardConfiguration NodeConfiguration,
	restrictedTransport model.Transport,
	restrictedConfiguration NodeConfiguration,
	replacer NodeTransportGenerationReplacer,
	readiness NodeTransportGenerationReadiness,
	tester NodeTransportCandidateTester,
) (*transport.Registry, error) {
	if replacer == nil || readiness == nil || tester == nil {
		return nil, fmt.Errorf("node transport runtime dependencies are incomplete")
	}
	selection, err := transport.NewSelection(selected)
	if err != nil {
		return nil, err
	}
	bundles := map[model.TransportKind]nodeTransportBundle{
		model.TransportStandard: {
			transport: standardTransport, configuration: standardConfiguration,
		},
		model.TransportRestricted: {
			transport: restrictedTransport, configuration: restrictedConfiguration,
		},
	}
	var identity transport.Identity
	for _, kind := range []model.TransportKind{model.TransportStandard, model.TransportRestricted} {
		bundle := bundles[kind]
		if err := bundle.transport.Validate(); err != nil {
			return nil, fmt.Errorf("validate %s node transport bundle: %w", kind, err)
		}
		if bundle.transport.OwnerKind != model.TargetNode || bundle.transport.Kind != kind ||
			bundle.transport.State == model.TransportDisabled {
			return nil, fmt.Errorf("%s node transport bundle has invalid identity or state", kind)
		}
		if err := bundle.configuration.Validate(); err != nil {
			return nil, fmt.Errorf("validate %s node transport configuration: %w", kind, err)
		}
		descriptor := bundle.configuration.RoutingCandidate().Descriptor()
		if descriptor.ActiveTransport != kind || descriptor.CredentialGeneration != bundle.transport.CredentialGeneration {
			return nil, fmt.Errorf("%s node transport bundle has a split routing selection", kind)
		}
		candidateIdentity := transport.IdentityFromTransport(bundle.transport)
		if kind == model.TransportStandard {
			identity = candidateIdentity
		} else if candidateIdentity != identity {
			return nil, fmt.Errorf("node transport bundles belong to different identities")
		}
	}
	if bundles[selection.Active].transport.State != model.TransportActive &&
		bundles[selection.Active].transport.State != model.TransportDegraded {
		return nil, fmt.Errorf("selected node transport is not active")
	}
	if bundles[selection.Standby].transport.State != model.TransportStandby {
		return nil, fmt.Errorf("unselected node transport is not standby")
	}
	coordinator := &nodeTransportCoordinator{
		identity: identity, selected: selected, bundles: bundles,
		replacer: replacer, readiness: readiness, tester: tester,
	}
	return transport.NewRegistry(
		&nodeTransportProvider{kind: model.TransportStandard, coordinator: coordinator},
		&nodeTransportProvider{kind: model.TransportRestricted, coordinator: coordinator},
	)
}

func (provider *nodeTransportProvider) Kind() model.TransportKind {
	if provider == nil {
		return ""
	}
	return provider.kind
}

func (provider *nodeTransportProvider) Render(
	ctx context.Context,
	request transport.RenderRequest,
) (transport.Candidate, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if provider == nil || provider.coordinator == nil {
		return nil, fmt.Errorf("node transport provider is incomplete")
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	provider.coordinator.mu.Lock()
	bundle, found := provider.coordinator.bundles[provider.kind]
	provider.coordinator.mu.Unlock()
	wanted := bundle.transport
	wanted.State = request.Transport.State
	if !found || request.Transport != wanted ||
		(request.Transport.State != model.TransportActive && request.Transport.State != model.TransportDegraded &&
			request.Transport.State != model.TransportStandby) {
		return nil, fmt.Errorf("node transport render request differs from the prepared authoritative bundle")
	}
	return &nodeTransportCandidate{
		descriptor:    transport.DescriptorFromTransport(bundle.transport),
		kind:          provider.kind,
		coordinator:   provider.coordinator,
		configuration: bundle.configuration,
	}, nil
}

func (provider *nodeTransportProvider) Prepare(ctx context.Context, value transport.Candidate) error {
	candidate, err := provider.candidate(value)
	if err != nil {
		return err
	}
	candidate.mu.Lock()
	defer candidate.mu.Unlock()
	if candidate.used {
		return fmt.Errorf("node transport candidate is already consumed")
	}
	if candidate.prepared != nil {
		return nil
	}
	prepared, err := provider.coordinator.replacer.Prepare(ctx, candidate.configuration)
	if err != nil {
		return err
	}
	candidate.prepared = prepared
	return nil
}

func (provider *nodeTransportProvider) Validate(_ context.Context, value transport.Candidate) error {
	candidate, err := provider.candidate(value)
	if err != nil {
		return err
	}
	if err := candidate.configuration.Validate(); err != nil {
		return err
	}
	descriptor := candidate.configuration.RoutingCandidate().Descriptor()
	if descriptor.ActiveTransport != provider.kind || descriptor.CredentialGeneration != candidate.descriptor.CredentialGeneration {
		return fmt.Errorf("node transport candidate has a split routing selection")
	}
	return nil
}

func (provider *nodeTransportProvider) StartTest(
	ctx context.Context,
	value transport.Candidate,
) (transport.TestResult, error) {
	candidate, err := provider.candidate(value)
	if err != nil {
		return transport.TestResult{}, err
	}
	return provider.coordinator.tester.Test(ctx, provider.kind, candidate.configuration)
}

func (provider *nodeTransportProvider) Activate(ctx context.Context, value transport.Candidate) error {
	candidate, err := provider.candidate(value)
	if err != nil {
		return err
	}
	candidate.mu.Lock()
	if candidate.used {
		candidate.mu.Unlock()
		return fmt.Errorf("node transport candidate is already consumed")
	}
	candidate.used = true
	prepared := candidate.prepared
	candidate.prepared = nil
	candidate.mu.Unlock()

	if prepared != nil {
		err = provider.coordinator.replacer.Activate(ctx, prepared)
	} else {
		err = provider.coordinator.replacer.Replace(ctx, candidate.configuration)
	}
	if err != nil {
		return err
	}
	provider.coordinator.mu.Lock()
	provider.coordinator.selected = provider.kind
	provider.coordinator.mu.Unlock()
	return nil
}

func (provider *nodeTransportProvider) Health(
	ctx context.Context,
	request transport.HealthRequest,
) (transport.Health, error) {
	if ctx == nil || provider == nil || provider.coordinator == nil {
		return transport.Health{}, fmt.Errorf("node transport provider is incomplete")
	}
	if err := request.Identity.Validate(); err != nil {
		return transport.Health{}, fmt.Errorf("validate node transport health identity: %w", err)
	}
	if request.Identity != provider.coordinator.identity {
		return transport.Health{}, fmt.Errorf("node transport health identity differs from the coordinator")
	}
	provider.coordinator.mu.Lock()
	selected := provider.coordinator.selected
	bundle := provider.coordinator.bundles[provider.kind]
	provider.coordinator.mu.Unlock()
	role := transport.RuntimeStandby
	condition := transport.HealthHealthy
	code := "node-transport-standby-ready"
	if selected == provider.kind {
		role = transport.RuntimeActive
		code = "node-transport-active-ready"
		if err := provider.coordinator.readiness.Check(ctx, bundle.configuration); err != nil {
			condition = transport.HealthUnavailable
			code = "node-transport-active-unavailable"
		}
	}
	health := transport.Health{
		Identity: request.Identity, Kind: provider.kind, Role: role,
		Condition: condition, Code: code,
	}
	return health, health.Validate()
}

func (provider *nodeTransportProvider) Drain(_ context.Context, request transport.DrainRequest) error {
	if provider == nil || provider.coordinator == nil {
		return fmt.Errorf("node transport provider is incomplete")
	}
	if err := request.Validate(time.Now()); err != nil {
		return err
	}
	if request.Identity != provider.coordinator.identity {
		return fmt.Errorf("node transport drain identity differs from the coordinator")
	}
	provider.coordinator.mu.Lock()
	selected := provider.coordinator.selected
	provider.coordinator.mu.Unlock()
	if selected == provider.kind {
		return fmt.Errorf("selected node transport cannot be drained")
	}
	// Replacing routing and frpc already closes the old generation's local
	// sockets. There is no second node process to stop; the standard WireGuard
	// interface remains available as a deliberately unselected standby.
	return nil
}

func (provider *nodeTransportProvider) Rollback(_ context.Context, value transport.Candidate) error {
	candidate, err := provider.candidate(value)
	if err != nil {
		return err
	}
	candidate.mu.Lock()
	prepared := candidate.prepared
	candidate.prepared = nil
	candidate.used = true
	candidate.mu.Unlock()
	if prepared != nil {
		prepared.Destroy()
	}
	return nil
}

func (candidate *nodeTransportCandidate) Descriptor() transport.CandidateDescriptor {
	if candidate == nil {
		return transport.CandidateDescriptor{}
	}
	return candidate.descriptor
}

func (provider *nodeTransportProvider) candidate(value transport.Candidate) (*nodeTransportCandidate, error) {
	if provider == nil || provider.coordinator == nil {
		return nil, fmt.Errorf("node transport provider is incomplete")
	}
	candidate, ok := value.(*nodeTransportCandidate)
	if !ok || candidate == nil || candidate.coordinator != provider.coordinator || candidate.kind != provider.kind ||
		candidate.descriptor.Kind != provider.kind {
		return nil, fmt.Errorf("node transport candidate belongs to another provider")
	}
	return candidate, nil
}

var _ transport.Provider = (*nodeTransportProvider)(nil)
