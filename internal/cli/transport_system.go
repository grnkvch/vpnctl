package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

var ErrSystemTransportRuntimeUnavailable = errors.New("system transport runtime adapter is unavailable")

func buildSystemTransportTester(paths store.Paths) (transportTester, error) {
	state, registry, err := buildSystemTransportPlanningRuntime(paths)
	if err != nil {
		return nil, err
	}
	return transport.NewNodeTester(state, registry, transport.TestLimits{})
}

func buildSystemTransportSwitcher(paths store.Paths) (TransportSwitcher, error) {
	state, registry, err := buildSystemTransportPlanningRuntime(paths)
	if err != nil {
		return nil, err
	}
	return transport.NewNodeSwitcher(state, registry, transport.SwitchLimits{})
}

func buildSystemTransportPlanningRuntime(paths store.Paths) (*store.StateStore, *transport.Registry, error) {
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, nil, err
	}
	registry, err := transport.NewRegistry(
		systemUnavailableTransportProvider{kind: model.TransportStandard},
		systemUnavailableTransportProvider{kind: model.TransportRestricted},
	)
	if err != nil {
		return nil, nil, err
	}
	return state, registry, nil
}

func buildSystemTransportDeferredWriter(store.Paths) (AuthoritativeDeferredWriter, error) {
	return systemUnavailableTransportDeferredWriter{}, nil
}

type systemUnavailableTransportDeferredWriter struct{}

func (systemUnavailableTransportDeferredWriter) RegisterPending(context.Context, MutationPlan) (DeferredReceipt, error) {
	return DeferredReceipt{}, ErrSystemTransportRuntimeUnavailable
}

type systemUnavailableTransportProvider struct{ kind model.TransportKind }

func (provider systemUnavailableTransportProvider) Kind() model.TransportKind { return provider.kind }

func (systemUnavailableTransportProvider) Render(context.Context, transport.RenderRequest) (transport.Candidate, error) {
	return nil, ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) Prepare(context.Context, transport.Candidate) error {
	return ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) Validate(context.Context, transport.Candidate) error {
	return ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) StartTest(context.Context, transport.Candidate) (transport.TestResult, error) {
	return transport.TestResult{}, ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) Activate(context.Context, transport.Candidate) error {
	return ErrSystemTransportRuntimeUnavailable
}

func (provider systemUnavailableTransportProvider) Health(_ context.Context, request transport.HealthRequest) (transport.Health, error) {
	if err := request.Identity.Validate(); err != nil {
		return transport.Health{}, fmt.Errorf("transport health identity: %w", err)
	}
	return transport.Health{}, ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) Drain(context.Context, transport.DrainRequest) error {
	return ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) Rollback(context.Context, transport.Candidate) error {
	return ErrSystemTransportRuntimeUnavailable
}

var _ transport.Provider = systemUnavailableTransportProvider{}
var _ AuthoritativeDeferredWriter = systemUnavailableTransportDeferredWriter{}
