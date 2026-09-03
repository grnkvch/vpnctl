package transport

import (
	"context"
	"fmt"
	"reflect"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

// Selection is the complete steady-state transport intent for one identity.
// It cannot represent multiple active transports or an implicit fallback.
type Selection struct {
	Active  model.TransportKind
	Standby model.TransportKind
}

func NewSelection(active model.TransportKind) (Selection, error) {
	if !isTransportKind(active) {
		return Selection{}, fmt.Errorf("unsupported active transport %q", active)
	}
	standby := model.TransportStandard
	if active == model.TransportStandard {
		standby = model.TransportRestricted
	}
	return Selection{Active: active, Standby: standby}, nil
}

func (selection Selection) Validate() error {
	if !isTransportKind(selection.Active) {
		return fmt.Errorf("unsupported active transport %q", selection.Active)
	}
	if !isTransportKind(selection.Standby) {
		return fmt.Errorf("unsupported standby transport %q", selection.Standby)
	}
	if selection.Active == selection.Standby {
		return fmt.Errorf("active and standby transport must differ")
	}
	return nil
}

// Registry requires exactly the standard and restricted providers. It does
// not choose between them and contains no fallback ordering.
type Registry struct {
	providers map[model.TransportKind]Provider
}

func NewRegistry(providers ...Provider) (*Registry, error) {
	registry := &Registry{providers: make(map[model.TransportKind]Provider, len(providers))}
	for index, provider := range providers {
		if nilProvider(provider) {
			return nil, fmt.Errorf("transport provider %d is nil", index)
		}
		kind := provider.Kind()
		if !isTransportKind(kind) {
			return nil, fmt.Errorf("transport provider %d has unsupported kind %q", index, kind)
		}
		if _, duplicate := registry.providers[kind]; duplicate {
			return nil, fmt.Errorf("duplicate %s transport provider", kind)
		}
		registry.providers[kind] = provider
	}
	for _, kind := range []model.TransportKind{model.TransportStandard, model.TransportRestricted} {
		if _, found := registry.providers[kind]; !found {
			return nil, fmt.Errorf("%s transport provider is required", kind)
		}
	}
	return registry, nil
}

func (registry *Registry) Provider(kind model.TransportKind) (Provider, error) {
	if registry == nil {
		return nil, fmt.Errorf("transport provider registry is nil")
	}
	provider, found := registry.providers[kind]
	if !found {
		return nil, fmt.Errorf("transport provider %q is not registered", kind)
	}
	return provider, nil
}

type Manager struct {
	identity  Identity
	selection Selection
	registry  *Registry
}

func NewManager(identity Identity, selection Selection, registry *Registry) (*Manager, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	if err := selection.Validate(); err != nil {
		return nil, err
	}
	if registry == nil {
		return nil, fmt.Errorf("transport provider registry is required")
	}
	return &Manager{identity: identity, selection: selection, registry: registry}, nil
}

func (manager *Manager) Selection() Selection {
	if manager == nil {
		return Selection{}
	}
	return manager.selection
}

// ObserveActive deliberately asks only the explicitly selected provider. A
// failed or degraded observation is returned without probing or activating the
// standby provider and without changing selection.
func (manager *Manager) ObserveActive(ctx context.Context) (Health, error) {
	if ctx == nil {
		return Health{}, fmt.Errorf("context is required")
	}
	if manager == nil || manager.registry == nil {
		return Health{}, fmt.Errorf("transport manager is incomplete")
	}
	provider, err := manager.registry.Provider(manager.selection.Active)
	if err != nil {
		return Health{}, err
	}
	health, err := provider.Health(ctx, HealthRequest{Identity: manager.identity})
	if err != nil {
		return Health{}, fmt.Errorf("observe active %s transport: %w", manager.selection.Active, err)
	}
	if err := manager.validateHealth(health, manager.selection.Active, RuntimeActive); err != nil {
		return Health{}, fmt.Errorf("observe active %s transport: %w", manager.selection.Active, err)
	}
	return health, nil
}

// CheckSteadyState verifies the configured pair but never repairs it. In
// particular, observing reversed roles is an error rather than an instruction
// to adopt the provider that happens to report active.
func (manager *Manager) CheckSteadyState(ctx context.Context) ([2]Health, error) {
	var observations [2]Health
	if ctx == nil {
		return observations, fmt.Errorf("context is required")
	}
	if manager == nil || manager.registry == nil {
		return observations, fmt.Errorf("transport manager is incomplete")
	}
	wanted := []struct {
		kind model.TransportKind
		role RuntimeRole
	}{
		{kind: manager.selection.Active, role: RuntimeActive},
		{kind: manager.selection.Standby, role: RuntimeStandby},
	}
	for index, expected := range wanted {
		provider, err := manager.registry.Provider(expected.kind)
		if err != nil {
			return observations, err
		}
		observations[index], err = provider.Health(ctx, HealthRequest{Identity: manager.identity})
		if err != nil {
			return observations, fmt.Errorf("observe %s transport steady state: %w", expected.kind, err)
		}
		if err := manager.validateHealth(observations[index], expected.kind, expected.role); err != nil {
			return observations, fmt.Errorf("observe %s transport steady state: %w", expected.kind, err)
		}
	}
	return observations, nil
}

func (manager *Manager) validateHealth(health Health, kind model.TransportKind, role RuntimeRole) error {
	if err := health.Validate(); err != nil {
		return err
	}
	if health.Identity != manager.identity {
		return fmt.Errorf("provider returned health for a different transport identity")
	}
	if health.Kind != kind {
		return fmt.Errorf("provider returned %s health for %s transport", health.Kind, kind)
	}
	if health.Role != role {
		return fmt.Errorf("%s transport reports %s role, expected %s", kind, health.Role, role)
	}
	return nil
}

func nilProvider(provider Provider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
