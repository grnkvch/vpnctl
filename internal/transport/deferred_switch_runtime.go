package transport

import (
	"bytes"
	"context"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

// DeferredNodeRuntime reuses the immediate make-before-break provider
// workflow without committing authoritative node state. The caller retains
// the activation handle until the gateway commit is known and can restore the
// previous production bundle if finalization is rejected.
type DeferredNodeRuntime struct {
	registry *Registry
	limits   SwitchLimits
}

type DeferredActivation interface {
	Result() (SwitchResult, error)
	Rollback(context.Context) error
}

type DeferredSwitchActivation struct {
	store    *ephemeralSwitchStore
	switcher *NodeSwitcher
	previous model.TransportKind
	result   SwitchResult
}

func NewDeferredNodeRuntime(registry *Registry, limits SwitchLimits) (*DeferredNodeRuntime, error) {
	if registry == nil {
		return nil, fmt.Errorf("deferred transport switch provider registry is required")
	}
	normalized, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	return &DeferredNodeRuntime{registry: registry, limits: normalized}, nil
}

func (runtime *DeferredNodeRuntime) Activate(
	ctx context.Context,
	current model.State,
	operation model.Operation,
) (DeferredActivation, error) {
	if ctx == nil || runtime == nil || runtime.registry == nil {
		return nil, fmt.Errorf("deferred transport switch runtime is incomplete")
	}
	desired, intent, err := DeferredSwitchDesiredState(current, operation)
	if err != nil {
		return nil, err
	}
	store := &ephemeralSwitchStore{state: current}
	switcher, err := NewNodeSwitcher(store, runtime.registry, runtime.limits)
	if err != nil {
		return nil, err
	}
	plan, err := switcher.Plan(intent.Target)
	if err != nil {
		return nil, err
	}
	planned, plannedErr := model.EncodeState(plan.candidate)
	wanted, wantedErr := model.EncodeState(desired)
	if plannedErr != nil || wantedErr != nil || !bytes.Equal(planned, wanted) {
		return nil, fmt.Errorf("%w: runtime candidate differs from published transport intent", ErrTransportSwitchStale)
	}
	result, err := switcher.Apply(ctx, plan)
	if err != nil {
		return nil, err
	}
	if !result.Changed || result.Previous != current.Nodes[0].ActiveTransport || result.Active != intent.Target ||
		result.StateGeneration != intent.DesiredNodeGeneration || result.ActiveHealth.Condition != HealthHealthy {
		return nil, fmt.Errorf("deferred transport switch runtime returned an invalid activation result")
	}
	return &DeferredSwitchActivation{
		store: store, switcher: switcher, previous: result.Previous, result: result,
	}, nil
}

func (activation *DeferredSwitchActivation) Result() (SwitchResult, error) {
	if activation == nil || activation.store == nil || activation.switcher == nil {
		return SwitchResult{}, fmt.Errorf("deferred transport switch activation is incomplete")
	}
	return activation.result, nil
}

// Rollback is idempotent and uses the same bounded make-before-break workflow
// in reverse. It changes provider runtime only; the ephemeral state is never
// written to the node's authoritative store.
func (activation *DeferredSwitchActivation) Rollback(ctx context.Context) error {
	if ctx == nil || activation == nil || activation.store == nil || activation.switcher == nil {
		return fmt.Errorf("deferred transport switch activation is incomplete")
	}
	plan, err := activation.switcher.Plan(activation.previous)
	if err != nil {
		return err
	}
	result, err := activation.switcher.Apply(ctx, plan)
	if err != nil {
		return err
	}
	if result.Active != activation.previous {
		return fmt.Errorf("deferred transport switch rollback did not restore the previous selection")
	}
	return nil
}

type ephemeralSwitchStore struct{ state model.State }

func (store *ephemeralSwitchStore) Load() (model.State, error) {
	if store == nil {
		return model.State{}, fmt.Errorf("ephemeral transport switch state is unavailable")
	}
	return store.state, nil
}

func (store *ephemeralSwitchStore) Save(expectedGeneration uint64, candidate model.State) error {
	if store == nil || store.state.Generation != expectedGeneration {
		return ErrTransportSwitchStale
	}
	if err := model.ValidateTransition(store.state, candidate); err != nil {
		return err
	}
	store.state = candidate
	return nil
}

var _ SwitchStateStore = (*ephemeralSwitchStore)(nil)
var _ DeferredActivation = (*DeferredSwitchActivation)(nil)
