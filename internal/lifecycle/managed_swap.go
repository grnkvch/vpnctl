package lifecycle

import (
	"context"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

type ManagedSwapLifecycleState interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

type ManagedSwapLifecyclePlatform interface {
	Status(context.Context, *model.ManagedSwap) (linuxplatform.ManagedSwapStatus, error)
	Deactivate(context.Context, model.ManagedSwap, bool) error
}

type ManagedSwapLifecycle struct {
	state    ManagedSwapLifecycleState
	platform ManagedSwapLifecyclePlatform
}

type ManagedSwapLifecycleResult struct {
	Changed    bool
	Generation uint64
	Status     linuxplatform.ManagedSwapStatus
}

func NewManagedSwapLifecycle(state ManagedSwapLifecycleState, platform ManagedSwapLifecyclePlatform) (*ManagedSwapLifecycle, error) {
	if state == nil || platform == nil {
		return nil, fmt.Errorf("managed swap lifecycle dependencies are incomplete")
	}
	return &ManagedSwapLifecycle{state: state, platform: platform}, nil
}

func (lifecycle *ManagedSwapLifecycle) Status(ctx context.Context) (linuxplatform.ManagedSwapStatus, error) {
	if ctx == nil {
		return linuxplatform.ManagedSwapStatus{}, fmt.Errorf("context is required")
	}
	state, err := lifecycle.state.Load()
	if err != nil {
		return linuxplatform.ManagedSwapStatus{}, fmt.Errorf("load managed swap state: %w", err)
	}
	return lifecycle.platform.Status(ctx, state.Host.ManagedSwap)
}

// Uninstall disables activation while preserving both the allocation file and
// a disabled ownership record in durable state for a recoverable reinstall.
func (lifecycle *ManagedSwapLifecycle) Uninstall(ctx context.Context) (ManagedSwapLifecycleResult, error) {
	if ctx == nil {
		return ManagedSwapLifecycleResult{}, fmt.Errorf("context is required")
	}
	state, err := lifecycle.state.Load()
	if err != nil {
		return ManagedSwapLifecycleResult{}, fmt.Errorf("load managed swap state: %w", err)
	}
	if state.Host.ManagedSwap == nil {
		status, err := lifecycle.platform.Status(ctx, nil)
		return ManagedSwapLifecycleResult{Generation: state.Generation, Status: status}, err
	}
	owned := *state.Host.ManagedSwap
	if err := lifecycle.platform.Deactivate(ctx, owned, false); err != nil {
		return ManagedSwapLifecycleResult{}, fmt.Errorf("deactivate managed swap for uninstall: %w", err)
	}
	changed := owned.Enabled
	if changed {
		next, err := model.NextGeneration(state.Generation)
		if err != nil {
			return ManagedSwapLifecycleResult{}, err
		}
		candidate := state
		candidate.Generation = next
		owned.Enabled = false
		candidate.Host.ManagedSwap = &owned
		if err := lifecycle.state.Save(state.Generation, candidate); err != nil {
			return ManagedSwapLifecycleResult{}, fmt.Errorf("persist disabled managed swap ownership: %w", err)
		}
		state = candidate
	}
	status, err := lifecycle.platform.Status(ctx, state.Host.ManagedSwap)
	if err != nil {
		return ManagedSwapLifecycleResult{}, err
	}
	return ManagedSwapLifecycleResult{Changed: changed, Generation: state.Generation, Status: status}, nil
}

// Purge removes only the owned swap runtime and allocation. The outer purge
// transaction removes authoritative state, so this method deliberately does
// not activate a new state generation that points at a deleted file.
func (lifecycle *ManagedSwapLifecycle) Purge(ctx context.Context) (ManagedSwapLifecycleResult, error) {
	if ctx == nil {
		return ManagedSwapLifecycleResult{}, fmt.Errorf("context is required")
	}
	state, err := lifecycle.state.Load()
	if err != nil {
		return ManagedSwapLifecycleResult{}, fmt.Errorf("load managed swap state: %w", err)
	}
	if state.Host.ManagedSwap == nil {
		return ManagedSwapLifecycleResult{Generation: state.Generation}, nil
	}
	if err := lifecycle.platform.Deactivate(ctx, *state.Host.ManagedSwap, true); err != nil {
		return ManagedSwapLifecycleResult{}, fmt.Errorf("purge managed swap: %w", err)
	}
	return ManagedSwapLifecycleResult{Changed: true, Generation: state.Generation}, nil
}
