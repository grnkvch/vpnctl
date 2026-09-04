package operations

import (
	"context"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

// FRPClientConfigurationApplier is the narrow transaction surface supplied by
// tunnel.FRPClientConfigurationManager. Keeping it as an interface makes the
// saga order testable without invoking a provider process.
type FRPClientConfigurationApplier interface {
	Apply(context.Context, tunnel.RenderRequest) (tunnel.FRPClientConfigurationResult, error)
}

// FRPExposeNodeTunnel adapts the production frpc renderer/configuration manager
// and provider-neutral readiness prober to the expose saga. Rollback reapplies
// the complete pre-expose topology, never an incremental provider directive.
type FRPExposeNodeTunnel struct {
	provider *tunnel.FRPProvider
	config   FRPClientConfigurationApplier
	prober   tunnel.TunnelReadinessProber
}

func NewFRPExposeNodeTunnel(
	provider *tunnel.FRPProvider,
	config FRPClientConfigurationApplier,
	prober tunnel.TunnelReadinessProber,
) (*FRPExposeNodeTunnel, error) {
	if provider == nil || config == nil || prober == nil {
		return nil, fmt.Errorf("frp expose tunnel dependencies are incomplete")
	}
	return &FRPExposeNodeTunnel{provider: provider, config: config, prober: prober}, nil
}

func (runtime *FRPExposeNodeTunnel) Activate(
	ctx context.Context,
	before model.State,
	pending model.State,
	expose model.Expose,
) (ExposeTunnelActivation, error) {
	if ctx == nil || runtime == nil || runtime.provider == nil || runtime.config == nil || runtime.prober == nil {
		return ExposeTunnelActivation{}, fmt.Errorf("frp expose tunnel is incomplete")
	}
	if err := before.Validate(); err != nil {
		return ExposeTunnelActivation{}, fmt.Errorf("validate prior tunnel state: %w", err)
	}
	if err := model.ValidateTransition(before, pending); err != nil {
		return ExposeTunnelActivation{}, fmt.Errorf("validate pending tunnel state: %w", err)
	}
	if expose.Validate() != nil || !containsExpose(pending.Exposes, expose.ID) || containsExpose(before.Exposes, expose.ID) {
		return ExposeTunnelActivation{}, fmt.Errorf("pending tunnel state does not add the requested expose")
	}
	plan, err := tunnel.PlanFromState(pending)
	if err != nil {
		return ExposeTunnelActivation{}, err
	}
	request := tunnel.RenderRequest{Plan: plan}
	candidate, err := runtime.provider.Render(ctx, request)
	if err != nil {
		return ExposeTunnelActivation{}, fmt.Errorf("render expose tunnel candidate: %w", err)
	}
	frpCandidate, ok := candidate.(tunnel.FRPCandidate)
	if !ok {
		return ExposeTunnelActivation{}, fmt.Errorf("expose tunnel provider returned an incompatible candidate")
	}
	if err := runtime.provider.Validate(ctx, frpCandidate); err != nil {
		return ExposeTunnelActivation{}, fmt.Errorf("validate expose tunnel candidate: %w", err)
	}
	applied, err := runtime.config.Apply(ctx, request)
	if err != nil {
		return ExposeTunnelActivation{}, err
	}
	if applied.ConfigHash != frpCandidate.Descriptor().ConfigHash || applied.MappingCount != exposeMappingCount(plan) {
		return ExposeTunnelActivation{}, fmt.Errorf("activated frp candidate differs from the requested topology")
	}
	rollback, err := cloneExposeState(before)
	if err != nil {
		return ExposeTunnelActivation{}, err
	}
	retained := frpCandidate
	return ExposeTunnelActivation{
		ExposeID: expose.ID, Candidate: frpCandidate.Descriptor(),
		frpCandidate: &retained, rollbackState: &rollback,
	}, nil
}

func (runtime *FRPExposeNodeTunnel) Observe(
	ctx context.Context,
	activation ExposeTunnelActivation,
	expose model.Expose,
) (tunnel.TunnelReadinessResult, error) {
	if ctx == nil || runtime == nil || runtime.prober == nil || activation.frpCandidate == nil ||
		activation.ExposeID != expose.ID || activation.Candidate != activation.frpCandidate.Descriptor() {
		return tunnel.TunnelReadinessResult{}, fmt.Errorf("frp expose activation is invalid")
	}
	result, err := runtime.prober.Probe(ctx, *activation.frpCandidate)
	if err != nil {
		return tunnel.TunnelReadinessResult{}, err
	}
	if result.Candidate != activation.Candidate {
		return tunnel.TunnelReadinessResult{}, fmt.Errorf("frp readiness belongs to another candidate")
	}
	return result, nil
}

func (runtime *FRPExposeNodeTunnel) Rollback(ctx context.Context, activation ExposeTunnelActivation) error {
	if ctx == nil || runtime == nil || runtime.config == nil || activation.rollbackState == nil {
		return fmt.Errorf("frp expose rollback input is invalid")
	}
	plan, err := tunnel.PlanFromState(*activation.rollbackState)
	if err != nil {
		return err
	}
	_, err = runtime.config.Apply(ctx, tunnel.RenderRequest{Plan: plan})
	if err != nil {
		return fmt.Errorf("restore prior frp topology: %w", err)
	}
	return nil
}

func exposeMappingCount(plan tunnel.Plan) int {
	count := 0
	for _, node := range plan.Nodes {
		count += len(node.Mappings)
	}
	return count
}

var _ ExposeNodeTunnel = (*FRPExposeNodeTunnel)(nil)
