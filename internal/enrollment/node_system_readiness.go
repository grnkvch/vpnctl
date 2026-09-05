package enrollment

import (
	"context"
	"fmt"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

type SystemNodeConfigurationReadiness struct {
	routing *routing.NodeRoutingReadinessGate
	tunnel  *tunnel.FRPClientConnectionProber
}

func NewSystemNodeConfigurationReadiness(paths store.Paths, runner linuxplatform.ProbeRunner) (*SystemNodeConfigurationReadiness, error) {
	if runner == nil {
		return nil, fmt.Errorf("system node readiness runner is required")
	}
	routingProber, err := routing.NewNodeRoutingSystemReadinessProber(paths, runner)
	if err != nil {
		return nil, err
	}
	routingGate, err := routing.NewNodeRoutingReadinessGate(routingProber)
	if err != nil {
		return nil, err
	}
	tunnelProber, err := tunnel.NewFRPClientConnectionProber(runner)
	if err != nil {
		return nil, err
	}
	return &SystemNodeConfigurationReadiness{routing: routingGate, tunnel: tunnelProber}, nil
}

func (readiness *SystemNodeConfigurationReadiness) Check(ctx context.Context, configuration NodeConfiguration) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if readiness == nil || readiness.routing == nil || readiness.tunnel == nil {
		return fmt.Errorf("system node configuration readiness is incomplete")
	}
	if _, _, err := readiness.routing.Check(ctx, configuration.RoutingCandidate()); err != nil {
		return err
	}
	return readiness.tunnel.Probe(ctx, configuration.TunnelCandidate())
}

var _ NodeConfigurationReadinessChecker = (*SystemNodeConfigurationReadiness)(nil)
