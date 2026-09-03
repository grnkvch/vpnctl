package transport

import (
	"context"
	"fmt"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

type RestrictedGatewayHealthExpectation struct {
	Identity    Identity
	RuntimeRole RuntimeRole
}

type RestrictedGatewayHealthObserver struct {
	runner linuxplatform.ProbeRunner
}

func NewRestrictedGatewayHealthObserver(runner linuxplatform.ProbeRunner) (*RestrictedGatewayHealthObserver, error) {
	if runner == nil {
		return nil, fmt.Errorf("restricted health runner is required")
	}
	return &RestrictedGatewayHealthObserver{runner: runner}, nil
}

// Observe is passive: it reads systemd and kernel socket state, never dials a
// handshake host, starts a service, changes the selected role, or probes the
// standby transport.
func (observer *RestrictedGatewayHealthObserver) Observe(ctx context.Context, expected RestrictedGatewayHealthExpectation) (Health, error) {
	health := Health{Identity: expected.Identity, Kind: model.TransportRestricted, Role: expected.RuntimeRole}
	if ctx == nil {
		return Health{}, fmt.Errorf("context is required")
	}
	if observer == nil || observer.runner == nil {
		return Health{}, fmt.Errorf("restricted gateway health observer is incomplete")
	}
	if err := expected.Identity.Validate(); err != nil {
		return Health{}, err
	}
	if expected.RuntimeRole != RuntimeActive && expected.RuntimeRole != RuntimeStandby {
		return Health{}, fmt.Errorf("restricted runtime role must be active or standby")
	}
	active, err := observer.query(ctx, "systemctl", "is-active", "--quiet", "vpnctl-restricted.service")
	if err != nil {
		return Health{}, err
	}
	if !active.available {
		return restrictedHealthResult(health, HealthUnavailable, "restricted-service-unavailable")
	}
	udp, err := observer.query(ctx, "ss", "-H", "-lunp", "sport = :8443")
	if err != nil {
		return Health{}, err
	}
	if !udp.available {
		return restrictedHealthResult(health, HealthUnavailable, "restricted-socket-observation-unavailable")
	}
	if strings.TrimSpace(udp.output) != "" {
		return restrictedHealthResult(health, HealthUnavailable, "restricted-native-udp-listener-present")
	}
	tcp, err := observer.query(ctx, "ss", "-H", "-ltnp", "sport = :8443")
	if err != nil {
		return Health{}, err
	}
	if !tcp.available {
		return restrictedHealthResult(health, HealthUnavailable, "restricted-socket-observation-unavailable")
	}
	if strings.TrimSpace(tcp.output) == "" {
		return restrictedHealthResult(health, HealthUnavailable, "restricted-tcp-listener-missing")
	}
	if !validRestrictedTCPListener(tcp.output) {
		return restrictedHealthResult(health, HealthUnavailable, "restricted-tcp-listener-mismatch")
	}
	return restrictedHealthResult(health, HealthHealthy, "restricted-listener-healthy")
}

func validRestrictedTCPListener(output string) bool {
	line := strings.TrimSpace(output)
	if line == "" || strings.Count(line, "\n") != 0 || !strings.Contains(line, `(("mihomo",pid=`) {
		return false
	}
	for _, field := range strings.Fields(line) {
		if field == "*:8443" || field == "0.0.0.0:8443" {
			return true
		}
	}
	return false
}

type restrictedQueryResult struct {
	output    string
	available bool
}

func (observer *RestrictedGatewayHealthObserver) query(ctx context.Context, name string, arguments ...string) (restrictedQueryResult, error) {
	result, err := observer.runner.Run(ctx, linuxplatform.ProbeCommand{Name: name, Args: arguments})
	if err != nil {
		return restrictedQueryResult{}, fmt.Errorf("observe restricted transport: %w", err)
	}
	if result.ExitCode != 0 {
		return restrictedQueryResult{}, nil
	}
	return restrictedQueryResult{output: string(result.Stdout), available: true}, nil
}

func restrictedHealthResult(base Health, condition HealthCondition, code string) (Health, error) {
	base.Condition = condition
	base.Code = code
	return base, base.Validate()
}
