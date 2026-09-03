package transport

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestRestrictedGatewayHealthObservesTCPOnlyWithoutChangingRuntimeRole(t *testing.T) {
	t.Parallel()
	runner := &restrictedHealthRunner{results: map[string]linuxplatform.ProbeResult{
		"systemctl is-active --quiet vpnctl-restricted.service": {},
		"ss -H -lunp sport = :8443":                             {},
		"ss -H -ltnp sport = :8443":                             {Stdout: []byte(`LISTEN 0 4096 *:8443 *:* users:(("mihomo",pid=41,fd=7))` + "\n")},
	}}
	observer, err := NewRestrictedGatewayHealthObserver(runner)
	if err != nil {
		t.Fatal(err)
	}
	health, err := observer.Observe(context.Background(), RestrictedGatewayHealthExpectation{
		Identity:    Identity{OwnerKind: model.TargetNode, OwnerID: "20000000-0000-4000-8000-000000000001", CredentialGeneration: 1},
		RuntimeRole: RuntimeStandby,
	})
	if err != nil || health.Condition != HealthHealthy || health.Role != RuntimeStandby || health.Code != "restricted-listener-healthy" {
		t.Fatalf("Observe() = %#v, %v", health, err)
	}
	if got := strings.Join(runner.calls, " | "); got != "systemctl is-active --quiet vpnctl-restricted.service | ss -H -lunp sport = :8443 | ss -H -ltnp sport = :8443" {
		t.Fatalf("restricted health calls = %q", got)
	}
}

func TestRestrictedGatewayHealthFailsClosedOnUDPOrMissingTCP(t *testing.T) {
	t.Parallel()
	identity := Identity{OwnerKind: model.TargetClient, OwnerID: "30000000-0000-4000-8000-000000000001", CredentialGeneration: 1}
	for name, fixture := range map[string]struct {
		results map[string]linuxplatform.ProbeResult
		code    string
	}{
		"native udp": {
			results: map[string]linuxplatform.ProbeResult{
				"systemctl is-active --quiet vpnctl-restricted.service": {},
				"ss -H -lunp sport = :8443":                             {Stdout: []byte("UNCONN 0 0 0.0.0.0:8443 0.0.0.0:*\n")},
			},
			code: "restricted-native-udp-listener-present",
		},
		"missing tcp": {
			results: map[string]linuxplatform.ProbeResult{
				"systemctl is-active --quiet vpnctl-restricted.service": {},
				"ss -H -lunp sport = :8443":                             {},
				"ss -H -ltnp sport = :8443":                             {},
			},
			code: "restricted-tcp-listener-missing",
		},
		"inactive": {
			results: map[string]linuxplatform.ProbeResult{
				"systemctl is-active --quiet vpnctl-restricted.service": {ExitCode: 3},
			},
			code: "restricted-service-unavailable",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			observer, _ := NewRestrictedGatewayHealthObserver(&restrictedHealthRunner{results: fixture.results})
			health, err := observer.Observe(context.Background(), RestrictedGatewayHealthExpectation{Identity: identity, RuntimeRole: RuntimeActive})
			if err != nil || health.Condition != HealthUnavailable || health.Role != RuntimeActive || health.Code != fixture.code {
				t.Fatalf("Observe() = %#v, %v", health, err)
			}
		})
	}
}

type restrictedHealthRunner struct {
	results map[string]linuxplatform.ProbeResult
	calls   []string
}

func (runner *restrictedHealthRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	runner.calls = append(runner.calls, key)
	result, found := runner.results[key]
	if !found {
		return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected restricted health command %s", key)
	}
	return result, nil
}
