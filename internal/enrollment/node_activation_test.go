package enrollment

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

func TestNodeConfigurationActivatorPublishesThenStartsInFailClosedOrder(t *testing.T) {
	configuration := compiledNodeActivationFixture(t)
	installer := &nodeActivationInstaller{}
	runner := &nodeActivationRunner{}
	readiness := &nodeActivationReadiness{}
	activator, err := NewNodeConfigurationActivator("/usr/local/bin/vpnctl", installer, runner, readiness)
	if err != nil {
		t.Fatal(err)
	}
	if err := activator.Activate(context.Background(), configuration); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if installer.calls != 1 || installer.request.Role != model.RoleNode || len(installer.request.Configs) != len(configuration.ConfigFiles())+1 {
		t.Fatalf("published request = %+v", installer.request)
	}
	for _, unit := range installer.request.Units {
		if !unit.Enable || unit.Start {
			t.Fatalf("unit activation flags = %+v", unit)
		}
	}
	wantCommands := []string{}
	for _, unit := range nodeActivationOrder {
		wantCommands = append(wantCommands, "start "+unit, "is-active --quiet "+unit)
	}
	if !reflect.DeepEqual(runner.calls, wantCommands) {
		t.Fatalf("systemctl calls = %v, want %v", runner.calls, wantCommands)
	}
	if readiness.calls != 1 || readiness.generation != configuration.StateGeneration() {
		t.Fatalf("readiness calls=%d generation=%d", readiness.calls, readiness.generation)
	}
}

func TestNodeConfigurationActivatorRetainsGuardAfterLaterFailure(t *testing.T) {
	configuration := compiledNodeActivationFixture(t)
	runner := &nodeActivationRunner{fail: "start vpnctl-routing.service"}
	activator, err := NewNodeConfigurationActivator(
		"/usr/local/bin/vpnctl", &nodeActivationInstaller{}, runner, &nodeActivationReadiness{},
	)
	if err != nil {
		t.Fatal(err)
	}
	err = activator.Activate(context.Background(), configuration)
	if !errors.Is(err, ErrNodeActivationPending) {
		t.Fatalf("Activate() error = %v", err)
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "start vpnctl-routing-guard.service") || strings.Contains(joined, "start vpnctl-tunnel-client.service") ||
		strings.Contains(joined, "stop ") || strings.Contains(joined, "disable ") {
		t.Fatalf("failure compensation reopened or advanced boundary: %s", joined)
	}
}

func compiledNodeActivationFixture(t *testing.T) NodeConfiguration {
	return compiledNodeActivationFixtureFor(t, model.TransportRestricted)
}

func compiledNodeActivationFixtureFor(t *testing.T, active model.TransportKind) NodeConfiguration {
	t.Helper()
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	t.Cleanup(fixture.destroy)
	presets := []string{}
	if active == model.TransportRestricted {
		presets = []string{"telegram"}
	}
	if _, err := fixture.workflow.Join(context.Background(), fixture.token, active, presets); err != nil {
		t.Fatal(err)
	}
	state, err := fixture.nodeState.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.DNS = &model.DNSUpstreamState{SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamDirect, IPv4: []string{"192.0.2.53"}}
	state.Components.Components = append(state.Components.Components, nodeConfigurationFRPPin())
	compiler, err := NewNodeConfigurationCompiler(t.TempDir(), fixture.nodeSecrets, NodeConfigurationRuntime{
		WireGuardRunner: &joinWireGuardRunner{}, Now: func() time.Time { return fixture.now.Add(time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := compiler.Compile(context.Background(), state, linuxplatform.HostSnapshot{Routes: []linuxplatform.Route{{
		Family: "ipv4", Destination: "default", Gateway: "192.0.2.1", Device: "ens3", Table: "main",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return configuration
}

type nodeActivationInstaller struct {
	calls   int
	request linuxplatform.RoleInstallationRequest
}

func (installer *nodeActivationInstaller) Apply(_ context.Context, request linuxplatform.RoleInstallationRequest) (linuxplatform.RoleInstallationResult, error) {
	installer.calls++
	installer.request = request
	return linuxplatform.RoleInstallationResult{}, nil
}

type nodeActivationRunner struct {
	calls []string
	fail  string
}

func (runner *nodeActivationRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	joined := strings.Join(command.Args, " ")
	runner.calls = append(runner.calls, joined)
	if joined == runner.fail {
		return linuxplatform.ProbeResult{ExitCode: 1}, nil
	}
	return linuxplatform.ProbeResult{}, nil
}

type nodeActivationReadiness struct {
	calls      int
	generation uint64
}

func (readiness *nodeActivationReadiness) Check(_ context.Context, configuration NodeConfiguration) error {
	readiness.calls++
	readiness.generation = configuration.StateGeneration()
	if configuration.TunnelCandidate().Descriptor().Provider != tunnel.FRPProviderName {
		return errors.New("unexpected tunnel provider")
	}
	return nil
}
