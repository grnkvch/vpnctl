package controller

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
)

func TestGatewayDNSDispatcherCommitsStateAndSharedForwarderTogether(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.Generation++
	state.DNS = &model.DNSUpstreamState{
		SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamGateway, IPv4: model.DefaultGatewayDNSUpstreams(),
	}
	if err := stateStore.Save(1, state); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(paths.ConfigDir, "generated", "gateway")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	current, err := routing.RenderGatewayDNSConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, routing.GatewayDNSConfigFileName)
	if err := os.WriteFile(configPath, current.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &gatewayDNSControllerRunner{}
	dispatcher, err := NewGatewayDNSMutationDispatcher(paths, runner)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: &recordingObserver{}, Dispatcher: dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	response := server.mutateResponse(control.LocalRequest{
		SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate, Operation: "dns.set", ExpectedGeneration: state.Generation,
		Payload: json.RawMessage(`{"ipv4":["9.9.9.9"]}`),
	})
	if !response.OK || response.Generation != state.Generation+1 {
		t.Fatalf("DNS mutation response = %+v", response)
	}
	after, err := stateStore.Load()
	if err != nil || !reflect.DeepEqual(after.DNS.IPv4, []string{"9.9.9.9"}) {
		t.Fatalf("authoritative DNS after mutation = %+v, %v", after.DNS, err)
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	config, err := routing.DecodeGatewayDNSConfig(content)
	if err != nil || config.Generation != after.Generation || !reflect.DeepEqual(config.UpstreamIPv4, after.DNS.IPv4) {
		t.Fatalf("shared forwarder config = %+v, %v", config, err)
	}
	if !reflect.DeepEqual(runner.calls, []string{"systemctl restart vpnctl-dns.service"}) {
		t.Fatalf("runtime calls = %v", runner.calls)
	}

	idempotent := server.mutateResponse(control.LocalRequest{
		SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate, Operation: "dns.set", ExpectedGeneration: after.Generation,
		Payload: json.RawMessage(`{"ipv4":["9.9.9.9"]}`),
	})
	if !idempotent.OK || idempotent.Generation != after.Generation || len(runner.calls) != 1 {
		t.Fatalf("idempotent DNS mutation = %+v calls=%v", idempotent, runner.calls)
	}
}

func TestGatewayDNSDispatcherRejectsOtherScopesAndAmbiguousPayloads(t *testing.T) {
	paths, _ := controllerTestState(t, model.RoleGateway)
	dispatcher, err := NewGatewayDNSMutationDispatcher(paths, &gatewayDNSControllerRunner{})
	if err != nil {
		t.Fatal(err)
	}
	state := model.State{Host: model.Host{Role: model.RoleNode}}
	for _, test := range []struct {
		operation string
		payload   string
	}{
		{operation: "policy.set", payload: `{"ipv4":["9.9.9.9"]}`},
		{operation: "dns.set", payload: `{"ipv4":["9.9.9.9"],"fallback":true}`},
		{operation: "dns.set", payload: `{"ipv4":["9.9.9.9"]} {}`},
	} {
		if _, err := dispatcher.Prepare(context.Background(), state, test.operation, json.RawMessage(test.payload)); err == nil {
			t.Fatalf("Prepare(%s, %s) accepted invalid request", test.operation, test.payload)
		}
	}
}

type gatewayDNSControllerRunner struct{ calls []string }

func (runner *gatewayDNSControllerRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	runner.calls = append(runner.calls, command.Name+" "+strings.Join(command.Args, " "))
	return linuxplatform.ProbeResult{}, nil
}
