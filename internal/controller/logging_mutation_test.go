package controller

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
)

func TestGatewayLoggingDispatcherCommitsUnderControllerWriter(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	now := time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC)
	dispatcher, err := NewGatewayLoggingMutationDispatcher(paths, func() time.Time { return now }, func() (string, error) {
		return "dddddddd-dddd-4ddd-8ddd-dddddddddddd", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: &recordingObserver{}, Dispatcher: dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	before, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	response := server.mutateResponse(control.LocalRequest{
		SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate, Operation: "log.enable", ExpectedGeneration: before.Generation,
		Payload: json.RawMessage(`{"scope":"routing","level":"debug","duration_seconds":900,"file":false}`),
	})
	if !response.OK || response.Generation != before.Generation+1 {
		t.Fatalf("logging mutation response = %+v", response)
	}
	after, err := stateStore.Load()
	if err != nil || len(after.Logging) != 1 || after.Logging[0].Scope != model.LogRouting || after.Logging[0].ExpiresAt != now.Add(15*time.Minute) {
		t.Fatalf("authoritative logging after mutation = %+v, %v", after.Logging, err)
	}
	var change operations.LoggingChange
	if err := json.Unmarshal(response.Data, &change); err != nil || change.Enabled == nil || change.Enabled.ID != after.Logging[0].ID {
		t.Fatalf("logging response data = %+v, %v", change, err)
	}

	disable := server.mutateResponse(control.LocalRequest{
		SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate, Operation: "log.disable", ExpectedGeneration: after.Generation,
		Payload: json.RawMessage(`{"scope":"routing"}`),
	})
	if !disable.OK || disable.Generation != after.Generation+1 {
		t.Fatalf("logging disable response = %+v", disable)
	}
	disabled, err := stateStore.Load()
	if err != nil || disabled.Logging[0].State != model.LogDisabled {
		t.Fatalf("disabled logging state = %+v, %v", disabled.Logging, err)
	}
}

func TestGatewayLoggingDispatcherRejectsUnknownAndAmbiguousPayloads(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	dispatcher, err := NewGatewayLoggingMutationDispatcher(paths, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		operation string
		payload   string
	}{
		{operation: "log.rotate", payload: `{"scope":"dns"}`},
		{operation: "log.enable", payload: `{"scope":"dns","level":"debug","duration_seconds":60,"file":false,"remote":true}`},
		{operation: "log.disable", payload: `{"scope":"dns"} {}`},
	} {
		if _, err := dispatcher.Prepare(context.Background(), state, test.operation, json.RawMessage(test.payload)); err == nil {
			t.Fatalf("Prepare(%s, %s) accepted invalid request", test.operation, test.payload)
		}
	}
}

func TestGatewayMutationDispatcherRoutesOnlyClosedFamilies(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	dns, _ := NewGatewayDNSMutationDispatcher(paths, &gatewayDNSControllerRunner{})
	logging, _ := NewGatewayLoggingMutationDispatcher(paths, nil, nil)
	router, err := NewGatewayMutationDispatcher(dns, logging)
	if err != nil {
		t.Fatal(err)
	}
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.DNS = &model.DNSUpstreamState{SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamGateway, IPv4: model.DefaultGatewayDNSUpstreams()}
	if _, err := router.Prepare(context.Background(), state, "log.disable", json.RawMessage(`{"scope":"all"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := router.Prepare(context.Background(), state, "policy.set", json.RawMessage(`{}`)); err == nil {
		t.Fatal("gateway mutation router accepted unknown family")
	}
	if !reflect.DeepEqual(state.Logging, []model.LoggingSession{}) {
		t.Fatal("dispatcher planning mutated caller state")
	}
}
