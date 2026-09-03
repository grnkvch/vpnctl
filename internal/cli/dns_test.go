package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestDNSGrammarShowSetResetAndValidation(t *testing.T) {
	tests := []struct {
		args      []string
		action    string
		ipv4      []string
		dryRun    bool
		jsonMode  bool
		wantError bool
	}{
		{args: []string{"dns", "show"}, action: "show"},
		{args: []string{"--json", "dns", "set", "1.1.1.1", "8.8.8.8", "--dry-run"}, action: "set", ipv4: []string{"1.1.1.1", "8.8.8.8"}, dryRun: true, jsonMode: true},
		{args: []string{"dns", "reset", "--json"}, action: "reset", jsonMode: true},
		{args: []string{"dns", "set"}, wantError: true},
		{args: []string{"dns", "show", "--dry-run"}, wantError: true},
		{args: []string{"dns", "reset", "1.1.1.1"}, wantError: true},
		{args: []string{"dns", "automatic"}, wantError: true},
	}
	for _, test := range tests {
		parsed, err := parseDNSArguments(test.args)
		if (err != nil) != test.wantError {
			t.Fatalf("parseDNSArguments(%v) error = %v", test.args, err)
		}
		if err == nil && (parsed.Action != test.action || !reflect.DeepEqual(parsed.IPv4, test.ipv4) || parsed.DryRun != test.dryRun || parsed.JSON != test.jsonMode) {
			t.Fatalf("parseDNSArguments(%v) = %+v", test.args, parsed)
		}
	}
}

func TestExecuteDNSShowAndGatewaySetUseRoleOwnedControllerMutation(t *testing.T) {
	paths, _ := store.NewPaths(t.TempDir())
	state := cliDNSState(model.RoleGateway)
	fakeStore := &cliDNSStore{state: state}
	restore := stubDNSCommand(t, paths, RoleGateway, fakeStore)
	defer restore()
	var calls int
	dnsCallGateway = func(_ context.Context, socket string, request control.LocalRequest) (control.LocalResponse, error) {
		calls++
		if socket != paths.ControlSocket || request.Method != control.LocalMutate || request.Operation != "dns.set" || request.ExpectedGeneration != state.Generation {
			t.Fatalf("gateway DNS request = %+v socket=%s", request, socket)
		}
		var payload struct {
			IPv4 []string `json:"ipv4"`
		}
		if err := json.Unmarshal(request.Payload, &payload); err != nil || !reflect.DeepEqual(payload.IPv4, []string{"9.9.9.9"}) {
			t.Fatalf("gateway DNS payload = %+v, %v", payload, err)
		}
		return control.LocalResponse{SchemaVersion: control.LocalSchemaVersion, OK: true, Generation: state.Generation + 1, Data: json.RawMessage(`{}`)}, nil
	}

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"dns", "show", "--json"}, &stdout, &stderr); code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("dns show code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var shown output.Result
	if err := json.Unmarshal(stdout.Bytes(), &shown); err != nil || shown.Command != "dns.show" || shown.Data["scope"] != "gateway" {
		t.Fatalf("dns show result = %+v, %v", shown, err)
	}
	stdout.Reset()
	if code := Execute([]string{"dns", "set", "9.9.9.9", "--json"}, &stdout, &stderr); code != ExitSuccess || calls != 1 {
		t.Fatalf("dns set code=%d calls=%d stdout=%q stderr=%q", code, calls, stdout.String(), stderr.String())
	}
	var set output.Result
	if err := json.Unmarshal(stdout.Bytes(), &set); err != nil || set.Command != "dns.set" || set.Data["changed"] != true || set.Data["generation"] != float64(state.Generation+1) {
		t.Fatalf("dns set result = %+v, %v", set, err)
	}
}

func TestExecuteDNSDryRunAndNodeResetAreReadOnlyThenAtomic(t *testing.T) {
	paths, _ := store.NewPaths(t.TempDir())
	state := cliDNSState(model.RoleNode)
	fakeStore := &cliDNSStore{state: state}
	restore := stubDNSCommand(t, paths, RoleNode, fakeStore)
	defer restore()
	discoverCalls := 0
	dnsDiscover = func(root string) ([]string, error) {
		discoverCalls++
		if root != paths.Root {
			t.Fatalf("discovery root = %s", root)
		}
		return []string{"198.51.100.53"}, nil
	}
	dnsCallGateway = func(context.Context, string, control.LocalRequest) (control.LocalResponse, error) {
		t.Fatal("node DNS command contacted gateway controller")
		return control.LocalResponse{}, errors.New("unexpected")
	}

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"dns", "reset", "--dry-run", "--json"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("dry-run code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if fakeStore.saves != 0 || state.Generation != fakeStore.state.Generation || discoverCalls != 1 {
		t.Fatalf("dry-run saves/generation/discovery = %d/%d/%d", fakeStore.saves, fakeStore.state.Generation, discoverCalls)
	}
	stdout.Reset()
	if code := Execute([]string{"dns", "reset", "--json"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("reset code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if fakeStore.saves != 1 || fakeStore.state.Generation != state.Generation+1 || !reflect.DeepEqual(fakeStore.state.DNS.IPv4, []string{"198.51.100.53"}) {
		t.Fatalf("node reset state = %+v saves=%d", fakeStore.state.DNS, fakeStore.saves)
	}
}

func TestExecuteGatewayDNSResetUsesOnlyFrozenGatewayDefaults(t *testing.T) {
	paths, _ := store.NewPaths(t.TempDir())
	state := cliDNSState(model.RoleGateway)
	state.DNS.IPv4 = []string{"9.9.9.9"}
	fakeStore := &cliDNSStore{state: state}
	restore := stubDNSCommand(t, paths, RoleGateway, fakeStore)
	defer restore()
	dnsDiscover = func(string) ([]string, error) {
		t.Fatal("gateway reset attempted node resolver discovery")
		return nil, errors.New("unexpected")
	}
	dnsCallGateway = func(_ context.Context, _ string, request control.LocalRequest) (control.LocalResponse, error) {
		if request.Operation != "dns.reset" {
			t.Fatalf("gateway reset operation = %s", request.Operation)
		}
		var payload struct {
			IPv4 []string `json:"ipv4"`
		}
		if err := json.Unmarshal(request.Payload, &payload); err != nil || !reflect.DeepEqual(payload.IPv4, model.DefaultGatewayDNSUpstreams()) {
			t.Fatalf("gateway reset payload = %+v, %v", payload, err)
		}
		return control.LocalResponse{SchemaVersion: control.LocalSchemaVersion, OK: true, Generation: state.Generation + 1}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"dns", "reset", "--json"}, &stdout, &stderr); code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("gateway reset code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

type cliDNSStore struct {
	state model.State
	saves int
}

func (stateStore *cliDNSStore) Load() (model.State, error) { return stateStore.state, nil }

func (stateStore *cliDNSStore) Save(expected uint64, candidate model.State) error {
	if expected != stateStore.state.Generation {
		return store.ErrStateConflict
	}
	stateStore.state = candidate
	stateStore.saves++
	return nil
}

func stubDNSCommand(t *testing.T, paths store.Paths, role HostRole, stateStore dnsStateStore) func() {
	t.Helper()
	oldPaths, oldRole, oldStore := dnsSystemPaths, dnsLoadRole, dnsNewStore
	oldDiscover, oldCall := dnsDiscover, dnsCallGateway
	oldRunner, oldPrepare := dnsRunner, dnsPrepareNode
	dnsSystemPaths = func() store.Paths { return paths }
	dnsLoadRole = func(store.Paths) (HostRole, error) { return role, nil }
	dnsNewStore = func(store.Paths) (dnsStateStore, error) { return stateStore, nil }
	return func() {
		dnsSystemPaths, dnsLoadRole, dnsNewStore = oldPaths, oldRole, oldStore
		dnsDiscover, dnsCallGateway = oldDiscover, oldCall
		dnsRunner, dnsPrepareNode = oldRunner, oldPrepare
	}
}

func cliDNSState(role model.Role) model.State {
	host := model.Host{
		SchemaVersion: model.ResourceSchemaVersion, ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Role: role,
		OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC),
	}
	dns := model.DNSUpstreamState{SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamDirect, IPv4: []string{"192.0.2.53"}}
	if role == model.RoleGateway {
		host.PublicIPv4, host.ExternalInterface, host.SSHPort = "203.0.113.10", "eth0", 22
		host.ClientCIDR, host.NodeCIDR = model.DefaultClientCIDR, model.DefaultNodeCIDR
		dns.Scope, dns.IPv4 = model.DNSUpstreamGateway, model.DefaultGatewayDNSUpstreams()
	}
	return model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 4, Host: host, DNS: &dns,
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports: []model.Transport{}, Exposes: []model.Expose{}, Certificates: []model.Certificate{}, Operations: []model.Operation{},
		Logging: []model.LoggingSession{}, Backups: []model.Backup{},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2-test", ControlProtocols: []string{"1.0"},
			StateSchemaMinimum: 1, StateSchemaMaximum: 1, TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1,
			Components: []model.ComponentPin{{Name: "vpnctl", Version: "v2-test", Source: "test", Bundled: true, SHA256: strings.Repeat("a", 64), Capabilities: []string{"dns"}}},
		},
	}
}
