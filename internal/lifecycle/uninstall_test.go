package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestNodeUninstallGatewayClientSendsOneAuthenticatedRevocationRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := enrolledNodeUpdateState(t, now, 9, gatewayTestManifest())
	caller := &recordingNodeUninstallCaller{}
	client, err := NewNodeUninstallGatewayClient(caller, func() time.Time { return now }, func() (string, error) {
		return "92000000-0000-4000-8000-000000000001", nil
	}, bytes.NewReader(bytes.Repeat([]byte{0x42}, control.RPCNonceBytes)))
	if err != nil {
		t.Fatal(err)
	}
	confirmation, _ := json.Marshal(NodeUninstallConfirmation{Confirmed: true, NodeID: state.Nodes[0].ID})
	caller.result = control.RPCCallResult{StatusCode: http.StatusOK, Response: control.NewRPCResponse("success", 10, confirmation)}
	result, err := client.RevokeForUninstall(context.Background(), state)
	if err != nil || !result.Confirmed || result.GatewayGeneration != 10 || caller.calls != 1 {
		t.Fatalf("RevokeForUninstall() = %+v, %v calls=%d", result, err, caller.calls)
	}
	request := caller.request
	if request.Operation != NodeUninstallOperation || request.NodeID != state.Nodes[0].ID || request.ExpectedStateGeneration != 9 ||
		request.CredentialGeneration != state.Nodes[0].CredentialGeneration || !request.Timestamp.Equal(now) {
		t.Fatalf("uninstall request = %+v", request)
	}
	var payload NodeUninstallRequest
	if err := control.DecodeRPCPayload(request.Payload, &payload); err != nil || !payload.ConfirmRevoke {
		t.Fatalf("uninstall payload = %+v, %v", payload, err)
	}
}

func TestNodeUninstallGatewayClientRejectsUnconfirmedOrUnavailableResponse(t *testing.T) {
	state := enrolledNodeUpdateState(t, time.Now().UTC().Truncate(time.Second), 9, gatewayTestManifest())
	for _, test := range []struct {
		name   string
		result control.RPCCallResult
	}{
		{name: "gateway conflict", result: control.RPCCallResult{StatusCode: http.StatusConflict, Response: control.NewRPCResponse("conflict", 9, json.RawMessage(`{}`))}},
		{name: "wrong identity", result: control.RPCCallResult{StatusCode: http.StatusOK, Response: control.NewRPCResponse("success", 10, json.RawMessage(`{"confirmed":true,"node_id":"92000000-0000-4000-8000-000000000099"}`))}},
	} {
		t.Run(test.name, func(t *testing.T) {
			caller := &recordingNodeUninstallCaller{result: test.result}
			client, _ := NewNodeUninstallGatewayClient(caller, nil, func() (string, error) {
				return "92000000-0000-4000-8000-000000000001", nil
			}, bytes.NewReader(bytes.Repeat([]byte{0x42}, control.RPCNonceBytes)))
			if _, err := client.RevokeForUninstall(context.Background(), state); err == nil {
				t.Fatal("unconfirmed gateway response was accepted")
			}
		})
	}
}

func TestGatewayUninstallRequiresForceAndPublishesCompleteImpact(t *testing.T) {
	state := uninstallGatewayState(t)
	store := &memoryUninstallState{state: state}
	runtime := newRecordingUninstallRuntime(model.RoleGateway)
	uninstaller, _ := NewUninstaller(store, runtime)

	blocked, err := uninstaller.Plan(context.Background(), UninstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !blocked.Blocked || !blocked.ForceRequired || len(blocked.ActiveNodeIDs) != 1 || blocked.ActiveNodeIDs[0] != state.Nodes[0].ID {
		t.Fatalf("blocked gateway plan = %+v", blocked)
	}
	if !containsString(blocked.Preserved, "/var/lib/vpnctl/applied-material") {
		t.Fatalf("recoverable uninstall does not preserve applied material: %v", blocked.Preserved)
	}
	if _, err := uninstaller.Apply(context.Background(), blocked); !errors.Is(err, ErrUninstallForceRequired) {
		t.Fatalf("blocked Apply() error = %v", err)
	}
	if !reflect.DeepEqual(runtime.calls, []string{"inspect"}) {
		t.Fatalf("blocked gateway calls = %v", runtime.calls)
	}

	runtime.calls = nil
	forced, err := uninstaller.Plan(context.Background(), UninstallOptions{Force: true})
	if err != nil || forced.Blocked || !forced.Force {
		t.Fatalf("forced gateway plan = %+v, %v", forced, err)
	}
	result, err := uninstaller.Apply(context.Background(), forced)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{"inspect", "inspect", "stop", "dns", "network", "swap", "runtime", "binary"}
	if !reflect.DeepEqual(runtime.calls, wantCalls) || !result.BinaryRemoved || result.NodeRevoked {
		t.Fatalf("forced result/calls = %+v / %v", result, runtime.calls)
	}
}

func TestNodeUninstallOnlineRevokePrecedesEveryLocalMutation(t *testing.T) {
	state := enrolledNodeUpdateState(t, time.Now().UTC().Truncate(time.Second), 9, gatewayTestManifest())
	store := &memoryUninstallState{state: state}
	runtime := newRecordingUninstallRuntime(model.RoleNode)
	runtime.revocation = UninstallNodeRevocation{Confirmed: true, GatewayGeneration: 10}
	uninstaller, _ := NewUninstaller(store, runtime)

	plan, err := uninstaller.Plan(context.Background(), UninstallOptions{})
	if err != nil || !plan.NodeRevokeRequired || plan.LocalOnly || plan.NodeID != state.Nodes[0].ID {
		t.Fatalf("online node plan = %+v, %v", plan, err)
	}
	result, err := uninstaller.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"inspect", "inspect", "revoke", "stop", "dns", "network", "swap", "runtime", "binary"}
	if !reflect.DeepEqual(runtime.calls, want) || !result.NodeRevoked || result.GatewayGeneration != 10 || result.NodeID != state.Nodes[0].ID {
		t.Fatalf("online result/calls = %+v / %v", result, runtime.calls)
	}
}

func TestNodeUninstallUnavailableGatewayLeavesLocalHostUntouched(t *testing.T) {
	state := enrolledNodeUpdateState(t, time.Now().UTC().Truncate(time.Second), 9, gatewayTestManifest())
	runtime := newRecordingUninstallRuntime(model.RoleNode)
	runtime.revokeErr = errors.New("offline")
	uninstaller, _ := NewUninstaller(&memoryUninstallState{state: state}, runtime)
	plan, _ := uninstaller.Plan(context.Background(), UninstallOptions{})

	if _, err := uninstaller.Apply(context.Background(), plan); !errors.Is(err, ErrUninstallGatewayUnavailable) {
		t.Fatalf("offline Apply() error = %v", err)
	}
	if want := []string{"inspect", "inspect", "revoke"}; !reflect.DeepEqual(runtime.calls, want) {
		t.Fatalf("offline node mutated local host: %v", runtime.calls)
	}
}

func TestNodeLocalOnlySkipsGatewayAndCompletesRecoverableCleanup(t *testing.T) {
	state := enrolledNodeUpdateState(t, time.Now().UTC().Truncate(time.Second), 9, gatewayTestManifest())
	runtime := newRecordingUninstallRuntime(model.RoleNode)
	uninstaller, _ := NewUninstaller(&memoryUninstallState{state: state}, runtime)
	plan, err := uninstaller.Plan(context.Background(), UninstallOptions{LocalOnly: true})
	if err != nil || !plan.LocalOnly || !plan.NodeRevokeRequired {
		t.Fatalf("local-only plan = %+v, %v", plan, err)
	}
	result, err := uninstaller.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"inspect", "inspect", "stop", "dns", "network", "swap", "runtime", "binary"}
	if !reflect.DeepEqual(runtime.calls, want) || result.NodeRevoked || !result.LocalOnly {
		t.Fatalf("local-only result/calls = %+v / %v", result, runtime.calls)
	}
}

func TestUninstallDoesNotRemoveBinaryAfterEarlierCleanupFailure(t *testing.T) {
	state := initialNodeState("91000000-0000-4000-8000-000000000004", time.Now().UTC().Truncate(time.Second), gatewayTestManifest(), []string{"192.0.2.53"})
	runtime := newRecordingUninstallRuntime(model.RoleNode)
	runtime.runtimeErr = errors.New("injected")
	uninstaller, _ := NewUninstaller(&memoryUninstallState{state: state}, runtime)
	plan, _ := uninstaller.Plan(context.Background(), UninstallOptions{})
	if _, err := uninstaller.Apply(context.Background(), plan); err == nil {
		t.Fatal("Apply() succeeded despite runtime cleanup failure")
	}
	if want := []string{"inspect", "inspect", "stop", "dns", "network", "swap", "runtime"}; !reflect.DeepEqual(runtime.calls, want) {
		t.Fatalf("binary was not last: %v", runtime.calls)
	}
}

func TestUninstallRejectsRoleFlagsAndStateOrRuntimeDrift(t *testing.T) {
	gateway := uninstallGatewayState(t)
	runtime := newRecordingUninstallRuntime(model.RoleGateway)
	uninstaller, _ := NewUninstaller(&memoryUninstallState{state: gateway}, runtime)
	if _, err := uninstaller.Plan(context.Background(), UninstallOptions{LocalOnly: true}); !errors.Is(err, ErrUninstallRoleFlag) {
		t.Fatalf("gateway local-only error = %v", err)
	}

	node := initialNodeState("91000000-0000-4000-8000-000000000004", time.Now().UTC().Truncate(time.Second), gatewayTestManifest(), []string{"192.0.2.53"})
	nodeStore := &memoryUninstallState{state: node}
	nodeRuntime := newRecordingUninstallRuntime(model.RoleNode)
	nodeUninstaller, _ := NewUninstaller(nodeStore, nodeRuntime)
	if _, err := nodeUninstaller.Plan(context.Background(), UninstallOptions{Force: true}); !errors.Is(err, ErrUninstallRoleFlag) {
		t.Fatalf("node force error = %v", err)
	}
	plan, _ := nodeUninstaller.Plan(context.Background(), UninstallOptions{})
	nodeStore.state.Generation++
	if _, err := nodeUninstaller.Apply(context.Background(), plan); !errors.Is(err, ErrUninstallPlanStale) {
		t.Fatalf("state drift error = %v", err)
	}
	nodeStore.state = node
	plan, _ = nodeUninstaller.Plan(context.Background(), UninstallOptions{})
	nodeRuntime.plan.RuntimePaths = append(nodeRuntime.plan.RuntimePaths, "/run/vpnctl/drift")
	if _, err := nodeUninstaller.Apply(context.Background(), plan); !errors.Is(err, ErrUninstallPlanStale) {
		t.Fatalf("runtime drift error = %v", err)
	}
}

func uninstallGatewayState(t *testing.T) model.State {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	state := initialGatewayState("91000000-0000-4000-8000-000000000001", now, linuxplatform.GatewayNetworkPlan{
		PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
	}, 22, gatewayTestManifest(), gatewayTestHandshakeHost())
	state.EnrollmentIdentity = updateTestEnrollmentIdentity(now)
	node := updateTestGatewayNode("91000000-0000-4000-8000-000000000002", "private-api", "10.67.0.2", now)
	state.Nodes = []model.Node{node}
	state.Transports = []model.Transport{updateTestNodeTransport(node, "transport-key:private-api")}
	state.Invites = []model.Invite{updateTestConsumedInvite(state, node, "1.0", now)}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	return state
}

type memoryUninstallState struct{ state model.State }

func (state *memoryUninstallState) Load() (model.State, error) { return state.state, nil }

type recordingUninstallRuntime struct {
	plan       UninstallHostPlan
	purgePlan  PurgeHostPlan
	calls      []string
	revocation UninstallNodeRevocation
	revokeErr  error
	runtimeErr error
	dataErr    error
}

func newRecordingUninstallRuntime(role model.Role) *recordingUninstallRuntime {
	return &recordingUninstallRuntime{plan: UninstallHostPlan{
		StateGeneration: 1,
		Units:           []string{"vpnctl-standard.service"}, GeneratedPaths: []string{"/etc/vpnctl/generated/" + string(role)},
		AuxiliaryUnits: []string{},
		RuntimePaths:   []string{"/run/vpnctl"}, ComponentPaths: []string{"/usr/local/libexec/vpnctl/mihomo"},
		WatchdogTransactionIDs: []string{}, WatchdogUnitFiles: []string{},
		BinaryPath: "/usr/local/bin/vpnctl", BinarySHA256: strings.Repeat("a", 64),
		DNSRestorationRequired: role == model.RoleNode, NetworkRestoreRequired: true,
	}, purgePlan: PurgeHostPlan{
		StateGeneration: 1, ConfigDir: "/etc/vpnctl", StateDir: "/var/lib/vpnctl",
		BackupsDir: "/var/lib/vpnctl/backups", BackupArchives: 1,
	}}
}

func (runtime *recordingUninstallRuntime) Inspect(_ context.Context, state model.State) (UninstallHostPlan, error) {
	runtime.calls = append(runtime.calls, "inspect")
	plan := runtime.plan
	plan.StateGeneration = state.Generation
	return plan, nil
}
func (runtime *recordingUninstallRuntime) RevokeNode(context.Context, model.State) (UninstallNodeRevocation, error) {
	runtime.calls = append(runtime.calls, "revoke")
	return runtime.revocation, runtime.revokeErr
}

func (runtime *recordingUninstallRuntime) InspectPurge(_ context.Context, state model.State, includeBackups bool) (PurgeHostPlan, error) {
	runtime.calls = append(runtime.calls, "inspect-purge")
	plan := runtime.purgePlan
	plan.StateGeneration = state.Generation
	plan.IncludeBackups = includeBackups
	return plan, nil
}
func (runtime *recordingUninstallRuntime) StopServices(context.Context, UninstallHostPlan) error {
	runtime.calls = append(runtime.calls, "stop")
	return nil
}
func (runtime *recordingUninstallRuntime) RestoreDNS(context.Context, UninstallHostPlan) (bool, error) {
	runtime.calls = append(runtime.calls, "dns")
	return runtime.plan.DNSRestorationRequired, nil
}
func (runtime *recordingUninstallRuntime) RestoreNetwork(context.Context, UninstallHostPlan) (bool, error) {
	runtime.calls = append(runtime.calls, "network")
	return runtime.plan.NetworkRestoreRequired, nil
}
func (runtime *recordingUninstallRuntime) DisableManagedSwap(context.Context, UninstallHostPlan) (bool, uint64, error) {
	runtime.calls = append(runtime.calls, "swap")
	return false, 1, nil
}

func (runtime *recordingUninstallRuntime) PurgeManagedSwap(context.Context, UninstallHostPlan) (bool, error) {
	runtime.calls = append(runtime.calls, "purge-swap")
	return true, nil
}
func (runtime *recordingUninstallRuntime) RemoveManagedRuntime(context.Context, UninstallHostPlan) error {
	runtime.calls = append(runtime.calls, "runtime")
	return runtime.runtimeErr
}

func (runtime *recordingUninstallRuntime) RemovePurgedData(_ context.Context, plan PurgeHostPlan) (bool, bool, error) {
	runtime.calls = append(runtime.calls, "data")
	return runtime.dataErr == nil, plan.IncludeBackups && runtime.purgePlan.BackupArchives > 0, runtime.dataErr
}
func (runtime *recordingUninstallRuntime) RemoveBinary(context.Context, UninstallHostPlan) (bool, error) {
	runtime.calls = append(runtime.calls, "binary")
	return runtime.plan.BinaryPath != "", nil
}

type recordingNodeUninstallCaller struct {
	result  control.RPCCallResult
	err     error
	request control.RPCRequest
	calls   int
}

func (caller *recordingNodeUninstallCaller) CallManagement(_ context.Context, request control.RPCRequest) (control.RPCCallResult, error) {
	caller.calls++
	caller.request = request
	return caller.result, caller.err
}
