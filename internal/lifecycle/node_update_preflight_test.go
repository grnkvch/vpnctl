package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const (
	nodeUpdateGatewayID = "81000000-0000-4000-8000-000000000001"
	nodeUpdateHostID    = "81000000-0000-4000-8000-000000000002"
	nodeUpdateNodeID    = "81000000-0000-4000-8000-000000000003"
)

func TestNodeUpdatePreflightStopsUnavailableAndIncompatibleBeforeLocalMutation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	gatewayManifest := nodeUpdateManifest("v2.1.0", []string{"1.2"})
	gatewayState := initialGatewayState(nodeUpdateGatewayID, now, linuxplatform.GatewayNetworkPlan{
		PublicIPv4: "203.0.113.10", ExternalInterface: "eth0",
		ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
	}, 22, gatewayManifest, model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: now,
	})
	gatewayState.Generation = 9
	if err := gatewayState.Validate(); err != nil {
		t.Fatal(err)
	}
	handler, err := NewGatewayNodeUpdatePreflightHandler(staticNodeUpdateStateReader{state: gatewayState})
	if err != nil {
		t.Fatal(err)
	}
	protocols, err := control.NewRPCProtocolRegistryFromVersions([]string{"1.2"}, map[int]control.RPCHandler{1: handler})
	if err != nil {
		t.Fatal(err)
	}
	material, err := control.GenerateGatewayControlMaterial(rand.Reader, nodeUpdateGatewayID, "127.0.0.1", now)
	if err != nil {
		t.Fatal(err)
	}
	nodeIdentity, err := control.GenerateNodeControlCSR(rand.Reader, nodeUpdateNodeID)
	if err != nil {
		t.Fatal(err)
	}
	nodeCertificate, err := control.IssueNodeControlCertificate(
		rand.Reader, material.ControlCACertificatePEM, material.ControlCAPrivateKeyPEM,
		nodeIdentity.CSRPEM, nodeUpdateNodeID, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	server, err := control.NewRPCServer(control.RPCServerConfig{
		GatewayID: nodeUpdateGatewayID, NodeCIDR: "127.0.0.0/8",
		CertificatePEM: material.GatewayCertificatePEM, PrivateKeyPEM: material.GatewayPrivateKeyPEM,
		ClientCACertificatePEM: material.ControlCACertificatePEM, Protocols: protocols,
		Authorizer: control.RPCAuthorizerFunc(func(context.Context, control.RPCPeer, control.RPCRequest) (control.RPCAuthorization, error) {
			return control.RPCAuthorization{Authorized: true}, nil
		}),
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client, err := control.NewRPCClient(control.RPCClientConfig{
		Address: listener.Addr().String(), GatewayID: nodeUpdateGatewayID, NodeID: nodeUpdateNodeID,
		CACertificatePEM: material.ControlCACertificatePEM,
		CertificatePEM:   nodeCertificate.CertificatePEM, PrivateKeyPEM: nodeIdentity.PrivateKeyPEM,
		Timeout: time.Second, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	serveContext, stopServer := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveContext, listener) }()

	nodeState := enrolledNodeUpdateState(t, now, gatewayState.Generation, nodeUpdateManifest("v2.0.0", []string{"1.0"}))
	reader := &countingNodeUpdateStateReader{state: nodeState}
	ids := []string{
		"82000000-0000-4000-8000-000000000001",
		"82000000-0000-4000-8000-000000000002",
		"82000000-0000-4000-8000-000000000003",
	}
	nextID := 0
	preflighter, err := NewNodeUpdatePreflighter(NodeUpdatePreflightRuntime{
		State: reader, Gateway: client, Now: func() time.Time { return now }, Entropy: rand.Reader,
		NewUUID: func() (string, error) {
			id := ids[nextID]
			nextID++
			return id, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dataPlane := &nodeUpdateDataPlane{active: true}
	before := nodeState
	if !nodeHasActiveTunnel(before) {
		t.Fatal("precondition: compatible applied node data plane is not active")
	}

	compatible, err := preflighter.Preflight(context.Background(), nodeUpdateManifest("v2.1.1", []string{"1.1"}))
	if err != nil || compatible.Status != NodeUpdateReady || compatible.GatewayVPNCTLVersion != "v2.1.0" ||
		compatible.SelectedProtocol != "1.1" || compatible.AuthoritativeGeneration != gatewayState.Generation {
		t.Fatalf("compatible preflight = %+v, %v", compatible, err)
	}
	incompatible, err := preflighter.Preflight(context.Background(), nodeUpdateManifest("v3.0.0", []string{"2.0", "1.0"}))
	if err != nil || incompatible.Status != NodeUpdateIncompatible || incompatible.Code != "node_newer_than_gateway" || len(incompatible.RequiresAction) != 1 {
		t.Fatalf("incompatible preflight = %+v, %v", incompatible, err)
	}

	stopServer()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("control server shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("control server did not stop")
	}
	unavailable, err := preflighter.Preflight(context.Background(), nodeUpdateManifest("v2.1.1", []string{"1.1"}))
	if err != nil || unavailable.Status != NodeUpdateUnavailable || unavailable.Code != "controller_unavailable" || len(unavailable.RequiresAction) != 1 {
		t.Fatalf("unavailable preflight = %+v, %v", unavailable, err)
	}
	if !reflect.DeepEqual(reader.state, before) || reader.loads.Load() != 3 || !nodeHasActiveTunnel(reader.state) {
		t.Fatalf("preflight mutated/read unexpected local state: loads=%d state=%+v", reader.loads.Load(), reader.state)
	}
	if !dataPlane.active || dataPlane.starts != 0 || dataPlane.stops != 0 || dataPlane.restarts != 0 {
		t.Fatalf("failed management changed compatible data plane: %+v", dataPlane)
	}
}

func TestEvaluateNodeUpdateCompatibilityEnforcesGatewayFirstWindow(t *testing.T) {
	gateway := nodeUpdateManifest("v3.2.0", []string{"3.2", "2.5"})
	for _, test := range []struct {
		name     string
		target   model.ComponentManifest
		ready    bool
		selected string
		code     string
	}{
		{name: "same-major-additive", target: nodeUpdateManifest("v3.1.0", []string{"3.1", "2.9"}), ready: true, selected: "3.1"},
		{name: "previous-major-node", target: nodeUpdateManifest("v2.4.0", []string{"2.4", "1.9"}), ready: true, selected: "2.4"},
		{name: "node-newer-even-with-mutual-previous", target: nodeUpdateManifest("v4.0.0", []string{"4.0", "3.2"}), code: "node_newer_than_gateway"},
		{name: "no-mutual-major", target: nodeUpdateManifest("v1.9.0", []string{"1.9"}), code: "no_mutual_control_protocol"},
	} {
		t.Run(test.name, func(t *testing.T) {
			compatibility, code, _, err := EvaluateNodeUpdateCompatibility(gateway, test.target)
			if err != nil || compatibility.Compatible != test.ready || compatibility.SelectedProtocol != test.selected || code != test.code {
				t.Fatalf("compatibility = %+v, code=%q, error=%v", compatibility, code, err)
			}
		})
	}
}

func TestNodeUpdatePreflightBlocksLocalSchemaAndPendingRequestWithoutGatewayCall(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	state := enrolledNodeUpdateState(t, now, 7, nodeUpdateManifest("v2.0.0", []string{"1.0"}))
	caller := &countingNodeUpdateGatewayCaller{}
	preflighter, err := NewNodeUpdatePreflighter(NodeUpdatePreflightRuntime{
		State: staticNodeUpdateStateReader{state: state}, Gateway: caller,
		NewUUID: func() (string, error) { return "83000000-0000-4000-8000-000000000001", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	incompatibleSchema := nodeUpdateManifest("v3.0.0", []string{"1.0"})
	incompatibleSchema.StateSchemaMinimum = model.StateSchemaVersion + 1
	incompatibleSchema.StateSchemaMaximum = model.StateSchemaVersion + 1
	plan, err := preflighter.Preflight(context.Background(), incompatibleSchema)
	if err != nil || plan.Status != NodeUpdateBlocked || plan.Code != "target_state_schema_incompatible" || caller.calls.Load() != 0 {
		t.Fatalf("schema preflight = %+v, calls=%d, %v", plan, caller.calls.Load(), err)
	}

	state.Nodes[0].Gateway.PendingRequestID = "83000000-0000-4000-8000-000000000002"
	state.Operations = append(state.Operations, model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: "83000000-0000-4000-8000-000000000003",
		Type: model.OperationApply, State: model.OperationPending, TargetKind: "node", TargetID: nodeUpdateNodeID,
		RequestID: state.Nodes[0].Gateway.PendingRequestID, ExpectedGeneration: 7, DesiredGeneration: 8,
		Steps: []model.OperationStep{}, CreatedAt: now, UpdatedAt: now,
	})
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	preflighter.runtime.State = staticNodeUpdateStateReader{state: state}
	plan, err = preflighter.Preflight(context.Background(), nodeUpdateManifest("v2.1.0", []string{"1.0"}))
	if err != nil || plan.Status != NodeUpdateBlocked || plan.Code != "management_request_pending" || caller.calls.Load() != 0 {
		t.Fatalf("pending-request preflight = %+v, calls=%d, %v", plan, caller.calls.Load(), err)
	}
}

func nodeUpdateManifest(version string, protocols []string) model.ComponentManifest {
	return model.ComponentManifest{
		SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: version,
		ControlProtocols: append([]string(nil), protocols...), StateSchemaMinimum: model.StateSchemaVersion, StateSchemaMaximum: model.StateSchemaVersion,
		TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1, MigrationReversible: true,
		Components: []model.ComponentPin{{
			Name: "vpnctl", Version: version, Source: "bundle:vpnctl", Bundled: true,
			SHA256: strings.Repeat("a", 64), Capabilities: []string{"cli", "controller"},
		}},
	}
}

func enrolledNodeUpdateState(t *testing.T, now time.Time, gatewayGeneration uint64, manifest model.ComponentManifest) model.State {
	t.Helper()
	state := initialNodeState(nodeUpdateHostID, now, manifest)
	state.Generation = 2
	state.Nodes = append(state.Nodes, model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: nodeUpdateNodeID, Name: "private-node",
		Lifecycle: model.LifecycleActive, OverlayIPv4: "10.67.0.2", CredentialGeneration: 1,
		AssignedPresets: []string{}, ActiveTransport: model.TransportStandard, IdempotencyRecords: []model.IdempotencyRecord{},
		Gateway: &model.GatewayTrust{
			PublicIPv4: "203.0.113.10", EnrollmentFingerprint: testNodeUpdateFingerprint(0x11),
			ControlCAFingerprints: []string{testNodeUpdateFingerprint(0x22)}, LastKnownGatewayGeneration: gatewayGeneration,
		},
		CreatedAt: now,
	})
	state.Transports = append(state.Transports, model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: nodeUpdateNodeID,
		Kind: model.TransportStandard, State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP,
		Port: 51820, CredentialGeneration: 1, CredentialRef: "transport-key:standard",
		PublicKey: "node-update-public-key", ConfigHash: strings.Repeat("b", 64),
	})
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	return state
}

func testNodeUpdateFingerprint(value byte) string {
	return "sha256:" + hex.EncodeToString(bytesOf(value, 32))
}

func bytesOf(value byte, size int) []byte {
	result := make([]byte, size)
	for index := range result {
		result[index] = value
	}
	return result
}

type staticNodeUpdateStateReader struct{ state model.State }

func (reader staticNodeUpdateStateReader) Load() (model.State, error) { return reader.state, nil }

type countingNodeUpdateStateReader struct {
	state model.State
	loads atomic.Int32
}

func (reader *countingNodeUpdateStateReader) Load() (model.State, error) {
	reader.loads.Add(1)
	return reader.state, nil
}

type countingNodeUpdateGatewayCaller struct{ calls atomic.Int32 }

func (caller *countingNodeUpdateGatewayCaller) CallManagement(context.Context, control.RPCRequest) (control.RPCCallResult, error) {
	caller.calls.Add(1)
	return control.RPCCallResult{}, nil
}

type nodeUpdateDataPlane struct {
	active                  bool
	starts, stops, restarts int
}
