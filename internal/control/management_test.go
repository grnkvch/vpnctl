package control

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestCallManagementReturnsTypedUnavailableWithoutHidingLocalValidation(t *testing.T) {
	material, node := rpcTestIdentities(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	client, err := NewRPCClient(RPCClientConfig{
		Address: address, GatewayID: testGatewayID, NodeID: testNodeID,
		CACertificatePEM: material.ControlCACertificatePEM,
		CertificatePEM:   nodeCertificatePEM(t, material, node), PrivateKeyPEM: node.PrivateKeyPEM,
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := validRPCRequest(time.Now().UTC())
	result, err := client.CallManagement(context.Background(), request)
	if err != nil || result.StatusCode != http.StatusServiceUnavailable || result.Response.Category != "unavailable" ||
		result.Response.ErrorCode != "controller_unavailable" || result.Response.ProtocolMajor != request.ProtocolMajor ||
		result.Response.ProtocolMinor != request.ProtocolMinor || len(result.Response.RequiresAction) != 1 {
		t.Fatalf("unavailable management result = %+v, %v", result, err)
	}
	if err := result.Response.Validate(); err != nil {
		t.Fatalf("unavailable response is invalid: %v", err)
	}

	invalid := request
	invalid.RequestID = "not-a-uuid"
	if result, err := client.CallManagement(context.Background(), invalid); err == nil || result.StatusCode != 0 {
		t.Fatalf("local validation was converted to unavailable = %+v, %v", result, err)
	}
}

func TestCallManagementPreservesTypedIncompatibleControllerResult(t *testing.T) {
	current := &recordingProtocolHandler{name: "current"}
	protocols, err := NewRPCProtocolRegistryFromVersions([]string{"2.2"}, map[int]RPCHandler{2: current})
	if err != nil {
		t.Fatal(err)
	}
	material, node := rpcTestIdentities(t)
	server, err := newRPCServer(RPCServerConfig{
		GatewayID: testGatewayID, NodeCIDR: "127.0.0.0/8",
		CertificatePEM: material.GatewayCertificatePEM, PrivateKeyPEM: material.GatewayPrivateKeyPEM,
		ClientCACertificatePEM: material.ControlCACertificatePEM, Protocols: protocols, Authorizer: allowAllRPCAuthorizer(),
	}, defaultRPCLimits())
	if err != nil {
		t.Fatal(err)
	}
	fixture := startRPCTestFixture(t, server, material, node)
	request := validRPCRequest(time.Now().UTC())
	request.ProtocolMajor, request.ProtocolMinor = 3, 0
	result, err := fixture.client.CallManagement(context.Background(), request)
	if err != nil || result.StatusCode != http.StatusConflict || result.Response.Category != "conflict" ||
		result.Response.ErrorCode != "incompatible_protocol" || len(result.Response.RequiresAction) != 1 || len(current.versions) != 0 {
		t.Fatalf("incompatible management result = %+v, handler=%+v, %v", result, current.versions, err)
	}
}
