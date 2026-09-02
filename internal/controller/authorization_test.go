package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestRPCNodeAuthorizationRejectsRevokedCryptographicallyValidCertificate(t *testing.T) {
	fixture := newAuthorizationRPCFixture(t)
	request := authorizationTestRequest("50000000-0000-4000-8000-000000000001", 1, 2)
	if result, err := fixture.oldClient.Call(context.Background(), request); err != nil || result.StatusCode != http.StatusOK {
		t.Fatalf("active node call = %+v, %v", result, err)
	}

	state, err := fixture.state.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.Generation++
	state.Nodes[0], err = state.Nodes[0].Revoke(state.Nodes[0].CreatedAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	state.Transports[0].State = model.TransportDisabled
	if err := fixture.state.Save(2, state); err != nil {
		t.Fatal(err)
	}

	request = authorizationTestRequest("50000000-0000-4000-8000-000000000002", 1, 3)
	result, err := fixture.oldClient.Call(context.Background(), request)
	if err != nil || result.StatusCode != http.StatusForbidden || result.Response.ErrorCode != "node_inactive" || result.Response.AuthoritativeGeneration != 3 {
		t.Fatalf("revoked node call = %+v, %v", result, err)
	}
	if calls := fixture.handlerCalls.Load(); calls != 1 {
		t.Fatalf("revoked request reached operation handler: calls=%d", calls)
	}
}

func TestRPCNodeAuthorizationBindsCertificateToCurrentCredentialGeneration(t *testing.T) {
	fixture := newAuthorizationRPCFixture(t)
	if result, err := fixture.oldClient.Call(context.Background(), authorizationTestRequest("50000000-0000-4000-8000-000000000003", 1, 2)); err != nil || result.StatusCode != http.StatusOK {
		t.Fatalf("initial credential call = %+v, %v", result, err)
	}

	newNode, err := control.GenerateNodeControlCSR(rand.Reader, mutationTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := control.IssueNodeControlCertificate(
		rand.Reader, fixture.material.ControlCACertificatePEM, fixture.material.ControlCAPrivateKeyPEM,
		newNode.CSRPEM, mutationTestNodeID, time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	state, err := fixture.state.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.Generation++
	state.Nodes[0], err = state.Nodes[0].AdvanceCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	state.Transports[0].CredentialGeneration = 2
	state.Transports[0].CredentialRef = "secret:node-standard-2"
	state.Transports[0].ConfigHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	state.Certificates[0] = authorizationCertificateRecord(issued, state.Certificates[0].ID, 2)
	if err := fixture.state.Save(2, state); err != nil {
		t.Fatal(err)
	}

	staleEnvelope := authorizationTestRequest("50000000-0000-4000-8000-000000000004", 1, 3)
	result, err := fixture.oldClient.Call(context.Background(), staleEnvelope)
	if err != nil || result.StatusCode != http.StatusForbidden || result.Response.ErrorCode != "credential_generation_mismatch" {
		t.Fatalf("old generation envelope = %+v, %v", result, err)
	}
	forgedCurrent := authorizationTestRequest("50000000-0000-4000-8000-000000000005", 2, 3)
	result, err = fixture.oldClient.Call(context.Background(), forgedCurrent)
	if err != nil || result.StatusCode != http.StatusForbidden || result.Response.ErrorCode != "credential_not_authorized" {
		t.Fatalf("old certificate with current generation envelope = %+v, %v", result, err)
	}
	if calls := fixture.handlerCalls.Load(); calls != 1 {
		t.Fatalf("old credential reached operation handler: calls=%d", calls)
	}

	currentClient, err := control.NewRPCClient(control.RPCClientConfig{
		Address: fixture.address, GatewayID: fixture.gatewayID, NodeID: mutationTestNodeID,
		CACertificatePEM: fixture.material.ControlCACertificatePEM,
		CertificatePEM:   issued.CertificatePEM, PrivateKeyPEM: newNode.PrivateKeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	current := authorizationTestRequest("50000000-0000-4000-8000-000000000006", 2, 3)
	if result, err := currentClient.Call(context.Background(), current); err != nil || result.StatusCode != http.StatusOK {
		t.Fatalf("current credential call = %+v, %v", result, err)
	}
	if calls := fixture.handlerCalls.Load(); calls != 2 {
		t.Fatalf("current credential did not reach operation handler: calls=%d", calls)
	}
}

func TestRPCNodeAuthorizationFailsClosedWhenStateUnavailable(t *testing.T) {
	authorizer, err := NewRPCNodeAuthorizer(failingGatewayStateReader{})
	if err != nil {
		t.Fatal(err)
	}
	request := authorizationTestRequest("50000000-0000-4000-8000-000000000007", 1, 2)
	authorization, err := authorizer.AuthorizeRPC(context.Background(), control.RPCPeer{
		NodeID: mutationTestNodeID, CertificateFingerprint: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0x42}, sha256.Size)),
	}, request)
	if err != nil || authorization.Authorized || authorization.Denial.StatusCode != http.StatusServiceUnavailable ||
		authorization.Denial.Response.ErrorCode != "authorization_unavailable" {
		t.Fatalf("unavailable authorization = %+v, %v", authorization, err)
	}
}

type authorizationRPCFixture struct {
	state        *store.StateStore
	material     control.GatewayControlMaterial
	oldClient    *control.RPCClient
	address      string
	gatewayID    string
	handlerCalls atomic.Int32
}

func newAuthorizationRPCFixture(t *testing.T) *authorizationRPCFixture {
	t.Helper()
	_, stateStore := controllerTestState(t, model.RoleGateway)
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	material, err := control.GenerateGatewayControlMaterial(rand.Reader, state.Host.ID, "127.0.0.1", now)
	if err != nil {
		t.Fatal(err)
	}
	node, err := control.GenerateNodeControlCSR(rand.Reader, mutationTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := control.IssueNodeControlCertificate(
		rand.Reader, material.ControlCACertificatePEM, material.ControlCAPrivateKeyPEM,
		node.CSRPEM, mutationTestNodeID, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := state.Host.InitializedAt.Add(time.Minute)
	state.Generation++
	state.Nodes = append(state.Nodes, model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: mutationTestNodeID, Name: "private-1",
		Lifecycle: model.LifecycleActive, OverlayIPv4: "10.67.0.2", CredentialGeneration: 1,
		AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
		IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: createdAt,
	})
	state.Transports = append(state.Transports, model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: mutationTestNodeID,
		Kind: model.TransportStandard, State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP,
		Port: 51820, CredentialGeneration: 1, CredentialRef: "secret:node-standard",
		PublicKey: "test-public-key", ConfigHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	state.Certificates = append(state.Certificates, authorizationCertificateRecord(issued, "60000000-0000-4000-8000-000000000001", 1))
	if err := stateStore.Save(1, state); err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewRPCNodeAuthorizer(stateStore)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &authorizationRPCFixture{state: stateStore, material: material, gatewayID: state.Host.ID}
	handler := control.RPCHandlerFunc(func(context.Context, control.RPCPeer, control.RPCRequest) (control.RPCHandlerResult, error) {
		fixture.handlerCalls.Add(1)
		return control.RPCHandlerResult{StatusCode: http.StatusOK, Response: control.NewRPCResponse("success", 1, json.RawMessage(`{"authorized":true}`))}, nil
	})
	protocols, err := control.NewRPCProtocolRegistryFromVersions([]string{"1.0"}, map[int]control.RPCHandler{1: handler})
	if err != nil {
		t.Fatal(err)
	}
	server, err := control.NewRPCServer(control.RPCServerConfig{
		GatewayID: state.Host.ID, NodeCIDR: "127.0.0.0/8",
		CertificatePEM: material.GatewayCertificatePEM, PrivateKeyPEM: material.GatewayPrivateKeyPEM,
		ClientCACertificatePEM: material.ControlCACertificatePEM, Protocols: protocols, Authorizer: authorizer,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture.address = listener.Addr().String()
	fixture.oldClient, err = control.NewRPCClient(control.RPCClientConfig{
		Address: fixture.address, GatewayID: state.Host.ID, NodeID: mutationTestNodeID,
		CACertificatePEM: material.ControlCACertificatePEM,
		CertificatePEM:   issued.CertificatePEM, PrivateKeyPEM: node.PrivateKeyPEM,
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("authorized RPC server shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("authorized RPC server did not stop")
		}
	})
	return fixture
}

func authorizationCertificateRecord(issued control.IssuedNodeCertificate, id string, generation uint64) model.Certificate {
	fingerprint := sha256.Sum256(issued.Certificate.Raw)
	return model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: id, Kind: model.CertificateControlNode,
		OwnerKind: "node", OwnerID: mutationTestNodeID,
		Fingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]), SerialHex: issued.Certificate.SerialNumber.Text(16),
		Subject: issued.Certificate.Subject.String(), SANs: []string{issued.IdentityURI},
		NotBefore: issued.Certificate.NotBefore, NotAfter: issued.Certificate.NotAfter, WarningDays: 180,
		Generation: generation, CertificateRef: "pki:node-control",
	}
}

func authorizationTestRequest(requestID string, credentialGeneration, expectedGeneration uint64) control.RPCRequest {
	return control.RPCRequest{
		ProtocolMajor: 1, ProtocolMinor: 0, RequestID: requestID,
		ExpectedStateGeneration: expectedGeneration, NodeID: mutationTestNodeID, CredentialGeneration: credentialGeneration,
		Timestamp: time.Now().UTC(), Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, control.RPCNonceBytes)),
		Operation: "status", Payload: json.RawMessage(`{}`),
	}
}

type failingGatewayStateReader struct{}

func (failingGatewayStateReader) Load() (model.State, error) {
	return model.State{}, context.DeadlineExceeded
}
