package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestGatewayControlLeafRenewsAutomaticallyAtBoundaryWithoutDataPlaneRestart(t *testing.T) {
	fixture := newGatewayRenewalFixture(t)
	boundary := fixture.initialLeaf.NotAfter.Add(-control.ControlRenewalWindow)
	fixture.clock.Set(boundary.Add(-time.Second))
	ticks := make(chan time.Time, 1)
	waits := make(chan struct{}, 2)
	renewer, err := fixture.controller.NewGatewayControlLeafRenewer(fixture.secrets, fixture.server, GatewayControlLeafRenewalRuntime{
		Entropy:       rand.Reader,
		NewUUID:       func() (string, error) { return "70000000-0000-4000-8000-000000000001", nil },
		CheckInterval: GatewayControlLeafCheckInterval,
		After: func(interval time.Duration) <-chan time.Time {
			if interval != GatewayControlLeafCheckInterval {
				t.Errorf("renewal interval = %s", interval)
			}
			waits <- struct{}{}
			return ticks
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- renewer.Run(ctx) }()
	select {
	case <-waits:
	case <-time.After(2 * time.Second):
		t.Fatal("automatic renewal did not perform its startup check")
	}
	beforeWindow, err := fixture.state.Load()
	if err != nil || beforeWindow.Generation != 2 || beforeWindow.Certificates[fixture.serverCertificateIndex].Generation != 1 {
		t.Fatalf("pre-window state changed = generation %d certificate %d, %v", beforeWindow.Generation, beforeWindow.Certificates[fixture.serverCertificateIndex].Generation, err)
	}
	fixture.call(t, "71000000-0000-4000-8000-000000000001", 2)

	fixture.clock.Set(boundary)
	ticks <- boundary
	select {
	case <-waits:
	case <-time.After(2 * time.Second):
		t.Fatal("automatic renewal did not finish the boundary cycle")
	}
	cancel()
	if err := <-runDone; err != nil {
		t.Fatalf("renewal Run() error = %v", err)
	}
	after, err := fixture.state.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != 3 || after.Certificates[fixture.serverCertificateIndex].Generation != 2 ||
		after.Certificates[fixture.serverCertificateIndex].Fingerprint == fixture.initialServerRecord.Fingerprint {
		t.Fatalf("renewed state = generation %d certificate %+v", after.Generation, after.Certificates[fixture.serverCertificateIndex])
	}
	fixture.call(t, "71000000-0000-4000-8000-000000000002", 3)
	assertServedGatewayFingerprint(t, fixture, after.Certificates[fixture.serverCertificateIndex].Fingerprint)

	if !reflect.DeepEqual(after.Certificates[fixture.caCertificateIndex], fixture.initialCARecord) ||
		!reflect.DeepEqual(after.Certificates[fixture.nodeCertificateIndex], fixture.initialNodeCertificate) ||
		!reflect.DeepEqual(after.Certificates[fixture.publicCertificateIndex], fixture.initialPublicCertificate) ||
		!reflect.DeepEqual(after.Nodes, fixture.initialNodes) || !reflect.DeepEqual(after.EnrollmentIdentity, fixture.initialEnrollment) {
		t.Fatal("control renewal changed CA, node trust, public ingress identity, node records, or enrollment identity")
	}
	for reference, expected := range fixture.preservedSecrets {
		actual, err := fixture.secrets.Get(reference)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Errorf("preserved secret %s changed: %v", reference, err)
		}
	}
	renewedRecord := after.Certificates[fixture.serverCertificateIndex]
	for _, reference := range []model.SecretRef{model.SecretRef(renewedRecord.CertificateRef), renewedRecord.PrivateKeyRef} {
		kind, id, _ := reference.Parts()
		info, err := os.Stat(filepath.Join(fixture.paths.SecretsDir, kind, id))
		if err != nil || info.Mode().Perm() != store.SecretFileMode {
			t.Errorf("renewed secret %s mode = %v, %v", reference, info, err)
		}
	}
	if fixture.dataPlane.starts != 0 || fixture.dataPlane.stops != 0 || fixture.dataPlane.restarts != 0 || !fixture.dataPlane.active {
		t.Fatalf("data plane changed during control renewal: %+v", fixture.dataPlane)
	}
	if fixture.handlerCalls.Load() != 2 {
		t.Fatalf("management calls across renewal = %d, want 2", fixture.handlerCalls.Load())
	}

	result, err := renewer.RenewIfNeeded(context.Background())
	if err != nil || result.Changed || result.StateGeneration != 3 || result.CertificateGeneration != 2 {
		t.Fatalf("idempotent post-renewal check = %+v, %v", result, err)
	}
	unchanged, _ := fixture.state.Load()
	if unchanged.Generation != 3 {
		t.Fatalf("post-renewal check advanced state to %d", unchanged.Generation)
	}
}

func TestGatewayControlLeafRenewalCommitFailureKeepsPriorGeneration(t *testing.T) {
	fixture := newGatewayRenewalFixture(t)
	fixture.clock.Set(fixture.initialLeaf.NotAfter.Add(-control.ControlRenewalWindow))
	fixture.controller.runtime.State = failingRenewalStateStore{delegate: fixture.state}
	referenceID := "70000000-0000-4000-8000-000000000002"
	renewer, err := fixture.controller.NewGatewayControlLeafRenewer(fixture.secrets, fixture.server, GatewayControlLeafRenewalRuntime{
		Entropy: rand.Reader, NewUUID: func() (string, error) { return referenceID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := renewer.RenewIfNeeded(context.Background()); err == nil || result.Changed {
		t.Fatalf("failed commit result = %+v, %v", result, err)
	}
	state, err := fixture.state.Load()
	if err != nil || state.Generation != 2 || !reflect.DeepEqual(state.Certificates[fixture.serverCertificateIndex], fixture.initialServerRecord) {
		t.Fatalf("failed commit changed authoritative state = %+v, %v", state, err)
	}
	for _, reference := range []model.SecretRef{model.SecretRef("control-cert:" + referenceID), model.SecretRef("control-key:" + referenceID)} {
		if _, err := fixture.secrets.Get(reference); err == nil {
			t.Errorf("failed commit retained staged secret %s", reference)
		}
	}
	fixture.call(t, "71000000-0000-4000-8000-000000000003", 2)
	assertServedGatewayFingerprint(t, fixture, fixture.initialServerRecord.Fingerprint)
	if fixture.dataPlane.starts != 0 || fixture.dataPlane.stops != 0 || fixture.dataPlane.restarts != 0 {
		t.Fatalf("failed control renewal changed data plane: %+v", fixture.dataPlane)
	}
}

type gatewayRenewalFixture struct {
	paths                    store.Paths
	state                    *store.StateStore
	secrets                  *store.SecretStore
	controller               *Controller
	server                   *control.RPCServer
	client                   *control.RPCClient
	clientPrivateKey         []byte
	listener                 net.Listener
	clock                    *testAtomicClock
	initialLeaf              *x509.Certificate
	initialCARecord          model.Certificate
	initialServerRecord      model.Certificate
	initialNodeCertificate   model.Certificate
	initialPublicCertificate model.Certificate
	initialNodes             []model.Node
	initialEnrollment        *model.EnrollmentIdentity
	preservedSecrets         map[model.SecretRef][]byte
	caCertificateIndex       int
	serverCertificateIndex   int
	nodeCertificateIndex     int
	publicCertificateIndex   int
	dataPlane                *dataPlaneMock
	handlerCalls             atomic.Int32
}

func newGatewayRenewalFixture(t *testing.T) *gatewayRenewalFixture {
	t.Helper()
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := state.Host.InitializedAt.Add(time.Hour).UTC().Truncate(time.Second)
	state.Host.NodeCIDR = "127.0.0.0/8"
	material, err := control.GenerateGatewayControlMaterial(rand.Reader, state.Host.ID, "127.0.0.1", issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	node, err := control.GenerateNodeControlCSR(rand.Reader, mutationTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	nodeIssued, err := control.IssueNodeControlCertificate(
		rand.Reader, material.ControlCACertificatePEM, material.ControlCAPrivateKeyPEM,
		node.CSRPEM, mutationTestNodeID, issuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	ca := parseCertificatePEMForRenewalTest(t, material.ControlCACertificatePEM)
	serverLeaf := parseCertificatePEMForRenewalTest(t, material.GatewayCertificatePEM)
	caRecord := gatewayRenewalCertificateRecord(
		"72000000-0000-4000-8000-000000000001", model.CertificateControlCA, state.Host.ID, ca,
		control.ControlCACertificateRef, control.ControlCAPrivateKeyRef, []string{},
	)
	serverRecord := gatewayRenewalCertificateRecord(
		"72000000-0000-4000-8000-000000000002", model.CertificateControlServer, state.Host.ID, serverLeaf,
		control.GatewayControlCertificateRef, control.GatewayControlPrivateKeyRef,
		[]string{"IP:127.0.0.1", "urn:vpnctl:gateway:" + state.Host.ID},
	)
	nodeRecord := authorizationCertificateRecord(nodeIssued, "72000000-0000-4000-8000-000000000003", 1)
	publicRecord := model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: "72000000-0000-4000-8000-000000000004",
		Kind: model.CertificatePublicIngress, OwnerKind: "host", OwnerID: state.Host.ID,
		Fingerprint: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0x33}, sha256.Size)), SerialHex: "01",
		Subject: "public ingress fixture", SANs: []string{"IP:" + state.Host.PublicIPv4},
		NotBefore: issuedAt, NotAfter: issuedAt.Add(control.ControlLeafValidity), WarningDays: 180,
		Generation: 1, CertificateRef: "public-cert:webhook", PrivateKeyRef: "public-key:webhook",
	}
	state.Generation++
	state.Nodes = append(state.Nodes, model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: mutationTestNodeID, Name: "private-1",
		Lifecycle: model.LifecycleActive, OverlayIPv4: "127.0.0.2", CredentialGeneration: 1,
		AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
		IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: issuedAt,
	})
	state.Transports = append(state.Transports, model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: mutationTestNodeID,
		Kind: model.TransportStandard, State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP,
		Port: 51820, CredentialGeneration: 1, CredentialRef: "secret:node-standard",
		PublicKey: "test-public-key", ConfigHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	state.Certificates = []model.Certificate{caRecord, serverRecord, nodeRecord, publicRecord}
	state.EnrollmentIdentity = &model.EnrollmentIdentity{
		SchemaVersion: model.ResourceSchemaVersion, Algorithm: "Ed25519", Fingerprint: material.EnrollmentFingerprint,
		PublicKeyRef: control.EnrollmentPublicKeyRef, PrivateKeyRef: control.EnrollmentPrivateKeyRef,
		Generation: 1, CreatedAt: issuedAt,
	}
	if err := stateStore.Save(1, state); err != nil {
		t.Fatal(err)
	}
	secretStore, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[model.SecretRef][]byte{
		model.SecretRef(control.ControlCACertificateRef):      material.ControlCACertificatePEM,
		control.ControlCAPrivateKeyRef:                        material.ControlCAPrivateKeyPEM,
		model.SecretRef(control.GatewayControlCertificateRef): material.GatewayCertificatePEM,
		control.GatewayControlPrivateKeyRef:                   material.GatewayPrivateKeyPEM,
		model.SecretRef(control.EnrollmentPublicKeyRef):       material.EnrollmentPublicKeyPEM,
		control.EnrollmentPrivateKeyRef:                       material.EnrollmentPrivateKeyPEM,
		model.SecretRef(nodeRecord.CertificateRef):            nodeIssued.CertificatePEM,
		model.SecretRef(publicRecord.CertificateRef):          []byte("public-ingress-certificate-canary"),
		publicRecord.PrivateKeyRef:                            []byte("public-ingress-private-key-canary"),
	}
	for reference, value := range secrets {
		if err := secretStore.PutIfAbsent(reference, value); err != nil {
			t.Fatalf("store fixture secret %s: %v", reference, err)
		}
	}
	clock := &testAtomicClock{}
	clock.Set(issuedAt)
	dataPlane := &dataPlaneMock{active: true}
	controller, err := NewController(ControllerRuntime{Paths: paths, State: stateStore, Observer: dataPlane, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, _ := NewRPCNodeAuthorizer(stateStore)
	fixture := &gatewayRenewalFixture{
		paths: paths, state: stateStore, secrets: secretStore, controller: controller, clock: clock,
		clientPrivateKey: append([]byte(nil), node.PrivateKeyPEM...),
		initialLeaf:      serverLeaf, initialCARecord: caRecord, initialServerRecord: serverRecord,
		initialNodeCertificate: nodeRecord, initialPublicCertificate: publicRecord,
		initialNodes: append([]model.Node(nil), state.Nodes...), initialEnrollment: state.EnrollmentIdentity,
		preservedSecrets: secrets, caCertificateIndex: 0, serverCertificateIndex: 1,
		nodeCertificateIndex: 2, publicCertificateIndex: 3, dataPlane: dataPlane,
	}
	handler := control.RPCHandlerFunc(func(context.Context, control.RPCPeer, control.RPCRequest) (control.RPCHandlerResult, error) {
		fixture.handlerCalls.Add(1)
		current, _ := stateStore.Load()
		return control.RPCHandlerResult{StatusCode: http.StatusOK, Response: control.NewRPCResponse("success", current.Generation, json.RawMessage(`{"ok":true}`))}, nil
	})
	protocols, err := control.NewRPCProtocolRegistryFromVersions([]string{"1.0"}, map[int]control.RPCHandler{1: handler})
	if err != nil {
		t.Fatal(err)
	}
	fixture.server, err = control.NewRPCServer(control.RPCServerConfig{
		GatewayID: state.Host.ID, NodeCIDR: state.Host.NodeCIDR,
		CertificatePEM: material.GatewayCertificatePEM, PrivateKeyPEM: material.GatewayPrivateKeyPEM,
		ClientCACertificatePEM: material.ControlCACertificatePEM, Protocols: protocols, Authorizer: authorizer, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.listener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture.client, err = control.NewRPCClient(control.RPCClientConfig{
		Address: fixture.listener.Addr().String(), GatewayID: state.Host.ID, NodeID: mutationTestNodeID,
		CACertificatePEM: material.ControlCACertificatePEM,
		CertificatePEM:   nodeIssued.CertificatePEM, PrivateKeyPEM: node.PrivateKeyPEM, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveContext, stopServer := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- fixture.server.Serve(serveContext, fixture.listener) }()
	t.Cleanup(func() {
		stopServer()
		select {
		case err := <-serveDone:
			if err != nil {
				t.Errorf("renewal RPC server shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("renewal RPC server did not stop")
		}
	})
	return fixture
}

func (fixture *gatewayRenewalFixture) call(t *testing.T, requestID string, expectedGeneration uint64) {
	t.Helper()
	request := control.RPCRequest{
		ProtocolMajor: 1, ProtocolMinor: 0, RequestID: requestID,
		ExpectedStateGeneration: expectedGeneration, NodeID: mutationTestNodeID, CredentialGeneration: 1,
		Timestamp: fixture.clock.Now(), Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, control.RPCNonceBytes)),
		Operation: "status", Payload: json.RawMessage(`{}`),
	}
	result, err := fixture.client.Call(context.Background(), request)
	if err != nil || result.StatusCode != http.StatusOK {
		t.Fatalf("control call at %s = %+v, %v", fixture.clock.Now(), result, err)
	}
}

func assertServedGatewayFingerprint(t *testing.T, fixture *gatewayRenewalFixture, expected string) {
	t.Helper()
	ca := x509.NewCertPool()
	ca.AppendCertsFromPEM(fixture.preservedSecrets[model.SecretRef(control.ControlCACertificateRef)])
	nodeCertificate, err := tls.X509KeyPair(
		fixture.preservedSecrets[model.SecretRef(fixture.initialNodeCertificate.CertificateRef)],
		mustRenewalNodeKey(t, fixture),
	)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := tls.Dial("tcp", fixture.listener.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: ca, Certificates: []tls.Certificate{nodeCertificate}, ServerName: "127.0.0.1",
		NextProtos: []string{"http/1.1"}, Time: fixture.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	peer := connection.ConnectionState().PeerCertificates[0]
	if actual := gatewayCertificateFingerprint(peer.Raw); actual != expected {
		t.Fatalf("served gateway fingerprint = %s, want %s", actual, expected)
	}
}

func mustRenewalNodeKey(t *testing.T, fixture *gatewayRenewalFixture) []byte {
	t.Helper()
	// The node private key is deliberately not in gateway state or secrets. It
	// is recovered only from the test client's immutable TLS identity below.
	return fixture.clientPrivateKey
}

func gatewayRenewalCertificateRecord(id string, kind model.CertificateKind, ownerID string, certificate *x509.Certificate, certificateRef string, privateKeyRef model.SecretRef, sans []string) model.Certificate {
	canonicalSANs := make([]string, len(sans))
	copy(canonicalSANs, sans)
	return model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: id, Kind: kind, OwnerKind: "host", OwnerID: ownerID,
		Fingerprint: gatewayCertificateFingerprint(certificate.Raw), SerialHex: certificate.SerialNumber.Text(16),
		Subject: certificate.Subject.String(), SANs: canonicalSANs,
		NotBefore: certificate.NotBefore.UTC(), NotAfter: certificate.NotAfter.UTC(), WarningDays: control.ControlWarningDays,
		Generation: 1, CertificateRef: certificateRef, PrivateKeyRef: privateKeyRef,
	}
}

func parseCertificatePEMForRenewalTest(t *testing.T, value []byte) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode(value)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("invalid certificate PEM fixture")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

type testAtomicClock struct {
	unix atomic.Int64
}

type failingRenewalStateStore struct {
	delegate *store.StateStore
}

func (store failingRenewalStateStore) Load() (model.State, error) {
	return store.delegate.Load()
}

func (failingRenewalStateStore) Save(uint64, model.State) error {
	return context.DeadlineExceeded
}

func (clock *testAtomicClock) Set(value time.Time) {
	clock.unix.Store(value.UTC().Unix())
}

func (clock *testAtomicClock) Now() time.Time {
	return time.Unix(clock.unix.Load(), 0).UTC()
}
