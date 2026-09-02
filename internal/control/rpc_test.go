package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRPCServerAndShortLivedClientUseTLS13HTTP11AndStrictIdentity(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	fixture := newRPCTestFixture(t, defaultRPCLimits(), RPCHandlerFunc(func(_ context.Context, peer RPCPeer, request RPCRequest) (RPCHandlerResult, error) {
		var payload struct {
			Probe string `json:"probe"`
		}
		if err := DecodeRPCPayload(request.Payload, &payload); err != nil {
			return RPCHandlerResult{}, err
		}
		if peer.NodeID != testNodeID || payload.Probe != "ready" {
			return RPCHandlerResult{}, errors.New("unexpected authenticated request")
		}
		calls.Add(1)
		response := NewRPCResponse("success", 42, json.RawMessage(`{"ready":true}`))
		response.ResourceIDs["node_id"] = peer.NodeID
		return RPCHandlerResult{StatusCode: http.StatusOK, Response: response}, nil
	}))

	for range 2 {
		result, err := fixture.client.Call(context.Background(), validRPCRequest(time.Now().UTC()))
		if err != nil {
			t.Fatal(err)
		}
		if result.StatusCode != http.StatusOK || result.Response.Category != "success" || result.Response.AuthoritativeGeneration != 42 ||
			result.Response.ResourceIDs["node_id"] != testNodeID {
			t.Fatalf("RPC result = %+v", result)
		}
	}
	if calls.Load() != 2 || fixture.listener.accepted.Load() < 2 {
		t.Fatalf("short-lived calls/accepted connections = %d/%d", calls.Load(), fixture.listener.accepted.Load())
	}

	mismatched := validRPCRequest(time.Now().UTC())
	mismatched.NodeID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	body, _ := json.Marshal(mismatched)
	response := fixture.rawRequest(t, body, RPCContentType, RPCPathPrefix+mismatched.Operation)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("certificate/envelope mismatch status = %d", response.StatusCode)
	}
	assertTypedRPCFailure(t, response, "identity_mismatch")
}

func TestRPCServerRejectsPublicBindingAndNonMTLSClients(t *testing.T) {
	t.Parallel()

	material, node := rpcTestIdentities(t)
	server := newTestRPCServer(t, material, defaultRPCLimits(), successRPCHandler())
	wildcard, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Serve(context.Background(), wildcard); err == nil || !strings.Contains(err.Error(), "must bind only 127.0.0.1") {
		t.Fatalf("Serve(wildcard) error = %v", err)
	}
	if _, err := wildcard.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("rejected wildcard listener remained open: %v", err)
	}

	fixture := startRPCTestFixture(t, server, material, node)
	host := fixture.listener.Addr().String()
	ca := parseCertificateForTest(t, material.ControlCACertificatePEM)
	withoutCertificate := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: newCertificatePool(ca), ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"},
	}
	if connection, err := tls.Dial("tcp", host, withoutCertificate); err == nil {
		_, _ = io.WriteString(connection, "POST /rpc/v1/status HTTP/1.1\r\nHost: control\r\nContent-Length: 0\r\n\r\n")
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		if _, readErr := connection.Read(make([]byte, 1)); readErr == nil {
			_ = connection.Close()
			t.Fatal("control RPC accepted a TLS client without a certificate")
		}
		_ = connection.Close()
	}
	tls12 := fixture.client.tlsConfig.Clone()
	tls12.MinVersion = tls.VersionTLS12
	tls12.MaxVersion = tls.VersionTLS12
	if connection, err := tls.Dial("tcp", host, tls12); err == nil {
		_ = connection.Close()
		t.Fatal("control RPC accepted TLS 1.2")
	}

	extraSANCertificate, extraSANKey := issueExtraSANNodeCertificate(t, material, node)
	extraIdentityTLS := fixture.client.tlsConfig.Clone()
	extraIdentityTLS.Certificates = []tls.Certificate{mustTLSKeyPair(t, extraSANCertificate, extraSANKey)}
	connection, err := tls.Dial("tcp", host, extraIdentityTLS)
	if err != nil {
		t.Fatalf("TLS should accept CA-valid fixture before URI boundary: %v", err)
	}
	requestBody, _ := json.Marshal(validRPCRequest(time.Now().UTC()))
	_, _ = fmt.Fprintf(connection, "POST %sstatus HTTP/1.1\r\nHost: control\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", RPCPathPrefix, len(requestBody))
	_, _ = connection.Write(requestBody)
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodPost})
	_ = connection.Close()
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("extra-SAN identity response = %v, %v", rpcResponseStatus(response), err)
	}
	assertTypedRPCFailure(t, response, "invalid_identity")
}

func TestRPCServerRejectsAmbiguousMalformedAndOversizedRequests(t *testing.T) {
	t.Parallel()

	fixture := newRPCTestFixture(t, defaultRPCLimits(), successRPCHandler())
	valid, _ := json.Marshal(validRPCRequest(time.Now().UTC()))
	unknown := append(bytes.TrimSuffix(valid, []byte("}")), []byte(`,"unknown":true}`)...)
	duplicate := bytes.Replace(valid, []byte(`"protocol_major":1`), []byte(`"protocol_major":1,"protocol_major":1`), 1)
	trailing := append(append([]byte(nil), valid...), []byte(` {}`)...)
	deepRequest := validRPCRequest(time.Now().UTC())
	deepRequest.Payload = json.RawMessage(`{"nested":` + strings.Repeat("[", RPCMaximumJSONDepth+1) + `0` + strings.Repeat("]", RPCMaximumJSONDepth+1) + `}`)
	deep, _ := json.Marshal(deepRequest)
	cases := []struct {
		name, contentType, path string
		body                    []byte
		status                  int
	}{
		{name: "malformed", contentType: RPCContentType, path: RPCPathPrefix + "status", body: []byte(`{"protocol_major":`), status: http.StatusBadRequest},
		{name: "unknown", contentType: RPCContentType, path: RPCPathPrefix + "status", body: unknown, status: http.StatusBadRequest},
		{name: "duplicate", contentType: RPCContentType, path: RPCPathPrefix + "status", body: duplicate, status: http.StatusBadRequest},
		{name: "trailing", contentType: RPCContentType, path: RPCPathPrefix + "status", body: trailing, status: http.StatusBadRequest},
		{name: "too-deep", contentType: RPCContentType, path: RPCPathPrefix + "status", body: deep, status: http.StatusBadRequest},
		{name: "wrong-content", contentType: "text/plain", path: RPCPathPrefix + "status", body: valid, status: http.StatusUnsupportedMediaType},
		{name: "wrong-operation", contentType: RPCContentType, path: RPCPathPrefix + "other", body: valid, status: http.StatusBadRequest},
		{name: "wrong-path", contentType: RPCContentType, path: "/public/status", body: valid, status: http.StatusNotFound},
		{name: "oversized", contentType: RPCContentType, path: RPCPathPrefix + "status", body: bytes.Repeat([]byte("x"), RPCMaximumRequestBytes+1), status: http.StatusRequestEntityTooLarge},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := fixture.rawRequest(t, test.body, test.contentType, test.path)
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
			}
			assertTypedRPCFailure(t, response, "")
		})
	}

	oversizedFixture := newRPCTestFixture(t, defaultRPCLimits(), RPCHandlerFunc(func(context.Context, RPCPeer, RPCRequest) (RPCHandlerResult, error) {
		response := NewRPCResponse("success", 42, json.RawMessage(`{"large":"`+strings.Repeat("x", RPCMaximumResponseBytes)+`"}`))
		return RPCHandlerResult{StatusCode: http.StatusOK, Response: response}, nil
	}))
	result, err := oversizedFixture.client.Call(context.Background(), validRPCRequest(time.Now().UTC()))
	if err != nil || result.StatusCode != http.StatusInternalServerError || result.Response.ErrorCode != "response_too_large" {
		t.Fatalf("oversized response result = %+v, %v", result, err)
	}
}

func TestRPCServerBoundsSessionsAndSlowInput(t *testing.T) {
	t.Parallel()

	limits := defaultRPCLimits()
	limits.readHeaderTimeout = 150 * time.Millisecond
	limits.readBodyTimeout = 200 * time.Millisecond
	limits.writeTimeout = 2 * time.Second
	limits.idleTimeout = 150 * time.Millisecond
	entered := make(chan struct{}, RPCMaximumConcurrentSessions)
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	handler := RPCHandlerFunc(func(_ context.Context, _ RPCPeer, request RPCRequest) (RPCHandlerResult, error) {
		if request.Operation == "hold" {
			current := active.Add(1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			entered <- struct{}{}
			<-release
			active.Add(-1)
		}
		return successRPCHandler().HandleRPC(context.Background(), RPCPeer{}, request)
	})
	fixture := newRPCTestFixture(t, limits, handler)
	hold := validRPCRequest(time.Now().UTC())
	hold.Operation = "hold"
	errorsSeen := make(chan error, RPCMaximumConcurrentSessions)
	var group sync.WaitGroup
	for range RPCMaximumConcurrentSessions {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := fixture.client.Call(context.Background(), hold)
			errorsSeen <- err
		}()
	}
	for range RPCMaximumConcurrentSessions {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("all bounded sessions did not enter")
		}
	}
	extraContext, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := fixture.client.Call(extraContext, hold); err == nil {
		t.Fatal("17th simultaneous control session was accepted")
	}
	close(release)
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("admitted control session failed: %v", err)
		}
	}
	if maximum.Load() != RPCMaximumConcurrentSessions {
		t.Fatalf("maximum handler concurrency = %d", maximum.Load())
	}

	connection, err := tls.Dial("tcp", fixture.listener.Addr().String(), fixture.client.tlsConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, _ = io.WriteString(connection, "POST /rpc/v1/status HTTP/1.1\r\nHost: control\r\nX-Slow:")
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	_, readErr := connection.Read(buffer)
	_ = connection.Close()
	if readErr == nil || time.Since(start) > time.Second {
		t.Fatalf("slow header was not bounded: %s, %v", time.Since(start), readErr)
	}

	connection, err = tls.Dial("tcp", fixture.listener.Addr().String(), fixture.client.tlsConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(connection, "POST /rpc/v1/status HTTP/1.1\r\nHost: control\r\nContent-Type: application/json\r\nX-Oversized: %s\r\nContent-Length: 0\r\n\r\n", strings.Repeat("h", 2*RPCMaximumHeaderBytes))
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	start = time.Now()
	headerResponse, headerErr := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodPost})
	_ = connection.Close()
	if headerResponse != nil {
		_ = headerResponse.Body.Close()
	}
	if time.Since(start) > time.Second || (headerErr == nil && headerResponse.StatusCode != http.StatusRequestHeaderFieldsTooLarge) {
		t.Fatalf("oversized header was not bounded: %s, %v", time.Since(start), headerErr)
	}

	connection, err = tls.Dial("tcp", fixture.listener.Addr().String(), fixture.client.tlsConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(connection, "POST /rpc/v1/status HTTP/1.1\r\nHost: control\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
	start = time.Now()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	_, readErr = connection.Read(buffer)
	_ = connection.Close()
	if time.Since(start) < 100*time.Millisecond || time.Since(start) > time.Second {
		t.Fatalf("slow body was not bounded: %s, %v", time.Since(start), readErr)
	}

	writeLimits := limits
	writeLimits.writeTimeout = 150 * time.Millisecond
	writeFixture := newRPCTestFixture(t, writeLimits, RPCHandlerFunc(func(ctx context.Context, _ RPCPeer, _ RPCRequest) (RPCHandlerResult, error) {
		<-ctx.Done()
		return RPCHandlerResult{}, ctx.Err()
	}))
	start = time.Now()
	writeResult, writeErr := writeFixture.client.Call(context.Background(), validRPCRequest(time.Now().UTC()))
	if time.Since(start) < 100*time.Millisecond || time.Since(start) > time.Second || (writeErr == nil && writeResult.StatusCode != http.StatusInternalServerError) {
		t.Fatalf("slow write was not bounded: %s, %+v, %v", time.Since(start), writeResult, writeErr)
	}
}

func TestRPCCodecsAndPayloadRejectAmbiguousShapes(t *testing.T) {
	t.Parallel()

	request := validRPCRequest(time.Now().UTC())
	encoded, _ := json.Marshal(request)
	if decoded, err := DecodeRPCRequest(encoded); err != nil || decoded.Operation != "status" {
		t.Fatalf("DecodeRPCRequest(valid) = %+v, %v", decoded, err)
	}
	if err := DecodeRPCPayload(json.RawMessage(`{"probe":"ok","unknown":true}`), &struct {
		Probe string `json:"probe"`
	}{}); err == nil {
		t.Fatal("DecodeRPCPayload accepted an unknown typed field")
	}
	response := NewRPCResponse("success", 1, json.RawMessage(`{"ok":true}`))
	responseBytes, _ := json.Marshal(response)
	if decoded, err := DecodeRPCResponse(responseBytes); err != nil || decoded.Category != "success" {
		t.Fatalf("DecodeRPCResponse(valid) = %+v, %v", decoded, err)
	}
	for _, invalid := range [][]byte{
		append(bytes.TrimSuffix(responseBytes, []byte("}")), []byte(`,"unknown":true}`)...),
		bytes.Replace(responseBytes, []byte(`"category":"success"`), []byte(`"category":"success","category":"internal"`), 1),
		append(append([]byte(nil), responseBytes...), []byte(` {}`)...),
	} {
		if _, err := DecodeRPCResponse(invalid); err == nil {
			t.Fatalf("DecodeRPCResponse accepted %s", invalid)
		}
	}
	limits := defaultRPCLimits()
	if limits.maximumRequestBytes != RPCMaximumRequestBytes || limits.maximumResponseBytes != RPCMaximumResponseBytes ||
		limits.maximumHeaderBytes != RPCMaximumHeaderBytes || limits.maximumConcurrentSessions != RPCMaximumConcurrentSessions ||
		limits.readHeaderTimeout != RPCReadHeaderTimeout || limits.readBodyTimeout != RPCReadBodyTimeout || limits.writeTimeout != RPCWriteTimeout || limits.idleTimeout != RPCIdleTimeout {
		t.Fatalf("production RPC limits drifted: %+v", limits)
	}
}

type rpcTestFixture struct {
	client   *RPCClient
	listener *rpcCountingListener
	cancel   context.CancelFunc
	done     chan error
}

func newRPCTestFixture(t *testing.T, limits rpcLimits, handler RPCHandler) *rpcTestFixture {
	t.Helper()
	material, node := rpcTestIdentities(t)
	server := newTestRPCServer(t, material, limits, handler)
	return startRPCTestFixture(t, server, material, node)
}

func newTestRPCServer(t *testing.T, material GatewayControlMaterial, limits rpcLimits, handler RPCHandler) *RPCServer {
	t.Helper()
	server, err := newRPCServer(RPCServerConfig{
		GatewayID: testGatewayID, NodeCIDR: "127.0.0.0/8",
		CertificatePEM: material.GatewayCertificatePEM, PrivateKeyPEM: material.GatewayPrivateKeyPEM,
		ClientCACertificatePEM: material.ControlCACertificatePEM, Handler: handler,
	}, limits)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func startRPCTestFixture(t *testing.T, server *RPCServer, material GatewayControlMaterial, node NodeCSRMaterial) *rpcTestFixture {
	t.Helper()
	base, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &rpcCountingListener{Listener: base}
	client, err := NewRPCClient(RPCClientConfig{
		Address: listener.Addr().String(), GatewayID: testGatewayID, NodeID: testNodeID,
		CACertificatePEM: material.ControlCACertificatePEM, CertificatePEM: nodeCertificatePEM(t, material, node), PrivateKeyPEM: node.PrivateKeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	fixture := &rpcTestFixture{client: client, listener: listener, cancel: cancel, done: done}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("RPC server shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("RPC server did not stop")
		}
	})
	return fixture
}

func rpcTestIdentities(t *testing.T) (GatewayControlMaterial, NodeCSRMaterial) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	material, err := GenerateGatewayControlMaterial(rand.Reader, testGatewayID, "127.0.0.1", now)
	if err != nil {
		t.Fatal(err)
	}
	node, err := GenerateNodeControlCSR(rand.Reader, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	return material, node
}

func nodeCertificatePEM(t *testing.T, material GatewayControlMaterial, node NodeCSRMaterial) []byte {
	t.Helper()
	issued, err := IssueNodeControlCertificate(rand.Reader, material.ControlCACertificatePEM, material.ControlCAPrivateKeyPEM, node.CSRPEM, testNodeID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return issued.CertificatePEM
}

func validRPCRequest(now time.Time) RPCRequest {
	return RPCRequest{
		ProtocolMajor: 1, ProtocolMinor: 0, RequestID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		ExpectedStateGeneration: 42, NodeID: testNodeID, CredentialGeneration: 7, Timestamp: now,
		Nonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, RPCNonceBytes)), Operation: "status",
		Payload: json.RawMessage(`{"probe":"ready"}`),
	}
}

func successRPCHandler() RPCHandler {
	return RPCHandlerFunc(func(context.Context, RPCPeer, RPCRequest) (RPCHandlerResult, error) {
		return RPCHandlerResult{StatusCode: http.StatusOK, Response: NewRPCResponse("success", 42, json.RawMessage(`{"ok":true}`))}, nil
	})
}

func (fixture *rpcTestFixture) rawRequest(t *testing.T, body []byte, contentType, path string) *http.Response {
	t.Helper()
	connection, err := tls.Dial("tcp", fixture.listener.Addr().String(), fixture.client.tlsConfig.Clone())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintf(connection, "POST %s HTTP/1.1\r\nHost: control\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", path, contentType, len(body))
	_, _ = connection.Write(body)
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodPost})
	_ = connection.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func assertTypedRPCFailure(t *testing.T, response *http.Response, errorCode string) {
	t.Helper()
	defer response.Body.Close()
	body, err := readBoundedBody(response.Body, RPCMaximumResponseBytes)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRPCResponse(body)
	if err != nil || decoded.Category == "success" || (errorCode != "" && decoded.ErrorCode != errorCode) {
		t.Fatalf("typed failure = %+v, %v", decoded, err)
	}
}

func issueExtraSANNodeCertificate(t *testing.T, material GatewayControlMaterial, node NodeCSRMaterial) ([]byte, []byte) {
	t.Helper()
	ca, caKey, err := parseControlAuthority(material.ControlCACertificatePEM, material.ControlCAPrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	nodeKey := parseEd25519PrivateKeyForTest(t, node.PrivateKeyPEM)
	identity, _ := url.Parse("urn:vpnctl:node:" + testNodeID)
	now := time.Now().UTC()
	serial, _ := randomPositiveSerial(rand.Reader)
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "invalid extra-SAN node"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity}, DNSNames: []string{"extra.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, nodeKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), node.PrivateKeyPEM
}

func mustTLSKeyPair(t *testing.T, certificate, key []byte) tls.Certificate {
	t.Helper()
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

type rpcCountingListener struct {
	net.Listener
	accepted atomic.Int32
}

func (listener *rpcCountingListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err == nil {
		listener.accepted.Add(1)
	}
	return connection, err
}

func rpcResponseStatus(response *http.Response) any {
	if response == nil {
		return nil
	}
	return response.StatusCode
}
