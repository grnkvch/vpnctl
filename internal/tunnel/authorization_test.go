package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestLoginAuthorizationAllowsOnlyExactActiveNodeAndNormalizesPinnedPool(t *testing.T) {
	t.Parallel()

	server, state, credentials := loginAuthorizationFixture(t)
	content := loginAuthorizationContent(t, testNodeA, 1, testTunnelCredential, 1)
	content["timestamp"] = json.RawMessage("1720000000")
	content["opaque_provider_field"] = json.RawMessage(`{"preserved":true}`)
	recorder := serveLoginAuthorization(t, server, content)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authorization status = %d", recorder.Code)
	}
	var response frpAuthorizationResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Reject || response.Unchange == nil || *response.Unchange || response.RejectReason != "" {
		t.Fatalf("allowed response envelope = reject:%t unchange:%v reason:%q", response.Reject, response.Unchange, response.RejectReason)
	}
	if pool, ok := rawJSONInteger(response.Content["pool_count"]); !ok || pool != 0 {
		t.Fatalf("normalized pool count = %d, %t", pool, ok)
	}
	if string(response.Content["timestamp"]) != "1720000000" || string(response.Content["opaque_provider_field"]) != `{"preserved":true}` {
		t.Fatal("Login normalization did not preserve provider content")
	}
	metadata, ok := rawJSONObject(response.Content["metas"])
	if !ok {
		t.Fatal("allowed response omitted Login identity metadata")
	}
	defer clearRawMessageMap(metadata)
	if nodeID, _ := rawJSONString(metadata["node_id"]); nodeID != testNodeA {
		t.Fatal("allowed response changed immutable node identity")
	}
	if string(content["pool_count"]) != "1" {
		t.Fatal("authorization mutated the received request content")
	}
	if state.loads != 1 || len(credentials.calls) != 1 || credentials.calls[0] != testNodeA+"/1" {
		t.Fatalf("authorization dependencies = state:%d credentials:%v", state.loads, credentials.calls)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("authorization response headers = %v", recorder.Header())
	}
}

func TestLoginAuthorizationRejectsInvalidRevokedOldGenerationAndCrossNodeIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		mutateState   func(*model.State)
		nodeID        string
		generation    uint64
		token         string
		poolCount     int64
		wantReason    string
		wantCredReads int
	}{
		{name: "unknown node", nodeID: "20000000-0000-4000-8000-000000000099", generation: 1, token: testTunnelCredential, poolCount: 1, wantReason: "unknown_node"},
		{name: "revoked node", mutateState: func(state *model.State) { state.Nodes[0].Lifecycle = model.LifecycleRevoked }, nodeID: testNodeA, generation: 1, token: testTunnelCredential, poolCount: 1, wantReason: "revoked"},
		{name: "old generation", mutateState: func(state *model.State) { state.Nodes[0].CredentialGeneration = 2 }, nodeID: testNodeA, generation: 1, token: testTunnelCredential, poolCount: 1, wantReason: "generation_mismatch"},
		{name: "cross-node token", nodeID: testNodeB, generation: 1, token: testTunnelCredential, poolCount: 1, wantReason: "token_mismatch", wantCredReads: 1},
		{name: "invalid token", nodeID: testNodeA, generation: 1, token: "not-a-credential", poolCount: 1, wantReason: "token_mismatch", wantCredReads: 1},
		{name: "provider pool drift", nodeID: testNodeA, generation: 1, token: testTunnelCredential, poolCount: 2, wantReason: "pool_input_not_one"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server, state, credentials := loginAuthorizationFixture(t)
			if test.mutateState != nil {
				test.mutateState(&state.state)
			}
			decision := server.authorizeLogin(loginAuthorizationContent(t, test.nodeID, test.generation, test.token, test.poolCount))
			defer clearRawMessageMap(decision.content)
			if decision.allowed || decision.unavailable || decision.reason != test.wantReason || len(credentials.calls) != test.wantCredReads {
				t.Fatalf("decision = allowed:%t unavailable:%t reason:%q credential_reads:%d", decision.allowed, decision.unavailable, decision.reason, len(credentials.calls))
			}
		})
	}
}

func TestLoginAuthorizationFailsClosedOnControllerOrCredentialError(t *testing.T) {
	t.Parallel()

	server, state, credentials := loginAuthorizationFixture(t)
	state.err = errors.New("state-path-canary")
	content := loginAuthorizationContent(t, testNodeA, 1, testTunnelCredential, 1)
	decision := server.authorizeLogin(content)
	if decision.allowed || !decision.unavailable || decision.reason != "controller_error" || len(credentials.calls) != 0 {
		t.Fatalf("state-error decision = %+v", decision)
	}
	recorder := serveLoginAuthorization(t, server, content)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "vpnctl authorization unavailable") ||
		strings.Contains(recorder.Body.String(), "canary") || strings.Contains(recorder.Body.String(), testTunnelCredential) {
		t.Fatalf("state-error response was not sanitized: status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	server, state, credentials = loginAuthorizationFixture(t)
	credentials.err = errors.New("secret-path-and-value-canary")
	decision = server.authorizeLogin(content)
	if decision.allowed || !decision.unavailable || decision.reason != "controller_error" || state.loads != 1 || len(credentials.calls) != 1 {
		t.Fatalf("credential-error decision = %+v loads=%d calls=%v", decision, state.loads, credentials.calls)
	}

	server, state, credentials = loginAuthorizationFixture(t)
	state.state.Host.Role = model.RoleNode
	decision = server.authorizeLogin(content)
	if decision.allowed || !decision.unavailable || len(credentials.calls) != 0 {
		t.Fatalf("wrong-role decision = %+v", decision)
	}

	server, state, credentials = loginAuthorizationFixture(t)
	state.state.Nodes = append(state.state.Nodes, state.state.Nodes[0])
	decision = server.authorizeLogin(content)
	if decision.allowed || !decision.unavailable || decision.reason != "controller_error" || len(credentials.calls) != 0 {
		t.Fatalf("duplicate-node decision = %+v", decision)
	}

	server, _, credentials = loginAuthorizationFixture(t)
	credentials.values[testNodeA+"/1"] = []byte("invalid-stored-secret")
	decision = server.authorizeLogin(content)
	if decision.allowed || !decision.unavailable || decision.reason != "controller_error" {
		t.Fatalf("corrupt-secret decision = %+v", decision)
	}
}

func TestLoginAuthorizationHTTPBoundaryRejectsMalformedAndOverloadedRequests(t *testing.T) {
	t.Parallel()

	server, _, _ := loginAuthorizationFixture(t)
	validContent := loginAuthorizationContent(t, testNodeA, 1, testTunnelCredential, 1)
	validBody := encodeLoginAuthorizationRequest(t, validContent)
	wrongVersionBody := bytes.Replace(validBody, []byte(`"version":"0.1.0"`), []byte(`"version":"9.0.0"`), 1)
	duplicateIdentity := bytes.Replace(validBody, []byte(`"node_id":"`+testNodeA+`"`), []byte(`"node_id":"`+testNodeA+`","node_id":"`+testNodeA+`"`), 1)
	tests := []struct {
		name   string
		method string
		target string
		body   []byte
	}{
		{name: "wrong method", method: http.MethodGet, target: FRPAuthorizationPath + "?version=0.1.0&op=Login", body: validBody},
		{name: "missing version query", method: http.MethodPost, target: FRPAuthorizationPath + "?op=Login", body: validBody},
		{name: "wrong envelope version", method: http.MethodPost, target: FRPAuthorizationPath + "?version=0.1.0&op=Login", body: wrongVersionBody},
		{name: "wrong operation", method: http.MethodPost, target: FRPAuthorizationPath + "?version=0.1.0&op=NewProxy", body: validBody},
		{name: "extra query", method: http.MethodPost, target: FRPAuthorizationPath + "?version=0.1.0&op=Login&debug=true", body: validBody},
		{name: "unknown envelope field", method: http.MethodPost, target: FRPAuthorizationPath + "?version=0.1.0&op=Login", body: bytes.Replace(validBody, []byte(`{"version":`), []byte(`{"unknown":true,"version":`), 1)},
		{name: "duplicate identity", method: http.MethodPost, target: FRPAuthorizationPath + "?version=0.1.0&op=Login", body: duplicateIdentity},
		{name: "trailing document", method: http.MethodPost, target: FRPAuthorizationPath + "?version=0.1.0&op=Login", body: append(append([]byte(nil), validBody...), []byte(` {}`)...)},
		{name: "oversized", method: http.MethodPost, target: FRPAuthorizationPath + "?version=0.1.0&op=Login", body: bytes.Repeat([]byte("x"), FRPAuthorizationMaximumBytes+1)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.target, bytes.NewReader(test.body))
			server.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "vpnctl authorization denied") ||
				strings.Contains(recorder.Body.String(), testTunnelCredential) {
				t.Fatalf("malformed response = status:%d body:%q", recorder.Code, recorder.Body.String())
			}
		})
	}

	server.admission <- struct{}{}
	for len(server.admission) < cap(server.admission) {
		server.admission <- struct{}{}
	}
	recorder := serveLoginAuthorization(t, server, validContent)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "vpnctl authorization unavailable") {
		t.Fatalf("overload response = status:%d body:%q", recorder.Code, recorder.Body.String())
	}
	for len(server.admission) > 0 {
		<-server.admission
	}
}

func TestLoginAuthorizationServeRequestsOnlyFixedIPv4LoopbackListener(t *testing.T) {
	server, _, _ := loginAuthorizationFixture(t)
	requested := make(chan string, 1)
	server.listen = func(network, address string) (net.Listener, error) {
		requested <- network + " " + address
		return net.Listen("tcp4", "127.0.0.1:0")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	select {
	case value := <-requested:
		if value != "tcp4 "+FRPAuthorizationAddress {
			t.Fatalf("listener request = %q", value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authorization listener did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authorization listener did not stop")
	}
}

func TestLoginAuthorizationServeRefusesNonLoopbackListener(t *testing.T) {
	t.Parallel()

	server, _, _ := loginAuthorizationFixture(t)
	listener := &authorizationStaticListener{address: &net.TCPAddr{IP: net.IPv4zero, Port: FRPAuthorizationPort}}
	server.listen = func(string, string) (net.Listener, error) { return listener, nil }
	if err := server.Serve(context.Background()); err == nil || !strings.Contains(err.Error(), "loopback-only") || !listener.closed {
		t.Fatalf("non-loopback Serve() = %v closed=%t", err, listener.closed)
	}
}

func TestLoginAuthorizationConstructorRejectsMissingDependencies(t *testing.T) {
	t.Parallel()

	state := &recordingAuthorizationState{}
	credentials := &recordingAuthorizationCredentials{}
	if _, err := NewLoginAuthorizationServer(nil, credentials); err == nil {
		t.Fatal("constructor accepted a missing state reader")
	}
	if _, err := NewLoginAuthorizationServer(state, nil); err == nil {
		t.Fatal("constructor accepted a missing credential source")
	}
}

type recordingAuthorizationState struct {
	mu    sync.Mutex
	state model.State
	err   error
	loads int
}

type authorizationStaticListener struct {
	address net.Addr
	closed  bool
}

func (*authorizationStaticListener) Accept() (net.Conn, error) {
	return nil, errors.New("unexpected Accept")
}

func (listener *authorizationStaticListener) Close() error {
	listener.closed = true
	return nil
}

func (listener *authorizationStaticListener) Addr() net.Addr { return listener.address }

func (reader *recordingAuthorizationState) Load() (model.State, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.loads++
	if reader.err != nil {
		return model.State{}, reader.err
	}
	return reader.state, nil
}

type recordingAuthorizationCredentials struct {
	mu     sync.Mutex
	values map[string][]byte
	err    error
	calls  []string
}

func (source *recordingAuthorizationCredentials) TunnelCredential(nodeID string, generation uint64) ([]byte, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	key := fmt.Sprintf("%s/%d", nodeID, generation)
	source.calls = append(source.calls, key)
	if source.err != nil {
		return nil, source.err
	}
	value, found := source.values[key]
	if !found {
		return nil, errors.New("credential absent")
	}
	return append([]byte(nil), value...), nil
}

func loginAuthorizationFixture(t *testing.T) (*LoginAuthorizationServer, *recordingAuthorizationState, *recordingAuthorizationCredentials) {
	t.Helper()
	first := testNode(testNodeA)
	second := testNode(testNodeB)
	second.Name = "private-node-b"
	second.OverlayIPv4 = "10.67.0.3"
	state := &recordingAuthorizationState{state: model.State{
		Host:  model.Host{Role: model.RoleGateway},
		Nodes: []model.Node{first, second},
	}}
	secondCredential, err := GenerateCredential(bytes.NewReader(bytes.Repeat([]byte{0x22}, CredentialBytes)))
	if err != nil {
		t.Fatal(err)
	}
	credentials := &recordingAuthorizationCredentials{values: map[string][]byte{
		testNodeA + "/1": []byte(testTunnelCredential),
		testNodeB + "/1": secondCredential,
	}}
	server, err := NewLoginAuthorizationServer(state, credentials)
	if err != nil {
		t.Fatal(err)
	}
	return server, state, credentials
}

func loginAuthorizationContent(t *testing.T, nodeID string, generation uint64, token string, poolCount int64) map[string]json.RawMessage {
	t.Helper()
	metadata, err := json.Marshal(map[string]string{
		"node_id": nodeID, "generation": fmt.Sprint(generation), "tunnel_token": token,
	})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]json.RawMessage{
		"version":    json.RawMessage(`"0.69.0"`),
		"pool_count": json.RawMessage(fmt.Sprint(poolCount)),
		"metas":      metadata,
	}
}

func serveLoginAuthorization(t *testing.T, server *LoginAuthorizationServer, content map[string]json.RawMessage) *httptest.ResponseRecorder {
	t.Helper()
	body := encodeLoginAuthorizationRequest(t, content)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, FRPAuthorizationPath+"?version="+FRPAuthorizationProtocol+"&op=Login", bytes.NewReader(body))
	server.ServeHTTP(recorder, request)
	clear(body)
	return recorder
}

func encodeLoginAuthorizationRequest(t *testing.T, content map[string]json.RawMessage) []byte {
	t.Helper()
	body, err := json.Marshal(frpAuthorizationRequest{Version: FRPAuthorizationProtocol, Op: "Login", Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
