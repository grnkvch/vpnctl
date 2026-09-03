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
	"strconv"
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

func TestNewProxyAuthorizationAllowsOnlyExactAuthoritativeMapping(t *testing.T) {
	t.Parallel()

	server, state, credentials := loginAuthorizationFixture(t)
	name, err := MappingName(testNodeA, testExposeA)
	if err != nil {
		t.Fatal(err)
	}
	content := newProxyAuthorizationContent(t, testNodeA, 1, testTunnelCredential, name, "tcp", 20000, 1)
	recorder := serveAuthorization(t, server, "NewProxy", content)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authorization status = %d", recorder.Code)
	}
	var response frpAuthorizationResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Reject || response.Unchange == nil || !*response.Unchange || response.RejectReason != "" || response.Content != nil {
		t.Fatalf("allowed response envelope = reject:%t unchange:%v reason:%q content:%v", response.Reject, response.Unchange, response.RejectReason, response.Content)
	}
	if state.loads != 1 || len(credentials.calls) != 1 || credentials.calls[0] != testNodeA+"/1" {
		t.Fatalf("authorization dependencies = state:%d credentials:%v", state.loads, credentials.calls)
	}
}

func TestNewProxyAuthorizationRejectsMaliciousStaleDisabledAndCrossNodeMappings(t *testing.T) {
	t.Parallel()

	nameA, _ := MappingName(testNodeA, testExposeA)
	nameB, _ := MappingName(testNodeB, testExposeB)
	tests := []struct {
		name        string
		nodeID      string
		token       func(*recordingAuthorizationCredentials) string
		mappingName string
		proxyType   string
		port        int64
		generation  uint64
		mutateState func(*model.State)
		wantReason  string
	}{
		{name: "unknown name", nodeID: testNodeA, mappingName: "vpnctl-n-unregistered", proxyType: "tcp", port: 20000, generation: 1, wantReason: "mapping_mismatch"},
		{name: "unsupported type", nodeID: testNodeA, mappingName: nameA, proxyType: "udp", port: 20000, generation: 1, wantReason: "mapping_mismatch"},
		{name: "arbitrary port", nodeID: testNodeA, mappingName: nameA, proxyType: "tcp", port: 20002, generation: 1, wantReason: "mapping_mismatch"},
		{name: "stale expose generation", nodeID: testNodeA, mappingName: nameA, proxyType: "tcp", port: 20000, generation: 2, wantReason: "mapping_mismatch"},
		{name: "disabled expose", nodeID: testNodeA, mappingName: nameA, proxyType: "tcp", port: 20000, generation: 1, mutateState: func(state *model.State) { state.Exposes[0].State = model.ExposeDisabled }, wantReason: "mapping_mismatch"},
		{name: "cross-node owner", nodeID: testNodeA, mappingName: nameB, proxyType: "tcp", port: 20001, generation: 1, wantReason: "mapping_mismatch"},
		{name: "cross-node identity", nodeID: testNodeB, token: func(credentials *recordingAuthorizationCredentials) string {
			return string(credentials.values[testNodeB+"/1"])
		}, mappingName: nameA, proxyType: "tcp", port: 20000, generation: 1, wantReason: "mapping_mismatch"},
		{name: "revoked node", nodeID: testNodeA, mappingName: nameA, proxyType: "tcp", port: 20000, generation: 1, mutateState: func(state *model.State) { state.Nodes[0].Lifecycle = model.LifecycleRevoked }, wantReason: "revoked"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server, state, credentials := loginAuthorizationFixture(t)
			if test.mutateState != nil {
				test.mutateState(&state.state)
			}
			token := testTunnelCredential
			if test.token != nil {
				token = test.token(credentials)
			}
			decision := server.authorizeNewProxy(newProxyAuthorizationContent(t, test.nodeID, 1, token, test.mappingName, test.proxyType, test.port, test.generation))
			if decision.allowed || decision.unavailable || decision.reason != test.wantReason {
				t.Fatalf("decision = allowed:%t unavailable:%t reason:%q", decision.allowed, decision.unavailable, decision.reason)
			}
		})
	}
}

func TestNewProxyAuthorizationReloadsStateAndFailsClosedOnAuthoritativeErrors(t *testing.T) {
	t.Parallel()

	server, state, credentials := loginAuthorizationFixture(t)
	name, _ := MappingName(testNodeA, testExposeA)
	oldContent := newProxyAuthorizationContent(t, testNodeA, 1, testTunnelCredential, name, "tcp", 20000, 1)
	if decision := server.authorizeNewProxy(oldContent); !decision.allowed {
		t.Fatalf("initial decision = %+v", decision)
	}
	state.state.Exposes[0].TunnelPort = 20002
	state.state.Exposes[0].Generation = 2
	if decision := server.authorizeNewProxy(oldContent); decision.allowed || decision.unavailable || decision.reason != "mapping_mismatch" {
		t.Fatalf("stale decision = %+v", decision)
	}
	newContent := newProxyAuthorizationContent(t, testNodeA, 1, testTunnelCredential, name, "tcp", 20002, 2)
	if decision := server.authorizeNewProxy(newContent); !decision.allowed {
		t.Fatalf("updated decision = %+v", decision)
	}

	state.err = errors.New("authoritative-state-path-canary")
	if decision := server.authorizeNewProxy(newContent); decision.allowed || !decision.unavailable || decision.reason != "controller_error" {
		t.Fatalf("state-error decision = %+v", decision)
	}
	recorder := serveAuthorization(t, server, "NewProxy", newContent)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "vpnctl authorization unavailable") ||
		strings.Contains(recorder.Body.String(), "canary") || strings.Contains(recorder.Body.String(), testTunnelCredential) {
		t.Fatalf("state-error response was not sanitized: status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	server, state, credentials = loginAuthorizationFixture(t)
	credentials.err = errors.New("credential-path-canary")
	if decision := server.authorizeNewProxy(oldContent); decision.allowed || !decision.unavailable || decision.reason != "controller_error" {
		t.Fatalf("credential-error decision = %+v", decision)
	}

	server, state, _ = loginAuthorizationFixture(t)
	state.state.Exposes = append(state.state.Exposes, state.state.Exposes[0])
	if decision := server.authorizeNewProxy(oldContent); decision.allowed || !decision.unavailable || decision.reason != "controller_error" {
		t.Fatalf("duplicate-mapping decision = %+v", decision)
	}

	server, state, _ = loginAuthorizationFixture(t)
	state.state.Exposes[0].TunnelPort = 1024
	if decision := server.authorizeNewProxy(oldContent); decision.allowed || !decision.unavailable || decision.reason != "controller_error" {
		t.Fatalf("invalid-authoritative-mapping decision = %+v", decision)
	}
}

func TestNewProxyAuthorizationRejectsMalformedIdentityAndMapping(t *testing.T) {
	t.Parallel()

	server, _, _ := loginAuthorizationFixture(t)
	name, _ := MappingName(testNodeA, testExposeA)
	valid := newProxyAuthorizationContent(t, testNodeA, 1, testTunnelCredential, name, "tcp", 20000, 1)
	tests := []struct {
		name   string
		mutate func(map[string]json.RawMessage)
	}{
		{name: "missing user", mutate: func(content map[string]json.RawMessage) { delete(content, "user") }},
		{name: "missing user metas", mutate: func(content map[string]json.RawMessage) { content["user"] = json.RawMessage(`{}`) }},
		{name: "missing mapping metas", mutate: func(content map[string]json.RawMessage) { delete(content, "metas") }},
		{name: "noncanonical generation", mutate: func(content map[string]json.RawMessage) { content["metas"] = json.RawMessage(`{"generation":"01"}`) }},
		{name: "fractional port", mutate: func(content map[string]json.RawMessage) { content["remote_port"] = json.RawMessage(`20000.0`) }},
		{name: "missing name", mutate: func(content map[string]json.RawMessage) { delete(content, "proxy_name") }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			content := cloneRawMessageMap(valid)
			defer clearRawMessageMap(content)
			test.mutate(content)
			decision := server.authorizeNewProxy(content)
			if decision.allowed || decision.unavailable {
				t.Fatalf("malformed decision = %+v", decision)
			}
		})
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
	if _, err := NewAuthorizationServer(nil, credentials); err == nil {
		t.Fatal("constructor accepted a missing state reader")
	}
	if _, err := NewAuthorizationServer(state, nil); err == nil {
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

func loginAuthorizationFixture(t *testing.T) (*AuthorizationServer, *recordingAuthorizationState, *recordingAuthorizationCredentials) {
	t.Helper()
	first := testNode(testNodeA)
	second := testNode(testNodeB)
	second.Name = "private-node-b"
	second.OverlayIPv4 = "10.67.0.3"
	state := &recordingAuthorizationState{state: model.State{
		Host:  model.Host{Role: model.RoleGateway},
		Nodes: []model.Node{first, second},
		Exposes: []model.Expose{
			testExpose(testExposeA, testNodeA, "first", 20000, model.ExposeReady),
			testExpose(testExposeB, testNodeB, "second", 20001, model.ExposeReady),
		},
	}}
	secondCredential, err := GenerateCredential(bytes.NewReader(bytes.Repeat([]byte{0x22}, CredentialBytes)))
	if err != nil {
		t.Fatal(err)
	}
	credentials := &recordingAuthorizationCredentials{values: map[string][]byte{
		testNodeA + "/1": []byte(testTunnelCredential),
		testNodeB + "/1": secondCredential,
	}}
	server, err := NewAuthorizationServer(state, credentials)
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

func serveLoginAuthorization(t *testing.T, server *AuthorizationServer, content map[string]json.RawMessage) *httptest.ResponseRecorder {
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

func newProxyAuthorizationContent(t *testing.T, nodeID string, credentialGeneration uint64, token, name, proxyType string, port int64, exposeGeneration uint64) map[string]json.RawMessage {
	t.Helper()
	identityMetadata, err := json.Marshal(map[string]string{
		"node_id": nodeID, "generation": fmt.Sprint(credentialGeneration), "tunnel_token": token,
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := json.Marshal(map[string]json.RawMessage{
		"metas": identityMetadata,
	})
	if err != nil {
		t.Fatal(err)
	}
	mappingMetadata, err := json.Marshal(map[string]string{"generation": fmt.Sprint(exposeGeneration)})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]json.RawMessage{
		"user":        user,
		"proxy_name":  json.RawMessage(strconv.Quote(name)),
		"proxy_type":  json.RawMessage(strconv.Quote(proxyType)),
		"remote_port": json.RawMessage(fmt.Sprint(port)),
		"metas":       mappingMetadata,
	}
}

func serveAuthorization(t *testing.T, server *AuthorizationServer, operation string, content map[string]json.RawMessage) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(frpAuthorizationRequest{Version: FRPAuthorizationProtocol, Op: operation, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, FRPAuthorizationPath+"?version="+FRPAuthorizationProtocol+"&op="+operation, bytes.NewReader(body))
	server.ServeHTTP(recorder, request)
	clear(body)
	return recorder
}
