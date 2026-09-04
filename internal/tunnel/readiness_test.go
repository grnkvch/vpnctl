package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestPinnedFRPReconnectAndUpstreamHealthContract(t *testing.T) {
	t.Parallel()

	contract := PinnedFRPReconnectContract()
	if contract.InitialDelay != time.Second || contract.Factor != 2 || contract.Jitter != 0.1 ||
		contract.InitialMaxDelay != 10*time.Second || contract.ReconnectMaxDelay != 20*time.Second ||
		contract.FastRetryCount != 3 || contract.FastRetryDelay != 200*time.Millisecond ||
		contract.FastRetryWindow != time.Minute || contract.FastRetryJitter != 0.5 {
		t.Fatalf("pinned reconnect contract = %+v", contract)
	}
	candidate := readinessCandidate(t, "/", 2, 9)
	config := string(candidate.Bytes())
	for _, required := range []string{
		"loginFailExit = false", "healthCheck.type = \"tcp\"",
		"healthCheck.timeoutSeconds = 1", "healthCheck.maxFailed = 1", "healthCheck.intervalSeconds = 3",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("frpc config lacks %q:\n%s", required, config)
		}
	}
	if strings.Count(config, "healthCheck.type = \"tcp\"") != 2 || strings.Count(config, "serverAddr =") != 1 ||
		strings.Contains(config, "17001") || strings.Contains(config, "standby") || strings.Contains(config, "proxyURL") {
		t.Fatalf("frpc retry/health topology is not single-active:\n%s", config)
	}
	mutated := bytes.Replace(candidate.Bytes(), []byte("healthCheck.maxFailed = 1"), []byte("healthCheck.maxFailed = 2"), 1)
	if err := ValidateFRPClientConfig(mutated); err == nil {
		t.Fatal("frpc config accepted a non-canonical health withdrawal threshold")
	}
}

func TestTunnelReadinessGateBindsGenerationMappingsAndIngressDecision(t *testing.T) {
	t.Parallel()

	candidate := readinessCandidate(t, "/", 2, 9)
	result := passedTunnelReadiness(t, candidate)
	gate, err := NewTunnelReadinessGate(&staticTunnelReadinessProber{result: result})
	if err != nil {
		t.Fatal(err)
	}
	ready, observed, err := gate.Check(context.Background(), candidate)
	if err != nil || !ready.Valid() || !observed.Ready() {
		t.Fatalf("ready gate = ready:%+v observed:%+v err:%v", ready, observed, err)
	}
	expose := testExpose(testExposeA, testNodeA, "first", 20000, model.ExposeDegraded)
	if status := observed.IngressHTTPStatus(candidate.Descriptor(), expose); status != 0 {
		t.Fatalf("ready ingress status = %d", status)
	}
	if state := observed.EffectiveExposeState(candidate.Descriptor(), expose); state != model.ExposeReady {
		t.Fatalf("ready effective expose state = %s", state)
	}

	stale := result
	stale.Candidate.Generation--
	gate, _ = NewTunnelReadinessGate(&staticTunnelReadinessProber{result: stale})
	if _, observed, err := gate.Check(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "another candidate generation") ||
		observed.IngressHTTPStatus(candidate.Descriptor(), expose) != http.StatusServiceUnavailable {
		t.Fatalf("stale generation gate = observed:%+v err:%v", observed, err)
	}

	staleMapping := result
	staleMapping.Mappings = append([]TunnelMappingReadiness(nil), result.Mappings...)
	staleMapping.Mappings[0].Generation++
	gate, _ = NewTunnelReadinessGate(&staticTunnelReadinessProber{result: staleMapping})
	if _, _, err := gate.Check(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "another candidate generation") {
		t.Fatalf("stale mapping readiness error = %v", err)
	}

	degraded := result
	degraded.Mappings = append([]TunnelMappingReadiness(nil), result.Mappings...)
	degraded.Mappings[0].Upstream = failedTunnelProbe("tunnel-upstream-unavailable")
	gate, _ = NewTunnelReadinessGate(&staticTunnelReadinessProber{result: degraded})
	_, degradedObserved, degradedErr := gate.Check(context.Background(), candidate)
	if !errors.Is(degradedErr, ErrTunnelNotReady) ||
		degradedObserved.IngressHTTPStatus(candidate.Descriptor(), expose) != http.StatusServiceUnavailable {
		t.Fatalf("degraded gate = observed:%+v err:%v", degradedObserved, degradedErr)
	}
	if state := degradedObserved.EffectiveExposeState(candidate.Descriptor(), expose); state != model.ExposeDegraded {
		t.Fatalf("degraded effective expose state = %s", state)
	}
	second := testExpose(testExposeB, testNodeA, "second", 20001, model.ExposeReady)
	if status := degradedObserved.IngressHTTPStatus(candidate.Descriptor(), second); status != 0 {
		t.Fatalf("independent healthy mapping status = %d", status)
	}
	second.State = model.ExposeDisabled
	if status := degradedObserved.IngressHTTPStatus(candidate.Descriptor(), second); status != http.StatusServiceUnavailable {
		t.Fatalf("disabled expose ingress status = %d", status)
	}
	if state := degradedObserved.EffectiveExposeState(candidate.Descriptor(), second); state != model.ExposeDisabled {
		t.Fatalf("disabled effective expose state = %s", state)
	}
}

func TestFRPClientSystemReadinessChecksExactConfigStatusAndUpstreams(t *testing.T) {
	t.Parallel()

	paths, candidate := installedReadinessCandidate(t, 2)
	document, err := parseFRPClientConfig(candidate.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	status := &staticFRPStatusSource{statuses: statusesForDocument(document)}
	upstream := &recordingTunnelUpstreamProber{}
	prober, err := NewFRPClientSystemReadinessProber(paths, status, upstream)
	if err != nil {
		t.Fatal(err)
	}
	result, err := prober.Probe(context.Background(), candidate)
	if err != nil || !result.Ready() {
		t.Fatalf("system readiness = %+v, %v", result, err)
	}
	if status.password != frpAdminPassword(testTunnelCredential) || strings.Contains(fmt.Sprintf("%+v", result), testTunnelCredential) {
		t.Fatal("readiness did not use or exposed the derived loopback credential safely")
	}
	if len(upstream.calls) != 2 || upstream.calls[0] != "127.0.0.1:3000" || upstream.calls[1] != "127.0.0.1:3000" {
		t.Fatalf("upstream probe calls = %v", upstream.calls)
	}

	status.statuses[0].RemoteAddr = "10.67.0.1:20009"
	result, err = prober.Probe(context.Background(), candidate)
	if err != nil || result.MappingSet.State != TunnelProbeFailed ||
		result.IngressHTTPStatus(candidate.Descriptor(), testExpose(testExposeA, testNodeA, "first", 20000, model.ExposeReady)) != http.StatusServiceUnavailable {
		t.Fatalf("mismatched runtime mapping = %+v, %v", result, err)
	}

	status.statuses = statusesForDocument(document)
	status.err = errors.New("admin-password-canary")
	result, err = prober.Probe(context.Background(), candidate)
	if err != nil || result.Connection.State != TunnelProbeFailed || strings.Contains(fmt.Sprintf("%+v", result), "canary") {
		t.Fatalf("unavailable status = %+v, %v", result, err)
	}

	status.err = nil
	configPath, _ := frpServicePaths(paths, model.RoleNode)
	drifted := readinessCandidate(t, paths.Root, 1, candidate.Descriptor().Generation+1)
	if err := os.WriteFile(configPath, drifted.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	status.calls = 0
	result, err = prober.Probe(context.Background(), candidate)
	if err != nil || result.Configuration.State != TunnelProbeFailed || status.calls != 0 {
		t.Fatalf("config drift = result:%+v status_calls:%d err:%v", result, status.calls, err)
	}
}

func TestTunnelUpstreamProbesAreBoundedAndIndependent(t *testing.T) {
	t.Parallel()

	paths, candidate := installedReadinessCandidate(t, 2)
	document, _ := parseFRPClientConfig(candidate.Bytes())
	status := &staticFRPStatusSource{statuses: statusesForDocument(document)}
	upstream := &recordingTunnelUpstreamProber{failAddress: document.Mappings[0].NodeUpstream, distinguishCalls: true}
	prober, _ := NewFRPClientSystemReadinessProber(paths, status, upstream)
	result, err := prober.Probe(context.Background(), candidate)
	passed, failed := 0, 0
	for _, mapping := range result.Mappings {
		if mapping.Upstream.State == TunnelProbePassed {
			passed++
		} else {
			failed++
		}
	}
	if err != nil || result.Ready() || passed != 1 || failed != 1 || upstream.maximum > FRPUpstreamProbeConcurrency {
		t.Fatalf("bounded independent probes = result:%+v max:%d err:%v", result, upstream.maximum, err)
	}
}

func TestFRPHTTPStatusSourceUsesExactAuthenticatedLoopbackRequestAndStrictJSON(t *testing.T) {
	t.Parallel()

	password := strings.Repeat("a", 64)
	doer := &recordingFRPHTTPDoer{statusCode: http.StatusOK, body: `{"tcp":[{"name":"mapping","type":"tcp","status":"running","err":"","local_addr":"127.0.0.1:3000","plugin":"","remote_addr":"10.67.0.1:20000"}]}`}
	source, err := newFRPHTTPStatusSource(doer)
	if err != nil {
		t.Fatal(err)
	}
	statuses, err := source.Status(context.Background(), password)
	if err != nil || len(statuses) != 1 || statuses[0].Name != "mapping" {
		t.Fatalf("Status() = %+v, %v", statuses, err)
	}
	username, observedPassword, basicOK := doer.request.BasicAuth()
	if doer.request.Method != http.MethodGet || doer.request.URL.String() != "http://127.0.0.1:17400/api/status" ||
		!basicOK || username != "vpnctl" || observedPassword != password || doer.request.Header.Get("Accept") != "application/json" {
		t.Fatalf("status request = %+v auth=%q/%q/%t", doer.request, username, observedPassword, basicOK)
	}

	for _, body := range []string{
		`{"tcp":[],"udp":[]}`,
		`{"udp":[]}`,
		`{"tcp":[{"name":"a","name":"b","type":"tcp","status":"running","err":"","local_addr":"127.0.0.1:1","plugin":"","remote_addr":"10.0.0.1:2"}]}`,
		`{"tcp":[{"name":"a","type":"tcp","status":"running","err":"","local_addr":"127.0.0.1:1","plugin":"","remote_addr":"10.0.0.1:2","unknown":true}]}`,
		`{"tcp":[]} trailing`,
	} {
		doer.body = body
		if _, err := source.Status(context.Background(), password); err == nil || strings.Contains(err.Error(), password) {
			t.Errorf("unsafe frpc status body accepted or leaked password: %q / %v", body, err)
		}
	}
	doer.statusCode = http.StatusUnauthorized
	doer.body = "credential-canary"
	if _, err := source.Status(context.Background(), password); err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatalf("non-200 status error = %v", err)
	}
}

func readinessCandidate(t *testing.T, root string, mappingCount int, generation uint64) FRPCandidate {
	t.Helper()
	provider, err := NewFRPProvider(root, testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	session := testFRPSession(t)
	session.Mappings = session.Mappings[:mappingCount]
	candidate, err := provider.Render(context.Background(), RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: testNodeHostID, Generation: generation,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{session},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return candidate.(FRPCandidate)
}

func installedReadinessCandidate(t *testing.T, mappingCount int) (store.Paths, FRPCandidate) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(paths.ConfigDir, "generated", "node")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := readinessCandidate(t, paths.Root, mappingCount, 9)
	configPath, _ := frpServicePaths(paths, model.RoleNode)
	if err := os.WriteFile(configPath, candidate.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return paths, candidate
}

func statusesForDocument(document frpClientDocument) []FRPProxyStatus {
	statuses := make([]FRPProxyStatus, len(document.Mappings))
	for index, mapping := range document.Mappings {
		statuses[index] = FRPProxyStatus{
			Name: mapping.Name, Type: "tcp", Status: "running", LocalAddr: mapping.NodeUpstream,
			RemoteAddr: netip.AddrPortFrom(document.ServerEndpoint.Addr(), mapping.GatewayEndpoint.Port()).String(),
		}
	}
	return statuses
}

func passedTunnelReadiness(t *testing.T, candidate FRPCandidate) TunnelReadinessResult {
	t.Helper()
	document, err := parseFRPClientConfig(candidate.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	result := newTunnelReadinessResult(candidate.Descriptor(), document.Mappings)
	result.Configuration = passedTunnelProbe("tunnel-generation-ready")
	result.Connection = passedTunnelProbe("tunnel-connection-ready")
	result.MappingSet = passedTunnelProbe("tunnel-mapping-set-ready")
	for index := range result.Mappings {
		result.Mappings[index].Registration = passedTunnelProbe("tunnel-mapping-ready")
		result.Mappings[index].Upstream = passedTunnelProbe("tunnel-upstream-ready")
	}
	return result
}

type staticTunnelReadinessProber struct {
	result TunnelReadinessResult
	err    error
}

func (prober *staticTunnelReadinessProber) Probe(context.Context, FRPCandidate) (TunnelReadinessResult, error) {
	return prober.result, prober.err
}

type staticFRPStatusSource struct {
	statuses []FRPProxyStatus
	err      error
	password string
	calls    int
}

func (source *staticFRPStatusSource) Status(_ context.Context, password string) ([]FRPProxyStatus, error) {
	source.calls++
	source.password = password
	return append([]FRPProxyStatus(nil), source.statuses...), source.err
}

type recordingTunnelUpstreamProber struct {
	mu               sync.Mutex
	calls            []string
	current          int
	maximum          int
	failAddress      string
	distinguishCalls bool
}

func (prober *recordingTunnelUpstreamProber) Probe(_ context.Context, address string) error {
	prober.mu.Lock()
	prober.current++
	if prober.current > prober.maximum {
		prober.maximum = prober.current
	}
	callIndex := len(prober.calls)
	prober.calls = append(prober.calls, address)
	prober.mu.Unlock()
	if prober.distinguishCalls {
		time.Sleep(5 * time.Millisecond)
	}
	prober.mu.Lock()
	prober.current--
	prober.mu.Unlock()
	if address == prober.failAddress && (!prober.distinguishCalls || callIndex == 0) {
		return errors.New("upstream-canary")
	}
	return nil
}

type recordingFRPHTTPDoer struct {
	request    *http.Request
	statusCode int
	body       string
}

func (doer *recordingFRPHTTPDoer) Do(request *http.Request) (*http.Response, error) {
	doer.request = request
	return &http.Response{StatusCode: doer.statusCode, Body: io.NopCloser(strings.NewReader(doer.body)), Header: make(http.Header)}, nil
}
