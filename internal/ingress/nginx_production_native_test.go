package ingress

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const (
	nginxProductionRuntimeEnvironment = "VPNCTL_NGINX_PRODUCTION_RUNTIME"
	nginxProductionSummaryEnvironment = "VPNCTL_NGINX_PRODUCTION_SUMMARY"
	nginxProductionPublicIPv4         = "192.0.2.10"
	nginxProductionMemoryMaximum      = 128 << 20
)

// TestNginxProductionRuntimeRegression is opt-in because it starts the exact
// pinned nginx runtime. It is compiled into the task-12.11 minimum-host gate
// and exercises the production renderer rather than the older spike template.
func TestNginxProductionRuntimeRegression(t *testing.T) {
	binary := os.Getenv(nginxProductionRuntimeEnvironment)
	if binary == "" {
		t.Skip("set VPNCTL_NGINX_PRODUCTION_RUNTIME to the pinned nginx binary")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Fatal("production nginx regression requires root on Linux")
	}
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		t.Fatal("VPNCTL_NGINX_PRODUCTION_RUNTIME must be a clean absolute path")
	}

	coordinator := &nginxProductionCoordinator{}
	echo := newNginxProductionUpstream(t, coordinator, false)
	loadA := newNginxProductionUpstream(t, coordinator, true)
	loadB := newNginxProductionUpstream(t, coordinator, true)
	bodyGuard := newNginxProductionUpstream(t, coordinator, false)
	abort := newNginxFaultUpstream(t, nginxFaultAbortBeforeHeaders)
	timeout := newNginxFaultUpstream(t, nginxFaultTimeoutBeforeHeaders)
	edgePort := reserveNginxRuntimePort(t)

	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	runtimeDirectory := filepath.Join(root, "run")
	secretDirectory := filepath.Join(root, "secrets")
	for _, path := range []string{
		runtimeDirectory,
		filepath.Join(runtimeDirectory, "client-body"),
		filepath.Join(runtimeDirectory, "proxy"),
		secretDirectory,
	} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	material, err := GeneratePublicCertificate(rand.Reader, nginxProductionPublicIPv4, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.PrivateKeyPEM)
	certificatePath := filepath.Join(secretDirectory, "gateway.crt")
	privateKeyPath := filepath.Join(secretDirectory, "gateway.key")
	if err := os.WriteFile(certificatePath, material.CertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privateKeyPath, material.PrivateKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	request := nginxRenderFixture()
	request.CertificatePath = certificatePath
	request.PrivateKeyPath = privateKeyPath
	request.RuntimeDirectory = runtimeDirectory
	request.Exposes = []model.Expose{
		nginxProductionExpose("91000000-0000-4000-8000-000000000001", "/echo", model.RoutePrefix, echo.Port(), 1<<20, 3),
		nginxProductionExpose("91000000-0000-4000-8000-000000000002", "/load/a", model.RouteExact, loadA.Port(), 1<<20, 3),
		nginxProductionExpose("91000000-0000-4000-8000-000000000003", "/load/b", model.RouteExact, loadB.Port(), 1<<20, 3),
		nginxProductionExpose("91000000-0000-4000-8000-000000000004", "/unavailable", model.RouteExact, abort.Port(), 64<<10, 3),
		nginxProductionExpose("91000000-0000-4000-8000-000000000005", "/timeout", model.RouteExact, timeout.Port(), 64<<10, 1),
		nginxProductionExpose("91000000-0000-4000-8000-000000000006", "/body-limit", model.RouteExact, bodyGuard.Port(), 32, 3),
	}
	candidate, err := RenderNginxConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	writeNginxProductionRuntimeCandidate(t, root, candidate, edgePort)
	if err := ValidatePinnedNginxConfig(context.Background(), linuxplatform.OSProbeRunner{}, binary, root); err != nil {
		t.Fatal(err)
	}
	nginx := startNginxRuntime(t, binary, root, edgePort)
	t.Cleanup(nginx.Stop)

	http1 := nginxProductionClient(t, edgePort, false)
	http2 := nginxProductionClient(t, edgePort, true)
	http1Body := bytes.Repeat([]byte("h1-body-canary-"), 32*1024)
	http2Body := bytes.Repeat([]byte("h2-body-canary-"), 4*1024)
	assertNginxProductionForwarding(t, http1, "/echo/subroute?alpha=1&alpha=2&encoded=%2F", http1Body, "HTTP/1.1", edgePort)
	assertNginxProductionForwarding(t, http2, "/echo/subroute?alpha=1&alpha=2&encoded=%2F", http2Body, "HTTP/2.0", edgePort)

	assertNginxProductionStatus(t, http1, "/missing", []byte("unknown"), http.StatusNotFound)
	assertNginxProductionStatus(t, http1, "/unavailable", []byte("unavailable"), http.StatusServiceUnavailable)
	assertNginxProductionStatus(t, http1, "/timeout", []byte("timeout"), http.StatusGatewayTimeout)
	assertNginxProductionStatus(t, http1, "/body-limit", bytes.Repeat([]byte("x"), 33), http.StatusRequestEntityTooLarge)
	if bodyGuard.Requests() != 0 {
		t.Fatal("over-limit request reached the production upstream")
	}

	maximumRSS := int64(0)
	safePhase := coordinator.Begin(t, 32)
	safeResults := runNginxProductionMixedLoad(t, http1, http2, 16, 16, "/load/a")
	safePhase.Wait(t)
	maximumRSS = max(maximumRSS, nginxProductionRSS(t, nginx.command.Process.Pid))
	safePhase.Release()
	safe := safeResults.Wait(t)
	coordinator.Finish(safePhase)
	assertNginxProductionCounts(t, safe, map[int]int{http.StatusOK: 32})
	if safe.Protocols["HTTP/1.1"] != 16 || safe.Protocols["HTTP/2.0"] != 16 {
		t.Fatalf("mixed safe protocols = %+v", safe.Protocols)
	}

	exposePhase := coordinator.Begin(t, DefaultExposeConcurrentRequests)
	exposeResults := runNginxProductionLoad(http1, 45, func(int) string { return "/load/a" })
	exposePhase.Wait(t)
	maximumRSS = max(maximumRSS, nginxProductionRSS(t, nginx.command.Process.Pid))
	time.Sleep(250 * time.Millisecond)
	exposePhase.Release()
	expose := exposeResults.Wait(t)
	coordinator.Finish(exposePhase)
	assertNginxProductionCounts(t, expose, map[int]int{http.StatusOK: 40, http.StatusServiceUnavailable: 5})

	gatewayPhase := coordinator.Begin(t, DefaultIngressGatewayConcurrentRequests)
	gatewayResults := runNginxProductionLoad(http1, 72, func(index int) string {
		if index%2 == 0 {
			return "/load/a"
		}
		return "/load/b"
	})
	gatewayPhase.Wait(t)
	maximumRSS = max(maximumRSS, nginxProductionRSS(t, nginx.command.Process.Pid))
	time.Sleep(250 * time.Millisecond)
	gatewayPhase.Release()
	gateway := gatewayResults.Wait(t)
	coordinator.Finish(gatewayPhase)
	assertNginxProductionCounts(t, gateway, map[int]int{http.StatusOK: 64, http.StatusServiceUnavailable: 8})

	if maximumRSS <= 0 || maximumRSS >= nginxProductionMemoryMaximum {
		t.Fatalf("production nginx RSS = %d bytes, expected 1..%d", maximumRSS, nginxProductionMemoryMaximum-1)
	}
	bodyFiles := 0
	for _, path := range []string{filepath.Join(runtimeDirectory, "client-body"), filepath.Join(runtimeDirectory, "proxy")} {
		bodyFiles += len(regularFilesUnder(t, path))
	}
	if bodyFiles != 0 {
		t.Fatalf("production nginx persisted %d request/response body files", bodyFiles)
	}

	summary := nginxProductionSummary{
		SchemaVersion: 1, Status: "passed", NginxVersion: NginxProviderRuntimeVersion,
		HTTP1Forwarding: true, HTTP2Forwarding: true, UpstreamHTTP11: true,
		PathQueryHeadersBody: true,
		SafeConcurrent:       safe.Statuses[http.StatusOK],
		ExposeAccepted:       expose.Statuses[http.StatusOK], ExposeRejected: expose.Statuses[http.StatusServiceUnavailable],
		GatewayAccepted: gateway.Statuses[http.StatusOK], GatewayRejected: gateway.Statuses[http.StatusServiceUnavailable],
		UnknownStatus: http.StatusNotFound, BodyLimitStatus: http.StatusRequestEntityTooLarge,
		UnavailableStatus: http.StatusServiceUnavailable, TimeoutStatus: http.StatusGatewayTimeout,
		MaximumRSSBytes: maximumRSS, BodyTempFiles: bodyFiles, RequestReplay: false,
	}
	writeNginxProductionSummary(t, summary)
	t.Logf("production ingress root=%s edge=127.0.0.1:%d maximum_rss_bytes=%d", root, edgePort, maximumRSS)
}

type nginxProductionSummary struct {
	SchemaVersion        int    `json:"schema_version"`
	Status               string `json:"status"`
	NginxVersion         string `json:"nginx_version"`
	HTTP1Forwarding      bool   `json:"http1_forwarding"`
	HTTP2Forwarding      bool   `json:"http2_forwarding"`
	UpstreamHTTP11       bool   `json:"upstream_http11"`
	PathQueryHeadersBody bool   `json:"path_query_headers_body"`
	SafeConcurrent       int    `json:"safe_concurrent"`
	ExposeAccepted       int    `json:"expose_accepted"`
	ExposeRejected       int    `json:"expose_rejected"`
	GatewayAccepted      int    `json:"gateway_accepted"`
	GatewayRejected      int    `json:"gateway_rejected"`
	UnknownStatus        int    `json:"unknown_status"`
	BodyLimitStatus      int    `json:"body_limit_status"`
	UnavailableStatus    int    `json:"unavailable_status"`
	TimeoutStatus        int    `json:"timeout_status"`
	MaximumRSSBytes      int64  `json:"maximum_rss_bytes"`
	BodyTempFiles        int    `json:"body_temp_files"`
	RequestReplay        bool   `json:"request_replay"`
}

func nginxProductionExpose(id, path string, mode model.RouteMode, port int, bodyLimit int64, timeout int) model.Expose {
	expose := nginxExposeFixture(id, path, mode, port, model.ExposeReady)
	expose.BodyLimitBytes = bodyLimit
	expose.UpstreamTimeoutSeconds = timeout
	return expose
}

func writeNginxProductionRuntimeCandidate(t *testing.T, root string, candidate NginxCandidate, edgePort int) {
	t.Helper()
	for _, artifact := range candidate.Artifacts() {
		content := artifact.Bytes()
		if artifact.RelativePath() == NginxMainConfigPath {
			oldListen := []byte("listen 0.0.0.0:443 ssl http2;")
			newListen := []byte("listen 127.0.0.1:" + strconv.Itoa(edgePort) + " ssl http2;")
			if bytes.Count(content, oldListen) != 1 {
				t.Fatal("production candidate public listener count is not one")
			}
			content = bytes.Replace(content, oldListen, newListen, 1)
		}
		path := filepath.Join(root, filepath.FromSlash(artifact.RelativePath()))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, artifact.Mode()); err != nil {
			t.Fatal(err)
		}
	}
}

func nginxProductionClient(t *testing.T, edgePort int, http2 bool) *http.Client {
	t.Helper()
	tlsConfig := &tls.Config{ // Test-only certificate and isolated loopback endpoint.
		InsecureSkipVerify: true, //nolint:gosec
		ServerName:         nginxProductionPublicIPv4,
		MinVersion:         tls.VersionTLS12,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig, ForceAttemptHTTP2: http2, DisableKeepAlives: !http2,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(edgePort)))
		},
	}
	if !http2 {
		tlsConfig.NextProtos = []string{"http/1.1"}
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	return client
}

type nginxProductionObservation struct {
	Method               string `json:"method"`
	RequestURI           string `json:"request_uri"`
	Protocol             string `json:"protocol"`
	Host                 string `json:"host"`
	Authorization        string `json:"authorization"`
	TelegramSecret       string `json:"telegram_secret"`
	Forwarded            string `json:"forwarded"`
	ForwardedFor         string `json:"forwarded_for"`
	ForwardedHost        string `json:"forwarded_host"`
	ForwardedPort        string `json:"forwarded_port"`
	ForwardedProto       string `json:"forwarded_proto"`
	RealIP               string `json:"real_ip"`
	OriginalForwardedFor string `json:"original_forwarded_for"`
	ForwardedClientCert  string `json:"forwarded_client_cert"`
	ForwardedPrefix      string `json:"forwarded_prefix"`
	BodyBytes            int    `json:"body_bytes"`
	BodySHA256           string `json:"body_sha256"`
}

func assertNginxProductionForwarding(t *testing.T, client *http.Client, requestURI string, body []byte, protocol string, edgePort int) {
	t.Helper()
	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, "https://"+nginxProductionPublicIPv4+requestURI, bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer non-secret-test-value")
	request.Header.Set("X-Telegram-Bot-Api-Secret-Token", "non-secret-provider-header")
	request.Header.Set("Forwarded", "for=198.51.100.20;proto=http")
	request.Header.Set("X-Forwarded-For", "198.51.100.20")
	request.Header.Set("X-Forwarded-Host", "attacker.example")
	request.Header.Set("X-Forwarded-Port", "80")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Forwarded-Prefix", "/attacker")
	request.Header.Set("X-Forwarded-Client-Cert", "attacker")
	request.Header.Set("X-Original-Forwarded-For", "198.51.100.20")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Proto != protocol {
		t.Fatalf("frontend response status/protocol = %d/%s, want 200/%s: %s", response.StatusCode, response.Proto, protocol, payload)
	}
	var observed nginxProductionObservation
	if err := json.Unmarshal(payload, &observed); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if observed.Method != http.MethodPost || observed.RequestURI != requestURI || observed.Protocol != "HTTP/1.1" ||
		observed.Host != nginxProductionPublicIPv4 || observed.Authorization != "Bearer non-secret-test-value" ||
		observed.TelegramSecret != "non-secret-provider-header" || observed.Forwarded != "" ||
		observed.ForwardedFor != "127.0.0.1" || observed.RealIP != "127.0.0.1" ||
		observed.ForwardedHost != nginxProductionPublicIPv4 || observed.ForwardedPort != strconv.Itoa(edgePort) ||
		observed.ForwardedProto != "https" || observed.ForwardedPrefix != "" || observed.ForwardedClientCert != "" ||
		observed.OriginalForwardedFor != "" || observed.BodyBytes != len(body) || observed.BodySHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("production forwarding observation = %+v", observed)
	}
}

func assertNginxProductionStatus(t *testing.T, client *http.Client, path string, body []byte, status int) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+nginxProductionPublicIPv4+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != status {
		t.Fatalf("POST %s status = %d, want %d", path, response.StatusCode, status)
	}
}

type nginxProductionCoordinator struct {
	mu      sync.Mutex
	current *nginxProductionPhase
}

type nginxProductionPhase struct {
	target      int
	arrived     chan struct{}
	release     chan struct{}
	arriveOnce  sync.Once
	releaseOnce sync.Once
	mu          sync.Mutex
	active      int
	maximum     int
}

func (coordinator *nginxProductionCoordinator) Begin(t *testing.T, target int) *nginxProductionPhase {
	t.Helper()
	phase := &nginxProductionPhase{target: target, arrived: make(chan struct{}), release: make(chan struct{})}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.current != nil {
		t.Fatal("production concurrency phase already active")
	}
	coordinator.current = phase
	t.Cleanup(phase.Release)
	return phase
}

func (coordinator *nginxProductionCoordinator) Hold() {
	coordinator.mu.Lock()
	phase := coordinator.current
	coordinator.mu.Unlock()
	if phase == nil {
		return
	}
	phase.mu.Lock()
	phase.active++
	phase.maximum = max(phase.maximum, phase.active)
	if phase.active >= phase.target {
		phase.arriveOnce.Do(func() { close(phase.arrived) })
	}
	phase.mu.Unlock()
	<-phase.release
	phase.mu.Lock()
	phase.active--
	phase.mu.Unlock()
}

func (phase *nginxProductionPhase) Wait(t *testing.T) {
	t.Helper()
	select {
	case <-phase.arrived:
	case <-time.After(10 * time.Second):
		phase.Release()
		t.Fatalf("production upstream did not reach %d concurrent requests", phase.target)
	}
}

func (phase *nginxProductionPhase) Release() {
	phase.arriveOnce.Do(func() { close(phase.arrived) })
	phase.releaseOnce.Do(func() { close(phase.release) })
}

func (coordinator *nginxProductionCoordinator) Finish(phase *nginxProductionPhase) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.current == phase {
		coordinator.current = nil
	}
}

type nginxProductionUpstream struct {
	server      *http.Server
	listener    net.Listener
	coordinator *nginxProductionCoordinator
	hold        bool
	requests    int
	mu          sync.Mutex
}

func newNginxProductionUpstream(t *testing.T, coordinator *nginxProductionCoordinator, hold bool) *nginxProductionUpstream {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &nginxProductionUpstream{listener: listener, coordinator: coordinator, hold: hold}
	upstream.server = &http.Server{
		Handler:           http.HandlerFunc(upstream.serveHTTP),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       3 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() { _ = upstream.server.Serve(listener) }()
	t.Cleanup(func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = upstream.server.Shutdown(shutdown)
	})
	return upstream
}

func (upstream *nginxProductionUpstream) Port() int {
	return upstream.listener.Addr().(*net.TCPAddr).Port
}

func (upstream *nginxProductionUpstream) Requests() int {
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	return upstream.requests
}

func (upstream *nginxProductionUpstream) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	upstream.mu.Lock()
	upstream.requests++
	upstream.mu.Unlock()
	body, err := io.ReadAll(io.LimitReader(request.Body, (1<<20)+1))
	_ = request.Body.Close()
	if err != nil || len(body) > 1<<20 {
		http.Error(writer, "invalid body", http.StatusBadRequest)
		return
	}
	if upstream.hold {
		upstream.coordinator.Hold()
	}
	digest := sha256.Sum256(body)
	observation := nginxProductionObservation{
		Method: request.Method, RequestURI: request.RequestURI, Protocol: request.Proto, Host: request.Host,
		Authorization: request.Header.Get("Authorization"), TelegramSecret: request.Header.Get("X-Telegram-Bot-Api-Secret-Token"),
		Forwarded: request.Header.Get("Forwarded"), ForwardedFor: request.Header.Get("X-Forwarded-For"),
		ForwardedHost: request.Header.Get("X-Forwarded-Host"), ForwardedPort: request.Header.Get("X-Forwarded-Port"),
		ForwardedProto: request.Header.Get("X-Forwarded-Proto"), RealIP: request.Header.Get("X-Real-IP"),
		OriginalForwardedFor: request.Header.Get("X-Original-Forwarded-For"),
		ForwardedClientCert:  request.Header.Get("X-Forwarded-Client-Cert"),
		ForwardedPrefix:      request.Header.Get("X-Forwarded-Prefix"),
		BodyBytes:            len(body), BodySHA256: hex.EncodeToString(digest[:]),
	}
	payload, _ := json.Marshal(observation)
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(payload)
}

type nginxProductionLoadResult struct {
	Statuses  map[int]int
	Protocols map[string]int
	Errors    []error
}

type nginxProductionPendingLoad struct {
	done   chan struct{}
	result nginxProductionLoadResult
}

func runNginxProductionLoad(client *http.Client, requests int, path func(int) string) *nginxProductionPendingLoad {
	start := make(chan struct{})
	pending := &nginxProductionPendingLoad{done: make(chan struct{}), result: nginxProductionLoadResult{
		Statuses: map[int]int{}, Protocols: map[string]int{}, Errors: []error{},
	}}
	var wait sync.WaitGroup
	var mutex sync.Mutex
	for index := 0; index < requests; index++ {
		wait.Add(1)
		go func(requestIndex int) {
			defer wait.Done()
			<-start
			status, protocol, err := nginxProductionLoadRequest(client, path(requestIndex))
			mutex.Lock()
			defer mutex.Unlock()
			if err != nil {
				pending.result.Errors = append(pending.result.Errors, err)
				return
			}
			pending.result.Statuses[status]++
			pending.result.Protocols[protocol]++
		}(index)
	}
	close(start)
	go func() {
		wait.Wait()
		close(pending.done)
	}()
	return pending
}

func runNginxProductionMixedLoad(t *testing.T, http1, http2 *http.Client, h1Count, h2Count int, path string) *nginxProductionPendingLoad {
	t.Helper()
	start := make(chan struct{})
	pending := &nginxProductionPendingLoad{done: make(chan struct{}), result: nginxProductionLoadResult{
		Statuses: map[int]int{}, Protocols: map[string]int{}, Errors: []error{},
	}}
	var wait sync.WaitGroup
	var mutex sync.Mutex
	launch := func(client *http.Client, count int) {
		for range count {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				status, protocol, err := nginxProductionLoadRequest(client, path)
				mutex.Lock()
				defer mutex.Unlock()
				if err != nil {
					pending.result.Errors = append(pending.result.Errors, err)
					return
				}
				pending.result.Statuses[status]++
				pending.result.Protocols[protocol]++
			}()
		}
	}
	launch(http1, h1Count)
	launch(http2, h2Count)
	close(start)
	go func() {
		wait.Wait()
		close(pending.done)
	}()
	return pending
}

func nginxProductionLoadRequest(client *http.Client, path string) (int, string, error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://"+nginxProductionPublicIPv4+path, strings.NewReader("load"))
	if err != nil {
		return 0, "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, "", err
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return 0, "", err
	}
	return response.StatusCode, response.Proto, nil
}

func (pending *nginxProductionPendingLoad) Wait(t *testing.T) nginxProductionLoadResult {
	t.Helper()
	select {
	case <-pending.done:
	case <-time.After(15 * time.Second):
		t.Fatal("production nginx load did not complete")
	}
	return pending.result
}

func assertNginxProductionCounts(t *testing.T, result nginxProductionLoadResult, wanted map[int]int) {
	t.Helper()
	if len(result.Errors) != 0 || !equalNginxProductionStatusCounts(result.Statuses, wanted) {
		t.Fatalf("production concurrency result statuses=%v errors=%v, want=%v", result.Statuses, result.Errors, wanted)
	}
}

func equalNginxProductionStatusCounts(left, right map[int]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func nginxProductionRSS(t *testing.T, masterPID int) int64 {
	t.Helper()
	seen := map[int]struct{}{}
	var total int64
	var visit func(int)
	visit = func(pid int) {
		if _, exists := seen[pid]; exists {
			return
		}
		seen[pid] = struct{}{}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			t.Fatalf("read nginx process status: %v", err)
		}
		for _, line := range strings.Split(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 3 && fields[0] == "VmRSS:" && fields[2] == "kB" {
				kilobytes, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				total += kilobytes * 1024
			}
		}
		children, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read nginx child list: %v", err)
		}
		for _, field := range strings.Fields(string(children)) {
			child, err := strconv.Atoi(field)
			if err != nil {
				t.Fatal(err)
			}
			visit(child)
		}
	}
	visit(masterPID)
	return total
}

func writeNginxProductionSummary(t *testing.T, summary nginxProductionSummary) {
	t.Helper()
	path := os.Getenv(nginxProductionSummaryEnvironment)
	if path == "" {
		return
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatal("VPNCTL_NGINX_PRODUCTION_SUMMARY must be a clean absolute path")
	}
	payload, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("create production ingress summary: %v", err)
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
