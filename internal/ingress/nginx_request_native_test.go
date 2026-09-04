package ingress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const nginxRuntimeExposeD = "10000000-0000-4000-8000-000000000004"

// TestNginxRuntimeDoesNotReplayNonIdempotentRequests is opt-in because it
// starts a real nginx child. The pinned Ubuntu parser remains covered by
// TestNginxConfigParsesWithPinnedNginx; this test exercises failure semantics.
func TestNginxRuntimeDoesNotReplayNonIdempotentRequests(t *testing.T) {
	binary := os.Getenv("VPNCTL_NGINX_RUNTIME")
	if binary == "" {
		t.Skip("set VPNCTL_NGINX_RUNTIME to an nginx binary for the runtime failure gate")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("VPNCTL_NGINX_RUNTIME must be an absolute path")
	}

	abort := newNginxFaultUpstream(t, nginxFaultAbortBeforeHeaders)
	timeout := newNginxFaultUpstream(t, nginxFaultTimeoutBeforeHeaders)
	partial := newNginxFaultUpstream(t, nginxFaultPartialResponse)
	bodyGuard := newNginxFaultUpstream(t, nginxFaultCompleteResponse)
	edgePort := reserveNginxRuntimePort(t)

	root := t.TempDir()
	runtimeDirectory := filepath.Join(root, "run")
	secretDirectory := filepath.Join(root, "secrets")
	for _, path := range []string{
		runtimeDirectory,
		filepath.Join(runtimeDirectory, "client-body"),
		filepath.Join(runtimeDirectory, "proxy"),
		secretDirectory,
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	material, err := GeneratePublicCertificate(rand.Reader, "192.0.2.10", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
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
		nginxRuntimeExpose(nginxTestExposeA, "/abort", abort.Port(), DefaultExposeBodyLimitBytes, 3),
		nginxRuntimeExpose(nginxTestExposeB, "/timeout", timeout.Port(), DefaultExposeBodyLimitBytes, 1),
		nginxRuntimeExpose(nginxTestExposeC, "/partial", partial.Port(), DefaultExposeBodyLimitBytes, 3),
		nginxRuntimeExpose(nginxRuntimeExposeD, "/body-limit", bodyGuard.Port(), 32, 3),
	}
	candidate, err := RenderNginxConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	writeNginxRuntimeCandidate(t, root, candidate, edgePort)
	nginx := startNginxRuntime(t, binary, root, edgePort)
	t.Cleanup(nginx.Stop)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ // Test-only generated certificate uses the production non-loopback IP identity.
			InsecureSkipVerify: true, //nolint:gosec
			NextProtos:         []string{"http/1.1"},
		},
		DisableKeepAlives: true,
	}, Timeout: 5 * time.Second}

	assertNginxRuntimeStatus(t, client, edgePort, "/abort", "abort-once", []byte("non-idempotent-abort"), http.StatusServiceUnavailable)
	assertNginxRuntimeStatus(t, client, edgePort, "/timeout", "timeout-once", []byte("non-idempotent-timeout"), http.StatusGatewayTimeout)
	assertNginxRuntimePartialClose(t, client, edgePort, partial)
	assertNginxRuntimeStatus(t, client, edgePort, "/body-limit", "must-not-reach-upstream", bytes.Repeat([]byte("x"), 33), http.StatusRequestEntityTooLarge)
	assertNginxRuntimeStatus(t, client, edgePort, "/body-limit", "application-502", bytes.Repeat([]byte("x"), 32), http.StatusBadGateway)

	// Let a provider retry, if accidentally enabled, reach the accepting fault
	// listener before asserting the per-request attempt ledger.
	time.Sleep(600 * time.Millisecond)
	for name, assertion := range map[string]struct {
		upstream *nginxFaultUpstream
		nonce    string
		want     int
	}{
		"pre-response abort":   {abort, "abort-once", 1},
		"pre-response timeout": {timeout, "timeout-once", 1},
		"partial response":     {partial, "partial-once", 1},
		"body limit":           {bodyGuard, "must-not-reach-upstream", 0},
		"application response": {bodyGuard, "application-502", 1},
	} {
		if got := assertion.upstream.Attempts(assertion.nonce); got != assertion.want {
			t.Errorf("%s upstream attempts = %d, want %d", name, got, assertion.want)
		}
	}
	for _, path := range []string{filepath.Join(runtimeDirectory, "client-body"), filepath.Join(runtimeDirectory, "proxy")} {
		if files := regularFilesUnder(t, path); len(files) != 0 {
			t.Errorf("request body persistence under %s: %v", path, files)
		}
	}
	t.Logf("runtime root=%s edge=127.0.0.1:%d upstreams=%d,%d,%d,%d", root, edgePort, abort.Port(), timeout.Port(), partial.Port(), bodyGuard.Port())
}

func nginxRuntimeExpose(id, path string, port int, bodyLimit int64, timeout int) model.Expose {
	expose := nginxExposeFixture(id, path, model.RouteExact, port, model.ExposeReady)
	expose.BodyLimitBytes = bodyLimit
	expose.UpstreamTimeoutSeconds = timeout
	return expose
}

func writeNginxRuntimeCandidate(t *testing.T, root string, candidate NginxCandidate, edgePort int) {
	t.Helper()
	for _, artifact := range candidate.Artifacts() {
		content := artifact.Bytes()
		if artifact.RelativePath() == NginxMainConfigPath {
			// A non-root test master retains the invoking account. Omitting the
			// production user directive avoids a harmless platform warning.
			content = bytes.Replace(content, []byte("user www-data;\n"), nil, 1)
			// macOS/arm64 uses 16 KiB pages and requires a larger minimum nginx
			// shared zone than the pinned 4 KiB-page Ubuntu target. This changes
			// only test capacity, not request behavior or production rendering.
			content = bytes.ReplaceAll(content, []byte(":64k"), []byte(":256k"))
			oldListen := []byte("listen 0.0.0.0:443 ssl http2;")
			newListen := []byte("listen 127.0.0.1:" + strconv.Itoa(edgePort) + " ssl;")
			if bytes.Count(content, oldListen) != 1 {
				t.Fatalf("runtime candidate public listener count is not one")
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

type nginxRuntimeProcess struct {
	command *exec.Cmd
	done    chan struct{}
	waitErr error
	stop    sync.Once
	output  *bytes.Buffer
}

func startNginxRuntime(t *testing.T, binary, root string, port int) *nginxRuntimeProcess {
	t.Helper()
	output := &bytes.Buffer{}
	command := exec.Command(binary, "-p", root+string(filepath.Separator), "-c", NginxMainConfigPath)
	command.Stdout = output
	command.Stderr = output
	process := &nginxRuntimeProcess{command: command, done: make(chan struct{}), output: output}
	if err := command.Start(); err != nil {
		t.Fatalf("start nginx runtime: %v", err)
	}
	go func() {
		process.waitErr = command.Wait()
		close(process.done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return process
		}
		select {
		case <-process.done:
			t.Fatalf("nginx runtime exited before readiness: %v\n%s", process.waitErr, output.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	process.Stop()
	t.Fatalf("nginx runtime did not bind its test listener\n%s", output.String())
	return nil
}

func (process *nginxRuntimeProcess) Stop() {
	process.stop.Do(func() {
		select {
		case <-process.done:
			return
		default:
		}
		_ = process.command.Process.Signal(syscall.SIGTERM)
		select {
		case <-process.done:
			return
		case <-time.After(3 * time.Second):
			_ = process.command.Process.Kill()
			<-process.done
		}
	})
}

func reserveNginxRuntimePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func assertNginxRuntimeStatus(t *testing.T, client *http.Client, port int, path, nonce string, body []byte, status int) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d%s", port, path), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Vpnctl-Test-Nonce", nonce)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatalf("read POST %s response: %v", path, err)
	}
	if response.StatusCode != status {
		t.Fatalf("POST %s status = %d, want %d", path, response.StatusCode, status)
	}
}

func assertNginxRuntimePartialClose(t *testing.T, client *http.Client, port int, upstream *nginxFaultUpstream) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d/partial", port), strings.NewReader("non-idempotent-partial"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Vpnctl-Test-Nonce", "partial-once")
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("partial POST did not expose started response: %v", err)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, []byte("partial-response")) || !errors.Is(readErr, io.ErrUnexpectedEOF) {
		t.Fatalf("partial response status=%d body=%q error=%v", response.StatusCode, body, readErr)
	}
	if upstream.Attempts("partial-once") != 1 {
		t.Fatalf("partial response was not forwarded exactly once")
	}
}

func regularFilesUnder(t *testing.T, root string) []string {
	t.Helper()
	var result []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			result = append(result, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

type nginxFaultBehavior int

const (
	nginxFaultAbortBeforeHeaders nginxFaultBehavior = iota
	nginxFaultTimeoutBeforeHeaders
	nginxFaultPartialResponse
	nginxFaultCompleteResponse
)

type nginxFaultUpstream struct {
	listener net.Listener
	behavior nginxFaultBehavior
	done     chan struct{}
	close    sync.Once
	wait     sync.WaitGroup
	mu       sync.Mutex
	attempts map[string]int
}

func newNginxFaultUpstream(t *testing.T, behavior nginxFaultBehavior) *nginxFaultUpstream {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &nginxFaultUpstream{
		listener: listener,
		behavior: behavior,
		done:     make(chan struct{}),
		attempts: make(map[string]int),
	}
	server.wait.Add(1)
	go server.serve()
	t.Cleanup(server.Close)
	return server
}

func (server *nginxFaultUpstream) Port() int {
	return server.listener.Addr().(*net.TCPAddr).Port
}

func (server *nginxFaultUpstream) Attempts(nonce string) int {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.attempts[nonce]
}

func (server *nginxFaultUpstream) Close() {
	server.close.Do(func() {
		close(server.done)
		_ = server.listener.Close()
		server.wait.Wait()
	})
}

func (server *nginxFaultUpstream) serve() {
	defer server.wait.Done()
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		server.wait.Add(1)
		go func() {
			defer server.wait.Done()
			defer connection.Close()
			server.handle(connection)
		}()
	}
}

func (server *nginxFaultUpstream) handle(connection net.Conn) {
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	request, err := http.ReadRequest(bufio.NewReader(connection))
	if err != nil {
		return
	}
	_, readErr := io.Copy(io.Discard, request.Body)
	_ = request.Body.Close()
	if readErr != nil {
		return
	}
	nonce := request.Header.Get("X-Vpnctl-Test-Nonce")
	server.mu.Lock()
	server.attempts[nonce]++
	server.mu.Unlock()

	switch server.behavior {
	case nginxFaultAbortBeforeHeaders:
		return
	case nginxFaultTimeoutBeforeHeaders:
		timer := time.NewTimer(1500 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-server.done:
			return
		case <-timer.C:
			_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		}
	case nginxFaultPartialResponse:
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\npartial-response")
	case nginxFaultCompleteResponse:
		_, _ = io.WriteString(connection, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}
}
