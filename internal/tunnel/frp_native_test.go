package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestFRPNativeConfigsWithPinnedBinaries(t *testing.T) {
	frpsBinary := os.Getenv("VPNCTL_FRPS")
	frpcBinary := os.Getenv("VPNCTL_FRPC")
	if frpsBinary == "" || frpcBinary == "" {
		t.Skip("set VPNCTL_FRPS and VPNCTL_FRPC to pinned Linux binaries")
	}
	root := t.TempDir()
	provider, err := NewFRPProvider(root, testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	server, err := provider.Render(context.Background(), RenderRequest{Plan: Plan{
		HostRole: model.RoleGateway, HostID: testGatewayHostID, Generation: 1,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := provider.Render(context.Background(), RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: testNodeHostID, Generation: 1,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{testFRPSession(t)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	serverDirectory := filepath.Join(root, "etc", "vpnctl", "generated", "gateway")
	clientDirectory := filepath.Join(root, "etc", "vpnctl", "generated", "node")
	for _, directory := range []string{serverDirectory, clientDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	certificatePEM, privateKeyPEM := nativeFRPTLSIdentity(t)
	serverConfigPath := filepath.Join(serverDirectory, FRPServerConfigFileName)
	clientConfigPath := filepath.Join(clientDirectory, FRPClientConfigFileName)
	for path, content := range map[string][]byte{
		serverConfigPath: server.(FRPCandidate).Bytes(), clientConfigPath: client.(FRPCandidate).Bytes(),
		filepath.Join(serverDirectory, FRPServerCertificateName): certificatePEM,
		filepath.Join(serverDirectory, FRPServerPrivateKeyName):  privateKeyPEM,
		filepath.Join(clientDirectory, FRPServerCertificateName): certificatePEM,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := linuxplatform.OSProbeRunner{}
	if err := ValidatePinnedFRPConfig(context.Background(), runner, frpsBinary, serverConfigPath); err != nil {
		t.Fatalf("native frps validation failed: %v", err)
	}
	if err := ValidatePinnedFRPConfig(context.Background(), runner, frpcBinary, clientConfigPath); err != nil {
		t.Fatalf("native frpc validation failed: %v", err)
	}
}

func TestFRPNativeLoginUsesProductionAuthorizerAndEffectiveZeroPool(t *testing.T) {
	frpsBinary := os.Getenv("VPNCTL_FRPS")
	frpcBinary := os.Getenv("VPNCTL_FRPC")
	if frpsBinary == "" || frpcBinary == "" {
		t.Skip("set VPNCTL_FRPS and VPNCTL_FRPC to pinned Linux binaries")
	}
	root := t.TempDir()
	certificatePEM, privateKeyPEM := nativeFRPTLSIdentity(t)
	certificatePath := filepath.Join(root, "tunnel-server.crt")
	privateKeyPath := filepath.Join(root, "tunnel-server.key")
	serverConfigPath := filepath.Join(root, "frps.toml")
	clientConfigPath := filepath.Join(root, "frpc.toml")
	serverConfig := renderFRPServerConfig(netip.MustParseAddrPort("127.0.0.1:17000"), certificatePath, privateKeyPath)
	serverConfig = bytes.Replace(serverConfig, []byte(`ops = ["Login", "NewProxy", "Ping"]`), []byte(`ops = ["Login"]`), 1)
	session := testFRPSession(t)
	session.Mappings = []Mapping{}
	clientConfig := renderFRPClientConfig(netip.MustParseAddrPort("127.0.0.1:17000"), session, testTunnelCredential, certificatePath)
	for path, content := range map[string][]byte{
		certificatePath: certificatePEM, privateKeyPath: privateKeyPEM,
		serverConfigPath: serverConfig, clientConfigPath: clientConfig,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	authorizer, _, _ := loginAuthorizationFixture(t)
	decisions := make(chan string, 8)
	authorizer.observe = func(operation string, allowed, unavailable bool, reason string) {
		decisions <- fmt.Sprintf("%s/%t/%t/%s", operation, allowed, unavailable, reason)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authorizationResult := make(chan error, 1)
	go func() { authorizationResult <- authorizer.Serve(ctx) }()
	waitForNativeTCPListener(t, FRPAuthorizationAddress)

	serverCommand := exec.CommandContext(ctx, frpsBinary, "-c", serverConfigPath)
	serverCommand.Stdout = io.Discard
	serverCommand.Stderr = io.Discard
	if err := serverCommand.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	serverResult := make(chan error, 1)
	go func() { serverResult <- serverCommand.Wait() }()
	waitForNativeTCPListener(t, "127.0.0.1:17000")

	clientCommand := exec.CommandContext(ctx, frpcBinary, "-c", clientConfigPath)
	clientCommand.Stdout = io.Discard
	clientCommand.Stderr = io.Discard
	if err := clientCommand.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	clientResult := make(chan error, 1)
	go func() { clientResult <- clientCommand.Wait() }()
	t.Cleanup(func() {
		cancel()
		for _, result := range []<-chan error{clientResult, serverResult, authorizationResult} {
			select {
			case <-result:
			case <-time.After(5 * time.Second):
				t.Error("native frp Login fixture did not stop")
			}
		}
	})

	select {
	case decision := <-decisions:
		if decision != "Login/true/false/identity_valid" {
			t.Fatalf("native Login decision = %q", decision)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pinned frpc did not reach the production Login authorizer")
	}
	waitForNativeEstablishedTunnel(t, 17000, 2)
}

func TestFRPNativeNewProxyUsesProductionAuthoritativeMapping(t *testing.T) {
	frpsBinary := os.Getenv("VPNCTL_FRPS")
	frpcBinary := os.Getenv("VPNCTL_FRPC")
	if frpsBinary == "" || frpcBinary == "" {
		t.Skip("set VPNCTL_FRPS and VPNCTL_FRPC to pinned Linux binaries")
	}
	root := t.TempDir()
	certificatePEM, privateKeyPEM := nativeFRPTLSIdentity(t)
	certificatePath := filepath.Join(root, "tunnel-server.crt")
	privateKeyPath := filepath.Join(root, "tunnel-server.key")
	serverConfigPath := filepath.Join(root, "frps.toml")
	clientConfigPath := filepath.Join(root, "frpc.toml")
	maliciousConfigPath := filepath.Join(root, "frpc-malicious.toml")
	serverConfig := renderFRPServerConfig(netip.MustParseAddrPort("127.0.0.1:17000"), certificatePath, privateKeyPath)
	serverConfig = bytes.Replace(serverConfig, []byte(`ops = ["Login", "NewProxy", "Ping"]`), []byte(`ops = ["Login", "NewProxy"]`), 1)
	session := testFRPSession(t)
	session.Mappings = session.Mappings[:1]
	clientConfig := renderFRPClientConfig(netip.MustParseAddrPort("127.0.0.1:17000"), session, testTunnelCredential, certificatePath)
	maliciousConfig := bytes.Replace(append([]byte(nil), clientConfig...), []byte("remotePort = 20000"), []byte("remotePort = 20002"), 1)
	for path, content := range map[string][]byte{
		certificatePath: certificatePEM, privateKeyPath: privateKeyPEM,
		serverConfigPath: serverConfig, clientConfigPath: clientConfig, maliciousConfigPath: maliciousConfig,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	authorizer, _, _ := loginAuthorizationFixture(t)
	decisions := make(chan string, 32)
	authorizer.observe = func(operation string, allowed, unavailable bool, reason string) {
		decisions <- fmt.Sprintf("%s/%t/%t/%s", operation, allowed, unavailable, reason)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	authorizationResult := make(chan error, 1)
	go func() { authorizationResult <- authorizer.Serve(ctx) }()
	waitForNativeTCPListener(t, FRPAuthorizationAddress)

	serverCommand := exec.CommandContext(ctx, frpsBinary, "-c", serverConfigPath)
	serverCommand.Stdout = io.Discard
	serverCommand.Stderr = io.Discard
	if err := serverCommand.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	serverResult := make(chan error, 1)
	go func() { serverResult <- serverCommand.Wait() }()
	waitForNativeTCPListener(t, "127.0.0.1:17000")

	maliciousContext, stopMalicious := context.WithCancel(ctx)
	maliciousCommand := exec.CommandContext(maliciousContext, frpcBinary, "-c", maliciousConfigPath)
	maliciousCommand.Stdout = io.Discard
	maliciousCommand.Stderr = io.Discard
	if err := maliciousCommand.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	maliciousResult := make(chan error, 1)
	go func() { maliciousResult <- maliciousCommand.Wait() }()
	waitForNativeAuthorizationDecisions(t, decisions, map[string]bool{
		"Login/true/false/identity_valid":       false,
		"NewProxy/false/false/mapping_mismatch": false,
	})
	assertNoNativeTCPListener(t, "127.0.0.1:20002")
	stopMalicious()
	select {
	case <-maliciousResult:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("malicious pinned frpc did not stop")
	}

	clientCommand := exec.CommandContext(ctx, frpcBinary, "-c", clientConfigPath)
	clientCommand.Stdout = io.Discard
	clientCommand.Stderr = io.Discard
	if err := clientCommand.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	clientResult := make(chan error, 1)
	go func() { clientResult <- clientCommand.Wait() }()
	t.Cleanup(func() {
		cancel()
		for _, result := range []<-chan error{clientResult, serverResult, authorizationResult} {
			select {
			case <-result:
			case <-time.After(5 * time.Second):
				t.Error("native frp NewProxy fixture did not stop")
			}
		}
	})
	waitForNativeAuthorizationDecisions(t, decisions, map[string]bool{
		"Login/true/false/identity_valid":   false,
		"NewProxy/true/false/mapping_valid": false,
	})
	waitForNativeTCPListener(t, "127.0.0.1:20000")
	waitForNativeEstablishedTunnel(t, 17000, 2)
}

func TestFRPNativeDynamicMappingReloadKeepsProcessConnectionAndStream(t *testing.T) {
	frpsBinary := os.Getenv("VPNCTL_FRPS")
	frpcBinary := os.Getenv("VPNCTL_FRPC")
	if frpsBinary == "" || frpcBinary == "" {
		t.Skip("set VPNCTL_FRPS and VPNCTL_FRPC to pinned Linux binaries")
	}
	root := t.TempDir()
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		paths.ConfigDir, paths.RuntimeDir,
		filepath.Join(paths.ConfigDir, "generated", "node"),
		filepath.Join(root, "usr", "local", "libexec", "vpnctl"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	_, installedFRPC := frpServicePaths(paths, model.RoleNode)
	copyNativeExecutable(t, frpcBinary, installedFRPC)
	certificatePEM, privateKeyPEM := nativeFRPTLSIdentity(t)
	trustedCertificatePath := filepath.Join(paths.ConfigDir, "generated", "node", FRPServerCertificateName)
	serverCertificatePath := filepath.Join(root, "server.crt")
	serverPrivateKeyPath := filepath.Join(root, "server.key")
	for path, content := range map[string][]byte{
		trustedCertificatePath: certificatePEM,
		serverCertificatePath:  certificatePEM,
		serverPrivateKeyPath:   privateKeyPEM,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	endpoint := netip.AddrPortFrom(nativePrivateIPv4(t), FRPServerPort)
	provider, err := NewFRPProvider(root, testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewFRPClientConfigurationManager(
		paths, provider, linuxplatform.OSProbeRunner{}, OSFRPClientReloadRunner{},
	)
	if err != nil {
		t.Fatal(err)
	}
	session := testFRPSession(t)
	oneMapping := session
	oneMapping.Mappings = oneMapping.Mappings[:1]
	if result, err := manager.Apply(context.Background(), nativeFRPClientRenderRequest(endpoint, oneMapping, 1)); err != nil || !result.Initial {
		t.Fatalf("initial native client config = result:%+v err:%v", result, err)
	}
	clientConfigPath, _ := frpServicePaths(paths, model.RoleNode)
	serverConfigPath := filepath.Join(root, "frps.toml")
	serverConfig := renderFRPServerConfig(endpoint, serverCertificatePath, serverPrivateKeyPath)
	serverConfig = bytes.Replace(serverConfig, []byte(`ops = ["Login", "NewProxy", "Ping"]`), []byte(`ops = ["Login", "NewProxy"]`), 1)
	if err := os.WriteFile(serverConfigPath, serverConfig, 0o600); err != nil {
		t.Fatal(err)
	}

	authorizer, authoritative, _ := loginAuthorizationFixture(t)
	authoritative.state.Exposes[1] = testExpose(testExposeB, testNodeA, "second", 20001, model.ExposeReady)
	decisions := make(chan string, 32)
	authorizer.observe = func(operation string, allowed, unavailable bool, reason string) {
		decisions <- fmt.Sprintf("%s/%t/%t/%s", operation, allowed, unavailable, reason)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend, err := net.Listen("tcp4", "127.0.0.1:3000")
	if err != nil {
		t.Fatal(err)
	}
	go serveNativeEcho(ctx, backend)
	authorizationResult := make(chan error, 1)
	go func() { authorizationResult <- authorizer.Serve(ctx) }()
	waitForNativeTCPListener(t, FRPAuthorizationAddress)

	serverCommand := exec.CommandContext(ctx, frpsBinary, "-c", serverConfigPath)
	serverCommand.Stdout = io.Discard
	serverCommand.Stderr = io.Discard
	if err := serverCommand.Start(); err != nil {
		t.Fatal(err)
	}
	serverResult := make(chan error, 1)
	go func() { serverResult <- serverCommand.Wait() }()
	waitForNativeTCPListener(t, endpoint.String())

	clientCommand := exec.CommandContext(ctx, installedFRPC, "-c", clientConfigPath)
	clientCommand.Stdout = io.Discard
	clientCommand.Stderr = io.Discard
	if err := clientCommand.Start(); err != nil {
		t.Fatal(err)
	}
	clientPID := clientCommand.Process.Pid
	clientResult := make(chan error, 1)
	go func() { clientResult <- clientCommand.Wait() }()
	t.Cleanup(func() {
		cancel()
		_ = backend.Close()
		for _, result := range []<-chan error{clientResult, serverResult, authorizationResult} {
			select {
			case <-result:
			case <-time.After(5 * time.Second):
				t.Error("native dynamic reload fixture did not stop")
			}
		}
	})
	waitForNativeAuthorizationDecisions(t, decisions, map[string]bool{
		"Login/true/false/identity_valid":   false,
		"NewProxy/true/false/mapping_valid": false,
	})
	waitForNativeTCPListener(t, "127.0.0.1:20000")
	waitForNativeEstablishedTunnel(t, FRPServerPort, 2)
	persistent, err := net.DialTimeout("tcp4", "127.0.0.1:20000", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer persistent.Close()
	nativePersistentRoundTrip(t, persistent, "before-add")

	if result, err := manager.Apply(ctx, nativeFRPClientRenderRequest(endpoint, session, 2)); err != nil || !result.Reloaded || result.MappingCount != 2 {
		t.Fatalf("native add mapping = result:%+v err:%v", result, err)
	}
	waitForNativeTCPListener(t, "127.0.0.1:20001")
	nativePersistentRoundTrip(t, persistent, "after-add")
	second, err := net.DialTimeout("tcp4", "127.0.0.1:20001", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	nativePersistentRoundTrip(t, second, "second-mapping")
	_ = second.Close()
	if clientCommand.Process.Pid != clientPID || clientCommand.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("dynamic add replaced or stopped the persistent frpc process")
	}
	waitForNativeEstablishedTunnel(t, FRPServerPort, 2)

	if result, err := manager.Apply(ctx, nativeFRPClientRenderRequest(endpoint, oneMapping, 3)); err != nil || !result.Reloaded || result.MappingCount != 1 {
		t.Fatalf("native remove mapping = result:%+v err:%v", result, err)
	}
	waitForNativeTCPListenerClosed(t, "127.0.0.1:20001")
	nativePersistentRoundTrip(t, persistent, "after-remove")
	if clientCommand.Process.Pid != clientPID || clientCommand.Process.Signal(syscall.Signal(0)) != nil {
		t.Fatal("dynamic remove replaced or stopped the persistent frpc process")
	}
	waitForNativeEstablishedTunnel(t, FRPServerPort, 2)
}

func nativeFRPClientRenderRequest(endpoint netip.AddrPort, session NodeSession, generation uint64) RenderRequest {
	return RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: testNodeHostID, Generation: generation,
		ServerEndpoint: endpoint, Nodes: []NodeSession{session},
	}}
}

func nativePrivateIPv4(t *testing.T) netip.Addr {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, networkInterface := range interfaces {
		addresses, err := networkInterface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().Is4() && prefix.Addr().IsPrivate() && !prefix.Addr().IsLoopback() {
				return prefix.Addr()
			}
		}
	}
	t.Fatal("native fixture has no private non-loopback IPv4 address")
	return netip.Addr{}
}

func copyNativeExecutable(t *testing.T, sourcePath, targetPath string) {
	t.Helper()
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	if err := target.Sync(); err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
}

func serveNativeEcho(ctx context.Context, listener net.Listener) {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}()
	}
}

func nativePersistentRoundTrip(t *testing.T, connection net.Conn, value string) {
	t.Helper()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte(value)
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("native echo = %q, want %q", received, payload)
	}
	clear(received)
	clear(payload)
}

func waitForNativeTCPListenerClosed(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if err != nil {
			return
		}
		_ = connection.Close()
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("native listener %s remained reachable", address)
}

func waitForNativeAuthorizationDecisions(t *testing.T, decisions <-chan string, wanted map[string]bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	remaining := len(wanted)
	for remaining > 0 {
		select {
		case decision := <-decisions:
			seen, expected := wanted[decision]
			if expected && !seen {
				wanted[decision] = true
				remaining--
			}
		case <-deadline:
			t.Fatalf("native authorization decisions incomplete: %v", wanted)
		}
	}
}

func assertNoNativeTCPListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp4", address, 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			t.Fatalf("unauthorized native listener %s became reachable", address)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func waitForNativeTCPListener(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("native listener %s did not become ready", address)
}

func waitForNativeEstablishedTunnel(t *testing.T, port, wantEntries int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	stable := 0
	for time.Now().Before(deadline) {
		entries, err := establishedTCPEntries(port)
		if err != nil {
			t.Fatal(err)
		}
		if entries == wantEntries {
			stable++
			if stable == 3 {
				return
			}
		} else {
			stable = 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	entries, _ := establishedTCPEntries(port)
	t.Fatalf("established TCP/%d entries = %d, want stable %d (one control connection)", port, entries, wantEntries)
}

func establishedTCPEntries(port int) (int, error) {
	content, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return 0, err
	}
	wantPort := strings.ToUpper(strconv.FormatInt(int64(port), 16))
	count := 0
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "01" {
			continue
		}
		_, localPort, localOK := strings.Cut(fields[1], ":")
		_, remotePort, remoteOK := strings.Cut(fields[2], ":")
		if localOK && remoteOK && (localPort == wantPort || remotePort == wantPort) {
			count++
		}
	}
	return count, nil
}

func nativeFRPTLSIdentity(t *testing.T) ([]byte, []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: FRPTLSServerName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{FRPTLSServerName},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certificatePEM, privateKeyPEM
}
