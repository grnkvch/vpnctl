package tunnel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const testTunnelCredential = "ERERERERERERERERERERERERERERERERERERERERERE"

func TestFRPProviderPinMatchesAcceptedManifest(t *testing.T) {
	t.Parallel()

	if FRPProviderVersion != "0.69.0" || FRPProviderAsset != "frp_0.69.0_linux_amd64.tar.gz" ||
		FRPProviderSHA256 != "6b90d1cd28fc661f170c0de90dde03d2c63e4fd7ce0ae2da2ca1c28014b8146e" ||
		FRPAuthorizationAddress != fmt.Sprintf("127.0.0.1:%d", FRPAuthorizationPort) {
		t.Fatalf("unexpected frp pin: %s %s %s", FRPProviderVersion, FRPProviderAsset, FRPProviderSHA256)
	}
	if decoded, err := base64.RawURLEncoding.Strict().DecodeString(testTunnelCredential); err != nil || len(decoded) != 32 {
		t.Fatalf("test tunnel credential is invalid: bytes=%d err=%v", len(decoded), err)
	}
	if _, err := NewFRPProvider("/", testFRPComponent(), staticFRPCredentials{}); err != nil {
		t.Fatalf("NewFRPProvider() error = %v", err)
	}

	component := testFRPComponent()
	component.Version = "0.69.1"
	if _, err := NewFRPProvider("/", component, staticFRPCredentials{}); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("wrong version error = %v", err)
	}
	component = testFRPComponent()
	component.Capabilities = []string{"dynamic-reload", "http-plugin-authorization", "tcp-mux"}
	if _, err := NewFRPProvider("/", component, staticFRPCredentials{}); err == nil || !strings.Contains(err.Error(), "tls-server-verification") {
		t.Fatalf("missing capability error = %v", err)
	}
}

func TestFRPProviderRendersOneInternalSharedServer(t *testing.T) {
	t.Parallel()

	provider, err := NewFRPProvider("/", testFRPComponent(), nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := provider.Render(context.Background(), RenderRequest{Plan: Plan{
		HostRole: model.RoleGateway, HostID: testGatewayHostID, Generation: 8,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{},
	}})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	frpCandidate, ok := candidate.(FRPCandidate)
	if !ok {
		t.Fatalf("candidate type = %T", candidate)
	}
	config := string(frpCandidate.Bytes())
	for _, required := range []string{
		`bindAddr = "10.67.0.1"`, `bindPort = 17000`, `proxyBindAddr = "127.0.0.1"`,
		`allowPorts = [{ start = 20000, end = 29999 }]`, `transport.tcpMux = true`,
		`transport.tls.force = true`, `addr = "127.0.0.1:19091"`,
		`ops = ["Login", "NewProxy", "Ping"]`,
	} {
		if !strings.Contains(config, required) {
			t.Errorf("server config does not contain %q:\n%s", required, config)
		}
	}
	for _, forbidden := range []string{"dashboard", "webServer.", "vhost", "kcp", "quic", "udp", "0.0.0.0", "auth.token"} {
		if strings.Contains(strings.ToLower(config), strings.ToLower(forbidden)) {
			t.Errorf("server config contains forbidden %q:\n%s", forbidden, config)
		}
	}
	descriptor := candidate.Descriptor()
	if descriptor.Provider != FRPProviderName || descriptor.HostRole != model.RoleGateway || descriptor.NodeID != "" || descriptor.ConfigHash == "" {
		t.Fatalf("server descriptor = %#v", descriptor)
	}
	if err := provider.Validate(context.Background(), candidate); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestFRPProviderRendersOneMultiplexedClientThroughActiveTransport(t *testing.T) {
	t.Parallel()

	provider, err := NewFRPProvider("/", testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	session := testFRPSession(t)
	// A provider caller is not required to pre-sort an otherwise valid plan.
	session.Mappings[0], session.Mappings[1] = session.Mappings[1], session.Mappings[0]
	candidate, err := provider.Render(context.Background(), RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: testNodeHostID, Generation: 9,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{session},
	}})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	frpCandidate := candidate.(FRPCandidate)
	config := string(frpCandidate.Bytes())
	for _, required := range []string{
		`serverAddr = "10.67.0.1"`, `serverPort = 17000`, `loginFailExit = false`,
		`webServer.addr = "127.0.0.1"`, `webServer.port = 17400`,
		`transport.protocol = "tcp"`, `transport.wireProtocol = "v1"`, `transport.poolCount = 0`,
		`transport.tcpMux = true`, `transport.tls.enable = true`,
		`transport.tls.disableCustomTLSFirstByte = true`,
		`transport.tls.serverName = "vpnctl-tunnel-gateway"`,
		`localIP = "127.0.0.1"`, `remotePort = 20000`, `remotePort = 20001`,
	} {
		if !strings.Contains(config, required) {
			t.Errorf("client config does not contain %q:\n%s", required, config)
		}
	}
	if strings.Count(config, "[[proxies]]") != 2 {
		t.Fatalf("proxy count = %d, want 2", strings.Count(config, "[[proxies]]"))
	}
	for _, forbidden := range []string{"proxyURL", "0.0.0.0", "udp", "poolCount = 1", "8443", "51820"} {
		if strings.Contains(config, forbidden) {
			t.Errorf("client config contains standby/public setting %q:\n%s", forbidden, config)
		}
	}
	descriptor := candidate.Descriptor()
	if descriptor.NodeID != testNodeA || descriptor.CredentialGeneration != 1 || descriptor.ActiveTransport != model.TransportRestricted {
		t.Fatalf("client descriptor = %#v", descriptor)
	}
	if strings.Contains(fmt.Sprintf("%#v", descriptor), testTunnelCredential) {
		t.Fatal("candidate descriptor contains the tunnel credential")
	}
	if err := provider.Validate(context.Background(), candidate); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestFRPClientRenderIsDeterministicAcrossMappingOrder(t *testing.T) {
	t.Parallel()

	provider, err := NewFRPProvider("/", testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	session := testFRPSession(t)
	request := RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: testNodeHostID, Generation: 4,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{session},
	}}
	first, err := provider.Render(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Plan.Nodes[0].Mappings[0], request.Plan.Nodes[0].Mappings[1] = request.Plan.Nodes[0].Mappings[1], request.Plan.Nodes[0].Mappings[0]
	second, err := provider.Render(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.(FRPCandidate).Bytes()) != string(second.(FRPCandidate).Bytes()) || first.Descriptor().ConfigHash != second.Descriptor().ConfigHash {
		t.Fatal("mapping input order changed the rendered client candidate")
	}
}

func TestFRPStrictValidatorsRejectUnsafeOrUnknownSettings(t *testing.T) {
	t.Parallel()

	provider, err := NewFRPProvider("/", testFRPComponent(), staticFRPCredentials{})
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
	serverConfig := string(server.(FRPCandidate).Bytes())
	clientConfig := string(client.(FRPCandidate).Bytes())
	tests := []struct {
		name    string
		server  bool
		content string
		replace string
	}{
		{name: "public server bind", server: true, content: serverConfig, replace: strings.Replace(serverConfig, `bindAddr = "10.67.0.1"`, `bindAddr = "0.0.0.0"`, 1)},
		{name: "dashboard", server: true, content: serverConfig, replace: serverConfig + "webServer.port = 7500\n"},
		{name: "server TLS disabled", server: true, content: serverConfig, replace: strings.Replace(serverConfig, "transport.tls.force = true", "transport.tls.force = false", 1)},
		{name: "public gateway endpoint", content: clientConfig, replace: strings.Replace(clientConfig, `serverAddr = "10.67.0.1"`, `serverAddr = "203.0.113.1"`, 1)},
		{name: "standby proxy", content: clientConfig, replace: strings.Replace(clientConfig, "transport.protocol = \"tcp\"", "transport.proxyURL = \"socks5://127.0.0.1:17890\"\ntransport.protocol = \"tcp\"", 1)},
		{name: "connection pool", content: clientConfig, replace: strings.Replace(clientConfig, "transport.poolCount = 0", "transport.poolCount = 1", 1)},
		{name: "client TLS disabled", content: clientConfig, replace: strings.Replace(clientConfig, "transport.tls.enable = true", "transport.tls.enable = false", 1)},
		{name: "UDP proxy", content: clientConfig, replace: strings.Replace(clientConfig, `type = "tcp"`, `type = "udp"`, 1)},
		{name: "duplicate remote port", content: clientConfig, replace: strings.Replace(clientConfig, "remotePort = 20001", "remotePort = 20000", 1)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var validationErr error
			if test.server {
				validationErr = ValidateFRPServerConfig([]byte(test.replace))
			} else {
				validationErr = ValidateFRPClientConfig([]byte(test.replace))
			}
			if validationErr == nil {
				t.Fatalf("unsafe config was accepted:\n%s", test.replace)
			}
		})
	}
}

func TestFRPProviderSanitizesCredentialSourceFailure(t *testing.T) {
	t.Parallel()

	provider, err := NewFRPProvider("/", testFRPComponent(), failingFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Render(context.Background(), RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: testNodeHostID, Generation: 1,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{testFRPSession(t)},
	}})
	if err == nil || err.Error() != "read frp node credential" || strings.Contains(err.Error(), "credential-canary") {
		t.Fatalf("credential source error was not sanitized: %v", err)
	}
}

func testFRPComponent() model.ComponentPin {
	return model.ComponentPin{
		Name: FRPProviderName, Version: FRPProviderVersion, Source: "vpnctl-release-bundle", Bundled: true,
		SHA256:       FRPProviderSHA256,
		Capabilities: []string{"dynamic-reload", "http-plugin-authorization", "tcp-mux", "tls-server-verification"},
	}
}

func testFRPSession(t *testing.T) NodeSession {
	t.Helper()
	session, err := NewNodeSession(testNode(testNodeA), []model.Expose{
		testExpose(testExposeA, testNodeA, "first", 20000, model.ExposeReady),
		testExpose(testExposeB, testNodeA, "second", 20001, model.ExposePending),
	}, 3)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

type staticFRPCredentials struct{}

func (staticFRPCredentials) TunnelCredential(string, uint64) ([]byte, error) {
	return []byte(testTunnelCredential), nil
}

type failingFRPCredentials struct{}

func (failingFRPCredentials) TunnelCredential(string, uint64) ([]byte, error) {
	return nil, errors.New("credential-canary")
}

const (
	testGatewayHostID = "30000000-0000-4000-8000-000000000001"
	testNodeHostID    = "30000000-0000-4000-8000-000000000002"
)
