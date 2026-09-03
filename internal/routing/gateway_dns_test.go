package routing

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestRenderGatewayDNSConfigUsesOneIdentityFreeSharedPolicy(t *testing.T) {
	t.Parallel()
	state := gatewayDNSState()
	state.Nodes = []model.Node{}
	candidate, err := RenderGatewayDNSConfig(state)
	if err != nil {
		t.Fatalf("RenderGatewayDNSConfig() error = %v", err)
	}
	want := GatewayDNSConfig{
		SchemaVersion: GatewayDNSConfigSchemaVersion,
		Generation:    11,
		ListenIPv4:    []string{"10.66.0.1", "10.67.0.1"},
		UpstreamIPv4:  []string{"1.1.1.1", "8.8.8.8"},
	}
	if got := candidate.Config(); !reflect.DeepEqual(got, want) {
		t.Fatalf("gateway DNS config = %+v, want %+v", got, want)
	}
	content := candidate.Bytes()
	for _, forbidden := range []string{"node_id", "client_id", "preset", "policy", "selector"} {
		if bytes.Contains(content, []byte(forbidden)) {
			t.Fatalf("shared gateway DNS config leaked per-identity field %q: %s", forbidden, content)
		}
	}
	decoded, err := DecodeGatewayDNSConfig(content)
	if err != nil || !reflect.DeepEqual(decoded, want) {
		t.Fatalf("DecodeGatewayDNSConfig() = %+v, %v", decoded, err)
	}
	copyConfig := candidate.Config()
	copyConfig.UpstreamIPv4[0] = "9.9.9.9"
	if candidate.Config().UpstreamIPv4[0] != "1.1.1.1" {
		t.Fatal("gateway DNS candidate exposed mutable upstream state")
	}
}

func TestRenderGatewayDNSConfigRejectsWrongRoleScopeAndInvalidDocuments(t *testing.T) {
	t.Parallel()
	state := gatewayDNSState()
	state.Host.Role = model.RoleNode
	state.Host.PublicIPv4 = ""
	state.Host.ExternalInterface = ""
	state.Host.SSHPort = 0
	state.Host.ClientCIDR = ""
	state.Host.NodeCIDR = ""
	state.DNS = &model.DNSUpstreamState{SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamDirect, IPv4: []string{"192.0.2.53"}}
	if _, err := RenderGatewayDNSConfig(state); err == nil {
		t.Fatal("node direct-DNS state rendered a gateway forwarder")
	}
	valid := gatewayDNSState()
	for name, content := range map[string][]byte{
		"unknown field": bytes.Replace(mustGatewayDNSBytes(t, valid), []byte("\"generation\":"), []byte("\"unknown\": 1,\n  \"generation\":"), 1),
		"trailing":      append(mustGatewayDNSBytes(t, valid), []byte("{}\n")...),
		"loopback":      bytes.Replace(mustGatewayDNSBytes(t, valid), []byte("1.1.1.1"), []byte("127.0.0.1"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeGatewayDNSConfig(content); err == nil {
				t.Fatal("invalid gateway DNS document was accepted")
			}
		})
	}
}

func TestGatewayDNSForwarderSharesUDPAndTCPWithoutIdentityPolicy(t *testing.T) {
	upstreamUDP, upstreamTCP, upstreamEndpoint := listenDNSPair(t)
	defer upstreamUDP.Close()
	defer upstreamTCP.Close()
	var upstreamQueries atomic.Int32
	upstreamCtx, stopUpstream := context.WithCancel(context.Background())
	defer stopUpstream()
	go serveTestDNSUDP(upstreamCtx, upstreamUDP, &upstreamQueries)
	go serveTestDNSTCP(upstreamCtx, upstreamTCP, &upstreamQueries)

	gatewayUDP, gatewayTCP, gatewayEndpoint := listenDNSPair(t)
	forwarder := &gatewayDNSForwarder{
		upstreamEndpoints: []string{upstreamEndpoint},
		timeout:           time.Second,
		maximumQueries:    8,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- forwarder.serveBound(ctx, []*net.UDPConn{gatewayUDP}, []net.Listener{gatewayTCP}) }()

	first := testDNSQuery(0x1001, "shared.example")
	if got := queryTestDNSUDP(t, gatewayEndpoint, first); !bytes.Equal(got, testDNSResponse(first)) {
		t.Fatalf("first node UDP response = %x", got)
	}
	second := testDNSQuery(0x2002, "shared.example")
	if got := queryTestDNSTCP(t, gatewayEndpoint, second); !bytes.Equal(got, testDNSResponse(second)) {
		t.Fatalf("second node TCP response = %x", got)
	}
	if got := upstreamQueries.Load(); got != 2 {
		t.Fatalf("shared upstream query count = %d, want 2", got)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gateway DNS shutdown error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gateway DNS forwarder did not stop after cancellation")
	}
}

func TestGatewayDNSConfigFileRequiresCanonicalRootOnlyRegularFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, GatewayDNSConfigFileName)
	content := mustGatewayDNSBytes(t, gatewayDNSState())
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readGatewayDNSConfigFile(path); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("readGatewayDNSConfigFile() = %q, %v", got, err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readGatewayDNSConfigFile(path); err == nil {
		t.Fatal("group-readable gateway DNS config was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readGatewayDNSConfigFile(path); err == nil {
		t.Fatal("gateway DNS config symlink was accepted")
	}
}

func gatewayDNSState() model.State {
	initialized := time.Date(2026, time.September, 4, 0, 0, 0, 0, time.UTC)
	return model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 11,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: initialized,
			PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", SSHPort: 22,
			ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
		},
		DNS: &model.DNSUpstreamState{
			SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamGateway,
			IPv4: model.DefaultGatewayDNSUpstreams(),
		},
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports: []model.Transport{}, Exposes: []model.Expose{}, Certificates: []model.Certificate{}, Operations: []model.Operation{},
		Logging: []model.LoggingSession{}, Backups: []model.Backup{},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2-test", ControlProtocols: []string{"1.0"},
			StateSchemaMinimum: 1, StateSchemaMaximum: 1, TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1,
			Components: []model.ComponentPin{{Name: "vpnctl", Version: "v2-test", Source: "test", Bundled: true, SHA256: strings.Repeat("a", 64), Capabilities: []string{"gateway-dns"}}},
		},
	}
}

func mustGatewayDNSBytes(t *testing.T, state model.State) []byte {
	t.Helper()
	candidate, err := RenderGatewayDNSConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	return candidate.Bytes()
}

func listenDNSPair(t *testing.T) (*net.UDPConn, net.Listener, string) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	return udp, tcp, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func serveTestDNSUDP(ctx context.Context, listener *net.UDPConn, count *atomic.Int32) {
	buffer := make([]byte, 4096)
	for {
		_ = listener.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, client, err := listener.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		count.Add(1)
		_, _ = listener.WriteToUDP(testDNSResponse(buffer[:n]), client)
	}
}

func serveTestDNSTCP(ctx context.Context, listener net.Listener, count *atomic.Int32) {
	for {
		if tcp, ok := listener.(*net.TCPListener); ok {
			_ = tcp.SetDeadline(time.Now().Add(100 * time.Millisecond))
		}
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go func() {
			defer connection.Close()
			header := make([]byte, 2)
			if _, err := io.ReadFull(connection, header); err != nil {
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(header))
			if _, err := io.ReadFull(connection, query); err != nil {
				return
			}
			response := testDNSResponse(query)
			binary.BigEndian.PutUint16(header, uint16(len(response)))
			count.Add(1)
			_ = writeAll(connection, header)
			_ = writeAll(connection, response)
		}()
	}
}

func testDNSQuery(id uint16, name string) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message, id)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0, 0, 1, 0, 1)
	return message
}

func testDNSResponse(query []byte) []byte {
	response := append([]byte(nil), query...)
	response[2] |= 0x80
	return response
}

func queryTestDNSUDP(t *testing.T, endpoint string, query []byte) []byte {
	t.Helper()
	connection, err := net.Dial("udp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if err := writeAll(connection, query); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4096)
	n, err := connection.Read(response)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), response[:n]...)
}

func queryTestDNSTCP(t *testing.T, endpoint string, query []byte) []byte {
	t.Helper()
	connection, err := net.Dial("tcp4", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if err := writeAll(connection, frame); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(connection, frame[:2]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint16(frame[:2]))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	return response
}
