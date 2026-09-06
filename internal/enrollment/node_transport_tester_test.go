package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

func TestBoundedNodeTransportCandidateTesterUsesOnePathAndAlwaysCloses(t *testing.T) {
	state, _, restrictedConfiguration := compiledNodeTransportPairFixture(t)
	path := &nodeTransportTestPath{}
	factory := &nodeTransportTestPathFactory{path: path}
	controlProbe := &nodeTransportTestControlProbe{}
	tester, err := NewBoundedNodeTransportCandidateTester(factory, controlProbe)
	if err != nil {
		t.Fatal(err)
	}
	tester.entropy = bytes.NewReader([]byte{0x12, 0x34})
	probeCalls := make([]string, 0, 3)
	tester.tunnelProbe = func(_ context.Context, received NodeTransportCandidatePath, configuration NodeConfiguration) error {
		if received != path || configuration.StateGeneration() != restrictedConfiguration.StateGeneration() {
			t.Fatal("tunnel probe received another path or generation")
		}
		probeCalls = append(probeCalls, "tunnel")
		return nil
	}
	tester.tcpProbe = func(_ context.Context, received NodeTransportCandidatePath, endpoint netip.AddrPort, query []byte) error {
		if received != path || endpoint.String() != "10.67.0.1:53" || binaryDNSID(query) != 0x1234 {
			t.Fatalf("TCP probe path=%T endpoint=%s query=%x", received, endpoint, query)
		}
		probeCalls = append(probeCalls, "tcp")
		return nil
	}
	tester.udpProbe = func(_ context.Context, received NodeTransportCandidatePath, endpoint netip.AddrPort, query []byte) error {
		if received != path || endpoint.String() != "10.67.0.1:53" || binaryDNSID(query) != 0x1234 {
			t.Fatalf("UDP probe path=%T endpoint=%s query=%x", received, endpoint, query)
		}
		probeCalls = append(probeCalls, "udp")
		return nil
	}

	result, err := tester.Test(context.Background(), model.TransportRestricted, restrictedConfiguration)
	if err != nil || !result.Ready() {
		t.Fatalf("candidate test = %+v, %v", result, err)
	}
	if factory.calls != 1 || factory.kind != model.TransportRestricted || !path.closed || controlProbe.nodeID != state.Nodes[0].ID || controlProbe.calls != 1 {
		t.Fatalf("factory=%+v path=%+v control=%+v", factory, path, controlProbe)
	}
	if got := probeCalls; len(got) != 3 || got[0] != "tunnel" || got[1] != "tcp" || got[2] != "udp" {
		t.Fatalf("probe order = %v", got)
	}
}

func TestBoundedNodeTransportCandidateTesterReportsEveryFailedProbeAndCleanup(t *testing.T) {
	_, standardConfiguration, _ := compiledNodeTransportPairFixture(t)
	path := &nodeTransportTestPath{}
	tester, _ := NewBoundedNodeTransportCandidateTester(
		&nodeTransportTestPathFactory{path: path},
		&nodeTransportTestControlProbe{err: errors.New("control unavailable")},
	)
	tester.entropy = bytes.NewReader([]byte{0x56, 0x78})
	tester.tunnelProbe = func(context.Context, NodeTransportCandidatePath, NodeConfiguration) error {
		return errors.New("tunnel unavailable")
	}
	tester.tcpProbe = func(context.Context, NodeTransportCandidatePath, netip.AddrPort, []byte) error {
		return errors.New("TCP unavailable")
	}
	tester.udpProbe = func(context.Context, NodeTransportCandidatePath, netip.AddrPort, []byte) error {
		return errors.New("UDP unavailable")
	}

	result, err := tester.Test(context.Background(), model.TransportStandard, standardConfiguration)
	if err != nil || result.Ready() || !path.closed || result.Control.State != transport.ProbeFailed ||
		result.ReverseTunnel.State != transport.ProbeFailed || result.SelectedTCP.State != transport.ProbeFailed ||
		result.SelectedUDP.State != transport.ProbeFailed {
		t.Fatalf("failed candidate test = %+v, path=%+v, %v", result, path, err)
	}

	path = &nodeTransportTestPath{closeErr: errors.New("cleanup failed")}
	tester.paths = &nodeTransportTestPathFactory{path: path}
	if _, err := tester.Test(context.Background(), model.TransportStandard, standardConfiguration); err == nil || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("cleanup error = %v", err)
	}
}

func TestNodeTransportDNSProbeIsBoundedAndRejectsSubstitution(t *testing.T) {
	query, err := nodeTransportDNSProbeQuery(bytes.NewReader([]byte{0xab, 0xcd}))
	if err != nil || binaryDNSID(query) != 0xabcd {
		t.Fatalf("DNS query = %x, %v", query, err)
	}
	response := append([]byte(nil), query...)
	response[2] |= 0x80
	if err := validateNodeTransportDNSProbeResponse(query, response); err != nil {
		t.Fatalf("valid DNS response: %v", err)
	}
	response[0] ^= 0xff
	if err := validateNodeTransportDNSProbeResponse(query, response); err == nil {
		t.Fatal("DNS response with another transaction ID was accepted")
	}
	if _, err := nodeTransportDNSProbeQuery(bytes.NewReader(nil)); err == nil {
		t.Fatal("short DNS probe entropy was accepted")
	}
}

func TestNodeTransportDNSProbesUseTCPFramingAndCandidateUDPExchange(t *testing.T) {
	query, err := nodeTransportDNSProbeQuery(bytes.NewReader([]byte{0x11, 0x22}))
	if err != nil {
		t.Fatal(err)
	}
	response := append([]byte(nil), query...)
	response[2] |= 0x80
	path := &scriptedNodeTransportPath{
		dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				header := make([]byte, 2)
				if _, err := io.ReadFull(server, header); err != nil {
					return
				}
				request := make([]byte, int(binary.BigEndian.Uint16(header)))
				if _, err := io.ReadFull(server, request); err != nil || !bytes.Equal(request, query) {
					return
				}
				binary.BigEndian.PutUint16(header, uint16(len(response)))
				_ = writeNodeTransportProbe(server, header)
				_ = writeNodeTransportProbe(server, response)
			}()
			return client, nil
		},
		udp: func(_ context.Context, address string, payload []byte) ([]byte, error) {
			if address != "10.67.0.1:53" || !bytes.Equal(payload, query) {
				return nil, errors.New("unexpected UDP request")
			}
			return response, nil
		},
	}
	endpoint := netip.MustParseAddrPort("10.67.0.1:53")
	if err := probeNodeTransportDNSTCP(context.Background(), path, endpoint, query); err != nil {
		t.Fatalf("TCP DNS probe: %v", err)
	}
	if err := probeNodeTransportDNSUDP(context.Background(), path, endpoint, query); err != nil {
		t.Fatalf("UDP DNS probe: %v", err)
	}
}

func TestNodeTransportTunnelProbeRequiresPinnedNameAndTLS13(t *testing.T) {
	_, configuration, _ := compiledNodeTransportPairFixture(t)
	certificatePEM, serverCertificate := nodeTransportTestTLSIdentity(t, tunnel.FRPTLSServerName)
	configuration = nodeTransportConfigurationWithCertificate(configuration, certificatePEM)
	path := nodeTransportTLSScriptedPath(serverCertificate, tls.VersionTLS13, tls.VersionTLS13)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeNodeTransportTunnelTLS(ctx, path, configuration); err != nil {
		t.Fatalf("tunnel TLS probe: %v", err)
	}

	wrongPEM, wrongCertificate := nodeTransportTestTLSIdentity(t, "wrong-tunnel.example")
	wrongConfiguration := nodeTransportConfigurationWithCertificate(configuration, wrongPEM)
	if err := probeNodeTransportTunnelTLS(ctx, nodeTransportTLSScriptedPath(wrongCertificate, tls.VersionTLS13, tls.VersionTLS13), wrongConfiguration); err == nil {
		t.Fatal("tunnel TLS probe accepted the wrong managed server name")
	}
	if err := probeNodeTransportTunnelTLS(ctx, nodeTransportTLSScriptedPath(serverCertificate, tls.VersionTLS12, tls.VersionTLS12), configuration); err == nil {
		t.Fatal("tunnel TLS probe accepted TLS 1.2")
	}
}

type nodeTransportTestPathFactory struct {
	path  NodeTransportCandidatePath
	kind  model.TransportKind
	calls int
}

type scriptedNodeTransportPath struct {
	dial func(context.Context, string, string) (net.Conn, error)
	udp  func(context.Context, string, []byte) ([]byte, error)
}

func (path *scriptedNodeTransportPath) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return path.dial(ctx, network, address)
}

func (path *scriptedNodeTransportPath) ExchangeUDP(ctx context.Context, address string, payload []byte) ([]byte, error) {
	return path.udp(ctx, address, payload)
}

func (*scriptedNodeTransportPath) Close(context.Context) error { return nil }

func (factory *nodeTransportTestPathFactory) Open(_ context.Context, kind model.TransportKind, _ NodeConfiguration) (NodeTransportCandidatePath, error) {
	factory.calls++
	factory.kind = kind
	return factory.path, nil
}

type nodeTransportTestPath struct {
	closed   bool
	closeErr error
}

func (*nodeTransportTestPath) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (*nodeTransportTestPath) ExchangeUDP(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("unused")
}

func (path *nodeTransportTestPath) Close(context.Context) error {
	path.closed = true
	return path.closeErr
}

type nodeTransportTestControlProbe struct {
	nodeID string
	calls  int
	err    error
}

func (probe *nodeTransportTestControlProbe) Probe(
	ctx context.Context,
	nodeID string,
	dial func(context.Context, string, string) (net.Conn, error),
) error {
	probe.calls++
	probe.nodeID = nodeID
	connection, err := dial(ctx, "tcp", "10.67.0.1:9443")
	if err == nil {
		_ = connection.Close()
	}
	if probe.err != nil {
		return probe.err
	}
	return err
}

func binaryDNSID(message []byte) uint16 {
	if len(message) < 2 {
		return 0
	}
	return uint16(message[0])<<8 | uint16(message[1])
}

func nodeTransportTestTLSIdentity(t *testing.T, serverName string) ([]byte, tls.Certificate) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: serverName},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{serverName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificatePEM, certificate
}

func nodeTransportConfigurationWithCertificate(configuration NodeConfiguration, certificatePEM []byte) NodeConfiguration {
	configuration.configs = configuration.ConfigFiles()
	for index := range configuration.configs {
		if configuration.configs[index].Name == tunnel.FRPServerCertificateName {
			configuration.configs[index].Content = append([]byte(nil), certificatePEM...)
		}
	}
	return configuration
}

func nodeTransportTLSScriptedPath(certificate tls.Certificate, minimum, maximum uint16) *scriptedNodeTransportPath {
	return &scriptedNodeTransportPath{dial: func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			connection := tls.Server(server, &tls.Config{
				Certificates: []tls.Certificate{certificate}, MinVersion: minimum, MaxVersion: maximum,
			})
			_ = connection.Handshake()
			_ = connection.Close()
		}()
		return client, nil
	}}
}
