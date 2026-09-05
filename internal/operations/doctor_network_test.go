package operations

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

const networkDoctorProbeID = "11111111-1111-4111-8111-111111111111-001"

func TestNetworkDoctorDNSProbesUDPAndTCP(t *testing.T) {
	t.Parallel()

	for _, protocol := range []DoctorProtocol{DoctorProtocolDNSUDP, DoctorProtocolDNSTCP} {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			t.Parallel()
			serverErr := make(chan error, 1)
			dial := func(_ context.Context, network, address string) (net.Conn, error) {
				wantNetwork := "udp"
				if protocol == DoctorProtocolDNSTCP {
					wantNetwork = "tcp"
				}
				if network != wantNetwork || address != "192.0.2.53:53" {
					t.Fatalf("dial = %s/%s, want %s/192.0.2.53:53", network, address, wantNetwork)
				}
				client, server := net.Pipe()
				go serveDoctorDNSPipe(server, protocol, serverErr)
				return client, nil
			}
			runner, err := newNetworkDoctorProbeRunner(dial, time.Now, nil)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := runner.Probe(context.Background(), DoctorProbeRequest{
				ProbeID: networkDoctorProbeID, Scope: DoctorScopeDNS, Name: "dns.direct.udp.1",
				Kind: DoctorProbeDirectDNS, Protocol: protocol, ResourceKind: "dns_path",
				ResourceID: "direct", Endpoint: "192.0.2.53:53",
			})
			if err != nil || !observation.Passed || observation.Code != "dns_query_passed" {
				t.Fatalf("observation = %+v, err=%v", observation, err)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNetworkDoctorTCPProbeUsesOnlyValidatedEndpoint(t *testing.T) {
	t.Parallel()

	serverClosed := make(chan struct{})
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:7000" {
			t.Fatalf("dial = %s/%s", network, address)
		}
		client, server := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, server)
			_ = server.Close()
			close(serverClosed)
		}()
		return client, nil
	}
	runner, err := newNetworkDoctorProbeRunner(dial, time.Now, nil)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runner.Probe(context.Background(), DoctorProbeRequest{
		ProbeID: networkDoctorProbeID, Scope: DoctorScopeTunnel, Name: "tunnel.server.tcp",
		Kind: DoctorProbeTunnelSession, Protocol: DoctorProtocolTCP, ResourceKind: "tunnel",
		ResourceID: "server", Endpoint: "127.0.0.1:7000",
	})
	if err != nil || !observation.Passed || observation.Code != "tunnel_tcp_passed" {
		t.Fatalf("observation = %+v, err=%v", observation, err)
	}
	<-serverClosed
}

func TestNetworkDoctorTLSAndReservedHealthUsePinnedPublicProfile(t *testing.T) {
	t.Parallel()

	certificate := networkDoctorCertificate(t, "203.0.113.10", time.Now())
	for _, probe := range []struct {
		name       string
		kind       DoctorProbeKind
		protocol   DoctorProtocol
		healthPath string
		code       string
	}{{"tls", DoctorProbeIngressTLS, DoctorProtocolTLS, "", "ingress_tls_passed"},
		{"health", DoctorProbeIngressHealth, DoctorProtocolHTTPS, "/.well-known/vpnctl/health", "ingress_health_passed"}} {
		probe := probe
		t.Run(probe.name, func(t *testing.T) {
			t.Parallel()
			serverErr := make(chan error, 1)
			dial := func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "203.0.113.10:443" {
					t.Fatalf("dial = %s/%s", network, address)
				}
				client, server := net.Pipe()
				go serveDoctorTLSPipe(server, certificate, probe.kind, serverErr)
				return client, nil
			}
			runner, err := newNetworkDoctorProbeRunner(dial, time.Now, nil)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := runner.Probe(context.Background(), DoctorProbeRequest{
				ProbeID: networkDoctorProbeID, Scope: DoctorScopeIngress, Name: "ingress.public." + probe.name,
				Kind: probe.kind, Protocol: probe.protocol, ResourceKind: "ingress", ResourceID: "public",
				Endpoint: "203.0.113.10:443", HealthPath: probe.healthPath,
			})
			if err != nil || !observation.Passed || observation.Code != probe.code {
				t.Fatalf("observation = %+v, err=%v", observation, err)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNetworkDoctorRejectsInvalidAndExternalRequestsBeforeDial(t *testing.T) {
	t.Parallel()

	dials := 0
	runner, err := newNetworkDoctorProbeRunner(func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, nil
	}, time.Now, nil)
	if err != nil {
		t.Fatal(err)
	}
	invalid := DoctorProbeRequest{Kind: DoctorProbeTunnelSession}
	if _, err := runner.Probe(context.Background(), invalid); err == nil || dials != 0 {
		t.Fatalf("invalid request err=%v dials=%d", err, dials)
	}
	probeURL, err := NewDoctorProbeURL("https://example.com/probe")
	if err != nil {
		t.Fatal(err)
	}
	external := DoctorProbeRequest{
		ProbeID: networkDoctorProbeID, Scope: DoctorScopeExternal, Name: "external.explicit_https_get",
		Kind: DoctorProbeExternalHTTPS, Protocol: DoctorProtocolHTTPS, ResourceKind: "external_dependency",
		ResourceID: "explicit", HTTPMethod: http.MethodGet, ProbeURL: probeURL,
	}
	if _, err := runner.Probe(context.Background(), external); err == nil || dials != 0 {
		t.Fatalf("external request err=%v dials=%d", err, dials)
	}
}

func TestNetworkDoctorDelegatesClosedActiveTransportProbe(t *testing.T) {
	t.Parallel()

	active := &networkDoctorActiveProbe{}
	runner, err := newNetworkDoctorProbeRunner(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("active probe reached network dialer")
		return nil, nil
	}, time.Now, active)
	if err != nil {
		t.Fatal(err)
	}
	request := DoctorProbeRequest{
		ProbeID: networkDoctorProbeID, Scope: DoctorScopeTransport, Name: "transport.standard.tcp",
		Kind: DoctorProbeActiveTransport, Protocol: DoctorProtocolTCP, ResourceKind: "transport",
		ResourceID: "standard", Transport: "standard", OuterProtocol: "udp",
	}
	observation, err := runner.Probe(context.Background(), request)
	if err != nil || observation.Code != "active_delegate_passed" || active.request != request {
		t.Fatalf("observation=%+v request=%+v err=%v", observation, active.request, err)
	}
}

type networkDoctorActiveProbe struct{ request DoctorProbeRequest }

func (probe *networkDoctorActiveProbe) ProbeActiveTransport(_ context.Context, request DoctorProbeRequest) (DoctorProbeObservation, error) {
	probe.request = request
	return DoctorProbeObservation{Passed: true, Code: "active_delegate_passed"}, nil
}

func serveDoctorDNSPipe(connection net.Conn, protocol DoctorProtocol, result chan<- error) {
	defer connection.Close()
	var query []byte
	if protocol == DoctorProtocolDNSTCP {
		var length [2]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			result <- err
			return
		}
		query = make([]byte, int(binary.BigEndian.Uint16(length[:])))
		if _, err := io.ReadFull(connection, query); err != nil {
			result <- err
			return
		}
	} else {
		query = make([]byte, 512)
		read, err := connection.Read(query)
		if err != nil {
			result <- err
			return
		}
		query = query[:read]
	}
	response := append([]byte(nil), query...)
	response[2], response[3] = 0x81, 0x80
	if protocol == DoctorProtocolDNSTCP {
		framed := make([]byte, len(response)+2)
		binary.BigEndian.PutUint16(framed[:2], uint16(len(response)))
		copy(framed[2:], response)
		_, resultErr := connection.Write(framed)
		result <- resultErr
		return
	}
	_, resultErr := connection.Write(response)
	result <- resultErr
}

func networkDoctorCertificate(t *testing.T, address string, now time.Time) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := now.UTC().Truncate(time.Second).Add(-time.Hour)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: address},
		NotBefore: notBefore, NotAfter: notBefore.Add(1825 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP(address)},
		BasicConstraintsValid: true, IsCA: false, SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func serveDoctorTLSPipe(connection net.Conn, certificate tls.Certificate, kind DoctorProbeKind, result chan<- error) {
	tlsConnection := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	defer tlsConnection.Close()
	if err := tlsConnection.Handshake(); err != nil {
		result <- err
		return
	}
	if kind == DoctorProbeIngressTLS {
		result <- nil
		return
	}
	request, err := http.ReadRequest(bufio.NewReader(tlsConnection))
	if err != nil {
		result <- err
		return
	}
	if request.Method != http.MethodGet || request.URL.Path != "/.well-known/vpnctl/health" {
		result <- io.ErrUnexpectedEOF
		return
	}
	_, err = io.WriteString(tlsConnection, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	result <- err
}
