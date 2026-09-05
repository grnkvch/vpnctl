package operations

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
)

const maximumDoctorDNSResponseBytes = 4096

type ActiveTransportDoctorProber interface {
	ProbeActiveTransport(context.Context, DoctorProbeRequest) (DoctorProbeObservation, error)
}

type doctorDialContext func(context.Context, string, string) (net.Conn, error)

// NetworkDoctorProbeRunner is the production-safe executor for closed doctor
// requests. It can dial only request endpoints that already passed
// DoctorProbeRequest.Validate; it has no state writer or mutation dependency.
type NetworkDoctorProbeRunner struct {
	dial   doctorDialContext
	now    func() time.Time
	active ActiveTransportDoctorProber
}

func NewNetworkDoctorProbeRunner(active ActiveTransportDoctorProber) (*NetworkDoctorProbeRunner, error) {
	dialer := &net.Dialer{Timeout: DefaultDoctorProbeTimeout, KeepAlive: 30 * time.Second}
	return newNetworkDoctorProbeRunner(dialer.DialContext, time.Now, active)
}

func newNetworkDoctorProbeRunner(dial doctorDialContext, now func() time.Time, active ActiveTransportDoctorProber) (*NetworkDoctorProbeRunner, error) {
	if dial == nil || now == nil {
		return nil, fmt.Errorf("network doctor runtime is incomplete")
	}
	return &NetworkDoctorProbeRunner{dial: dial, now: now, active: active}, nil
}

func (runner *NetworkDoctorProbeRunner) Probe(ctx context.Context, request DoctorProbeRequest) (DoctorProbeObservation, error) {
	if ctx == nil || runner == nil || runner.dial == nil || runner.now == nil {
		return DoctorProbeObservation{}, fmt.Errorf("network doctor runner is incomplete")
	}
	if err := request.Validate(); err != nil {
		return DoctorProbeObservation{}, err
	}
	switch request.Kind {
	case DoctorProbeDirectDNS, DoctorProbeGatewayDNS:
		return runner.probeDNS(ctx, request)
	case DoctorProbeTunnelSession, DoctorProbeTunnelMapping, DoctorProbeLocalUpstream:
		return runner.probeTCP(ctx, request)
	case DoctorProbeIngressTLS:
		return runner.probeTLS(ctx, request)
	case DoctorProbeIngressHealth:
		return runner.probeHTTPSHealth(ctx, request)
	case DoctorProbeActiveTransport:
		if runner.active == nil {
			return DoctorProbeObservation{}, fmt.Errorf("active transport doctor adapter is unavailable")
		}
		return runner.active.ProbeActiveTransport(ctx, request)
	case DoctorProbeExternalHTTPS:
		return DoctorProbeObservation{}, fmt.Errorf("external HTTPS requires the explicit opt-in runner")
	default:
		return DoctorProbeObservation{}, fmt.Errorf("unsupported doctor probe kind")
	}
}

func (runner *NetworkDoctorProbeRunner) probeTCP(ctx context.Context, request DoctorProbeRequest) (DoctorProbeObservation, error) {
	connection, err := runner.dial(ctx, "tcp", request.Endpoint)
	if err != nil {
		return DoctorProbeObservation{}, fmt.Errorf("TCP doctor connection failed")
	}
	if err := connection.Close(); err != nil {
		return DoctorProbeObservation{}, fmt.Errorf("close TCP doctor connection")
	}
	code := "tunnel_tcp_passed"
	if request.Kind == DoctorProbeLocalUpstream {
		code = "local_upstream_tcp_passed"
	}
	return DoctorProbeObservation{Passed: true, Code: code}, nil
}

func (runner *NetworkDoctorProbeRunner) probeDNS(ctx context.Context, request DoctorProbeRequest) (DoctorProbeObservation, error) {
	query := doctorDNSQuery(request.ProbeID)
	network := "udp"
	if request.Protocol == DoctorProtocolDNSTCP {
		network = "tcp"
	}
	connection, err := runner.dial(ctx, network, request.Endpoint)
	if err != nil {
		return DoctorProbeObservation{}, fmt.Errorf("DNS doctor connection failed")
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	var response []byte
	if network == "udp" {
		if _, err := connection.Write(query); err != nil {
			return DoctorProbeObservation{}, fmt.Errorf("send DNS doctor query")
		}
		buffer := make([]byte, maximumDoctorDNSResponseBytes)
		read, err := connection.Read(buffer)
		if err != nil {
			return DoctorProbeObservation{}, fmt.Errorf("read DNS doctor response")
		}
		response = buffer[:read]
	} else {
		framed := make([]byte, len(query)+2)
		binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
		copy(framed[2:], query)
		if _, err := connection.Write(framed); err != nil {
			return DoctorProbeObservation{}, fmt.Errorf("send DNS doctor query")
		}
		var length [2]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return DoctorProbeObservation{}, fmt.Errorf("read DNS doctor response length")
		}
		size := int(binary.BigEndian.Uint16(length[:]))
		if size < 12 || size > maximumDoctorDNSResponseBytes {
			return DoctorProbeObservation{}, fmt.Errorf("DNS doctor response size is invalid")
		}
		response = make([]byte, size)
		if _, err := io.ReadFull(connection, response); err != nil {
			return DoctorProbeObservation{}, fmt.Errorf("read DNS doctor response")
		}
	}
	if err := validateDoctorDNSResponse(query, response); err != nil {
		return DoctorProbeObservation{}, err
	}
	return DoctorProbeObservation{Passed: true, Code: "dns_query_passed"}, nil
}

func doctorDNSQuery(probeID string) []byte {
	digest := sha256.Sum256([]byte(probeID))
	query := make([]byte, 0, 29)
	query = append(query, digest[0], digest[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split("example.com", ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0x00, 0x00, 0x01, 0x00, 0x01)
}

func validateDoctorDNSResponse(query, response []byte) error {
	if len(query) < 12 || len(response) < 12 || response[0] != query[0] || response[1] != query[1] {
		return fmt.Errorf("DNS doctor response identity is invalid")
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x0200 != 0 || flags&0x000f != 0 || binary.BigEndian.Uint16(response[4:6]) == 0 {
		return fmt.Errorf("DNS doctor response status is invalid")
	}
	return nil
}

func (runner *NetworkDoctorProbeRunner) probeTLS(ctx context.Context, request DoctorProbeRequest) (DoctorProbeObservation, error) {
	connection, err := runner.dial(ctx, "tcp", request.Endpoint)
	if err != nil {
		return DoctorProbeObservation{}, fmt.Errorf("TLS doctor connection failed")
	}
	defer connection.Close()
	configuration, err := runner.publicIngressTLSConfig(request.Endpoint)
	if err != nil {
		return DoctorProbeObservation{}, err
	}
	tlsConnection := tls.Client(connection, configuration)
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return DoctorProbeObservation{}, fmt.Errorf("TLS doctor handshake failed")
	}
	return DoctorProbeObservation{Passed: true, Code: "ingress_tls_passed"}, nil
}

func (runner *NetworkDoctorProbeRunner) probeHTTPSHealth(ctx context.Context, request DoctorProbeRequest) (DoctorProbeObservation, error) {
	configuration, err := runner.publicIngressTLSConfig(request.Endpoint)
	if err != nil {
		return DoctorProbeObservation{}, err
	}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         runner.dial,
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		TLSHandshakeTimeout: DefaultDoctorProbeTimeout,
		TLSClientConfig:     configuration,
	}
	defer transport.CloseIdleConnections()
	outbound, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+request.Endpoint+request.HealthPath, nil)
	if err != nil {
		return DoctorProbeObservation{}, fmt.Errorf("construct ingress health request")
	}
	outbound.Header.Set("User-Agent", "vpnctl-doctor/"+request.ProbeID)
	response, err := transport.RoundTrip(outbound)
	if err != nil {
		return DoctorProbeObservation{}, fmt.Errorf("ingress health request failed")
	}
	if response.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		_ = response.Body.Close()
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return DoctorProbeObservation{Passed: false, Code: "ingress_health_status_failed"}, nil
	}
	return DoctorProbeObservation{Passed: true, Code: "ingress_health_passed"}, nil
}

func (runner *NetworkDoctorProbeRunner) publicIngressTLSConfig(endpoint string) (*tls.Config, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || port != strconv.Itoa(443) || net.ParseIP(host) == nil {
		return nil, fmt.Errorf("public ingress TLS endpoint is invalid")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		// The product certificate is intentionally self-signed and registered
		// explicitly with webhook providers. VerifyConnection below enforces
		// its IP identity, validity, RSA strength, and self-signature.
		InsecureSkipVerify: true, //nolint:gosec -- replaced by the closed verifier below
		VerifyConnection: func(connection tls.ConnectionState) error {
			if len(connection.PeerCertificates) != 1 {
				return fmt.Errorf("ingress TLS must present exactly one certificate")
			}
			if err := ingress.ValidateLivePublicCertificate(connection.PeerCertificates[0], host, runner.now()); err != nil {
				return fmt.Errorf("ingress TLS certificate does not match the pinned self-signed RSA profile")
			}
			return nil
		},
	}, nil
}

var _ DoctorProbeRunner = (*NetworkDoctorProbeRunner)(nil)
