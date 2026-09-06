package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const (
	nodeTransportCandidateProbeTimeout   = 5 * time.Second
	nodeTransportCandidateCleanupTimeout = 5 * time.Second
	nodeTransportDNSMaximumBytes         = 4096
	nodeTransportDNSProbeName            = "vpnctl-transport-test.invalid"
)

type NodeTransportCandidatePath interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	ExchangeUDP(context.Context, string, []byte) ([]byte, error)
	Close(context.Context) error
}

type NodeTransportCandidatePathFactory interface {
	Open(context.Context, model.TransportKind, NodeConfiguration) (NodeTransportCandidatePath, error)
}

type NodeTransportCandidateControlProbe interface {
	Probe(context.Context, string, func(context.Context, string, string) (net.Conn, error)) error
}

// BoundedNodeTransportCandidateTester proves all four mandatory node paths
// through one isolated candidate path. It never activates the candidate or
// changes the production selector and always closes transient resources on an
// independent bounded cleanup context.
type BoundedNodeTransportCandidateTester struct {
	paths   NodeTransportCandidatePathFactory
	control NodeTransportCandidateControlProbe
	entropy io.Reader

	tunnelProbe func(context.Context, NodeTransportCandidatePath, NodeConfiguration) error
	tcpProbe    func(context.Context, NodeTransportCandidatePath, netip.AddrPort, []byte) error
	udpProbe    func(context.Context, NodeTransportCandidatePath, netip.AddrPort, []byte) error
}

func NewBoundedNodeTransportCandidateTester(
	paths NodeTransportCandidatePathFactory,
	controlProbe NodeTransportCandidateControlProbe,
) (*BoundedNodeTransportCandidateTester, error) {
	if paths == nil || controlProbe == nil {
		return nil, fmt.Errorf("node transport candidate tester dependencies are incomplete")
	}
	return &BoundedNodeTransportCandidateTester{
		paths: paths, control: controlProbe, entropy: rand.Reader,
		tunnelProbe: probeNodeTransportTunnelTLS,
		tcpProbe:    probeNodeTransportDNSTCP,
		udpProbe:    probeNodeTransportDNSUDP,
	}, nil
}

func (tester *BoundedNodeTransportCandidateTester) Test(
	ctx context.Context,
	kind model.TransportKind,
	configuration NodeConfiguration,
) (result transport.TestResult, returnErr error) {
	if ctx == nil || tester == nil || tester.paths == nil || tester.control == nil || tester.entropy == nil ||
		tester.tunnelProbe == nil || tester.tcpProbe == nil || tester.udpProbe == nil {
		return transport.TestResult{}, fmt.Errorf("node transport candidate tester is incomplete")
	}
	if err := validateNodeTransportTestConfiguration(kind, configuration); err != nil {
		return transport.TestResult{}, err
	}
	path, err := tester.paths.Open(ctx, kind, configuration)
	if err != nil {
		return transport.TestResult{}, fmt.Errorf("open isolated %s candidate path: %w", kind, err)
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), nodeTransportCandidateCleanupTimeout)
		defer cancel()
		if closeErr := path.Close(cleanupContext); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close isolated %s candidate path: %w", kind, closeErr))
		}
	}()

	nodeID := configuration.StandardCandidate().Descriptor().OwnerID
	result.Control = tester.probe(ctx, "candidate-control-ready", "candidate-control-unavailable", func(probeContext context.Context) error {
		return tester.control.Probe(probeContext, nodeID, path.DialContext)
	})
	result.ReverseTunnel = tester.probe(ctx, "candidate-tunnel-tls-ready", "candidate-tunnel-tls-unavailable", func(probeContext context.Context) error {
		return tester.tunnelProbe(probeContext, path, configuration)
	})
	query, err := nodeTransportDNSProbeQuery(tester.entropy)
	if err != nil {
		return transport.TestResult{}, fmt.Errorf("create node transport DNS probe: %w", err)
	}
	endpoint, _ := configuration.TunnelCandidate().ServerEndpoint()
	dnsEndpoint := netip.AddrPortFrom(endpoint.Addr(), routing.GatewayDNSPort)
	result.SelectedTCP = tester.probe(ctx, string(kind)+"-selected-tcp-ready", string(kind)+"-selected-tcp-unavailable", func(probeContext context.Context) error {
		return tester.tcpProbe(probeContext, path, dnsEndpoint, query)
	})
	result.SelectedUDP = tester.probe(ctx, string(kind)+"-selected-udp-ready", string(kind)+"-selected-udp-unavailable", func(probeContext context.Context) error {
		return tester.udpProbe(probeContext, path, dnsEndpoint, query)
	})
	if err := result.Validate(); err != nil {
		return transport.TestResult{}, err
	}
	return result, nil
}

func (*BoundedNodeTransportCandidateTester) probe(
	ctx context.Context,
	readyCode, unavailableCode string,
	probe func(context.Context) error,
) transport.ProbeResult {
	probeContext, cancel := context.WithTimeout(ctx, nodeTransportCandidateProbeTimeout)
	defer cancel()
	if probe(probeContext) != nil {
		return transport.ProbeResult{State: transport.ProbeFailed, Code: unavailableCode}
	}
	return transport.ProbeResult{State: transport.ProbePassed, Code: readyCode}
}

func validateNodeTransportTestConfiguration(kind model.TransportKind, configuration NodeConfiguration) error {
	if kind != model.TransportStandard && kind != model.TransportRestricted {
		return fmt.Errorf("unsupported node transport test kind %q", kind)
	}
	if err := configuration.Validate(); err != nil {
		return err
	}
	descriptor := configuration.StandardCandidate().Descriptor()
	if kind == model.TransportRestricted {
		descriptor = configuration.RestrictedCandidate().Descriptor()
	}
	if descriptor.Kind != kind || descriptor.OwnerKind != model.TargetNode ||
		descriptor.OwnerID != configuration.StandardCandidate().Descriptor().OwnerID ||
		descriptor.CredentialGeneration != configuration.TunnelCandidate().Descriptor().CredentialGeneration ||
		configuration.RoutingCandidate().Descriptor().ActiveTransport != kind ||
		configuration.TunnelCandidate().Descriptor().ActiveTransport != kind {
		return fmt.Errorf("node transport test candidate does not match the complete target generation")
	}
	endpoint, err := configuration.TunnelCandidate().ServerEndpoint()
	if err != nil || !endpoint.Addr().Is4() || endpoint.Port() != tunnel.FRPServerPort {
		return fmt.Errorf("node transport test gateway endpoint is invalid")
	}
	return nil
}

func probeNodeTransportTunnelTLS(ctx context.Context, path NodeTransportCandidatePath, configuration NodeConfiguration) error {
	certificatePEM, err := nodeTransportConfigurationFile(configuration, tunnel.FRPServerCertificateName)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		return fmt.Errorf("node transport tunnel certificate is invalid")
	}
	endpoint, err := configuration.TunnelCandidate().ServerEndpoint()
	if err != nil {
		return err
	}
	raw, err := path.DialContext(ctx, "tcp4", endpoint.String())
	if err != nil {
		return err
	}
	defer raw.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			return err
		}
	}
	connection := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: tunnel.FRPTLSServerName,
	})
	if err := connection.HandshakeContext(ctx); err != nil {
		return err
	}
	if connection.ConnectionState().Version != tls.VersionTLS13 {
		return fmt.Errorf("node transport tunnel did not negotiate TLS 1.3")
	}
	return nil
}

func probeNodeTransportDNSTCP(ctx context.Context, path NodeTransportCandidatePath, endpoint netip.AddrPort, query []byte) error {
	connection, err := path.DialContext(ctx, "tcp4", endpoint.String())
	if err != nil {
		return err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return err
		}
	}
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(query)))
	if err := writeNodeTransportProbe(connection, header); err != nil {
		return err
	}
	if err := writeNodeTransportProbe(connection, query); err != nil {
		return err
	}
	if _, err := io.ReadFull(connection, header); err != nil {
		return err
	}
	count := int(binary.BigEndian.Uint16(header))
	if count < 12 || count > nodeTransportDNSMaximumBytes {
		return fmt.Errorf("node transport DNS TCP response has invalid size")
	}
	response := make([]byte, count)
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	return validateNodeTransportDNSProbeResponse(query, response)
}

func probeNodeTransportDNSUDP(ctx context.Context, path NodeTransportCandidatePath, endpoint netip.AddrPort, query []byte) error {
	response, err := path.ExchangeUDP(ctx, endpoint.String(), query)
	if err != nil {
		return err
	}
	return validateNodeTransportDNSProbeResponse(query, response)
}

func nodeTransportDNSProbeQuery(entropy io.Reader) ([]byte, error) {
	identifier := make([]byte, 2)
	if _, err := io.ReadFull(entropy, identifier); err != nil {
		return nil, err
	}
	message := make([]byte, 12)
	copy(message[:2], identifier)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	for _, label := range strings.Split(nodeTransportDNSProbeName, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	return append(message, 0, 0, 1, 0, 1), nil
}

func validateNodeTransportDNSProbeResponse(query, response []byte) error {
	if len(query) < 12 || len(response) < len(query) || len(response) > nodeTransportDNSMaximumBytes ||
		!bytes.Equal(query[:2], response[:2]) || response[2]&0x80 == 0 ||
		binary.BigEndian.Uint16(response[4:6]) != 1 || !bytes.Equal(query[12:], response[12:len(query)]) {
		return fmt.Errorf("node transport DNS response does not match the bounded probe")
	}
	return nil
}

func nodeTransportConfigurationFile(configuration NodeConfiguration, name string) ([]byte, error) {
	for _, config := range configuration.ConfigFiles() {
		if config.Name == name {
			return config.Content, nil
		}
	}
	return nil, fmt.Errorf("node transport configuration file %s is missing", strconv.Quote(name))
}

func writeNodeTransportProbe(writer io.Writer, content []byte) error {
	for len(content) != 0 {
		count, err := writer.Write(content)
		if err != nil {
			return err
		}
		if count <= 0 {
			return io.ErrUnexpectedEOF
		}
		content = content[count:]
	}
	return nil
}

var _ NodeTransportCandidateTester = (*BoundedNodeTransportCandidateTester)(nil)
