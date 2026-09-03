package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	DefaultRestrictedReadinessTimeout = 15 * time.Second
	maximumRestrictedProbeBytes       = 1024
	maximumRestrictedProbeAttempt     = 10 * time.Second
	restrictedProbeRetryDelay         = 100 * time.Millisecond
	restrictedSOCKSVersion            = 5
	restrictedSOCKSNoAuthentication   = 0
	restrictedSOCKSConnect            = 1
	restrictedSOCKSUDPAssociate       = 3
	restrictedSOCKSIPv4               = 1
)

var ErrRestrictedNotReady = errors.New("restricted transport is not ready")

type RestrictedReadinessResult struct {
	Candidate   CandidateDescriptor
	SelectedTCP ProbeResult
	SelectedUDP ProbeResult
}

func (result RestrictedReadinessResult) Validate() error {
	if err := result.Candidate.Validate(); err != nil {
		return fmt.Errorf("restricted readiness candidate: %w", err)
	}
	if result.Candidate.Kind != model.TransportRestricted {
		return fmt.Errorf("restricted readiness requires a restricted candidate")
	}
	if err := result.SelectedTCP.Validate(); err != nil {
		return fmt.Errorf("restricted selected TCP readiness: %w", err)
	}
	if err := result.SelectedUDP.Validate(); err != nil {
		return fmt.Errorf("restricted selected UDP readiness: %w", err)
	}
	return nil
}

func (result RestrictedReadinessResult) Ready() bool {
	return result.Validate() == nil &&
		result.SelectedTCP.State == ProbePassed && result.SelectedUDP.State == ProbePassed
}

// RestrictedReadinessProber owns a transient, isolated test connection. Its
// result is tied to the exact candidate descriptor so stale readiness cannot
// authorize another credential or config generation.
type RestrictedReadinessProber interface {
	Probe(context.Context, RestrictedNodeCandidate) (RestrictedReadinessResult, error)
}

type RestrictedReadinessGate struct {
	prober RestrictedReadinessProber
}

func NewRestrictedReadinessGate(prober RestrictedReadinessProber) (*RestrictedReadinessGate, error) {
	if prober == nil {
		return nil, fmt.Errorf("restricted readiness prober is required")
	}
	return &RestrictedReadinessGate{prober: prober}, nil
}

// RestrictedReadyCandidate can only be produced by Check after both mandatory
// probes pass. Later activation/switch orchestration must accept this type,
// never an unchecked RestrictedNodeCandidate.
type RestrictedReadyCandidate struct {
	candidate RestrictedNodeCandidate
	result    RestrictedReadinessResult
	verified  bool
}

var _ Candidate = RestrictedReadyCandidate{}

func (candidate RestrictedReadyCandidate) Descriptor() CandidateDescriptor {
	return candidate.candidate.Descriptor()
}

func (candidate RestrictedReadyCandidate) Bytes() []byte {
	return candidate.candidate.Bytes()
}

func (candidate RestrictedReadyCandidate) Readiness() RestrictedReadinessResult {
	return candidate.result
}

func (candidate RestrictedReadyCandidate) Valid() bool {
	return candidate.verified && candidate.result.Ready() && candidate.result.Candidate == candidate.candidate.Descriptor()
}

type RestrictedNotReadyError struct {
	Code string
}

func (failure *RestrictedNotReadyError) Error() string {
	if failure == nil || failure.Code == "" {
		return ErrRestrictedNotReady.Error()
	}
	return ErrRestrictedNotReady.Error() + ": " + failure.Code
}

func (failure *RestrictedNotReadyError) Unwrap() error { return ErrRestrictedNotReady }

func (gate *RestrictedReadinessGate) Check(ctx context.Context, candidate RestrictedNodeCandidate) (RestrictedReadyCandidate, RestrictedReadinessResult, error) {
	if ctx == nil {
		return RestrictedReadyCandidate{}, RestrictedReadinessResult{}, fmt.Errorf("context is required")
	}
	if gate == nil || gate.prober == nil {
		return RestrictedReadyCandidate{}, RestrictedReadinessResult{}, fmt.Errorf("restricted readiness gate is incomplete")
	}
	if err := candidate.Descriptor().Validate(); err != nil {
		return RestrictedReadyCandidate{}, RestrictedReadinessResult{}, err
	}
	if candidate.Descriptor().Kind != model.TransportRestricted {
		return RestrictedReadyCandidate{}, RestrictedReadinessResult{}, fmt.Errorf("restricted readiness gate received another transport kind")
	}
	if err := ValidateNodeRestrictedConfig(candidate.Bytes()); err != nil {
		return RestrictedReadyCandidate{}, RestrictedReadinessResult{}, fmt.Errorf("validate restricted candidate before readiness: %w", err)
	}
	result, err := gate.prober.Probe(ctx, candidate)
	if err != nil {
		return RestrictedReadyCandidate{}, RestrictedReadinessResult{}, fmt.Errorf("probe restricted readiness: %w", err)
	}
	if err := result.Validate(); err != nil {
		return RestrictedReadyCandidate{}, RestrictedReadinessResult{}, err
	}
	if result.Candidate != candidate.Descriptor() {
		return RestrictedReadyCandidate{}, result, fmt.Errorf("restricted readiness result belongs to another candidate")
	}
	if !result.Ready() {
		return RestrictedReadyCandidate{}, result, &RestrictedNotReadyError{Code: restrictedReadinessFailureCode(result)}
	}
	ready := RestrictedReadyCandidate{candidate: candidate, result: result, verified: true}
	return ready, result, nil
}

func restrictedReadinessFailureCode(result RestrictedReadinessResult) string {
	if result.SelectedTCP.State != ProbePassed {
		return "restricted-selected-tcp-unavailable"
	}
	if result.SelectedUDP.State != ProbePassed {
		return "restricted-uot-unavailable"
	}
	return "restricted-readiness-invalid"
}

// RestrictedNetworkReadinessProber performs bounded SOCKS5 round trips to a
// controlled gateway-loopback TCP/UDP echo endpoint. Because that endpoint is
// unreachable directly from the node, successful probes demonstrate the
// selected path; the candidate validator separately forbids DIRECT/native UDP.
type RestrictedNetworkReadinessProber struct {
	proxy        netip.AddrPort
	target       netip.AddrPort
	tcpChallenge []byte
	udpChallenge []byte
	timeout      time.Duration
}

var _ RestrictedReadinessProber = (*RestrictedNetworkReadinessProber)(nil)

func NewRestrictedNetworkReadinessProber(proxy, target string, tcpChallenge, udpChallenge []byte, timeout time.Duration) (*RestrictedNetworkReadinessProber, error) {
	proxyEndpoint, err := restrictedLoopbackEndpoint("proxy", proxy)
	if err != nil {
		return nil, err
	}
	targetEndpoint, err := restrictedLoopbackEndpoint("target", target)
	if err != nil {
		return nil, err
	}
	if proxyEndpoint == targetEndpoint {
		return nil, fmt.Errorf("restricted readiness proxy and target must differ")
	}
	if timeout == 0 {
		timeout = DefaultRestrictedReadinessTimeout
	}
	if timeout < 100*time.Millisecond || timeout > 30*time.Second {
		return nil, fmt.Errorf("restricted readiness timeout must be between 100ms and 30s")
	}
	if err := validateRestrictedProbeChallenge("TCP", tcpChallenge); err != nil {
		return nil, err
	}
	if err := validateRestrictedProbeChallenge("UDP", udpChallenge); err != nil {
		return nil, err
	}
	return &RestrictedNetworkReadinessProber{
		proxy: proxyEndpoint, target: targetEndpoint,
		tcpChallenge: append([]byte(nil), tcpChallenge...), udpChallenge: append([]byte(nil), udpChallenge...), timeout: timeout,
	}, nil
}

func (prober *RestrictedNetworkReadinessProber) Probe(ctx context.Context, candidate RestrictedNodeCandidate) (RestrictedReadinessResult, error) {
	if ctx == nil {
		return RestrictedReadinessResult{}, fmt.Errorf("context is required")
	}
	if prober == nil || !prober.proxy.IsValid() || !prober.target.IsValid() {
		return RestrictedReadinessResult{}, fmt.Errorf("restricted network readiness prober is incomplete")
	}
	if err := ValidateNodeRestrictedConfig(candidate.Bytes()); err != nil {
		return RestrictedReadinessResult{}, fmt.Errorf("validate restricted readiness candidate: %w", err)
	}
	result := RestrictedReadinessResult{Candidate: candidate.Descriptor()}
	tcpErr := restrictedRetryProbe(ctx, prober.timeout, func(probeContext context.Context) error {
		return restrictedSOCKSTCPRoundTrip(probeContext, prober.proxy, prober.target, prober.tcpChallenge)
	})
	if tcpErr == nil {
		result.SelectedTCP = ProbeResult{State: ProbePassed, Code: "restricted-selected-tcp-ready"}
	} else {
		result.SelectedTCP = ProbeResult{State: ProbeFailed, Code: "restricted-selected-tcp-unavailable"}
	}
	udpErr := restrictedRetryProbe(ctx, prober.timeout, func(probeContext context.Context) error {
		return restrictedSOCKSUDPRoundTrip(probeContext, prober.proxy, prober.target, prober.udpChallenge)
	})
	if udpErr == nil {
		result.SelectedUDP = ProbeResult{State: ProbePassed, Code: "restricted-uot-ready"}
	} else {
		result.SelectedUDP = ProbeResult{State: ProbeFailed, Code: "restricted-uot-unavailable"}
	}
	return result, nil
}

// restrictedRetryProbe retries only the same candidate path. Per-attempt
// deadlines recover from a cold provider connection without introducing a
// direct path, native UDP, or another transport into readiness.
func restrictedRetryProbe(ctx context.Context, timeout time.Duration, probe func(context.Context) error) error {
	probeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for {
		attemptTimeout := maximumRestrictedProbeAttempt
		if deadline, ok := probeContext.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				if lastErr != nil {
					return lastErr
				}
				return probeContext.Err()
			}
			if remaining < attemptTimeout {
				attemptTimeout = remaining
			}
		}
		attemptContext, attemptCancel := context.WithTimeout(probeContext, attemptTimeout)
		lastErr = probe(attemptContext)
		attemptCancel()
		if lastErr == nil {
			return nil
		}
		timer := time.NewTimer(restrictedProbeRetryDelay)
		select {
		case <-probeContext.Done():
			timer.Stop()
			return lastErr
		case <-timer.C:
		}
	}
}

// RenderRestrictedReadinessConfig adds a loopback-only SOCKS listener to an
// otherwise production-identical node candidate. It is transient test input,
// not a production routing artifact and contains no controller endpoint.
func RenderRestrictedReadinessConfig(candidate RestrictedNodeCandidate, socksPort int) ([]byte, error) {
	if err := candidate.Descriptor().Validate(); err != nil {
		return nil, err
	}
	if err := ValidateNodeRestrictedConfig(candidate.Bytes()); err != nil {
		return nil, err
	}
	if socksPort < 1024 || socksPort > 65535 || socksPort == RestrictedTCPPort {
		return nil, fmt.Errorf("restricted readiness SOCKS port must be an unprivileged non-provider port")
	}
	prefix := fmt.Sprintf("socks-port: %d\nallow-lan: false\nbind-address: 127.0.0.1\n", socksPort)
	content := append([]byte(prefix), candidate.Bytes()...)
	if len(content) > maximumRestrictedConfigBytes {
		return nil, fmt.Errorf("restricted readiness config exceeds %d bytes", maximumRestrictedConfigBytes)
	}
	return content, nil
}

func restrictedLoopbackEndpoint(name, value string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint.String() != value || !endpoint.Addr().Is4() || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("restricted readiness %s must be a canonical IPv4 loopback endpoint", name)
	}
	return endpoint, nil
}

func validateRestrictedProbeChallenge(name string, challenge []byte) error {
	if len(challenge) == 0 || len(challenge) > maximumRestrictedProbeBytes {
		return fmt.Errorf("restricted readiness %s challenge must contain 1..%d bytes", name, maximumRestrictedProbeBytes)
	}
	return nil
}

func restrictedSOCKSTCPRoundTrip(ctx context.Context, proxy, target netip.AddrPort, challenge []byte) error {
	connection, _, err := restrictedSOCKSRequest(ctx, proxy, restrictedSOCKSConnect, target)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := restrictedWriteAll(connection, challenge); err != nil {
		return err
	}
	received := make([]byte, len(challenge))
	if _, err := io.ReadFull(connection, received); err != nil {
		return err
	}
	if !bytes.Equal(received, challenge) {
		return fmt.Errorf("restricted TCP probe response mismatch")
	}
	return nil
}

func restrictedSOCKSUDPRoundTrip(ctx context.Context, proxy, target netip.AddrPort, challenge []byte) error {
	control, relay, err := restrictedSOCKSRequest(ctx, proxy, restrictedSOCKSUDPAssociate, netip.AddrPortFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		return err
	}
	defer control.Close()
	if relay.Addr().IsUnspecified() {
		relay = netip.AddrPortFrom(proxy.Addr(), relay.Port())
	}
	if !relay.Addr().Is4() || !relay.Addr().IsLoopback() || relay.Port() == 0 {
		return fmt.Errorf("restricted SOCKS UDP relay is not loopback")
	}
	client, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(proxy.Addr(), 0)))
	if err != nil {
		return err
	}
	defer client.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := client.SetDeadline(deadline); err != nil {
			return err
		}
	}
	packet := make([]byte, 0, 10+len(challenge))
	packet = append(packet, 0, 0, 0, restrictedSOCKSIPv4)
	packet = append(packet, target.Addr().AsSlice()...)
	packet = binary.BigEndian.AppendUint16(packet, target.Port())
	packet = append(packet, challenge...)
	if _, err := client.WriteToUDPAddrPort(packet, relay); err != nil {
		return err
	}
	response := make([]byte, 10+maximumRestrictedProbeBytes)
	count, _, err := client.ReadFromUDPAddrPort(response)
	if err != nil {
		return err
	}
	payload, err := restrictedSOCKSUDPPayload(response[:count])
	if err != nil {
		return err
	}
	if !bytes.Equal(payload, challenge) {
		return fmt.Errorf("restricted UDP probe response mismatch")
	}
	return nil
}

func restrictedSOCKSRequest(ctx context.Context, proxy netip.AddrPort, command byte, target netip.AddrPort) (net.Conn, netip.AddrPort, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", proxy.String())
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	failed := true
	defer func() {
		if failed {
			_ = connection.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, netip.AddrPort{}, err
		}
	}
	if err := restrictedWriteAll(connection, []byte{restrictedSOCKSVersion, 1, restrictedSOCKSNoAuthentication}); err != nil {
		return nil, netip.AddrPort{}, err
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(connection, greeting); err != nil {
		return nil, netip.AddrPort{}, err
	}
	if greeting[0] != restrictedSOCKSVersion || greeting[1] != restrictedSOCKSNoAuthentication {
		return nil, netip.AddrPort{}, fmt.Errorf("restricted SOCKS proxy rejected no-authentication method")
	}
	request := []byte{restrictedSOCKSVersion, command, 0, restrictedSOCKSIPv4}
	request = append(request, target.Addr().AsSlice()...)
	request = binary.BigEndian.AppendUint16(request, target.Port())
	if err := restrictedWriteAll(connection, request); err != nil {
		return nil, netip.AddrPort{}, err
	}
	relay, err := restrictedReadSOCKSReply(connection)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}
	failed = false
	return connection, relay, nil
}

func restrictedReadSOCKSReply(reader io.Reader) (netip.AddrPort, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return netip.AddrPort{}, err
	}
	if header[0] != restrictedSOCKSVersion || header[1] != 0 || header[2] != 0 {
		return netip.AddrPort{}, fmt.Errorf("restricted SOCKS request failed")
	}
	var address netip.Addr
	switch header[3] {
	case restrictedSOCKSIPv4:
		encoded := make([]byte, 4)
		if _, err := io.ReadFull(reader, encoded); err != nil {
			return netip.AddrPort{}, err
		}
		address = netip.AddrFrom4([4]byte(encoded))
	case 4:
		encoded := make([]byte, 16)
		if _, err := io.ReadFull(reader, encoded); err != nil {
			return netip.AddrPort{}, err
		}
		address = netip.AddrFrom16([16]byte(encoded))
	default:
		return netip.AddrPort{}, fmt.Errorf("restricted SOCKS reply address type is unsupported")
	}
	encodedPort := make([]byte, 2)
	if _, err := io.ReadFull(reader, encodedPort); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(address, binary.BigEndian.Uint16(encodedPort)), nil
}

func restrictedSOCKSUDPPayload(packet []byte) ([]byte, error) {
	if len(packet) < 10 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 || packet[3] != restrictedSOCKSIPv4 {
		return nil, fmt.Errorf("restricted SOCKS UDP response is invalid")
	}
	return packet[10:], nil
}

func restrictedWriteAll(writer io.Writer, content []byte) error {
	for len(content) > 0 {
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
