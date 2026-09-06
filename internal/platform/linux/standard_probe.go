package linux

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const (
	standardProbeMaximumUDPBytes = 4096
	standardProbeSocketTimeout   = 10 * time.Second
)

// StandardProbePath marks every socket for the dedicated gateway-/32 route
// through vpnctl-wg. Marking is mandatory: a failure aborts the dial instead
// of falling through to the production selector or direct routing.
type StandardProbePath struct{}

func NewStandardProbePath() *StandardProbePath { return &StandardProbePath{} }

func (*StandardProbePath) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("standard probe context is required")
	}
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("standard probe path supports only TCP dialing")
	}
	if _, err := standardProbeTarget(address); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Control: markStandardProbeSocket}
	return dialer.DialContext(ctx, "tcp4", address)
}

func (*StandardProbePath) ExchangeUDP(ctx context.Context, address string, payload []byte) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("standard probe context is required")
	}
	if _, err := standardProbeTarget(address); err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > standardProbeMaximumUDPBytes {
		return nil, fmt.Errorf("standard probe UDP payload must contain 1..%d bytes", standardProbeMaximumUDPBytes)
	}
	probeContext := ctx
	cancel := func() {}
	if _, bounded := ctx.Deadline(); !bounded {
		probeContext, cancel = context.WithTimeout(ctx, standardProbeSocketTimeout)
	}
	defer cancel()
	dialer := &net.Dialer{Control: markStandardProbeSocket}
	connection, err := dialer.DialContext(probeContext, "udp4", address)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if deadline, ok := probeContext.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	count, err := connection.Write(payload)
	if err != nil {
		return nil, err
	}
	if count != len(payload) {
		return nil, fmt.Errorf("standard probe UDP request was truncated")
	}
	response := make([]byte, standardProbeMaximumUDPBytes+1)
	count, err = connection.Read(response)
	if err != nil {
		return nil, err
	}
	if count == 0 || count > standardProbeMaximumUDPBytes {
		return nil, fmt.Errorf("standard probe UDP response has invalid size")
	}
	return append([]byte(nil), response[:count]...), nil
}

func standardProbeTarget(value string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint.String() != value || !endpoint.Addr().Is4() || !endpoint.Addr().IsGlobalUnicast() ||
		endpoint.Addr().IsLoopback() || endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("standard probe target must be a canonical non-loopback unicast IPv4 endpoint")
	}
	return endpoint, nil
}
