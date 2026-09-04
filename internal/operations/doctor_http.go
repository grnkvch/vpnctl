package operations

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// ExplicitGETDoctorRunner adds the one externally-addressed operation doctor
// permits. Calling RoundTrip directly deliberately disables redirect and
// cookie-jar behavior. The generated request has a nil body, no userinfo, no
// authorization/cookie/client-certificate material, and only a synthetic
// probe-ID User-Agent header.
type ExplicitGETDoctorRunner struct {
	base      DoctorProbeRunner
	transport http.RoundTripper
}

func NewExplicitGETDoctorRunner(base DoctorProbeRunner, transport http.RoundTripper) (*ExplicitGETDoctorRunner, error) {
	if nilInterface(base) {
		return nil, fmt.Errorf("base doctor probe runner is required")
	}
	if transport == nil {
		dialer := &net.Dialer{Timeout: DefaultDoctorProbeTimeout, KeepAlive: 30 * time.Second}
		transport = &http.Transport{
			Proxy:               nil,
			DialContext:         dialer.DialContext,
			ForceAttemptHTTP2:   true,
			DisableCompression:  true,
			TLSHandshakeTimeout: DefaultDoctorProbeTimeout,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		}
	}
	return &ExplicitGETDoctorRunner{base: base, transport: transport}, nil
}

func (runner *ExplicitGETDoctorRunner) Probe(ctx context.Context, request DoctorProbeRequest) (DoctorProbeObservation, error) {
	if ctx == nil {
		return DoctorProbeObservation{}, fmt.Errorf("context is required")
	}
	if runner == nil || nilInterface(runner.base) || runner.transport == nil {
		return DoctorProbeObservation{}, fmt.Errorf("explicit GET doctor runner is incomplete")
	}
	if request.Kind != DoctorProbeExternalHTTPS {
		return runner.base.Probe(ctx, request)
	}
	if err := request.Validate(); err != nil {
		return DoctorProbeObservation{}, fmt.Errorf("explicit HTTPS doctor request is invalid")
	}
	var outbound *http.Request
	if err := request.ProbeURL.Use(func(value string) error {
		created, err := http.NewRequestWithContext(ctx, http.MethodGet, value, nil)
		if err != nil {
			return err
		}
		created.Header.Set("User-Agent", "vpnctl-doctor/"+request.ProbeID)
		outbound = created
		return nil
	}); err != nil || outbound == nil {
		return DoctorProbeObservation{}, fmt.Errorf("construct explicit HTTPS doctor request")
	}
	response, err := runner.transport.RoundTrip(outbound)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return DoctorProbeObservation{}, fmt.Errorf("explicit HTTPS GET failed")
	}
	if response == nil {
		return DoctorProbeObservation{}, fmt.Errorf("explicit HTTPS GET returned no response")
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	switch {
	case response.StatusCode >= 200 && response.StatusCode < 300:
		return DoctorProbeObservation{Passed: true, Code: "explicit_https_get_passed"}, nil
	case response.StatusCode >= 300 && response.StatusCode < 400:
		return DoctorProbeObservation{Passed: false, Code: "explicit_https_redirect_refused"}, nil
	default:
		return DoctorProbeObservation{Passed: false, Code: "explicit_https_status_failed"}, nil
	}
}

var _ DoctorProbeRunner = (*ExplicitGETDoctorRunner)(nil)
