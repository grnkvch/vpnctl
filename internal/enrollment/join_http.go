package enrollment

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const PublicEnrollmentClientTimeout = 15 * time.Second

// HTTPSNodeJoinExchanger performs one bounded bootstrap request. The public
// ingress certificate is intentionally not a stable trust anchor: it rotates
// independently and is not carried by an invite. TLS therefore protects the
// token from passive observation, while the invite-pinned Ed25519 transcript
// authenticates the response before node state is committed.
type HTTPSNodeJoinExchanger struct {
	timeout     time.Duration
	now         func() time.Time
	dialContext func(context.Context, string, string) (net.Conn, error)
}

func NewHTTPSNodeJoinExchanger(timeout time.Duration, now func() time.Time) (*HTTPSNodeJoinExchanger, error) {
	if timeout == 0 {
		timeout = PublicEnrollmentClientTimeout
	}
	if timeout <= 0 || timeout > time.Minute {
		return nil, fmt.Errorf("public enrollment timeout must be positive and no more than one minute")
	}
	if now == nil {
		now = time.Now
	}
	dialer := &net.Dialer{}
	return &HTTPSNodeJoinExchanger{timeout: timeout, now: now, dialContext: dialer.DialContext}, nil
}

func (exchanger *HTTPSNodeJoinExchanger) Exchange(
	ctx context.Context,
	endpoint string,
	requestBody *output.Secret,
) (NodeJoinExchangeResult, error) {
	if exchanger == nil || ctx == nil || requestBody == nil || exchanger.now == nil || exchanger.dialContext == nil {
		return NodeJoinExchangeResult{}, fmt.Errorf("public enrollment exchanger is incomplete")
	}
	parsed, address, err := validatePublicEnrollmentClientEndpoint(endpoint)
	if err != nil {
		return NodeJoinExchangeResult{}, err
	}
	var result NodeJoinExchangeResult
	err = requestBody.Use(func(body []byte) error {
		bounded, cancel := context.WithTimeout(ctx, exchanger.timeout)
		defer cancel()
		wroteRequest := false
		trace := &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				wroteRequest = true
			}
		}}
		bounded = httptrace.WithClientTrace(bounded, trace)
		request, err := http.NewRequestWithContext(bounded, http.MethodPost, parsed.String(), bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build public enrollment request: %w", err)
		}
		request.Header.Set("Content-Type", PublicEnrollmentContentType)
		request.Header.Set("Connection", "close")
		request.Close = true
		transport := &http.Transport{
			Proxy: nil,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
				// The independently rotatable self-signed ingress leaf is not an
				// invite trust anchor. VerifyConnection enforces its public shape;
				// the signed enrollment transcript supplies gateway identity.
				InsecureSkipVerify: true, //nolint:gosec
				NextProtos:         []string{"http/1.1"},
				VerifyConnection: func(connection tls.ConnectionState) error {
					return verifyPublicEnrollmentTLS(connection, address, exchanger.now())
				},
			},
			ForceAttemptHTTP2: false, DisableKeepAlives: true, DisableCompression: true,
			TLSHandshakeTimeout: control.RPCReadBodyTimeout, ResponseHeaderTimeout: control.RPCWriteTimeout,
			MaxResponseHeaderBytes: control.RPCMaximumHeaderBytes,
			DialContext:            exchanger.dialContext,
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("public enrollment redirects are forbidden")
			},
		}
		response, err := client.Do(request)
		if err != nil {
			result.CommitPossible = wroteRequest
			return fmt.Errorf("perform public enrollment request: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			result.CommitPossible = false
			return fmt.Errorf("public enrollment was rejected")
		}
		result.CommitPossible = true
		if response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.TLS == nil ||
			(response.TLS.Version != tls.VersionTLS12 && response.TLS.Version != tls.VersionTLS13) ||
			response.TLS.NegotiatedProtocol != "http/1.1" || response.Header.Get("Content-Type") != PublicEnrollmentContentType {
			return fmt.Errorf("public enrollment response protocol is invalid")
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, control.RPCMaximumResponseBytes+1))
		if err != nil || len(data) == 0 || len(data) > control.RPCMaximumResponseBytes {
			clear(data)
			return fmt.Errorf("public enrollment response body is invalid")
		}
		result.Response = data
		return nil
	})
	return result, err
}

func validatePublicEnrollmentClientEndpoint(raw string) (*url.URL, netip.Addr, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Host == "" || parsed.Port() != "" ||
		parsed.Path != InviteEnrollmentPath || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, netip.Addr{}, fmt.Errorf("public enrollment endpoint is invalid")
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !address.Is4() || address.IsUnspecified() || address.String() != parsed.Hostname() {
		return nil, netip.Addr{}, fmt.Errorf("public enrollment endpoint requires a canonical public IPv4")
	}
	return parsed, address, nil
}

func verifyPublicEnrollmentTLS(connection tls.ConnectionState, address netip.Addr, now time.Time) error {
	if len(connection.PeerCertificates) != 1 {
		return fmt.Errorf("public enrollment requires one self-signed certificate")
	}
	certificate := connection.PeerCertificates[0]
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() != 2048 || certificate.SignatureAlgorithm != x509.SHA256WithRSA ||
		len(certificate.IPAddresses) != 1 || certificate.IPAddresses[0].String() != address.String() ||
		len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.URIs) != 0 ||
		certificate.Subject.CommonName != address.String() || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) ||
		certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) != nil {
		return fmt.Errorf("public enrollment certificate does not match the managed IP-only profile")
	}
	return nil
}

var _ NodeJoinExchanger = (*HTTPSNodeJoinExchanger)(nil)
