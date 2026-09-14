package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestHTTPSNodeJoinExchangerUsesManagedIPOnlyTLSAndHTTP11(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := newPublicEnrollmentTLSServer(t, "203.0.113.10", now, func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		if request.URL.Path != InviteEnrollmentPath || request.Proto != "HTTP/1.1" ||
			request.Header.Get("Content-Type") != PublicEnrollmentContentType || string(body) != `{"join":true}` {
			t.Errorf("request = path:%q proto:%q content-type:%q body:%q", request.URL.Path, request.Proto, request.Header.Get("Content-Type"), body)
		}
		writer.Header().Set("Content-Type", PublicEnrollmentContentType)
		_, _ = io.WriteString(writer, `{"accepted":true}`)
	})
	defer server.Close()

	exchanger, err := NewHTTPSNodeJoinExchanger(time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	exchanger.dialContext = mappedEnrollmentDialer(t, server.Listener.Addr().String())
	body, err := output.NewSecretString(`{"join":true}`)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Destroy()
	result, err := exchanger.Exchange(context.Background(), "https://203.0.113.10"+InviteEnrollmentPath, &body)
	if err != nil {
		t.Fatal(err)
	}
	if !result.CommitPossible || !bytes.Equal(result.Response, []byte(`{"accepted":true}`)) {
		t.Fatalf("exchange result = %+v", result)
	}
}

func TestHTTPSNodeJoinExchangerRejectsWrongManagedCertificateBeforeRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	called := false
	server := newPublicEnrollmentTLSServer(t, "203.0.113.11", now, func(http.ResponseWriter, *http.Request) { called = true })
	defer server.Close()
	exchanger, err := NewHTTPSNodeJoinExchanger(time.Second, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	exchanger.dialContext = mappedEnrollmentDialer(t, server.Listener.Addr().String())
	body, _ := output.NewSecretString(`{"join":true}`)
	defer body.Destroy()
	result, err := exchanger.Exchange(context.Background(), "https://203.0.113.10"+InviteEnrollmentPath, &body)
	if !errors.Is(err, ErrPublicEnrollmentUnavailable) || result.CommitPossible || called || !strings.Contains(err.Error(), "managed IP-only profile") {
		t.Fatalf("wrong-certificate result = %+v, error=%v, called=%t", result, err, called)
	}
}

func TestHTTPSNodeJoinExchangerClassifiesTransportAndGatewayAvailability(t *testing.T) {
	t.Run("dial failure", func(t *testing.T) {
		exchanger, err := NewHTTPSNodeJoinExchanger(time.Second, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		exchanger.dialContext = func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("private dial canary")
		}
		body, _ := output.NewSecretString(`{"join":true}`)
		defer body.Destroy()
		result, err := exchanger.Exchange(context.Background(), "https://203.0.113.10"+InviteEnrollmentPath, &body)
		if !errors.Is(err, ErrPublicEnrollmentUnavailable) || result.CommitPossible {
			t.Fatalf("dial failure = %+v, %v", result, err)
		}
	})

	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			server := newPublicEnrollmentTLSServer(t, "203.0.113.10", now, func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(status)
			})
			defer server.Close()
			exchanger, _ := NewHTTPSNodeJoinExchanger(time.Second, func() time.Time { return now })
			exchanger.dialContext = mappedEnrollmentDialer(t, server.Listener.Addr().String())
			body, _ := output.NewSecretString(`{"join":true}`)
			defer body.Destroy()
			result, err := exchanger.Exchange(context.Background(), "https://203.0.113.10"+InviteEnrollmentPath, &body)
			if !errors.Is(err, ErrPublicEnrollmentUnavailable) || result.CommitPossible {
				t.Fatalf("status %d = %+v, %v", status, result, err)
			}
		})
	}
}

func TestHTTPSNodeJoinExchangerKeepsRejectedInviteDistinctFromAvailability(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := newPublicEnrollmentTLSServer(t, "203.0.113.10", now, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()
	exchanger, _ := NewHTTPSNodeJoinExchanger(time.Second, func() time.Time { return now })
	exchanger.dialContext = mappedEnrollmentDialer(t, server.Listener.Addr().String())
	body, _ := output.NewSecretString(`{"join":true}`)
	defer body.Destroy()
	result, err := exchanger.Exchange(context.Background(), "https://203.0.113.10"+InviteEnrollmentPath, &body)
	if !errors.Is(err, ErrPublicEnrollmentRejected) || errors.Is(err, ErrPublicEnrollmentUnavailable) || result.CommitPossible {
		t.Fatalf("rejected invite = %+v, %v", result, err)
	}
}

func TestHTTPSNodeJoinExchangerRejectsNonCanonicalEndpoints(t *testing.T) {
	for _, endpoint := range []string{
		"http://203.0.113.10" + InviteEnrollmentPath,
		"https://203.0.113.10:443" + InviteEnrollmentPath,
		"https://gateway.example" + InviteEnrollmentPath,
		"https://203.0.113.10/other",
		"https://203.0.113.10" + InviteEnrollmentPath + "?token=forbidden",
	} {
		if _, _, err := validatePublicEnrollmentClientEndpoint(endpoint); err == nil {
			t.Fatalf("endpoint %q was accepted", endpoint)
		}
	}
}

func newPublicEnrollmentTLSServer(t *testing.T, certificateIP string, now time.Time, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	material, err := ingress.GeneratePublicCertificate(rand.Reader, certificateIP, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(material.CertificatePEM, material.PrivateKeyPEM)
	clear(material.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	return server
}

func mappedEnrollmentDialer(t *testing.T, target string) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "203.0.113.10:443" {
			t.Fatalf("dial target = %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
}
