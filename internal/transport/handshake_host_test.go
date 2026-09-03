package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestHandshakeHostBundleVerificationRejectsTamperAndAmbiguity(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := testHandshakeHostBundle()
	signed, err := encodeSignedHandshakeHostBundle(bundle, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := DecodeAndVerifyHandshakeHostBundle(signed, publicKey)
	if err != nil || !reflect.DeepEqual(verified, bundle) {
		t.Fatalf("verified bundle = %#v, %v", verified, err)
	}
	verified.Candidates[0].Hostname = "mutated.example"
	second, err := DecodeAndVerifyHandshakeHostBundle(signed, publicKey)
	if err != nil || second.Candidates[0].Hostname != "first.example" {
		t.Fatalf("caller mutation changed verified bundle = %#v, %v", second, err)
	}

	var envelope SignedHandshakeHostBundle
	if err := json.Unmarshal(signed, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload = envelope.Payload[:len(envelope.Payload)-1] + "A"
	tampered, _ := json.Marshal(envelope)
	if _, err := DecodeAndVerifyHandshakeHostBundle(tampered, publicKey); !errors.Is(err, ErrInvalidHandshakeHostBundle) {
		t.Fatalf("tampered bundle error = %v", err)
	}
	unknown := append(signed[:len(signed)-1], []byte(`,"unknown":true}`)...)
	if _, err := DecodeAndVerifyHandshakeHostBundle(unknown, publicKey); !errors.Is(err, ErrInvalidHandshakeHostBundle) {
		t.Fatalf("unknown envelope field error = %v", err)
	}
	duplicate := append([]byte(`{"schema_version":2,`), signed[1:]...)
	if _, err := DecodeAndVerifyHandshakeHostBundle(duplicate, publicKey); !errors.Is(err, ErrInvalidHandshakeHostBundle) {
		t.Fatalf("duplicate envelope field error = %v", err)
	}
	_, wrongPrivate, _ := ed25519.GenerateKey(rand.Reader)
	wrongPublic := wrongPrivate.Public().(ed25519.PublicKey)
	if _, err := DecodeAndVerifyHandshakeHostBundle(signed, wrongPublic); !errors.Is(err, ErrInvalidHandshakeHostBundle) {
		t.Fatalf("wrong release key error = %v", err)
	}
}

func TestBundledHandshakeHostListIsSignedAndVersioned(t *testing.T) {
	t.Parallel()
	publicKey, err := base64.RawURLEncoding.DecodeString(bundledHandshakeHostPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := DecodeAndVerifyHandshakeHostBundle(bundledHandshakeHostEnvelope, ed25519.PublicKey(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	want := []HandshakeHostCandidate{
		{ID: "microsoft", Hostname: "www.microsoft.com"},
		{ID: "apple", Hostname: "www.apple.com"},
		{ID: "cloudflare", Hostname: "www.cloudflare.com"},
	}
	if bundle.ListVersion != 1 || !reflect.DeepEqual(bundle.Candidates, want) {
		t.Fatalf("bundled handshake hosts = %#v", bundle)
	}
}

func TestHandshakeHostSelectorUsesFirstPassingCandidateOnly(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := encodeSignedHandshakeHostBundle(testHandshakeHostBundle(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Date(2026, 9, 3, 14, 0, 0, 0, time.UTC)
	prober := &recordingHandshakeHostProber{results: map[string]HandshakeHostProbeResult{
		"first":  {CandidateID: "first", Hostname: "first.example", ObservedAt: observedAt, Code: "reachability-failed"},
		"second": passingHandshakeHostProbe("second", "second.example", observedAt, 40*time.Millisecond),
		"third":  passingHandshakeHostProbe("third", "third.example", observedAt, time.Millisecond),
	}}
	selector, err := NewHandshakeHostSelector(signed, publicKey, prober, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := selector.Select(context.Background(), 1, observedAt)
	if err != nil {
		t.Fatal(err)
	}
	if selection.CandidateID != "second" || selection.Hostname != "second.example" || selection.ListVersion != 1 || !selection.SelectedAt.Equal(observedAt) {
		t.Fatalf("selection = %+v", selection)
	}
	if !reflect.DeepEqual(prober.calls, []string{"first", "second"}) {
		t.Fatalf("probe order = %v", prober.calls)
	}

	prober.calls = nil
	if _, err := selector.Select(context.Background(), 2, observedAt); !errors.Is(err, ErrInvalidHandshakeHostBundle) || len(prober.calls) != 0 {
		t.Fatalf("manifest mismatch = %v, probes %v", err, prober.calls)
	}
	prober.results["second"] = HandshakeHostProbeResult{CandidateID: "second", Hostname: "second.example", ObservedAt: observedAt, Reachable: true, TLS13: true, CertificateValid: true, Latency: time.Second, Code: "too-slow"}
	prober.results["third"] = HandshakeHostProbeResult{CandidateID: "third", Hostname: "third.example", ObservedAt: observedAt, Reachable: true, TLS13: false, CertificateValid: true, Latency: time.Millisecond, Code: "tls13-unavailable"}
	if _, err := selector.Select(context.Background(), 1, observedAt); !errors.Is(err, ErrNoHandshakeHostCandidate) {
		t.Fatalf("all candidates failed error = %v", err)
	}
	if !reflect.DeepEqual(prober.calls, []string{"first", "second", "third"}) {
		t.Fatalf("failed probe order = %v", prober.calls)
	}
}

func TestTLSHandshakeHostProberChecksReachabilityTLS13AndCertificate(t *testing.T) {
	t.Parallel()
	root, serverCertificate := handshakeHostTestCertificate(t, "probe.example")
	cases := []struct {
		name        string
		serverTLS   *tls.Config
		rootCAs     *x509.CertPool
		dialErr     error
		reachable   bool
		tls13       bool
		certificate bool
		code        string
	}{
		{name: "valid TLS 1.3", serverTLS: &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, rootCAs: root, reachable: true, tls13: true, certificate: true, code: "passed"},
		{name: "TLS 1.2 only", serverTLS: &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}, rootCAs: root, reachable: true, certificate: true, code: "tls13-unavailable"},
		{name: "untrusted certificate", serverTLS: &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, rootCAs: x509.NewCertPool(), reachable: true, code: "tls-or-certificate-failed"},
		{name: "unreachable", dialErr: errors.New("synthetic dial failure"), code: "reachability-failed"},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			dial := func(context.Context, string, string) (net.Conn, error) {
				if test.dialErr != nil {
					return nil, test.dialErr
				}
				client, server := net.Pipe()
				go func() {
					connection := tls.Server(server, test.serverTLS)
					_ = connection.Handshake()
					_ = connection.Close()
				}()
				return client, nil
			}
			prober, err := NewTLSHandshakeHostProber(TLSHandshakeHostProbeOptions{Port: 443, Timeout: time.Second, RootCAs: test.rootCAs, DialContext: dial})
			if err != nil {
				t.Fatal(err)
			}
			result := prober.Probe(context.Background(), HandshakeHostCandidate{ID: "probe", Hostname: "probe.example"})
			if result.Reachable != test.reachable || result.TLS13 != test.tls13 || result.CertificateValid != test.certificate || result.Code != test.code || result.CandidateID != "probe" || result.Hostname != "probe.example" {
				t.Fatalf("probe result = %+v", result)
			}
			if result.ObservedAt.IsZero() || result.Latency <= 0 {
				t.Fatalf("probe timing = %+v", result)
			}
		})
	}
}

func TestHandshakeHostDeliveryAndPassiveHealthNeverRotate(t *testing.T) {
	t.Parallel()
	state, _ := restrictedGatewayFixture(t)
	selected := *state.HandshakeHost
	for _, target := range []struct {
		kind model.TargetKind
		id   string
	}{
		{kind: model.TargetNode, id: state.Nodes[0].ID},
		{kind: model.TargetClient, id: state.Clients[0].ID},
	} {
		delivery, err := HandshakeHostDeliveryFor(state, target.kind, target.id)
		if err != nil {
			t.Fatal(err)
		}
		if delivery.Selection() != selected {
			t.Fatalf("%s delivery = %+v, want %+v", target.kind, delivery, selected)
		}
	}

	observation := HandshakeHostProbeResult{
		CandidateID: selected.CandidateID, Hostname: selected.Hostname,
		ObservedAt: selected.SelectedAt.Add(time.Hour), Reachable: false, Code: "reachability-failed",
	}
	before := selected
	health, err := EvaluatePinnedHandshakeHost(selected, observation, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if health.Condition != HealthDegraded || health.Code != "handshake-host-degraded" || !health.RequiresAction || health.Selection != before || selected != before {
		t.Fatalf("degraded health rotated selection: health=%+v selected=%+v", health, selected)
	}
	observation = passingHandshakeHostProbe(selected.CandidateID, selected.Hostname, selected.SelectedAt.Add(2*time.Hour), 30*time.Millisecond)
	health, err = EvaluatePinnedHandshakeHost(selected, observation, time.Second)
	if err != nil || health.Condition != HealthHealthy || health.RequiresAction || health.Selection != before {
		t.Fatalf("healthy observation = %+v, %v", health, err)
	}
}

func testHandshakeHostBundle() HandshakeHostBundle {
	return HandshakeHostBundle{SchemaVersion: 1, ListVersion: 1, Candidates: []HandshakeHostCandidate{
		{ID: "first", Hostname: "first.example"},
		{ID: "second", Hostname: "second.example"},
		{ID: "third", Hostname: "third.example"},
	}}
}

func encodeSignedHandshakeHostBundle(bundle HandshakeHostBundle, privateKey ed25519.PrivateKey) ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	envelope := SignedHandshakeHostBundle{
		SchemaVersion: HandshakeHostBundleSchemaVersion, Algorithm: HandshakeHostSignatureAlgorithm,
		KeyID: handshakeHostKeyID(publicKey), Payload: base64.RawURLEncoding.EncodeToString(payload),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, handshakeHostSignedMessage(payload))),
	}
	return json.Marshal(envelope)
}

type recordingHandshakeHostProber struct {
	results map[string]HandshakeHostProbeResult
	calls   []string
}

func (prober *recordingHandshakeHostProber) Probe(_ context.Context, candidate HandshakeHostCandidate) HandshakeHostProbeResult {
	prober.calls = append(prober.calls, candidate.ID)
	return prober.results[candidate.ID]
}

func passingHandshakeHostProbe(id, hostname string, observedAt time.Time, latency time.Duration) HandshakeHostProbeResult {
	return HandshakeHostProbeResult{
		CandidateID: id, Hostname: hostname, ObservedAt: observedAt,
		Reachable: true, TLS13: true, CertificateValid: true, Latency: latency, Code: "passed",
	}
}

func handshakeHostTestCertificate(t *testing.T, hostname string) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vpnctl handshake test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCertificate, leafPublic, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(rootCertificate)
	return pool, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafPrivate}
}
