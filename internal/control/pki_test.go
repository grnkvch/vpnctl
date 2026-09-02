package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testGatewayID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testNodeID    = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

func TestGatewayControlMaterialProfileAndTrustSeparation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC)
	material, err := GenerateGatewayControlMaterial(rand.Reader, testGatewayID, "10.67.0.1", now)
	if err != nil {
		t.Fatal(err)
	}
	ca := parseCertificateForTest(t, material.ControlCACertificatePEM)
	gateway := parseCertificateForTest(t, material.GatewayCertificatePEM)
	if ca.PublicKeyAlgorithm != x509.Ed25519 || gateway.PublicKeyAlgorithm != x509.Ed25519 || !ca.IsCA {
		t.Fatalf("control certificate algorithms/CA = %s/%s/%t", ca.PublicKeyAlgorithm, gateway.PublicKeyAlgorithm, ca.IsCA)
	}
	if ca.SerialNumber.Sign() <= 0 || ca.SerialNumber.BitLen() > 128 || gateway.SerialNumber.Sign() <= 0 || gateway.SerialNumber.BitLen() > 128 {
		t.Fatalf("serial bounds = %s/%d and %s/%d", ca.SerialNumber, ca.SerialNumber.BitLen(), gateway.SerialNumber, gateway.SerialNumber.BitLen())
	}
	if !ca.NotAfter.Equal(now.Add(ControlCAValidity)) || !gateway.NotAfter.Equal(now.Add(ControlLeafValidity)) {
		t.Fatalf("certificate expiry = %s/%s", ca.NotAfter, gateway.NotAfter)
	}
	if len(ca.URIs) != 0 || len(gateway.URIs) != 1 || gateway.URIs[0].String() != "urn:vpnctl:gateway:"+testGatewayID ||
		len(gateway.IPAddresses) != 1 || gateway.IPAddresses[0].String() != "10.67.0.1" {
		t.Fatalf("CA/gateway SANs = %v / %v %v", ca.URIs, gateway.URIs, gateway.IPAddresses)
	}
	if _, err := gateway.Verify(x509.VerifyOptions{
		Roots: newCertPool(ca), DNSName: "10.67.0.1", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: now,
	}); err != nil {
		t.Fatalf("verify gateway control chain: %v", err)
	}

	caKey := parseEd25519PrivateKeyForTest(t, material.ControlCAPrivateKeyPEM)
	gatewayKey := parseEd25519PrivateKeyForTest(t, material.GatewayPrivateKeyPEM)
	enrollmentKey := parseEd25519PrivateKeyForTest(t, material.EnrollmentPrivateKeyPEM)
	enrollmentPublic := parseEd25519PublicKeyForTest(t, material.EnrollmentPublicKeyPEM)
	if !ca.PublicKey.(ed25519.PublicKey).Equal(caKey.Public()) || !gateway.PublicKey.(ed25519.PublicKey).Equal(gatewayKey.Public()) || !enrollmentPublic.Equal(enrollmentKey.Public()) {
		t.Fatal("one or more control certificates/public keys do not match their private keys")
	}
	if ca.PublicKey.(ed25519.PublicKey).Equal(gateway.PublicKey) || ca.PublicKey.(ed25519.PublicKey).Equal(enrollmentPublic) || gateway.PublicKey.(ed25519.PublicKey).Equal(enrollmentPublic) {
		t.Fatal("control CA, gateway leaf, and enrollment signer reused a key")
	}
	publicDER, _ := x509.MarshalPKIXPublicKey(enrollmentPublic)
	fingerprint := sha256.Sum256(publicDER)
	if material.EnrollmentFingerprint != "sha256:"+hex.EncodeToString(fingerprint[:]) {
		t.Fatalf("enrollment fingerprint = %s", material.EnrollmentFingerprint)
	}
	for name, keyPEM := range map[string][]byte{"ca": material.ControlCAPrivateKeyPEM, "gateway": material.GatewayPrivateKeyPEM, "enrollment": material.EnrollmentPrivateKeyPEM} {
		block, rest := pem.Decode(keyPEM)
		if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			t.Fatalf("%s key is not one PKCS#8 PEM block", name)
		}
	}
}

func TestNodeCSRAndIssuedCertificateBindOnlyAuthoritativeIdentity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC)
	material, err := GenerateGatewayControlMaterial(rand.Reader, testGatewayID, "10.67.0.1", now)
	if err != nil {
		t.Fatal(err)
	}
	request, err := GenerateNodeControlCSR(rand.Reader, testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	csr := parseCSRForTest(t, request.CSRPEM)
	if csr.SignatureAlgorithm != x509.PureEd25519 || len(csr.URIs) != 1 || csr.URIs[0].String() != request.IdentityURI {
		t.Fatalf("node CSR profile = %s %v", csr.SignatureAlgorithm, csr.URIs)
	}
	issued, err := IssueNodeControlCertificate(rand.Reader, material.ControlCACertificatePEM, material.ControlCAPrivateKeyPEM, request.CSRPEM, testNodeID, now)
	if err != nil {
		t.Fatal(err)
	}
	if issued.IdentityURI != "urn:vpnctl:node:"+testNodeID || len(issued.Certificate.URIs) != 1 || issued.Certificate.URIs[0].String() != issued.IdentityURI ||
		issued.Certificate.Subject.CommonName != "vpnctl node control leaf" {
		t.Fatalf("issued node identity = %q, %v, %q", issued.IdentityURI, issued.Certificate.URIs, issued.Certificate.Subject.CommonName)
	}
	ca := parseCertificateForTest(t, material.ControlCACertificatePEM)
	if _, err := issued.Certificate.Verify(x509.VerifyOptions{
		Roots: newCertPool(ca), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now,
	}); err != nil {
		t.Fatalf("verify node control chain: %v", err)
	}
	nodeKey := parseEd25519PrivateKeyForTest(t, request.PrivateKeyPEM)
	if !issued.Certificate.PublicKey.(ed25519.PublicKey).Equal(nodeKey.Public()) {
		t.Fatal("issued certificate does not bind the node-local key")
	}

	mutableNameCSR := customCSR(t, ed25519.PrivateKey(nodeKey), "mutable-display-name", []*url.URL{mustURL(t, issued.IdentityURI)}, nil)
	mutableIssued, err := IssueNodeControlCertificate(rand.Reader, material.ControlCACertificatePEM, material.ControlCAPrivateKeyPEM, mutableNameCSR, testNodeID, now)
	if err != nil || mutableIssued.Certificate.Subject.CommonName == "mutable-display-name" {
		t.Fatalf("mutable CN influenced authorization certificate: subject=%q error=%v", mutableIssued.Certificate.Subject.CommonName, err)
	}

	wrongCSR, _ := GenerateNodeControlCSR(rand.Reader, "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	if _, err := IssueNodeControlCertificate(rand.Reader, material.ControlCACertificatePEM, material.ControlCAPrivateKeyPEM, wrongCSR.CSRPEM, testNodeID, now); !errors.Is(err, ErrInvalidNodeCSR) {
		t.Fatalf("wrong-node CSR error = %v", err)
	}
	multiple := customCSR(t, nodeKey, "ignored", []*url.URL{mustURL(t, issued.IdentityURI), mustURL(t, "urn:vpnctl:node:cccccccc-cccc-4ccc-8ccc-cccccccccccc")}, nil)
	if _, err := IssueNodeControlCertificate(rand.Reader, material.ControlCACertificatePEM, material.ControlCAPrivateKeyPEM, multiple, testNodeID, now); !errors.Is(err, ErrInvalidNodeCSR) {
		t.Fatalf("multi-identity CSR error = %v", err)
	}
	withDNS := customCSR(t, nodeKey, "ignored", []*url.URL{mustURL(t, issued.IdentityURI)}, []string{"mutable.example"})
	if _, err := IssueNodeControlCertificate(rand.Reader, material.ControlCACertificatePEM, material.ControlCAPrivateKeyPEM, withDNS, testNodeID, now); !errors.Is(err, ErrInvalidNodeCSR) {
		t.Fatalf("extra-SAN CSR error = %v", err)
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaCSR := customCSR(t, rsaKey, "ignored", []*url.URL{mustURL(t, issued.IdentityURI)}, nil)
	if _, err := IssueNodeControlCertificate(rand.Reader, material.ControlCACertificatePEM, material.ControlCAPrivateKeyPEM, rsaCSR, testNodeID, now); !errors.Is(err, ErrInvalidNodeCSR) {
		t.Fatalf("RSA CSR error = %v", err)
	}
}

func TestControlIdentityRejectsNonCanonicalInputsAndZeroSerialEntropy(t *testing.T) {
	t.Parallel()

	if _, err := GenerateNodeControlCSR(rand.Reader, strings.ToUpper(testNodeID)); !errors.Is(err, ErrInvalidControlIdentity) {
		t.Fatalf("uppercase node ID error = %v", err)
	}
	if _, err := GatewayOverlayIPv4("10.67.0.1/24"); !errors.Is(err, ErrInvalidControlIdentity) {
		t.Fatalf("host-bit node CIDR error = %v", err)
	}
	if address, err := GatewayOverlayIPv4("10.67.0.0/24"); err != nil || address != "10.67.0.1" {
		t.Fatalf("GatewayOverlayIPv4() = %q, %v", address, err)
	}
	if _, err := randomPositiveSerial(zeroReader{}); err == nil {
		t.Fatal("randomPositiveSerial(zero) error = nil")
	}
	serialEntropy := append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)...)
	serialReader := bytes.NewReader(serialEntropy)
	first, err := randomPositiveSerial(serialReader)
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomPositiveSerial(serialReader)
	if err != nil {
		t.Fatal(err)
	}
	if first.Cmp(second) == 0 || first.BitLen() > 128 || second.BitLen() > 128 {
		t.Fatalf("serial entropy was not consumed independently: %x / %x", first, second)
	}
}

type zeroReader struct{}

func (zeroReader) Read(destination []byte) (int, error) {
	clear(destination)
	return len(destination), nil
}

func parseCertificateForTest(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	der, err := decodeSinglePEM(data, "CERTIFICATE")
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func parseCSRForTest(t *testing.T, data []byte) *x509.CertificateRequest {
	t.Helper()
	der, err := decodeSinglePEM(data, "CERTIFICATE REQUEST")
	if err != nil {
		t.Fatal(err)
	}
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func parseEd25519PrivateKeyForTest(t *testing.T, data []byte) ed25519.PrivateKey {
	t.Helper()
	der, err := decodeSinglePEM(data, "PRIVATE KEY")
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T", key)
	}
	return privateKey
}

func parseEd25519PublicKeyForTest(t *testing.T, data []byte) ed25519.PublicKey {
	t.Helper()
	der, err := decodeSinglePEM(data, "PUBLIC KEY")
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T", key)
	}
	return publicKey
}

func newCertPool(certificates ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func customCSR(t *testing.T, key any, commonName string, uris []*url.URL, dns []string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName}, URIs: uris, DNSNames: dns,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
