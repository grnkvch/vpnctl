package controlspike

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	caValidity             = 3650 * 24 * time.Hour
	leafValidity           = 1825 * 24 * time.Hour
	renewalWindow          = 180 * 24 * time.Hour
	clockSkew              = 120 * time.Second
	maxRequestBytes        = 64 * 1024
	maxResponseBytes       = 256 * 1024
	maxHeaderBytes         = 8 * 1024
	maxJSONDepth           = 32
	readHeaderTimeout      = 2 * time.Second
	readTimeout            = 5 * time.Second
	writeTimeout           = 5 * time.Second
	idleTimeout            = 5 * time.Second
	maxConcurrentConns     = 16
	transcriptDomain       = "vpnctl-enrollment-transcript-v1"
	nodeID                 = "018f4d34-9a72-7b6c-8d5e-1234567890ab"
	gatewayID              = "018f4d34-9a72-7b6c-8d5e-abcdef123456"
	nodeURI                = "urn:vpnctl:node:" + nodeID
	gatewayURI             = "urn:vpnctl:gateway:" + gatewayID
	controlRPCPath         = "/rpc/v1/status"
	controlContentType     = "application/json"
	controlProtocolVersion = "1.0"
)

type certificateAuthority struct {
	certificate *x509.Certificate
	privateKey  ed25519.PrivateKey
	certPEM     []byte
	keyPEM      []byte
}

type issuedCertificate struct {
	certificate *x509.Certificate
	privateKey  ed25519.PrivateKey
	certPEM     []byte
	keyPEM      []byte
}

func spikeEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("VPNCTL_V2_CONTROL_SPIKE") != "1" {
		t.Skip("set VPNCTL_V2_CONTROL_SPIKE=1 to run the control crypto/RPC spike")
	}
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil {
			t.Fatalf("generate certificate serial: %v", err)
		}
		if serial.Sign() > 0 {
			return serial
		}
	}
}

func marshalPrivateKey(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newAuthority(t *testing.T, commonName string, now time.Time) certificateAuthority {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate authority key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"vpnctl control"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SignatureAlgorithm:    x509.PureEd25519,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatalf("create authority certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse authority certificate: %v", err)
	}
	return certificateAuthority{
		certificate: certificate,
		privateKey:  privateKey,
		certPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:      marshalPrivateKey(t, privateKey),
	}
}

func parseIdentityURI(t *testing.T, value string) *url.URL {
	t.Helper()
	identity, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse identity URI: %v", err)
	}
	return identity
}

func issueLeaf(t *testing.T, authority certificateAuthority, identityURI string, server bool, now time.Time) issuedCertificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:       randomSerial(t),
		Subject:            pkix.Name{CommonName: "vpnctl internal control leaf"},
		NotBefore:          now.Add(-5 * time.Minute),
		NotAfter:           now.Add(leafValidity),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		URIs:               []*url.URL{parseIdentityURI(t, identityURI)},
		SignatureAlgorithm: x509.PureEd25519,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, publicKey, authority.privateKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return issuedCertificate{
		certificate: certificate,
		privateKey:  privateKey,
		certPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:      marshalPrivateKey(t, privateKey),
	}
}

func createNodeCSR(t *testing.T, identityURI string) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "display-name-is-not-authority"},
		URIs:    []*url.URL{parseIdentityURI(t, identityURI)},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatalf("create node CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), privateKey
}

func signNodeCSR(t *testing.T, authority certificateAuthority, csrPEM []byte, expectedURI string, now time.Time) ([]byte, error) {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("CSR public key is not Ed25519")
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != expectedURI {
		return nil, errors.New("CSR URI SAN does not match immutable node identity")
	}
	template := &x509.Certificate{
		SerialNumber:       randomSerial(t),
		Subject:            pkix.Name{CommonName: "vpnctl node control leaf"},
		NotBefore:          now.Add(-5 * time.Minute),
		NotAfter:           now.Add(leafValidity),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:               []*url.URL{parseIdentityURI(t, expectedURI)},
		SignatureAlgorithm: x509.PureEd25519,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, csr.PublicKey, authority.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func runOpenSSL(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command("openssl", arguments...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %s: %v: %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output)
}

func TestEd25519PKIAndOpenSSLInteroperability(t *testing.T) {
	spikeEnabled(t)
	now := time.Now().UTC().Truncate(time.Second)
	authority := newAuthority(t, "vpnctl control CA", now)
	server := issueLeaf(t, authority, gatewayURI, true, now)
	csrPEM, nodePrivateKey := createNodeCSR(t, nodeURI)
	nodeCertPEM, err := signNodeCSR(t, authority, csrPEM, nodeURI, now)
	if err != nil {
		t.Fatalf("sign Go CSR: %v", err)
	}

	if authority.certificate.PublicKeyAlgorithm != x509.Ed25519 || server.certificate.PublicKeyAlgorithm != x509.Ed25519 {
		t.Fatal("control CA and leaf must use Ed25519")
	}
	if authority.certificate.SerialNumber.BitLen() > 128 || server.certificate.SerialNumber.BitLen() > 128 {
		t.Fatal("certificate serial exceeds 128 bits")
	}
	if got := server.certificate.NotAfter.Sub(now); got != leafValidity {
		t.Fatalf("unexpected leaf validity: %s", got)
	}
	if got := authority.certificate.NotAfter.Sub(now); got != caValidity {
		t.Fatalf("unexpected CA validity: %s", got)
	}

	directory := t.TempDir()
	writeFile(t, filepath.Join(directory, "ca.pem"), authority.certPEM, 0o644)
	writeFile(t, filepath.Join(directory, "server.pem"), server.certPEM, 0o644)
	writeFile(t, filepath.Join(directory, "node.pem"), nodeCertPEM, 0o644)
	writeFile(t, filepath.Join(directory, "node.key"), marshalPrivateKey(t, nodePrivateKey), 0o600)
	if output := runOpenSSL(t, directory, "verify", "-CAfile", "ca.pem", "-purpose", "sslclient", "node.pem"); !strings.Contains(output, "node.pem: OK") {
		t.Fatalf("OpenSSL did not accept Go node certificate: %s", output)
	}
	if output := runOpenSSL(t, directory, "verify", "-CAfile", "ca.pem", "-purpose", "sslserver", "-verify_ip", "127.0.0.1", "server.pem"); !strings.Contains(output, "server.pem: OK") {
		t.Fatalf("OpenSSL did not accept Go server certificate: %s", output)
	}
	if output := runOpenSSL(t, directory, "x509", "-in", "node.pem", "-noout", "-ext", "subjectAltName"); !strings.Contains(output, "URI:"+nodeURI) {
		t.Fatalf("OpenSSL did not expose the immutable node URI SAN: %s", output)
	}

	runOpenSSL(t, directory, "genpkey", "-algorithm", "ED25519", "-out", "openssl-node.key")
	runOpenSSL(t, directory, "req", "-new", "-key", "openssl-node.key", "-out", "openssl-node.csr", "-subj", "/CN=mutable-name", "-addext", "subjectAltName=URI:"+nodeURI)
	externalCSR, err := os.ReadFile(filepath.Join(directory, "openssl-node.csr"))
	if err != nil {
		t.Fatalf("read OpenSSL CSR: %v", err)
	}
	externalCert, err := signNodeCSR(t, authority, externalCSR, nodeURI, now)
	if err != nil {
		t.Fatalf("Go rejected OpenSSL Ed25519 CSR: %v", err)
	}
	writeFile(t, filepath.Join(directory, "openssl-node.pem"), externalCert, 0o644)
	if output := runOpenSSL(t, directory, "verify", "-CAfile", "ca.pem", "-purpose", "sslclient", "openssl-node.pem"); !strings.Contains(output, "openssl-node.pem: OK") {
		t.Fatalf("OpenSSL did not accept Go-signed OpenSSL CSR: %s", output)
	}

	wrongCSR, _ := createNodeCSR(t, "urn:vpnctl:node:018f4d34-9a72-7b6c-8d5e-deadbeef0000")
	if _, err := signNodeCSR(t, authority, wrongCSR, nodeURI, now); err == nil {
		t.Fatal("gateway signed a CSR carrying the wrong immutable URI SAN")
	}
	wrongIdentity := issueLeaf(t, authority, "urn:vpnctl:client:"+nodeID, false, now)
	if _, err := validateNodeIdentity(wrongIdentity.certificate); err == nil {
		t.Fatal("accepted a CA-valid certificate from the wrong URI namespace")
	}
	multipleIdentity := *wrongIdentity.certificate
	multipleIdentity.URIs = []*url.URL{parseIdentityURI(t, nodeURI), parseIdentityURI(t, "urn:vpnctl:node:018f4d34-9a72-7b6c-8d5e-deadbeef0000")}
	if _, err := validateNodeIdentity(&multipleIdentity); err == nil {
		t.Fatal("accepted a node certificate with multiple URI SAN identities")
	}
}

type enrollmentTranscript struct {
	Purpose          string
	InviteID         string
	Endpoint         string
	NodeID           string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	NodeNonce        []byte
	GatewayNonce     []byte
	Transport        string
	Presets          []string
	PublicKeyHashes  map[string][32]byte
	AssignmentSHA256 [32]byte
}

type signedEnrollment struct {
	Algorithm      string `json:"algorithm"`
	KeyFingerprint string `json:"key_fingerprint"`
	Transcript     string `json:"transcript"`
	Signature      string `json:"signature"`
}

func appendFrame(buffer *bytes.Buffer, name string, value []byte) {
	for _, field := range [][]byte{[]byte(name), value} {
		_ = binary.Write(buffer, binary.BigEndian, uint32(len(field)))
		_, _ = buffer.Write(field)
	}
}

func canonicalTranscript(input enrollmentTranscript) ([]byte, error) {
	if input.Purpose != "enroll" && input.Purpose != "recover" {
		return nil, errors.New("invalid transcript purpose")
	}
	if len(input.NodeNonce) != 16 || len(input.GatewayNonce) != 16 {
		return nil, errors.New("transcript nonces must contain 16 bytes")
	}
	presets := append([]string(nil), input.Presets...)
	sort.Strings(presets)
	for index := 1; index < len(presets); index++ {
		if presets[index] == presets[index-1] {
			return nil, errors.New("duplicate preset")
		}
	}
	keys := make([]string, 0, len(input.PublicKeyHashes))
	for key := range input.PublicKeyHashes {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	buffer := bytes.NewBuffer(nil)
	appendFrame(buffer, "domain", []byte(transcriptDomain))
	appendFrame(buffer, "purpose", []byte(input.Purpose))
	appendFrame(buffer, "invite_id", []byte(input.InviteID))
	appendFrame(buffer, "endpoint", []byte(input.Endpoint))
	appendFrame(buffer, "node_id", []byte(input.NodeID))
	appendFrame(buffer, "issued_at", []byte(input.IssuedAt.UTC().Format(time.RFC3339Nano)))
	appendFrame(buffer, "expires_at", []byte(input.ExpiresAt.UTC().Format(time.RFC3339Nano)))
	appendFrame(buffer, "node_nonce", input.NodeNonce)
	appendFrame(buffer, "gateway_nonce", input.GatewayNonce)
	appendFrame(buffer, "transport", []byte(input.Transport))
	for _, preset := range presets {
		appendFrame(buffer, "preset", []byte(preset))
	}
	for _, key := range keys {
		hash := input.PublicKeyHashes[key]
		appendFrame(buffer, "public_key_hash:"+key, hash[:])
	}
	appendFrame(buffer, "assignment_sha256", input.AssignmentSHA256[:])
	return buffer.Bytes(), nil
}

func publicKeyFingerprint(t *testing.T, publicKey ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	hash := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func signEnrollment(t *testing.T, transcript enrollmentTranscript, privateKey ed25519.PrivateKey) signedEnrollment {
	t.Helper()
	canonical, err := canonicalTranscript(transcript)
	if err != nil {
		t.Fatalf("canonicalize enrollment transcript: %v", err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return signedEnrollment{
		Algorithm:      "Ed25519",
		KeyFingerprint: publicKeyFingerprint(t, publicKey),
		Transcript:     base64.RawURLEncoding.EncodeToString(canonical),
		Signature:      base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)),
	}
}

type replayStore struct {
	mutex sync.Mutex
	seen  map[[32]byte]struct{}
}

func (store *replayStore) consume(value []byte) error {
	key := sha256.Sum256(value)
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.seen == nil {
		store.seen = make(map[[32]byte]struct{})
	}
	if _, found := store.seen[key]; found {
		return errors.New("signed enrollment transcript replayed")
	}
	store.seen[key] = struct{}{}
	return nil
}

func verifyEnrollment(envelope signedEnrollment, expected enrollmentTranscript, publicKey ed25519.PublicKey, now time.Time, store *replayStore) error {
	if envelope.Algorithm != "Ed25519" {
		return errors.New("unexpected enrollment signature algorithm")
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(der)
	if envelope.KeyFingerprint != "sha256:"+hex.EncodeToString(fingerprint[:]) {
		return errors.New("enrollment signing fingerprint mismatch")
	}
	canonical, err := canonicalTranscript(expected)
	if err != nil {
		return err
	}
	transcript, err := base64.RawURLEncoding.DecodeString(envelope.Transcript)
	if err != nil || !bytes.Equal(transcript, canonical) {
		return errors.New("enrollment transcript context mismatch")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(publicKey, transcript, signature) {
		return errors.New("invalid enrollment signature")
	}
	if now.Before(expected.IssuedAt.Add(-clockSkew)) || !now.Before(expected.ExpiresAt) {
		return errors.New("enrollment transcript outside validity window")
	}
	return store.consume(append(append([]byte(nil), transcript...), signature...))
}

func TestEnrollmentTranscriptSignatureAndReplayResistance(t *testing.T) {
	spikeEnabled(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate enrollment key: %v", err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	keyHash := sha256.Sum256([]byte("node-control-csr"))
	wireGuardHash := sha256.Sum256([]byte("wireguard-public-key"))
	assignmentHash := sha256.Sum256([]byte("normalized-assignment-v1"))
	transcript := enrollmentTranscript{
		Purpose:      "enroll",
		InviteID:     "018f4d34-9a72-7b6c-8d5e-111111111111",
		Endpoint:     "https://203.0.113.10/.well-known/vpnctl/enroll/v1",
		NodeID:       nodeID,
		IssuedAt:     now.Add(-time.Minute),
		ExpiresAt:    now.Add(14 * time.Minute),
		NodeNonce:    bytes.Repeat([]byte{0x11}, 16),
		GatewayNonce: bytes.Repeat([]byte{0x22}, 16),
		Transport:    "restricted",
		Presets:      []string{"telegram", "anthropic"},
		PublicKeyHashes: map[string][32]byte{
			"control_csr": keyHash,
			"wireguard":   wireGuardHash,
		},
		AssignmentSHA256: assignmentHash,
	}
	envelope := signEnrollment(t, transcript, privateKey)
	store := &replayStore{}
	if err := verifyEnrollment(envelope, transcript, publicKey, now, store); err != nil {
		t.Fatalf("verify first enrollment transcript: %v", err)
	}
	if err := verifyEnrollment(envelope, transcript, publicKey, now, store); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("expected replay rejection, got %v", err)
	}
	altered := transcript
	altered.Endpoint = "https://203.0.113.11/.well-known/vpnctl/enroll/v1"
	if err := verifyEnrollment(envelope, altered, publicKey, now, &replayStore{}); err == nil {
		t.Fatal("accepted enrollment signature with substituted endpoint")
	}
	altered = transcript
	altered.NodeNonce = bytes.Repeat([]byte{0x33}, 16)
	if err := verifyEnrollment(envelope, altered, publicKey, now, &replayStore{}); err == nil {
		t.Fatal("accepted enrollment signature with substituted nonce")
	}
	if err := verifyEnrollment(envelope, transcript, publicKey, transcript.ExpiresAt, &replayStore{}); err == nil {
		t.Fatal("accepted expired enrollment transcript")
	}

	directory := t.TempDir()
	privatePEM := marshalPrivateKey(t, privateKey)
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal enrollment public key: %v", err)
	}
	canonical, _ := canonicalTranscript(transcript)
	signature, _ := base64.RawURLEncoding.DecodeString(envelope.Signature)
	writeFile(t, filepath.Join(directory, "enrollment.key"), privatePEM, 0o600)
	writeFile(t, filepath.Join(directory, "enrollment.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
	writeFile(t, filepath.Join(directory, "transcript.bin"), canonical, 0o600)
	writeFile(t, filepath.Join(directory, "go.sig"), signature, 0o600)
	runOpenSSL(t, directory, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", "enrollment.pub", "-in", "transcript.bin", "-sigfile", "go.sig")
	runOpenSSL(t, directory, "pkeyutl", "-sign", "-rawin", "-inkey", "enrollment.key", "-in", "transcript.bin", "-out", "openssl.sig")
	openSSLSignature, err := os.ReadFile(filepath.Join(directory, "openssl.sig"))
	if err != nil {
		t.Fatalf("read OpenSSL signature: %v", err)
	}
	if !ed25519.Verify(publicKey, canonical, openSSLSignature) {
		t.Fatal("Go rejected OpenSSL Ed25519 enrollment signature")
	}
}

func needsRenewal(certificate *x509.Certificate, now time.Time) bool {
	return !certificate.NotAfter.After(now.Add(renewalWindow))
}

func certPool(authorities ...certificateAuthority) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, authority := range authorities {
		pool.AddCert(authority.certificate)
	}
	return pool
}

func tlsCertificate(t *testing.T, issued issuedCertificate) tls.Certificate {
	t.Helper()
	certificate, err := tls.X509KeyPair(issued.certPEM, issued.keyPEM)
	if err != nil {
		t.Fatalf("load TLS certificate: %v", err)
	}
	return certificate
}

func validateNodeIdentity(certificate *x509.Certificate) (string, error) {
	if len(certificate.URIs) != 1 {
		return "", errors.New("node certificate must contain exactly one URI SAN")
	}
	value := certificate.URIs[0].String()
	prefix := "urn:vpnctl:node:"
	if !strings.HasPrefix(value, prefix) {
		return "", errors.New("node URI SAN has the wrong namespace")
	}
	identity := strings.TrimPrefix(value, prefix)
	if len(identity) != 36 || identity[8] != '-' || identity[13] != '-' || identity[18] != '-' || identity[23] != '-' {
		return "", errors.New("node URI SAN does not contain a UUID")
	}
	if decoded, err := hex.DecodeString(strings.ReplaceAll(identity, "-", "")); err != nil || len(decoded) != 16 {
		return "", errors.New("node URI SAN UUID is not canonical hexadecimal")
	}
	return identity, nil
}

func TestRenewalAndControlCAOverlap(t *testing.T) {
	spikeEnabled(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	oldCA := newAuthority(t, "vpnctl old control CA", now)
	newCA := newAuthority(t, "vpnctl new control CA", now)
	oldServer := issueLeaf(t, oldCA, gatewayURI, true, now)
	renewedServer := issueLeaf(t, oldCA, gatewayURI, true, now.Add(leafValidity-renewalWindow))
	oldClient := issueLeaf(t, oldCA, nodeURI, false, now)
	newClient := issueLeaf(t, newCA, nodeURI, false, now)

	if oldServer.certificate.SerialNumber.Cmp(renewedServer.certificate.SerialNumber) == 0 {
		t.Fatal("gateway renewal reused a certificate serial")
	}
	if needsRenewal(oldServer.certificate, oldServer.certificate.NotAfter.Add(-renewalWindow-time.Second)) {
		t.Fatal("gateway leaf entered renewal before the 180-day window")
	}
	if !needsRenewal(oldServer.certificate, oldServer.certificate.NotAfter.Add(-renewalWindow)) {
		t.Fatal("gateway leaf did not enter renewal at the 180-day window")
	}

	dualRoots := certPool(oldCA, newCA)
	serverChecks := map[string]struct {
		leaf        issuedCertificate
		currentTime time.Time
	}{
		"old":     {leaf: oldServer, currentTime: now.Add(time.Hour)},
		"renewed": {leaf: renewedServer, currentTime: renewedServer.certificate.NotBefore.Add(time.Hour)},
	}
	for name, check := range serverChecks {
		if _, err := check.leaf.certificate.Verify(x509.VerifyOptions{Roots: dualRoots, DNSName: "127.0.0.1", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: check.currentTime}); err != nil {
			t.Fatalf("dual trust rejected %s gateway leaf: %v", name, err)
		}
	}
	for name, leaf := range map[string]issuedCertificate{"old": oldClient, "new": newClient} {
		if _, err := leaf.certificate.Verify(x509.VerifyOptions{Roots: dualRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now.Add(time.Hour)}); err != nil {
			t.Fatalf("dual trust rejected %s node leaf: %v", name, err)
		}
	}
	if _, err := oldClient.certificate.Verify(x509.VerifyOptions{Roots: certPool(newCA), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now.Add(time.Hour)}); err == nil {
		t.Fatal("new-only trust accepted an old-CA node leaf after overlap commit")
	}
}

type rpcEnvelope struct {
	ProtocolMajor           int             `json:"protocol_major"`
	ProtocolMinor           int             `json:"protocol_minor"`
	RequestID               string          `json:"request_id"`
	ExpectedStateGeneration uint64          `json:"expected_state_generation"`
	NodeID                  string          `json:"node_id"`
	CredentialGeneration    uint64          `json:"credential_generation"`
	Timestamp               time.Time       `json:"timestamp"`
	Nonce                   string          `json:"nonce"`
	Operation               string          `json:"operation"`
	Payload                 json.RawMessage `json:"payload"`
}

type rpcResult struct {
	SchemaVersion           int      `json:"schema_version"`
	Category                string   `json:"category"`
	AuthoritativeGeneration uint64   `json:"authoritative_generation"`
	Warnings                []string `json:"warnings"`
	RequiresAction          []string `json:"requires_action"`
}

type identityState struct {
	active               bool
	credentialGeneration uint64
	stateGeneration      uint64
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid JSON object closing delimiter")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array closing delimiter")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func decodeRPC(body []byte) (rpcEnvelope, error) {
	if len(body) == 0 || len(body) > maxRequestBytes {
		return rpcEnvelope{}, errors.New("RPC body size is invalid")
	}
	shape := json.NewDecoder(bytes.NewReader(body))
	if err := scanJSONValue(shape, 1); err != nil {
		return rpcEnvelope{}, err
	}
	if _, err := shape.Token(); !errors.Is(err, io.EOF) {
		return rpcEnvelope{}, errors.New("RPC body must contain one JSON value")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var envelope rpcEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return rpcEnvelope{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return rpcEnvelope{}, errors.New("RPC body contains trailing JSON")
	}
	return envelope, nil
}

type limitedListener struct {
	net.Listener
	tokens chan struct{}
}

type limitedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (connection *limitedConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}

func (listener *limitedListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case listener.tokens <- struct{}{}:
			return &limitedConnection{Conn: connection, release: func() { <-listener.tokens }}, nil
		default:
			_ = connection.Close()
		}
	}
}

type rpcFixture struct {
	address     string
	server      *http.Server
	listener    net.Listener
	client      *http.Client
	clientTLS   *tls.Config
	state       *identityState
	hold        chan struct{}
	entered     chan struct{}
	active      atomic.Int32
	maxObserved atomic.Int32
}

func newRPCFixture(t *testing.T) *rpcFixture {
	t.Helper()
	now := time.Now().UTC()
	authority := newAuthority(t, "vpnctl RPC control CA", now)
	serverLeaf := issueLeaf(t, authority, gatewayURI, true, now)
	clientLeaf := issueLeaf(t, authority, nodeURI, false, now)
	serverCertificate := tlsCertificate(t, serverLeaf)
	clientCertificate := tlsCertificate(t, clientLeaf)
	clientCAs := certPool(authority)

	fixture := &rpcFixture{
		state:   &identityState{active: true, credentialGeneration: 7, stateGeneration: 42},
		hold:    make(chan struct{}),
		entered: make(chan struct{}, maxConcurrentConns),
	}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != controlRPCPath || request.ProtoMajor != 1 || request.ProtoMinor != 1 {
			http.Error(writer, "invalid control method, path, or HTTP version", http.StatusNotFound)
			return
		}
		if mediaType := strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]); mediaType != controlContentType {
			http.Error(writer, "content type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		if request.ContentLength > maxRequestBytes {
			http.Error(writer, "request exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}
		request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, "request exceeds limit", http.StatusRequestEntityTooLarge)
			return
		}
		envelope, err := decodeRPC(body)
		if err != nil {
			http.Error(writer, "invalid RPC JSON", http.StatusBadRequest)
			return
		}
		peer := request.TLS.PeerCertificates[0]
		authenticatedNodeID, err := validateNodeIdentity(peer)
		if err != nil || envelope.NodeID != authenticatedNodeID || !fixture.state.active || envelope.CredentialGeneration != fixture.state.credentialGeneration {
			http.Error(writer, "inactive or stale authenticated node", http.StatusForbidden)
			return
		}
		if envelope.ProtocolMajor != 1 || envelope.ProtocolMinor < 0 || envelope.ExpectedStateGeneration != fixture.state.stateGeneration {
			http.Error(writer, "protocol or state generation conflict", http.StatusConflict)
			return
		}
		if delta := time.Since(envelope.Timestamp); delta < -clockSkew || delta > clockSkew {
			http.Error(writer, "request timestamp outside window", http.StatusBadRequest)
			return
		}
		nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
		if err != nil || len(nonce) != 16 {
			http.Error(writer, "invalid request nonce", http.StatusBadRequest)
			return
		}
		if envelope.Operation == "hold" {
			current := fixture.active.Add(1)
			for {
				maximum := fixture.maxObserved.Load()
				if current <= maximum || fixture.maxObserved.CompareAndSwap(maximum, current) {
					break
				}
			}
			fixture.entered <- struct{}{}
			<-fixture.hold
			fixture.active.Add(-1)
		}
		if envelope.Operation == "slow-write" {
			time.Sleep(writeTimeout + time.Second)
		}
		result := rpcResult{SchemaVersion: 1, Category: "success", AuthoritativeGeneration: fixture.state.stateGeneration, Warnings: []string{}, RequiresAction: []string{}}
		if envelope.Operation == "oversized-response" {
			result.Warnings = []string{strings.Repeat("x", maxResponseBytes)}
		}
		encoded, err := json.Marshal(result)
		if err != nil || len(encoded) > maxResponseBytes {
			http.Error(writer, "bounded response generation failed", http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", controlContentType)
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(encoded)
	})

	baseListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for RPC fixture: %v", err)
	}
	if host, _, _ := net.SplitHostPort(baseListener.Addr().String()); host != "127.0.0.1" {
		t.Fatalf("control fixture escaped private loopback binding: %s", baseListener.Addr())
	}
	listener := &limitedListener{Listener: baseListener, tokens: make(chan struct{}, maxConcurrentConns)}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		NextProtos:   []string{"http/1.1"},
	}
	server := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	tlsListener := tls.NewListener(listener, tlsConfig)
	go func() { _ = server.Serve(tlsListener) }()

	clientTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      clientCAs,
		Certificates: []tls.Certificate{clientCertificate},
		ServerName:   "127.0.0.1",
		NextProtos:   []string{"http/1.1"},
	}
	transport := &http.Transport{TLSClientConfig: clientTLS, ForceAttemptHTTP2: false, DisableKeepAlives: true}
	fixture.address = "https://" + baseListener.Addr().String()
	fixture.server = server
	fixture.listener = tlsListener
	fixture.clientTLS = clientTLS
	fixture.client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	t.Cleanup(func() {
		select {
		case <-fixture.hold:
		default:
			close(fixture.hold)
		}
		_ = server.Shutdown(context.Background())
		_ = tlsListener.Close()
		transport.CloseIdleConnections()
	})
	return fixture
}

func validEnvelope(operation string) rpcEnvelope {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	requestID := make([]byte, 16)
	_, _ = rand.Read(requestID)
	return rpcEnvelope{
		ProtocolMajor:           1,
		ProtocolMinor:           0,
		RequestID:               hex.EncodeToString(requestID),
		ExpectedStateGeneration: 42,
		NodeID:                  nodeID,
		CredentialGeneration:    7,
		Timestamp:               time.Now().UTC(),
		Nonce:                   base64.RawURLEncoding.EncodeToString(nonce),
		Operation:               operation,
		Payload:                 json.RawMessage(`{}`),
	}
}

func (fixture *rpcFixture) request(t *testing.T, body []byte, contentType string) (*http.Response, []byte, error) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, fixture.address+controlRPCPath, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("Content-Type", contentType)
	response, err := fixture.client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	return response, responseBody, readErr
}

func marshalEnvelope(t *testing.T, envelope rpcEnvelope) []byte {
	t.Helper()
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal RPC envelope: %v", err)
	}
	return data
}

func TestHTTPS11JSONRPCLimitsAndIdentity(t *testing.T) {
	spikeEnabled(t)
	fixture := newRPCFixture(t)
	response, body, err := fixture.request(t, marshalEnvelope(t, validEnvelope("status")), controlContentType)
	if err != nil {
		t.Fatalf("valid RPC request: %v", err)
	}
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 1 || response.ProtoMinor != 1 || len(body) > maxResponseBytes {
		t.Fatalf("unexpected valid RPC result: status=%d proto=%s bytes=%d", response.StatusCode, response.Proto, len(body))
	}
	if response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || response.TLS.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("unexpected control TLS/ALPN state: %+v", response.TLS)
	}

	unknown := append(bytes.TrimSuffix(marshalEnvelope(t, validEnvelope("status")), []byte("}")), []byte(`,"unknown":true}`)...)
	duplicate := bytes.Replace(marshalEnvelope(t, validEnvelope("status")), []byte(`"protocol_major":1`), []byte(`"protocol_major":1,"protocol_major":1`), 1)
	deep := []byte(strings.Repeat("[", maxJSONDepth+1) + "0" + strings.Repeat("]", maxJSONDepth+1))
	cases := []struct {
		name        string
		body        []byte
		contentType string
		status      int
	}{
		{name: "malformed", body: []byte(`{"protocol_major":`), contentType: controlContentType, status: http.StatusBadRequest},
		{name: "unknown", body: unknown, contentType: controlContentType, status: http.StatusBadRequest},
		{name: "duplicate", body: duplicate, contentType: controlContentType, status: http.StatusBadRequest},
		{name: "deep", body: deep, contentType: controlContentType, status: http.StatusBadRequest},
		{name: "trailing", body: append(marshalEnvelope(t, validEnvelope("status")), []byte(` {}`)...), contentType: controlContentType, status: http.StatusBadRequest},
		{name: "wrong-content-type", body: marshalEnvelope(t, validEnvelope("status")), contentType: "text/plain", status: http.StatusUnsupportedMediaType},
		{name: "oversized", body: bytes.Repeat([]byte("x"), maxRequestBytes+1), contentType: controlContentType, status: http.StatusRequestEntityTooLarge},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			response, _, err := fixture.request(t, testCase.body, testCase.contentType)
			if err != nil {
				t.Fatalf("malformed RPC request: %v", err)
			}
			if response.StatusCode != testCase.status {
				t.Fatalf("unexpected status: got %d want %d", response.StatusCode, testCase.status)
			}
		})
	}

	stale := validEnvelope("status")
	stale.CredentialGeneration = 6
	response, _, err = fixture.request(t, marshalEnvelope(t, stale), controlContentType)
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("stale credential generation was not rejected: status=%v err=%v", responseStatus(response), err)
	}
	fixture.state.active = false
	response, _, err = fixture.request(t, marshalEnvelope(t, validEnvelope("status")), controlContentType)
	if err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("inactive authoritative node was not rejected: status=%v err=%v", responseStatus(response), err)
	}
	fixture.state.active = true

	response, body, err = fixture.request(t, marshalEnvelope(t, validEnvelope("oversized-response")), controlContentType)
	if err != nil || response.StatusCode != http.StatusInternalServerError || len(body) > maxResponseBytes {
		t.Fatalf("oversized response was not bounded: status=%v bytes=%d err=%v", responseStatus(response), len(body), err)
	}

	noCertificateTLS := fixture.clientTLS.Clone()
	noCertificateTLS.Certificates = nil
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: noCertificateTLS, ForceAttemptHTTP2: false}, Timeout: 5 * time.Second}
	request, _ := http.NewRequest(http.MethodPost, fixture.address+controlRPCPath, bytes.NewReader(marshalEnvelope(t, validEnvelope("status"))))
	request.Header.Set("Content-Type", controlContentType)
	if _, err := client.Do(request); err == nil {
		t.Fatal("control RPC accepted a client without an mTLS certificate")
	}
	tls12Only := fixture.clientTLS.Clone()
	tls12Only.MinVersion = tls.VersionTLS12
	tls12Only.MaxVersion = tls.VersionTLS12
	if connection, err := tls.Dial("tcp", strings.TrimPrefix(fixture.address, "https://"), tls12Only); err == nil {
		_ = connection.Close()
		t.Fatal("control RPC accepted TLS 1.2 below the selected TLS 1.3 minimum")
	}
}

func responseStatus(response *http.Response) any {
	if response == nil {
		return nil
	}
	return response.StatusCode
}

func TestHTTPS11ConnectionAndHeaderTimeoutBounds(t *testing.T) {
	spikeEnabled(t)
	fixture := newRPCFixture(t)

	holdEnvelope := marshalEnvelope(t, validEnvelope("hold"))
	var waitGroup sync.WaitGroup
	errorsChannel := make(chan error, maxConcurrentConns)
	for range maxConcurrentConns {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			response, _, err := fixture.request(t, holdEnvelope, controlContentType)
			if err == nil && response.StatusCode != http.StatusOK {
				err = fmt.Errorf("hold request returned %d", response.StatusCode)
			}
			errorsChannel <- err
		}()
	}
	for range maxConcurrentConns {
		select {
		case <-fixture.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("16 RPC connections did not enter the bounded handler")
		}
	}
	extraContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	extraRequest, _ := http.NewRequestWithContext(extraContext, http.MethodPost, fixture.address+controlRPCPath, bytes.NewReader(holdEnvelope))
	extraRequest.Header.Set("Content-Type", controlContentType)
	if _, err := fixture.client.Do(extraRequest); err == nil {
		t.Fatal("17th concurrent control connection escaped the hard connection bound")
	}
	close(fixture.hold)
	waitGroup.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("admitted hold request failed: %v", err)
		}
	}
	if fixture.maxObserved.Load() != maxConcurrentConns {
		t.Fatalf("unexpected maximum handler concurrency: %d", fixture.maxObserved.Load())
	}

	connection, err := tls.Dial("tcp", strings.TrimPrefix(fixture.address, "https://"), fixture.clientTLS.Clone())
	if err != nil {
		t.Fatalf("dial slow-header TLS fixture: %v", err)
	}
	start := time.Now()
	_, _ = io.WriteString(connection, "POST /rpc/v1/status HTTP/1.1\r\nHost: control\r\nX-Slow:")
	_ = connection.SetReadDeadline(time.Now().Add(4 * time.Second))
	buffer := make([]byte, 1)
	_, readErr := connection.Read(buffer)
	_ = connection.Close()
	if readErr == nil || time.Since(start) > 4*time.Second {
		t.Fatalf("slow header was not closed within bound: duration=%s err=%v", time.Since(start), readErr)
	}

	oversizedHeaderConnection, err := tls.Dial("tcp", strings.TrimPrefix(fixture.address, "https://"), fixture.clientTLS.Clone())
	if err != nil {
		t.Fatalf("dial oversized-header TLS fixture: %v", err)
	}
	_, _ = fmt.Fprintf(oversizedHeaderConnection, "POST %s HTTP/1.1\r\nHost: control\r\nContent-Type: application/json\r\nX-Oversized: %s\r\nContent-Length: 0\r\n\r\n", controlRPCPath, strings.Repeat("h", 2*maxHeaderBytes))
	_ = oversizedHeaderConnection.SetReadDeadline(time.Now().Add(3 * time.Second))
	oversizedResponse, oversizedErr := http.ReadResponse(bufio.NewReader(oversizedHeaderConnection), &http.Request{Method: http.MethodPost})
	_ = oversizedHeaderConnection.Close()
	if oversizedErr == nil {
		defer oversizedResponse.Body.Close()
		if oversizedResponse.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("oversized header returned %d instead of 431", oversizedResponse.StatusCode)
		}
	}

	slowBodyConnection, err := tls.Dial("tcp", strings.TrimPrefix(fixture.address, "https://"), fixture.clientTLS.Clone())
	if err != nil {
		t.Fatalf("dial slow-body TLS fixture: %v", err)
	}
	_, _ = fmt.Fprintf(slowBodyConnection, "POST %s HTTP/1.1\r\nHost: control\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{", controlRPCPath)
	bodyStart := time.Now()
	_ = slowBodyConnection.SetReadDeadline(time.Now().Add(7 * time.Second))
	_, bodyReadErr := slowBodyConnection.Read(buffer)
	_ = slowBodyConnection.Close()
	bodyDuration := time.Since(bodyStart)
	if bodyReadErr == nil || bodyDuration < 4*time.Second || bodyDuration > 7*time.Second {
		t.Fatalf("slow body was not closed at the five-second read bound: duration=%s err=%v", bodyDuration, bodyReadErr)
	}

	writeStart := time.Now()
	_, _, writeErr := fixture.request(t, marshalEnvelope(t, validEnvelope("slow-write")), controlContentType)
	writeDuration := time.Since(writeStart)
	if writeErr == nil || writeDuration < 4*time.Second || writeDuration > 7*time.Second {
		t.Fatalf("slow response was not closed at the five-second write bound: duration=%s err=%v", writeDuration, writeErr)
	}

	idleConnection, err := tls.Dial("tcp", strings.TrimPrefix(fixture.address, "https://"), fixture.clientTLS.Clone())
	if err != nil {
		t.Fatalf("dial idle TLS fixture: %v", err)
	}
	idleBody := marshalEnvelope(t, validEnvelope("status"))
	_, _ = fmt.Fprintf(idleConnection, "POST %s HTTP/1.1\r\nHost: control\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n", controlRPCPath, len(idleBody))
	_, _ = idleConnection.Write(idleBody)
	idleResponse, err := http.ReadResponse(bufio.NewReader(idleConnection), &http.Request{Method: http.MethodPost})
	if err != nil {
		_ = idleConnection.Close()
		t.Fatalf("read pre-idle RPC response: %v", err)
	}
	_, _ = io.Copy(io.Discard, idleResponse.Body)
	_ = idleResponse.Body.Close()
	idleStart := time.Now()
	_ = idleConnection.SetReadDeadline(time.Now().Add(7 * time.Second))
	_, idleReadErr := idleConnection.Read(buffer)
	_ = idleConnection.Close()
	idleDuration := time.Since(idleStart)
	if idleReadErr == nil || idleDuration < 4*time.Second || idleDuration > 7*time.Second {
		t.Fatalf("idle connection was not closed at the five-second bound: duration=%s err=%v", idleDuration, idleReadErr)
	}
}
