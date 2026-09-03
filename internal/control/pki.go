package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	ControlCAValidity       = 3650 * 24 * time.Hour
	ControlLeafValidity     = 1825 * 24 * time.Hour
	ControlRenewalWindow    = 180 * 24 * time.Hour
	ControlWarningDays      = 180
	certificateBackdate     = 5 * time.Minute
	serialGenerationRetries = 32
)

var (
	ErrInvalidControlIdentity = errors.New("invalid control identity")
	ErrInvalidNodeCSR         = errors.New("invalid node control CSR")
	controlUUIDPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type GatewayControlMaterial struct {
	ControlCACertificatePEM []byte
	ControlCAPrivateKeyPEM  []byte
	GatewayCertificatePEM   []byte
	GatewayPrivateKeyPEM    []byte
	EnrollmentPublicKeyPEM  []byte
	EnrollmentPrivateKeyPEM []byte
	EnrollmentFingerprint   string

	controlCA          *x509.Certificate
	gatewayCertificate *x509.Certificate
}

type NodeCSRMaterial struct {
	CSRPEM        []byte
	PrivateKeyPEM []byte
	IdentityURI   string
}

type IssuedNodeCertificate struct {
	CertificatePEM []byte
	IdentityURI    string
	Certificate    *x509.Certificate
}

type IssuedGatewayCertificate struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	IdentityURI    string
	OverlayIPv4    string
	Certificate    *x509.Certificate
}

func GenerateGatewayControlMaterial(entropy io.Reader, gatewayID, overlayIPv4 string, issuedAt time.Time) (GatewayControlMaterial, error) {
	if entropy == nil {
		return GatewayControlMaterial{}, fmt.Errorf("entropy source is required")
	}
	gatewayURI, err := controlIdentityURI("gateway", gatewayID)
	if err != nil {
		return GatewayControlMaterial{}, err
	}
	overlay, err := netip.ParseAddr(overlayIPv4)
	if err != nil || !overlay.Is4() || overlay.String() != overlayIPv4 {
		return GatewayControlMaterial{}, fmt.Errorf("%w: gateway overlay address must be canonical IPv4", ErrInvalidControlIdentity)
	}
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	if issuedAt.IsZero() {
		return GatewayControlMaterial{}, fmt.Errorf("%w: issuance time is required", ErrInvalidControlIdentity)
	}

	caPublic, caPrivate, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return GatewayControlMaterial{}, fmt.Errorf("generate control CA key: %w", err)
	}
	caSerial, err := randomPositiveSerial(entropy)
	if err != nil {
		return GatewayControlMaterial{}, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "vpnctl control CA", Organization: []string{"vpnctl control"}},
		NotBefore:             issuedAt.Add(-certificateBackdate),
		NotAfter:              issuedAt.Add(ControlCAValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SignatureAlgorithm:    x509.PureEd25519,
		SubjectKeyId:          publicKeyID(caPublic),
	}
	caDER, err := x509.CreateCertificate(entropy, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return GatewayControlMaterial{}, fmt.Errorf("create control CA certificate: %w", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return GatewayControlMaterial{}, fmt.Errorf("parse created control CA certificate: %w", err)
	}

	gatewayPublic, gatewayPrivate, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return GatewayControlMaterial{}, fmt.Errorf("generate gateway control key: %w", err)
	}
	gatewaySerial, err := randomPositiveSerial(entropy)
	if err != nil {
		return GatewayControlMaterial{}, err
	}
	gatewayTemplate := &x509.Certificate{
		SerialNumber:          gatewaySerial,
		Subject:               pkix.Name{CommonName: "vpnctl gateway control leaf", Organization: []string{"vpnctl control"}},
		NotBefore:             issuedAt.Add(-certificateBackdate),
		NotAfter:              issuedAt.Add(ControlLeafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{gatewayURI},
		IPAddresses:           []net.IP{net.IP(overlay.AsSlice())},
		SignatureAlgorithm:    x509.PureEd25519,
		SubjectKeyId:          publicKeyID(gatewayPublic),
		AuthorityKeyId:        append([]byte(nil), caCertificate.SubjectKeyId...),
	}
	gatewayDER, err := x509.CreateCertificate(entropy, gatewayTemplate, caCertificate, gatewayPublic, caPrivate)
	if err != nil {
		return GatewayControlMaterial{}, fmt.Errorf("create gateway control certificate: %w", err)
	}
	gatewayCertificate, err := x509.ParseCertificate(gatewayDER)
	if err != nil {
		return GatewayControlMaterial{}, fmt.Errorf("parse created gateway control certificate: %w", err)
	}

	enrollmentPublic, enrollmentPrivate, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return GatewayControlMaterial{}, fmt.Errorf("generate enrollment signing key: %w", err)
	}
	enrollmentPublicDER, err := x509.MarshalPKIXPublicKey(enrollmentPublic)
	if err != nil {
		return GatewayControlMaterial{}, fmt.Errorf("marshal enrollment public key: %w", err)
	}
	enrollmentHash := sha256.Sum256(enrollmentPublicDER)

	caPrivatePEM, err := marshalPKCS8PrivateKey(caPrivate)
	if err != nil {
		return GatewayControlMaterial{}, err
	}
	gatewayPrivatePEM, err := marshalPKCS8PrivateKey(gatewayPrivate)
	if err != nil {
		return GatewayControlMaterial{}, err
	}
	enrollmentPrivatePEM, err := marshalPKCS8PrivateKey(enrollmentPrivate)
	if err != nil {
		return GatewayControlMaterial{}, err
	}
	return GatewayControlMaterial{
		ControlCACertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		ControlCAPrivateKeyPEM:  caPrivatePEM,
		GatewayCertificatePEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gatewayDER}),
		GatewayPrivateKeyPEM:    gatewayPrivatePEM,
		EnrollmentPublicKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: enrollmentPublicDER}),
		EnrollmentPrivateKeyPEM: enrollmentPrivatePEM,
		EnrollmentFingerprint:   "sha256:" + hex.EncodeToString(enrollmentHash[:]),
		controlCA:               caCertificate,
		gatewayCertificate:      gatewayCertificate,
	}, nil
}

func GenerateNodeControlCSR(entropy io.Reader, nodeID string) (NodeCSRMaterial, error) {
	if entropy == nil {
		return NodeCSRMaterial{}, fmt.Errorf("entropy source is required")
	}
	identity, err := controlIdentityURI("node", nodeID)
	if err != nil {
		return NodeCSRMaterial{}, err
	}
	_, privateKey, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return NodeCSRMaterial{}, fmt.Errorf("generate node control key: %w", err)
	}
	requestDER, err := x509.CreateCertificateRequest(entropy, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "vpnctl node control request"},
		URIs:    []*url.URL{identity},
	}, privateKey)
	if err != nil {
		return NodeCSRMaterial{}, fmt.Errorf("create node control CSR: %w", err)
	}
	privatePEM, err := marshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return NodeCSRMaterial{}, err
	}
	return NodeCSRMaterial{
		CSRPEM:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER}),
		PrivateKeyPEM: privatePEM,
		IdentityURI:   identity.String(),
	}, nil
}

// IssueGatewayControlCertificate creates a fresh server key and leaf under an
// existing control CA. It never changes CA or enrollment material and refuses
// a leaf whose full five-year validity would outlive the signing CA.
func IssueGatewayControlCertificate(entropy io.Reader, authorityCertificatePEM, authorityPrivateKeyPEM []byte, gatewayID, overlayIPv4 string, issuedAt time.Time) (IssuedGatewayCertificate, error) {
	if entropy == nil {
		return IssuedGatewayCertificate{}, fmt.Errorf("entropy source is required")
	}
	identity, err := controlIdentityURI("gateway", gatewayID)
	if err != nil {
		return IssuedGatewayCertificate{}, err
	}
	overlay, err := netip.ParseAddr(overlayIPv4)
	if err != nil || !overlay.Is4() || overlay.String() != overlayIPv4 {
		return IssuedGatewayCertificate{}, fmt.Errorf("%w: gateway overlay address must be canonical IPv4", ErrInvalidControlIdentity)
	}
	authority, authorityKey, err := parseControlAuthority(authorityCertificatePEM, authorityPrivateKeyPEM)
	if err != nil {
		return IssuedGatewayCertificate{}, err
	}
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	if issuedAt.IsZero() {
		return IssuedGatewayCertificate{}, fmt.Errorf("%w: issuance time is required", ErrInvalidControlIdentity)
	}
	notAfter := issuedAt.Add(ControlLeafValidity)
	if issuedAt.Before(authority.NotBefore) || notAfter.After(authority.NotAfter) {
		return IssuedGatewayCertificate{}, fmt.Errorf("%w: control CA validity cannot cover a renewed gateway leaf", ErrInvalidControlIdentity)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return IssuedGatewayCertificate{}, fmt.Errorf("generate gateway control key: %w", err)
	}
	serial, err := randomPositiveSerial(entropy)
	if err != nil {
		return IssuedGatewayCertificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "vpnctl gateway control leaf", Organization: []string{"vpnctl control"}},
		NotBefore:    issuedAt.Add(-certificateBackdate), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, URIs: []*url.URL{identity}, IPAddresses: []net.IP{net.IP(overlay.AsSlice())},
		SignatureAlgorithm: x509.PureEd25519, SubjectKeyId: publicKeyID(publicKey), AuthorityKeyId: append([]byte(nil), authority.SubjectKeyId...),
	}
	certificateDER, err := x509.CreateCertificate(entropy, template, authority, publicKey, authorityKey)
	if err != nil {
		return IssuedGatewayCertificate{}, fmt.Errorf("issue gateway control certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return IssuedGatewayCertificate{}, fmt.Errorf("parse issued gateway control certificate: %w", err)
	}
	privatePEM, err := marshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return IssuedGatewayCertificate{}, err
	}
	return IssuedGatewayCertificate{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		PrivateKeyPEM:  privatePEM, IdentityURI: identity.String(), OverlayIPv4: overlayIPv4, Certificate: certificate,
	}, nil
}

func IssueNodeControlCertificate(entropy io.Reader, authorityCertificatePEM, authorityPrivateKeyPEM, csrPEM []byte, authoritativeNodeID string, issuedAt time.Time) (IssuedNodeCertificate, error) {
	if entropy == nil {
		return IssuedNodeCertificate{}, fmt.Errorf("entropy source is required")
	}
	authority, authorityKey, err := parseControlAuthority(authorityCertificatePEM, authorityPrivateKeyPEM)
	if err != nil {
		return IssuedNodeCertificate{}, err
	}
	request, expectedIdentity, err := parseAndValidateNodeControlCSR(csrPEM, authoritativeNodeID)
	if err != nil {
		return IssuedNodeCertificate{}, err
	}
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	if issuedAt.IsZero() {
		return IssuedNodeCertificate{}, fmt.Errorf("%w: issuance time is required", ErrInvalidControlIdentity)
	}
	serial, err := randomPositiveSerial(entropy)
	if err != nil {
		return IssuedNodeCertificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "vpnctl node control leaf", Organization: []string{"vpnctl control"}},
		NotBefore:             issuedAt.Add(-certificateBackdate),
		NotAfter:              issuedAt.Add(ControlLeafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{expectedIdentity},
		SignatureAlgorithm:    x509.PureEd25519,
		AuthorityKeyId:        append([]byte(nil), authority.SubjectKeyId...),
	}
	certificateDER, err := x509.CreateCertificate(entropy, template, authority, request.PublicKey, authorityKey)
	if err != nil {
		return IssuedNodeCertificate{}, fmt.Errorf("issue node control certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return IssuedNodeCertificate{}, fmt.Errorf("parse issued node control certificate: %w", err)
	}
	return IssuedNodeCertificate{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		IdentityURI:    expectedIdentity.String(),
		Certificate:    certificate,
	}, nil
}

// ValidateNodeControlCSR applies the same profile used by certificate
// issuance without requiring access to the gateway control CA.
func ValidateNodeControlCSR(csrPEM []byte, authoritativeNodeID string) error {
	_, _, err := parseAndValidateNodeControlCSR(csrPEM, authoritativeNodeID)
	return err
}

func parseAndValidateNodeControlCSR(csrPEM []byte, authoritativeNodeID string) (*x509.CertificateRequest, *url.URL, error) {
	expectedIdentity, err := controlIdentityURI("node", authoritativeNodeID)
	if err != nil {
		return nil, nil, err
	}
	requestDER, err := decodeSinglePEM(csrPEM, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidNodeCSR, err)
	}
	request, err := x509.ParseCertificateRequest(requestDER)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parse request: %v", ErrInvalidNodeCSR, err)
	}
	if request.SignatureAlgorithm != x509.PureEd25519 {
		return nil, nil, fmt.Errorf("%w: signature algorithm must be Ed25519", ErrInvalidNodeCSR)
	}
	if _, ok := request.PublicKey.(ed25519.PublicKey); !ok {
		return nil, nil, fmt.Errorf("%w: public key must be Ed25519", ErrInvalidNodeCSR)
	}
	if err := request.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("%w: signature validation failed", ErrInvalidNodeCSR)
	}
	if len(request.URIs) != 1 || request.URIs[0].String() != expectedIdentity.String() ||
		len(request.DNSNames) != 0 || len(request.IPAddresses) != 0 || len(request.EmailAddresses) != 0 {
		return nil, nil, fmt.Errorf("%w: SAN must contain only authoritative URI %s", ErrInvalidNodeCSR, expectedIdentity)
	}
	return request, expectedIdentity, nil
}

func GatewayOverlayIPv4(nodeCIDR string) (string, error) {
	prefix, err := netip.ParsePrefix(nodeCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked().String() != nodeCIDR {
		return "", fmt.Errorf("%w: node CIDR must be canonical IPv4", ErrInvalidControlIdentity)
	}
	address := prefix.Addr().Next()
	if !address.IsValid() || !prefix.Contains(address) {
		return "", fmt.Errorf("%w: node CIDR has no gateway address", ErrInvalidControlIdentity)
	}
	return address.String(), nil
}

func randomPositiveSerial(entropy io.Reader) (*big.Int, error) {
	var raw [16]byte
	for attempt := 0; attempt < serialGenerationRetries; attempt++ {
		if _, err := io.ReadFull(entropy, raw[:]); err != nil {
			return nil, fmt.Errorf("read certificate serial entropy: %w", err)
		}
		serial := new(big.Int).SetBytes(raw[:])
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
	return nil, fmt.Errorf("generate positive certificate serial after %d attempts", serialGenerationRetries)
}

func controlIdentityURI(kind, id string) (*url.URL, error) {
	if kind != "gateway" && kind != "node" {
		return nil, fmt.Errorf("%w: unsupported identity kind", ErrInvalidControlIdentity)
	}
	if !controlUUIDPattern.MatchString(id) {
		return nil, fmt.Errorf("%w: identity ID must be a canonical UUID", ErrInvalidControlIdentity)
	}
	return &url.URL{Scheme: "urn", Opaque: "vpnctl:" + kind + ":" + id}, nil
}

func marshalPKCS8PrivateKey(privateKey ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal Ed25519 private key as PKCS#8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseControlAuthority(certificatePEM, privateKeyPEM []byte) (*x509.Certificate, ed25519.PrivateKey, error) {
	certificateDER, err := decodeSinglePEM(certificatePEM, "CERTIFICATE")
	if err != nil {
		return nil, nil, fmt.Errorf("parse control authority certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse control authority certificate: %w", err)
	}
	keyDER, err := decodeSinglePEM(privateKeyPEM, "PRIVATE KEY")
	if err != nil {
		return nil, nil, fmt.Errorf("parse control authority private key: %w", err)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse control authority PKCS#8 key: %w", err)
	}
	privateKey, ok := parsedKey.(ed25519.PrivateKey)
	if !ok || certificate.PublicKeyAlgorithm != x509.Ed25519 || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, fmt.Errorf("%w: control authority must be an Ed25519 CA", ErrInvalidControlIdentity)
	}
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !publicKey.Equal(privateKey.Public()) {
		return nil, nil, fmt.Errorf("%w: control authority certificate and key differ", ErrInvalidControlIdentity)
	}
	return certificate, privateKey, nil
}

func decodeSinglePEM(data []byte, wantType string) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != wantType || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("expected one %s PEM block", wantType)
	}
	return block.Bytes, nil
}

func publicKeyID(publicKey ed25519.PublicKey) []byte {
	digest := sha256.Sum256(publicKey)
	return append([]byte(nil), digest[:20]...)
}

func certificateFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}
