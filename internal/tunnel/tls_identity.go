package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const (
	GatewayTLSCertificateRef      = model.SecretRef("tunnel-cert:server-g1")
	GatewayTLSPrivateKeyRef       = model.SecretRef("tunnel-key:server-g1")
	GatewayTLSCertificateValidity = 1825 * 24 * time.Hour
	GatewayTLSCertificateWarnDays = 180
	gatewayTLSSerialBytes         = 16
)

type GatewayTLSIdentitySecretStore interface {
	Get(model.SecretRef) ([]byte, error)
	PutIfAbsent(model.SecretRef, []byte) error
	Delete(model.SecretRef) (bool, error)
}

type GatewayTLSIdentityRuntime struct {
	Entropy io.Reader
	NewUUID model.UUIDGenerator
}

type GatewayTLSIdentityInstallation struct {
	Certificate     model.Certificate
	OwnedReferences []model.SecretRef
}

func (GatewayTLSIdentityInstallation) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type GatewayTLSIdentityProvisioner struct {
	secrets GatewayTLSIdentitySecretStore
	runtime GatewayTLSIdentityRuntime
}

func NewGatewayTLSIdentityProvisioner(secrets GatewayTLSIdentitySecretStore, runtime GatewayTLSIdentityRuntime) (*GatewayTLSIdentityProvisioner, error) {
	if secrets == nil {
		return nil, fmt.Errorf("gateway tunnel TLS secret store is required")
	}
	if runtime.Entropy == nil {
		runtime.Entropy = rand.Reader
	}
	if runtime.NewUUID == nil {
		runtime.NewUUID = model.NewUUID
	}
	return &GatewayTLSIdentityProvisioner{secrets: secrets, runtime: runtime}, nil
}

// Provision returns the existing validated tunnel identity or creates the
// first stable identity. New secret files remain caller-owned until the
// certificate record is committed into authoritative gateway state.
func (provisioner *GatewayTLSIdentityProvisioner) Provision(ctx context.Context, state model.State, issuedAt time.Time) (GatewayTLSIdentityInstallation, error) {
	if ctx == nil {
		return GatewayTLSIdentityInstallation{}, fmt.Errorf("context is required")
	}
	if provisioner == nil || provisioner.secrets == nil || provisioner.runtime.Entropy == nil || provisioner.runtime.NewUUID == nil {
		return GatewayTLSIdentityInstallation{}, fmt.Errorf("gateway tunnel TLS provisioner is incomplete")
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return GatewayTLSIdentityInstallation{}, fmt.Errorf("gateway tunnel TLS identity requires valid gateway state")
	}
	records := gatewayTLSCertificateRecords(state)
	if len(records) > 1 {
		return GatewayTLSIdentityInstallation{}, fmt.Errorf("gateway tunnel TLS identity is ambiguous")
	}
	if len(records) == 1 {
		if err := provisioner.validateStored(records[0], state.Host.ID, issuedAt); err != nil {
			return GatewayTLSIdentityInstallation{}, err
		}
		return GatewayTLSIdentityInstallation{Certificate: records[0], OwnedReferences: []model.SecretRef{}}, nil
	}
	select {
	case <-ctx.Done():
		return GatewayTLSIdentityInstallation{}, ctx.Err()
	default:
	}
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	if issuedAt.IsZero() || issuedAt.Before(state.Host.InitializedAt) {
		return GatewayTLSIdentityInstallation{}, fmt.Errorf("gateway tunnel TLS issuance time is invalid")
	}
	certificatePEM, privateKeyPEM, certificate, err := generateGatewayTLSIdentity(provisioner.runtime.Entropy, issuedAt)
	if err != nil {
		return GatewayTLSIdentityInstallation{}, err
	}
	defer clear(privateKeyPEM)
	occupied := make(map[string]struct{}, len(state.Certificates))
	for _, existing := range state.Certificates {
		occupied[existing.ID] = struct{}{}
	}
	certificateID, err := model.AllocateUUID(occupied, provisioner.runtime.NewUUID)
	if err != nil {
		return GatewayTLSIdentityInstallation{}, fmt.Errorf("allocate gateway tunnel TLS certificate identity: %w", err)
	}
	installation := GatewayTLSIdentityInstallation{OwnedReferences: []model.SecretRef{}}
	entries := []struct {
		reference model.SecretRef
		content   []byte
	}{
		{reference: GatewayTLSCertificateRef, content: certificatePEM},
		{reference: GatewayTLSPrivateKeyRef, content: privateKeyPEM},
	}
	for _, entry := range entries {
		if err := provisioner.secrets.PutIfAbsent(entry.reference, entry.content); err != nil {
			return GatewayTLSIdentityInstallation{}, errors.Join(
				fmt.Errorf("store gateway tunnel TLS identity: %w", err),
				provisioner.Rollback(context.Background(), installation),
			)
		}
		installation.OwnedReferences = append(installation.OwnedReferences, entry.reference)
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	installation.Certificate = model.Certificate{
		SchemaVersion:  model.ResourceSchemaVersion,
		ID:             certificateID,
		Kind:           model.CertificateTunnelServer,
		OwnerKind:      "host",
		OwnerID:        state.Host.ID,
		Fingerprint:    "sha256:" + hex.EncodeToString(fingerprint[:]),
		SerialHex:      certificate.SerialNumber.Text(16),
		Subject:        certificate.Subject.String(),
		SANs:           []string{"DNS:" + FRPTLSServerName},
		NotBefore:      certificate.NotBefore.UTC(),
		NotAfter:       certificate.NotAfter.UTC(),
		WarningDays:    GatewayTLSCertificateWarnDays,
		Generation:     1,
		CertificateRef: GatewayTLSCertificateRef.String(),
		PrivateKeyRef:  GatewayTLSPrivateKeyRef,
	}
	if err := installation.Certificate.Validate(); err != nil {
		return GatewayTLSIdentityInstallation{}, errors.Join(err, provisioner.Rollback(context.Background(), installation))
	}
	if err := ValidateGatewayTLSIdentity(certificatePEM, privateKeyPEM, installation.Certificate, state.Host.ID, issuedAt); err != nil {
		return GatewayTLSIdentityInstallation{}, errors.Join(err, provisioner.Rollback(context.Background(), installation))
	}
	return installation, nil
}

func (provisioner *GatewayTLSIdentityProvisioner) Rollback(ctx context.Context, installation GatewayTLSIdentityInstallation) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if provisioner == nil || provisioner.secrets == nil {
		return fmt.Errorf("gateway tunnel TLS provisioner is incomplete")
	}
	allowed := map[model.SecretRef]struct{}{GatewayTLSCertificateRef: {}, GatewayTLSPrivateKeyRef: {}}
	seen := make(map[model.SecretRef]struct{}, len(installation.OwnedReferences))
	for _, reference := range installation.OwnedReferences {
		if _, ok := allowed[reference]; !ok {
			return fmt.Errorf("refuse rollback of non-tunnel TLS identity reference %s", reference)
		}
		if _, duplicate := seen[reference]; duplicate {
			return fmt.Errorf("refuse duplicate tunnel TLS identity rollback reference %s", reference)
		}
		seen[reference] = struct{}{}
	}
	var failures []error
	for index := len(installation.OwnedReferences) - 1; index >= 0; index-- {
		if _, err := provisioner.secrets.Delete(installation.OwnedReferences[index]); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (provisioner *GatewayTLSIdentityProvisioner) validateStored(record model.Certificate, gatewayID string, now time.Time) error {
	certificatePEM, err := provisioner.secrets.Get(model.SecretRef(record.CertificateRef))
	if err != nil {
		return fmt.Errorf("read gateway tunnel TLS certificate: %w", err)
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := provisioner.secrets.Get(record.PrivateKeyRef)
	if err != nil {
		return fmt.Errorf("read gateway tunnel TLS private key: %w", err)
	}
	defer clear(privateKeyPEM)
	return ValidateGatewayTLSIdentity(certificatePEM, privateKeyPEM, record, gatewayID, now)
}

func ValidateGatewayTLSIdentity(certificatePEM, privateKeyPEM []byte, record model.Certificate, gatewayID string, now time.Time) error {
	if err := record.Validate(); err != nil || record.Kind != model.CertificateTunnelServer || record.OwnerKind != "host" || record.OwnerID != gatewayID ||
		record.Generation != 1 || record.CertificateRef != GatewayTLSCertificateRef.String() || record.PrivateKeyRef != GatewayTLSPrivateKeyRef ||
		len(record.SANs) != 1 || record.SANs[0] != "DNS:"+FRPTLSServerName {
		return fmt.Errorf("gateway tunnel TLS certificate metadata is invalid")
	}
	certificateBlock, rest := pem.Decode(certificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("gateway tunnel TLS certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse gateway tunnel TLS certificate: %w", err)
	}
	keyBlock, rest := pem.Decode(privateKeyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("gateway tunnel TLS private key PEM is invalid")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	privateKey, ok := parsedKey.(ed25519.PrivateKey)
	publicKey, publicOK := certificate.PublicKey.(ed25519.PublicKey)
	if err != nil || !ok || !publicOK || len(privateKey) != ed25519.PrivateKeySize || !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return fmt.Errorf("gateway tunnel TLS key pair is invalid")
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	now = now.UTC()
	if certificate.SignatureAlgorithm != x509.PureEd25519 || certificate.Subject.CommonName != FRPTLSServerName ||
		len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != FRPTLSServerName || len(certificate.IPAddresses) != 0 ||
		len(certificate.EmailAddresses) != 0 || len(certificate.URIs) != 0 || certificate.IsCA ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature || len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
		certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) != nil ||
		certificate.VerifyHostname(FRPTLSServerName) != nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) ||
		record.Fingerprint != "sha256:"+hex.EncodeToString(fingerprint[:]) || record.SerialHex != certificate.SerialNumber.Text(16) ||
		record.Subject != certificate.Subject.String() || !record.NotBefore.Equal(certificate.NotBefore.UTC()) || !record.NotAfter.Equal(certificate.NotAfter.UTC()) ||
		record.WarningDays != GatewayTLSCertificateWarnDays {
		return fmt.Errorf("gateway tunnel TLS certificate differs from its managed profile")
	}
	return nil
}

func generateGatewayTLSIdentity(entropy io.Reader, issuedAt time.Time) ([]byte, []byte, *x509.Certificate, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate gateway tunnel TLS key: %w", err)
	}
	serialBytes := make([]byte, gatewayTLSSerialBytes)
	if _, err := io.ReadFull(entropy, serialBytes); err != nil {
		return nil, nil, nil, fmt.Errorf("generate gateway tunnel TLS serial: %w", err)
	}
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)
	clear(serialBytes)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: FRPTLSServerName},
		NotBefore:    issuedAt,
		NotAfter:     issuedAt.Add(GatewayTLSCertificateValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{FRPTLSServerName},
	}
	certificateDER, err := x509.CreateCertificate(entropy, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create gateway tunnel TLS certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse generated gateway tunnel TLS certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal gateway tunnel TLS private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), certificate, nil
}

func gatewayTLSCertificateRecords(state model.State) []model.Certificate {
	result := make([]model.Certificate, 0, 1)
	for _, record := range state.Certificates {
		if record.Kind == model.CertificateTunnelServer {
			result = append(result, record)
		}
	}
	return result
}
