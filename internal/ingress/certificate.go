package ingress

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const (
	PublicCertificateValidity      = 1825 * 24 * time.Hour
	PublicCertificateWarningWindow = 180 * 24 * time.Hour
	PublicCertificateWarningDays   = 180
	PublicCertificateKeyBits       = 2048
	PublicCertificateRef           = "ingress-cert:public-g1"
	PublicCertificatePrivateKeyRef = model.SecretRef("ingress-key:public-g1")
	PublicCertificateExportName    = "gateway.crt"
	publicCertificateMaximumBytes  = 64 << 10
	publicCertificateSerialBytes   = 16
)

var (
	ErrPublicCertificateNotFound   = errors.New("public ingress certificate not found")
	ErrPublicCertificateInvalid    = errors.New("public ingress certificate is invalid")
	ErrPublicCertificateExported   = errors.New("public certificate export already exists")
	ErrPublicCertificateUnsafePath = errors.New("public certificate export path is unsafe")
)

type PublicCertificateRequest struct {
	GatewayID  string
	PublicIPv4 string
	IssuedAt   time.Time
}

type PublicCertificateMaterial struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Certificate    *x509.Certificate
}

func (PublicCertificateMaterial) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type PublicCertificateInstallation struct {
	Certificate     model.Certificate
	OwnedReferences []model.SecretRef
}

func (PublicCertificateInstallation) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type PublicCertificateSecretStore interface {
	PutIfAbsent(model.SecretRef, []byte) error
	Get(model.SecretRef) ([]byte, error)
	Delete(model.SecretRef) (bool, error)
}

type PublicCertificateRuntime struct {
	Entropy io.Reader
	NewUUID model.UUIDGenerator
}

type PublicCertificateProvisioner struct {
	secrets PublicCertificateSecretStore
	runtime PublicCertificateRuntime
}

func NewPublicCertificateProvisioner(secrets PublicCertificateSecretStore, runtime PublicCertificateRuntime) (*PublicCertificateProvisioner, error) {
	if secrets == nil {
		return nil, fmt.Errorf("public certificate secret store is required")
	}
	if runtime.Entropy == nil {
		runtime.Entropy = rand.Reader
	}
	if runtime.NewUUID == nil {
		runtime.NewUUID = model.NewUUID
	}
	return &PublicCertificateProvisioner{secrets: secrets, runtime: runtime}, nil
}

func GeneratePublicCertificate(entropy io.Reader, publicIPv4 string, issuedAt time.Time) (PublicCertificateMaterial, error) {
	if entropy == nil {
		return PublicCertificateMaterial{}, fmt.Errorf("entropy source is required")
	}
	address, err := canonicalPublicCertificateIPv4(publicIPv4)
	if err != nil {
		return PublicCertificateMaterial{}, err
	}
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	if issuedAt.IsZero() {
		return PublicCertificateMaterial{}, fmt.Errorf("%w: issuance time is required", ErrPublicCertificateInvalid)
	}
	privateKey, err := rsa.GenerateKey(entropy, PublicCertificateKeyBits)
	if err != nil {
		return PublicCertificateMaterial{}, fmt.Errorf("generate public ingress RSA key: %w", err)
	}
	serial, err := publicCertificateSerial(entropy)
	if err != nil {
		return PublicCertificateMaterial{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: publicIPv4},
		NotBefore:             issuedAt,
		NotAfter:              issuedAt.Add(PublicCertificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IP(address.AsSlice())},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	certificateDER, err := x509.CreateCertificate(entropy, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return PublicCertificateMaterial{}, fmt.Errorf("create public ingress certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return PublicCertificateMaterial{}, fmt.Errorf("parse created public ingress certificate: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return PublicCertificateMaterial{}, fmt.Errorf("marshal public ingress private key: %w", err)
	}
	return PublicCertificateMaterial{
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		Certificate:    certificate,
	}, nil
}

func (provisioner *PublicCertificateProvisioner) Provision(ctx context.Context, request PublicCertificateRequest) (PublicCertificateInstallation, error) {
	if ctx == nil {
		return PublicCertificateInstallation{}, fmt.Errorf("context is required")
	}
	if provisioner == nil || provisioner.secrets == nil || provisioner.runtime.Entropy == nil || provisioner.runtime.NewUUID == nil {
		return PublicCertificateInstallation{}, fmt.Errorf("public certificate provisioner is incomplete")
	}
	select {
	case <-ctx.Done():
		return PublicCertificateInstallation{}, ctx.Err()
	default:
	}
	if _, err := canonicalPublicCertificateIPv4(request.PublicIPv4); err != nil {
		return PublicCertificateInstallation{}, err
	}
	if err := validateGatewayID(request.GatewayID); err != nil {
		return PublicCertificateInstallation{}, err
	}
	material, err := GeneratePublicCertificate(provisioner.runtime.Entropy, request.PublicIPv4, request.IssuedAt)
	if err != nil {
		return PublicCertificateInstallation{}, err
	}
	defer clear(material.PrivateKeyPEM)
	certificateID, err := model.AllocateUUID(nil, provisioner.runtime.NewUUID)
	if err != nil {
		return PublicCertificateInstallation{}, fmt.Errorf("allocate public ingress certificate identity: %w", err)
	}
	certificateRef, privateKeyRef, err := PublicCertificateReferences(1)
	if err != nil {
		return PublicCertificateInstallation{}, err
	}
	installation := PublicCertificateInstallation{OwnedReferences: []model.SecretRef{}}
	entries := []struct {
		reference model.SecretRef
		content   []byte
	}{
		{reference: model.SecretRef(certificateRef), content: material.CertificatePEM},
		{reference: privateKeyRef, content: material.PrivateKeyPEM},
	}
	for _, entry := range entries {
		if err := provisioner.secrets.PutIfAbsent(entry.reference, entry.content); err != nil {
			rollbackErr := provisioner.Rollback(context.Background(), installation)
			return PublicCertificateInstallation{}, errors.Join(fmt.Errorf("store public ingress identity: %w", err), rollbackErr)
		}
		installation.OwnedReferences = append(installation.OwnedReferences, entry.reference)
	}
	certificate := material.Certificate
	fingerprint := sha256.Sum256(certificate.Raw)
	installation.Certificate = model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion,
		ID:            certificateID, Kind: model.CertificatePublicIngress,
		OwnerKind: "host", OwnerID: request.GatewayID,
		Fingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]),
		SerialHex:   certificate.SerialNumber.Text(16), Subject: certificate.Subject.String(),
		SANs:      []string{"IP:" + request.PublicIPv4},
		NotBefore: certificate.NotBefore.UTC(), NotAfter: certificate.NotAfter.UTC(),
		WarningDays: PublicCertificateWarningDays, Generation: 1,
		CertificateRef: certificateRef, PrivateKeyRef: privateKeyRef,
	}
	if err := installation.Certificate.Validate(); err != nil {
		rollbackErr := provisioner.Rollback(context.Background(), installation)
		return PublicCertificateInstallation{}, errors.Join(fmt.Errorf("build public ingress certificate metadata: %w", err), rollbackErr)
	}
	if err := validatePublicCertificateRecord(installation.Certificate, request.GatewayID, request.PublicIPv4); err != nil {
		rollbackErr := provisioner.Rollback(context.Background(), installation)
		return PublicCertificateInstallation{}, errors.Join(err, rollbackErr)
	}
	return installation, nil
}

func (provisioner *PublicCertificateProvisioner) Rollback(ctx context.Context, installation PublicCertificateInstallation) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if provisioner == nil || provisioner.secrets == nil {
		return fmt.Errorf("public certificate provisioner is incomplete")
	}
	seen := make(map[model.SecretRef]struct{}, len(installation.OwnedReferences))
	for _, reference := range installation.OwnedReferences {
		if !isPublicCertificateGenerationReference(reference) {
			return fmt.Errorf("refuse rollback of non-ingress identity reference %s", reference)
		}
		if _, duplicate := seen[reference]; duplicate {
			return fmt.Errorf("refuse duplicate ingress identity rollback reference %s", reference)
		}
		seen[reference] = struct{}{}
	}
	var rollbackErrors []error
	for index := len(installation.OwnedReferences) - 1; index >= 0; index-- {
		if _, err := provisioner.secrets.Delete(installation.OwnedReferences[index]); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("delete public ingress identity %s: %w", installation.OwnedReferences[index], err))
		}
	}
	return errors.Join(rollbackErrors...)
}

type PublicCertificateCondition string

const (
	PublicCertificateHealthy  PublicCertificateCondition = "healthy"
	PublicCertificateExpiring PublicCertificateCondition = "expiring"
	PublicCertificateExpired  PublicCertificateCondition = "expired"
)

type PublicCertificateStatus struct {
	PublicIPv4      string
	CertificateID   string
	Fingerprint     string
	SerialHex       string
	Subject         string
	SANs            []string
	NotBefore       time.Time
	NotAfter        time.Time
	WarningStartsAt time.Time
	WarningDays     int
	Generation      uint64
	Condition       PublicCertificateCondition
}

func InspectPublicCertificate(state model.State, now time.Time) (PublicCertificateStatus, error) {
	if err := state.Validate(); err != nil {
		return PublicCertificateStatus{}, fmt.Errorf("validate public certificate state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return PublicCertificateStatus{}, fmt.Errorf("%w: certificate belongs only to a gateway", ErrPublicCertificateInvalid)
	}
	record, err := publicCertificateRecord(state)
	if err != nil {
		return PublicCertificateStatus{}, err
	}
	if err := validatePublicCertificateRecord(record, state.Host.ID, state.Host.PublicIPv4); err != nil {
		return PublicCertificateStatus{}, err
	}
	now = now.UTC()
	if now.IsZero() {
		return PublicCertificateStatus{}, fmt.Errorf("%w: inspection time is required", ErrPublicCertificateInvalid)
	}
	warningStartsAt := record.NotAfter.Add(-PublicCertificateWarningWindow)
	condition := PublicCertificateHealthy
	if !now.Before(record.NotAfter) {
		condition = PublicCertificateExpired
	} else if !now.Before(warningStartsAt) {
		condition = PublicCertificateExpiring
	}
	return PublicCertificateStatus{
		PublicIPv4: state.Host.PublicIPv4, CertificateID: record.ID,
		Fingerprint: record.Fingerprint, SerialHex: record.SerialHex, Subject: record.Subject,
		SANs: append([]string(nil), record.SANs...), NotBefore: record.NotBefore, NotAfter: record.NotAfter,
		WarningStartsAt: warningStartsAt, WarningDays: record.WarningDays,
		Generation: record.Generation, Condition: condition,
	}, nil
}

type PublicCertificateExport struct {
	Path        string
	Fingerprint string
	Changed     bool
}

func DefaultPublicCertificateExportPath(exportsDirectory string) string {
	return filepath.Join(exportsDirectory, PublicCertificateExportName)
}

// PublicCertificateReferences binds public ingress material to its logical
// certificate generation. Generation one preserves the v2 bootstrap paths;
// later rotations can be staged without overwriting the active identity.
func PublicCertificateReferences(generation uint64) (string, model.SecretRef, error) {
	if generation == 0 {
		return "", "", fmt.Errorf("public certificate generation must be positive")
	}
	suffix := strconv.FormatUint(generation, 10)
	certificate := "ingress-cert:public-g" + suffix
	privateKey := model.SecretRef("ingress-key:public-g" + suffix)
	if _, _, err := model.SecretRef(certificate).Parts(); err != nil {
		return "", "", err
	}
	if _, _, err := privateKey.Parts(); err != nil {
		return "", "", err
	}
	return certificate, privateKey, nil
}

func ExportPublicCertificate(state model.State, secrets PublicCertificateSecretStore, destination string) (PublicCertificateExport, error) {
	if secrets == nil {
		return PublicCertificateExport{}, fmt.Errorf("public certificate source is required")
	}
	if destination == "" || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return PublicCertificateExport{}, fmt.Errorf("%w: destination must be a clean absolute path", ErrPublicCertificateUnsafePath)
	}
	status, err := InspectPublicCertificate(state, time.Now())
	if err != nil {
		return PublicCertificateExport{}, err
	}
	record, _ := publicCertificateRecord(state)
	certificatePEM, err := secrets.Get(model.SecretRef(record.CertificateRef))
	if err != nil {
		return PublicCertificateExport{}, fmt.Errorf("read public ingress certificate: %w", err)
	}
	defer clear(certificatePEM)
	if _, err := ValidatePublicCertificatePEM(certificatePEM, record, state.Host.PublicIPv4); err != nil {
		return PublicCertificateExport{}, err
	}
	changed, err := writePublicCertificateNoReplace(destination, certificatePEM)
	if err != nil {
		return PublicCertificateExport{}, err
	}
	return PublicCertificateExport{Path: destination, Fingerprint: status.Fingerprint, Changed: changed}, nil
}

// PublicCertificateExportAvailable performs the read-only half of export. It
// reports true only when the exact current public certificate already exists
// at the requested regular-file destination. A missing file is normal; an
// unsafe or stale file is surfaced as drift instead of being overwritten.
func PublicCertificateExportAvailable(state model.State, secrets PublicCertificateSecretStore, destination string) (bool, error) {
	if secrets == nil {
		return false, fmt.Errorf("public certificate source is required")
	}
	if destination == "" || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return false, fmt.Errorf("%w: destination must be a clean absolute path", ErrPublicCertificateUnsafePath)
	}
	record, err := publicCertificateRecord(state)
	if err != nil {
		return false, err
	}
	certificatePEM, err := secrets.Get(model.SecretRef(record.CertificateRef))
	if err != nil {
		return false, fmt.Errorf("read public ingress certificate: %w", err)
	}
	defer clear(certificatePEM)
	if _, err := ValidatePublicCertificatePEM(certificatePEM, record, state.Host.PublicIPv4); err != nil {
		return false, err
	}
	info, err := os.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect public certificate export: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%w: destination is not a regular file", ErrPublicCertificateUnsafePath)
	}
	if info.Size() < 1 || info.Size() > publicCertificateMaximumBytes {
		return false, fmt.Errorf("%w: destination has an invalid size", ErrPublicCertificateExported)
	}
	existing, err := os.ReadFile(destination)
	if err != nil {
		return false, fmt.Errorf("read existing public certificate export: %w", err)
	}
	if !bytes.Equal(existing, certificatePEM) {
		return false, fmt.Errorf("%w: %s", ErrPublicCertificateExported, destination)
	}
	return true, nil
}

func ValidatePublicCertificatePEM(certificatePEM []byte, record model.Certificate, publicIPv4 string) (*x509.Certificate, error) {
	if len(certificatePEM) == 0 || len(certificatePEM) > publicCertificateMaximumBytes || bytes.Contains(certificatePEM, []byte("PRIVATE KEY")) {
		return nil, fmt.Errorf("%w: public PEM shape is invalid", ErrPublicCertificateInvalid)
	}
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: exactly one PEM certificate is required", ErrPublicCertificateInvalid)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse public PEM: %v", ErrPublicCertificateInvalid, err)
	}
	address, err := canonicalPublicCertificateIPv4(publicIPv4)
	if err != nil {
		return nil, err
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() != PublicCertificateKeyBits || publicKey.E != 65537 {
		return nil, fmt.Errorf("%w: RSA-2048 public key is required", ErrPublicCertificateInvalid)
	}
	if certificate.SignatureAlgorithm != x509.SHA256WithRSA || certificate.Subject.CommonName != publicIPv4 ||
		len(certificate.IPAddresses) != 1 || !certificate.IPAddresses[0].Equal(net.IP(address.AsSlice())) ||
		len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 || len(certificate.URIs) != 0 ||
		certificate.NotAfter.Sub(certificate.NotBefore) != PublicCertificateValidity || certificate.IsCA ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return nil, fmt.Errorf("%w: certificate shape differs from the public ingress contract", ErrPublicCertificateInvalid)
	}
	if err := certificate.VerifyHostname(publicIPv4); err != nil {
		return nil, fmt.Errorf("%w: IPv4 SAN verification failed", ErrPublicCertificateInvalid)
	}
	if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
		return nil, fmt.Errorf("%w: self-signature verification failed", ErrPublicCertificateInvalid)
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	if record.Kind != model.CertificatePublicIngress || record.Fingerprint != "sha256:"+hex.EncodeToString(fingerprint[:]) ||
		record.SerialHex != certificate.SerialNumber.Text(16) || record.Subject != certificate.Subject.String() ||
		!record.NotBefore.Equal(certificate.NotBefore) || !record.NotAfter.Equal(certificate.NotAfter) ||
		len(record.SANs) != 1 || record.SANs[0] != "IP:"+publicIPv4 {
		return nil, fmt.Errorf("%w: PEM differs from authoritative metadata", ErrPublicCertificateInvalid)
	}
	return certificate, nil
}

func publicCertificateRecord(state model.State) (model.Certificate, error) {
	var result model.Certificate
	found := false
	for _, certificate := range state.Certificates {
		if certificate.Kind != model.CertificatePublicIngress {
			continue
		}
		if found {
			return model.Certificate{}, fmt.Errorf("%w: multiple public ingress certificates are active", ErrPublicCertificateInvalid)
		}
		result = certificate
		found = true
	}
	if !found {
		return model.Certificate{}, ErrPublicCertificateNotFound
	}
	return result, nil
}

func validatePublicCertificateRecord(record model.Certificate, gatewayID, publicIPv4 string) error {
	if err := record.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrPublicCertificateInvalid, err)
	}
	if _, err := canonicalPublicCertificateIPv4(publicIPv4); err != nil {
		return err
	}
	certificateRef, privateKeyRef, referenceErr := PublicCertificateReferences(record.Generation)
	if referenceErr != nil || record.Kind != model.CertificatePublicIngress || record.OwnerKind != "host" || record.OwnerID != gatewayID ||
		record.Subject != "CN="+publicIPv4 || len(record.SANs) != 1 || record.SANs[0] != "IP:"+publicIPv4 ||
		record.NotAfter.Sub(record.NotBefore) != PublicCertificateValidity || record.WarningDays != PublicCertificateWarningDays ||
		record.Generation == 0 || record.CertificateRef != certificateRef || record.PrivateKeyRef != privateKeyRef {
		return fmt.Errorf("%w: authoritative metadata differs from ingress certificate contract", ErrPublicCertificateInvalid)
	}
	return nil
}

func isPublicCertificateGenerationReference(reference model.SecretRef) bool {
	kind, id, err := reference.Parts()
	if err != nil || kind != "ingress-cert" && kind != "ingress-key" || !strings.HasPrefix(id, "public-g") {
		return false
	}
	generation, err := strconv.ParseUint(strings.TrimPrefix(id, "public-g"), 10, 64)
	return err == nil && generation > 0 && strconv.FormatUint(generation, 10) == strings.TrimPrefix(id, "public-g")
}

func writePublicCertificateNoReplace(destination string, content []byte) (bool, error) {
	if info, err := os.Lstat(destination); err == nil {
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("%w: destination is not a regular file", ErrPublicCertificateUnsafePath)
		}
		existing, err := os.ReadFile(destination)
		if err != nil {
			return false, fmt.Errorf("read existing public certificate export: %w", err)
		}
		if bytes.Equal(existing, content) {
			return false, nil
		}
		return false, fmt.Errorf("%w: %s", ErrPublicCertificateExported, destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect public certificate export: %w", err)
	}
	directory := filepath.Dir(destination)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() {
		return false, fmt.Errorf("%w: destination directory is unavailable", ErrPublicCertificateUnsafePath)
	}
	temporary, err := os.CreateTemp(directory, ".gateway.crt.")
	if err != nil {
		return false, fmt.Errorf("create public certificate export candidate: %w", err)
	}
	temporaryPath := temporary.Name()
	keepTemporary := true
	defer func() {
		_ = temporary.Close()
		if keepTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return false, fmt.Errorf("set public certificate export mode: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return false, fmt.Errorf("write public certificate export: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return false, fmt.Errorf("sync public certificate export: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("close public certificate export: %w", err)
	}
	if err := os.Link(temporaryPath, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, fmt.Errorf("%w: %s", ErrPublicCertificateExported, destination)
		}
		return false, fmt.Errorf("activate public certificate export: %w", err)
	}
	if err := syncPublicCertificateDirectory(directory); err != nil {
		_ = os.Remove(destination)
		return false, err
	}
	if err := os.Remove(temporaryPath); err != nil {
		_ = os.Remove(destination)
		return false, fmt.Errorf("remove public certificate export candidate: %w", err)
	}
	keepTemporary = false
	if err := syncPublicCertificateDirectory(directory); err != nil {
		return false, err
	}
	return true, nil
}

func syncPublicCertificateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open public certificate export directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync public certificate export directory: %w", err)
	}
	return nil
}

func canonicalPublicCertificateIPv4(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.String() != value || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return netip.Addr{}, fmt.Errorf("%w: public identity must be canonical non-local IPv4", ErrPublicCertificateInvalid)
	}
	return address, nil
}

func validateGatewayID(value string) error {
	if len(value) != 36 {
		return fmt.Errorf("%w: gateway ID must be a canonical UUID", ErrPublicCertificateInvalid)
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return fmt.Errorf("%w: gateway ID must be a canonical UUID", ErrPublicCertificateInvalid)
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", character) {
			return fmt.Errorf("%w: gateway ID must be a canonical UUID", ErrPublicCertificateInvalid)
		}
	}
	return nil
}

func publicCertificateSerial(entropy io.Reader) (*big.Int, error) {
	buffer := make([]byte, publicCertificateSerialBytes)
	for attempt := 0; attempt < 32; attempt++ {
		if _, err := io.ReadFull(entropy, buffer); err != nil {
			return nil, fmt.Errorf("generate public ingress certificate serial: %w", err)
		}
		serial := new(big.Int).SetBytes(buffer)
		if serial.Sign() > 0 {
			return serial, nil
		}
	}
	return nil, fmt.Errorf("generate non-zero public ingress certificate serial")
}
