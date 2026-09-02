package control

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	ControlCACertificateRef      = "control-cert:ca"
	ControlCAPrivateKeyRef       = model.SecretRef("control-key:ca")
	GatewayControlCertificateRef = "control-cert:gateway"
	GatewayControlPrivateKeyRef  = model.SecretRef("control-key:gateway")
	EnrollmentPublicKeyRef       = "enrollment-public:gateway"
	EnrollmentPrivateKeyRef      = model.SecretRef("enrollment-key:gateway")
)

type GatewayIdentityRequest struct {
	GatewayID   string
	NodeCIDR    string
	Initialized time.Time
}

type GatewayIdentityInstallation struct {
	Certificates       []model.Certificate
	EnrollmentIdentity model.EnrollmentIdentity
	OwnedReferences    []model.SecretRef
}

type GatewayIdentitySecretStore interface {
	PutIfAbsent(model.SecretRef, []byte) error
	Delete(model.SecretRef) (bool, error)
}

type GatewayIdentityRuntime struct {
	Entropy io.Reader
	NewUUID model.UUIDGenerator
}

type GatewayIdentityProvisioner struct {
	secrets GatewayIdentitySecretStore
	runtime GatewayIdentityRuntime
}

func NewGatewayIdentityProvisioner(secrets GatewayIdentitySecretStore, runtime GatewayIdentityRuntime) (*GatewayIdentityProvisioner, error) {
	if secrets == nil {
		return nil, fmt.Errorf("gateway identity secret store is required")
	}
	if runtime.Entropy == nil {
		runtime.Entropy = rand.Reader
	}
	if runtime.NewUUID == nil {
		runtime.NewUUID = model.NewUUID
	}
	return &GatewayIdentityProvisioner{secrets: secrets, runtime: runtime}, nil
}

func (provisioner *GatewayIdentityProvisioner) Provision(ctx context.Context, request GatewayIdentityRequest) (GatewayIdentityInstallation, error) {
	if ctx == nil {
		return GatewayIdentityInstallation{}, fmt.Errorf("context is required")
	}
	if provisioner == nil || provisioner.secrets == nil || provisioner.runtime.Entropy == nil || provisioner.runtime.NewUUID == nil {
		return GatewayIdentityInstallation{}, fmt.Errorf("gateway identity provisioner is incomplete")
	}
	select {
	case <-ctx.Done():
		return GatewayIdentityInstallation{}, ctx.Err()
	default:
	}
	overlayIPv4, err := GatewayOverlayIPv4(request.NodeCIDR)
	if err != nil {
		return GatewayIdentityInstallation{}, err
	}
	material, err := GenerateGatewayControlMaterial(provisioner.runtime.Entropy, request.GatewayID, overlayIPv4, request.Initialized)
	if err != nil {
		return GatewayIdentityInstallation{}, err
	}
	occupied := make(map[string]struct{}, 2)
	caID, err := model.AllocateUUID(occupied, provisioner.runtime.NewUUID)
	if err != nil {
		return GatewayIdentityInstallation{}, fmt.Errorf("allocate control CA identity: %w", err)
	}
	gatewayCertificateID, err := model.AllocateUUID(occupied, provisioner.runtime.NewUUID)
	if err != nil {
		return GatewayIdentityInstallation{}, fmt.Errorf("allocate gateway control certificate identity: %w", err)
	}

	entries := []struct {
		reference model.SecretRef
		content   []byte
	}{
		{reference: model.SecretRef(ControlCACertificateRef), content: material.ControlCACertificatePEM},
		{reference: ControlCAPrivateKeyRef, content: material.ControlCAPrivateKeyPEM},
		{reference: model.SecretRef(GatewayControlCertificateRef), content: material.GatewayCertificatePEM},
		{reference: GatewayControlPrivateKeyRef, content: material.GatewayPrivateKeyPEM},
		{reference: model.SecretRef(EnrollmentPublicKeyRef), content: material.EnrollmentPublicKeyPEM},
		{reference: EnrollmentPrivateKeyRef, content: material.EnrollmentPrivateKeyPEM},
	}
	installation := GatewayIdentityInstallation{OwnedReferences: []model.SecretRef{}}
	for _, entry := range entries {
		if err := provisioner.secrets.PutIfAbsent(entry.reference, entry.content); err != nil {
			rollbackErr := provisioner.Rollback(context.Background(), installation)
			return GatewayIdentityInstallation{}, errors.Join(fmt.Errorf("store gateway control identity: %w", err), rollbackErr)
		}
		installation.OwnedReferences = append(installation.OwnedReferences, entry.reference)
	}

	issuedAt := request.Initialized.UTC().Truncate(time.Second)
	installation.Certificates = []model.Certificate{
		certificateRecord(caID, model.CertificateControlCA, request.GatewayID, material.controlCA, ControlCACertificateRef, ControlCAPrivateKeyRef, []string{}),
		certificateRecord(gatewayCertificateID, model.CertificateControlServer, request.GatewayID, material.gatewayCertificate, GatewayControlCertificateRef, GatewayControlPrivateKeyRef, []string{"IP:" + overlayIPv4, "urn:vpnctl:gateway:" + request.GatewayID}),
	}
	installation.EnrollmentIdentity = model.EnrollmentIdentity{
		SchemaVersion: model.ResourceSchemaVersion,
		Algorithm:     "Ed25519",
		Fingerprint:   material.EnrollmentFingerprint,
		PublicKeyRef:  EnrollmentPublicKeyRef,
		PrivateKeyRef: EnrollmentPrivateKeyRef,
		Generation:    1,
		CreatedAt:     issuedAt,
	}
	for _, certificate := range installation.Certificates {
		if err := certificate.Validate(); err != nil {
			rollbackErr := provisioner.Rollback(context.Background(), installation)
			return GatewayIdentityInstallation{}, errors.Join(fmt.Errorf("build control certificate metadata: %w", err), rollbackErr)
		}
	}
	if err := installation.EnrollmentIdentity.Validate(); err != nil {
		rollbackErr := provisioner.Rollback(context.Background(), installation)
		return GatewayIdentityInstallation{}, errors.Join(fmt.Errorf("build enrollment identity metadata: %w", err), rollbackErr)
	}
	return installation, nil
}

func (provisioner *GatewayIdentityProvisioner) Rollback(ctx context.Context, installation GatewayIdentityInstallation) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if provisioner == nil || provisioner.secrets == nil {
		return fmt.Errorf("gateway identity provisioner is incomplete")
	}
	allowed := gatewayIdentityReferenceSet()
	seen := make(map[model.SecretRef]struct{}, len(installation.OwnedReferences))
	for _, reference := range installation.OwnedReferences {
		if _, ok := allowed[reference]; !ok {
			return fmt.Errorf("refuse rollback of non-control identity reference %s", reference)
		}
		if _, duplicate := seen[reference]; duplicate {
			return fmt.Errorf("refuse duplicate control identity rollback reference %s", reference)
		}
		seen[reference] = struct{}{}
	}
	var rollbackErrors []error
	for index := len(installation.OwnedReferences) - 1; index >= 0; index-- {
		reference := installation.OwnedReferences[index]
		if _, err := provisioner.secrets.Delete(reference); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("delete control identity %s: %w", reference, err))
		}
	}
	return errors.Join(rollbackErrors...)
}

func certificateRecord(id string, kind model.CertificateKind, ownerID string, certificate *x509.Certificate, certificateRef string, privateKeyRef model.SecretRef, sans []string) model.Certificate {
	return model.Certificate{
		SchemaVersion:  model.ResourceSchemaVersion,
		ID:             id,
		Kind:           kind,
		OwnerKind:      "host",
		OwnerID:        ownerID,
		Fingerprint:    certificateFingerprint(certificate),
		SerialHex:      certificate.SerialNumber.Text(16),
		Subject:        certificate.Subject.String(),
		SANs:           sortedStrings(sans),
		NotBefore:      certificate.NotBefore.UTC(),
		NotAfter:       certificate.NotAfter.UTC(),
		WarningDays:    ControlWarningDays,
		Generation:     1,
		CertificateRef: certificateRef,
		PrivateKeyRef:  privateKeyRef,
	}
}

func gatewayIdentityReferenceSet() map[model.SecretRef]struct{} {
	references := []model.SecretRef{
		model.SecretRef(ControlCACertificateRef), ControlCAPrivateKeyRef,
		model.SecretRef(GatewayControlCertificateRef), GatewayControlPrivateKeyRef,
		model.SecretRef(EnrollmentPublicKeyRef), EnrollmentPrivateKeyRef,
	}
	result := make(map[model.SecretRef]struct{}, len(references))
	for _, reference := range references {
		result[reference] = struct{}{}
	}
	return result
}

func sortedStrings(values []string) []string {
	result := make([]string, len(values))
	copy(result, values)
	sort.Strings(result)
	return result
}
