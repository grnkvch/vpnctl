package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

const GatewayControlLeafCheckInterval = 24 * time.Hour

type GatewayControlRenewalSecretStore interface {
	Get(model.SecretRef) ([]byte, error)
	PutIfAbsent(model.SecretRef, []byte) error
	Delete(model.SecretRef) (bool, error)
}

type GatewayControlLeafPreparer interface {
	PrepareGatewayControlLeaf([]byte, []byte, time.Time) (control.GatewayControlLeafActivation, error)
}

type GatewayControlLeafRenewalRuntime struct {
	Entropy       io.Reader
	NewUUID       model.UUIDGenerator
	CheckInterval time.Duration
	After         func(time.Duration) <-chan time.Time
}

type GatewayControlLeafRenewalResult struct {
	Changed               bool
	StateGeneration       uint64
	CertificateGeneration uint64
	PreviousFingerprint   string
	CurrentFingerprint    string
}

type GatewayControlLeafRenewer struct {
	controller *Controller
	secrets    GatewayControlRenewalSecretStore
	preparer   GatewayControlLeafPreparer
	runtime    GatewayControlLeafRenewalRuntime
}

func (controller *Controller) NewGatewayControlLeafRenewer(secrets GatewayControlRenewalSecretStore, preparer GatewayControlLeafPreparer, runtime GatewayControlLeafRenewalRuntime) (*GatewayControlLeafRenewer, error) {
	if controller == nil || controller.runtime.State == nil {
		return nil, fmt.Errorf("gateway controller is required")
	}
	if secrets == nil || preparer == nil {
		return nil, fmt.Errorf("gateway control renewal dependencies are incomplete")
	}
	if runtime.Entropy == nil {
		runtime.Entropy = rand.Reader
	}
	if runtime.NewUUID == nil {
		runtime.NewUUID = model.NewUUID
	}
	if runtime.CheckInterval == 0 {
		runtime.CheckInterval = GatewayControlLeafCheckInterval
	}
	if runtime.CheckInterval <= 0 {
		return nil, fmt.Errorf("gateway control renewal check interval must be positive")
	}
	if runtime.After == nil {
		runtime.After = time.After
	}
	return &GatewayControlLeafRenewer{controller: controller, secrets: secrets, preparer: preparer, runtime: runtime}, nil
}

// Run performs an immediate check and continues checking without requiring an
// operator command. A failed cycle exits so the controller service supervisor
// can retry; it never starts, stops, or restarts a data-plane unit.
func (renewer *GatewayControlLeafRenewer) Run(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if renewer == nil || renewer.controller == nil || renewer.runtime.After == nil {
		return fmt.Errorf("gateway control leaf renewer is incomplete")
	}
	for {
		if _, err := renewer.RenewIfNeeded(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-renewer.runtime.After(renewer.runtime.CheckInterval):
		}
	}
}

func (renewer *GatewayControlLeafRenewer) RenewIfNeeded(ctx context.Context) (GatewayControlLeafRenewalResult, error) {
	if ctx == nil {
		return GatewayControlLeafRenewalResult{}, fmt.Errorf("context is required")
	}
	if renewer == nil || renewer.controller == nil || renewer.secrets == nil || renewer.preparer == nil ||
		renewer.runtime.Entropy == nil || renewer.runtime.NewUUID == nil {
		return GatewayControlLeafRenewalResult{}, fmt.Errorf("gateway control leaf renewer is incomplete")
	}
	renewer.controller.mutationMu.Lock()
	defer renewer.controller.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return GatewayControlLeafRenewalResult{}, err
	}
	state, err := renewer.controller.runtime.State.Load()
	if err != nil {
		return GatewayControlLeafRenewalResult{}, fmt.Errorf("load authoritative gateway state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return GatewayControlLeafRenewalResult{}, fmt.Errorf("control leaf renewal requires gateway state")
	}
	caIndex, leafIndex, err := gatewayControlCertificateIndexes(state)
	if err != nil {
		return GatewayControlLeafRenewalResult{}, err
	}
	current := state.Certificates[leafIndex]
	result := GatewayControlLeafRenewalResult{
		StateGeneration: state.Generation, CertificateGeneration: current.Generation,
		PreviousFingerprint: current.Fingerprint, CurrentFingerprint: current.Fingerprint,
	}
	now := renewer.controller.runtime.Now().UTC().Truncate(time.Second)
	if current.NotAfter.After(now.Add(control.ControlRenewalWindow)) {
		return result, nil
	}

	authority := state.Certificates[caIndex]
	authorityCertificatePEM, err := renewer.secrets.Get(model.SecretRef(authority.CertificateRef))
	if err != nil {
		return GatewayControlLeafRenewalResult{}, fmt.Errorf("read control CA certificate: %w", err)
	}
	authorityPrivateKeyPEM, err := renewer.secrets.Get(authority.PrivateKeyRef)
	if err != nil {
		return GatewayControlLeafRenewalResult{}, fmt.Errorf("read control CA private key: %w", err)
	}
	overlayIPv4, err := control.GatewayOverlayIPv4(state.Host.NodeCIDR)
	if err != nil {
		return GatewayControlLeafRenewalResult{}, err
	}
	issued, err := control.IssueGatewayControlCertificate(
		renewer.runtime.Entropy, authorityCertificatePEM, authorityPrivateKeyPEM,
		state.Host.ID, overlayIPv4, now,
	)
	if err != nil {
		return GatewayControlLeafRenewalResult{}, err
	}
	nextCertificateGeneration, err := model.NextGeneration(current.Generation)
	if err != nil {
		return GatewayControlLeafRenewalResult{}, fmt.Errorf("gateway control certificate %w", err)
	}
	nextStateGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return GatewayControlLeafRenewalResult{}, fmt.Errorf("gateway state %w", err)
	}
	referenceID, err := model.AllocateUUID(nil, renewer.runtime.NewUUID)
	if err != nil {
		return GatewayControlLeafRenewalResult{}, fmt.Errorf("allocate renewed control leaf reference: %w", err)
	}
	certificateRef := model.SecretRef("control-cert:" + referenceID)
	privateKeyRef := model.SecretRef("control-key:" + referenceID)
	staged := []model.SecretRef{}
	cleanup := func() error {
		var cleanupErrors []error
		for index := len(staged) - 1; index >= 0; index-- {
			if _, err := renewer.secrets.Delete(staged[index]); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("delete staged renewal secret %s: %w", staged[index], err))
			}
		}
		return errors.Join(cleanupErrors...)
	}
	if err := renewer.secrets.PutIfAbsent(certificateRef, issued.CertificatePEM); err != nil {
		return GatewayControlLeafRenewalResult{}, fmt.Errorf("stage renewed control certificate: %w", err)
	}
	staged = append(staged, certificateRef)
	if err := renewer.secrets.PutIfAbsent(privateKeyRef, issued.PrivateKeyPEM); err != nil {
		return GatewayControlLeafRenewalResult{}, errors.Join(fmt.Errorf("stage renewed control private key: %w", err), cleanup())
	}
	staged = append(staged, privateKeyRef)
	if err := ctx.Err(); err != nil {
		return GatewayControlLeafRenewalResult{}, errors.Join(err, cleanup())
	}
	activation, err := renewer.preparer.PrepareGatewayControlLeaf(issued.CertificatePEM, issued.PrivateKeyPEM, now)
	if err != nil {
		return GatewayControlLeafRenewalResult{}, errors.Join(fmt.Errorf("validate renewed gateway control leaf: %w", err), cleanup())
	}
	if activation == nil {
		return GatewayControlLeafRenewalResult{}, errors.Join(fmt.Errorf("validate renewed gateway control leaf: empty activation"), cleanup())
	}

	renewed := current
	renewed.Fingerprint = gatewayCertificateFingerprint(issued.Certificate.Raw)
	renewed.SerialHex = issued.Certificate.SerialNumber.Text(16)
	renewed.Subject = issued.Certificate.Subject.String()
	renewed.SANs = []string{"IP:" + issued.OverlayIPv4, issued.IdentityURI}
	sort.Strings(renewed.SANs)
	renewed.NotBefore = issued.Certificate.NotBefore.UTC()
	renewed.NotAfter = issued.Certificate.NotAfter.UTC()
	renewed.Generation = nextCertificateGeneration
	renewed.CertificateRef = string(certificateRef)
	renewed.PrivateKeyRef = privateKeyRef
	candidate := state
	candidate.Generation = nextStateGeneration
	candidate.Certificates = append([]model.Certificate(nil), state.Certificates...)
	candidate.Certificates[leafIndex] = renewed
	if err := renewer.controller.runtime.State.Save(state.Generation, candidate); err != nil {
		return GatewayControlLeafRenewalResult{}, errors.Join(fmt.Errorf("commit renewed gateway control leaf: %w", err), cleanup())
	}
	activation.Activate()
	renewer.controller.recordObservation(ctx, candidate)
	return GatewayControlLeafRenewalResult{
		Changed: true, StateGeneration: candidate.Generation, CertificateGeneration: renewed.Generation,
		PreviousFingerprint: current.Fingerprint, CurrentFingerprint: renewed.Fingerprint,
	}, nil
}

func gatewayControlCertificateIndexes(state model.State) (int, int, error) {
	caIndex, leafIndex := -1, -1
	rotationOperationID := ""
	if _, operation, found, err := activeControlCARotation(state); err != nil {
		return -1, -1, err
	} else if found {
		rotationOperationID = operation.ID
	}
	for index, certificate := range state.Certificates {
		if certificate.OwnerKind != "host" || certificate.OwnerID != state.Host.ID {
			continue
		}
		if rotationOperationID != "" && rotationCertificateIsStaged(certificate, rotationOperationID) {
			continue
		}
		switch certificate.Kind {
		case model.CertificateControlCA:
			if caIndex >= 0 {
				return -1, -1, fmt.Errorf("authoritative state contains multiple control CAs outside a rotation transaction")
			}
			caIndex = index
		case model.CertificateControlServer:
			if leafIndex >= 0 {
				return -1, -1, fmt.Errorf("authoritative state contains multiple gateway control leaves")
			}
			leafIndex = index
		}
	}
	if caIndex < 0 || leafIndex < 0 || state.Certificates[caIndex].PrivateKeyRef == "" || state.Certificates[leafIndex].PrivateKeyRef == "" {
		return -1, -1, fmt.Errorf("authoritative gateway control identity is incomplete")
	}
	return caIndex, leafIndex, nil
}

func gatewayCertificateFingerprint(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}
