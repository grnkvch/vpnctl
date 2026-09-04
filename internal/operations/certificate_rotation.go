package operations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const publicCertificateRotationRollbackTimeout = 15 * time.Second

var (
	ErrPublicCertificateRotationPlanStale = errors.New("public certificate rotation plan is stale")
	ErrPublicCertificateRotationUncertain = errors.New("public certificate rotation outcome is uncertain")
)

type PublicCertificateRotationStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

type PublicCertificateRotationSecretStore interface {
	ingress.PublicCertificateSecretStore
}

type PublicCertificateIngressActivation struct {
	CertificateID   string
	StateGeneration uint64
	Fingerprint     string
	opaque          any
}

func (PublicCertificateIngressActivation) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

// PublicCertificateRotationRuntime activates one complete ingress tree with
// the candidate TLS identity. Its rollback receipt represents exactly one
// prior serving generation and must not contain key bytes in ordinary output.
type PublicCertificateRotationRuntime interface {
	Activate(context.Context, model.State, model.State) (PublicCertificateIngressActivation, error)
	Rollback(context.Context, PublicCertificateIngressActivation) error
}

type PublicCertificateAffectedExpose struct {
	ID     string
	NodeID string
	Name   string
	State  model.ExposeState
}

type PublicCertificateRotationPlan struct {
	GatewayID                  string
	PublicIPv4                 string
	ExpectedStateGeneration    uint64
	NextStateGeneration        uint64
	CurrentCertificate         model.Certificate
	NextCertificateGeneration  uint64
	PreviousSnapshotGeneration uint64
	AffectedExposes            []PublicCertificateAffectedExpose
	CertificateExportPath      string
	beforeRaw                  []byte
}

func (PublicCertificateRotationPlan) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

func (plan PublicCertificateRotationPlan) Validate() error {
	if model.ValidateResourceID(plan.GatewayID) != nil || plan.ExpectedStateGeneration == 0 || plan.NextStateGeneration == 0 ||
		plan.CurrentCertificate.Validate() != nil || plan.CurrentCertificate.Kind != model.CertificatePublicIngress ||
		plan.CurrentCertificate.OwnerKind != "host" || plan.CurrentCertificate.OwnerID != plan.GatewayID {
		return fmt.Errorf("public certificate rotation plan identity is invalid")
	}
	address, err := netip.ParseAddr(plan.PublicIPv4)
	if err != nil || !address.Is4() || address.String() != plan.PublicIPv4 {
		return fmt.Errorf("public certificate rotation plan IPv4 is invalid")
	}
	wantState, stateErr := model.NextGeneration(plan.ExpectedStateGeneration)
	wantCertificate, certificateErr := model.NextGeneration(plan.CurrentCertificate.Generation)
	if stateErr != nil || certificateErr != nil || plan.NextStateGeneration != wantState ||
		plan.NextCertificateGeneration != wantCertificate {
		return fmt.Errorf("public certificate rotation plan generation is invalid")
	}
	wantPrevious := uint64(0)
	if plan.CurrentCertificate.Generation > 1 {
		wantPrevious = plan.CurrentCertificate.Generation - 1
	}
	if plan.PreviousSnapshotGeneration != wantPrevious {
		return fmt.Errorf("public certificate rotation rollback generation is invalid")
	}
	if plan.CertificateExportPath == "" || !filepath.IsAbs(plan.CertificateExportPath) ||
		filepath.Clean(plan.CertificateExportPath) != plan.CertificateExportPath || strings.ContainsAny(plan.CertificateExportPath, "\x00\r\n") {
		return fmt.Errorf("public certificate rotation export path is invalid")
	}
	if len(plan.beforeRaw) == 0 {
		return fmt.Errorf("public certificate rotation plan lacks state provenance")
	}
	seen := make(map[string]struct{}, len(plan.AffectedExposes))
	for _, expose := range plan.AffectedExposes {
		if model.ValidateResourceID(expose.ID) != nil || model.ValidateResourceID(expose.NodeID) != nil ||
			expose.State != model.ExposeReady && expose.State != model.ExposeDegraded {
			return fmt.Errorf("public certificate rotation impact is invalid")
		}
		if _, duplicate := seen[expose.ID]; duplicate {
			return fmt.Errorf("public certificate rotation impact duplicates an expose")
		}
		seen[expose.ID] = struct{}{}
	}
	return nil
}

type PublicCertificateRotationResult struct {
	GatewayID                     string
	StateGeneration               uint64
	CertificateID                 string
	CertificateGeneration         uint64
	PreviousCertificateGeneration uint64
	PreviousFingerprint           string
	CurrentFingerprint            string
	PublicIPv4                    string
	CertificateExportPath         string
	AffectedExposes               []PublicCertificateAffectedExpose
}

type PublicCertificateRotationRuntimeOptions struct {
	Entropy io.Reader
	Now     func() time.Time
}

type PublicCertificateRotationManager struct {
	state      PublicCertificateRotationStateStore
	secrets    PublicCertificateRotationSecretStore
	runtime    PublicCertificateRotationRuntime
	exportPath string
	entropy    io.Reader
	now        func() time.Time
}

func NewPublicCertificateRotationManager(
	state PublicCertificateRotationStateStore,
	secrets PublicCertificateRotationSecretStore,
	runtime PublicCertificateRotationRuntime,
	exportPath string,
	options PublicCertificateRotationRuntimeOptions,
) (*PublicCertificateRotationManager, error) {
	if state == nil || secrets == nil || runtime == nil || exportPath == "" || !filepath.IsAbs(exportPath) || filepath.Clean(exportPath) != exportPath {
		return nil, fmt.Errorf("public certificate rotation dependencies are incomplete")
	}
	if options.Entropy == nil {
		options.Entropy = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &PublicCertificateRotationManager{
		state: state, secrets: secrets, runtime: runtime, exportPath: exportPath,
		entropy: options.Entropy, now: options.Now,
	}, nil
}

// Plan is strictly read-only: key generation, snapshot cleanup, export staging,
// state writes, and ingress activation happen only after common CLI consent.
func (manager *PublicCertificateRotationManager) Plan(ctx context.Context) (PublicCertificateRotationPlan, error) {
	if ctx == nil || manager == nil || manager.state == nil || manager.secrets == nil || manager.runtime == nil {
		return PublicCertificateRotationPlan{}, fmt.Errorf("public certificate rotation manager is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return PublicCertificateRotationPlan{}, err
	}
	state, index, current, err := manager.loadGatewayState()
	if err != nil {
		return PublicCertificateRotationPlan{}, err
	}
	_ = index
	if _, err := ingress.InspectPublicCertificate(state, manager.now().UTC()); err != nil {
		return PublicCertificateRotationPlan{}, err
	}
	nextState, err := model.NextGeneration(state.Generation)
	if err != nil {
		return PublicCertificateRotationPlan{}, err
	}
	nextCertificate, err := model.NextGeneration(current.Generation)
	if err != nil {
		return PublicCertificateRotationPlan{}, err
	}
	beforeRaw, err := model.EncodeState(state)
	if err != nil {
		return PublicCertificateRotationPlan{}, err
	}
	previous := uint64(0)
	if current.Generation > 1 {
		previous = current.Generation - 1
	}
	plan := PublicCertificateRotationPlan{
		GatewayID: state.Host.ID, PublicIPv4: state.Host.PublicIPv4,
		ExpectedStateGeneration: state.Generation, NextStateGeneration: nextState,
		CurrentCertificate: current, NextCertificateGeneration: nextCertificate,
		PreviousSnapshotGeneration: previous, AffectedExposes: affectedPublicExposes(state.Exposes),
		CertificateExportPath: manager.exportPath, beforeRaw: beforeRaw,
	}
	if err := plan.Validate(); err != nil {
		return PublicCertificateRotationPlan{}, err
	}
	return plan, nil
}

func (manager *PublicCertificateRotationManager) Apply(
	ctx context.Context,
	plan PublicCertificateRotationPlan,
) (PublicCertificateRotationResult, error) {
	if ctx == nil || manager == nil || manager.state == nil || manager.secrets == nil || manager.runtime == nil {
		return PublicCertificateRotationResult{}, fmt.Errorf("public certificate rotation manager is incomplete")
	}
	if err := plan.Validate(); err != nil {
		return PublicCertificateRotationResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return PublicCertificateRotationResult{}, err
	}
	state, certificateIndex, current, err := manager.loadGatewayState()
	if err != nil {
		return PublicCertificateRotationResult{}, err
	}
	encoded, err := model.EncodeState(state)
	if err != nil || !reflect.DeepEqual(encoded, plan.beforeRaw) || state.Generation != plan.ExpectedStateGeneration ||
		!reflect.DeepEqual(current, plan.CurrentCertificate) || !reflect.DeepEqual(affectedPublicExposes(state.Exposes), plan.AffectedExposes) {
		return PublicCertificateRotationResult{}, ErrPublicCertificateRotationPlanStale
	}
	if err := ctx.Err(); err != nil {
		return PublicCertificateRotationResult{}, err
	}
	if err := manager.removeSupersededSnapshot(plan.PreviousSnapshotGeneration); err != nil {
		return PublicCertificateRotationResult{}, fmt.Errorf("remove superseded public certificate snapshot: %w", err)
	}
	issuedAt := manager.now().UTC().Truncate(time.Second)
	material, err := ingress.GeneratePublicCertificate(manager.entropy, plan.PublicIPv4, issuedAt)
	if err != nil {
		return PublicCertificateRotationResult{}, err
	}
	defer clearRotationBytes(material.PrivateKeyPEM)
	renewed, err := rotatedPublicCertificate(current, material, plan.NextCertificateGeneration)
	if err != nil {
		return PublicCertificateRotationResult{}, err
	}
	staged := make([]model.SecretRef, 0, 2)
	cleanupStaged := func() error {
		var cleanupErrors []error
		for index := len(staged) - 1; index >= 0; index-- {
			if _, cleanupErr := manager.secrets.Delete(staged[index]); cleanupErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("delete staged public certificate material: %w", cleanupErr))
			}
		}
		return errors.Join(cleanupErrors...)
	}
	if err := manager.secrets.PutIfAbsent(model.SecretRef(renewed.CertificateRef), material.CertificatePEM); err != nil {
		return PublicCertificateRotationResult{}, fmt.Errorf("stage public certificate: %w", err)
	}
	staged = append(staged, model.SecretRef(renewed.CertificateRef))
	if err := manager.secrets.PutIfAbsent(renewed.PrivateKeyRef, material.PrivateKeyPEM); err != nil {
		return PublicCertificateRotationResult{}, errors.Join(fmt.Errorf("stage public certificate private key: %w", err), cleanupStaged())
	}
	staged = append(staged, renewed.PrivateKeyRef)
	candidate, err := cloneExposeState(state)
	if err != nil {
		return PublicCertificateRotationResult{}, errors.Join(err, cleanupStaged())
	}
	candidate.Generation = plan.NextStateGeneration
	candidate.Certificates[certificateIndex] = renewed
	if err := model.ValidateTransition(state, candidate); err != nil {
		return PublicCertificateRotationResult{}, errors.Join(fmt.Errorf("build public certificate rotation state: %w", err), cleanupStaged())
	}
	export, err := ingress.PreparePublicCertificateExportRotation(state, candidate, manager.secrets, manager.exportPath)
	if err != nil {
		return PublicCertificateRotationResult{}, errors.Join(err, cleanupStaged())
	}
	activation, err := manager.runtime.Activate(ctx, state, candidate)
	if err != nil {
		return PublicCertificateRotationResult{}, errors.Join(fmt.Errorf("activate rotated public certificate: %w", err), export.Abort(), cleanupStaged())
	}
	if activation.CertificateID != renewed.ID || activation.StateGeneration != candidate.Generation || activation.Fingerprint != renewed.Fingerprint {
		return PublicCertificateRotationResult{}, manager.rollback(
			errors.New("public certificate ingress activation receipt is invalid"), activation, export, cleanupStaged,
		)
	}
	if err := export.Activate(); err != nil {
		return PublicCertificateRotationResult{}, manager.rollback(err, activation, export, cleanupStaged)
	}
	if saveErr := manager.state.Save(state.Generation, candidate); saveErr != nil {
		observed, loadErr := manager.state.Load()
		switch {
		case loadErr == nil && reflect.DeepEqual(observed, candidate):
			// The atomic state publication committed despite a durability/reporting
			// error. Runtime, export, and staged secrets already match it.
		case loadErr == nil && reflect.DeepEqual(observed, state):
			return PublicCertificateRotationResult{}, manager.rollback(saveErr, activation, export, cleanupStaged)
		default:
			return PublicCertificateRotationResult{}, &PublicCertificateRotationUncertainError{Cause: errors.Join(saveErr, loadErr)}
		}
	}
	return PublicCertificateRotationResult{
		GatewayID: candidate.Host.ID, StateGeneration: candidate.Generation,
		CertificateID: renewed.ID, CertificateGeneration: renewed.Generation,
		PreviousCertificateGeneration: current.Generation,
		PreviousFingerprint:           current.Fingerprint, CurrentFingerprint: renewed.Fingerprint,
		PublicIPv4: candidate.Host.PublicIPv4, CertificateExportPath: manager.exportPath,
		AffectedExposes: affectedPublicExposes(candidate.Exposes),
	}, nil
}

func (manager *PublicCertificateRotationManager) rollback(
	primary error,
	activation PublicCertificateIngressActivation,
	export *ingress.PublicCertificateExportRotation,
	cleanup func() error,
) error {
	rollbackContext, cancel := context.WithTimeout(context.Background(), publicCertificateRotationRollbackTimeout)
	defer cancel()
	exportErr := export.Rollback()
	runtimeErr := manager.runtime.Rollback(rollbackContext, activation)
	cleanupErr := cleanup()
	combined := errors.Join(primary, exportErr, runtimeErr, cleanupErr)
	if exportErr != nil || runtimeErr != nil || cleanupErr != nil {
		return &PublicCertificateRotationUncertainError{Cause: combined}
	}
	return combined
}

func (manager *PublicCertificateRotationManager) removeSupersededSnapshot(generation uint64) error {
	if generation == 0 {
		return nil
	}
	certificateRef, privateKeyRef, err := ingress.PublicCertificateReferences(generation)
	if err != nil {
		return err
	}
	if _, err := manager.secrets.Delete(privateKeyRef); err != nil {
		return err
	}
	if _, err := manager.secrets.Delete(model.SecretRef(certificateRef)); err != nil {
		return err
	}
	return nil
}

func (manager *PublicCertificateRotationManager) loadGatewayState() (model.State, int, model.Certificate, error) {
	state, err := manager.state.Load()
	if err != nil {
		return model.State{}, -1, model.Certificate{}, err
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return model.State{}, -1, model.Certificate{}, fmt.Errorf("public certificate rotation requires valid gateway state")
	}
	index := -1
	for candidateIndex, certificate := range state.Certificates {
		if certificate.Kind != model.CertificatePublicIngress {
			continue
		}
		if index >= 0 {
			return model.State{}, -1, model.Certificate{}, fmt.Errorf("gateway has multiple public ingress certificates")
		}
		index = candidateIndex
	}
	if index < 0 {
		return model.State{}, -1, model.Certificate{}, ingress.ErrPublicCertificateNotFound
	}
	return state, index, state.Certificates[index], nil
}

func rotatedPublicCertificate(
	current model.Certificate,
	material ingress.PublicCertificateMaterial,
	generation uint64,
) (model.Certificate, error) {
	if material.Certificate == nil {
		return model.Certificate{}, fmt.Errorf("rotated public certificate material is incomplete")
	}
	certificateRef, privateKeyRef, err := ingress.PublicCertificateReferences(generation)
	if err != nil {
		return model.Certificate{}, err
	}
	fingerprint := sha256.Sum256(material.Certificate.Raw)
	renewed := current
	renewed.Fingerprint = "sha256:" + hex.EncodeToString(fingerprint[:])
	renewed.SerialHex = material.Certificate.SerialNumber.Text(16)
	renewed.Subject = material.Certificate.Subject.String()
	renewed.SANs = []string{"IP:" + material.Certificate.Subject.CommonName}
	renewed.NotBefore = material.Certificate.NotBefore.UTC()
	renewed.NotAfter = material.Certificate.NotAfter.UTC()
	renewed.Generation = generation
	renewed.CertificateRef = certificateRef
	renewed.PrivateKeyRef = privateKeyRef
	if err := renewed.Validate(); err != nil {
		return model.Certificate{}, err
	}
	return renewed, nil
}

func affectedPublicExposes(exposes []model.Expose) []PublicCertificateAffectedExpose {
	result := make([]PublicCertificateAffectedExpose, 0, len(exposes))
	for _, expose := range exposes {
		if expose.State != model.ExposeReady && expose.State != model.ExposeDegraded {
			continue
		}
		result = append(result, PublicCertificateAffectedExpose{
			ID: expose.ID, NodeID: expose.NodeID, Name: expose.Name, State: expose.State,
		})
	}
	sort.Slice(result, func(left, right int) bool {
		leftName, rightName := strings.ToLower(result[left].Name), strings.ToLower(result[right].Name)
		if leftName != rightName {
			return leftName < rightName
		}
		return result[left].ID < result[right].ID
	})
	return result
}

func clearRotationBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

type PublicCertificateRotationUncertainError struct{ Cause error }

func (failure *PublicCertificateRotationUncertainError) Error() string {
	return ErrPublicCertificateRotationUncertain.Error()
}

func (failure *PublicCertificateRotationUncertainError) Unwrap() error {
	if failure == nil || failure.Cause == nil {
		return ErrPublicCertificateRotationUncertain
	}
	return errors.Join(ErrPublicCertificateRotationUncertain, failure.Cause)
}
