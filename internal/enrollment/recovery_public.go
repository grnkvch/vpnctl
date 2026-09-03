package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const (
	recoveryResponseCertificateHashName         = "control_certificate"
	recoveryResponseCertificateMetadataHashName = "control_certificate_metadata"
)

type NodeRecoveryAssignment struct {
	SchemaVersion                 int                 `json:"schema_version"`
	RecoveryID                    string              `json:"recovery_id"`
	RequestID                     string              `json:"request_id"`
	NodeID                        string              `json:"node_id"`
	NodeName                      string              `json:"node_name"`
	OverlayIPv4                   string              `json:"overlay_ipv4"`
	CurrentCredentialGeneration   uint64              `json:"current_credential_generation"`
	CredentialGeneration          uint64              `json:"credential_generation"`
	ActiveTransport               model.TransportKind `json:"active_transport"`
	Presets                       []string            `json:"presets"`
	PolicyGeneration              uint64              `json:"policy_generation,omitempty"`
	PolicyEffectiveHash           string              `json:"policy_effective_hash,omitempty"`
	ExposeIDs                     []string            `json:"expose_ids"`
	GatewayStateGeneration        uint64              `json:"gateway_state_generation"`
	ControlProtocol               string              `json:"control_protocol"`
	EnrollmentFingerprint         string              `json:"enrollment_fingerprint"`
	ControlCertificateFingerprint string              `json:"control_certificate_fingerprint"`
	RecoveredAt                   time.Time           `json:"recovered_at"`
	MaterialHashes                map[string]string   `json:"material_hashes"`
}

func (assignment NodeRecoveryAssignment) Validate() error {
	if assignment.SchemaVersion != NodeRecoverySchemaVersion ||
		!recoveryIDPattern.MatchString(assignment.RecoveryID) ||
		!transcriptUUIDPattern.MatchString(assignment.RequestID) ||
		!transcriptUUIDPattern.MatchString(assignment.NodeID) || validateInviteName(assignment.NodeName) != nil ||
		assignment.CurrentCredentialGeneration == 0 || assignment.GatewayStateGeneration == 0 {
		return fmt.Errorf("node recovery assignment identity or generation is invalid")
	}
	next, err := model.NextGeneration(assignment.CurrentCredentialGeneration)
	if err != nil || assignment.CredentialGeneration != next {
		return fmt.Errorf("node recovery assignment must advance one credential generation")
	}
	if assignment.ActiveTransport != model.TransportStandard && assignment.ActiveTransport != model.TransportRestricted {
		return fmt.Errorf("node recovery assignment transport is invalid")
	}
	overlay, err := netip.ParseAddr(assignment.OverlayIPv4)
	if err != nil || !overlay.Is4() || overlay.String() != assignment.OverlayIPv4 {
		return fmt.Errorf("node recovery assignment overlay IPv4 is invalid")
	}
	if err := validateCanonicalJoinPresets(assignment.Presets); err != nil {
		return err
	}
	if !fingerprintPattern.MatchString(assignment.EnrollmentFingerprint) ||
		!fingerprintPattern.MatchString(assignment.ControlCertificateFingerprint) ||
		!protocolPattern.MatchString(assignment.ControlProtocol) ||
		!hashPattern.MatchString(assignment.MaterialHashes[recoveryResponseCertificateHashName]) ||
		!hashPattern.MatchString(assignment.MaterialHashes[recoveryResponseCertificateMetadataHashName]) ||
		len(assignment.MaterialHashes) != 2 || assignment.RecoveredAt.IsZero() ||
		!assignment.RecoveredAt.Equal(canonicalTime(assignment.RecoveredAt)) {
		return fmt.Errorf("node recovery assignment trust material is invalid")
	}
	if assignment.PolicyGeneration == 0 && assignment.PolicyEffectiveHash != "" ||
		assignment.PolicyGeneration != 0 && !hashPattern.MatchString(assignment.PolicyEffectiveHash) {
		return fmt.Errorf("node recovery assignment policy binding is invalid")
	}
	if !sort.StringsAreSorted(assignment.ExposeIDs) || hasDuplicateStrings(assignment.ExposeIDs) {
		return fmt.Errorf("node recovery assignment expose IDs are not canonical")
	}
	for _, id := range assignment.ExposeIDs {
		if !transcriptUUIDPattern.MatchString(id) {
			return fmt.Errorf("node recovery assignment expose ID is invalid")
		}
	}
	return nil
}

func (assignment NodeRecoveryAssignment) SHA256() ([sha256.Size]byte, error) {
	if err := assignment.Validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded, err := json.Marshal(assignment)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return digest, nil
}

type nodeRecoveryWireResponse struct {
	SchemaVersion         int                    `json:"schema_version"`
	Assignment            NodeRecoveryAssignment `json:"assignment"`
	Certificate           model.Certificate      `json:"certificate"`
	ControlCertificatePEM string                 `json:"control_certificate_pem"`
}

type NodeRecoveryResponseMaterial struct {
	Assignment            NodeRecoveryAssignment
	Certificate           model.Certificate
	ControlCertificatePEM []byte
}

func (NodeRecoveryResponseMaterial) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

func (material *NodeRecoveryResponseMaterial) Destroy() {
	if material != nil {
		clear(material.ControlCertificatePEM)
		material.ControlCertificatePEM = nil
	}
}

func encodeNodeRecoveryResponse(assignment NodeRecoveryAssignment, certificate model.Certificate, certificatePEM []byte) (*output.Secret, error) {
	if err := assignment.Validate(); err != nil || certificate.Validate() != nil ||
		sha256Hex(certificatePEM) != assignment.MaterialHashes[recoveryResponseCertificateHashName] ||
		recoveryCertificateMetadataHash(certificate) != assignment.MaterialHashes[recoveryResponseCertificateMetadataHashName] ||
		certificate.Fingerprint != assignment.ControlCertificateFingerprint {
		return nil, fmt.Errorf("node recovery response material is invalid")
	}
	encoded, err := json.Marshal(nodeRecoveryWireResponse{
		SchemaVersion: NodeRecoverySchemaVersion, Assignment: assignment,
		Certificate:           certificate,
		ControlCertificatePEM: string(certificatePEM),
	})
	if err != nil {
		return nil, err
	}
	secret, err := output.NewSecret(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

func DecodeNodeRecoveryResponse(encoded json.RawMessage) (*NodeRecoveryResponseMaterial, error) {
	var wire nodeRecoveryWireResponse
	if err := controlDecodeRecovery(encoded, &wire); err != nil {
		return nil, err
	}
	certificatePEM := []byte(wire.ControlCertificatePEM)
	if wire.SchemaVersion != NodeRecoverySchemaVersion || wire.Assignment.Validate() != nil || wire.Certificate.Validate() != nil ||
		sha256Hex(certificatePEM) != wire.Assignment.MaterialHashes[recoveryResponseCertificateHashName] ||
		recoveryCertificateMetadataHash(wire.Certificate) != wire.Assignment.MaterialHashes[recoveryResponseCertificateMetadataHashName] ||
		wire.Certificate.Fingerprint != wire.Assignment.ControlCertificateFingerprint {
		clear(certificatePEM)
		return nil, fmt.Errorf("node recovery response is invalid")
	}
	return &NodeRecoveryResponseMaterial{Assignment: wire.Assignment, Certificate: wire.Certificate, ControlCertificatePEM: certificatePEM}, nil
}

func controlDecodeRecovery(encoded json.RawMessage, target any) error {
	if len(encoded) == 0 {
		return fmt.Errorf("node recovery response is empty")
	}
	if err := control.DecodeRPCPayload(encoded, target); err != nil {
		return fmt.Errorf("decode node recovery response: %w", err)
	}
	return nil
}

type GatewayRecoveryBuilder struct {
	recovery *RecoveryManager
	rotation *GatewayNodeRotationManager
}

func NewGatewayRecoveryBuilder(recovery *RecoveryManager, rotation *GatewayNodeRotationManager) (*GatewayRecoveryBuilder, error) {
	if recovery == nil || rotation == nil || recovery.state == nil {
		return nil, fmt.Errorf("gateway recovery requires token and rotation managers")
	}
	return &GatewayRecoveryBuilder{recovery: recovery, rotation: rotation}, nil
}

type PreparedRecoveryArtifacts struct {
	NodeID           string
	Transport        model.TransportKind
	Presets          []string
	PublicKeyHashes  map[string][sha256.Size]byte
	AssignmentSHA256 [sha256.Size]byte
	ResponseData     *output.Secret
	Committer        *gatewayRecoveryCommitter
}

func (builder *GatewayRecoveryBuilder) Prepare(
	ctx context.Context,
	authorization RecoveryAuthorization,
	publicRequest PublicEnrollmentRequest,
) (PreparedRecoveryArtifacts, error) {
	if builder == nil || builder.recovery == nil || builder.rotation == nil || ctx == nil {
		return PreparedRecoveryArtifacts{}, ErrPublicEnrollmentUnavailable
	}
	request, err := DecodeNodeRecoveryRequest(publicRequest.Payload, publicRequest.NodeNonce)
	if err != nil {
		return PreparedRecoveryArtifacts{}, fmt.Errorf("%w: invalid recovery payload", ErrPublicEnrollmentRejected)
	}
	destroyRequest := true
	defer func() {
		if destroyRequest {
			request.Destroy()
		}
	}()
	if request.RecoveryID != authorization.RecoveryID || request.PublicExchange.NodeID != authorization.NodeID ||
		request.CurrentGeneration != authorization.CredentialGeneration ||
		request.PublicExchange.CredentialGeneration != authorization.RequestedCredentialGeneration {
		return PreparedRecoveryArtifacts{}, fmt.Errorf("%w: recovery request differs from token binding", ErrPublicEnrollmentRejected)
	}
	state, err := builder.recovery.loadGatewayState()
	if err != nil || state.Generation != authorization.ExpectedStateGeneration {
		return PreparedRecoveryArtifacts{}, fmt.Errorf("%w: recovery state changed", ErrPublicEnrollmentRejected)
	}
	node, err := activeRecoveryNode(state, authorization.NodeID, authorization.CredentialGeneration)
	if err != nil {
		return PreparedRecoveryArtifacts{}, fmt.Errorf("%w: recovery node is inactive", ErrPublicEnrollmentRejected)
	}
	certificate, err := currentNodeControlCertificate(state, node)
	if err != nil || certificate.Fingerprint != authorization.BindingFingerprint {
		return PreparedRecoveryArtifacts{}, fmt.Errorf("%w: recovery certificate binding changed", ErrPublicEnrollmentRejected)
	}
	currentCertificatePEM, err := builder.rotation.secrets.Get(model.SecretRef(certificate.CertificateRef))
	if err != nil {
		return PreparedRecoveryArtifacts{}, ErrPublicEnrollmentUnavailable
	}
	defer clear(currentCertificatePEM)
	if err := VerifyNodeRecoveryProof(request, publicRequest.NodeNonce, currentCertificatePEM, authorization.BindingFingerprint); err != nil {
		return PreparedRecoveryArtifacts{}, err
	}
	rotationRequest := &NodeRotationRequest{
		SchemaVersion: NodeRotationSchemaVersion, RequestID: request.RequestID, NodeID: request.PublicExchange.NodeID,
		ExpectedGatewayStateGeneration: authorization.ExpectedStateGeneration,
		CurrentCredentialGeneration:    authorization.CredentialGeneration,
		RequestedCredentialGeneration:  authorization.RequestedCredentialGeneration,
		PublicExchange:                 request.PublicExchange, shared: request.shared,
	}
	preparation, err := builder.rotation.PrepareRecovery(ctx, rotationRequest)
	if err != nil {
		return PreparedRecoveryArtifacts{}, err
	}
	material, err := preparation.Material()
	if err != nil {
		_ = preparation.Abort(context.Background())
		preparation.Destroy()
		return PreparedRecoveryArtifacts{}, err
	}
	defer clear(material.ControlCertificatePEM)
	recoveredAt := canonicalTime(builder.recovery.now())
	assignment := NodeRecoveryAssignment{
		SchemaVersion: NodeRecoverySchemaVersion, RecoveryID: authorization.RecoveryID,
		RequestID: request.RequestID, NodeID: authorization.NodeID, NodeName: authorization.NodeName,
		OverlayIPv4: authorization.OverlayIPv4, CurrentCredentialGeneration: authorization.CredentialGeneration,
		CredentialGeneration: authorization.RequestedCredentialGeneration, ActiveTransport: authorization.ActiveTransport,
		Presets: append([]string{}, authorization.Presets...), PolicyGeneration: authorization.PolicyGeneration,
		PolicyEffectiveHash: authorization.PolicyEffectiveHash, ExposeIDs: append([]string{}, authorization.ExposeIDs...),
		GatewayStateGeneration: material.GatewayStateGeneration, ControlProtocol: authorization.ControlProtocol,
		EnrollmentFingerprint:         authorization.EnrollmentFingerprint,
		ControlCertificateFingerprint: material.Certificate.Fingerprint, RecoveredAt: recoveredAt,
		MaterialHashes: map[string]string{
			recoveryResponseCertificateHashName:         sha256Hex(material.ControlCertificatePEM),
			recoveryResponseCertificateMetadataHashName: recoveryCertificateMetadataHash(material.Certificate),
		},
	}
	if err := assignment.Validate(); err != nil || !recoveryStableMetadataMatches(authorization, assignment) {
		_ = preparation.Abort(context.Background())
		preparation.Destroy()
		return PreparedRecoveryArtifacts{}, errors.Join(err, fmt.Errorf("recovery assignment changed stable metadata"))
	}
	response, err := encodeNodeRecoveryResponse(assignment, material.Certificate, material.ControlCertificatePEM)
	if err != nil {
		_ = preparation.Abort(context.Background())
		preparation.Destroy()
		return PreparedRecoveryArtifacts{}, err
	}
	assignmentHash, err := assignment.SHA256()
	if err != nil {
		response.Destroy()
		_ = preparation.Abort(context.Background())
		preparation.Destroy()
		return PreparedRecoveryArtifacts{}, err
	}
	publicHashes, err := request.PublicExchange.TranscriptHashes()
	if err != nil {
		response.Destroy()
		_ = preparation.Abort(context.Background())
		preparation.Destroy()
		return PreparedRecoveryArtifacts{}, err
	}
	committer := &gatewayRecoveryCommitter{
		recovery: builder.recovery, authorization: authorization, request: request, preparation: preparation,
	}
	destroyRequest = false
	return PreparedRecoveryArtifacts{
		NodeID: authorization.NodeID, Transport: authorization.ActiveTransport,
		Presets: append([]string{}, authorization.Presets...), PublicKeyHashes: publicHashes,
		AssignmentSHA256: assignmentHash, ResponseData: response, Committer: committer,
	}, nil
}

type gatewayRecoveryCommitter struct {
	mu              sync.Mutex
	recovery        *RecoveryManager
	authorization   RecoveryAuthorization
	request         *NodeRecoveryRequest
	preparation     *GatewayNodeRotationPreparation
	commitAttempted bool
	committed       bool
	destroyed       bool
}

func (committer *gatewayRecoveryCommitter) Commit(ctx context.Context, replayHash string) error {
	if committer == nil || ctx == nil {
		return ErrPublicEnrollmentUnavailable
	}
	committer.mu.Lock()
	defer committer.mu.Unlock()
	if committer.destroyed || committer.committed || committer.preparation == nil {
		return ErrPublicEnrollmentRejected
	}
	if err := committer.preparation.Activate(ctx); err != nil {
		_ = committer.preparation.Abort(context.Background())
		return err
	}
	committer.commitAttempted = true
	commit, commitErr := committer.preparation.CommitRecovery(ctx, committer.authorization, replayHash, committer.recovery.now())
	if commit.State != NodeRotationCommitNew {
		return errors.Join(ErrPublicEnrollmentRejected, commitErr)
	}
	committer.committed = true
	deadline := time.Now().Add(NodeRotationDrainTimeout)
	// A response must still be delivered once the authoritative generation is
	// known new. Turning post-commit durability or bounded-drain cleanup into an
	// HTTP rejection would make the node destroy the only matching fresh set.
	// State authorization already rejects the old generation; later repair can
	// reconcile retained runtime/files.
	_ = committer.preparation.Drain(ctx, deadline)
	return nil
}

func (committer *gatewayRecoveryCommitter) Destroy() {
	if committer == nil {
		return
	}
	committer.mu.Lock()
	defer committer.mu.Unlock()
	if committer.destroyed {
		return
	}
	if !committer.committed && !committer.commitAttempted && committer.preparation != nil {
		_ = committer.preparation.Abort(context.Background())
	}
	if committer.preparation != nil {
		committer.preparation.Destroy()
	}
	if committer.request != nil {
		committer.request.Destroy()
	}
	committer.preparation = nil
	committer.request = nil
	committer.destroyed = true
}

type RecoveryEnrollmentCoordinator struct {
	recovery *RecoveryManager
	builder  *GatewayRecoveryBuilder
}

func NewRecoveryEnrollmentCoordinator(recovery *RecoveryManager, builder *GatewayRecoveryBuilder) (*RecoveryEnrollmentCoordinator, error) {
	if recovery == nil || builder == nil {
		return nil, fmt.Errorf("recovery manager and gateway recovery builder are required")
	}
	return &RecoveryEnrollmentCoordinator{recovery: recovery, builder: builder}, nil
}

func (coordinator *RecoveryEnrollmentCoordinator) PreparePublicEnrollment(
	ctx context.Context,
	request PublicEnrollmentRequest,
) (PublicEnrollmentTransaction, error) {
	if coordinator == nil || coordinator.recovery == nil || coordinator.builder == nil || ctx == nil {
		return nil, ErrPublicEnrollmentUnavailable
	}
	if request.Purpose != PurposeRecover || request.Endpoint == "" {
		return nil, ErrPublicEnrollmentRejected
	}
	var authorization RecoveryAuthorization
	if err := request.UseToken(func(token []byte) error {
		var err error
		authorization, err = coordinator.recovery.Authorize(token)
		return err
	}); err != nil || authorization.GatewayEndpoint != request.Endpoint {
		return nil, fmt.Errorf("%w: authorize recovery", ErrPublicEnrollmentRejected)
	}
	artifacts, err := coordinator.builder.Prepare(ctx, authorization, request)
	if err != nil {
		return nil, err
	}
	if artifacts.ResponseData == nil || artifacts.Committer == nil {
		if artifacts.ResponseData != nil {
			artifacts.ResponseData.Destroy()
		}
		if artifacts.Committer != nil {
			artifacts.Committer.Destroy()
		}
		return nil, ErrPublicEnrollmentUnavailable
	}
	transcript, err := NewEnrollmentTranscript(
		PurposeRecover, authorization.RecoveryID, authorization.GatewayEndpoint, artifacts.NodeID,
		authorization.IssuedAt, authorization.ExpiresAt, request.NodeNonce, request.GatewayNonce,
		artifacts.Transport, artifacts.Presets, artifacts.PublicKeyHashes, artifacts.AssignmentSHA256,
	)
	if err != nil {
		artifacts.ResponseData.Destroy()
		artifacts.Committer.Destroy()
		return nil, ErrPublicEnrollmentUnavailable
	}
	return &recoveryEnrollmentTransaction{
		transcript: transcript, fingerprint: authorization.EnrollmentFingerprint,
		responseData: artifacts.ResponseData, committer: artifacts.Committer,
	}, nil
}

type recoveryEnrollmentTransaction struct {
	mu           sync.Mutex
	transcript   EnrollmentTranscript
	fingerprint  string
	responseData *output.Secret
	committer    *gatewayRecoveryCommitter
	committed    bool
	destroyed    bool
}

func (transaction *recoveryEnrollmentTransaction) Transcript() EnrollmentTranscript {
	if transaction == nil {
		return EnrollmentTranscript{}
	}
	return transaction.transcript
}

func (transaction *recoveryEnrollmentTransaction) EnrollmentFingerprint() string {
	if transaction == nil {
		return ""
	}
	return transaction.fingerprint
}

func (transaction *recoveryEnrollmentTransaction) UseResponseData(callback func(json.RawMessage) error) error {
	if transaction == nil || callback == nil {
		return ErrPublicEnrollmentUnavailable
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.destroyed || transaction.responseData == nil {
		return ErrPublicEnrollmentUnavailable
	}
	return transaction.responseData.Use(func(data []byte) error { return callback(json.RawMessage(data)) })
}

func (transaction *recoveryEnrollmentTransaction) Commit(ctx context.Context, replayHash string) error {
	if transaction == nil || ctx == nil {
		return ErrPublicEnrollmentUnavailable
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.destroyed || transaction.committed || transaction.committer == nil {
		return ErrPublicEnrollmentRejected
	}
	if err := transaction.committer.Commit(ctx, replayHash); err != nil {
		return err
	}
	transaction.committed = true
	return nil
}

func (transaction *recoveryEnrollmentTransaction) Destroy() {
	if transaction == nil {
		return
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.destroyed {
		return
	}
	if transaction.responseData != nil {
		transaction.responseData.Destroy()
	}
	if transaction.committer != nil {
		transaction.committer.Destroy()
	}
	transaction.responseData = nil
	transaction.committer = nil
	transaction.destroyed = true
}

func hasDuplicateStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

func recoveryCertificateMetadataHash(certificate model.Certificate) string {
	encoded, err := json.Marshal(certificate)
	if err != nil {
		return ""
	}
	digest := sha256Hex(encoded)
	clear(encoded)
	return digest
}

func recoveryStableMetadataMatches(authorization RecoveryAuthorization, assignment NodeRecoveryAssignment) bool {
	return authorization.RecoveryID == assignment.RecoveryID && authorization.NodeID == assignment.NodeID &&
		authorization.NodeName == assignment.NodeName && authorization.OverlayIPv4 == assignment.OverlayIPv4 &&
		authorization.CredentialGeneration == assignment.CurrentCredentialGeneration &&
		authorization.RequestedCredentialGeneration == assignment.CredentialGeneration &&
		authorization.ActiveTransport == assignment.ActiveTransport &&
		reflect.DeepEqual(authorization.Presets, assignment.Presets) &&
		authorization.PolicyGeneration == assignment.PolicyGeneration &&
		authorization.PolicyEffectiveHash == assignment.PolicyEffectiveHash &&
		reflect.DeepEqual(authorization.ExposeIDs, assignment.ExposeIDs)
}

var _ PublicEnrollmentCoordinator = (*RecoveryEnrollmentCoordinator)(nil)
var _ PublicEnrollmentTransaction = (*recoveryEnrollmentTransaction)(nil)
