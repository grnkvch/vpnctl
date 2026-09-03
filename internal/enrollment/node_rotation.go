package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	NodeRotationSchemaVersion = 1
	NodeRotationDrainTimeout  = 30 * time.Second
	nodeRotationPlanMarker    = "<redacted-node-rotation-plan>"
)

var (
	ErrNodeRotationStale           = errors.New("node rotation plan is stale")
	ErrNodeRotationNotReady        = errors.New("node rotation candidate is not ready")
	ErrNodeRotationConflict        = errors.New("node rotation conflicts with authoritative state")
	ErrNodeRotationReplay          = errors.New("node rotation request was already processed")
	ErrNodeRotationCommitUncertain = errors.New("node rotation commit outcome is uncertain")
	ErrNodeRotationCleanupPending  = errors.New("node rotation cleanup remains pending")
)

type NodeRotationReadinessReport struct {
	Control    bool
	Standard   bool
	Restricted bool
	Tunnel     bool
}

func (report NodeRotationReadinessReport) Validate() error {
	if !report.Control || !report.Standard || !report.Restricted || !report.Tunnel {
		return fmt.Errorf("%w: control=%t standard=%t restricted=%t tunnel=%t",
			ErrNodeRotationNotReady, report.Control, report.Standard, report.Restricted, report.Tunnel)
	}
	return nil
}

// NodeRotationRequest is an authenticated current-generation control request.
// It exposes only the new public material; the two necessarily shared values
// stay callback-scoped and the aggregate cannot enter ordinary output.
type NodeRotationRequest struct {
	SchemaVersion                  int
	RequestID                      string
	NodeID                         string
	ExpectedGatewayStateGeneration uint64
	CurrentCredentialGeneration    uint64
	RequestedCredentialGeneration  uint64
	PublicExchange                 NodePublicExchange
	shared                         *NodeSharedCredentialExchange
}

func newNodeRotationRequest(
	requestID string,
	expectedGatewayGeneration, currentGeneration uint64,
	installation NodeCredentialInstallation,
	sharedPayload *output.Secret,
) (*NodeRotationRequest, error) {
	if sharedPayload == nil {
		return nil, fmt.Errorf("node rotation shared credential payload is required")
	}
	var retained *NodeSharedCredentialExchange
	err := sharedPayload.Use(func(encoded []byte) error {
		var err error
		retained, err = decodeNodeSharedCredentialExchange(encoded, installation.PublicExchange)
		return err
	})
	if err != nil {
		return nil, err
	}
	request := &NodeRotationRequest{
		SchemaVersion: NodeRotationSchemaVersion, RequestID: requestID, NodeID: installation.NodeID,
		ExpectedGatewayStateGeneration: expectedGatewayGeneration,
		CurrentCredentialGeneration:    currentGeneration, RequestedCredentialGeneration: installation.CredentialGeneration,
		PublicExchange: installation.PublicExchange, shared: retained,
	}
	if err := request.Validate(); err != nil {
		request.Destroy()
		return nil, err
	}
	return request, nil
}

func (request *NodeRotationRequest) Validate() error {
	if request == nil || request.SchemaVersion != NodeRotationSchemaVersion || request.shared == nil {
		return fmt.Errorf("node rotation request is incomplete")
	}
	if !transcriptUUIDPattern.MatchString(request.RequestID) || !transcriptUUIDPattern.MatchString(request.NodeID) {
		return fmt.Errorf("node rotation request identity is invalid")
	}
	if request.ExpectedGatewayStateGeneration == 0 || request.CurrentCredentialGeneration == 0 {
		return fmt.Errorf("node rotation request generation is invalid")
	}
	next, err := model.NextGeneration(request.CurrentCredentialGeneration)
	if err != nil || next != request.RequestedCredentialGeneration {
		return fmt.Errorf("node rotation credential generation must advance exactly once")
	}
	if request.PublicExchange.NodeID != request.NodeID ||
		request.PublicExchange.CredentialGeneration != request.RequestedCredentialGeneration {
		return fmt.Errorf("node rotation public exchange context differs from request")
	}
	return request.PublicExchange.Validate()
}

func (request *NodeRotationRequest) UseSharedCredentials(callback func(restrictedCredential, tunnelCredential []byte) error) error {
	if request == nil || request.shared == nil {
		return fmt.Errorf("node rotation shared credentials are unavailable")
	}
	return request.shared.Use(callback)
}

func (request *NodeRotationRequest) Destroy() {
	if request != nil && request.shared != nil {
		request.shared.Destroy()
		request.shared = nil
	}
}

func (NodeRotationRequest) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

// GatewayNodeRotationCandidate contains both generations only for a bounded
// staging/activation window. Providers may inspect shared values only inside
// UseNodeSharedCredentials.
type GatewayNodeRotationCandidate struct {
	Before                model.State
	Candidate             model.State
	RequestID             string
	NodeID                string
	CurrentGeneration     uint64
	RequestedGeneration   uint64
	ControlCertificatePEM []byte
	PublicExchange        NodePublicExchange
	shared                *NodeSharedCredentialExchange
}

func (candidate GatewayNodeRotationCandidate) UseNodeSharedCredentials(callback func(restrictedCredential, tunnelCredential []byte) error) error {
	if candidate.shared == nil {
		return fmt.Errorf("gateway node rotation shared credentials are unavailable")
	}
	return candidate.shared.Use(callback)
}

func (GatewayNodeRotationCandidate) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type GatewayNodeRotationRuntime interface {
	Stage(context.Context, GatewayNodeRotationCandidate) error
	Check(context.Context, GatewayNodeRotationCandidate) (NodeRotationReadinessReport, error)
	ActivateParallel(context.Context, GatewayNodeRotationCandidate) error
	Rollback(context.Context, GatewayNodeRotationCandidate) error
	Drain(context.Context, NodeRotationDrainRequest) error
}

type NodeRotationDrainRequest struct {
	NodeID             string
	PreviousGeneration uint64
	ActiveGeneration   uint64
	Deadline           time.Time
}

func (request NodeRotationDrainRequest) Validate(now time.Time) error {
	if !transcriptUUIDPattern.MatchString(request.NodeID) || request.PreviousGeneration == 0 {
		return fmt.Errorf("node rotation drain identity is invalid")
	}
	next, err := model.NextGeneration(request.PreviousGeneration)
	if err != nil || next != request.ActiveGeneration {
		return fmt.Errorf("node rotation drain generations are invalid")
	}
	if request.Deadline.IsZero() || !request.Deadline.After(now) {
		return fmt.Errorf("node rotation drain deadline must be in the future")
	}
	return nil
}

type GatewayNodeRotationOptions struct {
	Entropy          io.Reader
	Now              func() time.Time
	NewCertificateID model.UUIDGenerator
}

type GatewayNodeRotationManager struct {
	state   NodeLifecycleStateStore
	secrets NodeCredentialSecretStore
	runtime GatewayNodeRotationRuntime
	options GatewayNodeRotationOptions
}

func NewGatewayNodeRotationManager(
	state NodeLifecycleStateStore,
	secrets NodeCredentialSecretStore,
	runtime GatewayNodeRotationRuntime,
	options GatewayNodeRotationOptions,
) (*GatewayNodeRotationManager, error) {
	if state == nil || secrets == nil || runtime == nil {
		return nil, fmt.Errorf("gateway node rotation requires state, secret, and runtime services")
	}
	if options.Entropy == nil {
		options.Entropy = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewCertificateID == nil {
		options.NewCertificateID = model.NewUUID
	}
	return &GatewayNodeRotationManager{state: state, secrets: secrets, runtime: runtime, options: options}, nil
}

func (manager *GatewayNodeRotationManager) Prepare(
	ctx context.Context,
	request *NodeRotationRequest,
) (NodeRotationGatewayPreparation, error) {
	if manager == nil || manager.state == nil || manager.secrets == nil || manager.runtime == nil || ctx == nil {
		return nil, fmt.Errorf("gateway node rotation manager is incomplete")
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	state, err := manager.state.Load()
	if err != nil {
		return nil, fmt.Errorf("load gateway state for node rotation: %w", err)
	}
	if err := state.Validate(); err != nil {
		return nil, fmt.Errorf("validate gateway state for node rotation: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return nil, fmt.Errorf("node rotation requires gateway state")
	}
	if state.Generation != request.ExpectedGatewayStateGeneration {
		return nil, fmt.Errorf("%w: expected gateway generation %d, current %d",
			ErrNodeRotationConflict, request.ExpectedGatewayStateGeneration, state.Generation)
	}
	node, err := activeGatewayRotationNode(state, request.NodeID, request.CurrentCredentialGeneration)
	if err != nil {
		return nil, err
	}
	if _, findErr := node.FindIdempotencyResult(request.RequestID, canonicalTime(manager.options.Now())); findErr == nil {
		return nil, ErrNodeRotationReplay
	} else if !errors.Is(findErr, model.ErrIdempotencyRecordEvicted) {
		return nil, findErr
	}
	authority, err := (&GatewayJoinBuilder{secrets: manager.secrets}).loadJoinAuthority(state)
	if err != nil {
		return nil, err
	}
	defer authority.destroy()
	preparedAt := canonicalTime(manager.options.Now())
	issued, err := control.IssueNodeControlCertificate(
		manager.options.Entropy, authority.caCertificatePEM, authority.caPrivateKeyPEM,
		[]byte(request.PublicExchange.ControlCSRPEM), request.NodeID, preparedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("issue rotated node control certificate: %w", err)
	}
	defer clear(issued.CertificatePEM)
	certificateID, err := allocateRotationCertificateID(state, manager.options.NewCertificateID)
	if err != nil {
		return nil, err
	}
	candidateState, certificate, err := buildGatewayNodeRotationState(state, node, request, issued, certificateID, preparedAt)
	if err != nil {
		return nil, err
	}
	newReferences, err := NewNodeCredentialReferences(request.NodeID, request.RequestedCredentialGeneration)
	if err != nil {
		return nil, err
	}
	oldReferences, err := gatewayNodeCredentialReferences(state, node)
	if err != nil {
		return nil, err
	}
	candidate := GatewayNodeRotationCandidate{
		Before: state, Candidate: candidateState, RequestID: request.RequestID, NodeID: request.NodeID,
		CurrentGeneration: request.CurrentCredentialGeneration, RequestedGeneration: request.RequestedCredentialGeneration,
		ControlCertificatePEM: append([]byte(nil), issued.CertificatePEM...), PublicExchange: request.PublicExchange,
		shared: request.shared,
	}
	preparation := &GatewayNodeRotationPreparation{
		manager: manager, candidate: candidate, certificate: certificate,
		newReferences: newReferences, oldReferences: oldReferences,
	}
	if err := preparation.stage(ctx); err != nil {
		preparation.Destroy()
		return nil, err
	}
	return preparation, nil
}

func activeGatewayRotationNode(state model.State, nodeID string, generation uint64) (model.Node, error) {
	for _, node := range state.Nodes {
		if node.ID != nodeID {
			continue
		}
		if node.Lifecycle != model.LifecycleActive || node.CredentialGeneration != generation {
			return model.Node{}, fmt.Errorf("%w: node generation is not active", ErrNodeRotationConflict)
		}
		return node, nil
	}
	return model.Node{}, ErrNodeNotFound
}

func allocateRotationCertificateID(state model.State, generator model.UUIDGenerator) (string, error) {
	occupied := make(map[string]struct{}, len(state.Certificates)+len(state.Nodes)+1)
	occupied[state.Host.ID] = struct{}{}
	for _, node := range state.Nodes {
		occupied[node.ID] = struct{}{}
	}
	for _, certificate := range state.Certificates {
		occupied[certificate.ID] = struct{}{}
	}
	return model.AllocateUUID(occupied, generator)
}

func buildGatewayNodeRotationState(
	state model.State,
	node model.Node,
	request *NodeRotationRequest,
	issued control.IssuedNodeCertificate,
	certificateID string,
	preparedAt time.Time,
) (model.State, model.Certificate, error) {
	nextStateGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return model.State{}, model.Certificate{}, err
	}
	rotatedNode, err := node.AdvanceCredentialGeneration()
	if err != nil {
		return model.State{}, model.Certificate{}, err
	}
	resultHash := joinSemanticHash(
		request.RequestID, request.NodeID, fmt.Sprint(request.RequestedCredentialGeneration),
		request.PublicExchange.MaterialHashes[NodeControlCSRHashName],
		request.PublicExchange.MaterialHashes[NodeWireGuardPublicKeyHashName],
		request.PublicExchange.MaterialHashes[NodeRestrictedCredentialHashName],
		request.PublicExchange.MaterialHashes[NodeTunnelCredentialHashName],
	)
	rotatedNode, _, replay, err := rotatedNode.StoreIdempotencyResult(model.IdempotencyRecord{
		RequestID: request.RequestID, Operation: model.OperationRotate, ResultStatus: model.ResultOK,
		ResultHash: resultHash, StateGeneration: nextStateGeneration, RecordedAt: preparedAt,
	}, preparedAt)
	if err != nil || replay {
		return model.State{}, model.Certificate{}, errors.Join(ErrNodeRotationReplay, err)
	}
	newReferences, err := NewNodeCredentialReferences(node.ID, request.RequestedCredentialGeneration)
	if err != nil {
		return model.State{}, model.Certificate{}, err
	}
	standardReference, err := model.NewSecretRef("wireguard-peer", fmt.Sprintf("%s-g%d", node.ID, request.RequestedCredentialGeneration))
	if err != nil {
		return model.State{}, model.Certificate{}, err
	}
	certificateReference, err := model.NewSecretRef("control-cert", fmt.Sprintf("%s-g%d", node.ID, request.RequestedCredentialGeneration))
	if err != nil {
		return model.State{}, model.Certificate{}, err
	}
	certificate := model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: certificateID, Kind: model.CertificateControlNode,
		OwnerKind: "node", OwnerID: node.ID, Fingerprint: joinCertificateFingerprint(issued.Certificate),
		SerialHex: issued.Certificate.SerialNumber.Text(16), Subject: issued.Certificate.Subject.String(),
		SANs: []string{issued.IdentityURI}, NotBefore: issued.Certificate.NotBefore.UTC(), NotAfter: issued.Certificate.NotAfter.UTC(),
		WarningDays: control.ControlWarningDays, Generation: 1, CredentialGeneration: request.RequestedCredentialGeneration,
		CertificateRef: certificateReference.String(),
	}
	candidate := state
	candidate.Generation = nextStateGeneration
	candidate.Nodes = append([]model.Node(nil), state.Nodes...)
	for index := range candidate.Nodes {
		if candidate.Nodes[index].ID == node.ID {
			candidate.Nodes[index] = rotatedNode
		}
	}
	candidate.Transports = append([]model.Transport(nil), state.Transports...)
	for index := range candidate.Transports {
		record := &candidate.Transports[index]
		if record.OwnerKind != model.TargetNode || record.OwnerID != node.ID {
			continue
		}
		record.CredentialGeneration = request.RequestedCredentialGeneration
		switch record.Kind {
		case model.TransportStandard:
			record.CredentialRef = standardReference
			record.PublicKey = request.PublicExchange.WireGuardPublicKey
			record.ConfigHash = joinSemanticHash(node.ID, string(record.Kind), record.PublicKey, node.OverlayIPv4, fmt.Sprint(request.RequestedCredentialGeneration))
		case model.TransportRestricted:
			record.CredentialRef = newReferences.RestrictedCredential
			record.ConfigHash = joinSemanticHash(node.ID, string(record.Kind), record.HandshakeHost, node.OverlayIPv4, fmt.Sprint(request.RequestedCredentialGeneration))
		}
	}
	candidate.Certificates = removeNodeCertificates(state.Certificates, node.ID)
	candidate.Certificates = append(candidate.Certificates, certificate)
	if err := model.ValidateTransition(state, candidate); err != nil {
		return model.State{}, model.Certificate{}, fmt.Errorf("build gateway node rotation transition: %w", err)
	}
	return candidate, certificate, nil
}

type NodeRotationCommitState string

const (
	NodeRotationCommitOld     NodeRotationCommitState = "old"
	NodeRotationCommitNew     NodeRotationCommitState = "new"
	NodeRotationCommitUnknown NodeRotationCommitState = "unknown"
)

type NodeRotationGatewayCommit struct {
	State                  NodeRotationCommitState
	GatewayStateGeneration uint64
}

// GatewayNodeRotationMaterial is public-key material delivered over the
// already-authenticated control channel. It is still non-serializable so PEM
// and secret-store layout cannot accidentally reach command output.
type GatewayNodeRotationMaterial struct {
	RequestID              string
	NodeID                 string
	CredentialGeneration   uint64
	GatewayStateGeneration uint64
	Certificate            model.Certificate
	ControlCertificatePEM  []byte
}

func (GatewayNodeRotationMaterial) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type GatewayNodeRotationPreparation struct {
	mu            sync.Mutex
	manager       *GatewayNodeRotationManager
	candidate     GatewayNodeRotationCandidate
	certificate   model.Certificate
	newReferences NodeCredentialReferences
	oldReferences []model.SecretRef
	owned         []model.SecretRef
	staged        bool
	activated     bool
	committed     bool
	aborted       bool
	destroyed     bool
}

func (preparation *GatewayNodeRotationPreparation) Material() (GatewayNodeRotationMaterial, error) {
	if preparation == nil {
		return GatewayNodeRotationMaterial{}, fmt.Errorf("gateway node rotation preparation is required")
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	if preparation.destroyed || preparation.aborted || !preparation.staged {
		return GatewayNodeRotationMaterial{}, fmt.Errorf("gateway node rotation material is unavailable")
	}
	return GatewayNodeRotationMaterial{
		RequestID: preparation.candidate.RequestID, NodeID: preparation.candidate.NodeID,
		CredentialGeneration:   preparation.candidate.RequestedGeneration,
		GatewayStateGeneration: preparation.candidate.Candidate.Generation,
		Certificate:            preparation.certificate,
		ControlCertificatePEM:  append([]byte(nil), preparation.candidate.ControlCertificatePEM...),
	}, nil
}

func (preparation *GatewayNodeRotationPreparation) stage(ctx context.Context) error {
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	entries := []struct {
		reference model.SecretRef
		content   []byte
	}{{model.SecretRef(preparation.certificate.CertificateRef), preparation.candidate.ControlCertificatePEM}}
	err := preparation.candidate.UseNodeSharedCredentials(func(restrictedCredential, tunnelCredential []byte) error {
		entries = append(entries,
			struct {
				reference model.SecretRef
				content   []byte
			}{preparation.newReferences.RestrictedCredential, append([]byte(nil), restrictedCredential...)},
			struct {
				reference model.SecretRef
				content   []byte
			}{preparation.newReferences.TunnelCredential, append([]byte(nil), tunnelCredential...)},
		)
		return nil
	})
	if err != nil {
		return err
	}
	for index := 1; index < len(entries); index++ {
		defer clear(entries[index].content)
	}
	for _, entry := range entries {
		if err := preparation.manager.secrets.PutIfAbsent(entry.reference, entry.content); err != nil {
			return errors.Join(fmt.Errorf("stage gateway rotation credential %s: %w", entry.reference, err), preparation.deleteOwnedLocked())
		}
		preparation.owned = append(preparation.owned, entry.reference)
	}
	if err := preparation.manager.runtime.Stage(ctx, preparation.candidate); err != nil {
		return errors.Join(fmt.Errorf("stage gateway node rotation runtime: %w", err), preparation.rollbackRuntimeAndOwnedLocked())
	}
	preparation.staged = true
	report, err := preparation.manager.runtime.Check(ctx, preparation.candidate)
	if err == nil {
		err = report.Validate()
	}
	if err != nil {
		preparation.staged = false
		return errors.Join(err, preparation.rollbackRuntimeAndOwnedLocked())
	}
	return nil
}

func (preparation *GatewayNodeRotationPreparation) Activate(ctx context.Context) error {
	if preparation == nil || ctx == nil {
		return fmt.Errorf("gateway node rotation activation is incomplete")
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	if preparation.destroyed || preparation.aborted || !preparation.staged || preparation.committed {
		return fmt.Errorf("gateway node rotation preparation cannot be activated")
	}
	if preparation.activated {
		return nil
	}
	if err := preparation.manager.runtime.ActivateParallel(ctx, preparation.candidate); err != nil {
		return fmt.Errorf("activate parallel gateway node generation: %w", err)
	}
	preparation.activated = true
	return nil
}

func (preparation *GatewayNodeRotationPreparation) Commit(ctx context.Context) (NodeRotationGatewayCommit, error) {
	if preparation == nil || ctx == nil {
		return NodeRotationGatewayCommit{}, fmt.Errorf("gateway node rotation commit is incomplete")
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	if preparation.destroyed || preparation.aborted || !preparation.staged || !preparation.activated {
		return NodeRotationGatewayCommit{}, fmt.Errorf("gateway node rotation preparation is not active")
	}
	if preparation.committed {
		return NodeRotationGatewayCommit{State: NodeRotationCommitNew, GatewayStateGeneration: preparation.candidate.Candidate.Generation}, nil
	}
	before, candidate := preparation.candidate.Before, preparation.candidate.Candidate
	saveErr := preparation.manager.state.Save(before.Generation, candidate)
	if saveErr == nil {
		preparation.committed = true
		preparation.owned = nil
		return NodeRotationGatewayCommit{State: NodeRotationCommitNew, GatewayStateGeneration: candidate.Generation}, nil
	}
	current, loadErr := preparation.manager.state.Load()
	switch {
	case loadErr == nil && reflect.DeepEqual(current, candidate):
		preparation.committed = true
		preparation.owned = nil
		return NodeRotationGatewayCommit{State: NodeRotationCommitNew, GatewayStateGeneration: candidate.Generation},
			fmt.Errorf("%w: new gateway generation is active after save error: %v", ErrNodeRotationCommitUncertain, saveErr)
	case loadErr == nil && reflect.DeepEqual(current, before):
		rollbackErr := preparation.rollbackRuntimeAndOwnedLocked()
		preparation.aborted = true
		return NodeRotationGatewayCommit{State: NodeRotationCommitOld, GatewayStateGeneration: before.Generation},
			errors.Join(fmt.Errorf("commit gateway node rotation: %w", saveErr), rollbackErr)
	default:
		return NodeRotationGatewayCommit{State: NodeRotationCommitUnknown},
			errors.Join(ErrNodeRotationCommitUncertain, saveErr, loadErr)
	}
}

func (preparation *GatewayNodeRotationPreparation) Abort(ctx context.Context) error {
	if preparation == nil || ctx == nil {
		return fmt.Errorf("gateway node rotation abort is incomplete")
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	if preparation.committed {
		return fmt.Errorf("cannot abort committed gateway node rotation")
	}
	if preparation.aborted {
		return nil
	}
	preparation.aborted = true
	return preparation.rollbackRuntimeAndOwnedLocked()
}

func (preparation *GatewayNodeRotationPreparation) Drain(ctx context.Context, deadline time.Time) error {
	if preparation == nil || ctx == nil {
		return fmt.Errorf("gateway node rotation drain is incomplete")
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	if !preparation.committed || preparation.destroyed {
		return fmt.Errorf("gateway node rotation must commit before drain")
	}
	request := NodeRotationDrainRequest{
		NodeID: preparation.candidate.NodeID, PreviousGeneration: preparation.candidate.CurrentGeneration,
		ActiveGeneration: preparation.candidate.RequestedGeneration, Deadline: deadline,
	}
	if err := request.Validate(time.Now()); err != nil {
		return err
	}
	runtimeErr := preparation.manager.runtime.Drain(ctx, request)
	credentialErr := deleteGatewayNodeCredentials(preparation.manager.secrets, preparation.oldReferences)
	if err := errors.Join(runtimeErr, credentialErr); err != nil {
		return errors.Join(ErrNodeRotationCleanupPending, err)
	}
	return nil
}

func (preparation *GatewayNodeRotationPreparation) rollbackRuntimeAndOwnedLocked() error {
	runtimeErr := preparation.manager.runtime.Rollback(context.Background(), preparation.candidate)
	return errors.Join(runtimeErr, preparation.deleteOwnedLocked())
}

func (preparation *GatewayNodeRotationPreparation) deleteOwnedLocked() error {
	var failures []error
	for index := len(preparation.owned) - 1; index >= 0; index-- {
		if _, err := preparation.manager.secrets.Delete(preparation.owned[index]); err != nil {
			failures = append(failures, err)
		}
	}
	preparation.owned = nil
	return errors.Join(failures...)
}

func (preparation *GatewayNodeRotationPreparation) Destroy() {
	if preparation == nil {
		return
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	if preparation.destroyed {
		return
	}
	clear(preparation.candidate.ControlCertificatePEM)
	preparation.candidate.ControlCertificatePEM = nil
	preparation.destroyed = true
}

type NodeRotationGatewayPreparation interface {
	Material() (GatewayNodeRotationMaterial, error)
	Activate(context.Context) error
	Commit(context.Context) (NodeRotationGatewayCommit, error)
	Abort(context.Context) error
	Drain(context.Context, time.Time) error
	Destroy()
}

type NodeRotationGateway interface {
	Prepare(context.Context, *NodeRotationRequest) (NodeRotationGatewayPreparation, error)
}

type NodeRotationNodeCandidate struct {
	Before                model.State
	Candidate             model.State
	RequestID             string
	NodeID                string
	CurrentGeneration     uint64
	RequestedGeneration   uint64
	ControlCertificatePEM []byte
	Installation          NodeCredentialInstallation
}

func (NodeRotationNodeCandidate) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type NodeRotationNodeRuntime interface {
	Stage(context.Context, NodeRotationNodeCandidate) error
	Check(context.Context, NodeRotationNodeCandidate) (NodeRotationReadinessReport, error)
	ActivateParallel(context.Context, NodeRotationNodeCandidate) error
	Rollback(context.Context, NodeRotationNodeCandidate) error
	Drain(context.Context, NodeRotationDrainRequest) error
}

type NodeRotationOptions struct {
	Entropy         io.Reader
	Now             func() time.Time
	NewUUID         model.UUIDGenerator
	WireGuardRunner wireguard.Runner
	DrainTimeout    time.Duration
}

type NodeRotationWorkflow struct {
	state       NodeJoinStateStore
	secrets     NodeCredentialSecretStore
	credentials *NodeCredentialProvisioner
	gateway     NodeRotationGateway
	runtime     NodeRotationNodeRuntime
	options     NodeRotationOptions
}

func NewNodeRotationWorkflow(
	state NodeJoinStateStore,
	secrets NodeCredentialSecretStore,
	gateway NodeRotationGateway,
	runtime NodeRotationNodeRuntime,
	options NodeRotationOptions,
) (*NodeRotationWorkflow, error) {
	if state == nil || secrets == nil || gateway == nil || runtime == nil {
		return nil, fmt.Errorf("node rotation requires state, secret, gateway, and runtime services")
	}
	if options.Entropy == nil {
		options.Entropy = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.NewUUID == nil {
		options.NewUUID = model.NewUUID
	}
	if options.DrainTimeout == 0 {
		options.DrainTimeout = NodeRotationDrainTimeout
	}
	if options.DrainTimeout < time.Second || options.DrainTimeout > 5*time.Minute {
		return nil, fmt.Errorf("node rotation drain timeout must be between one second and five minutes")
	}
	credentials, err := NewNodeCredentialProvisioner(secrets, NodeCredentialRuntime{
		Entropy: options.Entropy, WireGuardRunner: options.WireGuardRunner,
	})
	if err != nil {
		return nil, err
	}
	return &NodeRotationWorkflow{
		state: state, secrets: secrets, credentials: credentials,
		gateway: gateway, runtime: runtime, options: options,
	}, nil
}

type NodeRotationPlan struct {
	NodeID                         string
	NodeName                       string
	ActiveTransport                model.TransportKind
	ExpectedLocalStateGeneration   uint64
	NextLocalStateGeneration       uint64
	ExpectedGatewayStateGeneration uint64
	CurrentCredentialGeneration    uint64
	RequestedCredentialGeneration  uint64

	beforeRaw []byte
}

func (NodeRotationPlan) String() string   { return nodeRotationPlanMarker }
func (NodeRotationPlan) GoString() string { return nodeRotationPlanMarker }
func (NodeRotationPlan) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

func (workflow *NodeRotationWorkflow) Plan() (NodeRotationPlan, error) {
	if workflow == nil || workflow.state == nil {
		return NodeRotationPlan{}, fmt.Errorf("node rotation workflow is incomplete")
	}
	state, node, err := loadLocalRotationState(workflow.state)
	if err != nil {
		return NodeRotationPlan{}, err
	}
	if _, pending, err := state.PendingNodeOperation(); err != nil {
		return NodeRotationPlan{}, err
	} else if pending {
		return NodeRotationPlan{}, model.ErrPendingRequest
	}
	next, err := model.NextGeneration(node.CredentialGeneration)
	if err != nil {
		return NodeRotationPlan{}, err
	}
	pendingStateGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return NodeRotationPlan{}, err
	}
	finalStateGeneration, err := model.NextGeneration(pendingStateGeneration)
	if err != nil {
		return NodeRotationPlan{}, err
	}
	raw, err := model.EncodeState(state)
	if err != nil {
		return NodeRotationPlan{}, err
	}
	return NodeRotationPlan{
		NodeID: node.ID, NodeName: node.Name, ActiveTransport: node.ActiveTransport,
		ExpectedLocalStateGeneration:   state.Generation,
		NextLocalStateGeneration:       finalStateGeneration,
		ExpectedGatewayStateGeneration: node.Gateway.LastKnownGatewayGeneration,
		CurrentCredentialGeneration:    node.CredentialGeneration, RequestedCredentialGeneration: next,
		beforeRaw: raw,
	}, nil
}

type NodeRotationResult struct {
	NodeID                       string
	NodeName                     string
	ActiveTransport              model.TransportKind
	PreviousCredentialGeneration uint64
	CredentialGeneration         uint64
	GatewayStateGeneration       uint64
	LocalStateGeneration         uint64
	NodeRuntimeCleanupNeeded     bool
	GatewayCleanupNeeded         bool
	CredentialCleanupNeeded      bool
	CommitConfirmationNeeded     bool
}

func (result NodeRotationResult) OutputResult() output.Result {
	status := output.StatusOK
	if result.NodeRuntimeCleanupNeeded || result.GatewayCleanupNeeded || result.CredentialCleanupNeeded || result.CommitConfirmationNeeded {
		status = output.StatusPending
	}
	public := output.NewResult("node.rotate", status, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": result.LocalStateGeneration,
		"credential_generation": result.CredentialGeneration,
		"active":                string(result.ActiveTransport),
	})
	public.ResourceIDs["node_id"] = result.NodeID
	if result.NodeRuntimeCleanupNeeded {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "repair_node_rotation_runtime", Message: "Run repair to finish draining the previous node credential generation.",
			ResourceIDs: map[string]string{"node_id": result.NodeID},
		})
	}
	if result.GatewayCleanupNeeded {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "repair_gateway_rotation", Message: "Run repair to finish draining the previous gateway-side node generation.",
			ResourceIDs: map[string]string{"node_id": result.NodeID},
		})
	}
	if result.CredentialCleanupNeeded {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "repair_node_rotation_credentials", Message: "Run repair to remove retained previous-generation node credentials.",
			ResourceIDs: map[string]string{"node_id": result.NodeID},
		})
	}
	if result.CommitConfirmationNeeded {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "inspect_node_rotation", Message: "Inspect gateway and node generations before retrying this rotation request.",
			ResourceIDs: map[string]string{"node_id": result.NodeID},
		})
	}
	return public
}

func (workflow *NodeRotationWorkflow) Apply(ctx context.Context, plan NodeRotationPlan) (NodeRotationResult, error) {
	if workflow == nil || workflow.state == nil || workflow.credentials == nil || workflow.gateway == nil || workflow.runtime == nil || ctx == nil {
		return NodeRotationResult{}, fmt.Errorf("node rotation workflow is incomplete")
	}
	current, node, err := loadLocalRotationState(workflow.state)
	if err != nil {
		return NodeRotationResult{}, err
	}
	currentRaw, err := model.EncodeState(current)
	if err != nil {
		return NodeRotationResult{}, err
	}
	if !sameNodeRotationPlan(plan, current, node, currentRaw) {
		return NodeRotationResult{}, ErrNodeRotationStale
	}
	if err := ctx.Err(); err != nil {
		return NodeRotationResult{}, err
	}
	startedAt := canonicalTime(workflow.options.Now())
	started, operation, resumed, err := current.BeginNodeOperation(model.OperationIntent{
		Type: model.OperationRotate, TargetKind: string(model.TargetNode), TargetID: node.ID,
		StepNames: []string{"generate", "gateway_stage", "node_stage", "activate", "commit", "drain"},
	}, startedAt, workflow.options.NewUUID)
	if err != nil {
		return NodeRotationResult{}, err
	}
	if resumed {
		return NodeRotationResult{}, model.ErrPendingRequest
	}
	if err := saveNodeRotationState(workflow.state, current, started, false); err != nil {
		return NodeRotationResult{}, err
	}
	installation, err := workflow.credentials.Provision(ctx, node.ID, plan.RequestedCredentialGeneration)
	if err != nil {
		return NodeRotationResult{}, workflow.failBeforeCommit(started, operation.RequestID, err)
	}
	keepNewCredentials := false
	defer func() {
		if !keepNewCredentials {
			_ = workflow.credentials.Rollback(context.Background(), installation)
		}
	}()
	shared, err := workflow.credentials.SharedCredentialPayload(installation)
	if err != nil {
		rollbackErr := workflow.credentials.Rollback(context.Background(), installation)
		return NodeRotationResult{}, errors.Join(workflow.failBeforeCommit(started, operation.RequestID, err), rollbackErr)
	}
	defer shared.Destroy()
	request, err := newNodeRotationRequest(
		operation.RequestID, plan.ExpectedGatewayStateGeneration, plan.CurrentCredentialGeneration,
		installation, shared,
	)
	if err != nil {
		rollbackErr := workflow.credentials.Rollback(context.Background(), installation)
		return NodeRotationResult{}, errors.Join(workflow.failBeforeCommit(started, operation.RequestID, err), rollbackErr)
	}
	defer request.Destroy()
	preparation, err := workflow.gateway.Prepare(ctx, request)
	if err != nil {
		rollbackErr := workflow.credentials.Rollback(context.Background(), installation)
		return NodeRotationResult{}, errors.Join(workflow.failBeforeCommit(started, operation.RequestID, err), rollbackErr)
	}
	defer preparation.Destroy()
	material, err := preparation.Material()
	if err != nil {
		return NodeRotationResult{}, workflow.compensateBeforeCommit(started, operation.RequestID, installation, preparation, NodeRotationNodeCandidate{}, err)
	}
	defer clear(material.ControlCertificatePEM)
	candidate, oldReferences, err := workflow.buildLocalCandidate(started, operation, installation, material)
	if err != nil {
		return NodeRotationResult{}, workflow.compensateBeforeCommit(started, operation.RequestID, installation, preparation, NodeRotationNodeCandidate{}, err)
	}
	localCertificateReference := model.SecretRef(material.Certificate.CertificateRef)
	if err := workflow.secrets.PutIfAbsent(localCertificateReference, material.ControlCertificatePEM); err != nil {
		return NodeRotationResult{}, workflow.compensateBeforeCommit(started, operation.RequestID, installation, preparation, candidate,
			fmt.Errorf("stage rotated local control certificate: %w", err))
	}
	defer func() {
		if !keepNewCredentials {
			_, _ = workflow.secrets.Delete(localCertificateReference)
		}
	}()
	if err := workflow.runtime.Stage(ctx, candidate); err != nil {
		return NodeRotationResult{}, workflow.compensateBeforeCommit(started, operation.RequestID, installation, preparation, candidate, err)
	}
	report, err := workflow.runtime.Check(ctx, candidate)
	if err == nil {
		err = report.Validate()
	}
	if err != nil {
		return NodeRotationResult{}, workflow.compensateBeforeCommit(started, operation.RequestID, installation, preparation, candidate, err)
	}
	if err := preparation.Activate(ctx); err != nil {
		return NodeRotationResult{}, workflow.compensateBeforeCommit(started, operation.RequestID, installation, preparation, candidate, err)
	}
	if err := workflow.runtime.ActivateParallel(ctx, candidate); err != nil {
		return NodeRotationResult{}, workflow.compensateBeforeCommit(started, operation.RequestID, installation, preparation, candidate, err)
	}
	report, err = workflow.runtime.Check(ctx, candidate)
	if err == nil {
		err = report.Validate()
	}
	if err != nil {
		return NodeRotationResult{}, workflow.compensateBeforeCommit(started, operation.RequestID, installation, preparation, candidate, err)
	}
	commit, commitErr := preparation.Commit(ctx)
	switch commit.State {
	case NodeRotationCommitOld:
		return NodeRotationResult{}, workflow.compensateBeforeCommit(started, operation.RequestID, installation, preparation, candidate, commitErr)
	case NodeRotationCommitUnknown:
		keepNewCredentials = true
		return NodeRotationResult{}, errors.Join(ErrNodeRotationCommitUncertain, commitErr)
	case NodeRotationCommitNew:
		// Once the gateway publishes the new generation, rolling local runtime
		// back would create a known cross-host split. Retain and finish new.
		keepNewCredentials = true
	default:
		return NodeRotationResult{}, workflow.compensateBeforeCommit(started, operation.RequestID, installation, preparation, candidate,
			fmt.Errorf("gateway returned invalid node rotation commit state %q", commit.State))
	}
	if commit.GatewayStateGeneration != candidate.Candidate.Nodes[0].Gateway.LastKnownGatewayGeneration {
		return NodeRotationResult{}, ErrNodeRotationCommitUncertain
	}
	result := NodeRotationResult{
		NodeID: node.ID, NodeName: node.Name, ActiveTransport: node.ActiveTransport,
		PreviousCredentialGeneration: plan.CurrentCredentialGeneration,
		CredentialGeneration:         plan.RequestedCredentialGeneration,
		GatewayStateGeneration:       commit.GatewayStateGeneration,
		LocalStateGeneration:         candidate.Candidate.Generation,
		CommitConfirmationNeeded:     commitErr != nil,
	}
	if err := saveNodeRotationState(workflow.state, started, candidate.Candidate, true); err != nil {
		result.CommitConfirmationNeeded = true
		return result, errors.Join(ErrNodeRotationCommitUncertain, commitErr, err)
	}
	drainStart := time.Now()
	drainRequest := NodeRotationDrainRequest{
		NodeID: node.ID, PreviousGeneration: plan.CurrentCredentialGeneration,
		ActiveGeneration: plan.RequestedCredentialGeneration, Deadline: drainStart.Add(workflow.options.DrainTimeout),
	}
	drainContext, cancelDrain := context.WithDeadline(ctx, drainRequest.Deadline)
	defer cancelDrain()
	nodeDrainResult := make(chan error, 1)
	gatewayDrainResult := make(chan error, 1)
	go func() { nodeDrainResult <- workflow.runtime.Drain(drainContext, drainRequest) }()
	go func() { gatewayDrainResult <- preparation.Drain(drainContext, drainRequest.Deadline) }()
	nodeDrainErr := <-nodeDrainResult
	gatewayDrainErr := <-gatewayDrainResult
	result.NodeRuntimeCleanupNeeded = nodeDrainErr != nil
	result.GatewayCleanupNeeded = gatewayDrainErr != nil
	credentialErr := deleteGatewayNodeCredentials(workflow.secrets, oldReferences)
	result.CredentialCleanupNeeded = credentialErr != nil
	cleanupErr := errors.Join(nodeDrainErr, gatewayDrainErr, credentialErr)
	if cleanupErr != nil {
		return result, errors.Join(ErrNodeRotationCleanupPending, commitErr, cleanupErr)
	}
	return result, commitErr
}

func loadLocalRotationState(stateStore NodeJoinStateStore) (model.State, model.Node, error) {
	state, err := stateStore.Load()
	if err != nil {
		return model.State{}, model.Node{}, fmt.Errorf("load local node rotation state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return model.State{}, model.Node{}, fmt.Errorf("validate local node rotation state: %w", err)
	}
	if state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Gateway == nil ||
		state.Nodes[0].Lifecycle != model.LifecycleActive {
		return model.State{}, model.Node{}, fmt.Errorf("node rotation requires one joined active private node")
	}
	return state, state.Nodes[0], nil
}

func sameNodeRotationPlan(plan NodeRotationPlan, state model.State, node model.Node, raw []byte) bool {
	next, err := model.NextGeneration(node.CredentialGeneration)
	pendingStateGeneration, pendingErr := model.NextGeneration(state.Generation)
	finalStateGeneration, finalErr := model.NextGeneration(pendingStateGeneration)
	return err == nil && pendingErr == nil && finalErr == nil &&
		plan.NextLocalStateGeneration == finalStateGeneration && len(plan.beforeRaw) != 0 && bytes.Equal(plan.beforeRaw, raw) &&
		plan.NodeID == node.ID && plan.NodeName == node.Name && plan.ActiveTransport == node.ActiveTransport &&
		plan.ExpectedLocalStateGeneration == state.Generation &&
		plan.ExpectedGatewayStateGeneration == node.Gateway.LastKnownGatewayGeneration &&
		plan.CurrentCredentialGeneration == node.CredentialGeneration && plan.RequestedCredentialGeneration == next
}

func (workflow *NodeRotationWorkflow) buildLocalCandidate(
	started model.State,
	operation model.Operation,
	installation NodeCredentialInstallation,
	material GatewayNodeRotationMaterial,
) (NodeRotationNodeCandidate, []model.SecretRef, error) {
	node := started.Nodes[0]
	if material.RequestID != operation.RequestID || material.NodeID != node.ID ||
		material.CredentialGeneration != installation.CredentialGeneration || material.GatewayStateGeneration == 0 {
		return NodeRotationNodeCandidate{}, nil, fmt.Errorf("gateway node rotation material context is invalid")
	}
	leaf, err := workflow.validateRotatedControlMaterial(started, installation, material)
	if err != nil {
		return NodeRotationNodeCandidate{}, nil, err
	}
	rotated, err := node.AdvanceCredentialGeneration()
	if err != nil {
		return NodeRotationNodeCandidate{}, nil, err
	}
	trust := *node.Gateway
	trust.LastKnownGatewayGeneration = material.GatewayStateGeneration
	trust.PendingRequestID = ""
	rotated.Gateway = &trust
	candidate := started
	candidate.Generation, err = model.NextGeneration(started.Generation)
	if err != nil {
		return NodeRotationNodeCandidate{}, nil, err
	}
	candidate.Nodes = []model.Node{rotated}
	candidate.Transports = append([]model.Transport(nil), started.Transports...)
	for index := range candidate.Transports {
		record := &candidate.Transports[index]
		if record.OwnerKind != model.TargetNode || record.OwnerID != node.ID {
			continue
		}
		record.CredentialGeneration = installation.CredentialGeneration
		switch record.Kind {
		case model.TransportStandard:
			record.CredentialRef = installation.References.WireGuardPrivateKey
			record.PublicKey = installation.PublicExchange.WireGuardPublicKey
			record.ConfigHash = joinSemanticHash(node.ID, string(record.Kind), record.PublicKey, node.OverlayIPv4, fmt.Sprint(installation.CredentialGeneration))
		case model.TransportRestricted:
			record.CredentialRef = installation.References.RestrictedCredential
			record.ConfigHash = joinSemanticHash(node.ID, string(record.Kind), record.HandshakeHost, node.OverlayIPv4, fmt.Sprint(installation.CredentialGeneration))
		}
	}
	certificateReference := model.SecretRef(material.Certificate.CertificateRef)
	localCertificate := localJoinedCertificate(
		material.Certificate.ID, node.ID, model.CertificateControlNode, certificateReference,
		installation.References.ControlPrivateKey, leaf, []string{"urn:vpnctl:node:" + node.ID},
	)
	localCertificate.CredentialGeneration = installation.CredentialGeneration
	candidate.Certificates = removeNodeCertificates(started.Certificates, node.ID)
	candidate.Certificates = append(candidate.Certificates, localCertificate)
	completedAt := canonicalTime(workflow.options.Now())
	candidate.Operations = append([]model.Operation(nil), started.Operations...)
	for index := range candidate.Operations {
		if candidate.Operations[index].RequestID != operation.RequestID {
			continue
		}
		updated := candidate.Operations[index]
		for _, step := range updated.Steps {
			updated, err = updated.TransitionStep(step.Name, model.OperationCompleted, completedAt)
			if err != nil {
				return NodeRotationNodeCandidate{}, nil, err
			}
		}
		updated, err = updated.Transition(model.OperationCompleted, completedAt, "")
		if err != nil {
			return NodeRotationNodeCandidate{}, nil, err
		}
		candidate.Operations[index] = updated
	}
	if err := model.ValidateTransition(started, candidate); err != nil {
		return NodeRotationNodeCandidate{}, nil, fmt.Errorf("build local node rotation transition: %w", err)
	}
	oldReferences, err := localNodeRotationCredentialReferences(started, node)
	if err != nil {
		return NodeRotationNodeCandidate{}, nil, err
	}
	return NodeRotationNodeCandidate{
		Before: started, Candidate: candidate, RequestID: operation.RequestID, NodeID: node.ID,
		CurrentGeneration: node.CredentialGeneration, RequestedGeneration: installation.CredentialGeneration,
		ControlCertificatePEM: append([]byte(nil), material.ControlCertificatePEM...), Installation: installation,
	}, oldReferences, nil
}

func (workflow *NodeRotationWorkflow) validateRotatedControlMaterial(
	state model.State,
	installation NodeCredentialInstallation,
	material GatewayNodeRotationMaterial,
) (*x509.Certificate, error) {
	var caRecord *model.Certificate
	for index := range state.Certificates {
		if state.Certificates[index].Kind == model.CertificateControlCA {
			copy := state.Certificates[index]
			caRecord = &copy
		}
	}
	if caRecord == nil || state.Nodes[0].Gateway == nil {
		return nil, fmt.Errorf("local control CA is unavailable")
	}
	caPEM, err := workflow.secrets.Get(model.SecretRef(caRecord.CertificateRef))
	if err != nil {
		return nil, fmt.Errorf("read local control CA: %w", err)
	}
	defer clear(caPEM)
	ca, err := parseSingleJoinCertificate(caPEM)
	if err != nil || !ca.IsCA || ca.CheckSignatureFrom(ca) != nil || joinCertificateFingerprint(ca) != caRecord.Fingerprint {
		return nil, fmt.Errorf("local control CA differs from authoritative metadata")
	}
	trusted := false
	for _, fingerprint := range state.Nodes[0].Gateway.ControlCAFingerprints {
		if fingerprint == caRecord.Fingerprint {
			trusted = true
		}
	}
	if !trusted {
		return nil, fmt.Errorf("local control CA is not pinned by gateway trust")
	}
	leaf, err := parseSingleJoinCertificate(material.ControlCertificatePEM)
	if err != nil || joinCertificateFingerprint(leaf) != material.Certificate.Fingerprint {
		return nil, fmt.Errorf("rotated control certificate metadata mismatch")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: workflow.options.Now().UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("verify rotated node control certificate: %w", err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "urn:vpnctl:node:"+state.Nodes[0].ID ||
		len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return nil, fmt.Errorf("rotated node control certificate identity is invalid")
	}
	block, rest := pem.Decode([]byte(installation.PublicExchange.ControlCSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("rotated node control CSR is invalid")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, fmt.Errorf("rotated node control CSR is invalid")
	}
	leafPublic, leafErr := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	csrPublic, csrErr := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if leafErr != nil || csrErr != nil || !bytes.Equal(leafPublic, csrPublic) {
		return nil, fmt.Errorf("rotated node certificate does not match the new local private key")
	}
	expectedReference, err := model.NewSecretRef("control-cert", fmt.Sprintf("%s-g%d", state.Nodes[0].ID, installation.CredentialGeneration))
	if err != nil || material.Certificate.CertificateRef != expectedReference.String() ||
		material.Certificate.OwnerID != state.Nodes[0].ID || material.Certificate.Kind != model.CertificateControlNode ||
		material.Certificate.CredentialGeneration != installation.CredentialGeneration {
		return nil, fmt.Errorf("rotated node control certificate reference is invalid")
	}
	return leaf, nil
}

func localNodeRotationCredentialReferences(state model.State, node model.Node) ([]model.SecretRef, error) {
	references, err := NewNodeCredentialReferences(node.ID, node.CredentialGeneration)
	if err != nil {
		return nil, err
	}
	unique := make(map[model.SecretRef]struct{}, len(references.Values())+1)
	for _, reference := range references.Values() {
		unique[reference] = struct{}{}
	}
	for _, certificate := range state.Certificates {
		if certificate.Kind == model.CertificateControlNode && certificate.OwnerID == node.ID {
			unique[model.SecretRef(certificate.CertificateRef)] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(unique))
	for reference := range unique {
		ordered = append(ordered, reference.String())
	}
	sort.Strings(ordered)
	result := make([]model.SecretRef, 0, len(ordered))
	for _, reference := range ordered {
		result = append(result, model.SecretRef(reference))
	}
	return result, nil
}

func saveNodeRotationState(store NodeJoinStateStore, before, candidate model.State, retryKnownOld bool) error {
	for attempt := 0; attempt < 2; attempt++ {
		saveErr := store.Save(before.Generation, candidate)
		if saveErr == nil {
			return nil
		}
		current, loadErr := store.Load()
		switch {
		case loadErr == nil && reflect.DeepEqual(current, candidate):
			return nil
		case loadErr == nil && reflect.DeepEqual(current, before):
			if retryKnownOld && attempt == 0 {
				continue
			}
			return saveErr
		default:
			return errors.Join(ErrNodeRotationCommitUncertain, saveErr, loadErr)
		}
	}
	return ErrNodeRotationCommitUncertain
}

func (workflow *NodeRotationWorkflow) compensateBeforeCommit(
	started model.State,
	requestID string,
	installation NodeCredentialInstallation,
	preparation NodeRotationGatewayPreparation,
	candidate NodeRotationNodeCandidate,
	cause error,
) error {
	var runtimeErr error
	if candidate.NodeID != "" {
		runtimeErr = workflow.runtime.Rollback(context.Background(), candidate)
	}
	gatewayErr := preparation.Abort(context.Background())
	credentialErr := workflow.credentials.Rollback(context.Background(), installation)
	stateErr := workflow.failBeforeCommit(started, requestID, cause)
	return errors.Join(cause, runtimeErr, gatewayErr, credentialErr, stateErr)
}

func (workflow *NodeRotationWorkflow) failBeforeCommit(started model.State, requestID string, cause error) error {
	failed := started
	next, err := model.NextGeneration(started.Generation)
	if err != nil {
		return errors.Join(cause, err)
	}
	failed.Generation = next
	failed.Nodes = append([]model.Node(nil), started.Nodes...)
	trust := *failed.Nodes[0].Gateway
	trust.PendingRequestID = ""
	failed.Nodes[0].Gateway = &trust
	failed.Operations = append([]model.Operation(nil), started.Operations...)
	failedAt := canonicalTime(workflow.options.Now())
	for index := range failed.Operations {
		if failed.Operations[index].RequestID != requestID {
			continue
		}
		updated := failed.Operations[index]
		for _, step := range updated.Steps {
			updated, err = updated.TransitionStep(step.Name, model.OperationFailed, failedAt)
			if err != nil {
				return errors.Join(cause, err)
			}
		}
		updated, err = updated.Transition(model.OperationFailed, failedAt, "node_rotation_failed")
		if err != nil {
			return errors.Join(cause, err)
		}
		failed.Operations[index] = updated
	}
	if err := model.ValidateTransition(started, failed); err != nil {
		return errors.Join(cause, err)
	}
	return errors.Join(cause, saveNodeRotationState(workflow.state, started, failed, true))
}
