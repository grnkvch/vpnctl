package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

var (
	ErrJoinConflict  = errors.New("node join conflicts with authoritative state")
	ErrJoinNotReady  = errors.New("node join candidate is not ready")
	ErrJoinUncertain = errors.New("node join commit outcome is uncertain")
)

// JoinReadinessReport is intentionally exhaustive: enrollment is permitted
// only when both transports plus control and tunnel paths have been checked on
// the staged gateway/node pair. Inactive transport readiness does not imply an
// automatic fallback; it only proves that a later manual switch is possible.
type JoinReadinessReport struct {
	Gateway    bool
	Control    bool
	Standard   bool
	Restricted bool
	Tunnel     bool
}

func (report JoinReadinessReport) Validate() error {
	if !report.Gateway || !report.Control || !report.Standard || !report.Restricted || !report.Tunnel {
		return fmt.Errorf("%w: gateway=%t control=%t standard=%t restricted=%t tunnel=%t",
			ErrJoinNotReady, report.Gateway, report.Control, report.Standard, report.Restricted, report.Tunnel)
	}
	return nil
}

type GatewayJoinReadinessChecker interface {
	Check(context.Context, GatewayJoinCandidate) (JoinReadinessReport, error)
}

// GatewayJoinCandidate is a non-serializable, pre-commit view supplied to the
// cross-host readiness adapter. Private node control/WireGuard keys are never
// present. The only shared symmetric values are callback-scoped.
type GatewayJoinCandidate struct {
	State                      model.State
	Node                       model.Node
	ControlCACertificatePEM    []byte
	ControlCertificatePEM      []byte
	EnrollmentPublicKeyPEM     []byte
	GatewayWireGuardPublicKey  string
	restrictedServerCredential []byte
	shared                     *output.Secret
}

func (candidate GatewayJoinCandidate) UseNodeSharedCredentials(callback func(restrictedCredential, tunnelCredential []byte) error) error {
	if candidate.shared == nil || callback == nil {
		return fmt.Errorf("join candidate shared credentials are unavailable")
	}
	return useRetainedJoinShared(candidate.shared, callback)
}

func (candidate GatewayJoinCandidate) RestrictedServerCredential() []byte {
	return append([]byte(nil), candidate.restrictedServerCredential...)
}

func (GatewayJoinCandidate) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type GatewayJoinRuntime struct {
	Entropy         io.Reader
	Now             func() time.Time
	WireGuardRunner wireguard.Runner
	Readiness       GatewayJoinReadinessChecker
}

type GatewayJoinBuilder struct {
	invites *InviteManager
	secrets NodeCredentialSecretStore
	runtime GatewayJoinRuntime
}

func NewGatewayJoinBuilder(invites *InviteManager, secrets NodeCredentialSecretStore, runtime GatewayJoinRuntime) (*GatewayJoinBuilder, error) {
	if invites == nil || invites.state == nil || secrets == nil || runtime.Readiness == nil {
		return nil, fmt.Errorf("gateway join requires invite, secret, and readiness services")
	}
	if runtime.Entropy == nil {
		runtime.Entropy = rand.Reader
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	return &GatewayJoinBuilder{invites: invites, secrets: secrets, runtime: runtime}, nil
}

func (builder *GatewayJoinBuilder) PrepareAuthorizedEnrollment(
	ctx context.Context,
	authorization InviteAuthorization,
	publicRequest PublicEnrollmentRequest,
) (PreparedEnrollmentArtifacts, error) {
	if builder == nil || builder.invites == nil || builder.secrets == nil || ctx == nil {
		return PreparedEnrollmentArtifacts{}, ErrPublicEnrollmentUnavailable
	}
	request, err := DecodeNodeJoinRequest(publicRequest.Payload)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, fmt.Errorf("%w: invalid join payload", ErrPublicEnrollmentRejected)
	}
	defer request.Destroy()
	if request.PublicExchange.CredentialGeneration != 1 {
		return PreparedEnrollmentArtifacts{}, fmt.Errorf("%w: initial join requires credential generation 1", ErrPublicEnrollmentRejected)
	}
	state, err := builder.invites.loadGatewayState()
	if err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}
	if state.Generation != authorization.ExpectedStateGeneration {
		return PreparedEnrollmentArtifacts{}, fmt.Errorf("%w: gateway generation changed", ErrJoinConflict)
	}
	if state.HandshakeHost == nil {
		return PreparedEnrollmentArtifacts{}, fmt.Errorf("gateway handshake host is unavailable")
	}
	if err := validateJoinIdentityAvailable(state, authorization.NodeName, request.PublicExchange.NodeID); err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}
	presetNames, selectors, policyHash, err := routing.ResolveEffectiveAssignment(state.Presets, request.Presets)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, fmt.Errorf("%w: %v", ErrPublicEnrollmentRejected, err)
	}
	allocator, err := model.AddressAllocatorFromState(state)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}
	overlayIPv4, err := allocator.Allocate(model.TargetNode, request.PublicExchange.NodeID)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}
	gatewayOverlayIPv4, err := control.GatewayOverlayIPv4(state.Host.NodeCIDR)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}
	preparedAt := canonicalTime(builder.runtime.Now())
	if preparedAt.Before(state.Host.InitializedAt) {
		return PreparedEnrollmentArtifacts{}, fmt.Errorf("gateway clock precedes host initialization")
	}

	authority, err := builder.loadJoinAuthority(state)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}
	defer authority.destroy()
	issued, err := control.IssueNodeControlCertificate(
		builder.runtime.Entropy, authority.caCertificatePEM, authority.caPrivateKeyPEM,
		[]byte(request.PublicExchange.ControlCSRPEM), request.PublicExchange.NodeID, preparedAt,
	)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, fmt.Errorf("issue node control certificate: %w", err)
	}
	defer clear(issued.CertificatePEM)

	gatewayWireGuardPublicKey, restrictedUpstream, err := builder.loadGatewayTransportMaterial(ctx)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}
	defer clear(restrictedUpstream)
	shared, err := retainJoinShared(request)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}
	keepShared := false
	defer func() {
		if !keepShared {
			shared.Destroy()
		}
	}()

	resources, assignment, err := buildGatewayJoinResources(gatewayJoinResourceInput{
		state: state, authorization: authorization, request: request, presetNames: presetNames,
		selectors: selectors, policyHash: policyHash, overlayIPv4: overlayIPv4,
		gatewayOverlayIPv4: gatewayOverlayIPv4, preparedAt: preparedAt,
		controlCA: authority.caRecord, controlCACertificatePEM: authority.caCertificatePEM,
		issued: issued, enrollmentPublicKeyPEM: authority.enrollmentPublicKeyPEM,
		gatewayWireGuardPublicKey: gatewayWireGuardPublicKey, restrictedUpstream: restrictedUpstream,
	})
	if err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}
	candidateState := state
	candidateState.Generation = assignment.GatewayStateGeneration
	appendGatewayJoinResources(&candidateState, resources)
	if err := candidateState.Validate(); err != nil {
		return PreparedEnrollmentArtifacts{}, fmt.Errorf("validate prepared join candidate: %w", err)
	}
	candidate := GatewayJoinCandidate{
		State: candidateState, Node: resources.node,
		ControlCACertificatePEM:    append([]byte(nil), authority.caCertificatePEM...),
		ControlCertificatePEM:      append([]byte(nil), issued.CertificatePEM...),
		EnrollmentPublicKeyPEM:     append([]byte(nil), authority.enrollmentPublicKeyPEM...),
		GatewayWireGuardPublicKey:  gatewayWireGuardPublicKey,
		restrictedServerCredential: append([]byte(nil), restrictedUpstream...), shared: &shared,
	}
	report, err := builder.runtime.Readiness.Check(ctx, candidate)
	destroyGatewayJoinCandidate(&candidate)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, fmt.Errorf("%w: %v", ErrJoinNotReady, err)
	}
	if err := report.Validate(); err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}

	response, err := encodeNodeJoinResponse(
		assignment, authority.caCertificatePEM, issued.CertificatePEM, authority.enrollmentPublicKeyPEM,
		gatewayWireGuardPublicKey, restrictedUpstream,
	)
	if err != nil {
		return PreparedEnrollmentArtifacts{}, err
	}
	assignmentHash, err := assignment.SHA256()
	if err != nil {
		response.Destroy()
		return PreparedEnrollmentArtifacts{}, err
	}
	publicHashes, err := request.PublicExchange.TranscriptHashes()
	if err != nil {
		response.Destroy()
		return PreparedEnrollmentArtifacts{}, err
	}
	committer := &gatewayJoinCommitter{
		invites: builder.invites, secrets: builder.secrets, authorization: authorization,
		resources: resources, assignment: assignment, shared: shared,
		controlCertificate: append([]byte(nil), issued.CertificatePEM...),
	}
	keepShared = true
	return PreparedEnrollmentArtifacts{
		NodeID: request.PublicExchange.NodeID, Transport: request.Transport,
		Presets: append([]string{}, presetNames...), PublicKeyHashes: publicHashes,
		AssignmentSHA256: assignmentHash, ResponseData: response, Committer: committer,
	}, nil
}

type gatewayJoinAuthority struct {
	caRecord               model.Certificate
	caCertificatePEM       []byte
	caPrivateKeyPEM        []byte
	enrollmentPublicKeyPEM []byte
}

func (authority *gatewayJoinAuthority) destroy() {
	clear(authority.caCertificatePEM)
	clear(authority.caPrivateKeyPEM)
	clear(authority.enrollmentPublicKeyPEM)
}

func (builder *GatewayJoinBuilder) loadJoinAuthority(state model.State) (gatewayJoinAuthority, error) {
	var records []model.Certificate
	for _, record := range state.Certificates {
		if record.Kind == model.CertificateControlCA {
			records = append(records, record)
		}
	}
	if len(records) != 1 || state.EnrollmentIdentity == nil {
		return gatewayJoinAuthority{}, fmt.Errorf("join requires exactly one active control CA and enrollment identity")
	}
	record := records[0]
	caPEM, err := builder.secrets.Get(model.SecretRef(record.CertificateRef))
	if err != nil {
		return gatewayJoinAuthority{}, fmt.Errorf("read control CA certificate: %w", err)
	}
	caKey, err := builder.secrets.Get(record.PrivateKeyRef)
	if err != nil {
		clear(caPEM)
		return gatewayJoinAuthority{}, fmt.Errorf("read control CA private key: %w", err)
	}
	enrollmentPublic, err := builder.secrets.Get(model.SecretRef(state.EnrollmentIdentity.PublicKeyRef))
	if err != nil {
		clear(caPEM)
		clear(caKey)
		return gatewayJoinAuthority{}, fmt.Errorf("read enrollment public key: %w", err)
	}
	certificate, err := parseSingleJoinCertificate(caPEM)
	if err != nil || !certificate.IsCA || joinCertificateFingerprint(certificate) != record.Fingerprint {
		clear(caPEM)
		clear(caKey)
		clear(enrollmentPublic)
		return gatewayJoinAuthority{}, fmt.Errorf("control CA material differs from authoritative metadata")
	}
	publicKey, err := parseEnrollmentPublicKey(enrollmentPublic)
	if err != nil {
		clear(caPEM)
		clear(caKey)
		clear(enrollmentPublic)
		return gatewayJoinAuthority{}, err
	}
	fingerprint, err := enrollmentPublicKeyFingerprint(publicKey)
	if err != nil || fingerprint != state.EnrollmentIdentity.Fingerprint {
		clear(caPEM)
		clear(caKey)
		clear(enrollmentPublic)
		return gatewayJoinAuthority{}, fmt.Errorf("enrollment public key differs from authoritative fingerprint")
	}
	return gatewayJoinAuthority{
		caRecord: record, caCertificatePEM: caPEM, caPrivateKeyPEM: caKey,
		enrollmentPublicKeyPEM: enrollmentPublic,
	}, nil
}

func (builder *GatewayJoinBuilder) loadGatewayTransportMaterial(ctx context.Context) (string, []byte, error) {
	privateKey, err := builder.secrets.Get(transport.GatewayStandardCredentialRef)
	if err != nil {
		return "", nil, fmt.Errorf("read gateway standard credential: %w", err)
	}
	defer clear(privateKey)
	publicKey, err := wireguard.PublicKey(ctx, builder.runtime.WireGuardRunner, strings.TrimSpace(string(privateKey)))
	if err != nil {
		return "", nil, err
	}
	restrictedBytes, err := builder.secrets.Get(transport.GatewayRestrictedCredentialRef)
	if err != nil {
		return "", nil, fmt.Errorf("read gateway restricted credential: %w", err)
	}
	defer clear(restrictedBytes)
	restrictedSecret, err := restricted.DecodeGatewaySecret(restrictedBytes)
	if err != nil {
		return "", nil, err
	}
	upstream, err := encodeRestrictedUpstreamCredential(restrictedSecret.ShadowsocksPassword)
	return publicKey, upstream, err
}

type gatewayJoinResourceInput struct {
	state                     model.State
	authorization             InviteAuthorization
	request                   *NodeJoinRequest
	presetNames               []string
	selectors                 []model.Selector
	policyHash                string
	overlayIPv4               string
	gatewayOverlayIPv4        string
	preparedAt                time.Time
	controlCA                 model.Certificate
	controlCACertificatePEM   []byte
	issued                    control.IssuedNodeCertificate
	enrollmentPublicKeyPEM    []byte
	gatewayWireGuardPublicKey string
	restrictedUpstream        []byte
}

type gatewayJoinResources struct {
	node          model.Node
	policy        *model.Policy
	transports    []model.Transport
	certificate   model.Certificate
	restrictedRef model.SecretRef
	tunnelRef     model.SecretRef
}

func buildGatewayJoinResources(input gatewayJoinResourceInput) (gatewayJoinResources, NodeJoinAssignment, error) {
	references, err := NewNodeCredentialReferences(input.request.PublicExchange.NodeID, 1)
	if err != nil {
		return gatewayJoinResources{}, NodeJoinAssignment{}, err
	}
	standardRef, err := model.NewSecretRef("wireguard-peer", input.request.PublicExchange.NodeID+"-g1")
	if err != nil {
		return gatewayJoinResources{}, NodeJoinAssignment{}, err
	}
	node := model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: input.request.PublicExchange.NodeID,
		Name: input.authorization.NodeName, Lifecycle: model.LifecycleActive,
		OverlayIPv4: input.overlayIPv4, CredentialGeneration: 1,
		AssignedPresets: append([]string{}, input.presetNames...), ActiveTransport: input.request.Transport,
		IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: input.preparedAt,
	}
	standardState, restrictedState := model.TransportStandby, model.TransportStandby
	if input.request.Transport == model.TransportStandard {
		standardState = model.TransportActive
	} else {
		restrictedState = model.TransportActive
	}
	transports := []model.Transport{
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: node.ID,
			Kind: model.TransportStandard, State: standardState, Provider: "wireguard", Protocol: model.ProtocolUDP,
			Port: transport.StandardUDPPort, CredentialGeneration: 1, CredentialRef: standardRef,
			PublicKey:  input.request.PublicExchange.WireGuardPublicKey,
			ConfigHash: joinSemanticHash(node.ID, string(model.TransportStandard), input.request.PublicExchange.WireGuardPublicKey, input.overlayIPv4),
		},
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: node.ID,
			Kind: model.TransportRestricted, State: restrictedState, Provider: restricted.ProviderName, Protocol: model.ProtocolTCP,
			Port: restricted.TCPPort, CredentialGeneration: 1, CredentialRef: references.RestrictedCredential,
			HandshakeHost: input.state.HandshakeHost.Hostname,
			ConfigHash:    joinSemanticHash(node.ID, string(model.TransportRestricted), input.state.HandshakeHost.Hostname, input.overlayIPv4),
		},
	}
	var policy *model.Policy
	if len(input.presetNames) != 0 {
		value := model.Policy{
			SchemaVersion: model.ResourceSchemaVersion, TargetKind: model.TargetNode, TargetID: node.ID,
			PresetNames: append([]string{}, input.presetNames...), Selectors: append([]model.Selector{}, input.selectors...),
			EffectiveHash: input.policyHash, Generation: 1,
		}
		policy = &value
	}
	certificateRef, err := model.NewSecretRef("control-cert", node.ID+"-g1")
	if err != nil {
		return gatewayJoinResources{}, NodeJoinAssignment{}, err
	}
	certificate := model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: node.ID, Kind: model.CertificateControlNode,
		OwnerKind: "node", OwnerID: node.ID, Fingerprint: joinCertificateFingerprint(input.issued.Certificate),
		SerialHex: input.issued.Certificate.SerialNumber.Text(16), Subject: input.issued.Certificate.Subject.String(),
		SANs: []string{input.issued.IdentityURI}, NotBefore: input.issued.Certificate.NotBefore.UTC(),
		NotAfter: input.issued.Certificate.NotAfter.UTC(), WarningDays: control.ControlWarningDays,
		Generation: 1, CredentialGeneration: 1, CertificateRef: certificateRef.String(),
	}
	nextGeneration, err := model.NextGeneration(input.state.Generation)
	if err != nil {
		return gatewayJoinResources{}, NodeJoinAssignment{}, err
	}
	assignment := NodeJoinAssignment{
		SchemaVersion: NodeJoinSchemaVersion, NodeID: node.ID, NodeName: node.Name, OverlayIPv4: node.OverlayIPv4,
		CredentialGeneration: 1, ActiveTransport: node.ActiveTransport, Presets: append([]string{}, node.AssignedPresets...),
		Selectors: append([]model.Selector{}, input.selectors...), CreatedAt: input.preparedAt,
		GatewayPublicIPv4: input.state.Host.PublicIPv4, NodeCIDR: input.state.Host.NodeCIDR,
		GatewayOverlayIPv4: input.gatewayOverlayIPv4, GatewayStateGeneration: nextGeneration,
		ControlProtocol:               input.authorization.ControlProtocol,
		EnrollmentFingerprint:         input.authorization.EnrollmentFingerprint,
		ControlCAFingerprint:          input.controlCA.Fingerprint,
		ControlCertificateFingerprint: certificate.Fingerprint,
		HandshakeHostCandidateID:      input.state.HandshakeHost.CandidateID,
		HandshakeHost:                 input.state.HandshakeHost.Hostname,
		HandshakeHostListVersion:      input.state.HandshakeHost.ListVersion,
		HandshakeHostSelectedAt:       input.state.HandshakeHost.SelectedAt,
		MaterialHashes: map[string]string{
			joinControlCAHashName:           sha256Hex(input.controlCACertificatePEM),
			joinControlCertificateHashName:  sha256Hex(input.issued.CertificatePEM),
			joinEnrollmentPublicKeyHashName: sha256Hex(input.enrollmentPublicKeyPEM),
			joinGatewayWireGuardKeyHashName: sha256Hex([]byte(input.gatewayWireGuardPublicKey)),
			joinRestrictedUpstreamHashName:  sha256Hex(input.restrictedUpstream),
		},
	}
	if len(input.presetNames) != 0 {
		assignment.PolicyEffectiveHash = input.policyHash
	}
	if err := assignment.Validate(); err != nil {
		return gatewayJoinResources{}, NodeJoinAssignment{}, err
	}
	return gatewayJoinResources{
		node: node, policy: policy, transports: transports, certificate: certificate,
		restrictedRef: references.RestrictedCredential, tunnelRef: references.TunnelCredential,
	}, assignment, nil
}

func appendGatewayJoinResources(candidate *model.State, resources gatewayJoinResources) {
	candidate.Nodes = append(append([]model.Node{}, candidate.Nodes...), resources.node)
	candidate.Transports = append(append([]model.Transport{}, candidate.Transports...), resources.transports...)
	candidate.Certificates = append(append([]model.Certificate{}, candidate.Certificates...), resources.certificate)
	if resources.policy != nil {
		candidate.Policies = append(append([]model.Policy{}, candidate.Policies...), *resources.policy)
	}
}

type gatewayJoinCommitter struct {
	mu                 sync.Mutex
	invites            *InviteManager
	secrets            NodeCredentialSecretStore
	authorization      InviteAuthorization
	resources          gatewayJoinResources
	assignment         NodeJoinAssignment
	shared             output.Secret
	controlCertificate []byte
	owned              []model.SecretRef
	committed          bool
	destroyed          bool
}

func (committer *gatewayJoinCommitter) Commit(ctx context.Context, replayHash string) error {
	if committer == nil || ctx == nil {
		return ErrPublicEnrollmentUnavailable
	}
	committer.mu.Lock()
	defer committer.mu.Unlock()
	if committer.destroyed || committer.committed {
		return ErrPublicEnrollmentRejected
	}
	entries := []struct {
		reference model.SecretRef
		content   []byte
	}{{reference: model.SecretRef(committer.resources.certificate.CertificateRef), content: committer.controlCertificate}}
	if err := useRetainedJoinShared(&committer.shared, func(restrictedCredential, tunnelCredential []byte) error {
		entries = append(entries,
			struct {
				reference model.SecretRef
				content   []byte
			}{committer.resources.restrictedRef, append([]byte(nil), restrictedCredential...)},
			struct {
				reference model.SecretRef
				content   []byte
			}{committer.resources.tunnelRef, append([]byte(nil), tunnelCredential...)},
		)
		return nil
	}); err != nil {
		return err
	}
	for index := 1; index < len(entries); index++ {
		defer clear(entries[index].content)
	}
	for _, entry := range entries {
		if err := committer.secrets.PutIfAbsent(entry.reference, entry.content); err != nil {
			rollbackErr := committer.rollbackOwned()
			return errors.Join(fmt.Errorf("stage join credential %s: %w", entry.reference, err), rollbackErr)
		}
		committer.owned = append(committer.owned, entry.reference)
	}
	_, err := committer.invites.commitAuthorizedMutation(ctx, committer.authorization, replayHash, func(_ model.State, candidate *model.State) error {
		if candidate.Generation != committer.assignment.GatewayStateGeneration {
			return fmt.Errorf("prepared join generation changed")
		}
		appendGatewayJoinResources(candidate, committer.resources)
		return nil
	})
	if err != nil {
		current, loadErr := committer.invites.loadGatewayState()
		if loadErr == nil && committer.joinWasCommittedInState(current, replayHash) {
			committer.committed = true
			committer.owned = nil
			return nil
		}
		if loadErr == nil && !gatewayStateContainsNode(current, committer.resources.node.ID) {
			return errors.Join(err, committer.rollbackOwned())
		}
		if loadErr != nil || current.Generation > committer.authorization.ExpectedStateGeneration {
			committer.owned = nil
			return errors.Join(ErrJoinUncertain, err, loadErr)
		}
		return errors.Join(err, committer.rollbackOwned())
	}
	committer.committed = true
	committer.owned = nil
	return nil
}

func (committer *gatewayJoinCommitter) joinWasCommittedInState(state model.State, replayHash string) bool {
	inviteIndex := inviteIndex(state.Invites, committer.authorization.InviteID)
	if inviteIndex < 0 || state.Invites[inviteIndex].State != model.InviteConsumed || state.Invites[inviteIndex].ConsumptionHash != replayHash {
		return false
	}
	for _, node := range state.Nodes {
		if node.ID == committer.resources.node.ID {
			return node.Name == committer.resources.node.Name && node.OverlayIPv4 == committer.resources.node.OverlayIPv4 &&
				node.CredentialGeneration == 1 && node.ActiveTransport == committer.resources.node.ActiveTransport
		}
	}
	return false
}

func gatewayStateContainsNode(state model.State, nodeID string) bool {
	for _, node := range state.Nodes {
		if node.ID == nodeID {
			return true
		}
	}
	return false
}

func (committer *gatewayJoinCommitter) rollbackOwned() error {
	var rollbackErrors []error
	for index := len(committer.owned) - 1; index >= 0; index-- {
		if _, err := committer.secrets.Delete(committer.owned[index]); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("rollback join credential %s: %w", committer.owned[index], err))
		}
	}
	committer.owned = nil
	return errors.Join(rollbackErrors...)
}

func (committer *gatewayJoinCommitter) Destroy() {
	if committer == nil {
		return
	}
	committer.mu.Lock()
	defer committer.mu.Unlock()
	if committer.destroyed {
		return
	}
	committer.shared.Destroy()
	clear(committer.controlCertificate)
	committer.controlCertificate = nil
	committer.destroyed = true
}

func retainJoinShared(request *NodeJoinRequest) (output.Secret, error) {
	var retained output.Secret
	err := request.UseSharedCredentials(func(restrictedCredential, tunnelCredential []byte) error {
		encoded, err := json.Marshal(nodeSharedCredentialWire{
			SchemaVersion:        NodeSharedExchangeSchemaVersion,
			RestrictedCredential: string(restrictedCredential), TunnelCredential: string(tunnelCredential),
		})
		if err != nil {
			return err
		}
		defer clear(encoded)
		retained, err = output.NewSecret(encoded)
		return err
	})
	return retained, err
}

func useRetainedJoinShared(secret *output.Secret, callback func(restrictedCredential, tunnelCredential []byte) error) error {
	if secret == nil || callback == nil {
		return fmt.Errorf("retained join shared credentials are unavailable")
	}
	return secret.Use(func(encoded []byte) error {
		var wire nodeSharedCredentialWire
		if err := control.DecodeRPCPayload(json.RawMessage(encoded), &wire); err != nil || wire.SchemaVersion != NodeSharedExchangeSchemaVersion {
			return fmt.Errorf("retained join shared credentials are invalid")
		}
		restrictedCredential := []byte(wire.RestrictedCredential)
		tunnelCredential := []byte(wire.TunnelCredential)
		defer clear(restrictedCredential)
		defer clear(tunnelCredential)
		return callback(restrictedCredential, tunnelCredential)
	})
}

func validateJoinIdentityAvailable(state model.State, nodeName, nodeID string) error {
	for _, node := range state.Nodes {
		if node.ID == nodeID {
			return fmt.Errorf("%w: node ID %s already exists", ErrJoinConflict, nodeID)
		}
		if node.Lifecycle != model.LifecycleDeleted && strings.EqualFold(node.Name, nodeName) {
			return fmt.Errorf("%w: node name %s already exists", ErrJoinConflict, nodeName)
		}
	}
	return nil
}

func parseSingleJoinCertificate(encoded []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("certificate must be one PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func joinCertificateFingerprint(certificate *x509.Certificate) string {
	if certificate == nil {
		return ""
	}
	digest := sha256.Sum256(certificate.Raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func joinSemanticHash(parts ...string) string {
	sorted := append([]string{}, parts...)
	sort.Strings(sorted)
	digest := sha256.Sum256([]byte(strings.Join(sorted, "\x00")))
	return hex.EncodeToString(digest[:])
}

func destroyGatewayJoinCandidate(candidate *GatewayJoinCandidate) {
	clear(candidate.ControlCACertificatePEM)
	clear(candidate.ControlCertificatePEM)
	clear(candidate.EnrollmentPublicKeyPEM)
	clear(candidate.restrictedServerCredential)
	candidate.ControlCACertificatePEM = nil
	candidate.ControlCertificatePEM = nil
	candidate.EnrollmentPublicKeyPEM = nil
	candidate.restrictedServerCredential = nil
}

var _ AuthorizedEnrollmentBuilder = (*GatewayJoinBuilder)(nil)
var _ PreparedEnrollmentCommitter = (*gatewayJoinCommitter)(nil)
