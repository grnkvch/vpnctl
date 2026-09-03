package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

type NodeJoinStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

// NodeJoinExchangeResult distinguishes a proven pre-commit rejection from a
// lost/invalid response after the gateway may have committed. Only the former
// permits automatic removal of freshly generated node credentials.
type NodeJoinExchangeResult struct {
	Response       []byte
	CommitPossible bool
}

type NodeJoinExchanger interface {
	Exchange(context.Context, string, *output.Secret) (NodeJoinExchangeResult, error)
}

type NodeJoinRuntime struct {
	Entropy         io.Reader
	Now             func() time.Time
	NewNodeID       model.UUIDGenerator
	WireGuardRunner wireguard.Runner
}

type NodeJoinWorkflow struct {
	state       NodeJoinStateStore
	secrets     NodeCredentialSecretStore
	credentials *NodeCredentialProvisioner
	exchanger   NodeJoinExchanger
	runtime     NodeJoinRuntime
}

type NodeJoinResult struct {
	NodeID                 string
	NodeName               string
	OverlayIPv4            string
	ActiveTransport        model.TransportKind
	Presets                []string
	GatewayStateGeneration uint64
	LocalStateGeneration   uint64
	ReplayHash             string
}

func NewNodeJoinWorkflow(
	state NodeJoinStateStore,
	secrets NodeCredentialSecretStore,
	exchanger NodeJoinExchanger,
	runtime NodeJoinRuntime,
) (*NodeJoinWorkflow, error) {
	if state == nil || secrets == nil || exchanger == nil {
		return nil, fmt.Errorf("node join requires state, secret, and exchange services")
	}
	if runtime.Entropy == nil {
		runtime.Entropy = rand.Reader
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	if runtime.NewNodeID == nil {
		runtime.NewNodeID = model.NewUUID
	}
	credentials, err := NewNodeCredentialProvisioner(secrets, NodeCredentialRuntime{
		Entropy: runtime.Entropy, WireGuardRunner: runtime.WireGuardRunner,
	})
	if err != nil {
		return nil, err
	}
	return &NodeJoinWorkflow{
		state: state, secrets: secrets, credentials: credentials, exchanger: exchanger, runtime: runtime,
	}, nil
}

func (workflow *NodeJoinWorkflow) Join(
	ctx context.Context,
	tokenSecret *output.Secret,
	transportKind model.TransportKind,
	presets []string,
) (NodeJoinResult, error) {
	if workflow == nil || ctx == nil || tokenSecret == nil {
		return NodeJoinResult{}, fmt.Errorf("node join input is incomplete")
	}
	state, err := workflow.state.Load()
	if err != nil {
		return NodeJoinResult{}, fmt.Errorf("load node state: %w", err)
	}
	if err := validateFreshNodeJoinState(state); err != nil {
		return NodeJoinResult{}, err
	}
	var token *DecodedInviteToken
	err = tokenSecret.Use(func(encoded []byte) error {
		var decodeErr error
		token, decodeErr = DecodeInviteToken(encoded)
		return decodeErr
	})
	if err != nil {
		return NodeJoinResult{}, err
	}
	defer token.Destroy()
	now := workflow.runtime.Now().UTC()
	if now.Before(token.IssuedAt.Add(-EnrollmentClockSkew)) || !now.Before(token.ExpiresAt) {
		return NodeJoinResult{}, ErrInviteExpired
	}
	nodeID, err := model.AllocateUUID(map[string]struct{}{state.Host.ID: {}}, workflow.runtime.NewNodeID)
	if err != nil {
		return NodeJoinResult{}, fmt.Errorf("allocate node identity: %w", err)
	}
	installation, err := workflow.credentials.Provision(ctx, nodeID, 1)
	if err != nil {
		return NodeJoinResult{}, err
	}
	rollbackGenerated := true
	defer func() {
		if rollbackGenerated {
			_ = workflow.credentials.Rollback(context.Background(), installation)
		}
	}()
	shared, err := workflow.credentials.SharedCredentialPayload(installation)
	if err != nil {
		return NodeJoinResult{}, err
	}
	defer shared.Destroy()
	joinPayload, err := EncodeNodeJoinRequest(transportKind, presets, installation.PublicExchange, shared)
	if err != nil {
		return NodeJoinResult{}, err
	}
	defer joinPayload.Destroy()
	nodeNonce, err := workflow.newNonce()
	if err != nil {
		return NodeJoinResult{}, err
	}
	requestBody, err := encodeNodePublicJoinRequest(tokenSecret, nodeNonce, joinPayload)
	if err != nil {
		return NodeJoinResult{}, err
	}
	defer requestBody.Destroy()
	exchange, err := workflow.exchanger.Exchange(ctx, token.GatewayEndpoint, requestBody)
	defer clear(exchange.Response)
	if err != nil {
		if exchange.CommitPossible {
			rollbackGenerated = false
			return NodeJoinResult{}, errors.Join(ErrJoinUncertain, err)
		}
		return NodeJoinResult{}, err
	}
	if !exchange.CommitPossible {
		return NodeJoinResult{}, fmt.Errorf("join exchanger returned a response without a committed gateway outcome")
	}
	// A successful public response is emitted only after the gateway commit.
	// From here on all local material is retained on failure for task 9.5
	// reconciliation; deleting it could make the committed identity unusable.
	rollbackGenerated = false
	publicResponse, err := DecodePublicEnrollmentResponse(exchange.Response, PurposeEnroll)
	if err != nil {
		return NodeJoinResult{}, errors.Join(ErrJoinUncertain, err)
	}
	material, err := DecodeNodeJoinResponse(publicResponse.Data)
	if err != nil {
		return NodeJoinResult{}, errors.Join(ErrJoinUncertain, err)
	}
	defer material.Destroy()
	var result NodeJoinResult
	err = material.Use(func(values NodeJoinResponseValues) error {
		verified, err := workflow.verifyAndBuildLocalJoin(
			state, *token, nodeNonce, installation, transportKind, presets, publicResponse, material.Assignment, values,
		)
		if err != nil {
			return err
		}
		for index := range verified.entries {
			defer clear(verified.entries[index].content)
		}
		for _, entry := range verified.entries {
			if err := workflow.secrets.PutIfAbsent(entry.reference, entry.content); err != nil {
				return fmt.Errorf("stage joined node material %s: %w", entry.reference, err)
			}
		}
		if err := workflow.state.Save(state.Generation, verified.state); err != nil {
			return fmt.Errorf("persist joined node state: %w", err)
		}
		result = verified.result
		return nil
	})
	if err != nil {
		return NodeJoinResult{}, errors.Join(ErrJoinUncertain, err)
	}
	return result, nil
}

func (workflow *NodeJoinWorkflow) newNonce() ([EnrollmentNonceBytes]byte, error) {
	var nonce [EnrollmentNonceBytes]byte
	if _, err := io.ReadFull(workflow.runtime.Entropy, nonce[:]); err != nil || allZero(nonce[:]) {
		return nonce, fmt.Errorf("generate node join nonce")
	}
	return nonce, nil
}

func encodeNodePublicJoinRequest(token *output.Secret, nonce [EnrollmentNonceBytes]byte, payload *output.Secret) (*output.Secret, error) {
	if token == nil || payload == nil || allZero(nonce[:]) {
		return nil, fmt.Errorf("public join request input is incomplete")
	}
	nonceText, err := CanonicalPublicEnrollmentNonce(nonce)
	if err != nil {
		return nil, err
	}
	var encoded []byte
	err = token.Use(func(tokenBytes []byte) error {
		return payload.Use(func(payloadBytes []byte) error {
			var object map[string]json.RawMessage
			if err := control.DecodeRPCPayload(json.RawMessage(payloadBytes), &object); err != nil {
				return err
			}
			wire := publicEnrollmentWireRequest{
				SchemaVersion: PublicEnrollmentSchemaVersion, Purpose: PurposeEnroll,
				Token: string(tokenBytes), NodeNonce: nonceText,
				Payload: append(json.RawMessage(nil), payloadBytes...),
			}
			defer clear(wire.Payload)
			var marshalErr error
			encoded, marshalErr = json.Marshal(wire)
			return marshalErr
		})
	})
	if err != nil {
		clear(encoded)
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > control.RPCMaximumRequestBytes {
		clear(encoded)
		return nil, fmt.Errorf("public join request exceeds %d bytes", control.RPCMaximumRequestBytes)
	}
	secret, err := output.NewSecret(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

type localJoinEntry struct {
	reference model.SecretRef
	content   []byte
}

type verifiedLocalJoin struct {
	state   model.State
	entries []localJoinEntry
	result  NodeJoinResult
}

func (workflow *NodeJoinWorkflow) verifyAndBuildLocalJoin(
	current model.State,
	token DecodedInviteToken,
	nodeNonce [EnrollmentNonceBytes]byte,
	installation NodeCredentialInstallation,
	requestedTransport model.TransportKind,
	requestedPresets []string,
	publicResponse PublicEnrollmentResponse,
	assignment NodeJoinAssignment,
	values NodeJoinResponseValues,
) (verifiedLocalJoin, error) {
	if err := validateNodeJoinAssignmentContext(token, installation, requestedTransport, requestedPresets, assignment); err != nil {
		return verifiedLocalJoin{}, err
	}
	assignmentHash, err := assignment.SHA256()
	if err != nil {
		return verifiedLocalJoin{}, err
	}
	publicHashes, err := installation.PublicExchange.TranscriptHashes()
	if err != nil {
		return verifiedLocalJoin{}, err
	}
	gatewayNonceBytes, err := decodeCanonicalBase64(publicResponse.GatewayNonce)
	if err != nil || len(gatewayNonceBytes) != EnrollmentNonceBytes {
		clear(gatewayNonceBytes)
		return verifiedLocalJoin{}, ErrEnrollmentSignature
	}
	var gatewayNonce [EnrollmentNonceBytes]byte
	copy(gatewayNonce[:], gatewayNonceBytes)
	clear(gatewayNonceBytes)
	expectedTranscript, err := NewEnrollmentTranscript(
		PurposeEnroll, token.InviteID, token.GatewayEndpoint, installation.NodeID,
		token.IssuedAt, token.ExpiresAt, nodeNonce, gatewayNonce,
		assignment.ActiveTransport, assignment.Presets, publicHashes, assignmentHash,
	)
	if err != nil {
		return verifiedLocalJoin{}, err
	}
	replayHash, err := VerifyEnrollmentTranscript(
		publicResponse.SignedTranscript, expectedTranscript, values.EnrollmentPublicKeyPEM,
		token.EnrollmentFingerprint, workflow.runtime.Now(),
	)
	if err != nil {
		return verifiedLocalJoin{}, err
	}
	ca, leaf, err := validateJoinedControlMaterial(
		values.ControlCACertificatePEM, values.ControlCertificatePEM,
		[]byte(installation.PublicExchange.ControlCSRPEM), assignment, workflow.runtime.Now(),
	)
	if err != nil {
		return verifiedLocalJoin{}, err
	}
	if string(values.GatewayWireGuardPublicKey) != assignmentGatewayWireGuardPublicKey(values) {
		return verifiedLocalJoin{}, fmt.Errorf("gateway WireGuard material is not canonical")
	}

	caReference := model.SecretRef("control-cert:gateway-ca-g1")
	leafReference := model.SecretRef("control-cert:" + assignment.NodeID + "-g1")
	enrollmentReference := model.SecretRef("enrollment-public:gateway")
	restrictedReference := model.SecretRef("restricted-server:gateway-g1")
	trust := &model.GatewayTrust{
		PublicIPv4: assignment.GatewayPublicIPv4, NodeCIDR: assignment.NodeCIDR,
		GatewayOverlayIPv4: assignment.GatewayOverlayIPv4, ControlProtocol: assignment.ControlProtocol,
		EnrollmentFingerprint: assignment.EnrollmentFingerprint, EnrollmentPublicKeyRef: enrollmentReference.String(),
		ControlCAFingerprints:         []string{assignment.ControlCAFingerprint},
		ControlCACertificateRefs:      []string{caReference.String()},
		StandardPublicKey:             string(values.GatewayWireGuardPublicKey),
		RestrictedServerCredentialRef: restrictedReference,
		LastKnownGatewayGeneration:    assignment.GatewayStateGeneration,
	}
	node := model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: assignment.NodeID, Name: assignment.NodeName,
		Lifecycle: model.LifecycleActive, OverlayIPv4: assignment.OverlayIPv4, CredentialGeneration: 1,
		AssignedPresets: append([]string{}, assignment.Presets...), ActiveTransport: assignment.ActiveTransport,
		IdempotencyRecords: []model.IdempotencyRecord{}, Gateway: trust, CreatedAt: assignment.CreatedAt,
	}
	standardState, restrictedState := model.TransportStandby, model.TransportStandby
	if assignment.ActiveTransport == model.TransportStandard {
		standardState = model.TransportActive
	} else {
		restrictedState = model.TransportActive
	}
	transports := []model.Transport{
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: node.ID,
			Kind: model.TransportStandard, State: standardState, Provider: "wireguard", Protocol: model.ProtocolUDP,
			Port: transport.StandardUDPPort, CredentialGeneration: 1,
			CredentialRef: installation.References.WireGuardPrivateKey,
			PublicKey:     installation.PublicExchange.WireGuardPublicKey,
			ConfigHash:    joinSemanticHash(node.ID, string(model.TransportStandard), installation.PublicExchange.WireGuardPublicKey, assignment.OverlayIPv4),
		},
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: node.ID,
			Kind: model.TransportRestricted, State: restrictedState, Provider: "mihomo", Protocol: model.ProtocolTCP,
			Port: 8443, CredentialGeneration: 1, CredentialRef: installation.References.RestrictedCredential,
			HandshakeHost: assignment.HandshakeHost,
			ConfigHash:    joinSemanticHash(node.ID, string(model.TransportRestricted), assignment.HandshakeHost, assignment.OverlayIPv4),
		},
	}
	caRecord := localJoinedCertificate(current.Host.ID, current.Host.ID, model.CertificateControlCA, caReference, "", ca, []string{})
	leafRecord := localJoinedCertificate(
		assignment.NodeID, assignment.NodeID, model.CertificateControlNode, leafReference,
		installation.References.ControlPrivateKey, leaf, []string{"urn:vpnctl:node:" + assignment.NodeID},
	)
	leafRecord.CredentialGeneration = 1
	candidate := current
	candidate.Generation, err = model.NextGeneration(current.Generation)
	if err != nil {
		return verifiedLocalJoin{}, err
	}
	candidate.Nodes = []model.Node{node}
	candidate.Transports = transports
	candidate.Certificates = []model.Certificate{caRecord, leafRecord}
	candidate.HandshakeHost = &model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: assignment.HandshakeHostListVersion,
		CandidateID: assignment.HandshakeHostCandidateID, Hostname: assignment.HandshakeHost,
		SelectedAt: assignment.HandshakeHostSelectedAt,
	}
	if len(assignment.Presets) != 0 {
		candidate.Policies = []model.Policy{{
			SchemaVersion: model.ResourceSchemaVersion, TargetKind: model.TargetNode, TargetID: node.ID,
			PresetNames: append([]string{}, assignment.Presets...), Selectors: append([]model.Selector{}, assignment.Selectors...),
			EffectiveHash: assignment.PolicyEffectiveHash, Generation: 1,
		}}
	}
	if err := model.ValidateTransition(current, candidate); err != nil {
		return verifiedLocalJoin{}, fmt.Errorf("build node join transition: %w", err)
	}
	entries := []localJoinEntry{
		{reference: caReference, content: append([]byte(nil), values.ControlCACertificatePEM...)},
		{reference: leafReference, content: append([]byte(nil), values.ControlCertificatePEM...)},
		{reference: enrollmentReference, content: append([]byte(nil), values.EnrollmentPublicKeyPEM...)},
		{reference: restrictedReference, content: append([]byte(nil), values.RestrictedServerCredential...)},
	}
	return verifiedLocalJoin{
		state: candidate, entries: entries,
		result: NodeJoinResult{
			NodeID: node.ID, NodeName: node.Name, OverlayIPv4: node.OverlayIPv4,
			ActiveTransport: node.ActiveTransport, Presets: append([]string{}, node.AssignedPresets...),
			GatewayStateGeneration: assignment.GatewayStateGeneration,
			LocalStateGeneration:   candidate.Generation, ReplayHash: replayHash,
		},
	}, nil
}

func validateFreshNodeJoinState(state model.State) error {
	if err := state.Validate(); err != nil {
		return err
	}
	if state.Host.Role != model.RoleNode || len(state.Nodes) != 0 || len(state.Transports) != 0 ||
		len(state.Policies) != 0 || len(state.Certificates) != 0 {
		return fmt.Errorf("join requires an initialized, not-yet-enrolled node host")
	}
	return nil
}

func validateNodeJoinAssignmentContext(
	token DecodedInviteToken,
	installation NodeCredentialInstallation,
	requestedTransport model.TransportKind,
	requestedPresets []string,
	assignment NodeJoinAssignment,
) error {
	parsedEndpoint, err := url.Parse(token.GatewayEndpoint)
	if err != nil {
		return ErrEnrollmentSignature
	}
	if assignment.NodeID != installation.NodeID || assignment.NodeName != token.NodeName ||
		assignment.CredentialGeneration != installation.CredentialGeneration ||
		assignment.ActiveTransport != requestedTransport ||
		assignment.GatewayPublicIPv4 != parsedEndpoint.Hostname() ||
		assignment.ControlProtocol != token.ControlProtocol ||
		assignment.EnrollmentFingerprint != token.EnrollmentFingerprint ||
		assignment.CreatedAt.Before(token.IssuedAt) || !assignment.CreatedAt.Before(token.ExpiresAt) {
		return fmt.Errorf("signed node join assignment differs from the request or invite")
	}
	if !samePresetRequest(requestedPresets, assignment.Presets) {
		return fmt.Errorf("signed node join assignment changed explicit presets")
	}
	return nil
}

func samePresetRequest(requested, assigned []string) bool {
	if len(requested) != len(assigned) {
		return false
	}
	seen := make(map[string]struct{}, len(requested))
	for _, name := range requested {
		seen[strings.ToLower(name)] = struct{}{}
	}
	for _, name := range assigned {
		if _, found := seen[strings.ToLower(name)]; !found {
			return false
		}
	}
	return true
}

func validateJoinedControlMaterial(caPEM, leafPEM, csrPEM []byte, assignment NodeJoinAssignment, now time.Time) (*x509.Certificate, *x509.Certificate, error) {
	ca, err := parseSingleJoinCertificate(caPEM)
	if err != nil || !ca.IsCA || ca.CheckSignatureFrom(ca) != nil || joinCertificateFingerprint(ca) != assignment.ControlCAFingerprint {
		return nil, nil, fmt.Errorf("joined control CA is invalid")
	}
	leaf, err := parseSingleJoinCertificate(leafPEM)
	if err != nil || joinCertificateFingerprint(leaf) != assignment.ControlCertificateFingerprint {
		return nil, nil, fmt.Errorf("joined node control certificate is invalid")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: now.UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, nil, fmt.Errorf("verify joined node control certificate: %w", err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "urn:vpnctl:node:"+assignment.NodeID ||
		len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return nil, nil, fmt.Errorf("joined node control certificate identity is invalid")
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, fmt.Errorf("node control CSR is invalid")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, nil, fmt.Errorf("node control CSR is invalid")
	}
	leafPublic, leafErr := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	csrPublic, csrErr := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if leafErr != nil || csrErr != nil || !bytes.Equal(leafPublic, csrPublic) {
		return nil, nil, fmt.Errorf("joined node certificate does not match the local private key")
	}
	return ca, leaf, nil
}

func assignmentGatewayWireGuardPublicKey(values NodeJoinResponseValues) string {
	value := string(values.GatewayWireGuardPublicKey)
	if strings.TrimSpace(value) != value || wireguard.ValidateKey(value) != nil {
		return ""
	}
	return value
}

func localJoinedCertificate(
	id, ownerID string,
	kind model.CertificateKind,
	reference model.SecretRef,
	privateReference model.SecretRef,
	certificate *x509.Certificate,
	sans []string,
) model.Certificate {
	ownerKind := "host"
	if kind == model.CertificateControlNode {
		ownerKind = "node"
	}
	return model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: id, Kind: kind,
		OwnerKind: ownerKind,
		OwnerID:   ownerID, Fingerprint: joinCertificateFingerprint(certificate),
		SerialHex: certificate.SerialNumber.Text(16), Subject: certificate.Subject.String(),
		SANs: append([]string{}, sans...), NotBefore: certificate.NotBefore.UTC(), NotAfter: certificate.NotAfter.UTC(),
		WarningDays: control.ControlWarningDays, Generation: 1,
		CertificateRef: reference.String(), PrivateKeyRef: privateReference,
	}
}
