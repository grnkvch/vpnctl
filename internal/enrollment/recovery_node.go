package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const nodeRecoveryPlanMarker = "<redacted-node-recovery-plan>"

var ErrNodeRecoveryStale = errors.New("node recovery plan is stale")

type NodeRecoveryOptions struct {
	Entropy         io.Reader
	Now             func() time.Time
	NewUUID         model.UUIDGenerator
	WireGuardRunner wireguard.Runner
	DrainTimeout    time.Duration
}

type NodeRecoveryWorkflow struct {
	state       NodeJoinStateStore
	secrets     NodeCredentialSecretStore
	credentials *NodeCredentialProvisioner
	exchanger   NodeJoinExchanger
	runtime     NodeRotationNodeRuntime
	options     NodeRecoveryOptions
}

func NewNodeRecoveryWorkflow(
	state NodeJoinStateStore,
	secrets NodeCredentialSecretStore,
	exchanger NodeJoinExchanger,
	runtime NodeRotationNodeRuntime,
	options NodeRecoveryOptions,
) (*NodeRecoveryWorkflow, error) {
	if state == nil || secrets == nil || exchanger == nil || runtime == nil {
		return nil, fmt.Errorf("node recovery requires state, secret, exchange, and runtime services")
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
		return nil, fmt.Errorf("node recovery drain timeout must be between one second and five minutes")
	}
	credentials, err := NewNodeCredentialProvisioner(secrets, NodeCredentialRuntime{
		Entropy: options.Entropy, WireGuardRunner: options.WireGuardRunner,
	})
	if err != nil {
		return nil, err
	}
	return &NodeRecoveryWorkflow{
		state: state, secrets: secrets, credentials: credentials, exchanger: exchanger, runtime: runtime, options: options,
	}, nil
}

type NodeRecoveryPlan struct {
	RecoveryID                     string
	NodeID                         string
	NodeName                       string
	ActiveTransport                model.TransportKind
	ExpectedLocalStateGeneration   uint64
	NextLocalStateGeneration       uint64
	ExpectedGatewayStateGeneration uint64
	CurrentCredentialGeneration    uint64
	RequestedCredentialGeneration  uint64
	ExpiresAt                      time.Time

	bindingFingerprint string
	beforeRaw          []byte
}

func (NodeRecoveryPlan) String() string   { return nodeRecoveryPlanMarker }
func (NodeRecoveryPlan) GoString() string { return nodeRecoveryPlanMarker }
func (NodeRecoveryPlan) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

func (workflow *NodeRecoveryWorkflow) Plan(tokenSecret *output.Secret) (NodeRecoveryPlan, error) {
	if workflow == nil || workflow.state == nil || workflow.secrets == nil || tokenSecret == nil {
		return NodeRecoveryPlan{}, fmt.Errorf("node recovery workflow is incomplete")
	}
	state, node, err := loadLocalRotationState(workflow.state)
	if err != nil {
		return NodeRecoveryPlan{}, err
	}
	if _, pending, err := state.PendingNodeOperation(); err != nil {
		return NodeRecoveryPlan{}, err
	} else if pending {
		return NodeRecoveryPlan{}, model.ErrPendingRequest
	}
	token, err := decodeRecoverySecret(tokenSecret)
	if err != nil {
		return NodeRecoveryPlan{}, err
	}
	defer token.Destroy()
	if err := workflow.validateLocalRecoveryBinding(state, node, *token); err != nil {
		return NodeRecoveryPlan{}, err
	}
	nextCredentialGeneration, err := model.NextGeneration(token.CredentialGeneration)
	if err != nil {
		return NodeRecoveryPlan{}, err
	}
	pendingGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return NodeRecoveryPlan{}, err
	}
	finalGeneration, err := model.NextGeneration(pendingGeneration)
	if err != nil {
		return NodeRecoveryPlan{}, err
	}
	raw, err := model.EncodeState(state)
	if err != nil {
		return NodeRecoveryPlan{}, err
	}
	return NodeRecoveryPlan{
		RecoveryID: token.RecoveryID, NodeID: node.ID, NodeName: node.Name, ActiveTransport: node.ActiveTransport,
		ExpectedLocalStateGeneration: state.Generation, NextLocalStateGeneration: finalGeneration,
		ExpectedGatewayStateGeneration: token.ExpectedGatewayStateGeneration,
		CurrentCredentialGeneration:    node.CredentialGeneration,
		RequestedCredentialGeneration:  nextCredentialGeneration, ExpiresAt: token.ExpiresAt,
		bindingFingerprint: token.BindingFingerprint, beforeRaw: raw,
	}, nil
}

type NodeRecoveryResult struct {
	NodeID                       string
	NodeName                     string
	ActiveTransport              model.TransportKind
	PreviousCredentialGeneration uint64
	CredentialGeneration         uint64
	GatewayStateGeneration       uint64
	LocalStateGeneration         uint64
	NodeRuntimeCleanupNeeded     bool
	CredentialCleanupNeeded      bool
	CommitConfirmationNeeded     bool
}

func (result NodeRecoveryResult) OutputResult() output.Result {
	status := output.StatusOK
	if result.NodeRuntimeCleanupNeeded || result.CredentialCleanupNeeded || result.CommitConfirmationNeeded {
		status = output.StatusPending
	}
	public := output.NewResult("node.recover", status, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": result.LocalStateGeneration,
		"credential_generation": result.CredentialGeneration, "active": string(result.ActiveTransport),
	})
	public.ResourceIDs["node_id"] = result.NodeID
	if result.NodeRuntimeCleanupNeeded {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "repair_node_recovery_runtime", Message: "Run repair to finish draining the previous node credential generation.",
			ResourceIDs: map[string]string{"node_id": result.NodeID},
		})
	}
	if result.CredentialCleanupNeeded {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "repair_node_recovery_credentials", Message: "Run repair to remove retained previous-generation node credentials.",
			ResourceIDs: map[string]string{"node_id": result.NodeID},
		})
	}
	if result.CommitConfirmationNeeded {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "inspect_node_recovery", Message: "Inspect gateway and node generations before retrying recovery.",
			ResourceIDs: map[string]string{"node_id": result.NodeID},
		})
	}
	return public
}

func (workflow *NodeRecoveryWorkflow) Apply(
	ctx context.Context,
	plan NodeRecoveryPlan,
	tokenSecret *output.Secret,
) (NodeRecoveryResult, error) {
	if workflow == nil || workflow.credentials == nil || workflow.exchanger == nil || workflow.runtime == nil ||
		ctx == nil || tokenSecret == nil {
		return NodeRecoveryResult{}, fmt.Errorf("node recovery workflow is incomplete")
	}
	current, node, err := loadLocalRotationState(workflow.state)
	if err != nil {
		return NodeRecoveryResult{}, err
	}
	currentRaw, err := model.EncodeState(current)
	if err != nil {
		return NodeRecoveryResult{}, err
	}
	token, err := decodeRecoverySecret(tokenSecret)
	if err != nil {
		return NodeRecoveryResult{}, err
	}
	defer token.Destroy()
	if !sameNodeRecoveryPlan(plan, current, node, currentRaw, *token) {
		return NodeRecoveryResult{}, ErrNodeRecoveryStale
	}
	if err := workflow.validateLocalRecoveryBinding(current, node, *token); err != nil {
		return NodeRecoveryResult{}, err
	}
	startedAt := canonicalTime(workflow.options.Now())
	started, operation, resumed, err := current.BeginNodeOperation(model.OperationIntent{
		Type: model.OperationRecover, TargetKind: string(model.TargetNode), TargetID: node.ID,
		StepNames: []string{"generate", "prove", "gateway_commit", "node_stage", "activate", "drain"},
	}, startedAt, workflow.options.NewUUID)
	if err != nil {
		return NodeRecoveryResult{}, err
	}
	if resumed {
		return NodeRecoveryResult{}, model.ErrPendingRequest
	}
	if err := saveNodeRotationState(workflow.state, current, started, false); err != nil {
		return NodeRecoveryResult{}, err
	}
	rotationHelper := workflow.rotationHelper()
	installation, err := workflow.credentials.Provision(ctx, node.ID, plan.RequestedCredentialGeneration)
	if err != nil {
		return NodeRecoveryResult{}, rotationHelper.failBeforeCommit(started, operation.RequestID, err)
	}
	keepNewCredentials := false
	defer func() {
		if !keepNewCredentials {
			_ = workflow.credentials.Rollback(context.Background(), installation)
		}
	}()
	shared, err := workflow.credentials.SharedCredentialPayload(installation)
	if err != nil {
		return NodeRecoveryResult{}, rotationHelper.failBeforeCommit(started, operation.RequestID, err)
	}
	defer shared.Destroy()
	oldPrivateKey, err := workflow.currentControlPrivateKey(started, node)
	if err != nil {
		return NodeRecoveryResult{}, rotationHelper.failBeforeCommit(started, operation.RequestID, err)
	}
	defer clear(oldPrivateKey)
	nodeNonce, err := workflow.newNonce()
	if err != nil {
		return NodeRecoveryResult{}, rotationHelper.failBeforeCommit(started, operation.RequestID, err)
	}
	payload, err := EncodeNodeRecoveryRequest(
		token.RecoveryID, operation.RequestID, node.CredentialGeneration, nodeNonce,
		installation, shared, oldPrivateKey,
	)
	if err != nil {
		return NodeRecoveryResult{}, rotationHelper.failBeforeCommit(started, operation.RequestID, err)
	}
	defer payload.Destroy()
	requestBody, err := encodeNodePublicRecoveryRequest(tokenSecret, nodeNonce, payload)
	if err != nil {
		return NodeRecoveryResult{}, rotationHelper.failBeforeCommit(started, operation.RequestID, err)
	}
	defer requestBody.Destroy()
	exchange, exchangeErr := workflow.exchanger.Exchange(ctx, token.GatewayEndpoint, requestBody)
	defer clear(exchange.Response)
	if exchangeErr != nil {
		if exchange.CommitPossible {
			keepNewCredentials = true
			return NodeRecoveryResult{}, errors.Join(ErrNodeRotationCommitUncertain, exchangeErr)
		}
		return NodeRecoveryResult{}, rotationHelper.failBeforeCommit(started, operation.RequestID, exchangeErr)
	}
	if !exchange.CommitPossible {
		return NodeRecoveryResult{}, rotationHelper.failBeforeCommit(started, operation.RequestID,
			fmt.Errorf("recovery exchanger returned a response without a committed gateway outcome"))
	}
	keepNewCredentials = true
	publicResponse, err := DecodePublicEnrollmentResponse(exchange.Response, PurposeRecover)
	if err != nil {
		return NodeRecoveryResult{}, errors.Join(ErrNodeRotationCommitUncertain, err)
	}
	material, err := DecodeNodeRecoveryResponse(publicResponse.Data)
	if err != nil {
		return NodeRecoveryResult{}, errors.Join(ErrNodeRotationCommitUncertain, err)
	}
	defer material.Destroy()
	if err := workflow.verifyRecoveryResponse(started, plan, *token, nodeNonce, installation, publicResponse, *material); err != nil {
		return NodeRecoveryResult{}, errors.Join(ErrNodeRotationCommitUncertain, err)
	}
	rotationMaterial := GatewayNodeRotationMaterial{
		RequestID: material.Assignment.RequestID, NodeID: material.Assignment.NodeID,
		CredentialGeneration:   material.Assignment.CredentialGeneration,
		GatewayStateGeneration: material.Assignment.GatewayStateGeneration,
		Certificate:            material.Certificate, ControlCertificatePEM: append([]byte(nil), material.ControlCertificatePEM...),
	}
	defer clear(rotationMaterial.ControlCertificatePEM)
	candidate, oldReferences, err := rotationHelper.buildLocalCandidate(started, operation, installation, rotationMaterial)
	if err != nil {
		return NodeRecoveryResult{}, errors.Join(ErrNodeRotationCommitUncertain, err)
	}
	localCertificateReference := model.SecretRef(material.Certificate.CertificateRef)
	if err := workflow.secrets.PutIfAbsent(localCertificateReference, material.ControlCertificatePEM); err != nil {
		return NodeRecoveryResult{}, errors.Join(ErrNodeRotationCommitUncertain, err)
	}
	if err := workflow.runtime.Stage(ctx, candidate); err != nil {
		return NodeRecoveryResult{}, errors.Join(ErrNodeRotationCommitUncertain, err)
	}
	report, err := workflow.runtime.Check(ctx, candidate)
	if err == nil {
		err = report.Validate()
	}
	if err != nil {
		return NodeRecoveryResult{}, errors.Join(ErrNodeRotationCommitUncertain, err)
	}
	if err := workflow.runtime.ActivateParallel(ctx, candidate); err != nil {
		return NodeRecoveryResult{}, errors.Join(ErrNodeRotationCommitUncertain, err)
	}
	report, err = workflow.runtime.Check(ctx, candidate)
	if err == nil {
		err = report.Validate()
	}
	if err != nil {
		return NodeRecoveryResult{}, errors.Join(ErrNodeRotationCommitUncertain, err)
	}
	result := NodeRecoveryResult{
		NodeID: node.ID, NodeName: node.Name, ActiveTransport: node.ActiveTransport,
		PreviousCredentialGeneration: plan.CurrentCredentialGeneration,
		CredentialGeneration:         plan.RequestedCredentialGeneration,
		GatewayStateGeneration:       material.Assignment.GatewayStateGeneration,
		LocalStateGeneration:         candidate.Candidate.Generation,
	}
	if err := saveNodeRotationState(workflow.state, started, candidate.Candidate, true); err != nil {
		result.CommitConfirmationNeeded = true
		return result, errors.Join(ErrNodeRotationCommitUncertain, err)
	}
	drainStart := time.Now()
	drainRequest := NodeRotationDrainRequest{
		NodeID: node.ID, PreviousGeneration: plan.CurrentCredentialGeneration,
		ActiveGeneration: plan.RequestedCredentialGeneration, Deadline: drainStart.Add(workflow.options.DrainTimeout),
	}
	drainContext, cancelDrain := context.WithDeadline(ctx, drainRequest.Deadline)
	defer cancelDrain()
	drainErr := workflow.runtime.Drain(drainContext, drainRequest)
	credentialErr := deleteGatewayNodeCredentials(workflow.secrets, oldReferences)
	result.NodeRuntimeCleanupNeeded = drainErr != nil
	result.CredentialCleanupNeeded = credentialErr != nil
	if cleanupErr := errors.Join(drainErr, credentialErr); cleanupErr != nil {
		return result, errors.Join(ErrNodeRotationCleanupPending, cleanupErr)
	}
	return result, nil
}

func (workflow *NodeRecoveryWorkflow) validateLocalRecoveryBinding(
	state model.State,
	node model.Node,
	token DecodedRecoveryToken,
) error {
	now := canonicalTime(workflow.options.Now())
	if now.Before(token.IssuedAt.Add(-EnrollmentClockSkew)) || !now.Before(token.ExpiresAt) {
		return ErrRecoveryExpired
	}
	if node.Gateway == nil || token.NodeID != node.ID || token.NodeName != node.Name ||
		token.CredentialGeneration != node.CredentialGeneration || token.BindingFingerprint == "" ||
		token.ControlProtocol != node.Gateway.ControlProtocol ||
		token.EnrollmentFingerprint != node.Gateway.EnrollmentFingerprint ||
		token.ExpectedGatewayStateGeneration <= node.Gateway.LastKnownGatewayGeneration ||
		token.GatewayEndpoint != "https://"+node.Gateway.PublicIPv4+EnrollmentRecoveryPath {
		return ErrRecoveryTokenInvalid
	}
	certificate, err := validateRecoverableNode(state, node, now)
	if err != nil || certificate.Fingerprint != token.BindingFingerprint {
		return ErrRecoveryNodeInactive
	}
	certificatePEM, err := workflow.secrets.Get(model.SecretRef(certificate.CertificateRef))
	if err != nil {
		return fmt.Errorf("read current node control certificate: %w", err)
	}
	defer clear(certificatePEM)
	parsed, err := parseSingleJoinCertificate(certificatePEM)
	if err != nil || joinCertificateFingerprint(parsed) != certificate.Fingerprint {
		return fmt.Errorf("current node control certificate differs from local state")
	}
	privateKeyPEM, err := workflow.secrets.Get(certificate.PrivateKeyRef)
	if err != nil {
		return fmt.Errorf("read current node control private key: %w", err)
	}
	defer clear(privateKeyPEM)
	privateKey, err := parseRecoveryControlPrivateKey(privateKeyPEM)
	if err != nil {
		return err
	}
	publicKey, ok := parsed.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return fmt.Errorf("current node control key does not match the recovery-bound certificate")
	}
	return nil
}

func (workflow *NodeRecoveryWorkflow) verifyRecoveryResponse(
	state model.State,
	plan NodeRecoveryPlan,
	token DecodedRecoveryToken,
	nodeNonce [EnrollmentNonceBytes]byte,
	installation NodeCredentialInstallation,
	publicResponse PublicEnrollmentResponse,
	material NodeRecoveryResponseMaterial,
) error {
	assignment := material.Assignment
	if assignment.RecoveryID != token.RecoveryID || assignment.RequestID == "" || assignment.NodeID != state.Nodes[0].ID ||
		assignment.NodeName != state.Nodes[0].Name || assignment.OverlayIPv4 != state.Nodes[0].OverlayIPv4 ||
		assignment.CurrentCredentialGeneration != state.Nodes[0].CredentialGeneration ||
		assignment.CredentialGeneration != installation.CredentialGeneration ||
		assignment.ActiveTransport != state.Nodes[0].ActiveTransport ||
		!reflect.DeepEqual(assignment.Presets, state.Nodes[0].AssignedPresets) ||
		assignment.GatewayStateGeneration != token.ExpectedGatewayStateGeneration+1 ||
		assignment.ControlProtocol != token.ControlProtocol ||
		assignment.EnrollmentFingerprint != token.EnrollmentFingerprint ||
		assignment.RecoveredAt.Before(token.IssuedAt) || !assignment.RecoveredAt.Before(token.ExpiresAt) ||
		assignment.ControlCertificateFingerprint != material.Certificate.Fingerprint ||
		plan.RequestedCredentialGeneration != assignment.CredentialGeneration {
		return fmt.Errorf("signed recovery assignment changed stable node identity or generation")
	}
	policyGeneration, policyHash := localRecoveryPolicy(state, state.Nodes[0].ID)
	if assignment.PolicyGeneration != policyGeneration || assignment.PolicyEffectiveHash != policyHash {
		return fmt.Errorf("signed recovery assignment changed node policy")
	}
	assignmentHash, err := assignment.SHA256()
	if err != nil {
		return err
	}
	publicHashes, err := installation.PublicExchange.TranscriptHashes()
	if err != nil {
		return err
	}
	gatewayNonceBytes, err := decodeCanonicalBase64(publicResponse.GatewayNonce)
	if err != nil || len(gatewayNonceBytes) != EnrollmentNonceBytes {
		clear(gatewayNonceBytes)
		return ErrEnrollmentSignature
	}
	var gatewayNonce [EnrollmentNonceBytes]byte
	copy(gatewayNonce[:], gatewayNonceBytes)
	clear(gatewayNonceBytes)
	expectedTranscript, err := NewEnrollmentTranscript(
		PurposeRecover, token.RecoveryID, token.GatewayEndpoint, state.Nodes[0].ID,
		token.IssuedAt, token.ExpiresAt, nodeNonce, gatewayNonce,
		assignment.ActiveTransport, assignment.Presets, publicHashes, assignmentHash,
	)
	if err != nil {
		return err
	}
	enrollmentPublicKey, err := workflow.secrets.Get(model.SecretRef(state.Nodes[0].Gateway.EnrollmentPublicKeyRef))
	if err != nil {
		return fmt.Errorf("read pinned enrollment public key: %w", err)
	}
	defer clear(enrollmentPublicKey)
	_, err = VerifyEnrollmentTranscript(
		publicResponse.SignedTranscript, expectedTranscript, enrollmentPublicKey,
		token.EnrollmentFingerprint, workflow.options.Now(),
	)
	return err
}

func localRecoveryPolicy(state model.State, nodeID string) (uint64, string) {
	for _, policy := range state.Policies {
		if policy.TargetKind == model.TargetNode && policy.TargetID == nodeID {
			return policy.Generation, policy.EffectiveHash
		}
	}
	return 0, ""
}

func (workflow *NodeRecoveryWorkflow) currentControlPrivateKey(state model.State, node model.Node) ([]byte, error) {
	certificate, err := currentNodeControlCertificate(state, node)
	if err != nil {
		return nil, err
	}
	value, err := workflow.secrets.Get(certificate.PrivateKeyRef)
	if err != nil {
		return nil, fmt.Errorf("read recovery proof private key: %w", err)
	}
	return value, nil
}

func (workflow *NodeRecoveryWorkflow) newNonce() ([EnrollmentNonceBytes]byte, error) {
	var nonce [EnrollmentNonceBytes]byte
	if _, err := io.ReadFull(workflow.options.Entropy, nonce[:]); err != nil || allZero(nonce[:]) {
		return nonce, fmt.Errorf("generate node recovery nonce")
	}
	return nonce, nil
}

func (workflow *NodeRecoveryWorkflow) rotationHelper() *NodeRotationWorkflow {
	return &NodeRotationWorkflow{
		state: workflow.state, secrets: workflow.secrets, credentials: workflow.credentials, runtime: workflow.runtime,
		options: NodeRotationOptions{
			Entropy: workflow.options.Entropy, Now: workflow.options.Now, NewUUID: workflow.options.NewUUID,
			WireGuardRunner: workflow.options.WireGuardRunner, DrainTimeout: workflow.options.DrainTimeout,
		},
	}
}

func decodeRecoverySecret(secret *output.Secret) (*DecodedRecoveryToken, error) {
	if secret == nil {
		return nil, ErrRecoveryTokenInvalid
	}
	var token *DecodedRecoveryToken
	err := secret.Use(func(value []byte) error {
		var err error
		token, err = DecodeRecoveryToken(value)
		return err
	})
	return token, err
}

func sameNodeRecoveryPlan(
	plan NodeRecoveryPlan,
	state model.State,
	node model.Node,
	raw []byte,
	token DecodedRecoveryToken,
) bool {
	pending, pendingErr := model.NextGeneration(state.Generation)
	final, finalErr := model.NextGeneration(pending)
	nextCredential, credentialErr := model.NextGeneration(node.CredentialGeneration)
	return pendingErr == nil && finalErr == nil && credentialErr == nil && bytes.Equal(plan.beforeRaw, raw) &&
		plan.RecoveryID == token.RecoveryID && plan.NodeID == node.ID && plan.NodeName == node.Name &&
		plan.ActiveTransport == node.ActiveTransport && plan.ExpectedLocalStateGeneration == state.Generation &&
		plan.NextLocalStateGeneration == final &&
		plan.ExpectedGatewayStateGeneration == token.ExpectedGatewayStateGeneration &&
		plan.CurrentCredentialGeneration == node.CredentialGeneration &&
		token.CredentialGeneration == node.CredentialGeneration && plan.RequestedCredentialGeneration == nextCredential &&
		plan.bindingFingerprint == token.BindingFingerprint && plan.ExpiresAt.Equal(token.ExpiresAt)
}

func encodeNodePublicRecoveryRequest(
	token *output.Secret,
	nonce [EnrollmentNonceBytes]byte,
	payload *output.Secret,
) (*output.Secret, error) {
	if token == nil || payload == nil || allZero(nonce[:]) {
		return nil, fmt.Errorf("public recovery request input is incomplete")
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
				SchemaVersion: PublicEnrollmentSchemaVersion, Purpose: PurposeRecover,
				Token: string(tokenBytes), NodeNonce: nonceText, Payload: append(json.RawMessage(nil), payloadBytes...),
			}
			defer clear(wire.Payload)
			encoded, err = json.Marshal(wire)
			return err
		})
	})
	if err != nil {
		clear(encoded)
		return nil, err
	}
	secret, err := output.NewSecret(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}
