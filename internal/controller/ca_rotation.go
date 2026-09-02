package controller

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

var (
	ErrControlCARotationExists     = errors.New("a control CA rotation is already staged")
	ErrControlCARotationNotFound   = errors.New("no staged control CA rotation exists")
	ErrControlCARotationIncomplete = errors.New("control CA rotation has nodes awaiting trust update")
	ErrControlCARotationImpact     = errors.New("control CA rotation impact changed after staging")
)

type GatewayControlCARotationSecretStore interface {
	Get(model.SecretRef) ([]byte, error)
	PutIfAbsent(model.SecretRef, []byte) error
	Delete(model.SecretRef) (bool, error)
}

type GatewayControlCATLSPreparer interface {
	PrepareGatewayControlTLS([]byte, []byte, [][]byte, time.Time) (control.GatewayControlLeafActivation, error)
}

type GatewayControlCARotationRuntime struct {
	Entropy io.Reader
	NewUUID model.UUIDGenerator
}

type ControlCARotationNodeImpact struct {
	ID           string
	Name         string
	TrustUpdated bool
}

type ControlCARotationPlan struct {
	Staged               bool
	OperationID          string
	StateGeneration      uint64
	CurrentCAFingerprint string
	StagedCAFingerprint  string
	Nodes                []ControlCARotationNodeImpact
}

type NodeControlTrustUpdate struct {
	OperationID        string
	NodeID             string
	StateGeneration    uint64
	OldCAFingerprint   string
	NewCAFingerprint   string
	ControlCAPEMs      [][]byte
	NodeCertificatePEM []byte
}

type NodeControlTrustAcknowledgement struct {
	OperationID     string
	NodeID          string
	StateGeneration uint64
	CAFingerprint   string
}

type ControlCARotationResult struct {
	OperationID     string
	StateGeneration uint64
	CAFingerprint   string
	NodeActions     []string
}

type GatewayControlCARotator struct {
	controller *Controller
	secrets    GatewayControlCARotationSecretStore
	preparer   GatewayControlCATLSPreparer
	runtime    GatewayControlCARotationRuntime
}

func (controller *Controller) NewGatewayControlCARotator(secrets GatewayControlCARotationSecretStore, preparer GatewayControlCATLSPreparer, runtime GatewayControlCARotationRuntime) (*GatewayControlCARotator, error) {
	if controller == nil || controller.runtime.State == nil {
		return nil, fmt.Errorf("gateway controller is required")
	}
	if secrets == nil || preparer == nil {
		return nil, fmt.Errorf("control CA rotation dependencies are incomplete")
	}
	if runtime.Entropy == nil {
		runtime.Entropy = rand.Reader
	}
	if runtime.NewUUID == nil {
		runtime.NewUUID = model.NewUUID
	}
	return &GatewayControlCARotator{controller: controller, secrets: secrets, preparer: preparer, runtime: runtime}, nil
}

// Plan is read-only. It reports the exact active-node impact and, when a
// transaction is already staged, which nodes have acknowledged dual trust.
func (rotator *GatewayControlCARotator) Plan(ctx context.Context) (ControlCARotationPlan, error) {
	if ctx == nil {
		return ControlCARotationPlan{}, fmt.Errorf("context is required")
	}
	if rotator == nil || rotator.controller == nil {
		return ControlCARotationPlan{}, fmt.Errorf("control CA rotator is incomplete")
	}
	rotator.controller.mutationMu.Lock()
	defer rotator.controller.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ControlCARotationPlan{}, err
	}
	state, err := rotator.controller.runtime.State.Load()
	if err != nil {
		return ControlCARotationPlan{}, fmt.Errorf("load authoritative gateway state: %w", err)
	}
	return controlCARotationPlan(state)
}

// Stage creates a durable second CA generation and gateway leaf, changes only
// the control listener to accept old+new node CAs, and leaves its old leaf live.
func (rotator *GatewayControlCARotator) Stage(ctx context.Context) (ControlCARotationPlan, error) {
	if ctx == nil {
		return ControlCARotationPlan{}, fmt.Errorf("context is required")
	}
	if rotator == nil || rotator.controller == nil || rotator.secrets == nil || rotator.preparer == nil || rotator.runtime.Entropy == nil || rotator.runtime.NewUUID == nil {
		return ControlCARotationPlan{}, fmt.Errorf("control CA rotator is incomplete")
	}
	rotator.controller.mutationMu.Lock()
	defer rotator.controller.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ControlCARotationPlan{}, err
	}
	state, err := rotator.controller.runtime.State.Load()
	if err != nil {
		return ControlCARotationPlan{}, fmt.Errorf("load authoritative gateway state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return ControlCARotationPlan{}, fmt.Errorf("control CA rotation requires gateway state")
	}
	if _, _, found, err := activeControlCARotation(state); err != nil {
		return ControlCARotationPlan{}, err
	} else if found {
		return ControlCARotationPlan{}, ErrControlCARotationExists
	}
	oldCA, oldServer, err := soleControlCAAndServer(state)
	if err != nil {
		return ControlCARotationPlan{}, err
	}
	oldCAPEM, oldServerPEM, oldServerKeyPEM, err := rotator.readAuthorityAndServer(oldCA, oldServer)
	if err != nil {
		return ControlCARotationPlan{}, err
	}
	now := rotator.controller.runtime.Now().UTC().Truncate(time.Second)
	overlayIPv4, err := control.GatewayOverlayIPv4(state.Host.NodeCIDR)
	if err != nil {
		return ControlCARotationPlan{}, err
	}
	material, err := control.GenerateGatewayControlMaterial(rotator.runtime.Entropy, state.Host.ID, overlayIPv4, now)
	if err != nil {
		return ControlCARotationPlan{}, fmt.Errorf("generate staged control CA: %w", err)
	}
	occupied := rotationOccupiedIDs(state)
	operationID, err := model.AllocateUUID(occupied, rotator.runtime.NewUUID)
	if err != nil {
		return ControlCARotationPlan{}, fmt.Errorf("allocate control CA rotation operation: %w", err)
	}
	caID, err := model.AllocateUUID(occupied, rotator.runtime.NewUUID)
	if err != nil {
		return ControlCARotationPlan{}, fmt.Errorf("allocate staged control CA identity: %w", err)
	}
	serverID, err := model.AllocateUUID(occupied, rotator.runtime.NewUUID)
	if err != nil {
		return ControlCARotationPlan{}, fmt.Errorf("allocate staged gateway leaf identity: %w", err)
	}
	caCertificate, err := parseRotationCertificate(material.ControlCACertificatePEM)
	if err != nil {
		return ControlCARotationPlan{}, err
	}
	serverCertificate, err := parseRotationCertificate(material.GatewayCertificatePEM)
	if err != nil {
		return ControlCARotationPlan{}, err
	}
	caCertificateRef := model.SecretRef("control-cert:" + operationID + "-ca")
	caKeyRef := model.SecretRef("control-key:" + operationID + "-ca")
	serverCertificateRef := model.SecretRef("control-cert:" + operationID + "-gateway")
	serverKeyRef := model.SecretRef("control-key:" + operationID + "-gateway")
	entries := []rotationSecret{
		{caCertificateRef, material.ControlCACertificatePEM}, {caKeyRef, material.ControlCAPrivateKeyPEM},
		{serverCertificateRef, material.GatewayCertificatePEM}, {serverKeyRef, material.GatewayPrivateKeyPEM},
	}
	staged, err := rotator.stageSecrets(entries)
	if err != nil {
		return ControlCARotationPlan{}, err
	}
	cleanup := func(cause error) error { return errors.Join(cause, rotator.deleteSecrets(staged)) }
	activation, err := rotator.preparer.PrepareGatewayControlTLS(oldServerPEM, oldServerKeyPEM, [][]byte{oldCAPEM, material.ControlCACertificatePEM}, now)
	if err != nil {
		return ControlCARotationPlan{}, cleanup(fmt.Errorf("prepare dual control CA trust: %w", err))
	}
	if activation == nil {
		return ControlCARotationPlan{}, cleanup(fmt.Errorf("prepare dual control CA trust: empty activation"))
	}
	nextGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return ControlCARotationPlan{}, cleanup(fmt.Errorf("gateway state %w", err))
	}
	steps := make([]model.OperationStep, 0, len(state.Nodes))
	for _, node := range sortedActiveNodes(state.Nodes) {
		steps = append(steps, model.OperationStep{Name: nodeRotationStep(node.ID), State: model.OperationPending, UpdatedAt: now})
	}
	operation := model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: operationID, Type: model.OperationTrustRotate, State: model.OperationPending,
		TargetKind: "host", TargetID: state.Host.ID, ExpectedGeneration: state.Generation, DesiredGeneration: nextGeneration,
		Steps: steps, CreatedAt: now, UpdatedAt: now,
	}
	stagedCARecord := rotationHostCertificateRecord(caID, model.CertificateControlCA, state.Host.ID, caCertificate, caCertificateRef, caKeyRef, nil)
	stagedServerRecord := rotationHostCertificateRecord(serverID, model.CertificateControlServer, state.Host.ID, serverCertificate, serverCertificateRef, serverKeyRef,
		[]string{"IP:" + overlayIPv4, "urn:vpnctl:gateway:" + state.Host.ID})
	candidate := state
	candidate.Generation = nextGeneration
	candidate.Certificates = append(append([]model.Certificate(nil), state.Certificates...), stagedCARecord, stagedServerRecord)
	candidate.Operations = append(append([]model.Operation(nil), state.Operations...), operation)
	if err := rotator.controller.runtime.State.Save(state.Generation, candidate); err != nil {
		return ControlCARotationPlan{}, cleanup(fmt.Errorf("commit staged control CA rotation: %w", err))
	}
	activation.Activate()
	rotator.controller.recordObservation(ctx, candidate)
	return controlCARotationPlan(candidate)
}

// RestoreRuntime reconstructs dual trust from durable staged state after a
// controller/control-listener restart. It is read-only and is a no-op when no
// rotation is active.
func (rotator *GatewayControlCARotator) RestoreRuntime(ctx context.Context) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("context is required")
	}
	if rotator == nil || rotator.controller == nil || rotator.secrets == nil || rotator.preparer == nil {
		return false, fmt.Errorf("control CA rotator is incomplete")
	}
	rotator.controller.mutationMu.Lock()
	defer rotator.controller.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	state, err := rotator.controller.runtime.State.Load()
	if err != nil {
		return false, fmt.Errorf("load authoritative gateway state: %w", err)
	}
	_, operation, found, err := activeControlCARotation(state)
	if err != nil || !found {
		return false, err
	}
	oldCA, newCA, oldServer, _, err := rotationCertificateGenerations(state, operation.ID)
	if err != nil {
		return false, err
	}
	oldCAPEM, err := rotator.secrets.Get(model.SecretRef(oldCA.CertificateRef))
	if err != nil {
		return false, fmt.Errorf("read current control CA certificate: %w", err)
	}
	newCAPEM, err := rotator.secrets.Get(model.SecretRef(newCA.CertificateRef))
	if err != nil {
		return false, fmt.Errorf("read staged control CA certificate: %w", err)
	}
	serverPEM, err := rotator.secrets.Get(model.SecretRef(oldServer.CertificateRef))
	if err != nil {
		return false, fmt.Errorf("read current gateway control certificate: %w", err)
	}
	serverKeyPEM, err := rotator.secrets.Get(oldServer.PrivateKeyRef)
	if err != nil {
		return false, fmt.Errorf("read current gateway control private key: %w", err)
	}
	activation, err := rotator.preparer.PrepareGatewayControlTLS(serverPEM, serverKeyPEM, [][]byte{oldCAPEM, newCAPEM}, rotator.controller.runtime.Now().UTC().Truncate(time.Second))
	if err != nil {
		return false, fmt.Errorf("restore dual control CA trust: %w", err)
	}
	if activation == nil {
		return false, fmt.Errorf("restore dual control CA trust: empty activation")
	}
	activation.Activate()
	return true, nil
}

// UpdateNodeTrust issues a same-generation node leaf under the staged CA from
// a node-generated CSR. The response contains the explicit old+new trust
// bundle; the node must persist it and acknowledge over its new mTLS identity.
func (rotator *GatewayControlCARotator) UpdateNodeTrust(ctx context.Context, nodeID string, csrPEM []byte) (NodeControlTrustUpdate, error) {
	if ctx == nil {
		return NodeControlTrustUpdate{}, fmt.Errorf("context is required")
	}
	if rotator == nil || rotator.controller == nil || rotator.secrets == nil {
		return NodeControlTrustUpdate{}, fmt.Errorf("control CA rotator is incomplete")
	}
	rotator.controller.mutationMu.Lock()
	defer rotator.controller.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return NodeControlTrustUpdate{}, err
	}
	state, err := rotator.controller.runtime.State.Load()
	if err != nil {
		return NodeControlTrustUpdate{}, fmt.Errorf("load authoritative gateway state: %w", err)
	}
	_, operation, found, err := activeControlCARotation(state)
	if err != nil {
		return NodeControlTrustUpdate{}, err
	}
	if !found {
		return NodeControlTrustUpdate{}, ErrControlCARotationNotFound
	}
	node, found := findActiveNode(state.Nodes, nodeID)
	if !found || !operationHasStep(operation, nodeRotationStep(nodeID)) {
		return NodeControlTrustUpdate{}, fmt.Errorf("%w: node %s is not in the staged impact", ErrControlCARotationImpact, nodeID)
	}
	oldCA, newCA, _, _, err := rotationCertificateGenerations(state, operation.ID)
	if err != nil {
		return NodeControlTrustUpdate{}, err
	}
	oldCAPEM, err := rotator.secrets.Get(model.SecretRef(oldCA.CertificateRef))
	if err != nil {
		return NodeControlTrustUpdate{}, fmt.Errorf("read current control CA certificate: %w", err)
	}
	newCAPEM, err := rotator.secrets.Get(model.SecretRef(newCA.CertificateRef))
	if err != nil {
		return NodeControlTrustUpdate{}, fmt.Errorf("read staged control CA certificate: %w", err)
	}
	if certificate, found := stagedNodeCertificate(state, operation.ID, nodeID); found {
		certificatePEM, err := rotator.secrets.Get(model.SecretRef(certificate.CertificateRef))
		if err != nil {
			return NodeControlTrustUpdate{}, fmt.Errorf("read staged node certificate: %w", err)
		}
		return nodeTrustUpdate(operation.ID, nodeID, state.Generation, oldCA, newCA, oldCAPEM, newCAPEM, certificatePEM), nil
	}
	if operationStepState(operation, nodeRotationStep(nodeID)) == model.OperationCompleted {
		return NodeControlTrustUpdate{}, fmt.Errorf("staged node certificate for %s is missing", nodeID)
	}
	newCAKeyPEM, err := rotator.secrets.Get(newCA.PrivateKeyRef)
	if err != nil {
		return NodeControlTrustUpdate{}, fmt.Errorf("read staged control CA private key: %w", err)
	}
	now := rotator.controller.runtime.Now().UTC().Truncate(time.Second)
	issued, err := control.IssueNodeControlCertificate(rotator.runtime.Entropy, newCAPEM, newCAKeyPEM, csrPEM, nodeID, now)
	if err != nil {
		return NodeControlTrustUpdate{}, err
	}
	certificateID, err := model.AllocateUUID(rotationOccupiedIDs(state), rotator.runtime.NewUUID)
	if err != nil {
		return NodeControlTrustUpdate{}, fmt.Errorf("allocate staged node certificate identity: %w", err)
	}
	certificateRef := model.SecretRef("control-cert:" + operation.ID + "-node-" + nodeID)
	if err := rotator.secrets.PutIfAbsent(certificateRef, issued.CertificatePEM); err != nil {
		return NodeControlTrustUpdate{}, fmt.Errorf("stage node control certificate: %w", err)
	}
	cleanup := func(cause error) error {
		return errors.Join(cause, rotator.deleteSecrets([]model.SecretRef{certificateRef}))
	}
	nextGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return NodeControlTrustUpdate{}, cleanup(fmt.Errorf("gateway state %w", err))
	}
	record := rotationNodeCertificateRecord(certificateID, node, issued, certificateRef)
	candidate := state
	candidate.Generation = nextGeneration
	candidate.Certificates = append(append([]model.Certificate(nil), state.Certificates...), record)
	if err := rotator.controller.runtime.State.Save(state.Generation, candidate); err != nil {
		return NodeControlTrustUpdate{}, cleanup(fmt.Errorf("commit node trust update: %w", err))
	}
	rotator.controller.recordObservation(ctx, candidate)
	return nodeTrustUpdate(operation.ID, nodeID, candidate.Generation, oldCA, newCA, oldCAPEM, newCAPEM, issued.CertificatePEM), nil
}

// AcknowledgeNodeTrust is accepted only from the staged new-CA certificate.
// Callers invoke it after atomically installing the returned dual-CA bundle
// and new identity on the node; commit is blocked until every active node acks.
func (rotator *GatewayControlCARotator) AcknowledgeNodeTrust(ctx context.Context, peer control.RPCPeer, newCAFingerprint string) (NodeControlTrustAcknowledgement, error) {
	if ctx == nil {
		return NodeControlTrustAcknowledgement{}, fmt.Errorf("context is required")
	}
	if rotator == nil || rotator.controller == nil {
		return NodeControlTrustAcknowledgement{}, fmt.Errorf("control CA rotator is incomplete")
	}
	rotator.controller.mutationMu.Lock()
	defer rotator.controller.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return NodeControlTrustAcknowledgement{}, err
	}
	state, err := rotator.controller.runtime.State.Load()
	if err != nil {
		return NodeControlTrustAcknowledgement{}, fmt.Errorf("load authoritative gateway state: %w", err)
	}
	operationIndex, operation, found, err := activeControlCARotation(state)
	if err != nil {
		return NodeControlTrustAcknowledgement{}, err
	}
	if !found {
		return NodeControlTrustAcknowledgement{}, ErrControlCARotationNotFound
	}
	if _, found := findActiveNode(state.Nodes, peer.NodeID); !found || !operationHasStep(operation, nodeRotationStep(peer.NodeID)) {
		return NodeControlTrustAcknowledgement{}, fmt.Errorf("%w: node %s is not in the staged impact", ErrControlCARotationImpact, peer.NodeID)
	}
	_, newCA, _, _, err := rotationCertificateGenerations(state, operation.ID)
	if err != nil {
		return NodeControlTrustAcknowledgement{}, err
	}
	certificate, found := stagedNodeCertificate(state, operation.ID, peer.NodeID)
	if !found || peer.CertificateFingerprint == "" || peer.CertificateFingerprint != certificate.Fingerprint || newCAFingerprint != newCA.Fingerprint {
		return NodeControlTrustAcknowledgement{}, fmt.Errorf("node trust acknowledgement is not authenticated by the staged CA generation")
	}
	result := NodeControlTrustAcknowledgement{
		OperationID: operation.ID, NodeID: peer.NodeID, StateGeneration: state.Generation, CAFingerprint: newCA.Fingerprint,
	}
	if operationStepState(operation, nodeRotationStep(peer.NodeID)) == model.OperationCompleted {
		return result, nil
	}
	now := rotator.controller.runtime.Now().UTC().Truncate(time.Second)
	updatedOperation, err := operation.TransitionStep(nodeRotationStep(peer.NodeID), model.OperationCompleted, now)
	if err != nil {
		return NodeControlTrustAcknowledgement{}, err
	}
	nextGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return NodeControlTrustAcknowledgement{}, fmt.Errorf("gateway state %w", err)
	}
	candidate := state
	candidate.Generation = nextGeneration
	candidate.Operations = append([]model.Operation(nil), state.Operations...)
	candidate.Operations[operationIndex] = updatedOperation
	if err := rotator.controller.runtime.State.Save(state.Generation, candidate); err != nil {
		return NodeControlTrustAcknowledgement{}, fmt.Errorf("commit node trust acknowledgement: %w", err)
	}
	rotator.controller.recordObservation(ctx, candidate)
	result.StateGeneration = candidate.Generation
	return result, nil
}

// Commit requires every still-active affected node to have acknowledged dual
// trust. It atomically switches the server leaf and client trust to new-only.
func (rotator *GatewayControlCARotator) Commit(ctx context.Context) (ControlCARotationResult, error) {
	return rotator.finish(ctx, true)
}

// Rollback restores old-only trust and the old server leaf. Nodes already
// updated remain manageable because their old certificate and CA were retained.
func (rotator *GatewayControlCARotator) Rollback(ctx context.Context) (ControlCARotationResult, error) {
	return rotator.finish(ctx, false)
}

func (rotator *GatewayControlCARotator) finish(ctx context.Context, commit bool) (ControlCARotationResult, error) {
	if ctx == nil {
		return ControlCARotationResult{}, fmt.Errorf("context is required")
	}
	if rotator == nil || rotator.controller == nil || rotator.secrets == nil || rotator.preparer == nil {
		return ControlCARotationResult{}, fmt.Errorf("control CA rotator is incomplete")
	}
	rotator.controller.mutationMu.Lock()
	defer rotator.controller.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ControlCARotationResult{}, err
	}
	state, err := rotator.controller.runtime.State.Load()
	if err != nil {
		return ControlCARotationResult{}, fmt.Errorf("load authoritative gateway state: %w", err)
	}
	operationIndex, operation, found, err := activeControlCARotation(state)
	if err != nil {
		return ControlCARotationResult{}, err
	}
	if !found {
		return ControlCARotationResult{}, ErrControlCARotationNotFound
	}
	oldCA, newCA, oldServer, newServer, err := rotationCertificateGenerations(state, operation.ID)
	if err != nil {
		return ControlCARotationResult{}, err
	}
	if commit {
		if err := validateRotationReady(state, operation); err != nil {
			return ControlCARotationResult{}, err
		}
	}
	selectedCA, selectedServer := oldCA, oldServer
	if commit {
		selectedCA, selectedServer = newCA, newServer
	}
	caPEM, err := rotator.secrets.Get(model.SecretRef(selectedCA.CertificateRef))
	if err != nil {
		return ControlCARotationResult{}, fmt.Errorf("read selected control CA certificate: %w", err)
	}
	serverPEM, err := rotator.secrets.Get(model.SecretRef(selectedServer.CertificateRef))
	if err != nil {
		return ControlCARotationResult{}, fmt.Errorf("read selected gateway control certificate: %w", err)
	}
	serverKeyPEM, err := rotator.secrets.Get(selectedServer.PrivateKeyRef)
	if err != nil {
		return ControlCARotationResult{}, fmt.Errorf("read selected gateway control private key: %w", err)
	}
	now := rotator.controller.runtime.Now().UTC().Truncate(time.Second)
	activation, err := rotator.preparer.PrepareGatewayControlTLS(serverPEM, serverKeyPEM, [][]byte{caPEM}, now)
	if err != nil {
		return ControlCARotationResult{}, fmt.Errorf("prepare final control CA trust: %w", err)
	}
	if activation == nil {
		return ControlCARotationResult{}, fmt.Errorf("prepare final control CA trust: empty activation")
	}
	removedReferences := []model.SecretRef{}
	keptCertificates := make([]model.Certificate, 0, len(state.Certificates))
	for _, certificate := range state.Certificates {
		staged := rotationCertificateIsStaged(certificate, operation.ID)
		remove := (!commit && staged) || (commit && !staged && (certificate.Kind == model.CertificateControlCA || certificate.Kind == model.CertificateControlServer || certificate.Kind == model.CertificateControlNode))
		if remove {
			removedReferences = appendCertificateReferences(removedReferences, certificate)
			continue
		}
		keptCertificates = append(keptCertificates, certificate)
	}
	updatedOperation, err := operation.Transition(map[bool]model.OperationState{true: model.OperationCompleted, false: model.OperationFailed}[commit], now, map[bool]string{true: "", false: "operator-rollback"}[commit])
	if err != nil {
		return ControlCARotationResult{}, err
	}
	nextGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return ControlCARotationResult{}, fmt.Errorf("gateway state %w", err)
	}
	candidate := state
	candidate.Generation = nextGeneration
	candidate.Certificates = keptCertificates
	candidate.Operations = append([]model.Operation(nil), state.Operations...)
	candidate.Operations[operationIndex] = updatedOperation
	if err := rotator.controller.runtime.State.Save(state.Generation, candidate); err != nil {
		return ControlCARotationResult{}, fmt.Errorf("commit control CA rotation outcome: %w", err)
	}
	activation.Activate()
	rotator.controller.recordObservation(ctx, candidate)
	cleanupErr := rotator.deleteSecrets(uniqueSecretRefs(removedReferences))
	actions := []string{}
	if !commit {
		for _, step := range operation.Steps {
			if step.State == model.OperationCompleted {
				actions = append(actions, strings.TrimPrefix(step.Name, "node-"))
			}
		}
		sort.Strings(actions)
	}
	result := ControlCARotationResult{OperationID: operation.ID, StateGeneration: candidate.Generation, CAFingerprint: selectedCA.Fingerprint, NodeActions: actions}
	if cleanupErr != nil {
		return result, fmt.Errorf("rotation committed but stale secret cleanup failed: %w", cleanupErr)
	}
	return result, nil
}

func controlCARotationPlan(state model.State) (ControlCARotationPlan, error) {
	if state.Host.Role != model.RoleGateway {
		return ControlCARotationPlan{}, fmt.Errorf("control CA rotation requires gateway state")
	}
	_, operation, staged, err := activeControlCARotation(state)
	if err != nil {
		return ControlCARotationPlan{}, err
	}
	plan := ControlCARotationPlan{Staged: staged, StateGeneration: state.Generation}
	if staged {
		oldCA, newCA, _, _, err := rotationCertificateGenerations(state, operation.ID)
		if err != nil {
			return ControlCARotationPlan{}, err
		}
		plan.OperationID, plan.CurrentCAFingerprint, plan.StagedCAFingerprint = operation.ID, oldCA.Fingerprint, newCA.Fingerprint
	} else {
		ca, _, err := soleControlCAAndServer(state)
		if err != nil {
			return ControlCARotationPlan{}, err
		}
		plan.CurrentCAFingerprint = ca.Fingerprint
	}
	for _, node := range sortedActiveNodes(state.Nodes) {
		plan.Nodes = append(plan.Nodes, ControlCARotationNodeImpact{ID: node.ID, Name: node.Name, TrustUpdated: staged && operationStepState(operation, nodeRotationStep(node.ID)) == model.OperationCompleted})
	}
	return plan, nil
}

func activeControlCARotation(state model.State) (int, model.Operation, bool, error) {
	index := -1
	var found model.Operation
	for candidateIndex, operation := range state.Operations {
		if operation.Type != model.OperationTrustRotate || operation.State == model.OperationCompleted || operation.State == model.OperationFailed {
			continue
		}
		if index >= 0 {
			return -1, model.Operation{}, false, fmt.Errorf("authoritative state contains multiple active control CA rotations")
		}
		index, found = candidateIndex, operation
	}
	return index, found, index >= 0, nil
}

func soleControlCAAndServer(state model.State) (model.Certificate, model.Certificate, error) {
	var ca, server model.Certificate
	caCount, serverCount := 0, 0
	for _, certificate := range state.Certificates {
		if certificate.OwnerKind != "host" || certificate.OwnerID != state.Host.ID {
			continue
		}
		switch certificate.Kind {
		case model.CertificateControlCA:
			ca, caCount = certificate, caCount+1
		case model.CertificateControlServer:
			server, serverCount = certificate, serverCount+1
		}
	}
	if caCount != 1 || serverCount != 1 || ca.PrivateKeyRef == "" || server.PrivateKeyRef == "" {
		return model.Certificate{}, model.Certificate{}, fmt.Errorf("authoritative gateway control identity requires exactly one CA and server leaf outside rotation")
	}
	return ca, server, nil
}

func rotationCertificateGenerations(state model.State, operationID string) (model.Certificate, model.Certificate, model.Certificate, model.Certificate, error) {
	var oldCA, newCA, oldServer, newServer model.Certificate
	counts := [4]int{}
	for _, certificate := range state.Certificates {
		staged := rotationCertificateIsStaged(certificate, operationID)
		switch {
		case certificate.Kind == model.CertificateControlCA && staged:
			newCA, counts[1] = certificate, counts[1]+1
		case certificate.Kind == model.CertificateControlCA:
			oldCA, counts[0] = certificate, counts[0]+1
		case certificate.Kind == model.CertificateControlServer && staged:
			newServer, counts[3] = certificate, counts[3]+1
		case certificate.Kind == model.CertificateControlServer:
			oldServer, counts[2] = certificate, counts[2]+1
		}
	}
	if counts != [4]int{1, 1, 1, 1} {
		return model.Certificate{}, model.Certificate{}, model.Certificate{}, model.Certificate{}, fmt.Errorf("staged control CA rotation identity is incomplete")
	}
	return oldCA, newCA, oldServer, newServer, nil
}

func validateRotationReady(state model.State, operation model.Operation) error {
	steps := make(map[string]model.OperationState, len(operation.Steps))
	for _, step := range operation.Steps {
		steps[step.Name] = step.State
	}
	for _, node := range state.Nodes {
		if node.Lifecycle != model.LifecycleActive {
			continue
		}
		step, found := steps[nodeRotationStep(node.ID)]
		if !found {
			return fmt.Errorf("%w: active node %s was added after staging", ErrControlCARotationImpact, node.ID)
		}
		if step != model.OperationCompleted {
			return fmt.Errorf("%w: node %s", ErrControlCARotationIncomplete, node.ID)
		}
		if _, found := stagedNodeCertificate(state, operation.ID, node.ID); !found {
			return fmt.Errorf("staged node certificate for %s is missing", node.ID)
		}
	}
	return nil
}

func (rotator *GatewayControlCARotator) readAuthorityAndServer(ca, server model.Certificate) ([]byte, []byte, []byte, error) {
	caPEM, err := rotator.secrets.Get(model.SecretRef(ca.CertificateRef))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read current control CA certificate: %w", err)
	}
	serverPEM, err := rotator.secrets.Get(model.SecretRef(server.CertificateRef))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read current gateway control certificate: %w", err)
	}
	serverKeyPEM, err := rotator.secrets.Get(server.PrivateKeyRef)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read current gateway control private key: %w", err)
	}
	return caPEM, serverPEM, serverKeyPEM, nil
}

type rotationSecret struct {
	reference model.SecretRef
	content   []byte
}

func (rotator *GatewayControlCARotator) stageSecrets(entries []rotationSecret) ([]model.SecretRef, error) {
	staged := make([]model.SecretRef, 0, len(entries))
	for _, entry := range entries {
		if err := rotator.secrets.PutIfAbsent(entry.reference, entry.content); err != nil {
			return nil, errors.Join(fmt.Errorf("stage rotation secret %s: %w", entry.reference, err), rotator.deleteSecrets(staged))
		}
		staged = append(staged, entry.reference)
	}
	return staged, nil
}

func (rotator *GatewayControlCARotator) deleteSecrets(references []model.SecretRef) error {
	var cleanupErrors []error
	for index := len(references) - 1; index >= 0; index-- {
		if _, err := rotator.secrets.Delete(references[index]); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("delete rotation secret %s: %w", references[index], err))
		}
	}
	return errors.Join(cleanupErrors...)
}

func rotationHostCertificateRecord(id string, kind model.CertificateKind, ownerID string, certificate *x509.Certificate, certificateRef, privateKeyRef model.SecretRef, sans []string) model.Certificate {
	values := make([]string, len(sans))
	copy(values, sans)
	sort.Strings(values)
	return model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: id, Kind: kind, OwnerKind: "host", OwnerID: ownerID,
		Fingerprint: gatewayCertificateFingerprint(certificate.Raw), SerialHex: certificate.SerialNumber.Text(16), Subject: certificate.Subject.String(),
		SANs: values, NotBefore: certificate.NotBefore.UTC(), NotAfter: certificate.NotAfter.UTC(), WarningDays: control.ControlWarningDays,
		Generation: 1, CertificateRef: string(certificateRef), PrivateKeyRef: privateKeyRef,
	}
}

func rotationNodeCertificateRecord(id string, node model.Node, issued control.IssuedNodeCertificate, certificateRef model.SecretRef) model.Certificate {
	return model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: id, Kind: model.CertificateControlNode, OwnerKind: "node", OwnerID: node.ID,
		Fingerprint: gatewayCertificateFingerprint(issued.Certificate.Raw), SerialHex: issued.Certificate.SerialNumber.Text(16), Subject: issued.Certificate.Subject.String(),
		SANs: []string{issued.IdentityURI}, NotBefore: issued.Certificate.NotBefore.UTC(), NotAfter: issued.Certificate.NotAfter.UTC(), WarningDays: control.ControlWarningDays,
		Generation: 1, CredentialGeneration: node.CredentialGeneration, CertificateRef: string(certificateRef),
	}
}

func parseRotationCertificate(certificatePEM []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("rotation certificate must contain exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse rotation certificate: %w", err)
	}
	return certificate, nil
}

func rotationOccupiedIDs(state model.State) map[string]struct{} {
	occupied := make(map[string]struct{}, len(state.Nodes)+len(state.Clients)+len(state.Certificates)+len(state.Operations)+1)
	occupied[state.Host.ID] = struct{}{}
	for _, node := range state.Nodes {
		occupied[node.ID] = struct{}{}
	}
	for _, client := range state.Clients {
		occupied[client.ID] = struct{}{}
	}
	for _, certificate := range state.Certificates {
		occupied[certificate.ID] = struct{}{}
	}
	for _, operation := range state.Operations {
		occupied[operation.ID] = struct{}{}
	}
	return occupied
}

func sortedActiveNodes(nodes []model.Node) []model.Node {
	result := make([]model.Node, 0, len(nodes))
	for _, node := range nodes {
		if node.Lifecycle == model.LifecycleActive {
			result = append(result, node)
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}

func findActiveNode(nodes []model.Node, id string) (model.Node, bool) {
	for _, node := range nodes {
		if node.ID == id && node.Lifecycle == model.LifecycleActive {
			return node, true
		}
	}
	return model.Node{}, false
}

func nodeRotationStep(nodeID string) string { return "node-" + nodeID }

func operationHasStep(operation model.Operation, name string) bool {
	for _, step := range operation.Steps {
		if step.Name == name {
			return true
		}
	}
	return false
}

func operationStepState(operation model.Operation, name string) model.OperationState {
	for _, step := range operation.Steps {
		if step.Name == name {
			return step.State
		}
	}
	return ""
}

func rotationCertificateIsStaged(certificate model.Certificate, operationID string) bool {
	return strings.HasPrefix(certificate.CertificateRef, "control-cert:"+operationID+"-")
}

func stagedNodeCertificate(state model.State, operationID, nodeID string) (model.Certificate, bool) {
	for _, certificate := range state.Certificates {
		if certificate.Kind == model.CertificateControlNode && certificate.OwnerID == nodeID && rotationCertificateIsStaged(certificate, operationID) {
			return certificate, true
		}
	}
	return model.Certificate{}, false
}

func nodeTrustUpdate(operationID, nodeID string, stateGeneration uint64, oldCA, newCA model.Certificate, oldCAPEM, newCAPEM, nodeCertificatePEM []byte) NodeControlTrustUpdate {
	return NodeControlTrustUpdate{
		OperationID: operationID, NodeID: nodeID, StateGeneration: stateGeneration,
		OldCAFingerprint: oldCA.Fingerprint, NewCAFingerprint: newCA.Fingerprint,
		ControlCAPEMs:      [][]byte{append([]byte(nil), oldCAPEM...), append([]byte(nil), newCAPEM...)},
		NodeCertificatePEM: append([]byte(nil), nodeCertificatePEM...),
	}
}

func appendCertificateReferences(references []model.SecretRef, certificate model.Certificate) []model.SecretRef {
	references = append(references, model.SecretRef(certificate.CertificateRef))
	if certificate.PrivateKeyRef != "" {
		references = append(references, certificate.PrivateKeyRef)
	}
	return references
}

func uniqueSecretRefs(references []model.SecretRef) []model.SecretRef {
	seen := make(map[model.SecretRef]struct{}, len(references))
	result := make([]model.SecretRef, 0, len(references))
	for _, reference := range references {
		if _, duplicate := seen[reference]; duplicate {
			continue
		}
		seen[reference] = struct{}{}
		result = append(result, reference)
	}
	return result
}
