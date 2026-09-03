package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const recoveryRequestID = "90000000-0000-4000-8000-000000000009"

func TestNodeRecoverySensitiveAggregatesRejectOrdinarySerialization(t *testing.T) {
	for name, value := range map[string]any{
		"request":  NodeRecoveryRequest{},
		"response": NodeRecoveryResponseMaterial{},
		"plan":     NodeRecoveryPlan{},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := json.Marshal(value); !errors.Is(err, output.ErrSensitiveSerialization) {
				t.Fatalf("json.Marshal(%s) error = %v", name, err)
			}
		})
	}
}

func TestNodeRecoveryReplacesCompleteGenerationAndPreservesStableResources(t *testing.T) {
	fixture := newNodeRecoveryFixture(t, "")
	defer fixture.destroy()
	beforeGateway := fixture.beforeGateway
	beforeNode := fixture.beforeNode
	plan, err := fixture.recovery.Plan(fixture.token)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NodeID != joinTestNodeID || plan.CurrentCredentialGeneration != 1 ||
		plan.RequestedCredentialGeneration != 2 || plan.ExpectedLocalStateGeneration != 3 ||
		plan.NextLocalStateGeneration != 5 || plan.ExpectedGatewayStateGeneration != 5 {
		t.Fatalf("Plan() = %s", plan.String())
	}
	result, err := fixture.recovery.Apply(context.Background(), plan, fixture.token)
	if err != nil {
		t.Fatal(err)
	}
	if result.CredentialGeneration != 2 || result.PreviousCredentialGeneration != 1 ||
		result.GatewayStateGeneration != 6 || result.LocalStateGeneration != 5 ||
		result.NodeRuntimeCleanupNeeded || result.CredentialCleanupNeeded || result.CommitConfirmationNeeded {
		t.Fatalf("Apply() = %+v", result)
	}
	gateway, _ := fixture.gatewayState.Load()
	nodeState, _ := fixture.nodeState.Load()
	if gateway.Generation != 6 || nodeState.Generation != 5 ||
		gateway.Nodes[0].CredentialGeneration != 2 || nodeState.Nodes[0].CredentialGeneration != 2 ||
		gateway.Invites[len(gateway.Invites)-1].State != model.InviteConsumed ||
		gateway.Invites[len(gateway.Invites)-1].ConsumptionHash == "" ||
		len(gateway.Nodes[0].IdempotencyRecords) != 1 ||
		gateway.Nodes[0].IdempotencyRecords[0].Operation != model.OperationRecover ||
		len(nodeState.Operations) != 1 || nodeState.Operations[0].Type != model.OperationRecover ||
		nodeState.Operations[0].State != model.OperationCompleted {
		t.Fatalf("recovered state mismatch: gateway=%+v node=%+v", gateway.Nodes[0], nodeState.Nodes[0])
	}
	if gateway.Nodes[0].ID != beforeGateway.Nodes[0].ID || gateway.Nodes[0].Name != beforeGateway.Nodes[0].Name ||
		gateway.Nodes[0].OverlayIPv4 != beforeGateway.Nodes[0].OverlayIPv4 ||
		gateway.Nodes[0].ActiveTransport != beforeGateway.Nodes[0].ActiveTransport ||
		!reflect.DeepEqual(gateway.Nodes[0].AssignedPresets, beforeGateway.Nodes[0].AssignedPresets) ||
		!reflect.DeepEqual(gateway.Policies, beforeGateway.Policies) || !reflect.DeepEqual(gateway.Exposes, beforeGateway.Exposes) ||
		nodeState.Nodes[0].ID != beforeNode.Nodes[0].ID || nodeState.Nodes[0].Name != beforeNode.Nodes[0].Name ||
		nodeState.Nodes[0].OverlayIPv4 != beforeNode.Nodes[0].OverlayIPv4 ||
		!reflect.DeepEqual(nodeState.Policies, beforeNode.Policies) {
		t.Fatal("recovery changed immutable identity, overlay IP, policies, presets, transport, or exposes")
	}
	for _, record := range append(append([]model.Transport{}, gateway.Transports...), nodeState.Transports...) {
		if record.CredentialGeneration != 2 {
			t.Fatalf("recovery retained mixed transport generation: %+v", record)
		}
	}
	assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 1, false)
	assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 2, true)
	assertRotationGatewaySecrets(t, fixture.gatewaySecrets, gateway, 1, false)
	assertRotationGatewaySecrets(t, fixture.gatewaySecrets, gateway, 2, true)
	if _, err := fixture.manager.Authorize(fixture.tokenBytes); !errors.Is(err, ErrRecoveryConsumed) {
		t.Fatalf("consumed recovery replay error = %v", err)
	}
}

func TestGatewayRecoveryRejectsClonedOrWrongHostWithoutOriginalKeyBeforeAnyMutation(t *testing.T) {
	fixture := newNodeRecoveryFixture(t, "")
	defer fixture.destroy()
	before, _ := fixture.gatewayState.Load()
	installation, err := fixture.recovery.credentials.Provision(context.Background(), joinTestNodeID, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.recovery.credentials.Rollback(context.Background(), installation)
	shared, err := fixture.recovery.credentials.SharedCredentialPayload(installation)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Destroy()
	_, wrongKey, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x2a}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(wrongPEM)
	nonce := [EnrollmentNonceBytes]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	payload, err := EncodeNodeRecoveryRequest(
		fixture.recoveryID, recoveryRequestID, 1, nonce, installation, shared, wrongPEM,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.Destroy()
	var payloadBytes []byte
	_ = payload.Use(func(value []byte) error { payloadBytes = append([]byte(nil), value...); return nil })
	request := PublicEnrollmentRequest{
		Purpose: PurposeRecover, Endpoint: "https://203.0.113.10" + EnrollmentRecoveryPath,
		NodeNonce: nonce, GatewayNonce: [EnrollmentNonceBytes]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		Payload: payloadBytes, token: fixture.token,
	}
	if _, err := fixture.coordinator.PreparePublicEnrollment(context.Background(), request); !errors.Is(err, ErrPublicEnrollmentRejected) {
		t.Fatalf("wrong-host PreparePublicEnrollment() error = %v", err)
	}
	after, _ := fixture.gatewayState.Load()
	if !reflect.DeepEqual(before, after) || fixture.gatewayRuntime.stageCalls != 0 {
		t.Fatalf("wrong-host proof mutated gateway state/runtime: before=%d after=%d stages=%d",
			before.Generation, after.Generation, fixture.gatewayRuntime.stageCalls)
	}
}

func TestNodeRecoveryFailureBeforePublicCommitKeepsOldGenerationAndTokenActive(t *testing.T) {
	for _, phase := range []string{"gateway_stage", "gateway_check", "gateway_activate"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newNodeRecoveryFixture(t, phase)
			defer fixture.destroy()
			plan, err := fixture.recovery.Plan(fixture.token)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.recovery.Apply(context.Background(), plan, fixture.token); err == nil {
				t.Fatalf("recovery accepted injected pre-commit failure at %s", phase)
			}
			gateway, _ := fixture.gatewayState.Load()
			nodeState, _ := fixture.nodeState.Load()
			if gateway.Generation != 5 || gateway.Nodes[0].CredentialGeneration != 1 ||
				gateway.Invites[len(gateway.Invites)-1].State != model.InviteActive ||
				nodeState.Nodes[0].CredentialGeneration != 1 || nodeState.Operations[0].State != model.OperationFailed {
				t.Fatalf("pre-commit failure did not preserve old generation/token: gateway=%+v node=%+v",
					gateway.Nodes[0], nodeState.Nodes[0])
			}
			assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 1, true)
			assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 2, false)
		})
	}
}

func TestNodeRecoveryFailureAfterGatewayCommitRetainsTwoCompleteSetsForReconciliation(t *testing.T) {
	for _, phase := range []string{"node_stage", "node_check", "node_activate", "post_check"} {
		t.Run(phase, func(t *testing.T) {
			fixture := newNodeRecoveryFixture(t, phase)
			defer fixture.destroy()
			plan, err := fixture.recovery.Plan(fixture.token)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.recovery.Apply(context.Background(), plan, fixture.token); !errors.Is(err, ErrNodeRotationCommitUncertain) {
				t.Fatalf("Apply(%s) error = %v", phase, err)
			}
			gateway, _ := fixture.gatewayState.Load()
			nodeState, _ := fixture.nodeState.Load()
			if gateway.Generation != 6 || gateway.Nodes[0].CredentialGeneration != 2 ||
				gateway.Invites[len(gateway.Invites)-1].State != model.InviteConsumed ||
				nodeState.Generation != 4 || nodeState.Nodes[0].CredentialGeneration != 1 ||
				nodeState.Operations[0].State != model.OperationPending {
				t.Fatalf("post-commit failure lost reconciliation state: gateway=%+v node=%+v",
					gateway.Nodes[0], nodeState.Nodes[0])
			}
			assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 1, true)
			assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 2, true)
		})
	}
}

type nodeRecoveryFixture struct {
	*nodeRotationFixture
	recovery      *NodeRecoveryWorkflow
	manager       *RecoveryManager
	coordinator   *RecoveryEnrollmentCoordinator
	token         *output.Secret
	tokenBytes    []byte
	recoveryID    string
	beforeGateway model.State
	beforeNode    model.State
}

func newNodeRecoveryFixture(t *testing.T, failure string) *nodeRecoveryFixture {
	t.Helper()
	base := newNodeRotationFixture(t, "", false)
	gateway, _ := base.gatewayState.Load()
	certificate, err := currentNodeControlCertificate(gateway, gateway.Nodes[0])
	if err != nil {
		base.destroy()
		t.Fatal(err)
	}
	now := certificate.NotAfter
	manager, err := NewRecoveryManager(
		base.gatewayState, bytes.NewReader(bytes.Repeat([]byte{0x33}, 256)), func() time.Time { return now },
	)
	if err != nil {
		base.destroy()
		t.Fatal(err)
	}
	issuePlan, err := manager.PlanIssue(joinTestNodeID)
	if err != nil {
		base.destroy()
		t.Fatal(err)
	}
	issued, err := manager.CommitIssue(context.Background(), issuePlan)
	if err != nil {
		base.destroy()
		t.Fatal(err)
	}
	var tokenBytes []byte
	_ = issued.Token.Use(func(value []byte) error { tokenBytes = append([]byte(nil), value...); return nil })
	base.gatewayRuntime.failure = failure
	base.nodeRuntime.failure = failure
	rotation, err := NewGatewayNodeRotationManager(
		base.gatewayState, base.gatewaySecrets, base.gatewayRuntime, GatewayNodeRotationOptions{
			Entropy: bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096)), Now: func() time.Time { return now },
			NewCertificateID: func() (string, error) { return rotationCertificateID, nil },
		},
	)
	if err != nil {
		issued.Token.Destroy()
		base.destroy()
		t.Fatal(err)
	}
	builder, err := NewGatewayRecoveryBuilder(manager, rotation)
	if err != nil {
		issued.Token.Destroy()
		base.destroy()
		t.Fatal(err)
	}
	coordinator, err := NewRecoveryEnrollmentCoordinator(manager, builder)
	if err != nil {
		issued.Token.Destroy()
		base.destroy()
		t.Fatal(err)
	}
	joinHandler, ok := base.exchanger.handler.(*PublicEnrollmentHandler)
	if !ok {
		issued.Token.Destroy()
		base.destroy()
		t.Fatalf("join handler = %T", base.exchanger.handler)
	}
	handler, err := NewPublicEnrollmentHandler(PublicEnrollmentHandlerConfig{
		PublicIPv4: "203.0.113.10", Signer: joinHandler.signer, Coordinator: coordinator,
		Entropy: bytes.NewReader(bytes.Repeat([]byte{0x64}, 128)), Now: func() time.Time { return now },
	})
	if err != nil {
		issued.Token.Destroy()
		base.destroy()
		t.Fatal(err)
	}
	exchanger := &handlerJoinExchanger{handler: handler}
	ids := []string{rotationOperationID, recoveryRequestID}
	nodeRecovery, err := NewNodeRecoveryWorkflow(
		base.nodeState, base.nodeSecrets, exchanger, base.nodeRuntime, NodeRecoveryOptions{
			Entropy: bytes.NewReader(bytes.Repeat([]byte{0x71}, 4096)), Now: func() time.Time { return now },
			NewUUID: func() (string, error) {
				if len(ids) == 0 {
					return "", errors.New("recovery UUID sequence exhausted")
				}
				id := ids[0]
				ids = ids[1:]
				return id, nil
			},
			WireGuardRunner: &joinWireGuardRunner{nodePrivate: rotationWireGuardPrivate(), nodePublic: rotationWireGuardPublic()},
			DrainTimeout:    5 * time.Second,
		},
	)
	if err != nil {
		issued.Token.Destroy()
		base.destroy()
		t.Fatal(err)
	}
	beforeGateway, _ := base.gatewayState.Load()
	beforeNode, _ := base.nodeState.Load()
	return &nodeRecoveryFixture{
		nodeRotationFixture: base, recovery: nodeRecovery, manager: manager, coordinator: coordinator,
		token: issued.Token, tokenBytes: tokenBytes, recoveryID: issued.RecoveryID,
		beforeGateway: beforeGateway, beforeNode: beforeNode,
	}
}

func (fixture *nodeRecoveryFixture) destroy() {
	if fixture == nil {
		return
	}
	if fixture.token != nil {
		fixture.token.Destroy()
	}
	clear(fixture.tokenBytes)
	fixture.nodeRotationFixture.destroy()
}
