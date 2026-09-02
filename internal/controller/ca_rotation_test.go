package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestControlCARotationKeepsBothGenerationsManageableUntilNewOnlyCommit(t *testing.T) {
	fixture := newGatewayRenewalFixture(t)
	rotator := newTestControlCARotator(t, fixture)
	before, err := fixture.state.Load()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := rotator.Plan(context.Background())
	if err != nil || plan.Staged || plan.StateGeneration != before.Generation || len(plan.Nodes) != 1 || plan.Nodes[0].ID != mutationTestNodeID {
		t.Fatalf("initial plan = %+v, %v", plan, err)
	}
	unchanged, _ := fixture.state.Load()
	if unchanged.Generation != before.Generation {
		t.Fatalf("read-only plan advanced state to %d", unchanged.Generation)
	}

	plan, err = rotator.Stage(context.Background())
	if err != nil || !plan.Staged || plan.OperationID == "" || plan.CurrentCAFingerprint == plan.StagedCAFingerprint || plan.Nodes[0].TrustUpdated {
		t.Fatalf("staged plan = %+v, %v", plan, err)
	}
	assertRotationCertificateCounts(t, fixture, 2, 2, 1)
	renewer, err := fixture.controller.NewGatewayControlLeafRenewer(fixture.secrets, fixture.server, GatewayControlLeafRenewalRuntime{
		Entropy: rand.Reader, NewUUID: func() (string, error) { return "77000000-0000-4000-8000-000000000001", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewal, err := renewer.RenewIfNeeded(context.Background()); err != nil || renewal.Changed {
		t.Fatalf("same-CA leaf renewal check during overlap = %+v, %v", renewal, err)
	}
	callRotationClient(t, fixture, fixture.client, "74000000-0000-4000-8000-000000000001")

	newNode, err := control.GenerateNodeControlCSR(rand.Reader, mutationTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	update, err := rotator.UpdateNodeTrust(context.Background(), mutationTestNodeID, newNode.CSRPEM)
	if err != nil || update.OperationID != plan.OperationID || update.OldCAFingerprint != plan.CurrentCAFingerprint ||
		update.NewCAFingerprint != plan.StagedCAFingerprint || len(update.ControlCAPEMs) != 2 {
		t.Fatalf("node trust update = %+v, %v", update, err)
	}
	dualBundle := append(append([]byte(nil), update.ControlCAPEMs[0]...), update.ControlCAPEMs[1]...)
	newDualClient := newRotationRPCClient(t, fixture, dualBundle, update.NodeCertificatePEM, newNode.PrivateKeyPEM)
	if repeated, err := rotator.UpdateNodeTrust(context.Background(), mutationTestNodeID, []byte("ignored-after-issuance")); err != nil ||
		!bytes.Equal(repeated.NodeCertificatePEM, update.NodeCertificatePEM) || repeated.StateGeneration != update.StateGeneration {
		t.Fatalf("idempotent node trust update = %+v, %v", repeated, err)
	}
	if restored, err := rotator.RestoreRuntime(context.Background()); err != nil || !restored {
		t.Fatalf("restore staged runtime = %t, %v", restored, err)
	}
	callRotationClient(t, fixture, fixture.client, "74000000-0000-4000-8000-000000000002")
	callRotationClient(t, fixture, newDualClient, "74000000-0000-4000-8000-000000000003")
	newCertificate := parseCertificatePEMForRenewalTest(t, update.NodeCertificatePEM)
	peer := control.RPCPeer{NodeID: mutationTestNodeID, CertificateFingerprint: gatewayCertificateFingerprint(newCertificate.Raw)}
	if _, err := rotator.AcknowledgeNodeTrust(context.Background(), control.RPCPeer{
		NodeID: mutationTestNodeID, CertificateFingerprint: fixture.initialNodeCertificate.Fingerprint,
	}, update.NewCAFingerprint); err == nil {
		t.Fatal("old-CA certificate acknowledged the staged node trust")
	}
	if _, err := rotator.AcknowledgeNodeTrust(context.Background(), peer, update.OldCAFingerprint); err == nil {
		t.Fatal("node trust acknowledgement accepted the wrong CA fingerprint")
	}
	ack, err := rotator.AcknowledgeNodeTrust(context.Background(), peer, update.NewCAFingerprint)
	if err != nil || ack.NodeID != mutationTestNodeID || ack.CAFingerprint != update.NewCAFingerprint || ack.StateGeneration <= update.StateGeneration {
		t.Fatalf("node trust acknowledgement = %+v, %v", ack, err)
	}
	plan, err = rotator.Plan(context.Background())
	if err != nil || !plan.Nodes[0].TrustUpdated {
		t.Fatalf("updated staged plan = %+v, %v", plan, err)
	}
	if repeated, err := rotator.AcknowledgeNodeTrust(context.Background(), peer, update.NewCAFingerprint); err != nil || repeated.StateGeneration != ack.StateGeneration {
		t.Fatalf("idempotent node trust acknowledgement = %+v, %v", repeated, err)
	}

	result, err := rotator.Commit(context.Background())
	if err != nil || result.CAFingerprint != update.NewCAFingerprint || result.OperationID != plan.OperationID || len(result.NodeActions) != 0 {
		t.Fatalf("commit = %+v, %v", result, err)
	}
	assertRotationCertificateCounts(t, fixture, 1, 1, 1)
	newOnlyClient := newRotationRPCClient(t, fixture, update.ControlCAPEMs[1], update.NodeCertificatePEM, newNode.PrivateKeyPEM)
	callRotationClient(t, fixture, newOnlyClient, "74000000-0000-4000-8000-000000000004")
	if _, err := fixture.client.Call(context.Background(), rotationRequest(fixture, "74000000-0000-4000-8000-000000000005")); err == nil {
		t.Fatal("old-CA node client remained trusted after commit")
	}
	after, err := fixture.state.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after.Certificates[certificateIndexByKind(t, after, model.CertificatePublicIngress)], fixture.initialPublicCertificate) ||
		!reflect.DeepEqual(after.EnrollmentIdentity, fixture.initialEnrollment) || !reflect.DeepEqual(after.Nodes, fixture.initialNodes) {
		t.Fatal("control CA rotation changed public ingress, enrollment identity, or node resources")
	}
	assertRotationDidNotTouchDataPlane(t, fixture)
	if finalPlan, err := rotator.Plan(context.Background()); err != nil || finalPlan.Staged || finalPlan.CurrentCAFingerprint != update.NewCAFingerprint {
		t.Fatalf("final plan = %+v, %v", finalPlan, err)
	}
}

func TestControlCARotationRollbackRestoresOldOnlyAndReportsNodeAction(t *testing.T) {
	fixture := newGatewayRenewalFixture(t)
	rotator := newTestControlCARotator(t, fixture)
	plan, err := rotator.Stage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	newNode, err := control.GenerateNodeControlCSR(rand.Reader, mutationTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	update, err := rotator.UpdateNodeTrust(context.Background(), mutationTestNodeID, newNode.CSRPEM)
	if err != nil {
		t.Fatal(err)
	}
	dualBundle := append(append([]byte(nil), update.ControlCAPEMs[0]...), update.ControlCAPEMs[1]...)
	newClient := newRotationRPCClient(t, fixture, dualBundle, update.NodeCertificatePEM, newNode.PrivateKeyPEM)
	callRotationClient(t, fixture, fixture.client, "75000000-0000-4000-8000-000000000001")
	callRotationClient(t, fixture, newClient, "75000000-0000-4000-8000-000000000002")
	newCertificate := parseCertificatePEMForRenewalTest(t, update.NodeCertificatePEM)
	if _, err := rotator.AcknowledgeNodeTrust(context.Background(), control.RPCPeer{
		NodeID: mutationTestNodeID, CertificateFingerprint: gatewayCertificateFingerprint(newCertificate.Raw),
	}, update.NewCAFingerprint); err != nil {
		t.Fatal(err)
	}

	result, err := rotator.Rollback(context.Background())
	if err != nil || result.CAFingerprint != plan.CurrentCAFingerprint || !reflect.DeepEqual(result.NodeActions, []string{mutationTestNodeID}) {
		t.Fatalf("rollback = %+v, %v", result, err)
	}
	assertRotationCertificateCounts(t, fixture, 1, 1, 1)
	callRotationClient(t, fixture, fixture.client, "75000000-0000-4000-8000-000000000003")
	if _, err := newClient.Call(context.Background(), rotationRequest(fixture, "75000000-0000-4000-8000-000000000004")); err == nil {
		t.Fatal("new-CA node client remained trusted after rollback")
	}
	state, err := fixture.state.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, certificate := range state.Certificates {
		if rotationCertificateIsStaged(certificate, plan.OperationID) {
			t.Fatalf("rollback retained staged certificate %+v", certificate)
		}
	}
	for _, operation := range state.Operations {
		if operation.ID == plan.OperationID && (operation.State != model.OperationFailed || operation.ErrorCode != "operator-rollback") {
			t.Fatalf("rollback operation = %+v", operation)
		}
	}
	assertRotationDidNotTouchDataPlane(t, fixture)
}

func TestControlCARotationCommitRefusesIncompleteImpact(t *testing.T) {
	fixture := newGatewayRenewalFixture(t)
	rotator := newTestControlCARotator(t, fixture)
	plan, err := rotator.Stage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	newNode, err := control.GenerateNodeControlCSR(rand.Reader, mutationTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	update, err := rotator.UpdateNodeTrust(context.Background(), mutationTestNodeID, newNode.CSRPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotator.Commit(context.Background()); !errors.Is(err, ErrControlCARotationIncomplete) {
		t.Fatalf("incomplete commit error = %v", err)
	}
	state, _ := fixture.state.Load()
	if state.Generation != update.StateGeneration || state.Generation == plan.StateGeneration {
		t.Fatalf("incomplete commit advanced state to %d", state.Generation)
	}
	callRotationClient(t, fixture, fixture.client, "76000000-0000-4000-8000-000000000001")
}

func newTestControlCARotator(t *testing.T, fixture *gatewayRenewalFixture) *GatewayControlCARotator {
	t.Helper()
	ids := []string{
		"73000000-0000-4000-8000-000000000001",
		"73000000-0000-4000-8000-000000000002",
		"73000000-0000-4000-8000-000000000003",
		"73000000-0000-4000-8000-000000000004",
	}
	next := 0
	rotator, err := fixture.controller.NewGatewayControlCARotator(fixture.secrets, fixture.server, GatewayControlCARotationRuntime{
		Entropy: rand.Reader,
		NewUUID: func() (string, error) {
			if next >= len(ids) {
				return "", errors.New("test UUID sequence exhausted")
			}
			id := ids[next]
			next++
			return id, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rotator
}

func newRotationRPCClient(t *testing.T, fixture *gatewayRenewalFixture, caPEM, certificatePEM, privateKeyPEM []byte) *control.RPCClient {
	t.Helper()
	client, err := control.NewRPCClient(control.RPCClientConfig{
		Address: fixture.listener.Addr().String(), GatewayID: fixture.initialServerRecord.OwnerID, NodeID: mutationTestNodeID,
		CACertificatePEM: caPEM, CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM, Now: fixture.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func rotationRequest(fixture *gatewayRenewalFixture, requestID string) control.RPCRequest {
	state, _ := fixture.state.Load()
	return control.RPCRequest{
		ProtocolMajor: 1, ProtocolMinor: 0, RequestID: requestID, ExpectedStateGeneration: state.Generation,
		NodeID: mutationTestNodeID, CredentialGeneration: 1, Timestamp: fixture.clock.Now(),
		Nonce:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x72}, control.RPCNonceBytes)),
		Operation: "status", Payload: json.RawMessage(`{}`),
	}
}

func callRotationClient(t *testing.T, fixture *gatewayRenewalFixture, client *control.RPCClient, requestID string) {
	t.Helper()
	result, err := client.Call(context.Background(), rotationRequest(fixture, requestID))
	if err != nil || result.StatusCode != http.StatusOK {
		t.Fatalf("rotation control call = %+v, %v", result, err)
	}
}

func assertRotationCertificateCounts(t *testing.T, fixture *gatewayRenewalFixture, wantCA, wantServer, wantNode int) {
	t.Helper()
	state, err := fixture.state.Load()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[model.CertificateKind]int{}
	for _, certificate := range state.Certificates {
		counts[certificate.Kind]++
	}
	if counts[model.CertificateControlCA] != wantCA || counts[model.CertificateControlServer] != wantServer || counts[model.CertificateControlNode] != wantNode {
		t.Fatalf("certificate counts = %+v, want CA=%d server=%d node=%d", counts, wantCA, wantServer, wantNode)
	}
}

func certificateIndexByKind(t *testing.T, state model.State, kind model.CertificateKind) int {
	t.Helper()
	for index, certificate := range state.Certificates {
		if certificate.Kind == kind {
			return index
		}
	}
	t.Fatalf("certificate kind %s is absent", kind)
	return -1
}

func assertRotationDidNotTouchDataPlane(t *testing.T, fixture *gatewayRenewalFixture) {
	t.Helper()
	if fixture.dataPlane.starts != 0 || fixture.dataPlane.stops != 0 || fixture.dataPlane.restarts != 0 || !fixture.dataPlane.active {
		t.Fatalf("control CA rotation changed data plane: %+v", fixture.dataPlane)
	}
	publicCertificate, err := fixture.secrets.Get(model.SecretRef(fixture.initialPublicCertificate.CertificateRef))
	if err != nil || !bytes.Equal(publicCertificate, fixture.preservedSecrets[model.SecretRef(fixture.initialPublicCertificate.CertificateRef)]) {
		t.Fatalf("public ingress certificate changed: %v", err)
	}
	publicKey, err := fixture.secrets.Get(fixture.initialPublicCertificate.PrivateKeyRef)
	if err != nil || !bytes.Equal(publicKey, fixture.preservedSecrets[fixture.initialPublicCertificate.PrivateKeyRef]) {
		t.Fatalf("public ingress key changed: %v", err)
	}
	if _, err := store.NewSecretStore(fixture.paths); err != nil {
		t.Fatalf("secret store became invalid: %v", err)
	}
}
