package enrollment

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestV2NodeCredentialLifecycleE2E(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", false)
	defer fixture.destroy()
	beforeGateway, _ := fixture.gatewayState.Load()
	beforeNode, _ := fixture.nodeState.Load()

	rotation, err := fixture.rotation.Plan()
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := fixture.rotation.Apply(context.Background(), rotation)
	if err != nil || rotated.CredentialGeneration != 2 || rotated.PreviousCredentialGeneration != 1 {
		t.Fatalf("node rotation = %+v, %v", rotated, err)
	}
	assertSuccessfulNodeRotation(t, fixture, beforeGateway, beforeNode)
	rotatedGateway, _ := fixture.gatewayState.Load()
	rotatedCertificate, err := currentNodeControlCertificate(rotatedGateway, rotatedGateway.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}

	runtime := &recordingNodeLifecycleRuntime{state: fixture.gatewayState, report: healthyNodeRevocationReport()}
	lifecycle, err := NewNodeLifecycleManager(
		fixture.gatewayState, fixture.gatewaySecrets, runtime,
		func() time.Time { return fixture.oldGateway.Host.InitializedAt.Add(6 * time.Minute) },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.PlanDelete(joinTestNodeID); !errors.Is(err, ErrNodeDeleteRequiresRevoke) {
		t.Fatalf("active node delete error = %v", err)
	}
	revocation, err := lifecycle.PlanRevoke(joinTestNodeID)
	if err != nil || revocation.CredentialGeneration != 2 || len(revocation.ExposeIDs) != 1 {
		t.Fatalf("node revoke plan = %s, %v", revocation.String(), err)
	}
	revoked, err := lifecycle.CommitRevoke(context.Background(), revocation)
	if err != nil || !revoked.Changed || revoked.CredentialGeneration != 2 || !revoked.ConnectionsClosed {
		t.Fatalf("node revoke = %+v, %v", revoked, err)
	}
	revokedGateway, _ := fixture.gatewayState.Load()
	if revokedGateway.Generation != 6 || revokedGateway.Nodes[0].Lifecycle != model.LifecycleRevoked ||
		revokedGateway.Nodes[0].CredentialGeneration != 2 || len(revokedGateway.Exposes) != 1 ||
		revokedGateway.Exposes[0].State != model.ExposeDisabled || len(revokedGateway.Policies) != 1 {
		t.Fatalf("node revoke changed stable resources or left an active path: %+v", revokedGateway)
	}
	for _, record := range revokedGateway.Transports {
		if record.OwnerID == joinTestNodeID && record.State != model.TransportDisabled {
			t.Fatalf("node revoke retained active transport: %+v", record)
		}
	}
	authorizer, err := control.NewStateNodeAuthorizer(fixture.gatewayState)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := authorizer.AuthorizeRPC(context.Background(), control.RPCPeer{
		NodeID: joinTestNodeID, CertificateFingerprint: rotatedCertificate.Fingerprint,
	}, control.RPCRequest{NodeID: joinTestNodeID, CredentialGeneration: 2})
	if err != nil || authorization.Authorized || authorization.Denial.Response.ErrorCode != "node_inactive" {
		t.Fatalf("revoked node generation authorization = %+v, %v", authorization, err)
	}
	assertRotationGatewaySecrets(t, fixture.gatewaySecrets, revokedGateway, 1, false)
	assertRotationGatewaySecrets(t, fixture.gatewaySecrets, revokedGateway, 2, false)
	assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 2, true)

	deletion, err := lifecycle.PlanDelete(joinTestNodeID)
	if err != nil || deletion.CredentialGeneration != 2 {
		t.Fatalf("node delete plan = %s, %v", deletion.String(), err)
	}
	deleted, err := lifecycle.CommitDelete(context.Background(), deletion)
	if err != nil || !deleted.Changed || runtime.deleteCalls != 1 {
		t.Fatalf("node delete = %+v, %v", deleted, err)
	}
	finalGateway, _ := fixture.gatewayState.Load()
	if finalGateway.Generation != 7 || len(finalGateway.Nodes) != 1 ||
		finalGateway.Nodes[0].Lifecycle != model.LifecycleDeleted || len(finalGateway.Transports) != 0 ||
		len(finalGateway.Policies) != 0 || len(finalGateway.Exposes) != 0 || len(finalGateway.Certificates) != 2 ||
		finalGateway.Certificates[0].Kind != model.CertificateControlCA ||
		finalGateway.Certificates[1].Kind != model.CertificateTunnelServer {
		t.Fatalf("node delete retained gateway-owned resources: %+v", finalGateway)
	}
	localState, _ := fixture.nodeState.Load()
	if localState.Nodes[0].ID != beforeNode.Nodes[0].ID || localState.Nodes[0].Lifecycle != model.LifecycleActive ||
		localState.Nodes[0].CredentialGeneration != 2 {
		t.Fatalf("gateway-side lifecycle assumed private-node access: %+v", localState.Nodes[0])
	}
}
