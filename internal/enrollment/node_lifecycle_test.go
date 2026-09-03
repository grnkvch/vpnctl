package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

const nodeLifecycleExposeID = "40000000-0000-4000-8000-000000000004"

func TestNodeRevokeImmediatelyDisablesEveryPathAndIsIdempotent(t *testing.T) {
	fixture := newNodeLifecycleFixture(t, healthyNodeRevocationReport())
	defer fixture.destroy()
	plan, err := fixture.manager.PlanRevoke("PRIVATE-NODE")
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Changed || plan.NodeID != joinTestNodeID || plan.NextStateGeneration != 5 ||
		!reflect.DeepEqual(plan.ExposeIDs, []string{nodeLifecycleExposeID}) {
		t.Fatalf("PlanRevoke() = %s", plan.String())
	}
	if _, err := plan.MarshalJSON(); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("plan MarshalJSON() error = %v", err)
	}
	result, err := fixture.manager.CommitRevoke(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.StateGeneration != 5 || !result.ConnectionsClosed ||
		!reflect.DeepEqual(result.DisabledExposeIDs, []string{nodeLifecycleExposeID}) {
		t.Fatalf("CommitRevoke() = %+v", result)
	}
	assertNodeRevokedFailClosed(t, fixture)

	repeatedPlan, err := fixture.manager.PlanRevoke(joinTestNodeID)
	if err != nil || repeatedPlan.Changed || repeatedPlan.NextStateGeneration != 5 {
		t.Fatalf("repeated PlanRevoke() = %s, %v", repeatedPlan.String(), err)
	}
	repeated, err := fixture.manager.CommitRevoke(context.Background(), repeatedPlan)
	if err != nil || repeated.Changed || repeated.StateGeneration != 5 || !repeated.ConnectionsClosed || fixture.runtime.revokeCalls != 2 {
		t.Fatalf("repeated CommitRevoke() = %+v, %v; calls=%d", repeated, err, fixture.runtime.revokeCalls)
	}
	state, _ := fixture.gatewayState.Load()
	if state.Generation != 5 {
		t.Fatalf("repeated revoke advanced generation to %d", state.Generation)
	}
}

func TestNodeRevokeRejectsTamperedPlanBeforeMutation(t *testing.T) {
	fixture := newNodeLifecycleFixture(t, healthyNodeRevocationReport())
	defer fixture.destroy()
	plan, err := fixture.manager.PlanRevoke("private-node")
	if err != nil {
		t.Fatal(err)
	}
	plan.NodeName = "different-node"
	if _, err := fixture.manager.CommitRevoke(context.Background(), plan); !errors.Is(err, ErrNodeLifecycleStale) {
		t.Fatalf("CommitRevoke(tampered plan) error = %v", err)
	}
	state, err := fixture.gatewayState.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != 4 || state.Nodes[0].Lifecycle != model.LifecycleActive || fixture.runtime.revokeCalls != 0 {
		t.Fatalf("tampered plan changed state/runtime: generation=%d lifecycle=%s calls=%d",
			state.Generation, state.Nodes[0].Lifecycle, fixture.runtime.revokeCalls)
	}
}

func TestNodeDeleteRequiresRevokeAndRemovesOnlyGatewayResources(t *testing.T) {
	fixture := newNodeLifecycleFixture(t, healthyNodeRevocationReport())
	defer fixture.destroy()
	if _, err := fixture.manager.PlanDelete("private-node"); !errors.Is(err, ErrNodeDeleteRequiresRevoke) {
		t.Fatalf("PlanDelete(active) error = %v", err)
	}
	revoke, _ := fixture.manager.PlanRevoke("private-node")
	if _, err := fixture.manager.CommitRevoke(context.Background(), revoke); err != nil {
		t.Fatal(err)
	}
	plan, err := fixture.manager.PlanDelete(joinTestNodeID)
	if err != nil || !plan.Changed || plan.NextStateGeneration != 6 {
		t.Fatalf("PlanDelete() = %s, %v", plan.String(), err)
	}
	result, err := fixture.manager.CommitDelete(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.StateGeneration != 6 || fixture.runtime.deleteCalls != 1 {
		t.Fatalf("CommitDelete() = %+v, %v; calls=%d", result, err, fixture.runtime.deleteCalls)
	}
	state, _ := fixture.gatewayState.Load()
	if len(state.Nodes) != 1 || state.Nodes[0].Lifecycle != model.LifecycleDeleted || state.Nodes[0].RevokedAt == nil ||
		len(state.Nodes[0].AssignedPresets) != 0 || len(state.Transports) != 0 || len(state.Policies) != 0 ||
		len(state.Exposes) != 0 || len(state.Certificates) != 1 || state.Certificates[0].Kind != model.CertificateControlCA {
		t.Fatalf("deleted gateway resources = %+v", state)
	}
	catalog, _ := NewNodeCatalog(fixture.gatewayState)
	listed, listErr := catalog.List()
	if listErr != nil || len(listed.Items) != 0 {
		t.Fatalf("List() after delete = %+v, %v", listed, listErr)
	}
	if _, showErr := catalog.Show(joinTestNodeID); !errors.Is(showErr, ErrNodeNotFound) {
		t.Fatalf("Show(deleted) error = %v", showErr)
	}
	local, _ := fixture.nodeState.Load()
	if len(local.Nodes) != 1 || local.Nodes[0].Lifecycle != model.LifecycleActive {
		t.Fatalf("gateway delete assumed private-node access: %+v", local.Nodes)
	}
}

func TestIncompleteRuntimeCloseKeepsAuthoritativeRevokeFailClosed(t *testing.T) {
	report := healthyNodeRevocationReport()
	report.TunnelClosed = false
	fixture := newNodeLifecycleFixture(t, report)
	defer fixture.destroy()
	plan, _ := fixture.manager.PlanRevoke("private-node")
	result, err := fixture.manager.CommitRevoke(context.Background(), plan)
	if !errors.Is(err, ErrNodeCleanupPending) || !errors.Is(err, ErrNodeRevocationIncomplete) ||
		!result.RuntimeReconcileNeeded || result.ConnectionsClosed {
		t.Fatalf("CommitRevoke(incomplete runtime) = %+v, %v", result, err)
	}
	public := result.OutputResult()
	if public.Status != output.StatusPending || len(public.RequiresAction) != 1 || public.RequiresAction[0].Code != "repair_node_runtime" {
		t.Fatalf("pending output = %+v", public)
	}
	assertNodeRevokedFailClosed(t, fixture)
}

func TestRevokingOneNodePreservesOtherNodeIdentityAndPaths(t *testing.T) {
	joined := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer joined.destroy()
	if _, err := joined.workflow.Join(context.Background(), joined.token, model.TransportRestricted, []string{"telegram"}); err != nil {
		t.Fatal(err)
	}
	secondID := "30000000-0000-4000-8000-000000000003"
	secondState, secondSecrets := joinAdditionalLifecycleNode(t, joined, "webhook-node", secondID)
	runtime := &recordingNodeLifecycleRuntime{state: joined.gatewayState, report: healthyNodeRevocationReport()}
	manager, err := NewNodeLifecycleManager(
		joined.gatewayState, joined.gatewaySecrets, runtime,
		func() time.Time { return joined.now.Add(3 * time.Minute) },
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.PlanRevoke(joinTestNodeID)
	if err != nil || plan.NextStateGeneration != 6 {
		t.Fatalf("PlanRevoke() = %s, %v", plan.String(), err)
	}
	if _, err := manager.CommitRevoke(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	state, _ := joined.gatewayState.Load()
	if len(state.Nodes) != 2 || state.Nodes[0].Lifecycle != model.LifecycleRevoked || state.Nodes[1].ID != secondID ||
		state.Nodes[1].Lifecycle != model.LifecycleActive || len(state.Transports) != 4 || len(state.Certificates) != 3 {
		t.Fatalf("one-of-many revoke state = %+v", state)
	}
	for _, record := range state.Transports {
		if record.OwnerID == joinTestNodeID && record.State != model.TransportDisabled {
			t.Fatalf("revoked node transport = %+v", record)
		}
		if record.OwnerID == secondID && record.State == model.TransportDisabled {
			t.Fatalf("other node transport disabled = %+v", record)
		}
	}
	standard, err := transport.RenderGatewayStandardConfig(context.Background(), transport.GatewayStandardRenderRequest{
		State: state, CredentialRef: transport.GatewayStandardCredentialRef,
		Credentials: joined.gatewaySecrets, KeyRunner: &joinWireGuardRunner{},
	})
	if err != nil || len(standard.Peers()) != 1 || standard.Peers()[0].Identity.OwnerID != secondID {
		t.Fatalf("one-of-many standard peers = %+v, %v", standard.Peers(), err)
	}
	restricted, err := transport.RenderGatewayRestrictedConfig(transport.GatewayRestrictedRenderRequest{
		State: state, CredentialRef: transport.GatewayRestrictedCredentialRef, Credentials: joined.gatewaySecrets,
	})
	if err != nil || len(restricted.Users()) != 1 || restricted.Users()[0].Identity.OwnerID != secondID {
		t.Fatalf("one-of-many restricted users = %+v, %v", restricted.Users(), err)
	}
	secondRefs, _ := NewNodeCredentialReferences(secondID, 1)
	for _, reference := range []model.SecretRef{secondRefs.RestrictedCredential, secondRefs.TunnelCredential} {
		value, readErr := joined.gatewaySecrets.Get(reference)
		if readErr != nil || len(value) == 0 {
			clear(value)
			t.Fatalf("other node credential %s unavailable: %v", reference, readErr)
		}
		clear(value)
	}
	local, _ := secondState.Load()
	if len(local.Nodes) != 1 || local.Nodes[0].ID != secondID || local.Nodes[0].Lifecycle != model.LifecycleActive {
		t.Fatalf("other private node changed = %+v", local.Nodes)
	}
	for _, reference := range secondRefs.Values() {
		value, readErr := secondSecrets.Get(reference)
		if readErr != nil || len(value) == 0 {
			clear(value)
			t.Fatalf("other node local credential %s unavailable: %v", reference, readErr)
		}
		clear(value)
	}
}

func TestNodeRevokeKnownStateFailureLeavesRuntimeAndCredentialsUntouched(t *testing.T) {
	fixture := newNodeLifecycleFixture(t, healthyNodeRevocationReport())
	defer fixture.destroy()
	stateStore := &failingNodeLifecycleState{base: fixture.gatewayState, commit: false}
	manager, err := NewNodeLifecycleManager(stateStore, fixture.gatewaySecrets, fixture.runtime, func() time.Time {
		return fixture.now.Add(3 * time.Minute)
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.PlanRevoke("private-node")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CommitRevoke(context.Background(), plan); !errors.Is(err, errNodeLifecycleTestSave) {
		t.Fatalf("CommitRevoke() error = %v", err)
	}
	state, _ := fixture.gatewayState.Load()
	if state.Generation != 4 || state.Nodes[0].Lifecycle != model.LifecycleActive || fixture.runtime.revokeCalls != 0 {
		t.Fatalf("known failed revoke changed state/runtime: generation=%d node=%s calls=%d",
			state.Generation, state.Nodes[0].Lifecycle, fixture.runtime.revokeCalls)
	}
	references, _ := NewNodeCredentialReferences(joinTestNodeID, 1)
	for _, reference := range []model.SecretRef{references.RestrictedCredential, references.TunnelCredential} {
		value, readErr := fixture.gatewaySecrets.Get(reference)
		if readErr != nil || len(value) == 0 {
			clear(value)
			t.Fatalf("known failed revoke removed %s: %v", reference, readErr)
		}
		clear(value)
	}
}

func TestNodeRevokeCommittedUncertainStillClosesAndCleans(t *testing.T) {
	fixture := newNodeLifecycleFixture(t, healthyNodeRevocationReport())
	defer fixture.destroy()
	stateStore := &failingNodeLifecycleState{base: fixture.gatewayState, commit: true}
	manager, err := NewNodeLifecycleManager(stateStore, fixture.gatewaySecrets, fixture.runtime, func() time.Time {
		return fixture.now.Add(3 * time.Minute)
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := manager.PlanRevoke("private-node")
	result, err := manager.CommitRevoke(context.Background(), plan)
	if !errors.Is(err, ErrNodeLifecycleUncertain) || !result.ConnectionsClosed || fixture.runtime.revokeCalls != 1 {
		t.Fatalf("CommitRevoke(committed uncertain) = %+v, %v; calls=%d", result, err, fixture.runtime.revokeCalls)
	}
	assertNodeRevokedFailClosed(t, fixture)
}

func TestNodeRevokeCredentialCleanupFailureNeverReactivatesNode(t *testing.T) {
	fixture := newNodeLifecycleFixture(t, healthyNodeRevocationReport())
	defer fixture.destroy()
	references, _ := NewNodeCredentialReferences(joinTestNodeID, 1)
	secrets := &failingNodeLifecycleSecrets{NodeCredentialSecretStore: fixture.gatewaySecrets, fail: references.TunnelCredential}
	manager, err := NewNodeLifecycleManager(fixture.gatewayState, secrets, fixture.runtime, func() time.Time {
		return fixture.now.Add(3 * time.Minute)
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := manager.PlanRevoke("private-node")
	result, err := manager.CommitRevoke(context.Background(), plan)
	if !errors.Is(err, ErrNodeCleanupPending) || !result.CredentialCleanupNeeded || result.RuntimeReconcileNeeded {
		t.Fatalf("CommitRevoke(cleanup failure) = %+v, %v", result, err)
	}
	state, _ := fixture.gatewayState.Load()
	if state.Nodes[0].Lifecycle != model.LifecycleRevoked || state.Transports[0].State != model.TransportDisabled ||
		state.Transports[1].State != model.TransportDisabled || state.Exposes[0].State != model.ExposeDisabled {
		t.Fatalf("credential cleanup failure weakened state: %+v", state)
	}
	value, readErr := fixture.gatewaySecrets.Get(references.TunnelCredential)
	if readErr != nil || len(value) == 0 {
		clear(value)
		t.Fatalf("failure fixture did not retain tunnel credential: %v", readErr)
	}
	clear(value)
}

func joinAdditionalLifecycleNode(
	t *testing.T,
	joined *joinFixture,
	name, nodeID string,
) (*inviteMemoryState, *store.SecretStore) {
	t.Helper()
	plan, err := joined.manager.PlanIssue(name)
	if err != nil {
		t.Fatal(err)
	}
	invite, err := joined.manager.CommitIssue(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	defer invite.Token.Destroy()
	gateway, _ := joined.gatewayState.Load()
	nodeStateValue := joinInitialNodeState(joined.now, gateway.Components)
	nodeStateValue.Host.ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	nodeState := newInviteMemoryState(t, nodeStateValue)
	nodeSecrets := newJoinSecretStore(t)
	runner := &joinWireGuardRunner{
		nodePrivate: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)),
		nodePublic:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)),
	}
	workflow, err := NewNodeJoinWorkflow(nodeState, nodeSecrets, joined.exchanger, NodeJoinRuntime{
		Entropy: rand.Reader, Now: func() time.Time { return joined.now.Add(2 * time.Minute) },
		NewNodeID: func() (string, error) { return nodeID, nil }, WireGuardRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.Join(context.Background(), invite.Token, model.TransportStandard, []string{}); err != nil {
		t.Fatal(err)
	}
	return nodeState, nodeSecrets
}

var errNodeLifecycleTestSave = errors.New("injected node lifecycle save failure")

type failingNodeLifecycleState struct {
	base   *inviteMemoryState
	commit bool
}

func (state *failingNodeLifecycleState) Load() (model.State, error) { return state.base.Load() }

func (state *failingNodeLifecycleState) Save(expected uint64, candidate model.State) error {
	if state.commit {
		if err := state.base.Save(expected, candidate); err != nil {
			return err
		}
	}
	return errNodeLifecycleTestSave
}

type failingNodeLifecycleSecrets struct {
	NodeCredentialSecretStore
	fail model.SecretRef
}

func (secrets *failingNodeLifecycleSecrets) Delete(reference model.SecretRef) (bool, error) {
	if reference == secrets.fail {
		return false, errors.New("injected node credential cleanup failure")
	}
	return secrets.NodeCredentialSecretStore.Delete(reference)
}

type nodeLifecycleFixture struct {
	*joinFixture
	manager *NodeLifecycleManager
	runtime *recordingNodeLifecycleRuntime
}

func newNodeLifecycleFixture(t *testing.T, report NodeRevocationReport) *nodeLifecycleFixture {
	t.Helper()
	joined := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	if _, err := joined.workflow.Join(context.Background(), joined.token, model.TransportRestricted, []string{"telegram"}); err != nil {
		joined.destroy()
		t.Fatal(err)
	}
	state, err := joined.gatewayState.Load()
	if err != nil {
		joined.destroy()
		t.Fatal(err)
	}
	exposeCreatedAt := state.Nodes[0].CreatedAt.Add(time.Minute)
	state.Generation++
	state.Exposes = append(state.Exposes, model.Expose{
		SchemaVersion: model.ResourceSchemaVersion, ID: nodeLifecycleExposeID, NodeID: joinTestNodeID,
		Name: "telegram-api", Upstream: "127.0.0.1:3000", RouteMode: model.RouteExact,
		Path: "/telegram/webhook", BodyLimitBytes: 1 << 20, UpstreamTimeoutSeconds: 15,
		ConcurrentRequests: 20, TunnelPort: 18111, State: model.ExposeReady, Generation: 1, CreatedAt: exposeCreatedAt,
	})
	if err := joined.gatewayState.Save(3, state); err != nil {
		joined.destroy()
		t.Fatal(err)
	}
	runtime := &recordingNodeLifecycleRuntime{state: joined.gatewayState, report: report}
	manager, err := NewNodeLifecycleManager(
		joined.gatewayState, joined.gatewaySecrets, runtime,
		func() time.Time { return joined.now.Add(3 * time.Minute) },
	)
	if err != nil {
		joined.destroy()
		t.Fatal(err)
	}
	return &nodeLifecycleFixture{joinFixture: joined, manager: manager, runtime: runtime}
}

type recordingNodeLifecycleRuntime struct {
	state       *inviteMemoryState
	report      NodeRevocationReport
	revokeCalls int
	deleteCalls int
}

func (runtime *recordingNodeLifecycleRuntime) Revoke(_ context.Context, candidate model.State, nodeID string) (NodeRevocationReport, error) {
	runtime.revokeCalls++
	authoritative, err := runtime.state.Load()
	if err != nil {
		return NodeRevocationReport{}, err
	}
	if !reflect.DeepEqual(authoritative, candidate) {
		return NodeRevocationReport{}, errors.New("runtime called before authoritative revocation")
	}
	for _, node := range candidate.Nodes {
		if node.ID == nodeID && node.Lifecycle != model.LifecycleRevoked {
			return NodeRevocationReport{}, errors.New("runtime received active node")
		}
	}
	return runtime.report, nil
}

func (runtime *recordingNodeLifecycleRuntime) Delete(_ context.Context, candidate model.State, nodeID string) error {
	runtime.deleteCalls++
	authoritative, err := runtime.state.Load()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(authoritative, candidate) {
		return errors.New("runtime called before authoritative deletion")
	}
	for _, node := range candidate.Nodes {
		if node.ID == nodeID && node.Lifecycle != model.LifecycleDeleted {
			return errors.New("runtime received non-deleted node")
		}
	}
	return nil
}

func healthyNodeRevocationReport() NodeRevocationReport {
	return NodeRevocationReport{
		ControlClosed: true, StandardClosed: true, RestrictedClosed: true, TunnelClosed: true, ExposesDisabled: true,
	}
}

func assertNodeRevokedFailClosed(t *testing.T, fixture *nodeLifecycleFixture) {
	t.Helper()
	state, err := fixture.gatewayState.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != 5 || len(state.Nodes) != 1 || state.Nodes[0].Lifecycle != model.LifecycleRevoked ||
		state.Nodes[0].RevokedAt == nil || len(state.Transports) != 2 || len(state.Exposes) != 1 ||
		state.Exposes[0].State != model.ExposeDisabled || state.Exposes[0].Generation != 2 || len(state.Policies) != 1 || len(state.Certificates) != 2 {
		t.Fatalf("revoked state = %+v", state)
	}
	for _, record := range state.Transports {
		if record.OwnerID == joinTestNodeID && record.State != model.TransportDisabled {
			t.Fatalf("revoked transport remained %s", record.State)
		}
	}
	catalog, err := NewNodeCatalog(fixture.gatewayState)
	if err != nil {
		t.Fatal(err)
	}
	shown, err := catalog.Show("PRIVATE-NODE")
	if err != nil || shown.Resource.Lifecycle != model.LifecycleRevoked || shown.Resource.RevokedAt == nil ||
		shown.Resource.ControlCertificate.Fingerprint == "" || len(shown.Resource.Transports) != 2 {
		t.Fatalf("revoked diagnostic view = %+v, %v", shown, err)
	}

	standard, err := transport.RenderGatewayStandardConfig(context.Background(), transport.GatewayStandardRenderRequest{
		State: state, CredentialRef: transport.GatewayStandardCredentialRef,
		Credentials: fixture.gatewaySecrets, KeyRunner: &joinWireGuardRunner{},
	})
	if err != nil || len(standard.Peers()) != 0 {
		t.Fatalf("revoked standard render peers=%+v error=%v", standard.Peers(), err)
	}
	restricted, err := transport.RenderGatewayRestrictedConfig(transport.GatewayRestrictedRenderRequest{
		State: state, CredentialRef: transport.GatewayRestrictedCredentialRef, Credentials: fixture.gatewaySecrets,
	})
	if err != nil || len(restricted.Users()) != 0 {
		t.Fatalf("revoked restricted render users=%+v error=%v", restricted.Users(), err)
	}
	var certificate model.Certificate
	for _, current := range state.Certificates {
		if current.Kind == model.CertificateControlNode {
			certificate = current
		}
	}
	authorizer, err := controller.NewRPCNodeAuthorizer(fixture.gatewayState)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := authorizer.AuthorizeRPC(context.Background(), control.RPCPeer{
		NodeID: joinTestNodeID, CertificateFingerprint: certificate.Fingerprint,
	}, control.RPCRequest{NodeID: joinTestNodeID, CredentialGeneration: 1})
	if err != nil || authorization.Authorized || authorization.Denial.Response.ErrorCode != "node_inactive" {
		t.Fatalf("revoked control authorization = %+v, %v", authorization, err)
	}
	references, _ := NewNodeCredentialReferences(joinTestNodeID, 1)
	for _, reference := range []model.SecretRef{
		model.SecretRef(certificate.CertificateRef), references.RestrictedCredential, references.TunnelCredential,
	} {
		if _, readErr := fixture.gatewaySecrets.Get(reference); !errors.Is(readErr, store.ErrSecretNotFound) {
			t.Fatalf("revoked gateway credential %s remains: %v", reference, readErr)
		}
	}
}
