package enrollment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

const (
	rotationOperationID   = "50000000-0000-4000-8000-000000000005"
	rotationRequestID     = "60000000-0000-4000-8000-000000000006"
	rotationCertificateID = "70000000-0000-4000-8000-000000000007"
	rotationExposeID      = "80000000-0000-4000-8000-000000000008"
)

func TestNodeRotationAtomicallyActivatesFullNewGenerationAndDrainsOld(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", false)
	defer fixture.destroy()
	beforeGateway, _ := fixture.gatewayState.Load()
	beforeNode, _ := fixture.nodeState.Load()
	plan, err := fixture.rotation.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if plan.NodeID != joinTestNodeID || plan.CurrentCredentialGeneration != 1 || plan.RequestedCredentialGeneration != 2 ||
		plan.ExpectedGatewayStateGeneration != 4 || plan.ExpectedLocalStateGeneration != 3 || plan.NextLocalStateGeneration != 5 {
		t.Fatalf("Plan() = %s", plan.String())
	}
	if _, err := plan.MarshalJSON(); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("plan MarshalJSON() error = %v", err)
	}
	result, err := fixture.rotation.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.CredentialGeneration != 2 || result.PreviousCredentialGeneration != 1 ||
		result.GatewayStateGeneration != 5 || result.LocalStateGeneration != 5 ||
		result.NodeRuntimeCleanupNeeded || result.GatewayCleanupNeeded || result.CredentialCleanupNeeded {
		t.Fatalf("Apply() = %+v", result)
	}
	assertSuccessfulNodeRotation(t, fixture, beforeGateway, beforeNode)
}

func TestNodeRotationFailureBeforeGatewayCommitRestoresCompleteOldGeneration(t *testing.T) {
	for _, phase := range []string{
		"gateway_stage", "gateway_check", "node_stage", "node_check",
		"gateway_activate", "node_activate", "post_check", "gateway_commit",
	} {
		t.Run(phase, func(t *testing.T) {
			fixture := newNodeRotationFixture(t, phase, false)
			defer fixture.destroy()
			plan, err := fixture.rotation.Plan()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.rotation.Apply(context.Background(), plan); err == nil {
				t.Fatalf("Apply() succeeded at injected phase %s", phase)
			}
			assertOldNodeRotationGeneration(t, fixture)
		})
	}
}

func TestNodeRotationOperationStartFailureLeavesExactOldState(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", false)
	defer fixture.destroy()
	stateStore := &numberedNodeRotationState{base: fixture.nodeState, failAt: 1}
	fixture.rotation.state = stateStore
	plan, err := fixture.rotation.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.rotation.Apply(context.Background(), plan); !errors.Is(err, errNodeLifecycleTestSave) {
		t.Fatalf("Apply(operation save failure) error = %v", err)
	}
	state, _ := fixture.nodeState.Load()
	if state.Generation != 3 || state.Nodes[0].CredentialGeneration != 1 || len(state.Operations) != 0 ||
		fixture.gatewayRuntime.stageCalls != 0 {
		t.Fatalf("operation save failure mutated state/runtime: generation=%d credential=%d operations=%d stage=%d",
			state.Generation, state.Nodes[0].CredentialGeneration, len(state.Operations), fixture.gatewayRuntime.stageCalls)
	}
}

func TestNodeRotationCredentialGenerationFailureRetainsCompleteOldSet(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", false)
	defer fixture.destroy()
	provisioner, err := NewNodeCredentialProvisioner(fixture.nodeSecrets, NodeCredentialRuntime{
		Entropy: randReaderForRotation(), WireGuardRunner: errorNodeRotationWireGuardRunner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.rotation.credentials = provisioner
	plan, _ := fixture.rotation.Plan()
	if _, err := fixture.rotation.Apply(context.Background(), plan); err == nil {
		t.Fatal("Apply() accepted credential generation failure")
	}
	assertOldNodeRotationGeneration(t, fixture)
}

func TestNodeRotationRetriesOneKnownLocalCommitFailure(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", false)
	defer fixture.destroy()
	stateStore := &numberedNodeRotationState{base: fixture.nodeState, failAt: 2}
	fixture.rotation.state = stateStore
	plan, _ := fixture.rotation.Plan()
	result, err := fixture.rotation.Apply(context.Background(), plan)
	if err != nil || result.CredentialGeneration != 2 || stateStore.saves != 3 {
		t.Fatalf("Apply(transient local commit failure) = %+v, %v; saves=%d", result, err, stateStore.saves)
	}
	state, _ := fixture.nodeState.Load()
	if state.Nodes[0].CredentialGeneration != 2 || state.Operations[0].State != model.OperationCompleted {
		t.Fatalf("transient local commit failure did not converge: %+v", state)
	}
}

func TestNodeRotationCommittedSaveErrorFinishesCompleteNewGeneration(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", true)
	defer fixture.destroy()
	plan, _ := fixture.rotation.Plan()
	result, err := fixture.rotation.Apply(context.Background(), plan)
	if !errors.Is(err, ErrNodeRotationCommitUncertain) || result.CredentialGeneration != 2 {
		t.Fatalf("Apply(committed save error) = %+v, %v", result, err)
	}
	gateway, _ := fixture.gatewayState.Load()
	nodeState, _ := fixture.nodeState.Load()
	if gateway.Nodes[0].CredentialGeneration != 2 || nodeState.Nodes[0].CredentialGeneration != 2 ||
		fixture.gatewayRuntime.activeGeneration != 2 || fixture.nodeRuntime.activeGeneration != 2 {
		t.Fatalf("committed save error left mixed generations: gateway=%d node=%d runtimes=%d/%d",
			gateway.Nodes[0].CredentialGeneration, nodeState.Nodes[0].CredentialGeneration,
			fixture.gatewayRuntime.activeGeneration, fixture.nodeRuntime.activeGeneration)
	}
}

func TestNodeRotationCleanupFailureKeepsNewGenerationActiveAndReturnsRepair(t *testing.T) {
	fixture := newNodeRotationFixture(t, "node_drain", false)
	defer fixture.destroy()
	plan, _ := fixture.rotation.Plan()
	result, err := fixture.rotation.Apply(context.Background(), plan)
	if !errors.Is(err, ErrNodeRotationCleanupPending) || !result.NodeRuntimeCleanupNeeded ||
		result.GatewayCleanupNeeded || result.CredentialCleanupNeeded {
		t.Fatalf("Apply(cleanup failure) = %+v, %v", result, err)
	}
	public := result.OutputResult()
	if public.Status != output.StatusPending || len(public.RequiresAction) != 1 ||
		public.RequiresAction[0].Code != "repair_node_rotation_runtime" {
		t.Fatalf("pending output = %+v", public)
	}
	gateway, _ := fixture.gatewayState.Load()
	nodeState, _ := fixture.nodeState.Load()
	if gateway.Nodes[0].CredentialGeneration != 2 || nodeState.Nodes[0].CredentialGeneration != 2 {
		t.Fatalf("cleanup failure rolled back committed generation")
	}
}

func TestNodeRotationRejectsTamperedPlanWithoutOperationOrCredentials(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", false)
	defer fixture.destroy()
	plan, _ := fixture.rotation.Plan()
	plan.RequestedCredentialGeneration++
	if _, err := fixture.rotation.Apply(context.Background(), plan); !errors.Is(err, ErrNodeRotationStale) {
		t.Fatalf("Apply(tampered plan) error = %v", err)
	}
	nodeState, _ := fixture.nodeState.Load()
	if nodeState.Generation != 3 || len(nodeState.Operations) != 0 || fixture.gatewayRuntime.stageCalls != 0 {
		t.Fatalf("tampered plan mutated state/runtime: generation=%d operations=%d stage=%d",
			nodeState.Generation, len(nodeState.Operations), fixture.gatewayRuntime.stageCalls)
	}
}

func TestNodeRotationTimeTravelRefusesExpiryBeforeAnyApplyEffectAndDirectsRecovery(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", false)
	defer fixture.destroy()
	before, err := fixture.nodeState.Load()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := currentNodeControlCertificate(before, before.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	now := certificate.NotAfter.Add(-time.Second)
	fixture.rotation.options.Now = func() time.Time { return now }
	plan, err := fixture.rotation.Plan()
	if err != nil {
		t.Fatalf("Plan(before expiry) error = %v", err)
	}

	now = certificate.NotAfter
	if _, err := fixture.rotation.Apply(context.Background(), plan); !errors.Is(err, ErrNodeCertificateExpired) {
		t.Fatalf("Apply(at expiry) error = %v", err)
	} else {
		var expiry *NodeCertificateExpiredError
		if !errors.As(err, &expiry) || expiry.NodeID != joinTestNodeID || !expiry.NotAfter.Equal(certificate.NotAfter) ||
			!strings.Contains(err.Error(), "sudo vpnctl node recover "+joinTestNodeID) ||
			!strings.Contains(err.Error(), "sudo vpnctl node recover\"") {
			t.Fatalf("expiry recovery direction = %T %v", err, err)
		}
	}
	after, _ := fixture.nodeState.Load()
	if !reflect.DeepEqual(before, after) || fixture.gatewayRuntime.stageCalls != 0 || fixture.nodeRuntime.checkCalls != 0 {
		t.Fatalf("expired Apply changed state/runtime: before=%d after=%d gateway_stage=%d node_checks=%d",
			before.Generation, after.Generation, fixture.gatewayRuntime.stageCalls, fixture.nodeRuntime.checkCalls)
	}
	assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 2, false)

	if _, err := fixture.rotation.Plan(); !errors.Is(err, ErrNodeCertificateExpired) {
		t.Fatalf("Plan(at expiry) error = %v", err)
	}
}

func TestGatewayRefusesRotationIfCertificateExpiresBeforeRequestPreparation(t *testing.T) {
	fixture := newNodeRotationFixture(t, "", false)
	defer fixture.destroy()
	nodeState, _ := fixture.nodeState.Load()
	certificate, err := currentNodeControlCertificate(nodeState, nodeState.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	fixture.rotation.options.Now = func() time.Time { return certificate.NotAfter.Add(-time.Second) }
	gateway, ok := fixture.rotation.gateway.(*GatewayNodeRotationManager)
	if !ok {
		t.Fatalf("gateway rotation service = %T", fixture.rotation.gateway)
	}
	gateway.options.Now = func() time.Time { return certificate.NotAfter }
	plan, err := fixture.rotation.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.rotation.Apply(context.Background(), plan); !errors.Is(err, ErrNodeCertificateExpired) {
		t.Fatalf("Apply(gateway at expiry) error = %v", err)
	}
	if fixture.gatewayRuntime.stageCalls != 0 {
		t.Fatalf("expired gateway staged runtime %d times", fixture.gatewayRuntime.stageCalls)
	}
	assertOldNodeRotationGeneration(t, fixture)
}

func TestNodeRotationReadinessRequiresEveryCredentialMember(t *testing.T) {
	for _, mutate := range []func(*NodeRotationReadinessReport){
		func(report *NodeRotationReadinessReport) { report.Control = false },
		func(report *NodeRotationReadinessReport) { report.Standard = false },
		func(report *NodeRotationReadinessReport) { report.Restricted = false },
		func(report *NodeRotationReadinessReport) { report.Tunnel = false },
	} {
		report := healthyNodeRotationReadiness()
		mutate(&report)
		if !errors.Is(report.Validate(), ErrNodeRotationNotReady) {
			t.Fatalf("Validate() accepted %+v", report)
		}
	}
}

func TestNodeRotationSensitiveAggregatesRejectOrdinarySerialization(t *testing.T) {
	for name, value := range map[string]any{
		"request":           NodeRotationRequest{},
		"gateway candidate": GatewayNodeRotationCandidate{},
		"gateway material":  GatewayNodeRotationMaterial{},
		"node candidate":    NodeRotationNodeCandidate{},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := json.Marshal(value); !errors.Is(err, output.ErrSensitiveSerialization) {
				t.Fatalf("json.Marshal(%s) error = %v", name, err)
			}
		})
	}
}

type nodeRotationFixture struct {
	*joinFixture
	rotation       *NodeRotationWorkflow
	gatewayRuntime *recordingGatewayNodeRotationRuntime
	nodeRuntime    *recordingNodeRotationRuntime
	oldGateway     model.State
	oldNode        model.State
}

type numberedNodeRotationState struct {
	base   *inviteMemoryState
	failAt int
	saves  int
}

func (state *numberedNodeRotationState) Load() (model.State, error) { return state.base.Load() }

func (state *numberedNodeRotationState) Save(expected uint64, candidate model.State) error {
	state.saves++
	if state.saves == state.failAt {
		return errNodeLifecycleTestSave
	}
	return state.base.Save(expected, candidate)
}

type errorNodeRotationWireGuardRunner struct{}

func (errorNodeRotationWireGuardRunner) Run(context.Context, string, []string, string) (string, error) {
	return "", errors.New("injected rotation key generation failure")
}

func newNodeRotationFixture(t *testing.T, failure string, commitAfterWrite bool) *nodeRotationFixture {
	t.Helper()
	joined := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	if _, err := joined.workflow.Join(context.Background(), joined.token, model.TransportRestricted, []string{"telegram"}); err != nil {
		joined.destroy()
		t.Fatal(err)
	}
	gateway, err := joined.gatewayState.Load()
	if err != nil {
		joined.destroy()
		t.Fatal(err)
	}
	gateway.Generation = 4
	gateway.Exposes = append(gateway.Exposes, model.Expose{
		SchemaVersion: model.ResourceSchemaVersion, ID: rotationExposeID, NodeID: joinTestNodeID,
		Name: "telegram-api", Upstream: "127.0.0.1:3000", RouteMode: model.RouteExact,
		Path: "/telegram/webhook", BodyLimitBytes: 1 << 20, UpstreamTimeoutSeconds: 15,
		ConcurrentRequests: 20, TunnelPort: 18112, State: model.ExposeReady, Generation: 1,
		CreatedAt: joined.now.Add(2 * time.Minute),
	})
	if err := joined.gatewayState.Save(3, gateway); err != nil {
		joined.destroy()
		t.Fatal(err)
	}
	nodeState, err := joined.nodeState.Load()
	if err != nil {
		joined.destroy()
		t.Fatal(err)
	}
	nodeCandidate := nodeState
	nodeCandidate.Generation = 3
	nodeCandidate.Nodes = append([]model.Node(nil), nodeState.Nodes...)
	trust := *nodeCandidate.Nodes[0].Gateway
	trust.LastKnownGatewayGeneration = 4
	nodeCandidate.Nodes[0].Gateway = &trust
	if err := model.ValidateTransition(nodeState, nodeCandidate); err != nil {
		joined.destroy()
		t.Fatal(err)
	}
	if err := joined.nodeState.Save(2, nodeCandidate); err != nil {
		joined.destroy()
		t.Fatal(err)
	}
	gatewayRuntime := &recordingGatewayNodeRotationRuntime{
		state: joined.gatewayState, failure: failure, activeGeneration: 1,
	}
	nodeRuntime := &recordingNodeRotationRuntime{
		state: joined.nodeState, failure: failure, activeGeneration: 1,
	}
	var gatewayStore NodeLifecycleStateStore = joined.gatewayState
	if failure == "gateway_commit" {
		gatewayStore = &failingNodeLifecycleState{base: joined.gatewayState, commit: false}
	} else if commitAfterWrite {
		gatewayStore = &failingNodeLifecycleState{base: joined.gatewayState, commit: true}
	}
	gatewayManager, err := NewGatewayNodeRotationManager(
		gatewayStore, joined.gatewaySecrets, gatewayRuntime, GatewayNodeRotationOptions{
			Entropy: randReaderForRotation(), Now: func() time.Time { return joined.now.Add(4 * time.Minute) },
			NewCertificateID: func() (string, error) { return rotationCertificateID, nil },
		},
	)
	if err != nil {
		joined.destroy()
		t.Fatal(err)
	}
	ids := []string{rotationOperationID, rotationRequestID}
	rotation, err := NewNodeRotationWorkflow(
		joined.nodeState, joined.nodeSecrets, gatewayManager, nodeRuntime, NodeRotationOptions{
			Entropy: randReaderForRotation(), Now: func() time.Time { return joined.now.Add(4 * time.Minute) },
			NewUUID: func() (string, error) {
				if len(ids) == 0 {
					return "", errors.New("rotation UUID sequence exhausted")
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
		joined.destroy()
		t.Fatal(err)
	}
	oldGateway, _ := joined.gatewayState.Load()
	oldNode, _ := joined.nodeState.Load()
	return &nodeRotationFixture{
		joinFixture: joined, rotation: rotation, gatewayRuntime: gatewayRuntime, nodeRuntime: nodeRuntime,
		oldGateway: oldGateway, oldNode: oldNode,
	}
}

func healthyNodeRotationReadiness() NodeRotationReadinessReport {
	return NodeRotationReadinessReport{Control: true, Standard: true, Restricted: true, Tunnel: true}
}

type recordingGatewayNodeRotationRuntime struct {
	state            *inviteMemoryState
	failure          string
	activeGeneration uint64
	stageCalls       int
	checkCalls       int
}

func (runtime *recordingGatewayNodeRotationRuntime) Stage(_ context.Context, candidate GatewayNodeRotationCandidate) error {
	runtime.stageCalls++
	state, _ := runtime.state.Load()
	if !reflect.DeepEqual(state, candidate.Before) || state.Nodes[0].CredentialGeneration != 1 {
		return errors.New("gateway staged after authoritative generation changed")
	}
	if runtime.failure == "gateway_stage" {
		return errors.New("injected gateway stage failure")
	}
	return nil
}

func (runtime *recordingGatewayNodeRotationRuntime) Check(_ context.Context, candidate GatewayNodeRotationCandidate) (NodeRotationReadinessReport, error) {
	runtime.checkCalls++
	if runtime.failure == "gateway_check" {
		return NodeRotationReadinessReport{}, errors.New("injected gateway readiness failure")
	}
	if candidate.Candidate.Nodes[0].CredentialGeneration != 2 || candidate.CurrentGeneration != 1 {
		return NodeRotationReadinessReport{}, errors.New("gateway candidate generation mismatch")
	}
	return healthyNodeRotationReadiness(), nil
}

func (runtime *recordingGatewayNodeRotationRuntime) ActivateParallel(_ context.Context, _ GatewayNodeRotationCandidate) error {
	if runtime.failure == "gateway_activate" {
		return errors.New("injected gateway activation failure")
	}
	runtime.activeGeneration = 2
	return nil
}

func (runtime *recordingGatewayNodeRotationRuntime) Rollback(_ context.Context, _ GatewayNodeRotationCandidate) error {
	runtime.activeGeneration = 1
	return nil
}

func (runtime *recordingGatewayNodeRotationRuntime) Drain(_ context.Context, request NodeRotationDrainRequest) error {
	if err := request.Validate(time.Now()); err != nil {
		return err
	}
	if runtime.failure == "gateway_drain" {
		return errors.New("injected gateway drain failure")
	}
	runtime.activeGeneration = request.ActiveGeneration
	return nil
}

type recordingNodeRotationRuntime struct {
	state            *inviteMemoryState
	failure          string
	activeGeneration uint64
	checkCalls       int
}

func (runtime *recordingNodeRotationRuntime) Stage(_ context.Context, candidate NodeRotationNodeCandidate) error {
	state, _ := runtime.state.Load()
	if !reflect.DeepEqual(state, candidate.Before) || state.Nodes[0].CredentialGeneration != 1 {
		return errors.New("node staged after local generation changed")
	}
	if runtime.failure == "node_stage" {
		return errors.New("injected node stage failure")
	}
	return nil
}

func (runtime *recordingNodeRotationRuntime) Check(_ context.Context, candidate NodeRotationNodeCandidate) (NodeRotationReadinessReport, error) {
	runtime.checkCalls++
	if (runtime.failure == "node_check" && runtime.checkCalls == 1) ||
		(runtime.failure == "post_check" && runtime.checkCalls == 2) {
		return NodeRotationReadinessReport{}, errors.New("injected node readiness failure")
	}
	if candidate.Candidate.Nodes[0].CredentialGeneration != 2 || candidate.CurrentGeneration != 1 {
		return NodeRotationReadinessReport{}, errors.New("node candidate generation mismatch")
	}
	return healthyNodeRotationReadiness(), nil
}

func (runtime *recordingNodeRotationRuntime) ActivateParallel(_ context.Context, _ NodeRotationNodeCandidate) error {
	if runtime.failure == "node_activate" {
		return errors.New("injected node activation failure")
	}
	runtime.activeGeneration = 2
	return nil
}

func (runtime *recordingNodeRotationRuntime) Rollback(_ context.Context, _ NodeRotationNodeCandidate) error {
	runtime.activeGeneration = 1
	return nil
}

func (runtime *recordingNodeRotationRuntime) Drain(_ context.Context, request NodeRotationDrainRequest) error {
	if err := request.Validate(time.Now()); err != nil {
		return err
	}
	if runtime.failure == "node_drain" {
		return errors.New("injected node drain failure")
	}
	runtime.activeGeneration = request.ActiveGeneration
	return nil
}

func assertOldNodeRotationGeneration(t *testing.T, fixture *nodeRotationFixture) {
	t.Helper()
	gateway, _ := fixture.gatewayState.Load()
	nodeState, _ := fixture.nodeState.Load()
	if gateway.Nodes[0].CredentialGeneration != 1 || nodeState.Nodes[0].CredentialGeneration != 1 ||
		fixture.gatewayRuntime.activeGeneration != 1 || fixture.nodeRuntime.activeGeneration != 1 ||
		nodeState.Nodes[0].Gateway.PendingRequestID != "" || len(nodeState.Operations) != 1 ||
		nodeState.Operations[0].State != model.OperationFailed {
		t.Fatalf("failure left mixed state: gateway=%d node=%d runtime=%d/%d pending=%q operations=%+v",
			gateway.Nodes[0].CredentialGeneration, nodeState.Nodes[0].CredentialGeneration,
			fixture.gatewayRuntime.activeGeneration, fixture.nodeRuntime.activeGeneration,
			nodeState.Nodes[0].Gateway.PendingRequestID, nodeState.Operations)
	}
	assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 1, true)
	assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 2, false)
	assertRotationGatewaySecrets(t, fixture.gatewaySecrets, gateway, 1, true)
	assertRotationGatewaySecrets(t, fixture.gatewaySecrets, gateway, 2, false)
}

func assertSuccessfulNodeRotation(t *testing.T, fixture *nodeRotationFixture, beforeGateway, beforeNode model.State) {
	t.Helper()
	gateway, _ := fixture.gatewayState.Load()
	nodeState, _ := fixture.nodeState.Load()
	if gateway.Generation != 5 || nodeState.Generation != 5 || gateway.Nodes[0].CredentialGeneration != 2 ||
		nodeState.Nodes[0].CredentialGeneration != 2 || nodeState.Nodes[0].Gateway.PendingRequestID != "" ||
		len(gateway.Nodes[0].IdempotencyRecords) != 1 || gateway.Nodes[0].IdempotencyRecords[0].RequestID != rotationRequestID ||
		len(nodeState.Operations) != 1 || nodeState.Operations[0].State != model.OperationCompleted {
		t.Fatalf("rotated state mismatch: gateway=%+v node=%+v", gateway.Nodes[0], nodeState.Nodes[0])
	}
	if gateway.Nodes[0].ID != beforeGateway.Nodes[0].ID || gateway.Nodes[0].Name != beforeGateway.Nodes[0].Name ||
		gateway.Nodes[0].OverlayIPv4 != beforeGateway.Nodes[0].OverlayIPv4 ||
		gateway.Nodes[0].ActiveTransport != beforeGateway.Nodes[0].ActiveTransport ||
		!reflect.DeepEqual(gateway.Nodes[0].AssignedPresets, beforeGateway.Nodes[0].AssignedPresets) ||
		!reflect.DeepEqual(gateway.Policies, beforeGateway.Policies) || !reflect.DeepEqual(gateway.Exposes, beforeGateway.Exposes) ||
		nodeState.Nodes[0].ID != beforeNode.Nodes[0].ID || nodeState.Nodes[0].OverlayIPv4 != beforeNode.Nodes[0].OverlayIPv4 ||
		!reflect.DeepEqual(nodeState.Policies, beforeNode.Policies) {
		t.Fatalf("rotation changed stable identity/policy/exposes")
	}
	for _, record := range append(append([]model.Transport{}, gateway.Transports...), nodeState.Transports...) {
		if record.CredentialGeneration != 2 {
			t.Fatalf("transport retained mixed generation: %+v", record)
		}
	}
	assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 1, false)
	assertRotationGenerationSecrets(t, fixture.nodeSecrets, joinTestNodeID, 2, true)
	assertRotationGatewaySecrets(t, fixture.gatewaySecrets, gateway, 1, false)
	assertRotationGatewaySecrets(t, fixture.gatewaySecrets, gateway, 2, true)
	encodedGateway, err := model.EncodeState(gateway)
	if err != nil {
		t.Fatal(err)
	}
	newLocalReferences, _ := NewNodeCredentialReferences(joinTestNodeID, 2)
	for _, reference := range newLocalReferences.Values() {
		value, readErr := fixture.nodeSecrets.Get(reference)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(value) != 0 && bytes.Contains(encodedGateway, value) {
			clear(value)
			t.Fatalf("gateway state contains rotated node private/shared material from %s", reference)
		}
		clear(value)
	}
	standard, err := transport.RenderGatewayStandardConfig(context.Background(), transport.GatewayStandardRenderRequest{
		State: gateway, CredentialRef: transport.GatewayStandardCredentialRef,
		Credentials: fixture.gatewaySecrets, KeyRunner: &joinWireGuardRunner{},
	})
	if err != nil || len(standard.Peers()) != 1 || standard.Peers()[0].Identity.CredentialGeneration != 2 ||
		standard.Peers()[0].PublicKey != rotationWireGuardPublic() {
		t.Fatalf("rotated standard render = %+v, %v", standard.Peers(), err)
	}
	restrictedConfig, err := transport.RenderGatewayRestrictedConfig(transport.GatewayRestrictedRenderRequest{
		State: gateway, CredentialRef: transport.GatewayRestrictedCredentialRef, Credentials: fixture.gatewaySecrets,
	})
	if err != nil || len(restrictedConfig.Users()) != 1 || restrictedConfig.Users()[0].Identity.CredentialGeneration != 2 {
		t.Fatalf("rotated restricted render = %+v, %v", restrictedConfig.Users(), err)
	}
	var certificate model.Certificate
	for _, current := range gateway.Certificates {
		if current.Kind == model.CertificateControlNode {
			certificate = current
		}
	}
	authorizer, _ := controller.NewRPCNodeAuthorizer(fixture.gatewayState)
	authorization, err := authorizer.AuthorizeRPC(context.Background(), control.RPCPeer{
		NodeID: joinTestNodeID, CertificateFingerprint: beforeGateway.Certificates[len(beforeGateway.Certificates)-1].Fingerprint,
	}, control.RPCRequest{NodeID: joinTestNodeID, CredentialGeneration: 1})
	if err != nil || authorization.Authorized || authorization.Denial.Response.ErrorCode != "credential_generation_mismatch" {
		t.Fatalf("old control generation authorization = %+v, %v", authorization, err)
	}
	newAuthorization, err := authorizer.AuthorizeRPC(context.Background(), control.RPCPeer{
		NodeID: joinTestNodeID, CertificateFingerprint: certificate.Fingerprint,
	}, control.RPCRequest{NodeID: joinTestNodeID, CredentialGeneration: 2})
	if err != nil || !newAuthorization.Authorized {
		t.Fatalf("new control generation authorization = %+v, %v", newAuthorization, err)
	}
}

func assertRotationGenerationSecrets(t *testing.T, secrets *store.SecretStore, nodeID string, generation uint64, present bool) {
	t.Helper()
	references, _ := NewNodeCredentialReferences(nodeID, generation)
	certificateReference, _ := model.NewSecretRef("control-cert", fmt.Sprintf("%s-g%d", nodeID, generation))
	for _, reference := range append(references.Values(), certificateReference) {
		value, err := secrets.Get(reference)
		if present && (err != nil || len(value) == 0) {
			clear(value)
			t.Fatalf("expected node credential %s: %v", reference, err)
		}
		if !present && !errors.Is(err, store.ErrSecretNotFound) {
			clear(value)
			t.Fatalf("unexpected node credential %s: %v", reference, err)
		}
		clear(value)
	}
}

func assertRotationGatewaySecrets(t *testing.T, secrets *store.SecretStore, state model.State, generation uint64, present bool) {
	t.Helper()
	references, _ := NewNodeCredentialReferences(joinTestNodeID, generation)
	certificateReference, _ := model.NewSecretRef("control-cert", fmt.Sprintf("%s-g%d", joinTestNodeID, generation))
	for _, reference := range []model.SecretRef{references.RestrictedCredential, references.TunnelCredential, certificateReference} {
		value, err := secrets.Get(reference)
		if present && (err != nil || len(value) == 0) {
			clear(value)
			t.Fatalf("expected gateway credential %s: %v", reference, err)
		}
		if !present && !errors.Is(err, store.ErrSecretNotFound) {
			clear(value)
			t.Fatalf("unexpected gateway credential %s: %v", reference, err)
		}
		clear(value)
	}
}

func rotationWireGuardPrivate() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
}

func rotationWireGuardPublic() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
}

func randReaderForRotation() *bytes.Reader {
	// Ed25519 key generation and serial issuance need independent deterministic
	// bytes in tests; repeated non-zero material is sufficient for fixtures.
	return bytes.NewReader(bytes.Repeat([]byte{0x5a}, 4096))
}
