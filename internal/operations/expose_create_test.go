package operations

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

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const (
	exposeSagaGatewayID     = "62000000-0000-4000-8000-000000000001"
	exposeSagaNodeID        = "62000000-0000-4000-8000-000000000002"
	exposeSagaNodeHostID    = "62000000-0000-4000-8000-000000000003"
	exposeSagaExposeID      = "62000000-0000-4000-8000-000000000004"
	exposeSagaCertificateID = "62000000-0000-4000-8000-000000000005"
	exposeSagaOperationID   = "62000000-0000-4000-8000-000000000006"
	exposeSagaPathCanary    = "/telegram/webhook-path-canary-9X2Q"
)

func TestExposeCreateSagaPublishesReadyTunnelBeforeIngressAndRendersSensitiveURLOnlyForHuman(t *testing.T) {
	t.Parallel()

	saga, state, gateway, tunnelRuntime, trace := newExposeSagaFixture(t, tunnel.TunnelProbePassed)
	plan, err := saga.Plan(context.Background(), ingress.ExposeCreateRequest{
		Upstream: "3000", Name: "telegram", Path: exposeSagaPathCanary,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Expose.TunnelPort != tunnel.DefaultLoopbackPortFirst || plan.Expose.State != model.ExposePending {
		t.Fatalf("planned expose = %+v", plan.Expose)
	}
	if _, err := json.Marshal(plan); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("plan serialization error = %v", err)
	}

	created, err := saga.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if created.State != model.ExposeReady || created.GatewayStateGeneration != 13 || created.LocalStateGeneration != 9 {
		t.Fatalf("creation result = %+v", created)
	}
	if gateway.publishedState != model.ExposeReady || gateway.abortCalls != 0 || tunnelRuntime.rollbackCalls != 0 {
		t.Fatalf("gateway/tunnel result = state:%s abort:%d rollback:%d", gateway.publishedState, gateway.abortCalls, tunnelRuntime.rollbackCalls)
	}
	if got := state.state.Exposes; len(got) != 1 || got[0].State != model.ExposeReady || got[0].Path != exposeSagaPathCanary {
		t.Fatalf("final local exposes = %+v", got)
	}
	wantOrder := []string{
		"gateway_reserve", "tunnel_activate", "node_save_8", "tunnel_observe", "gateway_publish_ready", "node_save_9",
	}
	assertTraceSubsequence(t, *trace, wantOrder)

	result, err := created.Output()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{exposeSagaPathCanary, "webhook-path-canary", "public_url", "https://203.0.113.10/telegram"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("JSON output leaked %q: %s", forbidden, encoded)
		}
	}
	if strings.Contains(fmt.Sprintf("%#v", result), exposeSagaPathCanary) {
		t.Fatal("ordinary result formatting leaked the sensitive path")
	}
	var human bytes.Buffer
	if err := output.RenderHuman(&human, result); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"public url: https://203.0.113.10" + exposeSagaPathCanary,
		"output path: /var/lib/vpnctl/exports/gateway.crt",
		"scp root@203.0.113.10:/var/lib/vpnctl/exports/gateway.crt ./gateway.crt",
	} {
		if !strings.Contains(human.String(), expected) {
			t.Fatalf("human output lacks %q:\n%s", expected, human.String())
		}
	}
}

func TestExposeCreateSagaKeepsStoppedApplicationAsPublishedDegradedExpose(t *testing.T) {
	t.Parallel()

	saga, state, gateway, tunnelRuntime, trace := newExposeSagaFixture(t, tunnel.TunnelProbeFailed)
	plan, err := saga.Plan(context.Background(), ingress.ExposeCreateRequest{Upstream: "3000", Path: exposeSagaPathCanary})
	if err != nil {
		t.Fatal(err)
	}
	created, err := saga.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if created.State != model.ExposeDegraded || gateway.publishedState != model.ExposeDegraded ||
		len(state.state.Exposes) != 1 || state.state.Exposes[0].State != model.ExposeDegraded ||
		gateway.abortCalls != 0 || tunnelRuntime.rollbackCalls != 0 {
		t.Fatalf("degraded result = %+v, gateway=%s, local=%+v", created, gateway.publishedState, state.state.Exposes)
	}
	assertTraceSubsequence(t, *trace, []string{"tunnel_activate", "tunnel_observe", "gateway_publish_degraded"})
	result, err := created.Output()
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != output.StatusDegraded || result.ExitCategory != output.CategoryUnavailable ||
		len(result.Warnings) != 1 || len(result.RequiresAction) != 1 {
		t.Fatalf("degraded command result = %+v", result)
	}
}

func TestExposeCreateSagaRollsBackBeforeIngressWhenMappingRegistrationFails(t *testing.T) {
	t.Parallel()

	saga, state, gateway, tunnelRuntime, trace := newExposeSagaFixture(t, tunnel.TunnelProbePassed)
	tunnelRuntime.registration = tunnel.TunnelProbeFailed
	plan, err := saga.Plan(context.Background(), ingress.ExposeCreateRequest{Upstream: "3000", Path: exposeSagaPathCanary})
	if err != nil {
		t.Fatal(err)
	}
	_, err = saga.Apply(context.Background(), plan)
	if !errors.Is(err, ErrExposeTunnelNotReady) {
		t.Fatalf("Apply() error = %v", err)
	}
	if gateway.publishCalls != 0 || gateway.abortCalls != 1 || tunnelRuntime.rollbackCalls != 1 {
		t.Fatalf("compensation calls = publish:%d abort:%d tunnel:%d", gateway.publishCalls, gateway.abortCalls, tunnelRuntime.rollbackCalls)
	}
	if len(state.state.Exposes) != 0 || state.state.Generation != 9 || state.state.Nodes[0].Gateway.LastKnownGatewayGeneration != 13 {
		t.Fatalf("compensated local state = generation:%d gateway:%d exposes:%+v",
			state.state.Generation, state.state.Nodes[0].Gateway.LastKnownGatewayGeneration, state.state.Exposes)
	}
	assertTraceSubsequence(t, *trace, []string{
		"node_save_8", "tunnel_observe", "tunnel_rollback", "gateway_abort", "node_save_9",
	})
}

func TestExposeCreateSagaDeferWritesOnlyAuthoritativePendingRegistration(t *testing.T) {
	t.Parallel()

	saga, state, gateway, tunnelRuntime, trace := newExposeSagaFixture(t, tunnel.TunnelProbePassed)
	plan, err := saga.Plan(context.Background(), ingress.ExposeCreateRequest{Upstream: "3000", Path: exposeSagaPathCanary})
	if err != nil {
		t.Fatal(err)
	}
	before := cloneTestExposeState(t, state.state)
	*trace = nil
	deferred, err := saga.Defer(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if deferred.OperationID != exposeSagaOperationID || deferred.GatewayStateGeneration != 12 ||
		gateway.deferCalls != 1 || state.saveCalls != 0 || tunnelRuntime.activateCalls != 0 || gateway.publishCalls != 0 {
		t.Fatalf("deferred result/calls = %+v save:%d activate:%d publish:%d", deferred, state.saveCalls, tunnelRuntime.activateCalls, gateway.publishCalls)
	}
	if !reflect.DeepEqual(state.state, before) || !reflect.DeepEqual(*trace, []string{"gateway_defer"}) {
		t.Fatalf("defer mutated local state or called another adapter: trace=%v", *trace)
	}
	result, err := deferred.Output()
	if err != nil || result.Status != output.StatusPending || result.Data["operation_id"] != exposeSagaOperationID {
		t.Fatalf("deferred output = %+v, %v", result, err)
	}
}

func TestExposeCreateSagaDoesNotBlindlyRollbackAfterPublishedStateBecomesUncertain(t *testing.T) {
	t.Parallel()

	saga, state, gateway, tunnelRuntime, _ := newExposeSagaFixture(t, tunnel.TunnelProbePassed)
	state.failSaveCall = 2
	plan, err := saga.Plan(context.Background(), ingress.ExposeCreateRequest{Upstream: "3000", Path: exposeSagaPathCanary})
	if err != nil {
		t.Fatal(err)
	}
	_, err = saga.Apply(context.Background(), plan)
	if !errors.Is(err, ErrExposeOutcomeUncertain) {
		t.Fatalf("Apply() error = %v", err)
	}
	if gateway.publishCalls != 1 || gateway.abortCalls != 0 || tunnelRuntime.rollbackCalls != 0 ||
		len(state.state.Exposes) != 1 || state.state.Exposes[0].State != model.ExposePending {
		t.Fatalf("uncertain outcome was blindly rolled back: publish:%d abort:%d rollback:%d state:%+v",
			gateway.publishCalls, gateway.abortCalls, tunnelRuntime.rollbackCalls, state.state.Exposes)
	}
}

func TestFRPExposeNodeTunnelAppliesAndRollsBackCompleteTopology(t *testing.T) {
	t.Parallel()

	before := exposeSagaNodeState(t)
	expose := model.Expose{
		SchemaVersion: model.ResourceSchemaVersion, ID: exposeSagaExposeID, NodeID: exposeSagaNodeID,
		Upstream: "127.0.0.1:3000", RouteMode: model.RouteExact, Path: exposeSagaPathCanary,
		BodyLimitBytes: 1 << 20, UpstreamTimeoutSeconds: 15, ConcurrentRequests: 40,
		TunnelPort: 20000, State: model.ExposePending, Generation: 1, CreatedAt: exposeSagaCreatedAt().Add(time.Hour),
	}
	pending, err := addPendingNodeExpose(before, expose, 12)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := tunnel.NewFRPProvider("/", model.ComponentPin{
		Name: tunnel.FRPProviderName, Version: tunnel.FRPProviderVersion, Source: "vpnctl-release-bundle", Bundled: true,
		SHA256:       tunnel.FRPProviderSHA256,
		Capabilities: []string{"dynamic-reload", "http-plugin-authorization", "tcp-mux", "tls-server-verification"},
	}, staticExposeTunnelCredential{})
	if err != nil {
		t.Fatal(err)
	}
	applier := &recordingExposeFRPApplier{provider: provider}
	prober := &readyExposeFRPProber{expose: expose}
	runtime, err := NewFRPExposeNodeTunnel(provider, applier, prober)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := runtime.Activate(context.Background(), before, pending, expose)
	if err != nil {
		t.Fatal(err)
	}
	if activation.Candidate.Provider != tunnel.FRPProviderName || activation.Candidate.Generation != pending.Generation ||
		activation.frpCandidate == nil || activation.rollbackState == nil {
		t.Fatalf("activation = %+v", activation)
	}
	if _, err := json.Marshal(activation); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("activation serialization error = %v", err)
	}
	observed, err := runtime.Observe(context.Background(), activation, expose)
	if err != nil || observed.Candidate != activation.Candidate || prober.calls != 1 {
		t.Fatalf("Observe() = %+v, %v", observed, err)
	}
	if err := runtime.Rollback(context.Background(), activation); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(applier.mappingCounts, []int{1, 0}) {
		t.Fatalf("applied complete mapping counts = %v", applier.mappingCounts)
	}
}

func TestGatewayExposeCoordinatorCommitsIngressBetweenPendingAndFinalState(t *testing.T) {
	t.Parallel()

	trace := &[]string{}
	nodeStore := &memoryExposeState{state: exposeSagaNodeState(t), trace: trace, label: "node"}
	gatewayStore := &memoryExposeState{state: exposeSagaGatewayState(t), trace: trace, label: "gateway"}
	publisher := &memoryGatewayIngressPublisher{trace: trace}
	service, err := NewGatewayExposeCoordinatorService(
		gatewayStore, memoryGatewayCertificateExporter{trace: trace}, memoryGatewayUnavailablePorts{},
		publisher, memoryGatewayDeferredWriter{}, testExposeNormalizer(), "/var/lib/vpnctl/exports/gateway.crt",
	)
	if err != nil {
		t.Fatal(err)
	}
	tunnelRuntime := &memoryExposeTunnel{trace: trace, registration: tunnel.TunnelProbePassed, upstream: tunnel.TunnelProbePassed}
	saga, err := NewExposeCreateSaga(nodeStore, service, tunnelRuntime)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := saga.Plan(context.Background(), ingress.ExposeCreateRequest{Upstream: "3000", Path: exposeSagaPathCanary})
	if err != nil {
		t.Fatal(err)
	}
	created, err := saga.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if created.State != model.ExposeReady || len(gatewayStore.state.Exposes) != 1 ||
		gatewayStore.state.Exposes[0].State != model.ExposeReady || publisher.rollbackCalls != 0 {
		t.Fatalf("gateway result = %+v, state=%+v", created, gatewayStore.state.Exposes)
	}
	assertTraceSubsequence(t, *trace, []string{
		"certificate_export", "gateway_save_12", "tunnel_activate", "node_save_8", "tunnel_observe",
		"ingress_activate", "gateway_save_13", "node_save_9",
	})
}

func TestGatewayExposeCoordinatorRollsBackIngressWhenFinalStateCommitFails(t *testing.T) {
	t.Parallel()

	trace := &[]string{}
	nodeStore := &memoryExposeState{state: exposeSagaNodeState(t), trace: trace, label: "node"}
	gatewayStore := &memoryExposeState{state: exposeSagaGatewayState(t), trace: trace, label: "gateway", failSaveCall: 2}
	publisher := &memoryGatewayIngressPublisher{trace: trace}
	service, err := NewGatewayExposeCoordinatorService(
		gatewayStore, memoryGatewayCertificateExporter{trace: trace}, memoryGatewayUnavailablePorts{},
		publisher, memoryGatewayDeferredWriter{}, testExposeNormalizer(), "/var/lib/vpnctl/exports/gateway.crt",
	)
	if err != nil {
		t.Fatal(err)
	}
	tunnelRuntime := &memoryExposeTunnel{trace: trace, registration: tunnel.TunnelProbePassed, upstream: tunnel.TunnelProbePassed}
	saga, _ := NewExposeCreateSaga(nodeStore, service, tunnelRuntime)
	plan, err := saga.Plan(context.Background(), ingress.ExposeCreateRequest{Upstream: "3000", Path: exposeSagaPathCanary})
	if err != nil {
		t.Fatal(err)
	}
	_, err = saga.Apply(context.Background(), plan)
	if err == nil || errors.Is(err, ErrExposeOutcomeUncertain) {
		t.Fatalf("known compensated Apply() error = %v", err)
	}
	if publisher.rollbackCalls != 1 || tunnelRuntime.rollbackCalls != 1 ||
		len(gatewayStore.state.Exposes) != 0 || len(nodeStore.state.Exposes) != 0 {
		t.Fatalf("rollback result = ingress:%d tunnel:%d gateway:%+v node:%+v",
			publisher.rollbackCalls, tunnelRuntime.rollbackCalls, gatewayStore.state.Exposes, nodeStore.state.Exposes)
	}
	assertTraceSubsequence(t, *trace, []string{
		"ingress_activate", "ingress_rollback", "tunnel_rollback", "gateway_save_13", "node_save_9",
	})
}

func newExposeSagaFixture(
	t *testing.T,
	upstream tunnel.TunnelProbeState,
) (*ExposeCreateSaga, *memoryExposeState, *memoryExposeGateway, *memoryExposeTunnel, *[]string) {
	t.Helper()
	trace := &[]string{}
	state := &memoryExposeState{state: exposeSagaNodeState(t), trace: trace}
	gateway := &memoryExposeGateway{snapshot: exposeSagaGatewaySnapshot(t), trace: trace}
	tunnelRuntime := &memoryExposeTunnel{trace: trace, registration: tunnel.TunnelProbePassed, upstream: upstream}
	saga, err := NewExposeCreateSaga(state, gateway, tunnelRuntime)
	if err != nil {
		t.Fatal(err)
	}
	return saga, state, gateway, tunnelRuntime, trace
}

type memoryExposeState struct {
	state        model.State
	trace        *[]string
	label        string
	saveCalls    int
	failSaveCall int
}

func (store *memoryExposeState) Load() (model.State, error) {
	return cloneTestExposeStateNoTest(store.state)
}

func (store *memoryExposeState) Save(expectedGeneration uint64, candidate model.State) error {
	store.saveCalls++
	if store.failSaveCall == store.saveCalls {
		return errors.New("injected node state failure")
	}
	if store.state.Generation != expectedGeneration {
		return errors.New("stale node state generation")
	}
	if err := model.ValidateTransition(store.state, candidate); err != nil {
		return err
	}
	cloned, err := cloneTestExposeStateNoTest(candidate)
	if err != nil {
		return err
	}
	store.state = cloned
	label := store.label
	if label == "" {
		label = "node"
	}
	*store.trace = append(*store.trace, fmt.Sprintf("%s_save_%d", label, candidate.Generation))
	return nil
}

type memoryExposeGateway struct {
	snapshot       ExposeGatewaySnapshot
	trace          *[]string
	deferCalls     int
	reserveCalls   int
	publishCalls   int
	abortCalls     int
	publishedState model.ExposeState
}

func (gateway *memoryExposeGateway) Plan(_ context.Context, nodeID string, request ingress.ExposeCreateRequest) (ExposeGatewaySnapshot, error) {
	if nodeID != gateway.snapshot.Node.ID {
		return ExposeGatewaySnapshot{}, errors.New("unknown node")
	}
	normalized, err := testExposeNormalizer().Normalize(ingress.ExposeNamespace{
		NodeID: nodeID, StateGeneration: gateway.snapshot.Generation, Existing: []model.Expose{},
	}, request)
	if err != nil {
		return ExposeGatewaySnapshot{}, err
	}
	result := gateway.snapshot
	result.Normalized = normalized
	result.TunnelPort = tunnel.DefaultLoopbackPortFirst
	*gateway.trace = append(*gateway.trace, "gateway_plan")
	return result, nil
}

func (gateway *memoryExposeGateway) Reserve(_ context.Context, plan ExposeCreatePlan) (ExposeGatewayReservation, error) {
	gateway.reserveCalls++
	*gateway.trace = append(*gateway.trace, "gateway_reserve")
	return ExposeGatewayReservation{
		ExposeID: plan.Expose.ID, PreviousGeneration: gateway.snapshot.Generation, Generation: gateway.snapshot.Generation + 1,
	}, nil
}

func (gateway *memoryExposeGateway) Publish(_ context.Context, reservation ExposeGatewayReservation, state model.ExposeState) (ExposeGatewayPublication, error) {
	gateway.publishCalls++
	gateway.publishedState = state
	*gateway.trace = append(*gateway.trace, "gateway_publish_"+string(state))
	return ExposeGatewayPublication{ExposeID: reservation.ExposeID, Generation: reservation.Generation + 1}, nil
}

func (gateway *memoryExposeGateway) Abort(_ context.Context, reservation ExposeGatewayReservation) (uint64, error) {
	gateway.abortCalls++
	*gateway.trace = append(*gateway.trace, "gateway_abort")
	return reservation.Generation + 1, nil
}

func (gateway *memoryExposeGateway) Defer(_ context.Context, plan ExposeCreatePlan) (ExposeDeferredRegistration, error) {
	gateway.deferCalls++
	*gateway.trace = append(*gateway.trace, "gateway_defer")
	return ExposeDeferredRegistration{ExposeID: plan.Expose.ID, OperationID: exposeSagaOperationID, Generation: gateway.snapshot.Generation + 1}, nil
}

type memoryExposeTunnel struct {
	trace          *[]string
	registration   tunnel.TunnelProbeState
	upstream       tunnel.TunnelProbeState
	activateCalls  int
	rollbackCalls  int
	lastActivation ExposeTunnelActivation
}

type staticExposeTunnelCredential struct{}

func (staticExposeTunnelCredential) TunnelCredential(string, uint64) ([]byte, error) {
	return []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, tunnel.CredentialBytes))), nil
}

type recordingExposeFRPApplier struct {
	provider      *tunnel.FRPProvider
	mappingCounts []int
}

func (applier *recordingExposeFRPApplier) Apply(ctx context.Context, request tunnel.RenderRequest) (tunnel.FRPClientConfigurationResult, error) {
	candidate, err := applier.provider.Render(ctx, request)
	if err != nil {
		return tunnel.FRPClientConfigurationResult{}, err
	}
	count := exposeMappingCount(request.Plan)
	applier.mappingCounts = append(applier.mappingCounts, count)
	return tunnel.FRPClientConfigurationResult{MappingCount: count, ConfigHash: candidate.Descriptor().ConfigHash}, nil
}

type readyExposeFRPProber struct {
	expose model.Expose
	calls  int
}

type memoryGatewayCertificateExporter struct{ trace *[]string }

func (exporter memoryGatewayCertificateExporter) Ensure(model.State, string) error {
	*exporter.trace = append(*exporter.trace, "certificate_export")
	return nil
}

type memoryGatewayUnavailablePorts struct{}

func (memoryGatewayUnavailablePorts) Unavailable(context.Context) ([]int, error) { return []int{}, nil }

type memoryGatewayDeferredWriter struct{}

func (memoryGatewayDeferredWriter) Register(_ context.Context, plan ExposeCreatePlan) (ExposeDeferredRegistration, error) {
	return ExposeDeferredRegistration{ExposeID: plan.Expose.ID, OperationID: exposeSagaOperationID, Generation: plan.ExpectedGatewayStateGeneration + 1}, nil
}

type memoryGatewayIngressPublisher struct {
	trace         *[]string
	rollbackCalls int
}

func (publisher *memoryGatewayIngressPublisher) Activate(_ context.Context, before, candidate model.State) (GatewayExposeIngressActivation, error) {
	if candidate.Generation != before.Generation+1 || len(candidate.Exposes) != len(before.Exposes)+0 {
		return GatewayExposeIngressActivation{}, errors.New("invalid ingress candidate")
	}
	expose := candidate.Exposes[len(candidate.Exposes)-1]
	if expose.State != model.ExposeReady && expose.State != model.ExposeDegraded {
		return GatewayExposeIngressActivation{}, errors.New("ingress candidate is not effective")
	}
	*publisher.trace = append(*publisher.trace, "ingress_activate")
	return GatewayExposeIngressActivation{ExposeID: expose.ID, StateGeneration: candidate.Generation, ConfigHash: strings.Repeat("a", 64)}, nil
}

func (publisher *memoryGatewayIngressPublisher) Rollback(_ context.Context, _ GatewayExposeIngressActivation) error {
	publisher.rollbackCalls++
	*publisher.trace = append(*publisher.trace, "ingress_rollback")
	return nil
}

func (prober *readyExposeFRPProber) Probe(_ context.Context, candidate tunnel.FRPCandidate) (tunnel.TunnelReadinessResult, error) {
	prober.calls++
	name, _ := tunnel.MappingName(prober.expose.NodeID, prober.expose.ID)
	passed := tunnel.TunnelProbeResult{State: tunnel.TunnelProbePassed, Code: "ok"}
	return tunnel.TunnelReadinessResult{
		Candidate: candidate.Descriptor(), Configuration: passed, Connection: passed, MappingSet: passed,
		Mappings: []tunnel.TunnelMappingReadiness{{
			ExposeID: prober.expose.ID, Name: name, Generation: prober.expose.Generation,
			Registration: passed, Upstream: passed,
		}},
	}, nil
}

func (runtime *memoryExposeTunnel) Activate(_ context.Context, before, pending model.State, expose model.Expose) (ExposeTunnelActivation, error) {
	runtime.activateCalls++
	if containsExpose(before.Exposes, expose.ID) || !containsExpose(pending.Exposes, expose.ID) {
		return ExposeTunnelActivation{}, errors.New("candidate ordering violation")
	}
	activation := ExposeTunnelActivation{ExposeID: expose.ID, Candidate: tunnel.CandidateDescriptor{
		Provider: "test", HostRole: model.RoleNode, HostID: pending.Host.ID,
		Generation: pending.Generation, NodeID: expose.NodeID,
		CredentialGeneration: pending.Nodes[0].CredentialGeneration,
		ActiveTransport:      pending.Nodes[0].ActiveTransport, ConfigHash: strings.Repeat("a", 64),
	}}
	runtime.lastActivation = activation
	*runtime.trace = append(*runtime.trace, "tunnel_activate")
	return activation, nil
}

func (runtime *memoryExposeTunnel) Observe(_ context.Context, activation ExposeTunnelActivation, expose model.Expose) (tunnel.TunnelReadinessResult, error) {
	*runtime.trace = append(*runtime.trace, "tunnel_observe")
	name, _ := tunnel.MappingName(expose.NodeID, expose.ID)
	return tunnel.TunnelReadinessResult{
		Candidate:     activation.Candidate,
		Configuration: tunnel.TunnelProbeResult{State: tunnel.TunnelProbePassed, Code: "ok"},
		Connection:    tunnel.TunnelProbeResult{State: tunnel.TunnelProbePassed, Code: "ok"},
		MappingSet:    tunnel.TunnelProbeResult{State: tunnel.TunnelProbePassed, Code: "ok"},
		Mappings: []tunnel.TunnelMappingReadiness{{
			ExposeID: expose.ID, Name: name, Generation: expose.Generation,
			Registration: tunnel.TunnelProbeResult{State: runtime.registration, Code: probeCode(runtime.registration, "registration")},
			Upstream:     tunnel.TunnelProbeResult{State: runtime.upstream, Code: probeCode(runtime.upstream, "upstream")},
		}},
	}, nil
}

func (runtime *memoryExposeTunnel) Rollback(_ context.Context, activation ExposeTunnelActivation) error {
	if activation != runtime.lastActivation {
		return errors.New("wrong tunnel activation")
	}
	runtime.rollbackCalls++
	*runtime.trace = append(*runtime.trace, "tunnel_rollback")
	return nil
}

func probeCode(state tunnel.TunnelProbeState, name string) string {
	if state == tunnel.TunnelProbePassed {
		return "ok"
	}
	return name + "_unavailable"
}

func exposeSagaGatewaySnapshot(t *testing.T) ExposeGatewaySnapshot {
	t.Helper()
	nodeState := exposeSagaNodeState(t)
	node := nodeState.Nodes[0]
	node.Gateway = nil
	created := exposeSagaCreatedAt()
	certificate := model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: exposeSagaCertificateID,
		Kind: model.CertificatePublicIngress, OwnerKind: "host", OwnerID: exposeSagaGatewayID,
		Fingerprint: "sha256:" + strings.Repeat("c", 64), SerialHex: "1", Subject: "CN=203.0.113.10",
		SANs: []string{"IP:203.0.113.10"}, NotBefore: created, NotAfter: created.AddDate(5, 0, 0), WarningDays: 180,
		Generation: 1, CertificateRef: ingress.PublicCertificateRef, PrivateKeyRef: ingress.PublicCertificatePrivateKeyRef,
	}
	if err := certificate.Validate(); err != nil {
		t.Fatal(err)
	}
	return ExposeGatewaySnapshot{
		GatewayID: exposeSagaGatewayID, Generation: 11, PublicIPv4: "203.0.113.10", Node: node,
		Certificate:           certificate,
		CertificateExportPath: "/var/lib/vpnctl/exports/gateway.crt",
	}
}

func testExposeNormalizer() *ingress.ExposeNormalizer {
	return ingress.NewExposeNormalizer(ingress.ExposeNormalizerRuntime{
		NewUUID: func() (string, error) { return exposeSagaExposeID, nil },
		Now:     func() time.Time { return exposeSagaCreatedAt().Add(time.Hour) },
	})
}

func exposeSagaNodeState(t *testing.T) model.State {
	t.Helper()
	created := exposeSagaCreatedAt()
	node := model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: exposeSagaNodeID, Name: "private-1",
		Lifecycle: model.LifecycleActive, OverlayIPv4: "10.67.0.2", CredentialGeneration: 1,
		AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
		IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: created,
		Gateway: &model.GatewayTrust{
			PublicIPv4: "203.0.113.10", NodeCIDR: model.DefaultNodeCIDR, GatewayOverlayIPv4: "10.67.0.1",
			ControlProtocol: "1.0", EnrollmentFingerprint: "sha256:" + strings.Repeat("d", 64),
			EnrollmentPublicKeyRef:        "enrollment-public:gateway",
			ControlCAFingerprints:         []string{"sha256:" + strings.Repeat("e", 64)},
			ControlCACertificateRefs:      []string{"control-cert:gateway-ca-g1"},
			StandardPublicKey:             base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32)),
			RestrictedServerCredentialRef: "restricted-upstream:gateway-g1", LastKnownGatewayGeneration: 7,
		},
	}
	state := model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 7,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: exposeSagaNodeHostID, Role: model.RoleNode,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: created,
		},
		HandshakeHost: &model.HandshakeHost{
			SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft",
			Hostname: "www.microsoft.com", SelectedAt: created,
		},
		Invites: []model.Invite{}, Nodes: []model.Node{node}, Clients: []model.Client{}, Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports: []model.Transport{
			{
				SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: exposeSagaNodeID,
				Kind: model.TransportStandard, State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP,
				Port: 51820, CredentialGeneration: 1, CredentialRef: "wireguard-key:node-g1",
				PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32)), ConfigHash: strings.Repeat("a", 64),
			},
			{
				SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: exposeSagaNodeID,
				Kind: model.TransportRestricted, State: model.TransportStandby, Provider: "mihomo", Protocol: model.ProtocolTCP,
				Port: 8443, CredentialGeneration: 1, CredentialRef: "restricted-key:node-g1",
				HandshakeHost: "www.microsoft.com", ConfigHash: strings.Repeat("b", 64),
			},
		},
		Exposes: []model.Expose{}, Certificates: []model.Certificate{}, Operations: []model.Operation{},
		Logging: []model.LoggingSession{}, Backups: []model.Backup{},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0-dev",
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: 1, StateSchemaMaximum: 1,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1,
			MigrationReversible: true,
			Components: []model.ComponentPin{{
				Name: "frp", Version: "0.69.0", Source: "vpnctl-release-bundle", Bundled: true,
				SHA256: strings.Repeat("f", 64), Capabilities: []string{"tcp-mux"},
			}},
		},
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("node fixture: %v", err)
	}
	return state
}

func exposeSagaGatewayState(t *testing.T) model.State {
	t.Helper()
	state := cloneTestExposeState(t, exposeSagaNodeState(t))
	state.Generation = 11
	state.Host = model.Host{
		SchemaVersion: model.ResourceSchemaVersion, ID: exposeSagaGatewayID, Role: model.RoleGateway,
		OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: exposeSagaCreatedAt(),
		PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", SSHPort: 22,
		ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
	}
	state.Nodes[0].Gateway = nil
	state.Certificates = []model.Certificate{exposeSagaGatewaySnapshot(t).Certificate}
	if err := state.Validate(); err != nil {
		t.Fatalf("gateway fixture: %v", err)
	}
	return state
}

func exposeSagaCreatedAt() time.Time {
	return time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
}

func cloneTestExposeState(t *testing.T, state model.State) model.State {
	t.Helper()
	cloned, err := cloneTestExposeStateNoTest(state)
	if err != nil {
		t.Fatal(err)
	}
	return cloned
}

func cloneTestExposeStateNoTest(state model.State) (model.State, error) {
	encoded, err := model.EncodeState(state)
	if err != nil {
		return model.State{}, err
	}
	return model.DecodeState(encoded)
}

func assertTraceSubsequence(t *testing.T, trace, wanted []string) {
	t.Helper()
	index := 0
	for _, entry := range trace {
		if index < len(wanted) && entry == wanted[index] {
			index++
		}
	}
	if index != len(wanted) {
		t.Fatalf("trace %v does not contain ordered subsequence %v", trace, wanted)
	}
}
