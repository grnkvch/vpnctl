package operations

import (
	"context"
	"encoding/json"
	"errors"
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
	exposeRemoveSecondID   = "62000000-0000-4000-8000-000000000007"
	exposeRemoveOperation  = "62000000-0000-4000-8000-000000000008"
	exposeRemoveSecondPath = "/openai/webhook-path-canary-4K8M"
)

func TestExposeRemoveSagaUnpublishesDrainsAndRemovesOnlyTargetBeforePortRelease(t *testing.T) {
	t.Parallel()

	trace := &[]string{}
	nodeState, gatewayState := exposeRemovalStates(t)
	nodeStore := &memoryExposeState{state: nodeState, trace: trace, label: "node"}
	gatewayStore := &memoryExposeState{state: gatewayState, trace: trace, label: "gateway"}
	publisher := &recordingRemovalPublisher{trace: trace}
	service, err := NewGatewayExposeRemovalService(gatewayStore, publisher, removalDeferredWriter{})
	if err != nil {
		t.Fatal(err)
	}
	tunnelRuntime := &recordingRemovalTunnel{trace: trace, retainedID: exposeRemoveSecondID}
	waiter := &recordingRemovalWaiter{trace: trace}
	saga, err := NewExposeRemoveSaga(nodeStore, service, tunnelRuntime, waiter)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := saga.Plan(context.Background(), "telegram")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Expose.ID != exposeSagaExposeID || plan.ExpectedGatewayStateGeneration != 11 {
		t.Fatalf("plan = %+v", plan)
	}
	if _, err := json.Marshal(plan); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("plan serialization error = %v", err)
	}
	removed, err := saga.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if removed.ExposeID != exposeSagaExposeID || removed.LocalStateGeneration != 9 ||
		removed.GatewayStateGeneration != 13 || removed.DrainSeconds != 10 {
		t.Fatalf("removed = %+v", removed)
	}
	assertTraceSubsequence(t, *trace, []string{
		"ingress_unpublish", "gateway_save_12", "node_save_8", "drain_10s",
		"tunnel_remove", "gateway_save_13", "node_save_9",
	})
	if publisher.activeExposeCount != 1 || publisher.retainedID != exposeRemoveSecondID ||
		waiter.duration != ExposeRemovalDrain || tunnelRuntime.mappingCount != 1 {
		t.Fatalf("isolated removal evidence = publisher:%+v waiter:%s tunnel:%+v", publisher, waiter.duration, tunnelRuntime)
	}
	for label, state := range map[string]model.State{"node": nodeStore.state, "gateway": gatewayStore.state} {
		if len(state.Exposes) != 1 || state.Exposes[0].ID != exposeRemoveSecondID || state.Exposes[0].State != model.ExposeReady {
			t.Fatalf("%s final exposes = %+v", label, state.Exposes)
		}
	}
	allocator, remaps, err := tunnel.DefaultLoopbackAllocatorFromExposes(gatewayStore.state.Exposes, nil)
	if err != nil || len(remaps) != 0 {
		t.Fatalf("restore final allocator = %v, %+v", err, remaps)
	}
	port, err := allocator.Allocate(exposeSagaExposeID)
	if err != nil || port != tunnel.DefaultLoopbackPortFirst {
		t.Fatalf("released port reallocation = %d, %v", port, err)
	}
	result, err := removed.Output()
	if err != nil || len(result.RequiresAction) != 1 || result.RequiresAction[0].Code != "remove_external_webhook" ||
		result.RequiresAction[0].Command != "" {
		t.Fatalf("remove output/action = %+v, %v", result, err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), exposeSagaPathCanary) || strings.Contains(string(encoded), exposeRemoveSecondPath) {
		t.Fatalf("remove output leaked a webhook path: %s", encoded)
	}
}

func TestExposeRemoveSagaLeavesDisabledReservationWhenDrainIsInterrupted(t *testing.T) {
	t.Parallel()

	trace := &[]string{}
	nodeState, gatewayState := exposeRemovalStates(t)
	nodeStore := &memoryExposeState{state: nodeState, trace: trace, label: "node"}
	gatewayStore := &memoryExposeState{state: gatewayState, trace: trace, label: "gateway"}
	service, err := NewGatewayExposeRemovalService(gatewayStore, &recordingRemovalPublisher{trace: trace}, removalDeferredWriter{})
	if err != nil {
		t.Fatal(err)
	}
	tunnelRuntime := &recordingRemovalTunnel{trace: trace, retainedID: exposeRemoveSecondID}
	saga, err := NewExposeRemoveSaga(nodeStore, service, tunnelRuntime, failingRemovalWaiter{trace: trace})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := saga.Plan(context.Background(), exposeSagaExposeID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = saga.Apply(context.Background(), plan)
	if !errors.Is(err, ErrExposeRemovalIncomplete) {
		t.Fatalf("Apply() error = %v", err)
	}
	if tunnelRuntime.calls != 0 || gatewayStore.state.Generation != 12 || nodeStore.state.Generation != 8 {
		t.Fatalf("interrupted removal advanced too far: tunnel=%d gateway=%d node=%d", tunnelRuntime.calls, gatewayStore.state.Generation, nodeStore.state.Generation)
	}
	for label, state := range map[string]model.State{"node": nodeStore.state, "gateway": gatewayStore.state} {
		if len(state.Exposes) != 2 || state.Exposes[0].State != model.ExposeDisabled || state.Exposes[0].TunnelPort != 20000 {
			t.Fatalf("%s did not retain disabled reserved target: %+v", label, state.Exposes)
		}
	}
}

func TestExposeRemoveSagaDeferredWritesOnlyAuthoritativeRegistration(t *testing.T) {
	t.Parallel()

	trace := &[]string{}
	nodeState, gatewayState := exposeRemovalStates(t)
	nodeStore := &memoryExposeState{state: nodeState, trace: trace, label: "node"}
	gatewayStore := &memoryExposeState{state: gatewayState, trace: trace, label: "gateway"}
	deferred := &recordingRemovalDeferredWriter{trace: trace}
	service, err := NewGatewayExposeRemovalService(gatewayStore, &recordingRemovalPublisher{trace: trace}, deferred)
	if err != nil {
		t.Fatal(err)
	}
	tunnelRuntime := &recordingRemovalTunnel{trace: trace, retainedID: exposeRemoveSecondID}
	saga, err := NewExposeRemoveSaga(nodeStore, service, tunnelRuntime, &recordingRemovalWaiter{trace: trace})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := saga.Plan(context.Background(), "telegram")
	if err != nil {
		t.Fatal(err)
	}
	beforeNode := cloneTestExposeState(t, nodeStore.state)
	beforeGateway := cloneTestExposeState(t, gatewayStore.state)
	deferredResult, err := saga.Defer(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if deferredResult.OperationID != exposeRemoveOperation || deferredResult.GatewayStateGeneration != 12 ||
		!reflect.DeepEqual(beforeNode, nodeStore.state) || !reflect.DeepEqual(beforeGateway, gatewayStore.state) ||
		tunnelRuntime.calls != 0 || deferred.calls != 1 {
		t.Fatalf("deferred result/state = %+v node:%v gateway:%v calls:%d/%d", deferredResult,
			reflect.DeepEqual(beforeNode, nodeStore.state), reflect.DeepEqual(beforeGateway, gatewayStore.state), tunnelRuntime.calls, deferred.calls)
	}
	result, err := deferredResult.Output()
	if err != nil || result.Status != output.StatusPending || len(result.RequiresAction) != 1 {
		t.Fatalf("deferred output = %+v, %v", result, err)
	}
}

func TestFRPExposeNodeTunnelRemovalAppliesCompleteRetainedTopology(t *testing.T) {
	t.Parallel()

	node, _ := exposeRemovalStates(t)
	node.Generation = 8
	node.Exposes[0].State = model.ExposeDisabled
	node.Exposes[0].Generation++
	if err := node.Validate(); err != nil {
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
	runtime, err := NewFRPExposeNodeTunnel(provider, applier, &readyExposeFRPProber{expose: node.Exposes[1]})
	if err != nil {
		t.Fatal(err)
	}
	deactivation, err := runtime.Deactivate(context.Background(), node, node.Exposes[0])
	if err != nil {
		t.Fatal(err)
	}
	if deactivation.ExposeID != exposeSagaExposeID || deactivation.Candidate.Generation != 8 ||
		!reflect.DeepEqual(applier.mappingCounts, []int{1}) {
		t.Fatalf("deactivation = %+v, mapping counts = %v", deactivation, applier.mappingCounts)
	}
	if _, err := json.Marshal(deactivation); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("deactivation serialization error = %v", err)
	}
}

type recordingRemovalPublisher struct {
	trace             *[]string
	activeExposeCount int
	retainedID        string
}

func (publisher *recordingRemovalPublisher) Activate(_ context.Context, before, candidate model.State) (GatewayExposeIngressActivation, error) {
	var changed model.Expose
	for _, expose := range candidate.Exposes {
		if expose.State != model.ExposeDisabled {
			publisher.activeExposeCount++
			publisher.retainedID = expose.ID
		}
		for _, old := range before.Exposes {
			if old.ID == expose.ID && old.State != expose.State {
				changed = expose
			}
		}
	}
	request := ingress.NginxRenderRequest{
		StateGeneration: candidate.Generation, PublicIPv4: candidate.Host.PublicIPv4,
		CertificatePath: "/var/lib/vpnctl/secrets/public.crt", PrivateKeyPath: "/var/lib/vpnctl/secrets/public.key",
		RuntimeDirectory: "/run/vpnctl-ingress", Limits: ingress.DefaultGatewayHardLimits(), Exposes: candidate.Exposes,
	}
	rendered, err := ingress.RenderNginxConfig(request)
	if err != nil || rendered.ActiveExposeCount() != publisher.activeExposeCount || changed.State != model.ExposeDisabled {
		return GatewayExposeIngressActivation{}, errors.New("invalid ingress removal candidate")
	}
	*publisher.trace = append(*publisher.trace, "ingress_unpublish")
	return GatewayExposeIngressActivation{
		ExposeID: changed.ID, StateGeneration: candidate.Generation, ConfigHash: rendered.ConfigHash(),
	}, nil
}

func (publisher *recordingRemovalPublisher) Rollback(context.Context, GatewayExposeIngressActivation) error {
	*publisher.trace = append(*publisher.trace, "ingress_rollback")
	return nil
}

type recordingRemovalTunnel struct {
	trace        *[]string
	retainedID   string
	calls        int
	mappingCount int
}

func (runtime *recordingRemovalTunnel) Deactivate(_ context.Context, disabled model.State, target model.Expose) (ExposeTunnelDeactivation, error) {
	runtime.calls++
	plan, err := tunnel.PlanFromState(disabled)
	if err != nil {
		return ExposeTunnelDeactivation{}, err
	}
	runtime.mappingCount = exposeMappingCount(plan)
	if runtime.mappingCount != 1 || len(plan.Nodes) != 1 || len(plan.Nodes[0].Mappings) != 1 ||
		plan.Nodes[0].Mappings[0].ExposeID != runtime.retainedID {
		return ExposeTunnelDeactivation{}, errors.New("tunnel removal changed another mapping")
	}
	*runtime.trace = append(*runtime.trace, "tunnel_remove")
	return ExposeTunnelDeactivation{
		ExposeID: target.ID,
		Candidate: tunnel.CandidateDescriptor{
			Provider: "frp", HostRole: disabled.Host.Role, HostID: disabled.Host.ID,
			Generation: disabled.Generation, NodeID: disabled.Nodes[0].ID,
			CredentialGeneration: disabled.Nodes[0].CredentialGeneration,
			ActiveTransport:      disabled.Nodes[0].ActiveTransport, ConfigHash: strings.Repeat("a", 64),
		},
	}, nil
}

type recordingRemovalWaiter struct {
	trace    *[]string
	duration time.Duration
}

func (waiter *recordingRemovalWaiter) Wait(_ context.Context, duration time.Duration) error {
	waiter.duration = duration
	*waiter.trace = append(*waiter.trace, "drain_"+duration.String())
	return nil
}

type failingRemovalWaiter struct{ trace *[]string }

func (waiter failingRemovalWaiter) Wait(context.Context, time.Duration) error {
	*waiter.trace = append(*waiter.trace, "drain_interrupted")
	return context.Canceled
}

type removalDeferredWriter struct{}

func (removalDeferredWriter) RegisterRemoval(_ context.Context, plan ExposeRemovePlan) (ExposeRemovalDeferredRegistration, error) {
	return ExposeRemovalDeferredRegistration{
		ExposeID: plan.Expose.ID, OperationID: exposeRemoveOperation, Generation: plan.ExpectedGatewayStateGeneration + 1,
	}, nil
}

type recordingRemovalDeferredWriter struct {
	trace *[]string
	calls int
}

func (writer *recordingRemovalDeferredWriter) RegisterRemoval(_ context.Context, plan ExposeRemovePlan) (ExposeRemovalDeferredRegistration, error) {
	writer.calls++
	*writer.trace = append(*writer.trace, "gateway_defer_remove")
	return removalDeferredWriter{}.RegisterRemoval(context.Background(), plan)
}

func exposeRemovalStates(t *testing.T) (model.State, model.State) {
	t.Helper()
	first := model.Expose{
		SchemaVersion: model.ResourceSchemaVersion, ID: exposeSagaExposeID, NodeID: exposeSagaNodeID, Name: "telegram",
		Upstream: "127.0.0.1:3000", RouteMode: model.RouteExact, Path: exposeSagaPathCanary,
		BodyLimitBytes: 1 << 20, UpstreamTimeoutSeconds: 15, ConcurrentRequests: 40,
		TunnelPort: 20000, State: model.ExposeReady, Generation: 2, CreatedAt: exposeSagaCreatedAt().Add(time.Hour),
	}
	second := model.Expose{
		SchemaVersion: model.ResourceSchemaVersion, ID: exposeRemoveSecondID, NodeID: exposeSagaNodeID, Name: "openai",
		Upstream: "127.0.0.1:4000", RouteMode: model.RouteExact, Path: exposeRemoveSecondPath,
		BodyLimitBytes: 2 << 20, UpstreamTimeoutSeconds: 30, ConcurrentRequests: 40,
		TunnelPort: 20001, State: model.ExposeReady, Generation: 3, CreatedAt: exposeSagaCreatedAt().Add(2 * time.Hour),
	}
	node := exposeSagaNodeState(t)
	gateway := exposeSagaGatewayState(t)
	node.Exposes = []model.Expose{first, second}
	gateway.Exposes = []model.Expose{first, second}
	if err := node.Validate(); err != nil {
		t.Fatalf("node removal fixture: %v", err)
	}
	if err := gateway.Validate(); err != nil {
		t.Fatalf("gateway removal fixture: %v", err)
	}
	return node, gateway
}
