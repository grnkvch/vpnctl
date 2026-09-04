package operations

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestExposeRPCConnectsNodeCoordinatorToSerializedGatewayAuthority(t *testing.T) {
	t.Parallel()

	gatewayState := exposeSagaGatewayState(t)
	trace := &[]string{}
	stateStore := &memoryExposeState{state: gatewayState, trace: trace, label: "gateway"}
	publisher := &memoryGatewayIngressPublisher{trace: trace}
	service, err := NewGatewayExposeCoordinatorService(
		stateStore, memoryGatewayCertificateExporter{trace: trace}, memoryGatewayUnavailablePorts{}, publisher,
		memoryGatewayDeferredWriter{}, testExposeNormalizer(), "/var/lib/vpnctl/exports/gateway.crt",
	)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewExposeGatewayRPCHandler(&sync.Mutex{}, service)
	if err != nil {
		t.Fatal(err)
	}
	caller := directExposeRPCCaller{handler: handler, peer: control.RPCPeer{NodeID: exposeSagaNodeID}}
	client, err := NewRemoteExposeGatewayCoordinator(
		caller, control.RPCProtocolVersion{Major: 1, Minor: 0}, exposeSagaNodeID, 1, 7,
		exposeSagaCreatedAt, func() (string, error) { return exposeSagaOperationID, nil },
		bytes.NewReader(bytes.Repeat([]byte{0x5a}, control.RPCNonceBytes*8)),
	)
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := client.Plan(context.Background(), exposeSagaNodeID, ingress.ExposeCreateRequest{
		Upstream: "3000", Name: "telegram", Path: exposeSagaPathCanary,
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Generation != 11 || snapshot.Normalized.Path != exposeSagaPathCanary || snapshot.TunnelPort != 20000 {
		t.Fatalf("RPC plan snapshot = %+v", snapshot)
	}
	plan := ExposeCreatePlan{
		Normalized: snapshot.Normalized,
		Expose: model.Expose{
			SchemaVersion: model.ResourceSchemaVersion, ID: snapshot.Normalized.ExposeID, NodeID: snapshot.Normalized.NodeID,
			Name: snapshot.Normalized.Name, Upstream: snapshot.Normalized.Upstream, RouteMode: snapshot.Normalized.RouteMode,
			Path: snapshot.Normalized.Path, BodyLimitBytes: snapshot.Normalized.Limits.BodyBytes,
			UpstreamTimeoutSeconds: snapshot.Normalized.Limits.UpstreamTimeoutSeconds,
			ConcurrentRequests:     snapshot.Normalized.Limits.ConcurrentRequests, TunnelPort: snapshot.TunnelPort,
			State: model.ExposePending, Generation: 1, CreatedAt: snapshot.Normalized.CreatedAt,
		},
		NodeHostID: exposeSagaNodeHostID, ExpectedLocalStateGeneration: 7,
		ExpectedGatewayStateGeneration: snapshot.Generation, GatewayID: snapshot.GatewayID,
		PublicIPv4: snapshot.PublicIPv4, Certificate: snapshot.Certificate, CertificateExportPath: snapshot.CertificateExportPath,
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	reservation, err := client.Reserve(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.Generation != 12 || stateStore.state.Generation != 12 || stateStore.state.Exposes[0].State != model.ExposePending {
		t.Fatalf("RPC reservation = %+v, gateway generation = %d", reservation, stateStore.state.Generation)
	}
	publication, err := client.Publish(context.Background(), reservation, model.ExposeReady)
	if err != nil {
		t.Fatal(err)
	}
	if publication.Generation != 13 || publication.ExposeID != plan.Expose.ID || stateStore.state.Exposes[0].State != model.ExposeReady {
		t.Fatalf("RPC publication = %+v, gateway expose = %+v", publication, stateStore.state.Exposes)
	}
	if publisher.rollbackCalls != 0 {
		t.Fatal("successful RPC publication rolled ingress back")
	}
}

func TestGatewayExposeStateDeferredWriterRegistersDesiredExposeWithoutRuntime(t *testing.T) {
	t.Parallel()
	gatewayState := exposeSagaGatewayState(t)
	stateStore := &memoryExposeState{state: gatewayState, trace: &[]string{}, label: "gateway"}
	service, err := NewGatewayExposeCoordinatorService(
		stateStore, memoryGatewayCertificateExporter{trace: &[]string{}}, memoryGatewayUnavailablePorts{},
		&memoryGatewayIngressPublisher{trace: &[]string{}}, memoryGatewayDeferredWriter{},
		testExposeNormalizer(), "/var/lib/vpnctl/exports/gateway.crt",
	)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.Plan(context.Background(), exposeSagaNodeID, ingress.ExposeCreateRequest{
		Upstream: "3000", Name: "telegram", Path: exposeSagaPathCanary,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan := exposeRPCPlanFixture(t, snapshot)
	writer, err := NewGatewayExposeStateDeferredWriter(
		stateStore, exposeSagaCreatedAt, func() (string, error) { return exposeSagaOperationID, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := writer.Register(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Generation != 12 || receipt.ExposeID != exposeSagaExposeID || receipt.OperationID != exposeSagaOperationID {
		t.Fatalf("deferred receipt = %+v", receipt)
	}
	if len(stateStore.state.Exposes) != 1 || stateStore.state.Exposes[0].State != model.ExposePending ||
		len(stateStore.state.Operations) != 1 || stateStore.state.Operations[0].State != model.OperationPending ||
		stateStore.state.Operations[0].TargetID != exposeSagaExposeID {
		t.Fatalf("deferred gateway state = exposes:%+v operations:%+v", stateStore.state.Exposes, stateStore.state.Operations)
	}
}

func TestSystemGatewayExposeUnavailablePortsParsesManagedRangeStrictly(t *testing.T) {
	t.Parallel()
	runner := &exposeSSRunner{result: linuxplatform.ProbeResult{Stdout: []byte(
		"LISTEN 0 4096 127.0.0.1:20002 0.0.0.0:*\n" +
			"LISTEN 0 4096 [::]:20001 [::]:*\n" +
			"LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n",
	)}}
	inspector, err := NewSystemGatewayExposeUnavailablePorts(runner)
	if err != nil {
		t.Fatal(err)
	}
	ports, err := inspector.Unavailable(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 || ports[0] != 20001 || ports[1] != 20002 {
		t.Fatalf("managed unavailable ports = %v", ports)
	}
	runner.result.Stdout = []byte("malformed-listener\n")
	if _, err := inspector.Unavailable(context.Background()); err == nil {
		t.Fatal("malformed ss output was treated as an empty listener set")
	}
}

func exposeRPCPlanFixture(t *testing.T, snapshot ExposeGatewaySnapshot) ExposeCreatePlan {
	t.Helper()
	plan := ExposeCreatePlan{
		Normalized: snapshot.Normalized,
		Expose: model.Expose{
			SchemaVersion: model.ResourceSchemaVersion, ID: snapshot.Normalized.ExposeID, NodeID: snapshot.Normalized.NodeID,
			Name: snapshot.Normalized.Name, Upstream: snapshot.Normalized.Upstream, RouteMode: snapshot.Normalized.RouteMode,
			Path: snapshot.Normalized.Path, BodyLimitBytes: snapshot.Normalized.Limits.BodyBytes,
			UpstreamTimeoutSeconds: snapshot.Normalized.Limits.UpstreamTimeoutSeconds,
			ConcurrentRequests:     snapshot.Normalized.Limits.ConcurrentRequests, TunnelPort: snapshot.TunnelPort,
			State: model.ExposePending, Generation: 1, CreatedAt: snapshot.Normalized.CreatedAt,
		},
		NodeHostID: exposeSagaNodeHostID, ExpectedLocalStateGeneration: 7,
		ExpectedGatewayStateGeneration: snapshot.Generation, GatewayID: snapshot.GatewayID,
		PublicIPv4: snapshot.PublicIPv4, Certificate: snapshot.Certificate, CertificateExportPath: snapshot.CertificateExportPath,
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	return plan
}

type directExposeRPCCaller struct {
	handler control.RPCHandler
	peer    control.RPCPeer
}

type exposeSSRunner struct {
	result linuxplatform.ProbeResult
	err    error
}

func (runner *exposeSSRunner) Run(context.Context, linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	return runner.result, runner.err
}

func (caller directExposeRPCCaller) CallManagement(ctx context.Context, request control.RPCRequest) (control.RPCCallResult, error) {
	if err := request.Validate(); err != nil {
		return control.RPCCallResult{}, err
	}
	result, err := caller.handler.HandleRPC(ctx, caller.peer, request)
	if err != nil {
		return control.RPCCallResult{}, err
	}
	if err := result.Response.Validate(); err != nil {
		return control.RPCCallResult{}, err
	}
	return control.RPCCallResult{StatusCode: result.StatusCode, Response: result.Response}, nil
}
