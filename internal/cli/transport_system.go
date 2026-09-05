package cli

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

var ErrSystemTransportRuntimeUnavailable = errors.New("system transport runtime adapter is unavailable")

type transportDeferredGateway interface {
	RegisterDeferred(context.Context, model.TransportKind, model.TransportKind, uint64) (transport.DeferredSwitchReceipt, error)
}

var transportBuildDeferredGateway = func(paths store.Paths) (transportDeferredGateway, error) {
	return operations.NewSystemRemoteTransportSwitchGateway(paths, nil)
}

func buildSystemTransportTester(paths store.Paths) (transportTester, error) {
	state, registry, err := buildSystemTransportPlanningRuntime(paths)
	if err != nil {
		return nil, err
	}
	return transport.NewNodeTester(state, registry, transport.TestLimits{})
}

func buildSystemTransportSwitcher(paths store.Paths) (TransportSwitcher, error) {
	state, registry, err := buildSystemTransportPlanningRuntime(paths)
	if err != nil {
		return nil, err
	}
	return transport.NewNodeSwitcher(state, registry, transport.SwitchLimits{})
}

func buildSystemTransportPlanningRuntime(paths store.Paths) (*store.StateStore, *transport.Registry, error) {
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, nil, err
	}
	registry, err := transport.NewRegistry(
		systemUnavailableTransportProvider{kind: model.TransportStandard},
		systemUnavailableTransportProvider{kind: model.TransportRestricted},
	)
	if err != nil {
		return nil, nil, err
	}
	return state, registry, nil
}

func buildSystemTransportDeferredWriter(paths store.Paths) (AuthoritativeDeferredWriter, error) {
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	gateway, err := transportBuildDeferredGateway(paths)
	if err != nil {
		return nil, err
	}
	return &systemTransportDeferredWriter{state: state, gateway: gateway, now: time.Now}, nil
}

type systemTransportDeferredWriter struct {
	state   *store.StateStore
	gateway transportDeferredGateway
	now     func() time.Time
}

func (writer *systemTransportDeferredWriter) RegisterPending(ctx context.Context, public MutationPlan) (DeferredReceipt, error) {
	if ctx == nil || writer == nil || writer.state == nil || writer.gateway == nil || writer.now == nil {
		return DeferredReceipt{}, ErrSystemTransportRuntimeUnavailable
	}
	current, currentOK := public.Result.Data["current"].(string)
	target, targetOK := public.Result.Data["candidate"].(string)
	nextGeneration, generationOK := public.Result.Data["generation"].(uint64)
	changed, changedOK := public.Result.Data["changed"].(bool)
	if public.Impact != ImpactAvailability || public.Result.Command != "transport.switch" ||
		!currentOK || !targetOK || !generationOK || !changedOK || !changed ||
		!validTransportCommandTarget(model.TransportKind(current)) || !validTransportCommandTarget(model.TransportKind(target)) || current == target {
		return DeferredReceipt{}, ErrInvalidMutationPlan
	}
	before, err := writer.state.Load()
	if err != nil {
		return DeferredReceipt{}, err
	}
	expectedNext, err := model.NextGeneration(before.Generation)
	if err != nil || expectedNext != nextGeneration || before.Host.Role != model.RoleNode || len(before.Nodes) != 1 ||
		before.Nodes[0].Lifecycle != model.LifecycleActive || before.Nodes[0].Gateway == nil ||
		before.Nodes[0].ActiveTransport != model.TransportKind(current) {
		return DeferredReceipt{}, transport.ErrTransportSwitchStale
	}
	if retained, found, pendingErr := before.PendingNodeOperation(); pendingErr != nil {
		return DeferredReceipt{}, pendingErr
	} else if found {
		return writer.retainedReceipt(before, retained, model.TransportKind(current), model.TransportKind(target))
	}
	receipt, err := writer.gateway.RegisterDeferred(ctx, model.TransportKind(current), model.TransportKind(target), before.Generation)
	if err != nil {
		return DeferredReceipt{}, err
	}
	if err := receipt.Validate(); err != nil || receipt.NodeID != before.Nodes[0].ID || receipt.Current != model.TransportKind(current) ||
		receipt.Target != model.TransportKind(target) || receipt.ExpectedNodeGeneration != before.Generation {
		return DeferredReceipt{}, transport.ErrTransportSwitchCommitUncertain
	}
	candidate, err := writer.mirrorGatewayIntent(before, receipt)
	if err != nil {
		return DeferredReceipt{}, errors.Join(transport.ErrTransportSwitchCommitUncertain, err)
	}
	if err := writer.state.Save(before.Generation, candidate); err != nil {
		return DeferredReceipt{}, errors.Join(transport.ErrTransportSwitchCommitUncertain, err)
	}
	committed, loadErr := writer.state.Load()
	if loadErr != nil || !reflect.DeepEqual(candidate, committed) {
		return DeferredReceipt{}, errors.Join(transport.ErrTransportSwitchCommitUncertain, loadErr)
	}
	return publicTransportDeferredReceipt(receipt), nil
}

func (writer *systemTransportDeferredWriter) mirrorGatewayIntent(
	before model.State,
	receipt transport.DeferredSwitchReceipt,
) (model.State, error) {
	if receipt.GatewayGeneration < 2 {
		return model.State{}, ErrInvalidMutationPlan
	}
	intent, err := transport.NewSwitchIntentTarget(receipt.NodeID, receipt.Target, receipt.ExpectedNodeGeneration)
	if err != nil || intent.DesiredNodeGeneration != receipt.DesiredNodeGeneration {
		return model.State{}, ErrInvalidMutationPlan
	}
	at := writer.now().UTC()
	stepNames := transport.SwitchOperationStepNames()
	steps := make([]model.OperationStep, len(stepNames))
	for index, name := range stepNames {
		steps[index] = model.OperationStep{Name: name, State: model.OperationPending, UpdatedAt: at}
	}
	operation := model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: receipt.OperationID, Type: model.OperationTransportSwitch,
		State: model.OperationPending, TargetKind: "transport", TargetID: intent.String(), RequestID: receipt.RequestID,
		ExpectedGeneration: receipt.GatewayGeneration - 1, DesiredGeneration: receipt.DesiredGatewayGeneration,
		Steps: steps, CreatedAt: at, UpdatedAt: at,
	}
	if err := operation.Validate(); err != nil {
		return model.State{}, err
	}
	candidate := before
	candidate.Generation, err = model.NextGeneration(before.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate.Operations = append(append([]model.Operation(nil), before.Operations...), operation)
	candidate.Nodes = append([]model.Node(nil), before.Nodes...)
	trust := *before.Nodes[0].Gateway
	trust.PendingRequestID = receipt.RequestID
	if receipt.GatewayGeneration > trust.LastKnownGatewayGeneration {
		trust.LastKnownGatewayGeneration = receipt.GatewayGeneration
	}
	candidate.Nodes[0].Gateway = &trust
	desiredNodeGeneration, err := model.NextGeneration(candidate.Generation)
	if err != nil || desiredNodeGeneration != receipt.DesiredNodeGeneration {
		return model.State{}, ErrInvalidMutationPlan
	}
	if err := model.ValidateTransition(before, candidate); err != nil {
		return model.State{}, err
	}
	return candidate, nil
}

func (writer *systemTransportDeferredWriter) retainedReceipt(
	state model.State,
	operation model.Operation,
	current model.TransportKind,
	target model.TransportKind,
) (DeferredReceipt, error) {
	intent, err := transport.ParseSwitchIntentTarget(operation.TargetID)
	registrationGeneration, registrationErr := model.NextGeneration(operation.ExpectedGeneration)
	desiredGatewayGeneration, desiredGatewayErr := model.NextGeneration(registrationGeneration)
	pendingNodeGeneration, pendingNodeErr := model.NextGeneration(intent.ExpectedNodeGeneration)
	desiredNodeGeneration, desiredNodeErr := model.NextGeneration(pendingNodeGeneration)
	if err != nil || registrationErr != nil || desiredGatewayErr != nil || pendingNodeErr != nil || desiredNodeErr != nil ||
		operation.Type != model.OperationTransportSwitch || operation.TargetKind != "transport" || operation.RequestID == "" ||
		registrationGeneration != state.Nodes[0].Gateway.LastKnownGatewayGeneration || operation.DesiredGeneration != desiredGatewayGeneration ||
		intent.NodeID != state.Nodes[0].ID || intent.Target != target || current != state.Nodes[0].ActiveTransport ||
		pendingNodeGeneration != state.Generation || intent.DesiredNodeGeneration != desiredNodeGeneration {
		return DeferredReceipt{}, model.ErrPendingRequest
	}
	receipt := transport.DeferredSwitchReceipt{
		OperationID: operation.ID, RequestID: operation.RequestID, NodeID: intent.NodeID,
		Current: current, Target: target,
		GatewayGeneration:        state.Nodes[0].Gateway.LastKnownGatewayGeneration,
		DesiredGatewayGeneration: operation.DesiredGeneration,
		ExpectedNodeGeneration:   intent.ExpectedNodeGeneration, DesiredNodeGeneration: intent.DesiredNodeGeneration,
	}
	if err := receipt.Validate(); err != nil {
		return DeferredReceipt{}, model.ErrPendingRequest
	}
	return publicTransportDeferredReceipt(receipt), nil
}

func publicTransportDeferredReceipt(receipt transport.DeferredSwitchReceipt) DeferredReceipt {
	result := output.NewResult("transport.switch", output.StatusPending, output.CategorySuccess, output.SafeObject{
		"changed": true, "current": string(receipt.Current), "candidate": string(receipt.Target), "generation": receipt.GatewayGeneration,
		"operation_id": receipt.OperationID,
	})
	result.ResourceIDs["node_id"] = receipt.NodeID
	result.ResourceIDs["operation_id"] = receipt.OperationID
	return DeferredReceipt{
		CommandID: "transport.switch", OperationID: receipt.OperationID,
		AuthoritativeGeneration: receipt.GatewayGeneration, Result: result,
	}
}

type systemUnavailableTransportProvider struct{ kind model.TransportKind }

func (provider systemUnavailableTransportProvider) Kind() model.TransportKind { return provider.kind }

func (systemUnavailableTransportProvider) Render(context.Context, transport.RenderRequest) (transport.Candidate, error) {
	return nil, ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) Prepare(context.Context, transport.Candidate) error {
	return ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) Validate(context.Context, transport.Candidate) error {
	return ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) StartTest(context.Context, transport.Candidate) (transport.TestResult, error) {
	return transport.TestResult{}, ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) Activate(context.Context, transport.Candidate) error {
	return ErrSystemTransportRuntimeUnavailable
}

func (provider systemUnavailableTransportProvider) Health(_ context.Context, request transport.HealthRequest) (transport.Health, error) {
	if err := request.Identity.Validate(); err != nil {
		return transport.Health{}, fmt.Errorf("transport health identity: %w", err)
	}
	return transport.Health{}, ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) Drain(context.Context, transport.DrainRequest) error {
	return ErrSystemTransportRuntimeUnavailable
}

func (systemUnavailableTransportProvider) Rollback(context.Context, transport.Candidate) error {
	return ErrSystemTransportRuntimeUnavailable
}

var _ transport.Provider = systemUnavailableTransportProvider{}
var _ AuthoritativeDeferredWriter = (*systemTransportDeferredWriter)(nil)
