package operations

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const ExposeRemovalDrain = time.Duration(ingress.DefaultIngressGracefulShutdownSeconds) * time.Second

var ErrExposeRemovalIncomplete = errors.New("expose removal is incomplete")

type ExposeRemovePlan struct {
	Expose                         model.Expose
	NodeHostID                     string
	ExpectedLocalStateGeneration   uint64
	ExpectedGatewayStateGeneration uint64
	GatewayID                      string
	PublicIPv4                     string
}

func (ExposeRemovePlan) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

func (plan ExposeRemovePlan) Validate() error {
	if err := plan.Expose.Validate(); err != nil {
		return fmt.Errorf("invalid expose removal target: %w", err)
	}
	if plan.Expose.State != model.ExposeReady && plan.Expose.State != model.ExposeDegraded && plan.Expose.State != model.ExposeDisabled {
		return fmt.Errorf("expose removal target must be published or disabled")
	}
	if model.ValidateResourceID(plan.NodeHostID) != nil || model.ValidateResourceID(plan.GatewayID) != nil ||
		plan.ExpectedLocalStateGeneration == 0 || plan.ExpectedGatewayStateGeneration == 0 {
		return fmt.Errorf("expose removal identity or generation is invalid")
	}
	address, err := netip.ParseAddr(plan.PublicIPv4)
	if err != nil || !address.Is4() || address.String() != plan.PublicIPv4 {
		return fmt.Errorf("expose removal gateway public IPv4 is invalid")
	}
	return nil
}

type ExposeGatewayRemovalSnapshot struct {
	GatewayID  string
	Generation uint64
	PublicIPv4 string
	NodeID     string
	Expose     model.Expose
}

func (ExposeGatewayRemovalSnapshot) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type ExposeGatewayUnpublication struct {
	ExposeID           string
	PreviousGeneration uint64
	Generation         uint64
	Drain              time.Duration
	AlreadyUnpublished bool
}

type ExposeRemovalDeferredRegistration struct {
	ExposeID    string
	OperationID string
	Generation  uint64
}

type ExposeGatewayRemovalCoordinator interface {
	PlanRemoval(context.Context, string, string) (ExposeGatewayRemovalSnapshot, error)
	Unpublish(context.Context, ExposeRemovePlan) (ExposeGatewayUnpublication, error)
	FinalizeRemoval(context.Context, ExposeGatewayUnpublication) (uint64, error)
	DeferRemoval(context.Context, ExposeRemovePlan) (ExposeRemovalDeferredRegistration, error)
}

type ExposeTunnelDeactivation struct {
	ExposeID  string
	Candidate tunnel.CandidateDescriptor
}

func (ExposeTunnelDeactivation) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type ExposeNodeTunnelRemovalRuntime interface {
	Deactivate(context.Context, model.State, model.Expose) (ExposeTunnelDeactivation, error)
}

type ExposeDrainWaiter interface {
	Wait(context.Context, time.Duration) error
}

type TimerExposeDrainWaiter struct{}

func (TimerExposeDrainWaiter) Wait(ctx context.Context, duration time.Duration) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if duration < 0 || duration > ExposeRemovalDrain {
		return fmt.Errorf("expose drain duration is outside the bounded contract")
	}
	if duration == 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type ExposeRemoveResult struct {
	ExposeID               string
	LocalStateGeneration   uint64
	GatewayStateGeneration uint64
	DrainSeconds           int
}

type ExposeRemoveDeferredResult struct {
	ExposeID               string
	OperationID            string
	GatewayStateGeneration uint64
}

type ExposeRemoveSaga struct {
	state   ExposeNodeStateStore
	gateway ExposeGatewayRemovalCoordinator
	tunnel  ExposeNodeTunnelRemovalRuntime
	waiter  ExposeDrainWaiter
}

func NewExposeRemoveSaga(
	state ExposeNodeStateStore,
	gateway ExposeGatewayRemovalCoordinator,
	tunnelRuntime ExposeNodeTunnelRemovalRuntime,
	waiter ExposeDrainWaiter,
) (*ExposeRemoveSaga, error) {
	if state == nil || gateway == nil || tunnelRuntime == nil || waiter == nil {
		return nil, fmt.Errorf("expose removal state, gateway, tunnel, and drain waiter are required")
	}
	return &ExposeRemoveSaga{state: state, gateway: gateway, tunnel: tunnelRuntime, waiter: waiter}, nil
}

func (saga *ExposeRemoveSaga) Plan(ctx context.Context, reference string) (ExposeRemovePlan, error) {
	if ctx == nil {
		return ExposeRemovePlan{}, fmt.Errorf("context is required")
	}
	local, node, err := saga.loadJoinedNode()
	if err != nil {
		return ExposeRemovePlan{}, err
	}
	target, err := resolveExpose(local.Exposes, node.ID, reference)
	if err != nil {
		return ExposeRemovePlan{}, err
	}
	snapshot, err := saga.gateway.PlanRemoval(ctx, node.ID, reference)
	if err != nil {
		return ExposeRemovePlan{}, errors.Join(ErrExposeGatewayUnavailable, err)
	}
	if model.ValidateResourceID(snapshot.GatewayID) != nil || snapshot.Generation < node.Gateway.LastKnownGatewayGeneration ||
		snapshot.PublicIPv4 != node.Gateway.PublicIPv4 || snapshot.NodeID != node.ID || !reflect.DeepEqual(snapshot.Expose, target) {
		return ExposeRemovePlan{}, ErrExposePlanStale
	}
	plan := ExposeRemovePlan{
		Expose: target, NodeHostID: local.Host.ID, ExpectedLocalStateGeneration: local.Generation,
		ExpectedGatewayStateGeneration: snapshot.Generation, GatewayID: snapshot.GatewayID, PublicIPv4: snapshot.PublicIPv4,
	}
	if err := plan.Validate(); err != nil {
		return ExposeRemovePlan{}, err
	}
	return plan, nil
}

func (saga *ExposeRemoveSaga) Apply(ctx context.Context, plan ExposeRemovePlan) (ExposeRemoveResult, error) {
	if ctx == nil || saga == nil || saga.state == nil || saga.gateway == nil || saga.tunnel == nil || saga.waiter == nil {
		return ExposeRemoveResult{}, fmt.Errorf("expose removal saga is incomplete")
	}
	if err := plan.Validate(); err != nil {
		return ExposeRemoveResult{}, err
	}
	local, node, err := saga.loadJoinedNode()
	if err != nil {
		return ExposeRemoveResult{}, err
	}
	target, err := resolveExpose(local.Exposes, node.ID, plan.Expose.ID)
	if err != nil || local.Generation != plan.ExpectedLocalStateGeneration || local.Host.ID != plan.NodeHostID ||
		!reflect.DeepEqual(target, plan.Expose) {
		return ExposeRemoveResult{}, ErrExposePlanStale
	}
	unpublication, err := saga.gateway.Unpublish(ctx, plan)
	if err != nil {
		if exposeCommitPossible(err) {
			return ExposeRemoveResult{}, &ExposeRemovalIncompleteError{Stage: "gateway_unpublish", Cause: err}
		}
		return ExposeRemoveResult{}, fmt.Errorf("unpublish gateway expose: %w", err)
	}
	if err := validateExposeUnpublication(unpublication, plan); err != nil {
		return ExposeRemoveResult{}, &ExposeRemovalIncompleteError{Stage: "gateway_unpublication_receipt", Cause: err}
	}
	disabled := local
	if plan.Expose.State != model.ExposeDisabled {
		disabled, err = disableNodeExpose(local, plan.Expose.ID, unpublication.Generation)
		if err != nil {
			return ExposeRemoveResult{}, &ExposeRemovalIncompleteError{Stage: "node_disable_plan", Cause: err}
		}
		if err := saga.state.Save(local.Generation, disabled); err != nil {
			return ExposeRemoveResult{}, &ExposeRemovalIncompleteError{Stage: "node_disable_state", Cause: err}
		}
	}
	if err := saga.waiter.Wait(ctx, unpublication.Drain); err != nil {
		return ExposeRemoveResult{}, &ExposeRemovalIncompleteError{Stage: "bounded_drain", Cause: err}
	}
	deactivation, err := saga.tunnel.Deactivate(ctx, disabled, plan.Expose)
	if err != nil {
		return ExposeRemoveResult{}, &ExposeRemovalIncompleteError{Stage: "node_tunnel_remove", Cause: err}
	}
	if deactivation.ExposeID != plan.Expose.ID || deactivation.Candidate.Generation != disabled.Generation {
		return ExposeRemoveResult{}, &ExposeRemovalIncompleteError{Stage: "node_tunnel_receipt", Cause: errors.New("invalid tunnel removal receipt")}
	}
	gatewayGeneration, err := saga.gateway.FinalizeRemoval(ctx, unpublication)
	if err != nil {
		return ExposeRemoveResult{}, &ExposeRemovalIncompleteError{Stage: "gateway_port_release", Cause: err}
	}
	wantGatewayGeneration, generationErr := model.NextGeneration(unpublication.Generation)
	if generationErr != nil || gatewayGeneration != wantGatewayGeneration {
		return ExposeRemoveResult{}, &ExposeRemovalIncompleteError{Stage: "gateway_release_receipt", Cause: ErrExposePlanStale}
	}
	final, err := deleteNodeExpose(disabled, plan.Expose.ID, gatewayGeneration)
	if err != nil {
		return ExposeRemoveResult{}, &ExposeRemovalIncompleteError{Stage: "node_delete_plan", Cause: err}
	}
	if err := saga.state.Save(disabled.Generation, final); err != nil {
		return ExposeRemoveResult{}, &ExposeRemovalIncompleteError{Stage: "node_delete_state", Cause: err}
	}
	return ExposeRemoveResult{
		ExposeID: plan.Expose.ID, LocalStateGeneration: final.Generation,
		GatewayStateGeneration: gatewayGeneration, DrainSeconds: int(unpublication.Drain / time.Second),
	}, nil
}

func (saga *ExposeRemoveSaga) Defer(ctx context.Context, plan ExposeRemovePlan) (ExposeRemoveDeferredResult, error) {
	if ctx == nil || saga == nil || saga.gateway == nil {
		return ExposeRemoveDeferredResult{}, fmt.Errorf("expose removal saga is incomplete")
	}
	if err := plan.Validate(); err != nil {
		return ExposeRemoveDeferredResult{}, err
	}
	registration, err := saga.gateway.DeferRemoval(ctx, plan)
	if err != nil {
		return ExposeRemoveDeferredResult{}, errors.Join(ErrExposeGatewayUnavailable, err)
	}
	want, generationErr := model.NextGeneration(plan.ExpectedGatewayStateGeneration)
	if generationErr != nil || registration.ExposeID != plan.Expose.ID || registration.Generation != want ||
		model.ValidateResourceID(registration.OperationID) != nil {
		return ExposeRemoveDeferredResult{}, fmt.Errorf("invalid deferred expose removal receipt")
	}
	return ExposeRemoveDeferredResult{
		ExposeID: registration.ExposeID, OperationID: registration.OperationID,
		GatewayStateGeneration: registration.Generation,
	}, nil
}

func (saga *ExposeRemoveSaga) loadJoinedNode() (model.State, model.Node, error) {
	if saga == nil || saga.state == nil || saga.gateway == nil {
		return model.State{}, model.Node{}, fmt.Errorf("expose removal saga is incomplete")
	}
	state, err := saga.state.Load()
	if err != nil {
		return model.State{}, model.Node{}, fmt.Errorf("load node expose state: %w", err)
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleNode || len(state.Nodes) != 1 ||
		state.Nodes[0].Lifecycle != model.LifecycleActive || state.Nodes[0].Gateway == nil {
		return model.State{}, model.Node{}, fmt.Errorf("expose removal requires one joined active node")
	}
	return state, state.Nodes[0], nil
}

func validateExposeUnpublication(receipt ExposeGatewayUnpublication, plan ExposeRemovePlan) error {
	if receipt.ExposeID != plan.Expose.ID || receipt.PreviousGeneration != plan.ExpectedGatewayStateGeneration {
		return fmt.Errorf("unpublication identity or prior generation is invalid")
	}
	if plan.Expose.State == model.ExposeDisabled {
		if !receipt.AlreadyUnpublished || receipt.Generation != receipt.PreviousGeneration || receipt.Drain != 0 {
			return fmt.Errorf("disabled expose unpublication is invalid")
		}
		return nil
	}
	want, err := model.NextGeneration(receipt.PreviousGeneration)
	if err != nil || receipt.AlreadyUnpublished || receipt.Generation != want || receipt.Drain != ExposeRemovalDrain {
		return fmt.Errorf("published expose unpublication is invalid")
	}
	return nil
}

func disableNodeExpose(before model.State, exposeID string, gatewayGeneration uint64) (model.State, error) {
	candidate, err := cloneExposeState(before)
	if err != nil {
		return model.State{}, err
	}
	candidate.Generation, err = model.NextGeneration(before.Generation)
	if err != nil {
		return model.State{}, err
	}
	found := false
	for index := range candidate.Exposes {
		if candidate.Exposes[index].ID != exposeID {
			continue
		}
		candidate.Exposes[index].State = model.ExposeDisabled
		candidate.Exposes[index].Generation, err = model.NextGeneration(candidate.Exposes[index].Generation)
		if err != nil {
			return model.State{}, err
		}
		found = true
	}
	if !found {
		return model.State{}, ErrExposePlanStale
	}
	candidate.Nodes[0].Gateway.LastKnownGatewayGeneration = gatewayGeneration
	if err := model.ValidateTransition(before, candidate); err != nil {
		return model.State{}, fmt.Errorf("build disabled node expose state: %w", err)
	}
	return candidate, nil
}

func deleteNodeExpose(before model.State, exposeID string, gatewayGeneration uint64) (model.State, error) {
	candidate, err := cloneExposeState(before)
	if err != nil {
		return model.State{}, err
	}
	candidate.Generation, err = model.NextGeneration(before.Generation)
	if err != nil {
		return model.State{}, err
	}
	found := false
	filtered := candidate.Exposes[:0]
	for _, expose := range candidate.Exposes {
		if expose.ID == exposeID {
			if expose.State != model.ExposeDisabled {
				return model.State{}, ErrExposePlanStale
			}
			found = true
			continue
		}
		filtered = append(filtered, expose)
	}
	if !found {
		return model.State{}, ErrExposePlanStale
	}
	candidate.Exposes = filtered
	candidate.Nodes[0].Gateway.LastKnownGatewayGeneration = gatewayGeneration
	if err := model.ValidateTransition(before, candidate); err != nil {
		return model.State{}, fmt.Errorf("build deleted node expose state: %w", err)
	}
	return candidate, nil
}

func (plan ExposeRemovePlan) PreviewOutput() (output.Result, error) {
	if err := plan.Validate(); err != nil {
		return output.Result{}, err
	}
	result := output.NewResult("expose.remove", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": false, "generation": plan.ExpectedGatewayStateGeneration,
		"impact": "availability", "drain_seconds": int(ExposeRemovalDrain / time.Second),
	})
	result.ResourceIDs["expose_id"] = plan.Expose.ID
	addWebhookRemovalAction(&result, plan.Expose.ID, true)
	return result, result.Validate()
}

func (result ExposeRemoveResult) Output() (output.Result, error) {
	if model.ValidateResourceID(result.ExposeID) != nil || result.LocalStateGeneration == 0 || result.GatewayStateGeneration == 0 ||
		result.DrainSeconds < 0 || result.DrainSeconds > int(ExposeRemovalDrain/time.Second) {
		return output.Result{}, fmt.Errorf("invalid expose removal result")
	}
	commandResult := output.NewResult("expose.remove", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": result.GatewayStateGeneration, "drain_seconds": result.DrainSeconds,
	})
	commandResult.ResourceIDs["expose_id"] = result.ExposeID
	addWebhookRemovalAction(&commandResult, result.ExposeID, false)
	return commandResult, commandResult.Validate()
}

func (result ExposeRemoveDeferredResult) Output() (output.Result, error) {
	if model.ValidateResourceID(result.ExposeID) != nil || model.ValidateResourceID(result.OperationID) != nil || result.GatewayStateGeneration == 0 {
		return output.Result{}, fmt.Errorf("invalid deferred expose removal result")
	}
	commandResult := output.NewResult("expose.remove", output.StatusPending, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": result.GatewayStateGeneration, "operation_id": result.OperationID,
	})
	commandResult.ResourceIDs["expose_id"] = result.ExposeID
	commandResult.ResourceIDs["operation_id"] = result.OperationID
	addWebhookRemovalAction(&commandResult, result.ExposeID, true)
	return commandResult, commandResult.Validate()
}

func addWebhookRemovalAction(result *output.Result, exposeID string, afterRemoval bool) {
	message := "Remove the external webhook registration that targeted this expose."
	if afterRemoval {
		message = "After the expose removal is applied, remove the external webhook registration that targeted it."
	}
	result.RequiresAction = append(result.RequiresAction, output.Action{
		Code: "remove_external_webhook", Message: message,
		ResourceIDs: map[string]string{"expose_id": exposeID},
	})
}

type ExposeRemovalIncompleteError struct {
	Stage string
	Cause error
}

func (failure *ExposeRemovalIncompleteError) Error() string {
	if failure == nil {
		return ErrExposeRemovalIncomplete.Error()
	}
	return fmt.Sprintf("%s: %s", ErrExposeRemovalIncomplete, failure.Stage)
}

func (failure *ExposeRemovalIncompleteError) Unwrap() error {
	if failure == nil || failure.Cause == nil {
		return ErrExposeRemovalIncomplete
	}
	return errors.Join(ErrExposeRemovalIncomplete, failure.Cause)
}
