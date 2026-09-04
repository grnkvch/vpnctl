package operations

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

type GatewayExposeRemovalDeferredWriter interface {
	RegisterRemoval(context.Context, ExposeRemovePlan) (ExposeRemovalDeferredRegistration, error)
}

// GatewayExposeRemovalService is the authoritative gateway transaction. It
// removes public reachability before acknowledging a drain, and releases the
// allocation only after the node reports that its complete FRP topology no
// longer contains the mapping.
type GatewayExposeRemovalService struct {
	state     GatewayExposeStateStore
	publisher GatewayExposeIngressPublisher
	deferred  GatewayExposeRemovalDeferredWriter
}

func NewGatewayExposeRemovalService(
	state GatewayExposeStateStore,
	publisher GatewayExposeIngressPublisher,
	deferred GatewayExposeRemovalDeferredWriter,
) (*GatewayExposeRemovalService, error) {
	if state == nil || publisher == nil || deferred == nil {
		return nil, fmt.Errorf("gateway expose removal dependencies are incomplete")
	}
	return &GatewayExposeRemovalService{state: state, publisher: publisher, deferred: deferred}, nil
}

func (service *GatewayExposeRemovalService) PlanRemoval(
	ctx context.Context,
	nodeID string,
	reference string,
) (ExposeGatewayRemovalSnapshot, error) {
	if ctx == nil || service == nil || service.state == nil {
		return ExposeGatewayRemovalSnapshot{}, fmt.Errorf("gateway expose removal service is incomplete")
	}
	state, _, err := loadGatewayExposeNode(service.state, nodeID)
	if err != nil {
		return ExposeGatewayRemovalSnapshot{}, err
	}
	expose, err := resolveExpose(state.Exposes, nodeID, reference)
	if err != nil {
		return ExposeGatewayRemovalSnapshot{}, err
	}
	return ExposeGatewayRemovalSnapshot{
		GatewayID: state.Host.ID, Generation: state.Generation, PublicIPv4: state.Host.PublicIPv4,
		NodeID: nodeID, Expose: expose,
	}, nil
}

func (service *GatewayExposeRemovalService) Unpublish(
	ctx context.Context,
	plan ExposeRemovePlan,
) (ExposeGatewayUnpublication, error) {
	if ctx == nil || service == nil || service.state == nil || service.publisher == nil {
		return ExposeGatewayUnpublication{}, fmt.Errorf("gateway expose removal service is incomplete")
	}
	if err := plan.Validate(); err != nil {
		return ExposeGatewayUnpublication{}, err
	}
	state, _, err := loadGatewayExposeNode(service.state, plan.Expose.NodeID)
	if err != nil {
		return ExposeGatewayUnpublication{}, err
	}
	if state.Host.ID != plan.GatewayID || state.Host.PublicIPv4 != plan.PublicIPv4 || state.Generation != plan.ExpectedGatewayStateGeneration {
		return ExposeGatewayUnpublication{}, ErrExposePlanStale
	}
	target, err := resolveExpose(state.Exposes, plan.Expose.NodeID, plan.Expose.ID)
	if err != nil || !reflect.DeepEqual(target, plan.Expose) {
		return ExposeGatewayUnpublication{}, ErrExposePlanStale
	}
	if target.State == model.ExposeDisabled {
		return ExposeGatewayUnpublication{
			ExposeID: target.ID, PreviousGeneration: state.Generation, Generation: state.Generation,
			AlreadyUnpublished: true,
		}, nil
	}
	candidate, err := cloneExposeState(state)
	if err != nil {
		return ExposeGatewayUnpublication{}, err
	}
	candidate.Generation, err = model.NextGeneration(state.Generation)
	if err != nil {
		return ExposeGatewayUnpublication{}, err
	}
	for index := range candidate.Exposes {
		if candidate.Exposes[index].ID != target.ID {
			continue
		}
		candidate.Exposes[index].State = model.ExposeDisabled
		candidate.Exposes[index].Generation, err = model.NextGeneration(candidate.Exposes[index].Generation)
		if err != nil {
			return ExposeGatewayUnpublication{}, err
		}
	}
	if err := model.ValidateTransition(state, candidate); err != nil {
		return ExposeGatewayUnpublication{}, fmt.Errorf("build gateway expose unpublication: %w", err)
	}
	activation, err := service.publisher.Activate(ctx, state, candidate)
	if err != nil {
		return ExposeGatewayUnpublication{}, err
	}
	if activation.ExposeID != target.ID || activation.StateGeneration != candidate.Generation {
		return ExposeGatewayUnpublication{}, &gatewayExposeCommitError{
			cause: errors.New("ingress unpublication receipt is invalid"), possible: true,
		}
	}
	if err := service.state.Save(state.Generation, candidate); err != nil {
		rollbackContext, cancel := context.WithTimeout(context.Background(), exposeCompensationTimeout)
		defer cancel()
		if rollbackErr := service.publisher.Rollback(rollbackContext, activation); rollbackErr != nil {
			return ExposeGatewayUnpublication{}, &gatewayExposeCommitError{cause: errors.Join(err, rollbackErr), possible: true}
		}
		return ExposeGatewayUnpublication{}, err
	}
	return ExposeGatewayUnpublication{
		ExposeID: target.ID, PreviousGeneration: state.Generation, Generation: candidate.Generation,
		Drain: ExposeRemovalDrain,
	}, nil
}

func (service *GatewayExposeRemovalService) FinalizeRemoval(
	ctx context.Context,
	unpublication ExposeGatewayUnpublication,
) (uint64, error) {
	if ctx == nil || service == nil || service.state == nil {
		return 0, fmt.Errorf("gateway expose removal service is incomplete")
	}
	if model.ValidateResourceID(unpublication.ExposeID) != nil || unpublication.Generation == 0 ||
		unpublication.PreviousGeneration == 0 || unpublication.Drain < 0 || unpublication.Drain > ExposeRemovalDrain {
		return 0, fmt.Errorf("gateway expose unpublication is invalid")
	}
	state, err := service.state.Load()
	if err != nil {
		return 0, err
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway || state.Generation != unpublication.Generation {
		return 0, ErrExposePlanStale
	}
	target, err := resolveExpose(state.Exposes, exposeOwner(state.Exposes, unpublication.ExposeID), unpublication.ExposeID)
	if err != nil || target.State != model.ExposeDisabled {
		return 0, ErrExposePlanStale
	}
	allocator, remaps, err := tunnel.DefaultLoopbackAllocatorFromExposes(state.Exposes, nil)
	if err != nil {
		return 0, fmt.Errorf("restore gateway expose allocation: %w", err)
	}
	if len(remaps) != 0 {
		return 0, fmt.Errorf("restore gateway expose allocation: persisted ports require repair")
	}
	port, assigned := allocator.Lookup(target.ID)
	if !assigned || port != target.TunnelPort {
		return 0, ErrExposePlanStale
	}
	released, err := allocator.Release(target.ID)
	if err != nil || !released {
		return 0, fmt.Errorf("release gateway expose allocation: %w", err)
	}
	for _, expose := range state.Exposes {
		if expose.ID == target.ID {
			continue
		}
		if retainedPort, ok := allocator.Lookup(expose.ID); !ok || retainedPort != expose.TunnelPort {
			return 0, fmt.Errorf("gateway expose allocation release affected another mapping")
		}
	}
	candidate, err := cloneExposeState(state)
	if err != nil {
		return 0, err
	}
	candidate.Generation, err = model.NextGeneration(state.Generation)
	if err != nil {
		return 0, err
	}
	filtered := candidate.Exposes[:0]
	for _, expose := range candidate.Exposes {
		if expose.ID != target.ID {
			filtered = append(filtered, expose)
		}
	}
	candidate.Exposes = filtered
	if err := model.ValidateTransition(state, candidate); err != nil {
		return 0, fmt.Errorf("build gateway expose release: %w", err)
	}
	if err := service.state.Save(state.Generation, candidate); err != nil {
		return 0, err
	}
	return candidate.Generation, nil
}

func (service *GatewayExposeRemovalService) DeferRemoval(
	ctx context.Context,
	plan ExposeRemovePlan,
) (ExposeRemovalDeferredRegistration, error) {
	if ctx == nil || service == nil || service.state == nil || service.deferred == nil {
		return ExposeRemovalDeferredRegistration{}, fmt.Errorf("gateway expose removal service is incomplete")
	}
	if err := plan.Validate(); err != nil {
		return ExposeRemovalDeferredRegistration{}, err
	}
	state, _, err := loadGatewayExposeNode(service.state, plan.Expose.NodeID)
	if err != nil {
		return ExposeRemovalDeferredRegistration{}, err
	}
	target, err := resolveExpose(state.Exposes, plan.Expose.NodeID, plan.Expose.ID)
	if err != nil || state.Host.ID != plan.GatewayID || state.Host.PublicIPv4 != plan.PublicIPv4 || state.Generation != plan.ExpectedGatewayStateGeneration ||
		!reflect.DeepEqual(target, plan.Expose) {
		return ExposeRemovalDeferredRegistration{}, ErrExposePlanStale
	}
	registration, err := service.deferred.RegisterRemoval(ctx, plan)
	if err != nil {
		return ExposeRemovalDeferredRegistration{}, err
	}
	want, generationErr := model.NextGeneration(state.Generation)
	if generationErr != nil || registration.ExposeID != target.ID || registration.Generation != want ||
		model.ValidateResourceID(registration.OperationID) != nil {
		return ExposeRemovalDeferredRegistration{}, &gatewayExposeCommitError{
			cause: errors.New("deferred expose removal receipt is invalid"), possible: true,
		}
	}
	return registration, nil
}

func loadGatewayExposeNode(stateStore GatewayExposeStateStore, nodeID string) (model.State, model.Node, error) {
	if model.ValidateResourceID(nodeID) != nil {
		return model.State{}, model.Node{}, ErrExposePlanStale
	}
	state, err := stateStore.Load()
	if err != nil {
		return model.State{}, model.Node{}, err
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return model.State{}, model.Node{}, fmt.Errorf("gateway expose authoritative state is invalid")
	}
	for _, node := range state.Nodes {
		if node.ID == nodeID && node.Lifecycle == model.LifecycleActive {
			return state, node, nil
		}
	}
	return model.State{}, model.Node{}, ErrExposePlanStale
}

func exposeOwner(exposes []model.Expose, exposeID string) string {
	for _, expose := range exposes {
		if expose.ID == exposeID {
			return expose.NodeID
		}
	}
	return ""
}

var _ ExposeGatewayRemovalCoordinator = (*GatewayExposeRemovalService)(nil)
