package cli

import (
	"context"
	"fmt"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/operations"
)

type ExposeCreateMutationSaga interface {
	Plan(context.Context, ingress.ExposeCreateRequest) (operations.ExposeCreatePlan, error)
	Apply(context.Context, operations.ExposeCreatePlan) (operations.ExposeCreateResult, error)
	Defer(context.Context, operations.ExposeCreatePlan) (operations.ExposeCreateDeferredResult, error)
}

// ExposeCreateMutationWorkflow connects the sensitive domain plan to the
// common dry-run/immediate/deferred CLI boundary. The public MutationPlan holds
// only safe output; the path-bearing plan remains private to this one command
// invocation.
type ExposeCreateMutationWorkflow struct {
	saga    ExposeCreateMutationSaga
	request ingress.ExposeCreateRequest

	mu      sync.Mutex
	planned *operations.ExposeCreatePlan
}

func NewExposeCreateMutationWorkflow(
	saga ExposeCreateMutationSaga,
	request ingress.ExposeCreateRequest,
) (*ExposeCreateMutationWorkflow, error) {
	if saga == nil {
		return nil, fmt.Errorf("expose creation saga is required")
	}
	return &ExposeCreateMutationWorkflow{saga: saga, request: request}, nil
}

func (workflow *ExposeCreateMutationWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if ctx == nil || workflow == nil || workflow.saga == nil {
		return MutationPlan{}, fmt.Errorf("expose mutation workflow is incomplete")
	}
	domainPlan, err := workflow.saga.Plan(ctx, workflow.request)
	if err != nil {
		return MutationPlan{}, err
	}
	result, err := domainPlan.PreviewOutput()
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.mu.Lock()
	retained := domainPlan
	workflow.planned = &retained
	workflow.mu.Unlock()
	return MutationPlan{Impact: ImpactNone, Result: result}, nil
}

func (workflow *ExposeCreateMutationWorkflow) Apply(
	ctx context.Context,
	publicPlan MutationPlan,
	_ *InteractionInputs,
) (AppliedMutation, error) {
	domainPlan, err := workflow.retainedPlan(publicPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	created, err := workflow.saga.Apply(ctx, domainPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	result, err := created.Output()
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: result}, nil
}

func (workflow *ExposeCreateMutationWorkflow) RegisterPending(
	ctx context.Context,
	publicPlan MutationPlan,
) (DeferredReceipt, error) {
	domainPlan, err := workflow.retainedPlan(publicPlan)
	if err != nil {
		return DeferredReceipt{}, err
	}
	deferred, err := workflow.saga.Defer(ctx, domainPlan)
	if err != nil {
		return DeferredReceipt{}, err
	}
	result, err := deferred.Output()
	if err != nil {
		return DeferredReceipt{}, err
	}
	return DeferredReceipt{
		CommandID: "expose", OperationID: deferred.OperationID,
		AuthoritativeGeneration: deferred.GatewayStateGeneration, Result: result,
	}, nil
}

func (workflow *ExposeCreateMutationWorkflow) retainedPlan(publicPlan MutationPlan) (operations.ExposeCreatePlan, error) {
	if workflow == nil || workflow.saga == nil {
		return operations.ExposeCreatePlan{}, fmt.Errorf("expose mutation workflow is incomplete")
	}
	workflow.mu.Lock()
	defer workflow.mu.Unlock()
	if workflow.planned == nil || publicPlan.Result.ResourceIDs["expose_id"] != workflow.planned.Expose.ID ||
		publicPlan.Result.Command != "expose" || publicPlan.Impact != ImpactNone {
		return operations.ExposeCreatePlan{}, fmt.Errorf("%w: expose public plan does not match retained domain plan", ErrInvalidMutationPlan)
	}
	return *workflow.planned, nil
}

var _ MutationWorkflow = (*ExposeCreateMutationWorkflow)(nil)
var _ AuthoritativeDeferredWriter = (*ExposeCreateMutationWorkflow)(nil)
