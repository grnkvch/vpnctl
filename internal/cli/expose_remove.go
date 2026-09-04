package cli

import (
	"context"
	"fmt"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/operations"
)

type ExposeRemoveMutationSaga interface {
	Plan(context.Context, string) (operations.ExposeRemovePlan, error)
	Apply(context.Context, operations.ExposeRemovePlan) (operations.ExposeRemoveResult, error)
	Defer(context.Context, operations.ExposeRemovePlan) (operations.ExposeRemoveDeferredResult, error)
}

// ExposeRemoveMutationWorkflow keeps the path-bearing domain plan private and
// delegates confirmation/dry-run/defer behavior to the common mutation runner.
type ExposeRemoveMutationWorkflow struct {
	saga      ExposeRemoveMutationSaga
	reference string

	mu      sync.Mutex
	planned *operations.ExposeRemovePlan
}

func NewExposeRemoveMutationWorkflow(
	saga ExposeRemoveMutationSaga,
	reference string,
) (*ExposeRemoveMutationWorkflow, error) {
	if saga == nil || reference == "" {
		return nil, fmt.Errorf("expose removal saga and reference are required")
	}
	return &ExposeRemoveMutationWorkflow{saga: saga, reference: reference}, nil
}

func (workflow *ExposeRemoveMutationWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if ctx == nil || workflow == nil || workflow.saga == nil {
		return MutationPlan{}, fmt.Errorf("expose removal mutation workflow is incomplete")
	}
	domainPlan, err := workflow.saga.Plan(ctx, workflow.reference)
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
	return MutationPlan{Impact: ImpactAvailability, Result: result}, nil
}

func (workflow *ExposeRemoveMutationWorkflow) Apply(
	ctx context.Context,
	publicPlan MutationPlan,
	_ *InteractionInputs,
) (AppliedMutation, error) {
	domainPlan, err := workflow.retainedPlan(publicPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	removed, err := workflow.saga.Apply(ctx, domainPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	result, err := removed.Output()
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: result}, nil
}

func (workflow *ExposeRemoveMutationWorkflow) RegisterPending(
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
		CommandID: "expose.remove", OperationID: deferred.OperationID,
		AuthoritativeGeneration: deferred.GatewayStateGeneration, Result: result,
	}, nil
}

func (workflow *ExposeRemoveMutationWorkflow) retainedPlan(publicPlan MutationPlan) (operations.ExposeRemovePlan, error) {
	if workflow == nil || workflow.saga == nil {
		return operations.ExposeRemovePlan{}, fmt.Errorf("expose removal mutation workflow is incomplete")
	}
	workflow.mu.Lock()
	defer workflow.mu.Unlock()
	if workflow.planned == nil || publicPlan.Result.Command != "expose.remove" || publicPlan.Impact != ImpactAvailability ||
		publicPlan.Result.ResourceIDs["expose_id"] != workflow.planned.Expose.ID {
		return operations.ExposeRemovePlan{}, fmt.Errorf("%w: expose removal public plan does not match retained domain plan", ErrInvalidMutationPlan)
	}
	return *workflow.planned, nil
}

var _ MutationWorkflow = (*ExposeRemoveMutationWorkflow)(nil)
var _ AuthoritativeDeferredWriter = (*ExposeRemoveMutationWorkflow)(nil)
