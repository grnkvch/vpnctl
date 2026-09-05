package cli

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/routing"
)

type clientMutationAPI interface {
	PlanAdd(routing.ClientAddRequest) (routing.ClientAddPlan, error)
	CommitAdd(context.Context, routing.ClientAddPlan) (routing.ClientAddResult, error)
	PlanRotate(string) (routing.ClientLifecyclePlan, error)
	CommitRotate(context.Context, routing.ClientLifecyclePlan) (routing.ClientLifecycleResult, error)
	PlanRevoke(string) (routing.ClientLifecyclePlan, error)
	CommitRevoke(routing.ClientLifecyclePlan) (routing.ClientLifecycleResult, error)
	PlanDelete(string) (routing.ClientLifecyclePlan, error)
	CommitDelete(routing.ClientLifecyclePlan) (routing.ClientLifecycleResult, error)
	PlanExport(routing.ClientExportRequest) (routing.ClientExportPlan, error)
	CommitExport(routing.ClientExportPlan) (routing.ClientExportResult, error)
}

type clientAddMutationWorkflow struct {
	service clientMutationAPI
	request routing.ClientAddRequest
	mu      sync.Mutex
	planned *routing.ClientAddPlan
}

func (workflow *clientAddMutationWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	plan, err := workflow.service.PlanAdd(workflow.request)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.mu.Lock()
	retained := plan
	workflow.planned = &retained
	workflow.mu.Unlock()
	return MutationPlan{Impact: ImpactNone, Result: clientAddPlanOutput(plan)}, nil
}

func (workflow *clientAddMutationWorkflow) Apply(ctx context.Context, public MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	plan, err := workflow.retainedPlan(public)
	if err != nil {
		return AppliedMutation{}, err
	}
	result, err := workflow.service.CommitAdd(ctx, plan)
	if err != nil {
		if errors.Is(err, errClientRuntimePending) && result.Client.ID != "" {
			public := clientAddResultOutput(result)
			markClientRuntimePending(&public, result.Client.ID)
			return AppliedMutation{Result: public}, nil
		}
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: clientAddResultOutput(result)}, nil
}

func (workflow *clientAddMutationWorkflow) retainedPlan(public MutationPlan) (routing.ClientAddPlan, error) {
	workflow.mu.Lock()
	defer workflow.mu.Unlock()
	if workflow.planned == nil || public.Impact != ImpactNone || public.Result.Command != "client.add" ||
		public.Result.ResourceIDs["client_id"] != workflow.planned.ClientID {
		return routing.ClientAddPlan{}, fmt.Errorf("%w: client add plan does not match retained plan", ErrInvalidMutationPlan)
	}
	return *workflow.planned, nil
}

func clientAddPlanOutput(plan routing.ClientAddPlan) output.Result {
	result := output.NewResult("client.add", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": plan.NextStateGeneration,
	})
	result.ResourceIDs["client_id"] = plan.ClientID
	return result
}

func clientAddResultOutput(result routing.ClientAddResult) output.Result {
	public := output.NewResult("client.add", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": result.Changed, "generation": result.StateGeneration,
	})
	public.ResourceIDs["client_id"] = result.Client.ID
	return public
}

type clientLifecycleMutationWorkflow struct {
	service   clientMutationAPI
	commandID string
	reference string
	mu        sync.Mutex
	planned   *routing.ClientLifecyclePlan
}

func (workflow *clientLifecycleMutationWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	var (
		plan routing.ClientLifecyclePlan
		err  error
	)
	switch workflow.commandID {
	case "client.rotate":
		plan, err = workflow.service.PlanRotate(workflow.reference)
	case "client.revoke":
		plan, err = workflow.service.PlanRevoke(workflow.reference)
	case "client.delete":
		plan, err = workflow.service.PlanDelete(workflow.reference)
	default:
		err = fmt.Errorf("unsupported client lifecycle command")
	}
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.mu.Lock()
	retained := plan
	workflow.planned = &retained
	workflow.mu.Unlock()
	impact := ImpactAvailability
	if workflow.commandID == "client.delete" {
		impact = ImpactDestructive
	}
	return MutationPlan{Impact: impact, Result: plan.OutputResult()}, nil
}

func (workflow *clientLifecycleMutationWorkflow) Apply(ctx context.Context, public MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	plan, err := workflow.retainedPlan(public)
	if err != nil {
		return AppliedMutation{}, err
	}
	var result routing.ClientLifecycleResult
	switch workflow.commandID {
	case "client.rotate":
		result, err = workflow.service.CommitRotate(ctx, plan)
	case "client.revoke":
		result, err = workflow.service.CommitRevoke(plan)
	case "client.delete":
		result, err = workflow.service.CommitDelete(plan)
	}
	if err != nil {
		if (errors.Is(err, routing.ErrClientCleanupPending) || errors.Is(err, errClientRuntimePending)) && result.ClientID != "" {
			public := result.OutputResult()
			if errors.Is(err, errClientRuntimePending) {
				markClientRuntimePending(&public, result.ClientID)
			}
			return AppliedMutation{Result: public}, nil
		}
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: result.OutputResult()}, nil
}

func markClientRuntimePending(result *output.Result, clientID string) {
	result.Status = output.StatusPending
	result.RequiresAction = append(result.RequiresAction, output.Action{
		Code: "repair_client_runtime", Message: "Run repair to publish the current client credentials to gateway listeners.",
		ResourceIDs: map[string]string{"client_id": clientID},
	})
}

func (workflow *clientLifecycleMutationWorkflow) retainedPlan(public MutationPlan) (routing.ClientLifecyclePlan, error) {
	workflow.mu.Lock()
	defer workflow.mu.Unlock()
	if workflow.planned == nil || public.Result.Command != workflow.commandID ||
		public.Result.ResourceIDs["client_id"] != workflow.planned.ClientID {
		return routing.ClientLifecyclePlan{}, fmt.Errorf("%w: client lifecycle plan does not match retained plan", ErrInvalidMutationPlan)
	}
	wantImpact := ImpactAvailability
	if workflow.commandID == "client.delete" {
		wantImpact = ImpactDestructive
	}
	if public.Impact != wantImpact {
		return routing.ClientLifecyclePlan{}, fmt.Errorf("%w: client lifecycle impact changed", ErrInvalidMutationPlan)
	}
	return *workflow.planned, nil
}

type clientExportMutationWorkflow struct {
	service clientMutationAPI
	request routing.ClientExportRequest
	mu      sync.Mutex
	planned *routing.ClientExportPlan
}

func (workflow *clientExportMutationWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	plan, err := workflow.service.PlanExport(workflow.request)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.mu.Lock()
	retained := plan
	workflow.planned = &retained
	workflow.mu.Unlock()
	return MutationPlan{Impact: ImpactNone, Result: plan.OutputResult()}, nil
}

func (workflow *clientExportMutationWorkflow) Apply(_ context.Context, public MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	workflow.mu.Lock()
	defer workflow.mu.Unlock()
	if workflow.planned == nil || public.Impact != ImpactNone || public.Result.Command != "client.export" ||
		public.Result.ResourceIDs["client_id"] != workflow.planned.ClientID {
		return AppliedMutation{}, fmt.Errorf("%w: client export plan does not match retained plan", ErrInvalidMutationPlan)
	}
	result, err := workflow.service.CommitExport(*workflow.planned)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: result.OutputResult()}, nil
}

var _ MutationWorkflow = (*clientAddMutationWorkflow)(nil)
var _ MutationWorkflow = (*clientLifecycleMutationWorkflow)(nil)
var _ MutationWorkflow = (*clientExportMutationWorkflow)(nil)
