package cli

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

type ConvergenceRepairOperator interface {
	Plan(context.Context) (operations.RepairPlan, error)
	Repair(context.Context, operations.RepairPlan) (operations.RepairResult, error)
}

// ConvergenceRepairWorkflow retains the exact owned-drift plan shown before
// consent. The operator independently re-plans immediately before execution,
// so consent never applies to a stale or broadened repair set.
type ConvergenceRepairWorkflow struct {
	operator ConvergenceRepairOperator
	role     HostRole

	mu      sync.Mutex
	planned *operations.RepairPlan
}

func NewConvergenceRepairWorkflow(role HostRole, operator ConvergenceRepairOperator) (*ConvergenceRepairWorkflow, error) {
	if operator == nil {
		return nil, fmt.Errorf("convergence repair operator is required")
	}
	return &ConvergenceRepairWorkflow{operator: operator, role: role}, nil
}

func (workflow *ConvergenceRepairWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if ctx == nil || workflow == nil || workflow.operator == nil {
		return MutationPlan{}, fmt.Errorf("convergence repair workflow is incomplete")
	}
	plan, err := workflow.operator.Plan(ctx)
	if err != nil {
		return MutationPlan{}, err
	}
	expectedRole, ok := convergenceApplyModelRole(workflow.role)
	if !ok || plan.Role != expectedRole {
		return MutationPlan{}, fmt.Errorf("%w: repair plan role %q differs from command host role %q", ErrInvalidMutationPlan, plan.Role, workflow.role)
	}
	result, err := convergenceRepairPlanOutput(plan)
	if err != nil {
		return MutationPlan{}, err
	}
	impact, err := convergenceApplyImpact(plan.Impact)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.mu.Lock()
	retained := cloneConvergenceRepairPlan(plan)
	workflow.planned = &retained
	workflow.mu.Unlock()
	return MutationPlan{Impact: impact, Result: result}, nil
}

func (workflow *ConvergenceRepairWorkflow) Apply(
	ctx context.Context,
	publicPlan MutationPlan,
	_ *InteractionInputs,
) (AppliedMutation, error) {
	domainPlan, err := workflow.retainedPlan(publicPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	result, err := workflow.operator.Repair(ctx, domainPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	publicResult, err := convergenceRepairResultOutput(result)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: publicResult}, nil
}

func (workflow *ConvergenceRepairWorkflow) retainedPlan(publicPlan MutationPlan) (operations.RepairPlan, error) {
	if workflow == nil || workflow.operator == nil {
		return operations.RepairPlan{}, fmt.Errorf("convergence repair workflow is incomplete")
	}
	workflow.mu.Lock()
	defer workflow.mu.Unlock()
	if workflow.planned == nil {
		return operations.RepairPlan{}, fmt.Errorf("%w: repair was not planned", ErrInvalidMutationPlan)
	}
	wantImpact, err := convergenceApplyImpact(workflow.planned.Impact)
	if err != nil {
		return operations.RepairPlan{}, err
	}
	wantResult, err := convergenceRepairPlanOutput(*workflow.planned)
	if err != nil {
		return operations.RepairPlan{}, err
	}
	if publicPlan.Impact != wantImpact || !reflect.DeepEqual(publicPlan.Result, wantResult) {
		return operations.RepairPlan{}, fmt.Errorf("%w: public repair plan differs from retained domain plan", ErrInvalidMutationPlan)
	}
	return cloneConvergenceRepairPlan(*workflow.planned), nil
}

func RunConvergenceRepair(
	ctx context.Context,
	role HostRole,
	dryRun bool,
	yes bool,
	jsonMode bool,
	terminal PromptIO,
	operator ConvergenceRepairOperator,
) (MutationOutcome, error) {
	workflow, err := NewConvergenceRepairWorkflow(role, operator)
	if err != nil {
		return MutationOutcome{}, err
	}
	return V2CommandRegistry().RunMutation(ctx, MutationRequest{
		CommandID: "repair", Role: role, DryRun: dryRun, Yes: yes, JSON: jsonMode,
	}, terminal, workflow, nil)
}

func convergenceRepairPlanOutput(plan operations.RepairPlan) (output.Result, error) {
	if err := plan.Validate(); err != nil {
		return output.Result{}, fmt.Errorf("validate repair plan: %w", err)
	}
	return convergenceRepairOutput(len(plan.Actions) != 0, plan.TargetGeneration, plan.Actions)
}

func convergenceRepairResultOutput(result operations.RepairResult) (output.Result, error) {
	if err := result.Validate(); err != nil {
		return output.Result{}, fmt.Errorf("validate repair result: %w", err)
	}
	return convergenceRepairOutput(result.Changed, result.Generation, result.Actions)
}

func convergenceRepairOutput(changed bool, generation uint64, actions []operations.RepairAction) (output.Result, error) {
	repairs := make(output.SafeList, len(actions))
	for index, action := range actions {
		item := output.SafeObject{
			"component":     action.Resource.Component,
			"resource_kind": string(action.Resource.Kind),
			"resource_id":   action.Resource.ID,
			"drift_kind":    string(action.DriftKind),
			"action":        string(action.Action),
			"impact":        string(action.Impact),
		}
		if action.TargetSHA256 != "" {
			item["target_sha256"] = action.TargetSHA256
		}
		if action.ObservedSHA256 != "" {
			item["observed_sha256"] = action.ObservedSHA256
		}
		repairs[index] = item
	}
	result := output.NewResult("repair", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": changed, "generation": generation,
		"repair_count": len(actions), "repairs": repairs,
	})
	return result, result.Validate()
}

func cloneConvergenceRepairPlan(plan operations.RepairPlan) operations.RepairPlan {
	plan.Actions = append([]operations.RepairAction{}, plan.Actions...)
	plan.Convergence.Changes = append([]operations.DesiredChange{}, plan.Convergence.Changes...)
	plan.Convergence.Drift = append([]operations.OwnedDrift{}, plan.Convergence.Drift...)
	return plan
}

var _ MutationWorkflow = (*ConvergenceRepairWorkflow)(nil)
