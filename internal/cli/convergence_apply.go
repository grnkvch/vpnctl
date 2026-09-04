package cli

import (
	"context"
	"fmt"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

type ConvergenceApplyOperator interface {
	Plan(context.Context) (operations.ApplyPlan, error)
	Apply(context.Context, operations.ApplyPlan) (operations.ApplyResult, error)
}

// ConvergenceApplyWorkflow retains the exact non-secret domain plan shown for
// conditional consent. The operator performs its own immediate re-plan before
// execution, so retained approval cannot cover changed operations or drift.
type ConvergenceApplyWorkflow struct {
	operator ConvergenceApplyOperator
	role     HostRole

	mu      sync.Mutex
	planned *operations.ApplyPlan
}

func NewConvergenceApplyWorkflow(role HostRole, operator ConvergenceApplyOperator) (*ConvergenceApplyWorkflow, error) {
	if operator == nil {
		return nil, fmt.Errorf("convergence apply operator is required")
	}
	return &ConvergenceApplyWorkflow{operator: operator, role: role}, nil
}

func (workflow *ConvergenceApplyWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if ctx == nil || workflow == nil || workflow.operator == nil {
		return MutationPlan{}, fmt.Errorf("convergence apply workflow is incomplete")
	}
	plan, err := workflow.operator.Plan(ctx)
	if err != nil {
		return MutationPlan{}, err
	}
	expectedRole, ok := convergenceApplyModelRole(workflow.role)
	if !ok || plan.Role != expectedRole {
		return MutationPlan{}, fmt.Errorf("%w: apply plan role %q differs from command host role %q", ErrInvalidMutationPlan, plan.Role, workflow.role)
	}
	result, err := convergenceApplyPlanOutput(plan)
	if err != nil {
		return MutationPlan{}, err
	}
	impact, err := convergenceApplyImpact(plan.Impact)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.mu.Lock()
	retained := plan
	workflow.planned = &retained
	workflow.mu.Unlock()
	return MutationPlan{Impact: impact, Result: result}, nil
}

func (workflow *ConvergenceApplyWorkflow) Apply(
	ctx context.Context,
	publicPlan MutationPlan,
	_ *InteractionInputs,
) (AppliedMutation, error) {
	domainPlan, err := workflow.retainedPlan(publicPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	result, err := workflow.operator.Apply(ctx, domainPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	publicResult, err := convergenceApplyResultOutput(result)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: publicResult}, nil
}

func (workflow *ConvergenceApplyWorkflow) retainedPlan(publicPlan MutationPlan) (operations.ApplyPlan, error) {
	if workflow == nil || workflow.operator == nil {
		return operations.ApplyPlan{}, fmt.Errorf("convergence apply workflow is incomplete")
	}
	workflow.mu.Lock()
	defer workflow.mu.Unlock()
	if workflow.planned == nil {
		return operations.ApplyPlan{}, fmt.Errorf("%w: apply was not planned", ErrInvalidMutationPlan)
	}
	wantImpact, err := convergenceApplyImpact(workflow.planned.Impact)
	if err != nil {
		return operations.ApplyPlan{}, err
	}
	wantChanged := len(workflow.planned.Operations) != 0
	changed, changedOK := publicPlan.Result.Data["changed"].(bool)
	generation, generationOK := safeUint64(publicPlan.Result.Data["generation"])
	if publicPlan.Impact != wantImpact || publicPlan.Result.Command != "apply" || !changedOK || changed != wantChanged ||
		!generationOK || generation != workflow.planned.DesiredGeneration {
		return operations.ApplyPlan{}, fmt.Errorf("%w: public apply plan differs from retained domain plan", ErrInvalidMutationPlan)
	}
	return *workflow.planned, nil
}

func RunConvergenceApply(
	ctx context.Context,
	role HostRole,
	yes bool,
	jsonMode bool,
	terminal PromptIO,
	operator ConvergenceApplyOperator,
) (MutationOutcome, error) {
	workflow, err := NewConvergenceApplyWorkflow(role, operator)
	if err != nil {
		return MutationOutcome{}, err
	}
	return V2CommandRegistry().RunMutation(ctx, MutationRequest{
		CommandID: "apply", Role: role, Yes: yes, JSON: jsonMode,
	}, terminal, workflow, nil)
}

func convergenceApplyPlanOutput(plan operations.ApplyPlan) (output.Result, error) {
	if err := plan.Validate(); err != nil {
		return output.Result{}, fmt.Errorf("validate apply plan: %w", err)
	}
	result := output.NewResult("apply", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": len(plan.Operations) != 0, "generation": plan.DesiredGeneration,
	})
	if len(plan.Operations) == 1 {
		result.Data["operation_id"] = plan.Operations[0].ID
	}
	addRemainingDriftAction(&result, len(plan.RemainingDrift))
	return result, result.Validate()
}

func convergenceApplyResultOutput(result operations.ApplyResult) (output.Result, error) {
	if err := result.Validate(); err != nil {
		return output.Result{}, fmt.Errorf("validate apply result: %w", err)
	}
	public := output.NewResult("apply", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": result.Changed, "generation": result.Generation,
	})
	if len(result.OperationIDs) == 1 {
		public.Data["operation_id"] = result.OperationIDs[0]
	}
	addRemainingDriftAction(&public, len(result.RemainingDrift))
	return public, public.Validate()
}

func convergenceApplyImpact(impact operations.ConvergenceImpact) (ImpactClass, error) {
	switch impact {
	case operations.ConvergenceImpactNone:
		return ImpactNone, nil
	case operations.ConvergenceImpactAvailability:
		return ImpactAvailability, nil
	case operations.ConvergenceImpactDestructive:
		return ImpactDestructive, nil
	default:
		return "", fmt.Errorf("unsupported convergence impact %q", impact)
	}
}

func convergenceApplyModelRole(role HostRole) (model.Role, bool) {
	switch role {
	case RoleGateway:
		return model.RoleGateway, true
	case RoleNode:
		return model.RoleNode, true
	default:
		return "", false
	}
}

func addRemainingDriftAction(result *output.Result, count int) {
	if count == 0 {
		return
	}
	result.Warnings = append(result.Warnings, output.Message{
		Code: "unrelated_drift_remains", Message: fmt.Sprintf("%d non-overlapping vpnctl-owned drift item(s) were not changed by apply.", count),
	})
	result.RequiresAction = append(result.RequiresAction, output.Action{
		Code: "repair_remaining_drift", Message: "Review and explicitly repair the remaining vpnctl-owned drift.", Command: "vpnctl repair",
	})
}

func safeUint64(value any) (uint64, bool) {
	switch value := value.(type) {
	case uint64:
		return value, true
	case uint:
		return uint64(value), true
	case int:
		if value >= 0 {
			return uint64(value), true
		}
	case int64:
		if value >= 0 {
			return uint64(value), true
		}
	}
	return 0, false
}

var _ MutationWorkflow = (*ConvergenceApplyWorkflow)(nil)
