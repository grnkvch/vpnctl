package cli

import (
	"context"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

type ConvergencePlanReader interface {
	Plan(context.Context) (operations.ConvergencePlan, error)
}

// RunConvergencePlan applies the public role gate and performs only the
// planner's read-only operation. System construction is kept outside this
// adapter so an unsupported role is rejected before state or host discovery.
func RunConvergencePlan(ctx context.Context, role HostRole, planner ConvergencePlanReader) (output.Result, error) {
	if ctx == nil {
		return output.Result{}, fmt.Errorf("context is required")
	}
	if planner == nil {
		return output.Result{}, fmt.Errorf("convergence planner is required")
	}
	var result output.Result
	err := V2CommandRegistry().Dispatch("plan", role, func(CommandSpec) error {
		plan, err := planner.Plan(ctx)
		if err != nil {
			return fmt.Errorf("plan convergence: %w", err)
		}
		result, err = ConvergencePlanOutput(plan)
		return err
	})
	return result, err
}

// ConvergencePlanOutput adapts the pure read-only plan to the frozen plan-v1
// result schema. Hashes and stable resource IDs are emitted; source material
// and sensitive paths never enter the result.
func ConvergencePlanOutput(plan operations.ConvergencePlan) (output.Result, error) {
	if err := plan.Validate(); err != nil {
		return output.Result{}, fmt.Errorf("validate convergence plan: %w", err)
	}
	changes := make([]output.SafeObject, 0, len(plan.Changes))
	for _, change := range plan.Changes {
		item := output.SafeObject{
			"operation_id":   change.OperationID,
			"operation_type": change.OperationType,
			"component":      change.Resource.Component,
			"resource_kind":  string(change.Resource.Kind),
			"resource_id":    change.Resource.ID,
			"change":         string(change.Kind),
			"impact":         string(change.Impact),
		}
		if change.TargetKind != "" {
			item["target_kind"] = change.TargetKind
			item["target_id"] = change.TargetID
		}
		if change.FromSHA256 != "" {
			item["from_sha256"] = change.FromSHA256
		}
		if change.ToSHA256 != "" {
			item["to_sha256"] = change.ToSHA256
		}
		changes = append(changes, item)
	}
	drift := make([]output.SafeObject, 0, len(plan.Drift))
	for _, item := range plan.Drift {
		entry := output.SafeObject{
			"component":     item.Resource.Component,
			"resource_kind": string(item.Resource.Kind),
			"resource_id":   item.Resource.ID,
			"drift":         string(item.Kind),
			"impact":        string(item.Impact),
		}
		if item.ExpectedSHA256 != "" {
			entry["expected_sha256"] = item.ExpectedSHA256
		}
		if item.ActualSHA256 != "" {
			entry["actual_sha256"] = item.ActualSHA256
		}
		drift = append(drift, entry)
	}
	status := output.StatusOK
	if len(changes) != 0 {
		status = output.StatusPending
	}
	result := output.NewResult("plan", status, output.CategorySuccess, output.SafeObject{
		"impact": string(plan.Impact), "changes": changes, "drift": drift,
	})
	if len(drift) != 0 {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "review_drift", Message: "Review vpnctl-owned drift before applying any overlapping pending change.", Command: "vpnctl repair",
		})
	}
	return result, result.Validate()
}
