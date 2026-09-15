package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type ConvergencePlanReader interface {
	Plan(context.Context) (operations.ConvergencePlan, error)
}

type gatewayReadinessConvergencePlanReader struct {
	base      ConvergencePlanReader
	state     gatewayConvergencePlanStateReader
	readiness gatewayBootstrapStatusObserver
}

type gatewayConvergencePlanStateReader interface {
	Load() (model.State, error)
}

func composeSystemConvergencePlanReader(paths store.Paths, role HostRole, base ConvergencePlanReader) (ConvergencePlanReader, error) {
	if base == nil {
		return nil, fmt.Errorf("convergence planner is required")
	}
	if role != RoleGateway {
		return base, nil
	}
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	readiness, err := newSystemGatewayBootstrapStatusObserver(paths)
	if err != nil {
		return nil, err
	}
	return &gatewayReadinessConvergencePlanReader{base: base, state: state, readiness: readiness}, nil
}

func (reader *gatewayReadinessConvergencePlanReader) Plan(ctx context.Context) (operations.ConvergencePlan, error) {
	if ctx == nil || reader == nil || reader.base == nil || reader.state == nil || reader.readiness == nil {
		return operations.ConvergencePlan{}, fmt.Errorf("gateway readiness convergence planner is incomplete")
	}
	plan, err := reader.base.Plan(ctx)
	if err != nil {
		return operations.ConvergencePlan{}, err
	}
	state, err := reader.state.Load()
	if err != nil {
		return operations.ConvergencePlan{}, err
	}
	if state.Host.Role != model.RoleGateway || !gatewayReadinessPlanMatchesState(state, plan) {
		return operations.ConvergencePlan{}, operations.ErrConvergencePlanInvalid
	}
	report, err := reader.readiness.Inspect(ctx, state)
	if err != nil {
		return operations.ConvergencePlan{}, err
	}
	plan.Drift = mergeGatewayReadinessDrift(plan.Drift, report)
	if len(plan.Drift) != 0 && plan.Impact == operations.ConvergenceImpactNone {
		plan.Impact = operations.ConvergenceImpactAvailability
	}
	if err := plan.Validate(); err != nil {
		return operations.ConvergencePlan{}, fmt.Errorf("%w: gateway readiness: %v", operations.ErrConvergencePlanInvalid, err)
	}
	return plan, nil
}

func gatewayReadinessPlanMatchesState(state model.State, plan operations.ConvergencePlan) bool {
	if state.Generation < plan.DesiredGeneration {
		return false
	}
	if state.Generation == plan.DesiredGeneration {
		return true
	}
	if plan.DesiredGeneration != plan.AppliedGeneration || len(plan.Changes) != 0 {
		return false
	}
	for _, operation := range state.Operations {
		if operation.State != model.OperationCompleted && operation.State != model.OperationFailed {
			return false
		}
	}
	return true
}

func mergeGatewayReadinessDrift(existing []operations.OwnedDrift, report lifecycle.GatewayBootstrapReadinessReport) []operations.OwnedDrift {
	// ConvergencePlan requires present empty arrays. Preserve that contract when
	// a healthy readiness projection has nothing to append.
	result := append(make([]operations.OwnedDrift, 0, len(existing)), existing...)
	seen := make(map[string]struct{}, len(result))
	for _, item := range result {
		seen[gatewayReadinessResourceOrder(item.Resource)] = struct{}{}
	}
	for _, check := range report.Checks {
		if check.Condition == lifecycle.GatewayReadinessHealthy {
			continue
		}
		kind := operations.ManagedResourceState
		component := "ingress"
		switch check.Kind {
		case "file", "tree":
			kind = operations.ManagedResourceFile
		case "unit":
			kind = operations.ManagedResourceUnit
		case "listener":
			kind = operations.ManagedResourceNetwork
		case "package":
			component = "package"
		}
		resource := operations.ManagedResourceKey{Component: component, Kind: kind, ID: check.ID}
		key := gatewayReadinessResourceOrder(resource)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		expected := check.ExpectedSHA256
		if expected == "" {
			expected = operations.ManagedFingerprint([]byte(strings.Join([]string{"gateway-readiness-v1", check.Kind, check.ID, check.Expected, check.Code}, "\x00")))
		}
		drift := operations.OwnedDrift{
			Resource: resource, Kind: operations.OwnedDriftMissing,
			Impact: operations.ConvergenceImpactAvailability, ExpectedSHA256: expected,
		}
		if check.Condition != lifecycle.GatewayReadinessMissing {
			drift.Kind = operations.OwnedDriftModified
			drift.ActualSHA256 = check.ObservedSHA256
			if drift.ActualSHA256 == "" || drift.ActualSHA256 == expected {
				drift.ActualSHA256 = operations.ManagedFingerprint([]byte(strings.Join([]string{"gateway-readiness-v1", string(check.Condition), check.Code, check.Observed}, "\x00")))
			}
		}
		result = append(result, drift)
		seen[key] = struct{}{}
	}
	sort.Slice(result, func(left, right int) bool {
		return gatewayReadinessResourceOrder(result[left].Resource) < gatewayReadinessResourceOrder(result[right].Resource)
	})
	return result
}

func gatewayReadinessResourceOrder(key operations.ManagedResourceKey) string {
	return key.Component + "\x00" + string(key.Kind) + "\x00" + key.ID
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
	if len(changes) != 0 || len(drift) != 0 {
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
