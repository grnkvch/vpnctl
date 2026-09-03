package cli

import (
	"context"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

type TransportSwitcher interface {
	Plan(model.TransportKind) (transport.SwitchPlan, error)
	Apply(context.Context, transport.SwitchPlan) (transport.SwitchResult, error)
}

// TransportSwitchWorkflow adapts the node switch saga to the common consent,
// dry-run, and authoritative-defer boundary. In deferred mode RunMutation
// sends the complete non-secret target plan to its gateway writer and never
// calls Apply, so local active connections cannot change.
type TransportSwitchWorkflow struct {
	switcher TransportSwitcher
	target   model.TransportKind
	plan     transport.SwitchPlan
	planned  bool
}

func NewTransportSwitchWorkflow(switcher TransportSwitcher, target model.TransportKind) (*TransportSwitchWorkflow, error) {
	if switcher == nil {
		return nil, fmt.Errorf("transport switcher is required")
	}
	if target != model.TransportStandard && target != model.TransportRestricted {
		return nil, fmt.Errorf("unsupported transport switch target %q", target)
	}
	return &TransportSwitchWorkflow{switcher: switcher, target: target}, nil
}

func (workflow *TransportSwitchWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.switcher == nil {
		return MutationPlan{}, fmt.Errorf("transport switch workflow is incomplete")
	}
	plan, err := workflow.switcher.Plan(workflow.target)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan = plan
	workflow.planned = true
	return MutationPlan{Impact: ImpactAvailability, Result: transportSwitchPlanOutput(plan)}, nil
}

func (workflow *TransportSwitchWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.switcher == nil || !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("transport switch was not planned")
	}
	result, err := workflow.switcher.Apply(ctx, workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: transportSwitchResultOutput(result)}, nil
}

func transportSwitchPlanOutput(plan transport.SwitchPlan) output.Result {
	return output.NewResult("transport.switch", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": plan.Changed, "current": string(plan.Current), "target": string(plan.Target),
		"generation": plan.NextStateGeneration,
	})
}

func transportSwitchResultOutput(result transport.SwitchResult) output.Result {
	status := output.StatusOK
	category := output.CategorySuccess
	if result.ActiveHealth.Condition == transport.HealthDegraded || result.ActiveHealth.Condition == transport.HealthUnavailable {
		status = output.StatusDegraded
		category = output.CategoryUnavailable
	}
	public := output.NewResult("transport.switch", status, category, output.SafeObject{
		"changed": result.Changed, "previous": string(result.Previous), "active": string(result.Active),
		"generation": result.StateGeneration, "health": string(result.ActiveHealth.Condition),
	})
	if result.NodeID != "" {
		public.ResourceIDs["node_id"] = result.NodeID
	}
	if status == output.StatusDegraded {
		action := output.Action{
			Code: "inspect_active_transport", Message: "The explicitly selected active transport is degraded; inspect it before manually choosing another transport.",
			Command: "vpnctl doctor transport",
		}
		if result.NodeID != "" {
			action.ResourceIDs = map[string]string{"node_id": result.NodeID}
		}
		public.RequiresAction = append(public.RequiresAction, action)
	}
	return public
}

var _ MutationWorkflow = (*TransportSwitchWorkflow)(nil)
