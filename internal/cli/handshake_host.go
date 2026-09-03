package cli

import (
	"context"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

type HandshakeHostGatewayManager interface {
	PlanPrepare(context.Context, string) (transport.HandshakeHostPreparePlan, error)
	Prepare(transport.HandshakeHostPreparePlan) (transport.HandshakeHostChangeResult, error)
	PlanCommit() (transport.HandshakeHostCommitPlan, error)
	Commit(context.Context, transport.HandshakeHostCommitPlan) (transport.HandshakeHostChangeResult, error)
	PlanRollback() (transport.HandshakeHostRollbackPlan, error)
	Rollback(context.Context, transport.HandshakeHostRollbackPlan) (transport.HandshakeHostChangeResult, error)
}

type HandshakeHostRecoveryManager interface {
	Plan(context.Context, string) (transport.HandshakeHostRecoveryPlan, error)
	Apply(context.Context, transport.HandshakeHostRecoveryPlan) (transport.HandshakeHostRecoveryResult, error)
}

type HandshakeHostPrepareWorkflow struct {
	manager  HandshakeHostGatewayManager
	hostname string
	plan     transport.HandshakeHostPreparePlan
	planned  bool
}

func NewHandshakeHostPrepareWorkflow(manager HandshakeHostGatewayManager, hostname string) (*HandshakeHostPrepareWorkflow, error) {
	if manager == nil || hostname == "" {
		return nil, fmt.Errorf("handshake-host prepare manager and hostname are required")
	}
	return &HandshakeHostPrepareWorkflow{manager: manager, hostname: hostname}, nil
}

func (workflow *HandshakeHostPrepareWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	plan, err := workflow.manager.PlanPrepare(ctx, workflow.hostname)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan, workflow.planned = plan, true
	return MutationPlan{Impact: ImpactAvailability, Result: handshakeHostPreparePlanOutput(plan)}, nil
}

func (workflow *HandshakeHostPrepareWorkflow) Apply(_ context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("handshake-host replacement was not planned")
	}
	result, err := workflow.manager.Prepare(workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: handshakeHostChangeOutput("transport.host.prepare", result, true)}, nil
}

type HandshakeHostCommitWorkflow struct {
	manager HandshakeHostGatewayManager
	plan    transport.HandshakeHostCommitPlan
	planned bool
}

func NewHandshakeHostCommitWorkflow(manager HandshakeHostGatewayManager) (*HandshakeHostCommitWorkflow, error) {
	if manager == nil {
		return nil, fmt.Errorf("handshake-host commit manager is required")
	}
	return &HandshakeHostCommitWorkflow{manager: manager}, nil
}

func (workflow *HandshakeHostCommitWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	plan, err := workflow.manager.PlanCommit()
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan, workflow.planned = plan, true
	return MutationPlan{Impact: ImpactAvailability, Result: handshakeHostCommitPlanOutput(plan)}, nil
}

func (workflow *HandshakeHostCommitWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("handshake-host commit was not planned")
	}
	result, err := workflow.manager.Commit(ctx, workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: handshakeHostChangeOutput("transport.host.commit", result, false)}, nil
}

type HandshakeHostRollbackWorkflow struct {
	manager HandshakeHostGatewayManager
	plan    transport.HandshakeHostRollbackPlan
	planned bool
}

func NewHandshakeHostRollbackWorkflow(manager HandshakeHostGatewayManager) (*HandshakeHostRollbackWorkflow, error) {
	if manager == nil {
		return nil, fmt.Errorf("handshake-host rollback manager is required")
	}
	return &HandshakeHostRollbackWorkflow{manager: manager}, nil
}

func (workflow *HandshakeHostRollbackWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	plan, err := workflow.manager.PlanRollback()
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan, workflow.planned = plan, true
	return MutationPlan{Impact: ImpactAvailability, Result: handshakeHostRollbackPlanOutput(plan)}, nil
}

func (workflow *HandshakeHostRollbackWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("handshake-host rollback was not planned")
	}
	result, err := workflow.manager.Rollback(ctx, workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: handshakeHostChangeOutput("transport.host.rollback", result, false)}, nil
}

type HandshakeHostRecoveryWorkflow struct {
	manager  HandshakeHostRecoveryManager
	hostname string
	plan     transport.HandshakeHostRecoveryPlan
	planned  bool
}

func NewHandshakeHostRecoveryWorkflow(manager HandshakeHostRecoveryManager, hostname string) (*HandshakeHostRecoveryWorkflow, error) {
	if manager == nil || hostname == "" {
		return nil, fmt.Errorf("handshake-host recovery manager and hostname are required")
	}
	return &HandshakeHostRecoveryWorkflow{manager: manager, hostname: hostname}, nil
}

func (workflow *HandshakeHostRecoveryWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	plan, err := workflow.manager.Plan(ctx, workflow.hostname)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan, workflow.planned = plan, true
	return MutationPlan{Impact: ImpactAvailability, Result: handshakeHostRecoveryPlanOutput(plan)}, nil
}

func (workflow *HandshakeHostRecoveryWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("handshake-host recovery was not planned")
	}
	result, err := workflow.manager.Apply(ctx, workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	public := output.NewResult("transport.host.recover", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"active": result.Active.Hostname, "generation": result.StateGeneration,
		"credential_generation": result.CredentialGeneration, "health": string(result.Health.Condition),
	})
	if result.NodeID != "" {
		public.ResourceIDs["node_id"] = result.NodeID
	}
	return AppliedMutation{Result: public}, nil
}

func HandshakeHostShowOutput(view transport.HandshakeHostView) output.Result {
	data := output.SafeObject{
		"active": view.Active.Hostname, "state": string(view.State), "generation": view.StateGeneration,
		"health": string(view.Health.Condition), "health_code": view.Health.Code, "rollback_available": view.RollbackAvailable,
	}
	if view.Prepared != nil {
		data["prepared"] = view.Prepared.Hostname
	}
	if view.State == "prepared" {
		data["affected_nodes"] = append([]string(nil), view.Impact.NodeIDs...)
		data["affected_clients"] = append([]string(nil), view.Impact.ClientIDs...)
	}
	if view.State == "committed" {
		data["stale_nodes"] = append([]string(nil), view.Impact.NodeIDs...)
		data["stale_clients"] = append([]string(nil), view.Impact.ClientIDs...)
	}
	if view.RollbackExpiresAt != nil {
		data["rollback_expires_at"] = view.RollbackExpiresAt.Format("2006-01-02T15:04:05Z07:00")
	}
	status, category := output.StatusOK, output.CategorySuccess
	if view.Health.RequiresAction {
		status, category = output.StatusDegraded, output.CategoryUnavailable
	}
	result := output.NewResult("transport.host.show", status, category, data)
	if view.OperationID != "" {
		result.ResourceIDs["operation_id"] = view.OperationID
	}
	if view.Health.RequiresAction {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "replace_handshake_host", Message: "The active handshake host is degraded; explicitly prepare and commit a replacement.",
			Command: "vpnctl transport host prepare <host>",
		})
	}
	return result
}

func handshakeHostPreparePlanOutput(plan transport.HandshakeHostPreparePlan) output.Result {
	return output.NewResult("transport.host.prepare", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"current": plan.Current.Hostname, "candidate": plan.Candidate.Hostname,
		"generation": plan.NextStateGeneration, "affected_nodes": append([]string(nil), plan.Impact.NodeIDs...),
		"affected_clients": append([]string(nil), plan.Impact.ClientIDs...),
	})
}

func handshakeHostCommitPlanOutput(plan transport.HandshakeHostCommitPlan) output.Result {
	return output.NewResult("transport.host.commit", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"current": plan.Current.Hostname, "candidate": plan.Candidate.Hostname,
		"generation": plan.NextStateGeneration, "stale_nodes": append([]string(nil), plan.Impact.NodeIDs...),
		"stale_clients": append([]string(nil), plan.Impact.ClientIDs...),
	})
}

func handshakeHostRollbackPlanOutput(plan transport.HandshakeHostRollbackPlan) output.Result {
	return output.NewResult("transport.host.rollback", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"current": plan.Current.Hostname, "previous": plan.Previous.Hostname,
		"generation": plan.NextStateGeneration, "stale_nodes": append([]string(nil), plan.Impact.NodeIDs...),
		"stale_clients": append([]string(nil), plan.Impact.ClientIDs...),
	})
}

func handshakeHostRecoveryPlanOutput(plan transport.HandshakeHostRecoveryPlan) output.Result {
	result := output.NewResult("transport.host.recover", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"current": plan.Current.Hostname, "candidate": plan.Candidate.Hostname,
		"generation": plan.NextStateGeneration, "credential_generation": plan.CredentialGeneration,
	})
	if plan.NodeID != "" {
		result.ResourceIDs["node_id"] = plan.NodeID
	}
	return result
}

func handshakeHostChangeOutput(command string, change transport.HandshakeHostChangeResult, prepared bool) output.Result {
	status := output.StatusOK
	data := output.SafeObject{"active": change.Active.Hostname, "generation": change.StateGeneration}
	if prepared {
		status = output.StatusPending
		if change.Prepared != nil {
			data["prepared"] = change.Prepared.Hostname
		}
	}
	if change.RollbackUntil != nil {
		data["rollback_expires_at"] = change.RollbackUntil.Format("2006-01-02T15:04:05Z07:00")
	}
	result := output.NewResult(command, status, output.CategorySuccess, data)
	if change.OperationID != "" {
		result.ResourceIDs["operation_id"] = change.OperationID
	}
	if prepared {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "commit_handshake_host", Message: "Review the affected nodes and clients, then explicitly commit the prepared handshake host.",
			Command: "vpnctl transport host commit", ResourceIDs: map[string]string{"operation_id": change.OperationID},
		})
	}
	for _, nodeID := range change.StaleNodeIDs {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "apply_node_handshake_host", Message: "Apply the committed handshake host on this node; use SSH recovery if its restricted control path is unavailable.",
			Command: "vpnctl apply", ResourceIDs: map[string]string{"node_id": nodeID},
		})
	}
	for _, clientID := range change.StaleClientIDs {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "re_export_clash_client", Message: "Re-export and manually replace this client's Clash profile.",
			Command: "vpnctl client export " + clientID + " clash", ResourceIDs: map[string]string{"client_id": clientID},
		})
	}
	return result
}

var _ MutationWorkflow = (*HandshakeHostPrepareWorkflow)(nil)
var _ MutationWorkflow = (*HandshakeHostCommitWorkflow)(nil)
var _ MutationWorkflow = (*HandshakeHostRollbackWorkflow)(nil)
var _ MutationWorkflow = (*HandshakeHostRecoveryWorkflow)(nil)
