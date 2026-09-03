package cli

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestHandshakeHostPrepareUsesNoPromptAndDryRunDoesNotPersist(t *testing.T) {
	t.Parallel()

	manager := newRecordingHandshakeHostGatewayManager()
	workflow, _ := NewHandshakeHostPrepareWorkflow(manager, "www.apple.com")
	dryRun, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "transport.host.prepare", Role: RoleGateway, DryRun: true,
	}, nil, workflow, nil)
	if err != nil {
		t.Fatalf("prepare dry-run error = %v", err)
	}
	if dryRun.Mode != MutationDryRun || dryRun.Result.Status != output.StatusOK || manager.planPrepareCalls != 1 || manager.prepareCalls != 0 {
		t.Fatalf("prepare dry-run outcome=%+v calls=%d/%d", dryRun, manager.planPrepareCalls, manager.prepareCalls)
	}

	workflow, _ = NewHandshakeHostPrepareWorkflow(manager, "www.apple.com")
	applied, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "transport.host.prepare", Role: RoleGateway,
	}, nil, workflow, nil)
	if err != nil {
		t.Fatalf("prepare immediate error = %v", err)
	}
	if applied.Result.Status != output.StatusPending || manager.prepareCalls != 1 || len(applied.Result.RequiresAction) != 1 || applied.Result.RequiresAction[0].Code != "commit_handshake_host" {
		t.Fatalf("prepare immediate outcome=%+v calls=%d", applied, manager.prepareCalls)
	}
}

func TestHandshakeHostCommitRollbackAndRecoveryUseExplicitConfirmation(t *testing.T) {
	t.Parallel()

	manager := newRecordingHandshakeHostGatewayManager()
	commit, _ := NewHandshakeHostCommitWorkflow(manager)
	_, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "transport.host.commit", Role: RoleGateway,
	}, nil, commit, nil)
	if !errors.Is(err, ErrInteractionRefused) || manager.commitCalls != 0 {
		t.Fatalf("unconfirmed commit error=%v calls=%d", err, manager.commitCalls)
	}
	commit, _ = NewHandshakeHostCommitWorkflow(manager)
	committed, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "transport.host.commit", Role: RoleGateway, Yes: true,
	}, nil, commit, nil)
	if err != nil || manager.commitCalls != 1 || len(committed.Result.RequiresAction) != 2 {
		t.Fatalf("confirmed commit=%+v error=%v calls=%d", committed, err, manager.commitCalls)
	}
	if committed.Result.RequiresAction[0].Code != "apply_node_handshake_host" || committed.Result.RequiresAction[1].Code != "re_export_clash_client" {
		t.Fatalf("commit stale actions = %+v", committed.Result.RequiresAction)
	}

	rollback, _ := NewHandshakeHostRollbackWorkflow(manager)
	rolledBack, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "transport.host.rollback", Role: RoleGateway, Yes: true,
	}, nil, rollback, nil)
	if err != nil || manager.rollbackCalls != 1 || rolledBack.Result.Data["active"] != "www.microsoft.com" {
		t.Fatalf("confirmed rollback=%+v error=%v calls=%d", rolledBack, err, manager.rollbackCalls)
	}

	recoveryManager := &recordingHandshakeHostRecoveryManager{}
	recovery, _ := NewHandshakeHostRecoveryWorkflow(recoveryManager, "www.apple.com")
	_, err = V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "transport.host.recover", Role: RoleNode,
	}, nil, recovery, nil)
	if !errors.Is(err, ErrInteractionRefused) || recoveryManager.applies != 0 {
		t.Fatalf("unconfirmed recovery error=%v applies=%d", err, recoveryManager.applies)
	}
	recovery, _ = NewHandshakeHostRecoveryWorkflow(recoveryManager, "www.apple.com")
	recovered, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "transport.host.recover", Role: RoleNode, Yes: true,
	}, nil, recovery, nil)
	if err != nil || recoveryManager.applies != 1 || recovered.Result.Data["credential_generation"] != uint64(3) || recovered.Result.ResourceIDs["node_id"] != lifecycleCLINodeID {
		t.Fatalf("confirmed recovery=%+v error=%v applies=%d", recovered, err, recoveryManager.applies)
	}
}

func TestHandshakeHostShowOutputContainsNoCandidateWhenCommitted(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	result := HandshakeHostShowOutput(transport.HandshakeHostView{
		State: model.HandshakeHostCommitted, OperationID: lifecycleCLIOperationID,
		Active:            model.HandshakeHost{Hostname: "www.apple.com"},
		Health:            transport.HandshakeHostHealth{Condition: transport.HealthHealthy, Code: "handshake-host-healthy"},
		RollbackAvailable: true, RollbackExpiresAt: &now, StateGeneration: 11,
	})
	if err := result.Validate(); err != nil {
		t.Fatalf("show output validation = %v", err)
	}
	if result.Command != "transport.host.show" || result.Data["active"] != "www.apple.com" || result.Data["rollback_available"] != true {
		t.Fatalf("show output = %+v", result)
	}
	if _, found := result.Data["prepared"]; found {
		t.Fatalf("committed show leaked a prepared marker: %+v", result.Data)
	}
}

func TestHandshakeHostShowOutputRequiresManualReplacementWhenDegraded(t *testing.T) {
	t.Parallel()

	result := HandshakeHostShowOutput(transport.HandshakeHostView{
		Active: model.HandshakeHost{Hostname: "www.microsoft.com"},
		Health: transport.HandshakeHostHealth{
			Condition: transport.HealthDegraded, Code: "handshake-host-degraded", RequiresAction: true,
		},
		StateGeneration: 7,
	})
	if err := result.Validate(); err != nil {
		t.Fatalf("degraded show output validation = %v", err)
	}
	if result.Status != output.StatusDegraded || result.ExitCategory != output.CategoryUnavailable || len(result.RequiresAction) != 1 ||
		result.RequiresAction[0].Code != "replace_handshake_host" {
		t.Fatalf("degraded show output = %+v", result)
	}
}

const (
	lifecycleCLINodeID      = "20000000-0000-4000-8000-000000000001"
	lifecycleCLIClientID    = "30000000-0000-4000-8000-000000000001"
	lifecycleCLIOperationID = "40000000-0000-4000-8000-000000000001"
)

type recordingHandshakeHostGatewayManager struct {
	planPrepareCalls  int
	prepareCalls      int
	planCommitCalls   int
	commitCalls       int
	planRollbackCalls int
	rollbackCalls     int
}

func newRecordingHandshakeHostGatewayManager() *recordingHandshakeHostGatewayManager {
	return &recordingHandshakeHostGatewayManager{}
}

func cliHandshakeHost(id, hostname string, selected time.Time) model.HandshakeHost {
	return model.HandshakeHost{SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: id, Hostname: hostname, SelectedAt: selected}
}

func (manager *recordingHandshakeHostGatewayManager) PlanPrepare(_ context.Context, hostname string) (transport.HandshakeHostPreparePlan, error) {
	manager.planPrepareCalls++
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	if hostname != "www.apple.com" {
		return transport.HandshakeHostPreparePlan{}, errors.New("unexpected hostname")
	}
	return transport.HandshakeHostPreparePlan{
		OperationID: lifecycleCLIOperationID, Current: cliHandshakeHost("microsoft", "www.microsoft.com", now), Candidate: cliHandshakeHost("apple", hostname, now),
		Impact:                  transport.HandshakeHostImpact{NodeIDs: []string{lifecycleCLINodeID}, ClientIDs: []string{lifecycleCLIClientID}},
		ExpectedStateGeneration: 9, NextStateGeneration: 10,
	}, nil
}

func (manager *recordingHandshakeHostGatewayManager) Prepare(plan transport.HandshakeHostPreparePlan) (transport.HandshakeHostChangeResult, error) {
	manager.prepareCalls++
	candidate := plan.Candidate
	return transport.HandshakeHostChangeResult{
		OperationID: plan.OperationID, StateGeneration: plan.NextStateGeneration, Active: plan.Current, Prepared: &candidate,
	}, nil
}

func (manager *recordingHandshakeHostGatewayManager) PlanCommit() (transport.HandshakeHostCommitPlan, error) {
	manager.planCommitCalls++
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	return transport.HandshakeHostCommitPlan{
		OperationID: lifecycleCLIOperationID, Current: cliHandshakeHost("microsoft", "www.microsoft.com", now), Candidate: cliHandshakeHost("apple", "www.apple.com", now),
		Impact:                  transport.HandshakeHostImpact{NodeIDs: []string{lifecycleCLINodeID}, ClientIDs: []string{lifecycleCLIClientID}},
		ExpectedStateGeneration: 10, NextStateGeneration: 11,
	}, nil
}

func (manager *recordingHandshakeHostGatewayManager) Commit(_ context.Context, plan transport.HandshakeHostCommitPlan) (transport.HandshakeHostChangeResult, error) {
	manager.commitCalls++
	expires := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	return transport.HandshakeHostChangeResult{
		OperationID: plan.OperationID, StateGeneration: plan.NextStateGeneration, Active: plan.Candidate, RollbackUntil: &expires,
		StaleNodeIDs: append([]string(nil), plan.Impact.NodeIDs...), StaleClientIDs: append([]string(nil), plan.Impact.ClientIDs...),
	}, nil
}

func (manager *recordingHandshakeHostGatewayManager) PlanRollback() (transport.HandshakeHostRollbackPlan, error) {
	manager.planRollbackCalls++
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	return transport.HandshakeHostRollbackPlan{
		OperationID: lifecycleCLIOperationID, Current: cliHandshakeHost("apple", "www.apple.com", now), Previous: cliHandshakeHost("microsoft", "www.microsoft.com", now),
		Impact:                  transport.HandshakeHostImpact{NodeIDs: []string{lifecycleCLINodeID}, ClientIDs: []string{lifecycleCLIClientID}},
		ExpectedStateGeneration: 11, NextStateGeneration: 12, RollbackExpiresAt: now.Add(24 * time.Hour),
	}, nil
}

func (manager *recordingHandshakeHostGatewayManager) Rollback(_ context.Context, plan transport.HandshakeHostRollbackPlan) (transport.HandshakeHostChangeResult, error) {
	manager.rollbackCalls++
	return transport.HandshakeHostChangeResult{
		OperationID: plan.OperationID, StateGeneration: plan.NextStateGeneration, Active: plan.Previous,
		StaleNodeIDs: append([]string(nil), plan.Impact.NodeIDs...), StaleClientIDs: append([]string(nil), plan.Impact.ClientIDs...),
	}, nil
}

type recordingHandshakeHostRecoveryManager struct {
	plans   int
	applies int
}

func (manager *recordingHandshakeHostRecoveryManager) Plan(_ context.Context, hostname string) (transport.HandshakeHostRecoveryPlan, error) {
	manager.plans++
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	return transport.HandshakeHostRecoveryPlan{
		NodeID: lifecycleCLINodeID, Current: cliHandshakeHost("microsoft", "www.microsoft.com", now), Candidate: cliHandshakeHost("apple", hostname, now),
		ExpectedStateGeneration: 9, NextStateGeneration: 10, CredentialGeneration: 3,
	}, nil
}

func (manager *recordingHandshakeHostRecoveryManager) Apply(_ context.Context, plan transport.HandshakeHostRecoveryPlan) (transport.HandshakeHostRecoveryResult, error) {
	manager.applies++
	return transport.HandshakeHostRecoveryResult{
		NodeID: plan.NodeID, Active: plan.Candidate, StateGeneration: plan.NextStateGeneration, CredentialGeneration: plan.CredentialGeneration,
		Health: transport.Health{Condition: transport.HealthHealthy},
	}, nil
}

var _ HandshakeHostGatewayManager = (*recordingHandshakeHostGatewayManager)(nil)
var _ HandshakeHostRecoveryManager = (*recordingHandshakeHostRecoveryManager)(nil)
