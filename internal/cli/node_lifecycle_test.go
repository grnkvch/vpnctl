package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestExecuteNodeLifecycleUsesRoleGateDryRunAndConfirmation(t *testing.T) {
	operator := &recordingNodeLifecycleOperator{}
	oldPaths, oldRole, oldBuilder, oldTTY := nodeLifecycleSystemPaths, nodeLifecycleLoadRole, nodeLifecycleBuilder, nodeLifecycleOpenTTY
	t.Cleanup(func() {
		nodeLifecycleSystemPaths, nodeLifecycleLoadRole, nodeLifecycleBuilder, nodeLifecycleOpenTTY = oldPaths, oldRole, oldBuilder, oldTTY
	})
	paths, _ := store.NewPaths(t.TempDir())
	nodeLifecycleSystemPaths = func() store.Paths { return paths }
	nodeLifecycleLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	nodeLifecycleBuilder = func(store.Paths) (NodeLifecycleOperator, error) { return operator, nil }
	nodeLifecycleOpenTTY = func() (PromptIO, io.Closer, error) { t.Fatal("unexpected TTY open"); return nil, nil, nil }

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"node", "revoke", "private-node", "--dry-run", "--json"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("node revoke dry-run code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if operator.commits != 0 || !strings.Contains(stdout.String(), `"command":"node.revoke"`) {
		t.Fatalf("dry-run mutated or emitted wrong output: commits=%d output=%q", operator.commits, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Execute([]string{"--json", "node", "delete", "private-node", "--yes"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("node delete code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if operator.commits != 1 || operator.lastCommit != "delete" || !strings.Contains(stdout.String(), `"command":"node.delete"`) {
		t.Fatalf("delete did not commit through workflow: operator=%+v output=%q", operator, stdout.String())
	}
}

func TestNodeLifecycleWorkflowsUseConfirmedImmediateImpact(t *testing.T) {
	for _, test := range []struct {
		name       string
		command    enrollment.NodeLifecycleCommand
		impact     ImpactClass
		construct  func(NodeLifecycleOperator, string) (*NodeLifecycleMutationWorkflow, error)
		commitCall string
	}{
		{name: "revoke", command: enrollment.NodeRevoke, impact: ImpactAvailability, construct: NewNodeRevokeMutationWorkflow, commitCall: "revoke"},
		{name: "delete", command: enrollment.NodeDelete, impact: ImpactDestructive, construct: NewNodeDeleteMutationWorkflow, commitCall: "delete"},
	} {
		t.Run(test.name, func(t *testing.T) {
			operator := &recordingNodeLifecycleOperator{command: test.command}
			workflow, err := test.construct(operator, "private-node")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := workflow.Plan(context.Background(), nil)
			if err != nil || plan.Impact != test.impact || plan.Result.Command != string(test.command) || operator.commits != 0 {
				t.Fatalf("Plan() = %+v, %v; operator=%+v", plan, err, operator)
			}
			if err := plan.Result.Validate(); err != nil {
				t.Fatalf("plan output: %v", err)
			}
			applied, err := workflow.Apply(context.Background(), plan, nil)
			if err != nil || operator.commits != 1 || operator.lastCommit != test.commitCall ||
				applied.Result.ResourceIDs["node_id"] != nodeLifecycleCLINodeID {
				t.Fatalf("Apply() = %+v, %v; operator=%+v", applied, err, operator)
			}
			if err := applied.Result.Validate(); err != nil {
				t.Fatalf("applied output: %v", err)
			}
		})
	}
}

func TestNodeLifecycleWorkflowDoesNotApplyFailedPlan(t *testing.T) {
	operator := &recordingNodeLifecycleOperator{command: enrollment.NodeRevoke, planErr: enrollment.ErrNodeNotFound}
	workflow, err := NewNodeRevokeMutationWorkflow(operator, "missing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.Plan(context.Background(), nil); !errors.Is(err, enrollment.ErrNodeNotFound) {
		t.Fatalf("Plan() error = %v", err)
	}
	if _, err := workflow.Apply(context.Background(), MutationPlan{}, nil); err == nil || operator.commits != 0 {
		t.Fatalf("Apply() error = %v; commits=%d", err, operator.commits)
	}
}

func TestNodeLifecycleWorkflowPreservesPostCommitRepairActions(t *testing.T) {
	operator := &recordingNodeLifecycleOperator{
		command:   enrollment.NodeRevoke,
		commitErr: errors.Join(enrollment.ErrNodeCleanupPending, enrollment.ErrNodeRevocationIncomplete),
		result: enrollment.NodeLifecycleResult{
			Command: enrollment.NodeRevoke, NodeID: nodeLifecycleCLINodeID, NodeName: "private-node",
			Changed: true, StateGeneration: 6, CredentialGeneration: 1, RuntimeReconcileNeeded: true,
		},
	}
	workflow, err := NewNodeRevokeMutationWorkflow(operator, "private-node")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := workflow.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := workflow.Apply(context.Background(), plan, nil)
	if err != nil {
		t.Fatalf("Apply(post-commit repair) error = %v", err)
	}
	if applied.Result.Status != output.StatusPending || len(applied.Result.RequiresAction) != 1 ||
		applied.Result.RequiresAction[0].Code != "repair_node_runtime" {
		t.Fatalf("Apply(post-commit repair) = %+v", applied)
	}
}

const nodeLifecycleCLINodeID = "20000000-0000-4000-8000-000000000004"

type recordingNodeLifecycleOperator struct {
	command    enrollment.NodeLifecycleCommand
	planErr    error
	commitErr  error
	result     enrollment.NodeLifecycleResult
	commits    int
	lastCommit string
}

func (operator *recordingNodeLifecycleOperator) plan(command enrollment.NodeLifecycleCommand) (enrollment.NodeLifecyclePlan, error) {
	if operator.planErr != nil {
		return enrollment.NodeLifecyclePlan{}, operator.planErr
	}
	return enrollment.NodeLifecyclePlan{
		Command: command, NodeID: nodeLifecycleCLINodeID, NodeName: "private-node", Changed: true,
		ExpectedStateGeneration: 5, NextStateGeneration: 6, CredentialGeneration: 1, ExposeIDs: []string{},
	}, nil
}

func (operator *recordingNodeLifecycleOperator) PlanRevoke(string) (enrollment.NodeLifecyclePlan, error) {
	return operator.plan(enrollment.NodeRevoke)
}

func (operator *recordingNodeLifecycleOperator) CommitRevoke(_ context.Context, plan enrollment.NodeLifecyclePlan) (enrollment.NodeLifecycleResult, error) {
	operator.commits++
	operator.lastCommit = "revoke"
	if operator.result.NodeID != "" {
		return operator.result, operator.commitErr
	}
	return recordingNodeLifecycleResult(plan), operator.commitErr
}

func (operator *recordingNodeLifecycleOperator) PlanDelete(string) (enrollment.NodeLifecyclePlan, error) {
	return operator.plan(enrollment.NodeDelete)
}

func (operator *recordingNodeLifecycleOperator) CommitDelete(_ context.Context, plan enrollment.NodeLifecyclePlan) (enrollment.NodeLifecycleResult, error) {
	operator.commits++
	operator.lastCommit = "delete"
	if operator.result.NodeID != "" {
		return operator.result, operator.commitErr
	}
	return recordingNodeLifecycleResult(plan), operator.commitErr
}

func recordingNodeLifecycleResult(plan enrollment.NodeLifecyclePlan) enrollment.NodeLifecycleResult {
	return enrollment.NodeLifecycleResult{
		Command: plan.Command, NodeID: plan.NodeID, NodeName: plan.NodeName, Changed: plan.Changed,
		StateGeneration: plan.NextStateGeneration, CredentialGeneration: plan.CredentialGeneration,
		DisabledExposeIDs: []string{}, ConnectionsClosed: plan.Command == enrollment.NodeRevoke,
	}
}

func TestNodeLifecyclePendingOutputUsesOnlySafeActions(t *testing.T) {
	result := enrollment.NodeLifecycleResult{
		Command: enrollment.NodeRevoke, NodeID: nodeLifecycleCLINodeID, NodeName: "private-node",
		Changed: true, StateGeneration: 6, CredentialGeneration: 1,
		RuntimeReconcileNeeded: true, CredentialCleanupNeeded: true,
	}.OutputResult()
	if result.Status != output.StatusPending || len(result.RequiresAction) != 2 {
		t.Fatalf("pending result = %+v", result)
	}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
}
