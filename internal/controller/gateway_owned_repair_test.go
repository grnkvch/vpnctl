package controller

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
)

func TestGatewayOwnedRepairPreparesExactRuntimeOnlyBatch(t *testing.T) {
	t.Parallel()

	state := gatewayRepairTestState(t)
	batch := gatewayOwnedRepairTestBatch(t, state.Generation)
	executor := &recordingGatewayOwnedRepairExecutor{}
	dispatcher, err := NewGatewayOwnedRepairDispatcher(executor)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(GatewayOwnedRepairPayload{Batch: batch})
	prepared, err := dispatcher.Prepare(context.Background(), state, GatewayOwnedRepairOperation, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.Changed || !prepared.RuntimeOnly || prepared.Timeout <= 0 || prepared.Apply == nil || prepared.Rollback == nil {
		t.Fatalf("owned repair preparation = %+v", prepared)
	}
	if err := prepared.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if executor.calls != 1 || executor.batch.TargetGeneration != batch.TargetGeneration {
		t.Fatalf("owned repair executor = calls:%d batch:%+v", executor.calls, executor.batch)
	}
	var result operations.RepairExecutionResult
	if err := json.Unmarshal(prepared.Result(), &result); err != nil || result.Validate(batch) != nil {
		t.Fatalf("owned repair result = %+v, %v", result, err)
	}
}

func TestGatewayOwnedRepairRejectsStaleOrBroadenedPayloadBeforeExecution(t *testing.T) {
	t.Parallel()

	state := gatewayRepairTestState(t)
	executor := &recordingGatewayOwnedRepairExecutor{}
	dispatcher, _ := NewGatewayOwnedRepairDispatcher(executor)
	batch := gatewayOwnedRepairTestBatch(t, state.Generation+1)
	payload, _ := json.Marshal(GatewayOwnedRepairPayload{Batch: batch})
	if _, err := dispatcher.Prepare(context.Background(), state, GatewayOwnedRepairOperation, payload); !errors.Is(err, operations.ErrRepairConflict) {
		t.Fatalf("stale owned repair error = %v", err)
	}
	payload = append(payload[:len(payload)-1], []byte(`,"extra":true}`)...)
	if _, err := dispatcher.Prepare(context.Background(), state, GatewayOwnedRepairOperation, payload); !errors.Is(err, operations.ErrRepairInvalid) {
		t.Fatalf("broadened owned repair error = %v", err)
	}
	if executor.calls != 0 {
		t.Fatal("rejected owned repair reached executor")
	}
}

func TestGatewayOwnedRepairSeparatesCurrentAuthorityFromOlderAppliedTarget(t *testing.T) {
	t.Parallel()

	state := gatewayRepairTestState(t)
	batch := gatewayOwnedRepairTestBatch(t, state.Generation)
	state.Generation += 2
	executor := &recordingGatewayOwnedRepairExecutor{}
	dispatcher, _ := NewGatewayOwnedRepairDispatcher(executor)
	payload, _ := json.Marshal(GatewayOwnedRepairPayload{Batch: batch})
	prepared, err := dispatcher.Prepare(context.Background(), state, GatewayOwnedRepairOperation, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Apply(context.Background()); err != nil || executor.calls != 1 {
		t.Fatalf("older Applied repair execution = calls:%d error:%v", executor.calls, err)
	}
	if prepared.Candidate.Generation != state.Generation || !prepared.RuntimeOnly {
		t.Fatalf("older Applied repair changed current authority: %+v", prepared)
	}
}

func gatewayOwnedRepairTestBatch(t *testing.T, generation uint64) operations.RepairExecutionBatch {
	t.Helper()
	key := operations.ManagedResourceKey{
		Component: "role.gateway", Kind: operations.ManagedResourceFile,
		ID: "/etc/vpnctl/generated/gateway/bootstrap.conf",
	}
	target := operations.ManagedFingerprint([]byte("gateway bootstrap"))
	drift := operations.OwnedDrift{
		Resource: key, Kind: operations.OwnedDriftMissing,
		Impact: operations.ConvergenceImpactAvailability, ExpectedSHA256: target,
	}
	convergence := operations.ConvergencePlan{
		DesiredGeneration: generation, AppliedGeneration: generation,
		Impact:  operations.ConvergenceImpactAvailability,
		Changes: []operations.DesiredChange{}, Drift: []operations.OwnedDrift{drift},
	}
	resolver, err := operations.NewLocalRoleRepairScopeResolver(model.RoleGateway, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := operations.BuildRepairPlan(model.RoleGateway, "", convergence, resolver)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := operations.NewRepairExecutionBatch(plan)
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

type recordingGatewayOwnedRepairExecutor struct {
	calls int
	batch operations.RepairExecutionBatch
}

func (executor *recordingGatewayOwnedRepairExecutor) RepairGateway(
	_ context.Context,
	batch operations.RepairExecutionBatch,
) (operations.RepairExecutionResult, error) {
	executor.calls++
	executor.batch = batch
	resources := make([]operations.RepairResourceResult, len(batch.Actions))
	for index, action := range batch.Actions {
		resources[index] = operations.RepairResourceResult{
			Resource: action.Resource, Present: true, RuntimeSHA256: action.TargetSHA256,
		}
	}
	return operations.RepairExecutionResult{Changed: true, TargetGeneration: batch.TargetGeneration, Resources: resources}, nil
}
