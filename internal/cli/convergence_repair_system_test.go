package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
)

func TestStateBoundConvergenceRepairKeepsAuthoritySnapshotAndMaterialTogether(t *testing.T) {
	t.Parallel()

	state := cliDNSState(model.RoleGateway)
	manifest, err := operations.NewConvergenceManifest(state.Generation, []operations.ManagedResource{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := operations.ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []operations.PendingOperation{}}
	source := &staticRepairSnapshotSource{snapshot: snapshot}
	planner, err := operations.NewConvergencePlanner(source, emptyRepairDiscoverer{})
	if err != nil {
		t.Fatal(err)
	}
	resolver, _ := operations.NewLocalRoleRepairScopeResolver(model.RoleGateway, "")
	executor := &noCallGatewayRepairExecutor{t: t}
	coordinator, err := operations.NewGatewayRepairCoordinator(planner, resolver, executor)
	if err != nil {
		t.Fatal(err)
	}
	reader := &mutableRepairStateReader{state: state}
	bound, err := newStateBoundConvergenceRepair(
		model.RoleGateway, "", reader, source, availableRepairMaterial{}, coordinator, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := bound.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Actions) != 0 || plan.TargetGeneration != state.Generation {
		t.Fatalf("state-bound no-op plan = %+v", plan)
	}
	result, err := bound.Repair(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Generation != state.Generation || result.Actions == nil || result.Resources == nil {
		t.Fatalf("state-bound no-op result = %+v", result)
	}

	reader.state.Generation++
	if _, err := bound.Plan(context.Background()); !errors.Is(err, operations.ErrRepairConflict) {
		t.Fatalf("authority/applied mismatch error = %v", err)
	}
}

func TestLocalGatewayOwnedRepairExecutorUsesGenerationBoundControllerMutation(t *testing.T) {
	t.Parallel()

	plan := convergenceRepairTestPlan(t)
	batch, err := operations.NewRepairExecutionBatch(plan)
	if err != nil {
		t.Fatal(err)
	}
	const authorityGeneration = 9
	var request control.LocalRequest
	executor := localGatewayOwnedRepairExecutor{
		socketPath: "/run/vpnctl/control.sock",
		call: func(_ context.Context, path string, received control.LocalRequest) (control.LocalResponse, error) {
			if path != "/run/vpnctl/control.sock" {
				t.Fatalf("owned repair socket = %s", path)
			}
			request = received
			resources := make([]operations.RepairResourceResult, len(batch.Actions))
			for index, action := range batch.Actions {
				resources[index] = operations.RepairResourceResult{Resource: action.Resource}
				if action.Action == operations.RepairRestore {
					resources[index].Present = true
					resources[index].RuntimeSHA256 = action.TargetSHA256
				}
			}
			encoded, _ := json.Marshal(operations.RepairExecutionResult{
				Changed: true, TargetGeneration: batch.TargetGeneration, Resources: resources,
			})
			return control.LocalResponse{
				SchemaVersion: control.LocalSchemaVersion, OK: true,
				Generation: authorityGeneration, Data: encoded,
			}, nil
		},
	}
	ctx := context.WithValue(context.Background(), repairAuthorityContextKey{}, uint64(authorityGeneration))
	result, err := executor.RepairGateway(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Validate(batch); err != nil {
		t.Fatal(err)
	}
	if request.Method != control.LocalMutate || request.Operation != "repair.owned" || request.ExpectedGeneration != authorityGeneration {
		t.Fatalf("owned repair local request = %+v", request)
	}
}

func TestGenericRepairBoundaryKeepsPendingIntentSeparateFromApplied(t *testing.T) {
	t.Parallel()

	state := model.State{Generation: 9}
	snapshot := operations.ConvergenceSnapshot{
		Desired: operations.ConvergenceManifest{Generation: 8},
		Applied: operations.ConvergenceManifest{Generation: 7},
		Pending: []operations.PendingOperation{{ID: "pending"}},
	}
	if !genericRepairBoundaryEligible(state, snapshot) {
		t.Fatal("registered pending intent incorrectly selected committed recovery")
	}
	snapshot.Pending = []operations.PendingOperation{}
	if genericRepairBoundaryEligible(state, snapshot) {
		t.Fatal("unexplained state/applied gap incorrectly selected generic repair")
	}
	state.Operations = []model.Operation{{State: model.OperationPending}}
	if !genericRepairBoundaryEligible(state, snapshot) {
		t.Fatal("locally retained pending operation incorrectly selected committed recovery")
	}
}

func TestFileRepairTransactionSerializesAndRejectsUnsafeLock(t *testing.T) {
	t.Parallel()

	runtimeDir := filepath.Join(t.TempDir(), "run", "vpnctl")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	transaction, err := newFileRepairTransaction(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	release, err := transaction.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := transaction.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrent repair lock error = %v", err)
	}
	release()
	release, err = transaction.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()

	if err := os.Remove(filepath.Join(runtimeDir, repairLockFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("foreign", filepath.Join(runtimeDir, repairLockFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Acquire(context.Background()); err == nil {
		t.Fatal("node repair accepted a symbolic-link lock")
	}
}

type staticRepairSnapshotSource struct {
	snapshot operations.ConvergenceSnapshot
}

func (source *staticRepairSnapshotSource) ReadConvergenceSnapshot(context.Context) (operations.ConvergenceSnapshot, error) {
	return source.snapshot, nil
}

type emptyRepairDiscoverer struct{}

func (emptyRepairDiscoverer) DiscoverOwnedResources(context.Context, operations.ConvergenceManifest) ([]operations.OwnedResourceObservation, error) {
	return []operations.OwnedResourceObservation{}, nil
}

type availableRepairMaterial struct{}

func (availableRepairMaterial) Load(context.Context, operations.ConvergenceManifest) (*operations.AppliedMaterialSet, error) {
	return &operations.AppliedMaterialSet{}, nil
}

type mutableRepairStateReader struct {
	state model.State
}

func (reader *mutableRepairStateReader) Load() (model.State, error) { return reader.state, nil }

type noCallGatewayRepairExecutor struct {
	t *testing.T
}

func (executor *noCallGatewayRepairExecutor) RepairGateway(context.Context, operations.RepairExecutionBatch) (operations.RepairExecutionResult, error) {
	executor.t.Fatal("no-op state-bound repair reached gateway executor")
	return operations.RepairExecutionResult{}, nil
}
