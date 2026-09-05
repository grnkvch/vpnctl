package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"golang.org/x/sys/unix"
)

const repairLockFileName = "repair.lock"

type repairStateReader interface {
	Load() (model.State, error)
}

type stateBoundConvergenceRepair struct {
	role        model.Role
	nodeID      string
	state       repairStateReader
	source      operations.ConvergenceSnapshotSource
	material    operations.AppliedMaterialLoader
	coordinator *operations.RepairCoordinator
	transaction repairTransaction

	mu              sync.Mutex
	plannedState    model.State
	plannedSnapshot operations.ConvergenceSnapshot
	planned         bool
}

type repairTransaction interface {
	Acquire(context.Context) (func(), error)
}

func newStateBoundConvergenceRepair(
	role model.Role,
	nodeID string,
	state repairStateReader,
	source operations.ConvergenceSnapshotSource,
	material operations.AppliedMaterialLoader,
	coordinator *operations.RepairCoordinator,
	transaction repairTransaction,
) (*stateBoundConvergenceRepair, error) {
	if state == nil || source == nil || material == nil || coordinator == nil {
		return nil, fmt.Errorf("state-bound convergence repair dependencies are incomplete")
	}
	if role == model.RoleGateway && (nodeID != "" || transaction != nil) ||
		role == model.RoleNode && (model.ValidateResourceID(nodeID) != nil || transaction == nil) ||
		role != model.RoleGateway && role != model.RoleNode {
		return nil, fmt.Errorf("state-bound convergence repair identity is invalid")
	}
	return &stateBoundConvergenceRepair{
		role: role, nodeID: nodeID, state: state, source: source,
		material: material, coordinator: coordinator, transaction: transaction,
	}, nil
}

func (repair *stateBoundConvergenceRepair) Plan(ctx context.Context) (operations.RepairPlan, error) {
	if ctx == nil || repair == nil || repair.coordinator == nil {
		return operations.RepairPlan{}, operations.ErrRepairInvalid
	}
	before, snapshotBefore, err := repair.currentBoundary(ctx)
	if err != nil {
		return operations.RepairPlan{}, err
	}
	plan, err := repair.coordinator.Plan(ctx)
	if err != nil {
		return operations.RepairPlan{}, err
	}
	after, snapshotAfter, err := repair.currentBoundary(ctx)
	if err != nil {
		return operations.RepairPlan{}, err
	}
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(snapshotBefore, snapshotAfter) ||
		plan.TargetGeneration != snapshotAfter.Applied.Generation {
		return operations.RepairPlan{}, operations.ErrRepairConflict
	}
	repair.mu.Lock()
	repair.plannedState = after
	repair.plannedSnapshot = snapshotAfter
	repair.planned = true
	repair.mu.Unlock()
	return plan, nil
}

func (repair *stateBoundConvergenceRepair) Repair(ctx context.Context, approved operations.RepairPlan) (operations.RepairResult, error) {
	if ctx == nil || repair == nil || repair.coordinator == nil {
		return operations.RepairResult{}, operations.ErrRepairInvalid
	}
	if err := approved.Validate(); err != nil || approved.Role != repair.role || approved.CurrentNodeID != repair.nodeID {
		return operations.RepairResult{}, errors.Join(operations.ErrRepairInvalid, err)
	}
	release := func() {}
	if repair.transaction != nil {
		var err error
		release, err = repair.transaction.Acquire(ctx)
		if err != nil {
			return operations.RepairResult{}, err
		}
	}
	defer release()
	repair.mu.Lock()
	plannedState, plannedSnapshot, planned := repair.plannedState, repair.plannedSnapshot, repair.planned
	repair.mu.Unlock()
	if !planned {
		return operations.RepairResult{}, operations.ErrRepairInvalid
	}

	before, snapshot, err := repair.currentBoundary(ctx)
	if err != nil {
		return operations.RepairResult{}, err
	}
	if !reflect.DeepEqual(before, plannedState) || !reflect.DeepEqual(snapshot, plannedSnapshot) ||
		snapshot.Applied.Generation != approved.TargetGeneration {
		return operations.RepairResult{}, operations.ErrRepairConflict
	}
	boundContext := context.WithValue(ctx, repairAuthorityContextKey{}, before.Generation)
	result, err := repair.coordinator.Repair(boundContext, approved)
	if err != nil {
		return operations.RepairResult{}, err
	}
	after, snapshotAfter, err := repair.currentBoundary(ctx)
	if err != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(snapshot, snapshotAfter) {
		return operations.RepairResult{}, errors.Join(operations.ErrRepairConflict, err)
	}
	return result, nil
}

func (repair *stateBoundConvergenceRepair) currentBoundary(ctx context.Context) (model.State, operations.ConvergenceSnapshot, error) {
	state, err := repair.state.Load()
	if err != nil {
		return model.State{}, operations.ConvergenceSnapshot{}, err
	}
	if err := validateRepairAuthority(state, repair.role, repair.nodeID); err != nil {
		return model.State{}, operations.ConvergenceSnapshot{}, err
	}
	snapshot, err := repair.source.ReadConvergenceSnapshot(ctx)
	if err != nil || !genericRepairBoundaryEligible(state, snapshot) {
		return model.State{}, operations.ConvergenceSnapshot{}, errors.Join(operations.ErrRepairConflict, err)
	}
	material, err := repair.material.Load(ctx, snapshot.Applied)
	if err != nil {
		return model.State{}, operations.ConvergenceSnapshot{}, errors.Join(operations.ErrRepairConflict, err)
	}
	material.Destroy()
	return state, snapshot, nil
}

func genericRepairBoundaryEligible(state model.State, snapshot operations.ConvergenceSnapshot) bool {
	if snapshot.Applied.Generation > state.Generation || snapshot.Desired.Generation > state.Generation {
		return false
	}
	if snapshot.Applied.Generation == state.Generation {
		return true
	}
	if len(snapshot.Pending) != 0 {
		return true
	}
	for _, operation := range state.Operations {
		if operation.State == model.OperationPending {
			return true
		}
	}
	return false
}

type repairAuthorityContextKey struct{}

func repairAuthorityGeneration(ctx context.Context) (uint64, bool) {
	generation, ok := ctx.Value(repairAuthorityContextKey{}).(uint64)
	return generation, ok && generation != 0
}

func validateRepairAuthority(state model.State, role model.Role, nodeID string) error {
	if err := state.Validate(); err != nil || state.Host.Role != role {
		return errors.Join(operations.ErrRepairInvalid, err)
	}
	if role == model.RoleGateway {
		if nodeID != "" {
			return operations.ErrRepairInvalid
		}
		return nil
	}
	if len(state.Nodes) != 1 || state.Nodes[0].ID != nodeID || state.Nodes[0].Lifecycle != model.LifecycleActive || state.Nodes[0].Gateway == nil {
		return operations.ErrRepairInvalid
	}
	return nil
}

type localGatewayOwnedRepairExecutor struct {
	socketPath string
	call       func(context.Context, string, control.LocalRequest) (control.LocalResponse, error)
}

func (executor localGatewayOwnedRepairExecutor) RepairGateway(
	ctx context.Context,
	batch operations.RepairExecutionBatch,
) (operations.RepairExecutionResult, error) {
	if ctx == nil || executor.socketPath == "" || executor.call == nil {
		return operations.RepairExecutionResult{}, operations.ErrRepairInvalid
	}
	if err := batch.Validate(); err != nil || batch.Role != model.RoleGateway || len(batch.Actions) == 0 {
		return operations.RepairExecutionResult{}, errors.Join(operations.ErrRepairInvalid, err)
	}
	authorityGeneration, ok := repairAuthorityGeneration(ctx)
	if !ok || authorityGeneration < batch.TargetGeneration || authorityGeneration < batch.Convergence.DesiredGeneration {
		return operations.RepairExecutionResult{}, operations.ErrRepairConflict
	}
	payload, err := json.Marshal(controller.GatewayOwnedRepairPayload{Batch: batch})
	if err != nil {
		return operations.RepairExecutionResult{}, err
	}
	response, err := executor.call(ctx, executor.socketPath, control.LocalRequest{
		SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate,
		Operation: controller.GatewayOwnedRepairOperation, ExpectedGeneration: authorityGeneration, Payload: payload,
	})
	if err != nil {
		return operations.RepairExecutionResult{}, errors.Join(ErrCommittedGatewayRepairUncertain, err)
	}
	if !response.OK {
		switch response.ErrorCode {
		case "generation_conflict", "mutation_failed":
			return operations.RepairExecutionResult{}, operations.ErrRepairConflict
		case "state_unavailable", "unsupported_operation", "unsupported_method":
			return operations.RepairExecutionResult{}, ErrCommittedGatewayRepairUnavailable
		default:
			return operations.RepairExecutionResult{}, fmt.Errorf("gateway owned repair failed: %s", response.ErrorCode)
		}
	}
	if response.Generation != authorityGeneration {
		return operations.RepairExecutionResult{}, operations.ErrRepairConflict
	}
	var result operations.RepairExecutionResult
	if err := control.DecodeRPCPayload(response.Data, &result); err != nil {
		return operations.RepairExecutionResult{}, err
	}
	if err := result.Validate(batch); err != nil {
		return operations.RepairExecutionResult{}, errors.Join(operations.ErrRepairInvalid, err)
	}
	return result, nil
}

type currentNodeOwnedRepairExecutor struct {
	probe *operations.RemoteRepairGatewayProbe
	local *operations.LocalRoleRepairExecutor
}

func (executor currentNodeOwnedRepairExecutor) RequireGateway(ctx context.Context, nodeID string) error {
	if executor.probe == nil {
		return operations.ErrRepairGatewayUnavailable
	}
	return executor.probe.RequireGateway(ctx, nodeID)
}

func (executor currentNodeOwnedRepairExecutor) RepairCurrentNode(
	ctx context.Context,
	batch operations.RepairExecutionBatch,
) (operations.RepairExecutionResult, error) {
	if executor.local == nil {
		return operations.RepairExecutionResult{}, operations.ErrRepairInvalid
	}
	return executor.local.RepairCurrentNode(ctx, batch)
}

type fileRepairTransaction struct {
	path string
}

func newFileRepairTransaction(runtimeDir string) (*fileRepairTransaction, error) {
	if !filepath.IsAbs(runtimeDir) || filepath.Clean(runtimeDir) != runtimeDir {
		return nil, fmt.Errorf("repair runtime directory must be clean and absolute")
	}
	return &fileRepairTransaction{path: filepath.Join(runtimeDir, repairLockFileName)}, nil
}

func (transaction *fileRepairTransaction) Acquire(ctx context.Context) (func(), error) {
	if ctx == nil || transaction == nil || transaction.path == "" {
		return nil, operations.ErrRepairInvalid
	}
	directory := filepath.Dir(transaction.path)
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("repair runtime directory must be a real mode-0700 directory")
	}
	directoryStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || directoryStat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("repair runtime directory must be owned by the current privileged user")
	}
	descriptor, err := unix.Open(transaction.path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open node repair lock: %w", err)
	}
	lock := os.NewFile(uintptr(descriptor), transaction.path)
	keep := false
	defer func() {
		if !keep {
			_ = lock.Close()
		}
	}()
	lockInfo, err := lock.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect node repair lock: %w", err)
	}
	stat, statOK := lockInfo.Sys().(*syscall.Stat_t)
	if !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0o600 || !statOK || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("node repair lock must be an owned 0600 single-link regular file")
	}
	for {
		err = unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("lock node repair transaction: %w", err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	keep = true
	return func() {
		_ = unix.Flock(descriptor, unix.LOCK_UN)
		_ = lock.Close()
	}, nil
}

func buildSystemGatewayConvergenceRepair(paths store.Paths) (ConvergenceRepairOperator, error) {
	state, source, material, planner, resolver, err := buildSystemRepairPlanning(paths, model.RoleGateway, "")
	if err != nil {
		return nil, err
	}
	executor := localGatewayOwnedRepairExecutor{socketPath: paths.ControlSocket, call: control.CallLocalMutation}
	coordinator, err := operations.NewGatewayRepairCoordinator(planner, resolver, executor)
	if err != nil {
		return nil, err
	}
	return newStateBoundConvergenceRepair(model.RoleGateway, "", state, source, material, coordinator, nil)
}

func buildSystemNodeConvergenceRepair(paths store.Paths) (ConvergenceRepairOperator, error) {
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	current, err := state.Load()
	if err != nil || current.Host.Role != model.RoleNode || len(current.Nodes) != 1 {
		return nil, errors.Join(operations.ErrRepairInvalid, err)
	}
	nodeID := current.Nodes[0].ID
	_, source, material, planner, resolver, err := buildSystemRepairPlanning(paths, model.RoleNode, nodeID)
	if err != nil {
		return nil, err
	}
	discoverer, err := operations.NewSystemOwnedResourceDiscoverer(paths.Root, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, err
	}
	host, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, err
	}
	local, err := operations.NewLocalRoleRepairExecutor(model.RoleNode, nodeID, source, discoverer, resolver, material, host)
	if err != nil {
		return nil, err
	}
	probe, err := operations.NewSystemRemoteRepairGatewayProbe(paths, nil)
	if err != nil {
		return nil, err
	}
	executor := currentNodeOwnedRepairExecutor{probe: probe, local: local}
	coordinator, err := operations.NewNodeRepairCoordinator(nodeID, planner, resolver, executor)
	if err != nil {
		return nil, err
	}
	transaction, err := newFileRepairTransaction(paths.RuntimeDir)
	if err != nil {
		return nil, err
	}
	return newStateBoundConvergenceRepair(model.RoleNode, nodeID, state, source, material, coordinator, transaction)
}

func buildSystemRepairPlanning(
	paths store.Paths,
	role model.Role,
	nodeID string,
) (*store.StateStore, *operations.FileConvergenceSnapshotSource, *operations.FileAppliedMaterialArchive, *operations.ConvergencePlanner, *operations.LocalRoleRepairScopeResolver, error) {
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	source, err := operations.NewFileConvergenceSnapshotSource(paths.ConvergenceFile)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	discoverer, err := operations.NewSystemOwnedResourceDiscoverer(paths.Root, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	planner, err := operations.NewConvergencePlanner(source, discoverer)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	resolver, err := operations.NewLocalRoleRepairScopeResolver(role, nodeID)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	material, err := operations.NewFileAppliedMaterialArchive(paths.AppliedMaterialDir)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return state, source, material, planner, resolver, nil
}

func systemConvergenceRepairEligible(ctx context.Context, paths store.Paths, role HostRole) bool {
	modelRole, ok := convergenceApplyModelRole(role)
	if ctx == nil || !ok {
		return false
	}
	state, err := store.NewStateStore(paths)
	if err != nil {
		return false
	}
	current, err := state.Load()
	nodeID := ""
	if modelRole == model.RoleNode && err == nil && len(current.Nodes) == 1 {
		nodeID = current.Nodes[0].ID
	}
	if err != nil || validateRepairAuthority(current, modelRole, nodeID) != nil {
		return false
	}
	_, source, material, _, _, err := buildSystemRepairPlanning(paths, modelRole, nodeID)
	if err != nil {
		return false
	}
	snapshot, err := source.ReadConvergenceSnapshot(ctx)
	if err != nil || !genericRepairBoundaryEligible(current, snapshot) {
		return false
	}
	retained, err := material.Load(ctx, snapshot.Applied)
	if err != nil {
		return false
	}
	retained.Destroy()
	return true
}

var (
	_ operations.GatewayRepairExecutor     = localGatewayOwnedRepairExecutor{}
	_ operations.CurrentNodeRepairExecutor = currentNodeOwnedRepairExecutor{}
	_ ConvergenceRepairOperator            = (*stateBoundConvergenceRepair)(nil)
)
