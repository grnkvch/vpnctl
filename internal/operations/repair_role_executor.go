package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

type AppliedMaterialLoader interface {
	Load(context.Context, ConvergenceManifest) (*AppliedMaterialSet, error)
}

type LocalRoleRepairHost interface {
	PlanRepair(context.Context, linuxplatform.RoleRepairRequest) (*linuxplatform.RoleRepairPlan, error)
	ApplyRepair(context.Context, *linuxplatform.RoleRepairPlan) (linuxplatform.RoleRepairResult, error)
}

// LocalRoleRepairExecutor is the material-to-host bridge. Callers must provide
// the surrounding host mutation lock: the gateway controller already does so,
// while the node command owns its process-local transaction boundary.
type LocalRoleRepairExecutor struct {
	role     model.Role
	nodeID   string
	source   ConvergenceSnapshotSource
	planner  *ConvergencePlanner
	resolver RepairScopeResolver
	material AppliedMaterialLoader
	host     LocalRoleRepairHost
}

func NewLocalRoleRepairExecutor(
	role model.Role,
	nodeID string,
	source ConvergenceSnapshotSource,
	discoverer OwnedResourceDiscoverer,
	resolver RepairScopeResolver,
	material AppliedMaterialLoader,
	host LocalRoleRepairHost,
) (*LocalRoleRepairExecutor, error) {
	if nilInterface(source) || nilInterface(discoverer) || nilInterface(resolver) || nilInterface(material) || nilInterface(host) {
		return nil, fmt.Errorf("local role repair executor dependencies are incomplete")
	}
	if role == model.RoleGateway && nodeID != "" || role == model.RoleNode && model.ValidateResourceID(nodeID) != nil || role != model.RoleGateway && role != model.RoleNode {
		return nil, fmt.Errorf("local role repair executor identity is invalid")
	}
	planner, err := NewConvergencePlanner(source, discoverer)
	if err != nil {
		return nil, err
	}
	return &LocalRoleRepairExecutor{
		role: role, nodeID: nodeID, source: source, planner: planner,
		resolver: resolver, material: material, host: host,
	}, nil
}

func (executor *LocalRoleRepairExecutor) RepairGateway(ctx context.Context, batch RepairExecutionBatch) (RepairExecutionResult, error) {
	if executor == nil || executor.role != model.RoleGateway || executor.nodeID != "" {
		return RepairExecutionResult{}, ErrRepairInvalid
	}
	return executor.execute(ctx, batch)
}

func (executor *LocalRoleRepairExecutor) RepairCurrentNode(ctx context.Context, batch RepairExecutionBatch) (RepairExecutionResult, error) {
	if executor == nil || executor.role != model.RoleNode || model.ValidateResourceID(executor.nodeID) != nil {
		return RepairExecutionResult{}, ErrRepairInvalid
	}
	return executor.execute(ctx, batch)
}

func (executor *LocalRoleRepairExecutor) execute(ctx context.Context, batch RepairExecutionBatch) (RepairExecutionResult, error) {
	if ctx == nil || executor == nil || executor.planner == nil || nilInterface(executor.source) ||
		nilInterface(executor.resolver) || nilInterface(executor.material) || nilInterface(executor.host) {
		return RepairExecutionResult{}, ErrRepairInvalid
	}
	if len(batch.Actions) == 0 || batch.Role != executor.role || batch.CurrentNodeID != executor.nodeID {
		return RepairExecutionResult{}, ErrRepairInvalid
	}
	fresh, snapshot, err := executor.freshBatch(ctx)
	if err != nil {
		return RepairExecutionResult{}, err
	}
	if !reflect.DeepEqual(batch, fresh) {
		return RepairExecutionResult{}, ErrRepairConflict
	}
	material, err := executor.material.Load(ctx, snapshot.Applied)
	if err != nil {
		return RepairExecutionResult{}, fmt.Errorf("load applied repair material: %w", err)
	}
	defer material.Destroy()
	request, err := executor.roleRequest(batch, material)
	if err != nil {
		return RepairExecutionResult{}, err
	}
	defer wipeLinuxRoleRepairRequest(&request)
	prepared, err := executor.host.PlanRepair(ctx, request)
	if err != nil {
		return RepairExecutionResult{}, fmt.Errorf("preflight local role repair: %w", err)
	}
	keepPrepared := false
	defer func() {
		if !keepPrepared {
			prepared.Destroy()
		}
	}()
	second, secondSnapshot, err := executor.freshBatch(ctx)
	if err != nil || !reflect.DeepEqual(secondSnapshot, snapshot) || !reflect.DeepEqual(second, batch) {
		return RepairExecutionResult{}, errors.Join(ErrRepairConflict, err)
	}
	keepPrepared = true
	hostResult, err := executor.host.ApplyRepair(ctx, prepared)
	if err != nil {
		return RepairExecutionResult{}, fmt.Errorf("apply local role repair: %w", err)
	}
	resources := make([]RepairResourceResult, len(batch.Actions))
	changed := false
	if len(hostResult.Resources) != len(batch.Actions) {
		return RepairExecutionResult{}, ErrRepairInvalid
	}
	for index, action := range batch.Actions {
		result := hostResult.Resources[index]
		if result.Name != roleRepairResourceName(action.Resource) || result.Kind != roleRepairResourceKind(action.Resource) {
			return RepairExecutionResult{}, ErrRepairInvalid
		}
		if !result.Changed || result.ContentSHA256 != request.Resources[index].ContentSHA256 {
			return RepairExecutionResult{}, ErrRepairInvalid
		}
		changed = changed || result.Changed
		resources[index] = RepairResourceResult{
			Resource: action.Resource, Present: true, RuntimeSHA256: action.TargetSHA256,
		}
	}
	return RepairExecutionResult{
		Changed: changed, TargetGeneration: batch.TargetGeneration, Resources: resources,
	}, nil
}

func (executor *LocalRoleRepairExecutor) freshBatch(ctx context.Context) (RepairExecutionBatch, ConvergenceSnapshot, error) {
	before, err := executor.source.ReadConvergenceSnapshot(ctx)
	if err != nil {
		return RepairExecutionBatch{}, ConvergenceSnapshot{}, err
	}
	before, err = canonicalSnapshot(before)
	if err != nil {
		return RepairExecutionBatch{}, ConvergenceSnapshot{}, err
	}
	convergence, err := executor.planner.Plan(ctx)
	if err != nil {
		return RepairExecutionBatch{}, ConvergenceSnapshot{}, err
	}
	plan, err := BuildRepairPlan(executor.role, executor.nodeID, convergence, executor.resolver)
	if err != nil {
		return RepairExecutionBatch{}, ConvergenceSnapshot{}, err
	}
	after, err := executor.source.ReadConvergenceSnapshot(ctx)
	if err != nil {
		return RepairExecutionBatch{}, ConvergenceSnapshot{}, err
	}
	after, err = canonicalSnapshot(after)
	if err != nil || !reflect.DeepEqual(before, after) {
		return RepairExecutionBatch{}, ConvergenceSnapshot{}, errors.Join(ErrRepairConflict, err)
	}
	return repairExecutionBatch(plan), after, nil
}

func (executor *LocalRoleRepairExecutor) roleRequest(
	batch RepairExecutionBatch,
	material *AppliedMaterialSet,
) (linuxplatform.RoleRepairRequest, error) {
	request := linuxplatform.RoleRepairRequest{
		Role: executor.role, Resources: make([]linuxplatform.RoleRepairResource, 0, len(batch.Actions)), RestartUnits: []string{},
	}
	selectedUnits := make(map[string]struct{})
	restartUnits := make(map[string]struct{})
	for _, action := range batch.Actions {
		if action.Action != RepairRestore || action.Resource.Kind != ManagedResourceFile && action.Resource.Kind != ManagedResourceUnit {
			wipeLinuxRoleRepairRequest(&request)
			return linuxplatform.RoleRepairRequest{}, fmt.Errorf("%w: local role executor is restore-only", ErrRepairInvalid)
		}
		if action.Resource.Kind == ManagedResourceUnit {
			selectedUnits[action.Resource.ID] = struct{}{}
		}
		for _, name := range action.RestartUnits {
			restartUnits[name] = struct{}{}
		}
		err := material.Use(action.Resource, func(mode os.FileMode, content []byte, runtime *ManagedUnitRuntime) error {
			kind := roleRepairResourceKind(action.Resource)
			wantMode := os.FileMode(0o600)
			if kind == linuxplatform.RoleRepairUnit {
				wantMode = 0o644
			}
			if mode != wantMode {
				return ErrRepairInvalid
			}
			digest := sha256.Sum256(content)
			resource := linuxplatform.RoleRepairResource{
				Kind: kind, Name: roleRepairResourceName(action.Resource),
				Content: append([]byte(nil), content...), ContentSHA256: hex.EncodeToString(digest[:]),
			}
			if kind == linuxplatform.RoleRepairUnit {
				if runtime == nil {
					clear(resource.Content)
					return ErrRepairInvalid
				}
				resource.UnitTarget = &linuxplatform.RoleRepairUnitTarget{
					LoadState: runtime.LoadState, ActiveState: runtime.ActiveState,
					SubState: runtime.SubState, Enablement: runtime.Enablement,
				}
			} else if runtime != nil {
				clear(resource.Content)
				return ErrRepairInvalid
			}
			request.Resources = append(request.Resources, resource)
			return nil
		})
		if err != nil {
			wipeLinuxRoleRepairRequest(&request)
			return linuxplatform.RoleRepairRequest{}, fmt.Errorf("bind applied repair material: %w", err)
		}
	}
	for _, name := range roleRepairRestartOrder(executor.role) {
		if _, selected := selectedUnits[name]; selected {
			delete(restartUnits, name)
			continue
		}
		if _, restart := restartUnits[name]; restart {
			request.RestartUnits = append(request.RestartUnits, name)
			delete(restartUnits, name)
		}
	}
	if len(restartUnits) != 0 {
		wipeLinuxRoleRepairRequest(&request)
		return linuxplatform.RoleRepairRequest{}, fmt.Errorf("%w: repair dependency is outside the local role", ErrRepairInvalid)
	}
	return request, nil
}

func roleRepairResourceKind(resource ManagedResourceKey) linuxplatform.RoleRepairResourceKind {
	if resource.Kind == ManagedResourceUnit {
		return linuxplatform.RoleRepairUnit
	}
	return linuxplatform.RoleRepairConfig
}

func roleRepairResourceName(resource ManagedResourceKey) string {
	if resource.Kind == ManagedResourceFile {
		return filepath.Base(resource.ID)
	}
	return resource.ID
}

func roleRepairRestartOrder(role model.Role) []string {
	if role == model.RoleNode {
		return []string{
			"vpnctl-standard.service", "vpnctl-routing-guard.service",
			"vpnctl-routing.service", "vpnctl-tunnel-client.service",
		}
	}
	return []string{
		"vpnctl-standard.service", "vpnctl-dns.service", "vpnctl-restricted.service",
		"vpnctl-tunnel-server.service", "vpnctl-controller.service",
	}
}

func wipeLinuxRoleRepairRequest(request *linuxplatform.RoleRepairRequest) {
	if request == nil {
		return
	}
	for index := range request.Resources {
		clear(request.Resources[index].Content)
		request.Resources[index].Content = nil
	}
	*request = linuxplatform.RoleRepairRequest{}
}

var _ GatewayRepairExecutor = (*LocalRoleRepairExecutor)(nil)
