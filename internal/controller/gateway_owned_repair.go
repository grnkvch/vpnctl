package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const GatewayOwnedRepairOperation = "repair.owned"

type GatewayOwnedRepairPayload struct {
	Batch operations.RepairExecutionBatch `json:"batch"`
}

// GatewayOwnedRepairDispatcher executes an already previewed, action-scoped
// drift repair under the controller mutation lock. It never changes desired
// state; LocalRoleRepairExecutor owns rollback of its selected host resources.
type GatewayOwnedRepairDispatcher struct {
	executor operations.GatewayRepairExecutor
}

func NewGatewayOwnedRepairDispatcher(executor operations.GatewayRepairExecutor) (*GatewayOwnedRepairDispatcher, error) {
	if executor == nil {
		return nil, fmt.Errorf("gateway owned repair executor is required")
	}
	return &GatewayOwnedRepairDispatcher{executor: executor}, nil
}

func NewSystemGatewayOwnedRepairDispatcher(paths store.Paths) (*GatewayOwnedRepairDispatcher, error) {
	source, err := operations.NewFileConvergenceSnapshotSource(paths.ConvergenceFile)
	if err != nil {
		return nil, err
	}
	discoverer, err := operations.NewSystemOwnedResourceDiscoverer(paths.Root, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, err
	}
	resolver, err := operations.NewLocalRoleRepairScopeResolver(model.RoleGateway, "")
	if err != nil {
		return nil, err
	}
	material, err := operations.NewFileAppliedMaterialArchive(paths.AppliedMaterialDir)
	if err != nil {
		return nil, err
	}
	host, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, err
	}
	executor, err := operations.NewLocalRoleRepairExecutor(
		model.RoleGateway, "", source, discoverer, resolver, material, host,
	)
	if err != nil {
		return nil, err
	}
	return NewGatewayOwnedRepairDispatcher(executor)
}

func (dispatcher *GatewayOwnedRepairDispatcher) Prepare(
	ctx context.Context,
	state model.State,
	operation string,
	payload json.RawMessage,
) (PreparedMutation, error) {
	if ctx == nil || dispatcher == nil || dispatcher.executor == nil || operation != GatewayOwnedRepairOperation {
		return PreparedMutation{}, operations.ErrRepairInvalid
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return PreparedMutation{}, errors.Join(operations.ErrRepairInvalid, err)
	}
	var request GatewayOwnedRepairPayload
	if err := control.DecodeRPCPayload(payload, &request); err != nil {
		return PreparedMutation{}, errors.Join(operations.ErrRepairInvalid, err)
	}
	if err := request.Batch.Validate(); err != nil || request.Batch.Role != model.RoleGateway ||
		request.Batch.CurrentNodeID != "" || len(request.Batch.Actions) == 0 ||
		request.Batch.TargetGeneration > state.Generation || request.Batch.Convergence.DesiredGeneration > state.Generation {
		return PreparedMutation{}, errors.Join(operations.ErrRepairConflict, err)
	}

	var result operations.RepairExecutionResult
	return PreparedMutation{
		Candidate: state, Changed: true, RuntimeOnly: true,
		Timeout: control.LocalMaximumMutationTimeout,
		Apply: func(applyContext context.Context) error {
			var err error
			result, err = dispatcher.executor.RepairGateway(applyContext, request.Batch)
			if err != nil {
				return err
			}
			return result.Validate(request.Batch)
		},
		Rollback: func(context.Context) error { return nil },
		Result: func() json.RawMessage {
			encoded, _ := json.Marshal(result)
			return encoded
		},
	}, nil
}
