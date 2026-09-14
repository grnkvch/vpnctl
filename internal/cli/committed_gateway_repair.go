package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	ErrCommittedGatewayRepairInvalid     = errors.New("committed gateway repair plan is invalid")
	ErrCommittedGatewayRepairStale       = errors.New("committed gateway repair plan is stale")
	ErrCommittedGatewayRepairPending     = errors.New("committed gateway repair is pending")
	ErrCommittedGatewayRepairUnavailable = errors.New("gateway controller is unavailable")
	ErrCommittedGatewayRepairUncertain   = errors.New("committed gateway repair outcome is uncertain")
)

type CommittedGatewayRepairOperator interface {
	Plan(context.Context) (controller.GatewayRepairPlan, error)
	Repair(context.Context, controller.GatewayRepairPlan) (controller.GatewayRepairData, error)
}

type committedGatewayRepairState interface {
	Load() (model.State, error)
}

type committedGatewayRepairPlanner interface {
	Plan(context.Context, model.State) (controller.GatewayRepairPlan, error)
}

type committedGatewayRepairLocalDispatcher interface {
	committedGatewayRepairPlanner
	Prepare(context.Context, model.State, string, json.RawMessage) (controller.PreparedMutation, error)
}

type committedGatewayRepairLocker func(context.Context, string, bool) (func(), error)

type systemCommittedGatewayRepair struct {
	state           committedGatewayRepairState
	planner         committedGatewayRepairPlanner
	localDispatcher committedGatewayRepairLocalDispatcher
	runtimeDir      string
	socketPath      string
	call            func(context.Context, string, control.LocalRequest) (control.LocalResponse, error)
	acquireLock     committedGatewayRepairLocker
}

func newSystemCommittedGatewayRepair(
	state committedGatewayRepairState,
	planner committedGatewayRepairPlanner,
	localDispatcher committedGatewayRepairLocalDispatcher,
	runtimeDir string,
	socketPath string,
	call func(context.Context, string, control.LocalRequest) (control.LocalResponse, error),
	acquireLock committedGatewayRepairLocker,
) (*systemCommittedGatewayRepair, error) {
	if state == nil || planner == nil || localDispatcher == nil || runtimeDir == "" || socketPath == "" || call == nil || acquireLock == nil {
		return nil, fmt.Errorf("committed gateway repair dependencies are incomplete")
	}
	return &systemCommittedGatewayRepair{
		state: state, planner: planner, localDispatcher: localDispatcher, runtimeDir: runtimeDir,
		socketPath: socketPath, call: call, acquireLock: acquireLock,
	}, nil
}

func buildSystemCommittedGatewayRepair(paths store.Paths) (CommittedGatewayRepairOperator, error) {
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	planner, err := controller.NewSystemGatewayRepairDispatcher(paths)
	if err != nil {
		return nil, err
	}
	return newSystemCommittedGatewayRepair(
		state, planner, planner, paths.RuntimeDir, paths.ControlSocket,
		control.CallLocalMutation, controller.AcquireGatewayMutationLock,
	)
}

func (repair *systemCommittedGatewayRepair) Plan(ctx context.Context) (controller.GatewayRepairPlan, error) {
	if ctx == nil || repair == nil || repair.state == nil || repair.planner == nil {
		return controller.GatewayRepairPlan{}, ErrCommittedGatewayRepairInvalid
	}
	state, err := repair.state.Load()
	if err != nil {
		return controller.GatewayRepairPlan{}, fmt.Errorf("load committed gateway repair state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return controller.GatewayRepairPlan{}, ErrCommittedGatewayRepairInvalid
	}
	plan, err := repair.planner.Plan(ctx, state)
	if err != nil {
		return controller.GatewayRepairPlan{}, err
	}
	if err := plan.Validate(); err != nil {
		return controller.GatewayRepairPlan{}, errors.Join(ErrCommittedGatewayRepairInvalid, err)
	}
	return cloneCommittedGatewayRepairPlan(plan), nil
}

func (repair *systemCommittedGatewayRepair) Repair(ctx context.Context, plan controller.GatewayRepairPlan) (controller.GatewayRepairData, error) {
	if ctx == nil || repair == nil || repair.call == nil {
		return controller.GatewayRepairData{}, ErrCommittedGatewayRepairInvalid
	}
	if err := plan.Validate(); err != nil {
		return controller.GatewayRepairData{}, errors.Join(ErrCommittedGatewayRepairInvalid, err)
	}
	fresh, err := repair.state.Load()
	if err != nil {
		return controller.GatewayRepairData{}, err
	}
	if fresh.Generation != plan.Generation || fresh.Host.Role != model.RoleGateway || fresh.Host.ID != plan.HostID {
		return controller.GatewayRepairData{}, ErrCommittedGatewayRepairStale
	}
	if plan.Bootstrap.Required || plan.NetworkActivationRequired {
		return repair.repairBootstrapLocally(ctx, fresh, plan)
	}
	payload, err := json.Marshal(controller.GatewayRepairPayload{Plan: plan})
	if err != nil {
		return controller.GatewayRepairData{}, err
	}
	response, err := repair.call(ctx, repair.socketPath, control.LocalRequest{
		SchemaVersion:      control.LocalSchemaVersion,
		Method:             control.LocalMutate,
		Operation:          controller.GatewayRepairOperation,
		ExpectedGeneration: plan.Generation,
		Payload:            payload,
	})
	if err != nil {
		return controller.GatewayRepairData{}, errors.Join(ErrCommittedGatewayRepairUncertain, err)
	}
	if !response.OK {
		switch response.ErrorCode {
		case "generation_conflict", "mutation_failed":
			return controller.GatewayRepairData{}, ErrCommittedGatewayRepairStale
		case "runtime_apply_failed":
			return controller.GatewayRepairData{}, ErrCommittedGatewayRepairPending
		case "state_unavailable", "unsupported_operation", "unsupported_method":
			return controller.GatewayRepairData{}, ErrCommittedGatewayRepairUnavailable
		default:
			return controller.GatewayRepairData{}, fmt.Errorf("gateway repair controller rejected operation: %s", response.ErrorCode)
		}
	}
	if response.Generation != plan.Generation {
		return controller.GatewayRepairData{}, ErrCommittedGatewayRepairStale
	}
	var result controller.GatewayRepairData
	if err := control.DecodeRPCPayload(response.Data, &result); err != nil {
		return controller.GatewayRepairData{}, fmt.Errorf("decode gateway repair result: %w", err)
	}
	return validateCommittedGatewayRepairResult(plan, result)
}

const committedGatewayBootstrapRepairTimeout = 5 * time.Minute

func (repair *systemCommittedGatewayRepair) repairBootstrapLocally(
	ctx context.Context,
	state model.State,
	plan controller.GatewayRepairPlan,
) (controller.GatewayRepairData, error) {
	if repair.localDispatcher == nil || repair.acquireLock == nil || repair.runtimeDir == "" {
		return controller.GatewayRepairData{}, ErrCommittedGatewayRepairInvalid
	}
	executionContext, cancel := context.WithTimeout(ctx, committedGatewayBootstrapRepairTimeout)
	defer cancel()
	release, err := repair.acquireLock(executionContext, repair.runtimeDir, true)
	if err != nil {
		return controller.GatewayRepairData{}, errors.Join(ErrCommittedGatewayRepairUnavailable, err)
	}
	defer release()

	fresh, err := repair.state.Load()
	if err != nil || !reflect.DeepEqual(fresh, state) {
		return controller.GatewayRepairData{}, errors.Join(ErrCommittedGatewayRepairStale, err)
	}
	payload, err := json.Marshal(controller.GatewayRepairPayload{Plan: plan})
	if err != nil {
		return controller.GatewayRepairData{}, err
	}
	prepared, err := repair.localDispatcher.Prepare(executionContext, fresh, controller.GatewayRepairOperation, payload)
	if err != nil {
		return controller.GatewayRepairData{}, err
	}
	if !prepared.Changed || !prepared.RuntimeOnly || !reflect.DeepEqual(prepared.Candidate, fresh) || prepared.Apply == nil || prepared.Rollback == nil || prepared.Timeout <= 0 || prepared.Timeout > committedGatewayBootstrapRepairTimeout {
		return controller.GatewayRepairData{}, ErrCommittedGatewayRepairInvalid
	}
	if err := prepared.Apply(executionContext); err != nil {
		return controller.GatewayRepairData{}, ErrCommittedGatewayRepairPending
	}
	after, err := repair.state.Load()
	if err != nil || !reflect.DeepEqual(after, fresh) {
		return controller.GatewayRepairData{}, errors.Join(ErrCommittedGatewayRepairUncertain, err)
	}
	if prepared.Result == nil {
		return controller.GatewayRepairData{}, ErrCommittedGatewayRepairInvalid
	}
	var result controller.GatewayRepairData
	if err := control.DecodeRPCPayload(prepared.Result(), &result); err != nil {
		return controller.GatewayRepairData{}, fmt.Errorf("decode local gateway bootstrap repair result: %w", err)
	}
	return validateCommittedGatewayRepairResult(plan, result)
}

func validateCommittedGatewayRepairResult(plan controller.GatewayRepairPlan, result controller.GatewayRepairData) (controller.GatewayRepairData, error) {
	if !result.Changed || result.NetworkActivationRequired != plan.NetworkActivationRequired ||
		result.NetworkActivationRequired != (result.TransactionID != "") ||
		result.TransactionID != "" && !operations.ValidWatchdogID(result.TransactionID) {
		return controller.GatewayRepairData{}, fmt.Errorf("gateway repair result is invalid")
	}
	return result, nil
}

type CommittedGatewayRepairWorkflow struct {
	operator CommittedGatewayRepairOperator

	mu      sync.Mutex
	planned *controller.GatewayRepairPlan
}

func NewCommittedGatewayRepairWorkflow(operator CommittedGatewayRepairOperator) (*CommittedGatewayRepairWorkflow, error) {
	if operator == nil {
		return nil, fmt.Errorf("committed gateway repair operator is required")
	}
	return &CommittedGatewayRepairWorkflow{operator: operator}, nil
}

func (workflow *CommittedGatewayRepairWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if ctx == nil || workflow == nil || workflow.operator == nil {
		return MutationPlan{}, ErrCommittedGatewayRepairInvalid
	}
	plan, err := workflow.operator.Plan(ctx)
	if err != nil {
		return MutationPlan{}, err
	}
	if err := plan.Validate(); err != nil {
		return MutationPlan{}, err
	}
	workflow.mu.Lock()
	retained := cloneCommittedGatewayRepairPlan(plan)
	workflow.planned = &retained
	workflow.mu.Unlock()
	return MutationPlan{Impact: ImpactAvailability, Result: committedGatewayRepairOutput(plan, nil)}, nil
}

func (workflow *CommittedGatewayRepairWorkflow) Apply(ctx context.Context, publicPlan MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if ctx == nil || workflow == nil || workflow.operator == nil {
		return AppliedMutation{}, ErrCommittedGatewayRepairInvalid
	}
	workflow.mu.Lock()
	if workflow.planned == nil {
		workflow.mu.Unlock()
		return AppliedMutation{}, fmt.Errorf("%w: committed gateway repair was not planned", ErrInvalidMutationPlan)
	}
	retained := cloneCommittedGatewayRepairPlan(*workflow.planned)
	workflow.mu.Unlock()
	if publicPlan.Impact != ImpactAvailability || !reflect.DeepEqual(publicPlan.Result, committedGatewayRepairOutput(retained, nil)) {
		return AppliedMutation{}, fmt.Errorf("%w: public committed gateway repair plan differs from retained plan", ErrInvalidMutationPlan)
	}
	result, err := workflow.operator.Repair(ctx, retained)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: committedGatewayRepairOutput(retained, &result)}, nil
}

func RunCommittedGatewayRepair(
	ctx context.Context,
	dryRun bool,
	yes bool,
	jsonMode bool,
	terminal PromptIO,
	operator CommittedGatewayRepairOperator,
) (MutationOutcome, error) {
	workflow, err := NewCommittedGatewayRepairWorkflow(operator)
	if err != nil {
		return MutationOutcome{}, err
	}
	return V2CommandRegistry().RunMutation(ctx, MutationRequest{
		CommandID: "repair", Role: RoleGateway, DryRun: dryRun, Yes: yes, JSON: jsonMode,
	}, terminal, workflow, nil)
}

func committedGatewayRepairOutput(plan controller.GatewayRepairPlan, applied *controller.GatewayRepairData) output.Result {
	artifacts := make(output.SafeList, len(plan.Artifacts))
	for index, artifact := range plan.Artifacts {
		artifacts[index] = output.SafeObject{"kind": artifact.Kind, "name": artifact.Name, "sha256": artifact.SHA256}
	}
	scope := "committed_gateway_services"
	if plan.NetworkActivationRequired || plan.Bootstrap.Required {
		scope = "gateway_bootstrap_recovery"
	}
	data := output.SafeObject{
		"changed": true, "generation": plan.Generation, "scope": scope,
		"tunnel_active": plan.TunnelActive, "network_activation_required": plan.NetworkActivationRequired,
		"services": append([]string(nil), plan.Services...), "artifacts": artifacts,
		"bootstrap": output.SafeObject{
			"required": plan.Bootstrap.Required, "packages": initPackagePlanOutput(plan.Bootstrap.PackagePlan),
			"ingress_candidate_sha256": plan.Bootstrap.IngressCandidateSHA256,
			"drop_in_sha256":           plan.Bootstrap.DropInSHA256, "readiness_sha256": plan.Bootstrap.ReadinessSHA256,
		},
	}
	if plan.NetworkActivationRequired {
		data["firewall_sha256"] = plan.FirewallSHA256
		data["initial_network_sha256"] = plan.InitialNetworkSHA256
	}
	result := output.NewResult("repair", output.StatusOK, output.CategorySuccess, data)
	result.ResourceIDs["host_id"] = plan.HostID
	if applied != nil && applied.TransactionID != "" {
		result.ResourceIDs["transaction_id"] = applied.TransactionID
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "confirm_network", Message: "Confirm the repaired network from a newly established SSH session before the 120-second rollback deadline.",
			Command: "vpnctl confirm " + applied.TransactionID, ResourceIDs: map[string]string{"transaction_id": applied.TransactionID},
		})
	}
	addInitPackageHumanTable(&result, plan.Bootstrap.PackagePlan)
	return result
}

func cloneCommittedGatewayRepairPlan(plan controller.GatewayRepairPlan) controller.GatewayRepairPlan {
	plan.Services = append([]string(nil), plan.Services...)
	plan.Artifacts = append([]controller.GatewayRepairArtifact(nil), plan.Artifacts...)
	if plan.Bootstrap.PackagePlan.Packages != nil {
		packages := make([]lifecycle.RolePackagePlanItem, len(plan.Bootstrap.PackagePlan.Packages))
		copy(packages, plan.Bootstrap.PackagePlan.Packages)
		plan.Bootstrap.PackagePlan.Packages = packages
	}
	return plan
}

var (
	_ CommittedGatewayRepairOperator = (*systemCommittedGatewayRepair)(nil)
	_ MutationWorkflow               = (*CommittedGatewayRepairWorkflow)(nil)
)
