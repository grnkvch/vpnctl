package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type policyStateStore interface {
	Load() (model.State, error)
	Save(uint64, model.State) error
}

type nodePolicyGateway interface {
	Plan(context.Context, routing.PolicyCommand, []string, bool) (operations.RemotePolicyPlan, error)
	Commit(context.Context, operations.RemotePolicyPlan) (routing.PolicyCommitResult, error)
}

var (
	policySystemPaths = store.DefaultPaths
	policyLoadRole    = loadSystemHostRole
	policyNewStore    = func(paths store.Paths) (policyStateStore, error) { return store.NewStateStore(paths) }
	policyBuildRemote = func(paths store.Paths) (nodePolicyGateway, error) {
		return operations.NewSystemRemotePolicyGateway(paths, nil)
	}
)

func isPolicyInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, map[string]bool{"--client": true})
	return len(positionals) >= 1 && positionals[0] == "policy"
}

type policyArguments struct {
	Action    routing.PolicyCommand
	CommandID string
	Client    string
	Presets   []string
	DryRun    bool
	Defer     bool
	JSON      bool
	Help      bool
}

func executePolicy(args []string, stdout, stderr io.Writer) int {
	parsed, err := parsePolicyArguments(args)
	if parsed.Help {
		printPolicyHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "policy failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitPolicyFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := policySystemPaths()
	role, err := policyLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitPolicyFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_host_state", "policy requires an initialized gateway or joined node")
	}
	commandID, err := resolvePolicyCommandID(parsed, role)
	if err != nil {
		return emitPolicyFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_target", err.Error())
	}
	parsed.CommandID = commandID
	stateState, err := policyNewStore(paths)
	if err != nil {
		return emitPolicyFailure(emitter, parsed.CommandID, output.CategoryInternal, "policy_state_unavailable", "vpnctl could not open policy state")
	}
	if parsed.Action == "show" {
		return executePolicyShow(emitter, role, stateState, parsed)
	}

	request := MutationRequest{
		CommandID: parsed.CommandID, Role: role, DryRun: parsed.DryRun, Defer: parsed.Defer, JSON: parsed.JSON,
	}
	if _, _, err := V2CommandRegistry().ResolveMutationMode(request); err != nil {
		category, code, message := classifyPolicyError(err)
		return emitPolicyFailure(emitter, parsed.CommandID, category, code, message)
	}

	var workflow MutationWorkflow
	var authority AuthoritativeDeferredWriter
	if role == RoleGateway {
		manager, buildErr := routing.NewPolicyManager(paths, stateState)
		if buildErr != nil {
			return emitPolicyFailure(emitter, parsed.CommandID, output.CategoryInternal, "policy_service_unavailable", "vpnctl could not construct the policy service")
		}
		workflow = &gatewayPolicyMutationWorkflow{manager: manager, command: parsed.Action, client: parsed.Client, presets: parsed.Presets}
	} else {
		remote, buildErr := policyBuildRemote(paths)
		if buildErr != nil {
			return emitPolicyFailure(emitter, parsed.CommandID, output.CategoryUnavailable, "gateway_unavailable", "the authoritative gateway is unavailable")
		}
		applier, buildErr := routing.NewNodePolicyApplier(stateState)
		if buildErr != nil {
			return emitPolicyFailure(emitter, parsed.CommandID, output.CategoryInternal, "policy_service_unavailable", "vpnctl could not construct the node policy service")
		}
		nodeWorkflow := &nodePolicyMutationWorkflow{gateway: remote, local: applier, command: parsed.Action, presets: parsed.Presets, deferred: parsed.Defer}
		workflow, authority = nodeWorkflow, nodeWorkflow
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), request, nil, workflow, authority)
	if err != nil {
		category, code, message := classifyPolicyError(err)
		return emitPolicyFailure(emitter, parsed.CommandID, category, code, message)
	}
	exit, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parsePolicyArguments(args []string) (policyArguments, error) {
	parsed := policyArguments{CommandID: "policy.show"}
	positionals := make([]string, 0, len(args))
	seen := make(map[string]bool)
	for index := 0; index < len(args); index++ {
		argument := args[index]
		name, inlineValue, inline := strings.Cut(argument, "=")
		switch name {
		case "--json", "--dry-run", "--defer":
			if inline || seen[name] {
				return parsed, fmt.Errorf("%s may be supplied only once and takes no value", name)
			}
			seen[name] = true
			switch name {
			case "--json":
				parsed.JSON = true
			case "--dry-run":
				parsed.DryRun = true
			case "--defer":
				parsed.Defer = true
			}
		case "--client":
			if seen[name] {
				return parsed, fmt.Errorf("--client may be supplied only once")
			}
			seen[name] = true
			if inline {
				parsed.Client = inlineValue
			} else if index+1 < len(args) {
				index++
				parsed.Client = args[index]
			}
			if parsed.Client == "" {
				return parsed, fmt.Errorf("--client requires a name or ID")
			}
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported policy option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) < 2 || positionals[0] != "policy" {
		return parsed, fmt.Errorf("policy requires show, set, or clear")
	}
	switch positionals[1] {
	case "show":
		parsed.Action, parsed.CommandID = "show", "policy.show"
		if len(positionals) != 2 || parsed.DryRun || parsed.Defer {
			return parsed, fmt.Errorf("policy show accepts only --client and --json")
		}
	case "set":
		parsed.Action, parsed.CommandID = routing.PolicySet, "policy.set.node"
		parsed.Presets = append([]string{}, positionals[2:]...)
		if len(parsed.Presets) == 0 {
			return parsed, routing.ErrPolicyEmptySet
		}
	case "clear":
		parsed.Action, parsed.CommandID = routing.PolicyClear, "policy.clear.node"
		parsed.Presets = []string{}
		if len(positionals) != 2 {
			return parsed, fmt.Errorf("policy clear accepts no preset arguments")
		}
	default:
		return parsed, fmt.Errorf("policy requires show, set, or clear")
	}
	return parsed, nil
}

func resolvePolicyCommandID(parsed policyArguments, role HostRole) (string, error) {
	if role == RoleGateway {
		if parsed.Client == "" {
			return parsed.CommandID, fmt.Errorf("gateway policy commands require an explicit --client target")
		}
		if parsed.Action == "show" {
			return "policy.show.gateway", nil
		}
		return "policy." + string(parsed.Action) + ".gateway", nil
	}
	if role == RoleNode {
		if parsed.Client != "" {
			return parsed.CommandID, fmt.Errorf("node policy commands target only the current node and do not accept --client")
		}
		if parsed.Action == "show" {
			return "policy.show.node", nil
		}
		return "policy." + string(parsed.Action) + ".node", nil
	}
	return parsed.CommandID, ErrUnsupportedRole
}

func executePolicyShow(emitter *ResultEmitter, role HostRole, stateStore policyStateStore, parsed policyArguments) int {
	var result output.Result
	err := V2CommandRegistry().Dispatch(parsed.CommandID, role, func(CommandSpec) error {
		state, err := stateStore.Load()
		if err != nil {
			return err
		}
		var view routing.PolicyView
		if role == RoleGateway {
			view, err = routing.ShowClientPolicy(state, parsed.Client)
		} else {
			view, err = routing.ShowCurrentNodePolicy(state)
		}
		if err == nil {
			result = policyShowOutput(view)
		}
		return err
	})
	if err != nil {
		category, code, message := classifyPolicyError(err)
		return emitPolicyFailure(emitter, parsed.CommandID, category, code, message)
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func policyShowOutput(view routing.PolicyView) output.Result {
	resource := output.SafeObject{
		"target_kind": string(view.TargetKind), "target_id": view.TargetID, "target_name": view.TargetName,
		"preset_names": append([]string{}, view.PresetNames...), "selectors": presetSelectorsOutput(view.Selectors),
		"effective_hash": view.EffectiveHash, "policy_generation": view.PolicyGeneration,
		"state_generation": view.StateGeneration,
	}
	result := output.NewResult("policy.show", output.StatusOK, output.CategorySuccess, output.SafeObject{"resource": resource})
	resourceKey := "node_id"
	if view.TargetKind == model.TargetClient {
		resourceKey = "client_id"
	}
	result.ResourceIDs[resourceKey] = view.TargetID
	if len(view.Selectors) != 0 {
		if boundary, err := routing.InspectClassificationBoundary(view.Selectors); err == nil {
			resource["classification_boundary"] = boundary.SafeObject()
			result.Warnings = append(result.Warnings, boundary.Warnings()...)
		}
	}
	return result
}

type gatewayPolicyMutationWorkflow struct {
	manager *routing.PolicyManager
	command routing.PolicyCommand
	client  string
	presets []string
	plan    *routing.PolicyReplacementPlan
}

func (workflow *gatewayPolicyMutationWorkflow) Plan(context.Context, *InteractionInputs) (MutationPlan, error) {
	var plan routing.PolicyReplacementPlan
	var err error
	if workflow.command == routing.PolicySet {
		plan, err = workflow.manager.PlanClientSet(workflow.client, workflow.presets)
	} else {
		plan, err = workflow.manager.PlanClientClear(workflow.client)
	}
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan = &plan
	preview := routing.PolicyCommitResult{
		Command: plan.Command, Changed: plan.Changed, StateGeneration: plan.NextStateGeneration,
		RequiresClientReExport: plan.RequiresClientReExport, Desired: plan.Desired,
	}.OutputResult()
	return MutationPlan{Impact: ImpactNone, Result: preview}, nil
}

func (workflow *gatewayPolicyMutationWorkflow) Apply(_ context.Context, public MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow.plan == nil || public.Result.Command != "policy."+string(workflow.command) {
		return AppliedMutation{}, ErrInvalidMutationPlan
	}
	result, err := workflow.manager.Commit(*workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: result.OutputResult()}, nil
}

type nodePolicyMutationWorkflow struct {
	gateway  nodePolicyGateway
	local    *routing.NodePolicyApplier
	command  routing.PolicyCommand
	presets  []string
	deferred bool

	mu   sync.Mutex
	plan *operations.RemotePolicyPlan
}

func (workflow *nodePolicyMutationWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	plan, err := workflow.gateway.Plan(ctx, workflow.command, workflow.presets, workflow.deferred)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.mu.Lock()
	workflow.plan = &plan
	workflow.mu.Unlock()
	preview := routing.PolicyCommitResult{
		Command: plan.Command, Changed: plan.Changed, StateGeneration: plan.NextStateGeneration, Desired: plan.Desired,
	}.OutputResult()
	return MutationPlan{Impact: ImpactNone, Result: preview}, nil
}

func (workflow *nodePolicyMutationWorkflow) Apply(ctx context.Context, public MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	plan, err := workflow.retained(public)
	if err != nil {
		return AppliedMutation{}, err
	}
	committed, err := workflow.gateway.Commit(ctx, plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	if _, err := workflow.local.Apply(committed.Desired); err != nil {
		committed.Pending = true
		result := committed.OutputResult()
		result.Warnings = append(result.Warnings, output.Message{Code: "node_policy_apply_pending", Message: "The gateway policy committed but node-local application remains pending."})
		result.RequiresAction = append(result.RequiresAction, output.Action{Code: "repair_node_policy", Message: "Reconcile the node routing policy from gateway-authoritative state.", Command: "vpnctl repair", ResourceIDs: map[string]string{"node_id": committed.Desired.TargetID}})
		return AppliedMutation{Result: result}, nil
	}
	return AppliedMutation{Result: committed.OutputResult()}, nil
}

func (workflow *nodePolicyMutationWorkflow) RegisterPending(ctx context.Context, public MutationPlan) (DeferredReceipt, error) {
	plan, err := workflow.retained(public)
	if err != nil {
		return DeferredReceipt{}, err
	}
	committed, err := workflow.gateway.Commit(ctx, plan)
	if err != nil {
		return DeferredReceipt{}, err
	}
	result := committed.OutputResult()
	// A gateway-authoritative desired generation is the durable receipt for
	// this deliberately deferred replacement. There is no local offline queue.
	return DeferredReceipt{
		CommandID:   "policy." + string(workflow.command) + ".node",
		OperationID: committed.OperationID, AuthoritativeGeneration: committed.StateGeneration, Result: result,
	}, nil
}

func (workflow *nodePolicyMutationWorkflow) retained(public MutationPlan) (operations.RemotePolicyPlan, error) {
	workflow.mu.Lock()
	defer workflow.mu.Unlock()
	if workflow.plan == nil || public.Result.Command != "policy."+string(workflow.command) || public.Impact != ImpactNone ||
		public.Result.ResourceIDs["node_id"] != workflow.plan.TargetID {
		return operations.RemotePolicyPlan{}, ErrInvalidMutationPlan
	}
	return *workflow.plan, nil
}

func classifyPolicyError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags), errors.Is(err, routing.ErrPolicyEmptySet),
		errors.Is(err, routing.ErrPolicyUnknownPreset), errors.Is(err, routing.ErrPolicyInvalidPreset),
		errors.Is(err, routing.ErrPolicyTargetNotFound), errors.Is(err, routing.ErrPolicyTargetInactive):
		return output.CategoryValidation, "policy_request_invalid", "the policy target, preset set, or command flags are invalid"
	case errors.Is(err, routing.ErrPolicyStalePlan), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "policy_conflict", "the policy conflicts with newer authoritative state"
	case errors.Is(err, operations.ErrPolicyGatewayUnavailable), errors.Is(err, ErrGatewayUnavailable):
		return output.CategoryUnavailable, "gateway_unavailable", "the authoritative gateway is unavailable"
	default:
		return output.CategoryInternal, "policy_operation_failed", "vpnctl could not complete the policy operation"
	}
}

func emitPolicyFailure(emitter *ResultEmitter, commandID string, category output.ExitCategory, code, message string) int {
	resultCommand := commandID
	if strings.HasPrefix(commandID, "policy.set") {
		resultCommand = "policy.set"
	} else if strings.HasPrefix(commandID, "policy.clear") {
		resultCommand = "policy.clear"
	} else {
		resultCommand = "policy.show"
	}
	data := output.SafeObject{"changed": false, "generation": uint64(0)}
	if resultCommand == "policy.show" {
		data = output.SafeObject{"resource": output.SafeObject{}}
	}
	result := output.NewResult(resultCommand, output.StatusFailed, category, data)
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func printPolicyHelp(writer io.Writer) {
	fmt.Fprint(writer, `Replace or inspect one complete selective-routing assignment.

Usage:
  vpnctl policy show [--client <name-or-id>] [--json]
  vpnctl policy set <preset...> [--client <name-or-id>] [--dry-run|--defer] [--json]
  vpnctl policy clear [--client <name-or-id>] [--dry-run|--defer] [--json]

On a node the current authenticated node is implicit and --defer is allowed.
On a gateway --client is required and --defer is rejected.
`)
}

var _ MutationWorkflow = (*gatewayPolicyMutationWorkflow)(nil)
var _ MutationWorkflow = (*nodePolicyMutationWorkflow)(nil)
var _ AuthoritativeDeferredWriter = (*nodePolicyMutationWorkflow)(nil)
