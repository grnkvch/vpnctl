package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type uninstallManager interface {
	Plan(context.Context, lifecycle.UninstallOptions) (lifecycle.UninstallPlan, error)
	Apply(context.Context, lifecycle.UninstallPlan) (lifecycle.UninstallResult, error)
}

var (
	uninstallSystemPaths = store.DefaultPaths
	uninstallLoadRole    = loadSystemHostRole
	uninstallBuilder     = buildSystemUninstaller
	uninstallOpenTTY     = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

type uninstallArguments struct {
	Force     bool
	LocalOnly bool
	DryRun    bool
	Yes       bool
	JSON      bool
	Help      bool
}

func isUninstallInvocation(args []string) bool {
	for _, argument := range args {
		switch argument {
		case "--json", "--dry-run", "--yes", "--force", "--local-only", "--help", "-h":
			continue
		default:
			return argument == "uninstall"
		}
	}
	return false
}

func executeUninstall(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseUninstallArguments(args)
	if parsed.Help {
		printUninstallHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "uninstall failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitUninstallFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := uninstallSystemPaths()
	role, err := uninstallLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitUninstallFailure(emitter, output.CategoryValidation, "invalid_host_state", "uninstall requires an initialized gateway or node")
	}
	options := lifecycle.UninstallOptions{Force: parsed.Force, LocalOnly: parsed.LocalOnly}
	manager, err := uninstallBuilder(context.Background(), paths, role, options)
	if err != nil {
		category, code, message := classifyUninstallError(err)
		return emitUninstallFailure(emitter, category, code, message)
	}
	workflow, err := NewUninstallWorkflow(manager, options)
	if err != nil {
		return emitUninstallFailure(emitter, output.CategoryInternal, "uninstall_internal_error", "vpnctl could not prepare the uninstall workflow")
	}
	var terminal PromptIO
	var closer io.Closer
	if !parsed.Yes && !parsed.DryRun {
		terminal, closer, _ = uninstallOpenTTY()
		if closer != nil {
			defer closer.Close()
		}
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "uninstall", Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes, JSON: parsed.JSON,
	}, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyUninstallError(err)
		var partial *uninstallApplyError
		if errors.As(err, &partial) {
			return emitPartialUninstallFailure(emitter, partial.result, category, code, message)
		}
		return emitUninstallFailure(emitter, category, code, message)
	}
	code, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func parseUninstallArguments(args []string) (uninstallArguments, error) {
	parsed := uninstallArguments{}
	positionals := make([]string, 0, 1)
	for _, argument := range args {
		switch argument {
		case "--json":
			if parsed.JSON {
				return parsed, fmt.Errorf("--json may be supplied only once")
			}
			parsed.JSON = true
		case "--dry-run":
			if parsed.DryRun {
				return parsed, fmt.Errorf("--dry-run may be supplied only once")
			}
			parsed.DryRun = true
		case "--yes":
			if parsed.Yes {
				return parsed, fmt.Errorf("--yes may be supplied only once")
			}
			parsed.Yes = true
		case "--force":
			if parsed.Force {
				return parsed, fmt.Errorf("--force may be supplied only once")
			}
			parsed.Force = true
		case "--local-only":
			if parsed.LocalOnly {
				return parsed, fmt.Errorf("--local-only may be supplied only once")
			}
			parsed.LocalOnly = true
		case "--defer":
			return parsed, fmt.Errorf("uninstall does not support --defer")
		case "--include-backups":
			return parsed, fmt.Errorf("uninstall always preserves backups and does not support --include-backups")
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported uninstall option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) == 0 || positionals[0] != "uninstall" {
		return parsed, fmt.Errorf("uninstall command is missing")
	}
	if len(positionals) != 1 {
		return parsed, fmt.Errorf("uninstall accepts no positional arguments")
	}
	if parsed.Force && parsed.LocalOnly {
		return parsed, fmt.Errorf("--force and --local-only are mutually exclusive")
	}
	return parsed, nil
}

type UninstallWorkflow struct {
	manager  uninstallManager
	options  lifecycle.UninstallOptions
	plan     lifecycle.UninstallPlan
	public   MutationPlan
	planned  bool
	finished bool
}

type uninstallApplyError struct {
	result lifecycle.UninstallResult
	cause  error
}

func (failure *uninstallApplyError) Error() string { return failure.cause.Error() }
func (failure *uninstallApplyError) Unwrap() error { return failure.cause }

func NewUninstallWorkflow(manager uninstallManager, options lifecycle.UninstallOptions) (*UninstallWorkflow, error) {
	if manager == nil {
		return nil, fmt.Errorf("uninstall manager is required")
	}
	return &UninstallWorkflow{manager: manager, options: options}, nil
}

func (workflow *UninstallWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.manager == nil || workflow.planned {
		return MutationPlan{}, fmt.Errorf("uninstall workflow cannot be planned")
	}
	plan, err := workflow.manager.Plan(ctx, workflow.options)
	if err != nil {
		return MutationPlan{}, err
	}
	public := MutationPlan{Impact: ImpactAvailability, Result: uninstallPlanOutput(plan)}
	if plan.Blocked {
		public.Impact = ImpactNone
	}
	workflow.plan, workflow.public, workflow.planned = plan, public, true
	return public, nil
}

func (workflow *UninstallWorkflow) Apply(ctx context.Context, public MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.manager == nil || !workflow.planned || workflow.finished || !reflect.DeepEqual(public, workflow.public) {
		return AppliedMutation{}, fmt.Errorf("uninstall apply does not match the retained plan")
	}
	result, err := workflow.manager.Apply(ctx, workflow.plan)
	workflow.finished = true
	if err != nil {
		if result.Changed && (result.Role == model.RoleGateway || result.Role == model.RoleNode) {
			return AppliedMutation{}, &uninstallApplyError{result: result, cause: err}
		}
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: uninstallResultOutput(result)}, nil
}

func uninstallPlanOutput(plan lifecycle.UninstallPlan) output.Result {
	status, category := output.StatusOK, output.CategorySuccess
	if plan.Blocked {
		status, category = output.StatusFailed, output.CategoryConflict
	}
	result := output.NewResult("uninstall", status, category, output.SafeObject{
		"changed": plan.Changed && !plan.Blocked, "generation": plan.ExpectedStateGeneration,
		"role": string(plan.Role), "blocked": plan.Blocked, "force_required": plan.ForceRequired,
		"local_only": plan.LocalOnly, "affected_services": append([]string{}, plan.AffectedServices...),
		"active_node_ids": append([]string{}, plan.ActiveNodeIDs...), "active_client_ids": append([]string{}, plan.ActiveClientIDs...),
		"active_expose_ids": append([]string{}, plan.ActiveExposeIDs...), "preserved": append([]string{}, plan.Preserved...),
	})
	if plan.NodeID != "" {
		result.ResourceIDs["node_id"] = plan.NodeID
	}
	addUninstallActions(&result, plan.Role, plan.NodeID, plan.LocalOnly, plan.NodeRevokeRequired, plan.ActiveNodeIDs, plan.ActiveClientIDs, plan.ActiveExposeIDs)
	return result
}

func uninstallResultOutput(value lifecycle.UninstallResult) output.Result {
	result := output.NewResult("uninstall", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": value.Changed, "generation": value.StateGeneration, "role": string(value.Role), "local_only": value.LocalOnly,
		"node_revoked": value.NodeRevoked, "gateway_generation": value.GatewayGeneration,
		"dns_restored": value.DNSRestored, "network_restored": value.NetworkRestored,
		"managed_swap_disabled": value.ManagedSwapDisabled, "binary_removed": value.BinaryRemoved,
		"installer_binary_retained": value.InstallerBinaryRetained, "affected_services": append([]string{}, value.AffectedServices...),
		"active_node_ids": append([]string{}, value.ActiveNodeIDs...), "active_client_ids": append([]string{}, value.ActiveClientIDs...),
		"active_expose_ids": append([]string{}, value.ActiveExposeIDs...), "preserved": append([]string{}, value.Preserved...),
	})
	if value.NodeID != "" {
		result.ResourceIDs["node_id"] = value.NodeID
	}
	if value.InstallerBinaryRetained {
		result.Warnings = append(result.Warnings, output.Message{Code: "installer_binary_retained", Message: "The running vpnctl binary was not proven installer-managed and was preserved."})
	}
	addUninstallActions(&result, value.Role, value.NodeID, value.LocalOnly, value.LocalOnly, value.ActiveNodeIDs, value.ActiveClientIDs, value.ActiveExposeIDs)
	return result
}

func addUninstallActions(result *output.Result, role model.Role, nodeID string, localOnly, nodeRevokeRequired bool, nodes, clients, exposes []string) {
	if result == nil {
		return
	}
	if role == model.RoleNode && localOnly && nodeRevokeRequired {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "revoke_node_on_gateway", Message: "Revoke this node on the gateway before reusing or discarding its retained identity.",
			ResourceIDs: map[string]string{"node_id": nodeID},
		})
	}
	for _, id := range nodes {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "reinstall_or_rebind_node", Message: "Reinstall or rebind this private node before expecting gateway connectivity.",
			ResourceIDs: map[string]string{"node_id": id},
		})
	}
	for _, id := range clients {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "remove_stale_client_profile", Message: "Remove the stale gateway profile from this client device.",
			ResourceIDs: map[string]string{"client_id": id},
		})
	}
	for _, id := range exposes {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "remove_or_reregister_webhook", Message: "Remove or register again the external webhook that targeted this expose route.",
			ResourceIDs: map[string]string{"expose_id": id},
		})
	}
}

func buildSystemUninstaller(_ context.Context, paths store.Paths, role HostRole, options lifecycle.UninstallOptions) (uninstallManager, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	state, err := stateStore.Load()
	if err != nil {
		return nil, err
	}
	var gateway lifecycle.UninstallNodeGateway
	if role == RoleNode && !options.LocalOnly && len(state.Nodes) == 1 && state.Nodes[0].Lifecycle == model.LifecycleActive && state.Nodes[0].Gateway != nil {
		gateway, err = lifecycle.NewSystemNodeUninstallGateway(paths, nil)
		if err != nil {
			return nil, err
		}
	}
	watchdogDB, err := operations.NewWatchdogStore(paths)
	if err != nil {
		return nil, err
	}
	runtime, err := lifecycle.NewSystemUninstallRuntime(paths, gateway, watchdogDB)
	if err != nil {
		return nil, err
	}
	return lifecycle.NewUninstaller(stateStore, runtime)
}

func classifyUninstallError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, lifecycle.ErrUninstallForceRequired):
		return output.CategoryConflict, "uninstall_force_required", "active gateway resources require review and an explicit --force"
	case errors.Is(err, lifecycle.ErrUninstallGatewayUnavailable):
		return output.CategoryUnavailable, "gateway_revoke_unavailable", "the gateway did not confirm node revocation; retry online or use --local-only and revoke it manually"
	case errors.Is(err, lifecycle.ErrUninstallPlanStale), errors.Is(err, lifecycle.ErrUninstallRuntimePlan), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "uninstall_conflict", "authoritative state or installer-owned host resources changed; inspect and retry"
	case errors.Is(err, lifecycle.ErrUninstallRoleFlag), errors.Is(err, ErrInteractionRefused), errors.Is(err, ErrConsentDeclined),
		errors.Is(err, ErrPromptInput), errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags):
		return output.CategoryValidation, "uninstall_validation", singleLineGatewayInitMessage(err.Error())
	case errors.Is(err, os.ErrPermission):
		return output.CategoryUnavailable, "uninstall_host_unavailable", "installer-owned host resources are not writable"
	default:
		return output.CategoryInternal, "uninstall_internal_error", "vpnctl could not complete the recoverable uninstall"
	}
}

func emitUninstallFailure(emitter *ResultEmitter, category output.ExitCategory, warningCode, warningMessage string) int {
	result := output.NewResult("uninstall", output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func emitPartialUninstallFailure(emitter *ResultEmitter, partial lifecycle.UninstallResult, category output.ExitCategory, warningCode, warningMessage string) int {
	result := uninstallResultOutput(partial)
	result.Status, result.ExitCategory = output.StatusFailed, category
	result.Warnings = append(result.Warnings, output.Message{
		Code:    warningCode,
		Message: singleLineGatewayInitMessage(warningMessage + "; the host was partially changed, so inspect the reported phase fields before retrying"),
	})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printUninstallHelp(writer io.Writer) {
	fmt.Fprint(writer, `Remove vpnctl-managed runtime resources while preserving recoverable state.

Usage:
  vpnctl uninstall [--force | --local-only] [--dry-run] [--yes] [--json]

Gateway uninstall requires --force when active nodes, clients, or exposes exist.
Node uninstall revokes itself on the gateway first; if the gateway is unavailable,
--local-only removes local runtime and prints the mandatory remote revoke action.
DNS and networking are restored exactly, managed swap activation is disabled, and
state, secrets, presets, exports, backups, and the swap allocation are preserved.
`)
}

var _ MutationWorkflow = (*UninstallWorkflow)(nil)
