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

type purgeManager interface {
	Plan(context.Context, lifecycle.PurgeOptions) (lifecycle.PurgePlan, error)
	Apply(context.Context, lifecycle.PurgePlan) (lifecycle.PurgeResult, error)
}

var (
	purgeSystemPaths = store.DefaultPaths
	purgeLoadRole    = loadSystemHostRole
	purgeBuilder     = buildSystemPurger
	purgeOpenTTY     = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

type purgeArguments struct {
	Force          bool
	LocalOnly      bool
	IncludeBackups bool
	DryRun         bool
	Yes            bool
	JSON           bool
	Help           bool
}

func isPurgeInvocation(args []string) bool {
	for _, argument := range args {
		switch argument {
		case "--json", "--dry-run", "--yes", "--force", "--local-only", "--include-backups", "--help", "-h":
			continue
		default:
			return argument == "purge"
		}
	}
	return false
}

func executePurge(args []string, stdout, stderr io.Writer) int {
	parsed, err := parsePurgeArguments(args)
	if parsed.Help {
		printPurgeHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "purge failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitPurgeFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := purgeSystemPaths()
	role, err := purgeLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitPurgeFailure(emitter, output.CategoryValidation, "invalid_host_state", "purge requires an initialized gateway or node")
	}
	if parsed.IncludeBackups && role != RoleGateway {
		return emitPurgeFailure(emitter, output.CategoryValidation, "purge_validation", "--include-backups is gateway-only")
	}
	options := lifecycle.PurgeOptions{Force: parsed.Force, LocalOnly: parsed.LocalOnly, IncludeBackups: parsed.IncludeBackups}
	manager, err := purgeBuilder(context.Background(), paths, role, options)
	if err != nil {
		category, code, message := classifyPurgeError(err)
		return emitPurgeFailure(emitter, category, code, message)
	}
	workflow, err := NewPurgeWorkflow(manager, options)
	if err != nil {
		return emitPurgeFailure(emitter, output.CategoryInternal, "purge_internal_error", "vpnctl could not prepare the purge workflow")
	}
	var terminal PromptIO
	var closer io.Closer
	if !parsed.DryRun {
		terminal, closer, _ = purgeOpenTTY()
		if closer != nil {
			defer closer.Close()
		}
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "purge", Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes, JSON: parsed.JSON, IncludeBackups: parsed.IncludeBackups,
	}, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyPurgeError(err)
		var partial *purgeApplyError
		if errors.As(err, &partial) {
			return emitPartialPurgeFailure(emitter, partial.result, category, code, message)
		}
		return emitPurgeFailure(emitter, category, code, message)
	}
	code, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func parsePurgeArguments(args []string) (purgeArguments, error) {
	parsed := purgeArguments{}
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
		case "--include-backups":
			if parsed.IncludeBackups {
				return parsed, fmt.Errorf("--include-backups may be supplied only once")
			}
			parsed.IncludeBackups = true
		case "--defer":
			return parsed, fmt.Errorf("purge does not support --defer")
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported purge option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) == 0 || positionals[0] != "purge" {
		return parsed, fmt.Errorf("purge command is missing")
	}
	if len(positionals) != 1 {
		return parsed, fmt.Errorf("purge accepts no positional arguments")
	}
	if parsed.Force && parsed.LocalOnly {
		return parsed, fmt.Errorf("--force and --local-only are mutually exclusive")
	}
	return parsed, nil
}

type PurgeWorkflow struct {
	manager  purgeManager
	options  lifecycle.PurgeOptions
	plan     lifecycle.PurgePlan
	public   MutationPlan
	planned  bool
	finished bool
}

type purgeApplyError struct {
	result lifecycle.PurgeResult
	cause  error
}

func (failure *purgeApplyError) Error() string { return failure.cause.Error() }
func (failure *purgeApplyError) Unwrap() error { return failure.cause }

func NewPurgeWorkflow(manager purgeManager, options lifecycle.PurgeOptions) (*PurgeWorkflow, error) {
	if manager == nil {
		return nil, fmt.Errorf("purge manager is required")
	}
	return &PurgeWorkflow{manager: manager, options: options}, nil
}

func (workflow *PurgeWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.manager == nil || workflow.planned {
		return MutationPlan{}, fmt.Errorf("purge workflow cannot be planned")
	}
	plan, err := workflow.manager.Plan(ctx, workflow.options)
	if err != nil {
		return MutationPlan{}, err
	}
	public := MutationPlan{Impact: ImpactDestructive, Result: purgePlanOutput(plan)}
	if plan.Blocked {
		public.Impact = ImpactNone
	}
	workflow.plan, workflow.public, workflow.planned = plan, public, true
	return public, nil
}

func (workflow *PurgeWorkflow) Apply(ctx context.Context, public MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.manager == nil || !workflow.planned || workflow.finished || !reflect.DeepEqual(public, workflow.public) {
		return AppliedMutation{}, fmt.Errorf("purge apply does not match the retained plan")
	}
	result, err := workflow.manager.Apply(ctx, workflow.plan)
	workflow.finished = true
	if err != nil {
		if result.Changed && (result.Role == model.RoleGateway || result.Role == model.RoleNode) {
			return AppliedMutation{}, &purgeApplyError{result: result, cause: err}
		}
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: purgeResultOutput(result)}, nil
}

func purgePlanOutput(plan lifecycle.PurgePlan) output.Result {
	status, category := output.StatusOK, output.CategorySuccess
	if plan.Blocked {
		status, category = output.StatusFailed, output.CategoryConflict
	}
	result := output.NewResult("purge", status, category, output.SafeObject{
		"changed": plan.Changed && !plan.Blocked, "generation": plan.ExpectedStateGeneration, "role": string(plan.Role),
		"blocked": plan.Blocked, "force_required": plan.ForceRequired, "local_only": plan.LocalOnly,
		"include_backups": plan.IncludeBackups, "backup_archives": plan.BackupArchives,
		"affected_services": append([]string{}, plan.AffectedServices...), "active_node_ids": append([]string{}, plan.ActiveNodeIDs...),
		"active_client_ids": append([]string{}, plan.ActiveClientIDs...), "active_expose_ids": append([]string{}, plan.ActiveExposeIDs...),
		"removed": append([]string{}, plan.Removed...), "preserved": append([]string{}, plan.Preserved...),
	})
	if plan.NodeID != "" {
		result.ResourceIDs["node_id"] = plan.NodeID
	}
	addUninstallActions(&result, plan.Role, plan.NodeID, plan.LocalOnly, plan.NodeRevokeRequired, plan.ActiveNodeIDs, plan.ActiveClientIDs, plan.ActiveExposeIDs)
	addPurgeRecoveryNotice(&result, plan.IncludeBackups, plan.BackupArchives)
	return result
}

func purgeResultOutput(value lifecycle.PurgeResult) output.Result {
	return purgeLifecycleResultOutput(value, true)
}

func purgeLifecycleResultOutput(value lifecycle.PurgeResult, final bool) output.Result {
	result := output.NewResult("purge", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": value.Changed, "generation": value.SourceStateGeneration, "role": string(value.Role), "local_only": value.LocalOnly,
		"include_backups": value.IncludeBackups, "backup_archives": value.BackupArchives,
		"node_revoked": value.NodeRevoked, "gateway_generation": value.GatewayGeneration,
		"dns_restored": value.DNSRestored, "network_restored": value.NetworkRestored,
		"managed_swap_purged": value.ManagedSwapPurged, "data_purged": value.DataPurged,
		"backups_removed": value.BackupsRemoved, "binary_removed": value.BinaryRemoved,
		"installer_binary_retained": value.InstallerBinaryRetained, "affected_services": append([]string{}, value.AffectedServices...),
		"active_node_ids": append([]string{}, value.ActiveNodeIDs...), "active_client_ids": append([]string{}, value.ActiveClientIDs...),
		"active_expose_ids": append([]string{}, value.ActiveExposeIDs...), "removed": append([]string{}, value.Removed...),
		"preserved": append([]string{}, value.Preserved...),
	})
	if value.NodeID != "" {
		result.ResourceIDs["node_id"] = value.NodeID
	}
	if value.InstallerBinaryRetained {
		result.Warnings = append(result.Warnings, output.Message{Code: "installer_binary_retained", Message: "The running vpnctl binary was not proven installer-managed and was preserved."})
	}
	addUninstallActions(&result, value.Role, value.NodeID, value.LocalOnly, value.LocalOnly, value.ActiveNodeIDs, value.ActiveClientIDs, value.ActiveExposeIDs)
	if final {
		addPurgeRecoveryNotice(&result, value.IncludeBackups, value.BackupArchives)
	}
	return result
}

func addPurgeRecoveryNotice(result *output.Result, includeBackups bool, archives int) {
	if !includeBackups && archives > 0 {
		result.Warnings = append(result.Warnings, output.Message{
			Code: "portable_backups_preserved", Message: fmt.Sprintf("Preserved %d portable backup archive(s) under /var/lib/vpnctl/backups; all other managed recovery data is erased.", archives),
		})
		return
	}
	result.Warnings = append(result.Warnings, output.Message{
		Code: "managed_recovery_erased", Message: "No vpnctl-managed recovery data remains after this purge; only operator-owned copies outside managed paths could still exist.",
	})
}

func buildSystemPurger(_ context.Context, paths store.Paths, role HostRole, options lifecycle.PurgeOptions) (purgeManager, error) {
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
	return lifecycle.NewPurger(stateStore, runtime)
}

func classifyPurgeError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, lifecycle.ErrUninstallForceRequired):
		return output.CategoryConflict, "purge_force_required", "active gateway resources require review and an explicit --force"
	case errors.Is(err, lifecycle.ErrUninstallGatewayUnavailable):
		return output.CategoryUnavailable, "gateway_revoke_unavailable", "the gateway did not confirm node revocation; retry online or use --local-only and revoke it manually"
	case errors.Is(err, lifecycle.ErrUninstallPlanStale), errors.Is(err, lifecycle.ErrUninstallRuntimePlan), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "purge_conflict", "authoritative state or installer-owned host resources changed; inspect and retry"
	case errors.Is(err, lifecycle.ErrUninstallRoleFlag), errors.Is(err, ErrInteractionRefused), errors.Is(err, ErrConsentDeclined),
		errors.Is(err, ErrPromptInput), errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags):
		return output.CategoryValidation, "purge_validation", singleLineGatewayInitMessage(err.Error())
	case errors.Is(err, os.ErrPermission):
		return output.CategoryUnavailable, "purge_host_unavailable", "installer-owned host resources are not writable"
	default:
		return output.CategoryInternal, "purge_internal_error", "vpnctl could not complete the irreversible purge"
	}
}

func emitPurgeFailure(emitter *ResultEmitter, category output.ExitCategory, warningCode, warningMessage string) int {
	result := output.NewResult("purge", output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func emitPartialPurgeFailure(emitter *ResultEmitter, partial lifecycle.PurgeResult, category output.ExitCategory, warningCode, warningMessage string) int {
	result := purgeLifecycleResultOutput(partial, false)
	result.Status, result.ExitCategory = output.StatusFailed, category
	result.Warnings = append(result.Warnings, output.Message{
		Code:    warningCode,
		Message: singleLineGatewayInitMessage(warningMessage + "; the host was partially changed, so inspect the reported phase fields before retrying and do not assume managed recovery remains"),
	})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printPurgeHelp(writer io.Writer) {
	fmt.Fprint(writer, `Irreversibly erase vpnctl-managed state after controlled runtime removal.

Usage:
  vpnctl purge [--force | --local-only] [--include-backups] [--dry-run] [--yes] [--json]

Type the exact role-specific phrase shown by vpnctl; --yes cannot bypass it.
Gateway purge also requires --force while active nodes, clients, or exposes exist.
Portable archives remain by default. Gateway-only --include-backups requires the
second exact phrase "delete backups" and removes those archives too.
`)
}

var _ MutationWorkflow = (*PurgeWorkflow)(nil)
