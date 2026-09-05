package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	repairSystemPaths  = store.DefaultPaths
	repairLoadRole     = loadSystemHostRole
	repairBuildNode    = buildSystemCommittedNodeRepair
	repairBuildGateway = buildSystemCommittedGatewayRepair
	repairOpenTTY      = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

func isRepairInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, nil)
	return len(positionals) > 0 && positionals[0] == "repair"
}

type repairArguments struct {
	DryRun bool
	Yes    bool
	JSON   bool
	Help   bool
}

func executeRepair(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseRepairArguments(args)
	if parsed.Help {
		printRepairHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "repair failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitRepairCommandFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error(), false, RoleUninitialized)
	}
	paths := repairSystemPaths()
	role, err := repairLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitRepairCommandFailure(emitter, output.CategoryValidation, "invalid_host_state", "repair requires an initialized host", false, RoleUninitialized)
	}
	var terminal PromptIO
	var closer io.Closer
	if !parsed.Yes && !parsed.DryRun {
		terminal, closer, err = repairOpenTTY()
		if err != nil {
			return emitRepairCommandFailure(emitter, output.CategoryValidation, "controlling_tty_required", "repair confirmation requires a controlling TTY or --yes", false, role)
		}
		defer closer.Close()
	}
	var outcome MutationOutcome
	switch role {
	case RoleGateway:
		operator, buildErr := repairBuildGateway(paths)
		if buildErr != nil {
			category, code, message := classifyRepairCommandError(buildErr)
			return emitRepairCommandFailure(emitter, category, code, message, false, role)
		}
		outcome, err = RunCommittedGatewayRepair(context.Background(), parsed.DryRun, parsed.Yes, parsed.JSON, terminal, operator)
	case RoleNode:
		operator, buildErr := repairBuildNode(paths)
		if buildErr != nil {
			category, code, message := classifyRepairCommandError(buildErr)
			return emitRepairCommandFailure(emitter, category, code, message, false, role)
		}
		outcome, err = RunCommittedNodeRepair(context.Background(), parsed.DryRun, parsed.Yes, parsed.JSON, terminal, operator)
	default:
		return emitRepairCommandFailure(emitter, output.CategoryValidation, "repair_request_invalid", "repair requires an initialized gateway or node", false, role)
	}
	if err != nil {
		category, code, message := classifyRepairCommandError(err)
		changed := errors.Is(err, enrollment.ErrNodeActivationPending) || errors.Is(err, ErrCommittedGatewayRepairPending) || errors.Is(err, ErrCommittedGatewayRepairUncertain)
		return emitRepairCommandFailure(emitter, category, code, message, changed, role)
	}
	exit, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parseRepairArguments(args []string) (repairArguments, error) {
	parsed := repairArguments{}
	positionals := make([]string, 0, len(args))
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
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported repair option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) != 1 || positionals[0] != "repair" {
		return parsed, fmt.Errorf("usage: vpnctl repair [--dry-run] [--yes] [--json]")
	}
	return parsed, nil
}

func printRepairHelp(writer io.Writer) {
	fmt.Fprint(writer, `Reconcile vpnctl-owned runtime from the committed generation.

Usage:
  vpnctl repair [--dry-run] [--yes] [--json]
`)
}

func classifyRepairCommandError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags), errors.Is(err, ErrInteractionRefused),
		errors.Is(err, ErrCommittedNodeRepairInvalid), errors.Is(err, ErrCommittedGatewayRepairInvalid), errors.Is(err, controller.ErrGatewayRepairInvalid),
		errors.Is(err, store.ErrStateNotFound):
		return output.CategoryValidation, "repair_request_invalid", "repair requires a valid committed host generation"
	case errors.Is(err, ErrCommittedNodeRepairStale), errors.Is(err, ErrCommittedGatewayRepairStale), errors.Is(err, controller.ErrGatewayRepairStale),
		errors.Is(err, store.ErrStateConflict), errors.Is(err, operations.ErrConvergenceSnapshotConflict), errors.Is(err, controller.ErrGatewayRepairWatchdogActive),
		errors.Is(err, controller.ErrGatewayRepairNetworkState):
		return output.CategoryConflict, "repair_plan_stale", "the committed generation changed after repair preview"
	case errors.Is(err, ErrCommittedGatewayRepairUnavailable):
		return output.CategoryUnavailable, "gateway_controller_unavailable", "gateway repair requires the local controller service"
	case errors.Is(err, ErrCommittedGatewayRepairUncertain):
		return output.CategoryUnavailable, "gateway_repair_outcome_uncertain", "the controller response was lost; inspect gateway status and any active watchdog transaction before retrying"
	case errors.Is(err, enrollment.ErrNodeActivationPending), errors.Is(err, ErrCommittedGatewayRepairPending), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return output.CategoryUnavailable, "repair_activation_pending", "the committed runtime is still not ready; resolve the reported host issue and retry repair"
	default:
		return output.CategoryInternal, "repair_failed", "vpnctl could not repair the committed runtime"
	}
}

func emitRepairCommandFailure(emitter *ResultEmitter, category output.ExitCategory, code, message string, changed bool, role HostRole) int {
	status := output.StatusFailed
	if category == output.CategoryUnavailable || category == output.CategoryConflict {
		status = output.StatusDegraded
	}
	result := output.NewResult("repair", status, category, output.SafeObject{"changed": changed})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: singleLineGatewayInitMessage(message)})
	if changed {
		action := output.Action{Code: "retry_node_repair", Message: "Retry repair after resolving the host readiness failure.", Command: "vpnctl repair"}
		if role == RoleGateway {
			action = output.Action{Code: "retry_gateway_repair", Message: "Retry repair after resolving the gateway readiness failure.", Command: "vpnctl repair"}
			if code == "gateway_repair_outcome_uncertain" {
				action = output.Action{Code: "inspect_gateway_repair", Message: "Inspect gateway and watchdog status before deciding whether to retry repair.", Command: "vpnctl status"}
			}
		}
		result.RequiresAction = append(result.RequiresAction, action)
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}
