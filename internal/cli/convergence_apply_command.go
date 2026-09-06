package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

var (
	applySystemPaths = store.DefaultPaths
	applyLoadRole    = loadSystemHostRole
	applyBuild       = buildSystemConvergenceApply
	applyOpenTTY     = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

func isApplyInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, nil)
	return len(positionals) > 0 && positionals[0] == "apply"
}

type convergenceApplyArguments struct {
	Yes  bool
	JSON bool
	Help bool
}

func executeConvergenceApply(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseConvergenceApplyArguments(args)
	if parsed.Help {
		printConvergenceApplyHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "apply failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitConvergenceApplyFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}

	paths := applySystemPaths()
	role, err := applyLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitConvergenceApplyFailure(emitter, output.CategoryValidation, "invalid_host_state", "apply requires an initialized gateway or joined node")
	}
	operator, err := applyBuild(paths, role)
	if err != nil {
		category, code, message := classifyConvergenceApplyError(err)
		return emitConvergenceApplyFailure(emitter, category, code, message)
	}

	// Conditional apply consent is known only after the complete convergence
	// plan exists. A missing controlling TTY must therefore not reject a true
	// no-op; retain the open error and surface it only if consent is required.
	var terminal PromptIO
	var closer io.Closer
	var terminalErr error
	if !parsed.Yes {
		terminal, closer, terminalErr = applyOpenTTY()
		if closer != nil {
			defer closer.Close()
		}
	}
	outcome, err := RunConvergenceApply(context.Background(), role, parsed.Yes, parsed.JSON, terminal, operator)
	if err != nil {
		if terminalErr != nil && (errors.Is(err, ErrInteractionRefused) || errors.Is(err, ErrPromptInput)) {
			return emitConvergenceApplyFailure(emitter, output.CategoryValidation, "controlling_tty_required", "availability-impacting apply requires a controlling TTY or --yes")
		}
		category, code, message := classifyConvergenceApplyError(err)
		return emitConvergenceApplyFailure(emitter, category, code, message)
	}
	exit, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parseConvergenceApplyArguments(args []string) (convergenceApplyArguments, error) {
	parsed := convergenceApplyArguments{}
	positionals := make([]string, 0, len(args))
	seen := make(map[string]bool)
	for _, argument := range args {
		switch argument {
		case "--json", "--yes":
			if seen[argument] {
				return parsed, fmt.Errorf("%s may be supplied only once", argument)
			}
			seen[argument] = true
			if argument == "--json" {
				parsed.JSON = true
			} else {
				parsed.Yes = true
			}
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported apply option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) != 1 || positionals[0] != "apply" {
		return parsed, fmt.Errorf("usage: vpnctl apply [--yes] [--json]")
	}
	return parsed, nil
}

func printConvergenceApplyHelp(writer io.Writer) {
	fmt.Fprint(writer, `Apply only registered pending desired-state changes.

Usage:
  vpnctl apply [--yes] [--json]

Use vpnctl plan for a read-only preview. Apply never repairs owned drift.
`)
}

func classifyConvergenceApplyError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags), errors.Is(err, ErrInvalidMutationPlan),
		errors.Is(err, operations.ErrApplyInvalid), errors.Is(err, operations.ErrConvergencePlanInvalid),
		errors.Is(err, store.ErrStateNotFound):
		return output.CategoryValidation, "apply_request_invalid", "apply requires valid registered pending state on this host"
	case errors.Is(err, operations.ErrApplyConflict), errors.Is(err, store.ErrStateConflict),
		errors.Is(err, operations.ErrConvergenceSnapshotConflict), errors.Is(err, transport.ErrTransportSwitchStale):
		return output.CategoryConflict, "apply_plan_stale", "the pending plan or an overlapping owned resource changed; review plan and repair conflicting drift"
	case errors.Is(err, operations.ErrApplyNodeAgentUnavailable):
		return output.CategoryUnavailable, "apply_requires_node", "one or more pending operations must be applied from their private node"
	case errors.Is(err, operations.ErrApplyGatewayUnavailable), errors.Is(err, operations.ErrTransportSwitchGatewayUnavailable):
		return output.CategoryUnavailable, "gateway_unavailable", "node apply requires the authoritative gateway"
	case errors.Is(err, operations.ErrConvergenceSnapshotUnavailable), errors.Is(err, ErrSystemConvergenceApplyUnavailable):
		return output.CategoryUnavailable, "apply_convergence_unavailable", "registered pending convergence material is not available for safe apply"
	case errors.Is(err, ErrSystemConvergenceApplyExecutorUnavailable):
		return output.CategoryUnavailable, "apply_executor_unavailable", "the registered pending operation has no connected production executor yet"
	case errors.Is(err, ErrSystemTransportRuntimeUnavailable):
		return output.CategoryUnavailable, "transport_runtime_unavailable", "the selected transport runtime adapter is unavailable; no gateway selection was changed"
	case errors.Is(err, operations.ErrTransportSwitchApplyUncertain):
		return output.CategoryUnavailable, "transport_switch_uncertain", "the transport switch outcome is uncertain; retry apply to reconcile the retained operation"
	case errors.Is(err, ErrInteractionRefused), errors.Is(err, ErrPromptInput), errors.Is(err, ErrConsentDeclined):
		return output.CategoryValidation, "apply_consent_required", "availability-impacting apply requires explicit confirmation or --yes"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return output.CategoryUnavailable, "apply_cancelled", "apply did not complete"
	default:
		return output.CategoryInternal, "apply_failed", "vpnctl could not apply the registered pending changes"
	}
}

func emitConvergenceApplyFailure(emitter *ResultEmitter, category output.ExitCategory, code, message string) int {
	status := output.StatusFailed
	if category == output.CategoryConflict || category == output.CategoryUnavailable {
		status = output.StatusDegraded
	}
	result := output.NewResult("apply", status, category, output.SafeObject{"changed": false, "generation": uint64(0)})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	switch code {
	case "apply_plan_stale":
		result.RequiresAction = append(result.RequiresAction, output.Action{Code: "review_apply_state", Message: "Review pending intent and repair overlapping owned drift before retrying.", Command: "vpnctl plan"})
	case "apply_requires_node":
		result.RequiresAction = append(result.RequiresAction, output.Action{Code: "apply_on_private_node", Message: "Run apply on the private node that owns the pending operation.", Command: "vpnctl apply"})
	case "transport_runtime_unavailable":
		result.RequiresAction = append(result.RequiresAction, output.Action{Code: "verify_transport_runtime", Message: "Verify the selected transport runtime, then retry the retained apply operation.", Command: "vpnctl doctor transport"})
	case "transport_switch_uncertain":
		result.RequiresAction = append(result.RequiresAction, output.Action{Code: "reconcile_transport_switch", Message: "Retry apply; vpnctl will reconcile the retained gateway operation before any new switch attempt.", Command: "vpnctl apply"})
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}
