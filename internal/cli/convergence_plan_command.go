package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	planSystemPaths = store.DefaultPaths
	planLoadRole    = loadSystemHostRole
	planBuild       = buildSystemConvergencePlanner
	planRun         = RunConvergencePlan
)

func isPlanInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, nil)
	return len(positionals) > 0 && positionals[0] == "plan"
}

type planArguments struct {
	JSON bool
	Help bool
}

func executePlan(args []string, stdout, stderr io.Writer) int {
	parsed, err := parsePlanArguments(args)
	if parsed.Help {
		printPlanHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "plan failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitPlanCommandFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := planSystemPaths()
	role, err := planLoadRole(paths)
	if err != nil {
		return emitPlanCommandFailure(emitter, output.CategoryValidation, "state_invalid", "authoritative state cannot be decoded or validated")
	}
	if role == RoleUninitialized {
		return emitPlanCommandFailure(emitter, output.CategoryValidation, "state_not_found", "vpnctl is not initialized on this host")
	}
	planner, err := planBuild(paths)
	if err != nil {
		return emitPlanCommandFailure(emitter, output.CategoryInternal, "planner_unavailable", "vpnctl could not construct the convergence planner")
	}
	result, err := planRun(context.Background(), role, planner)
	if err != nil {
		category, code, message := classifyPlanCommandError(err)
		return emitPlanCommandFailure(emitter, category, code, message)
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parsePlanArguments(args []string) (planArguments, error) {
	parsed := planArguments{}
	positionals := make([]string, 0, len(args))
	for _, argument := range args {
		switch argument {
		case "--json":
			if parsed.JSON {
				return parsed, fmt.Errorf("--json may be supplied only once")
			}
			parsed.JSON = true
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported plan option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) != 1 || positionals[0] != "plan" {
		return parsed, fmt.Errorf("usage: vpnctl plan [--json]")
	}
	return parsed, nil
}

func printPlanHelp(writer io.Writer) {
	fmt.Fprint(writer, `Show registered pending changes and vpnctl-owned drift without mutation.

Usage:
  vpnctl plan [--json]
`)
}

func buildSystemConvergencePlanner(paths store.Paths) (*operations.ConvergencePlanner, error) {
	convergence, err := operations.NewFileConvergenceSnapshotSource(paths.ConvergenceFile)
	if err != nil {
		return nil, err
	}
	owned, err := operations.NewSystemOwnedResourceDiscoverer(paths.Root, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, err
	}
	return operations.NewConvergencePlanner(convergence, owned)
}

func classifyPlanCommandError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole):
		return output.CategoryValidation, "unsupported_role", "plan requires an initialized gateway or node"
	case errors.Is(err, operations.ErrConvergencePlanInvalid):
		return output.CategoryValidation, "invalid_convergence_state", "persisted convergence metadata is invalid"
	case errors.Is(err, operations.ErrConvergenceSnapshotUnavailable):
		return output.CategoryUnavailable, "convergence_snapshot_unavailable", "persisted convergence metadata is not available yet"
	case errors.Is(err, operations.ErrOwnedResourceDiscoveryUnsupported):
		return output.CategoryUnavailable, "owned_discovery_unsupported", "one or more applied resource kinds do not have a production observer yet"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return output.CategoryUnavailable, "plan_cancelled", "convergence planning did not complete"
	default:
		return output.CategoryUnavailable, "owned_discovery_unavailable", "vpnctl could not observe one or more owned resources"
	}
}

func emitPlanCommandFailure(emitter *ResultEmitter, category output.ExitCategory, code, message string) int {
	status := output.StatusFailed
	if category == output.CategoryUnavailable || category == output.CategoryConflict {
		status = output.StatusDegraded
	}
	result := output.NewResult("plan", status, category, output.SafeObject{
		"impact": "none", "changes": []output.SafeObject{}, "drift": []output.SafeObject{},
	})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}
