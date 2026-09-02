package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type nodeInitializerAPI interface {
	Plan(context.Context) (lifecycle.NodeInitPlan, error)
	Apply(context.Context, lifecycle.NodeInitPlan) (lifecycle.NodeInitResult, error)
}

var (
	nodeInitSystemPaths = store.DefaultPaths
	nodeInitLoadRole    = loadSystemHostRole
	nodeInitBuilder     = buildSystemNodeInitializer
	nodeInitOpenTTY     = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

func isNodeInitInvocation(args []string) bool {
	hasInit := false
	hasNode := false
	for _, argument := range args {
		if argument == "init" {
			hasInit = true
		}
		if argument == "--node" || strings.HasPrefix(argument, "--node=") {
			hasNode = true
		}
	}
	return hasInit && hasNode
}

func executeNodeInit(args []string, stdout, stderr io.Writer) int {
	parsed, help, err := parseNodeInitArguments(args)
	if help {
		printNodeInitHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "init failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitNodeInitFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}

	paths := nodeInitSystemPaths()
	role, err := nodeInitLoadRole(paths)
	if err != nil {
		return emitNodeInitFailure(emitter, output.CategoryValidation, "invalid_host_state", "vpnctl host state is invalid")
	}
	if role == RoleGateway {
		return emitNodeInitFailure(emitter, output.CategoryConflict, "init_conflict", "host is already initialized as gateway; role changes require an explicit migration or reinitialization")
	}
	initializer, err := nodeInitBuilder(context.Background(), paths)
	if err != nil {
		category, code, message := classifyNodeInitError(err)
		return emitNodeInitFailure(emitter, category, code, message)
	}
	workflow := &nodeInitWorkflow{initializer: initializer}

	var terminal PromptIO
	var closer io.Closer
	if !parsed.Yes && !parsed.DryRun {
		terminal, closer, _ = nodeInitOpenTTY()
		if closer != nil {
			defer closer.Close()
		}
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "init.node", Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes, JSON: parsed.JSON,
	}, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyNodeInitError(err)
		return emitNodeInitFailure(emitter, category, code, message)
	}
	code, emitErr := emitter.Emit(outcome.Result)
	if emitErr != nil {
		fmt.Fprintf(stderr, "init failed: %v\n", emitErr)
		return ExitInternal
	}
	return code
}

type nodeInitArguments struct {
	DryRun bool
	Yes    bool
	JSON   bool
}

func parseNodeInitArguments(args []string) (nodeInitArguments, bool, error) {
	parsed := nodeInitArguments{}
	normalized := make([]string, 0, len(args))
	seenJSON := false
	seenInit := false
	for _, argument := range args {
		switch argument {
		case "--json":
			if seenJSON {
				return parsed, false, fmt.Errorf("--json may be supplied only once")
			}
			seenJSON = true
			parsed.JSON = true
		case "init":
			if seenInit {
				normalized = append(normalized, argument)
				continue
			}
			seenInit = true
		default:
			normalized = append(normalized, argument)
		}
	}
	if !seenInit {
		return parsed, false, fmt.Errorf("node init command is missing")
	}
	flags := flag.NewFlagSet("init --node", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	gateway := flags.Bool("gateway", false, "initialize gateway role")
	node := flags.Bool("node", false, "initialize node role")
	flags.BoolVar(&parsed.DryRun, "dry-run", false, "show plan without mutation")
	flags.BoolVar(&parsed.Yes, "yes", false, "skip ordinary confirmation")
	var help bool
	flags.BoolVar(&help, "h", false, "show help")
	flags.BoolVar(&help, "help", false, "show help")
	if err := flags.Parse(normalized); err != nil {
		return parsed, false, err
	}
	if help {
		return parsed, true, nil
	}
	if flags.NArg() != 0 {
		return parsed, false, fmt.Errorf("unexpected init argument: %s", flags.Arg(0))
	}
	if !*node || *gateway {
		return parsed, false, fmt.Errorf("init requires exactly one of --gateway or --node")
	}
	return parsed, false, nil
}

type nodeInitWorkflow struct {
	initializer nodeInitializerAPI
	plan        lifecycle.NodeInitPlan
	planned     bool
}

func (workflow *nodeInitWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	plan, err := workflow.initializer.Plan(ctx)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan = plan
	workflow.planned = true
	return MutationPlan{Impact: ImpactAvailability, Result: nodeInitOutput(plan, lifecycle.NodeInitResult{}, false)}, nil
}

func (workflow *nodeInitWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("node init was not planned")
	}
	result, err := workflow.initializer.Apply(ctx, workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: nodeInitOutput(workflow.plan, result, true)}, nil
}

func nodeInitOutput(plan lifecycle.NodeInitPlan, applied lifecycle.NodeInitResult, appliedResult bool) output.Result {
	changed := plan.Changed
	units := plan.Units
	enrollmentStatus := "unjoined"
	if plan.Enrolled {
		enrollmentStatus = "joined"
	}
	if appliedResult {
		changed = applied.Changed
		units = applied.Units
	}
	result := output.NewResult("init.node", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": changed, "role": "node", "enrollment_status": enrollmentStatus,
		"active_tunnel": plan.ActiveTunnel, "staged_units": append([]string(nil), units...),
	})
	if plan.HostID != "" {
		result.ResourceIDs["host_id"] = plan.HostID
	}
	return result
}

func buildSystemNodeInitializer(ctx context.Context, paths store.Paths) (nodeInitializerAPI, error) {
	discoverer, err := linuxplatform.NewDiscoverer(paths.Root)
	if err != nil {
		return nil, err
	}
	snapshot, err := discoverer.Discover(ctx)
	if err != nil {
		return nil, err
	}
	return controller.NewSystemNodeInitializer(paths, snapshot, developmentComponentManifest(), linuxplatform.DefaultVPNCTLBinaryPath)
}

func classifyNodeInitError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, lifecycle.ErrNodeRoleConflict), errors.Is(err, lifecycle.ErrNodeLayoutConflict):
		return output.CategoryConflict, "init_conflict", err.Error()
	case errors.Is(err, linuxplatform.ErrUnsupportedHost), errors.Is(err, ErrInteractionRefused), errors.Is(err, ErrConsentDeclined),
		errors.Is(err, ErrPromptInput), errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags):
		return output.CategoryValidation, "init_validation", err.Error()
	default:
		return output.CategoryInternal, "init_internal_error", "vpnctl could not initialize the node"
	}
}

func emitNodeInitFailure(emitter *ResultEmitter, category output.ExitCategory, warningCode, warningMessage string) int {
	result := output.NewResult("init.node", output.StatusFailed, category, output.SafeObject{"changed": false, "role": "node"})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printNodeInitHelp(writer io.Writer) {
	fmt.Fprint(writer, `Initialize this application host as an unjoined vpnctl node.

Usage:
  vpnctl init --node [--dry-run] [--yes] [--json]
`)
}
