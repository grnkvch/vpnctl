package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

var (
	exposeSystemPaths = store.DefaultPaths
	exposeLoadRole    = loadSystemHostRole
	exposeBuild       = buildSystemExposeCreateSaga
)

func isExposeInvocation(args []string) bool {
	for _, argument := range args {
		if argument == "--json" {
			continue
		}
		return argument == "expose"
	}
	return false
}

type exposeArguments struct {
	Request  ingress.ExposeCreateRequest
	DryRun   bool
	Defer    bool
	JSON     bool
	ShowHelp bool
}

func executeExpose(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseExposeArguments(args)
	if parsed.ShowHelp {
		printExposeHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "expose failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitExposeFailure(emitter, output.CategoryValidation, "invalid_arguments", "expose arguments are invalid")
	}
	paths := exposeSystemPaths()
	role, err := exposeLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitExposeFailure(emitter, output.CategoryValidation, "invalid_host_state", "expose requires an initialized and joined private node")
	}
	if role != RoleNode {
		return emitExposeFailure(emitter, output.CategoryValidation, "unsupported_role", "expose is available only on a private node")
	}
	saga, err := exposeBuild(paths)
	if err != nil {
		category, code, message := classifyExposeError(err)
		return emitExposeFailure(emitter, category, code, message)
	}
	workflow, err := NewExposeCreateMutationWorkflow(saga, parsed.Request)
	if err != nil {
		category, code, message := classifyExposeError(err)
		return emitExposeFailure(emitter, category, code, message)
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "expose", Role: role, DryRun: parsed.DryRun, Defer: parsed.Defer, JSON: parsed.JSON,
	}, nil, workflow, workflow)
	if err != nil {
		category, code, message := classifyExposeError(err)
		return emitExposeFailure(emitter, category, code, message)
	}
	code, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func parseExposeArguments(args []string) (exposeArguments, error) {
	parsed := exposeArguments{}
	positionals := make([]string, 0, 2)
	limitArguments := make([]string, 0, 4)
	seen := make(map[string]bool)
	for index := 0; index < len(args); index++ {
		argument := args[index]
		name, inlineValue, inline := strings.Cut(argument, "=")
		requireValue := func() (string, error) {
			if seen[name] {
				return "", fmt.Errorf("%s may be supplied only once", name)
			}
			seen[name] = true
			if inline {
				if inlineValue == "" {
					return "", fmt.Errorf("%s requires a value", name)
				}
				return inlineValue, nil
			}
			if index+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", name)
			}
			index++
			return args[index], nil
		}
		switch name {
		case "--json", "--dry-run", "--defer", "--prefix", "--allow-non-loopback":
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
			case "--prefix":
				parsed.Request.Prefix = true
			case "--allow-non-loopback":
				parsed.Request.AllowNonLoopback = true
			}
		case "--name", "--path":
			value, err := requireValue()
			if err != nil {
				return parsed, err
			}
			if name == "--name" {
				parsed.Request.Name = value
			} else {
				parsed.Request.Path = value
			}
		case "--body-limit", "--timeout":
			value, err := requireValue()
			if err != nil {
				return parsed, err
			}
			limitArguments = append(limitArguments, name, value)
		case "-h", "--help", "help":
			parsed.ShowHelp = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported expose option")
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.ShowHelp {
		return parsed, nil
	}
	if parsed.DryRun && parsed.Defer {
		return parsed, fmt.Errorf("--dry-run and --defer are mutually exclusive")
	}
	if len(positionals) != 2 || positionals[0] != "expose" {
		return parsed, fmt.Errorf("expose requires exactly one upstream")
	}
	parsed.Request.Upstream = positionals[1]
	limits, err := ingress.ParseExposeLimitOptions(limitArguments)
	if err != nil {
		return parsed, err
	}
	parsed.Request.LimitOverrides = limits
	return parsed, nil
}

func buildSystemExposeCreateSaga(paths store.Paths) (ExposeCreateMutationSaga, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	state, err := stateStore.Load()
	if err != nil || state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Gateway == nil {
		return nil, fmt.Errorf("%w: joined node state is unavailable", ErrGatewayUnavailable)
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, err
	}
	credentials, err := tunnel.NewStoreCredentialSource(secrets)
	if err != nil {
		return nil, err
	}
	var frpComponent model.ComponentPin
	found := false
	for _, component := range state.Components.Components {
		if component.Name == tunnel.FRPProviderName {
			frpComponent, found = component, true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("frp component is absent from installed state")
	}
	provider, err := tunnel.NewFRPProvider(paths.Root, frpComponent, credentials)
	if err != nil {
		return nil, err
	}
	runner := linuxplatform.OSProbeRunner{}
	configuration, err := tunnel.NewFRPClientConfigurationManager(paths, provider, runner, tunnel.OSFRPClientReloadRunner{})
	if err != nil {
		return nil, err
	}
	readiness, err := tunnel.NewFRPClientSystemReadinessProber(paths, tunnel.NewFRPHTTPStatusSource(), tunnel.NewNetTunnelUpstreamProber())
	if err != nil {
		return nil, err
	}
	tunnelRuntime, err := operations.NewFRPExposeNodeTunnel(provider, configuration, readiness)
	if err != nil {
		return nil, err
	}
	gateway, err := operations.NewSystemRemoteExposeGatewayCoordinator(paths, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	return operations.NewExposeCreateSaga(stateStore, gateway, tunnelRuntime)
}

func classifyExposeError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, operations.ErrExposeGatewayUnavailable), errors.Is(err, ErrGatewayUnavailable):
		return output.CategoryUnavailable, "gateway_unavailable", "the authoritative gateway is unavailable"
	case errors.Is(err, operations.ErrExposeOutcomeUncertain):
		return output.CategoryUnavailable, "expose_outcome_uncertain", "the expose outcome is uncertain; inspect state before retrying"
	case errors.Is(err, operations.ErrExposePlanStale), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "expose_conflict", "the expose conflicts with newer authoritative state"
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags), errors.Is(err, ingress.ErrExposeInvalidInput),
		errors.Is(err, ingress.ErrExposeNameConflict), errors.Is(err, ingress.ErrExposeRouteConflict),
		errors.Is(err, ingress.ErrExposeReservedPath), errors.Is(err, ingress.ErrExposeNonLoopbackOptIn),
		errors.Is(err, ingress.ErrExposeLimitInvalid), errors.Is(err, ingress.ErrUnsupportedExposeLimitOption):
		return output.CategoryValidation, "expose_validation", "the expose request is invalid"
	default:
		return output.CategoryInternal, "expose_internal_error", "vpnctl could not create the expose"
	}
}

func emitExposeFailure(emitter *ResultEmitter, category output.ExitCategory, warningCode, warningMessage string) int {
	result := output.NewResult("expose", output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: warningMessage})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printExposeHelp(writer io.Writer) {
	fmt.Fprint(writer, `Publish one HTTP application from the current private node.

Usage:
  vpnctl expose <port|host:port> [--name <name>] [--path <path>] [--prefix]
                [--allow-non-loopback] [--body-limit <size>] [--timeout <duration>]
                [--dry-run|--defer] [--json]

A port shorthand targets 127.0.0.1. If --path is omitted, vpnctl generates a
high-entropy exact path. Public URL paths are human-only and never enter JSON.
`)
}

type ExposeCreateMutationSaga interface {
	Plan(context.Context, ingress.ExposeCreateRequest) (operations.ExposeCreatePlan, error)
	Apply(context.Context, operations.ExposeCreatePlan) (operations.ExposeCreateResult, error)
	Defer(context.Context, operations.ExposeCreatePlan) (operations.ExposeCreateDeferredResult, error)
}

// ExposeCreateMutationWorkflow connects the sensitive domain plan to the
// common dry-run/immediate/deferred CLI boundary. The public MutationPlan holds
// only safe output; the path-bearing plan remains private to this one command
// invocation.
type ExposeCreateMutationWorkflow struct {
	saga    ExposeCreateMutationSaga
	request ingress.ExposeCreateRequest

	mu      sync.Mutex
	planned *operations.ExposeCreatePlan
}

func NewExposeCreateMutationWorkflow(
	saga ExposeCreateMutationSaga,
	request ingress.ExposeCreateRequest,
) (*ExposeCreateMutationWorkflow, error) {
	if saga == nil {
		return nil, fmt.Errorf("expose creation saga is required")
	}
	return &ExposeCreateMutationWorkflow{saga: saga, request: request}, nil
}

func (workflow *ExposeCreateMutationWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if ctx == nil || workflow == nil || workflow.saga == nil {
		return MutationPlan{}, fmt.Errorf("expose mutation workflow is incomplete")
	}
	domainPlan, err := workflow.saga.Plan(ctx, workflow.request)
	if err != nil {
		return MutationPlan{}, err
	}
	result, err := domainPlan.PreviewOutput()
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.mu.Lock()
	retained := domainPlan
	workflow.planned = &retained
	workflow.mu.Unlock()
	return MutationPlan{Impact: ImpactNone, Result: result}, nil
}

func (workflow *ExposeCreateMutationWorkflow) Apply(
	ctx context.Context,
	publicPlan MutationPlan,
	_ *InteractionInputs,
) (AppliedMutation, error) {
	domainPlan, err := workflow.retainedPlan(publicPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	created, err := workflow.saga.Apply(ctx, domainPlan)
	if err != nil {
		return AppliedMutation{}, err
	}
	result, err := created.Output()
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: result}, nil
}

func (workflow *ExposeCreateMutationWorkflow) RegisterPending(
	ctx context.Context,
	publicPlan MutationPlan,
) (DeferredReceipt, error) {
	domainPlan, err := workflow.retainedPlan(publicPlan)
	if err != nil {
		return DeferredReceipt{}, err
	}
	deferred, err := workflow.saga.Defer(ctx, domainPlan)
	if err != nil {
		return DeferredReceipt{}, err
	}
	result, err := deferred.Output()
	if err != nil {
		return DeferredReceipt{}, err
	}
	return DeferredReceipt{
		CommandID: "expose", OperationID: deferred.OperationID,
		AuthoritativeGeneration: deferred.GatewayStateGeneration, Result: result,
	}, nil
}

func (workflow *ExposeCreateMutationWorkflow) retainedPlan(publicPlan MutationPlan) (operations.ExposeCreatePlan, error) {
	if workflow == nil || workflow.saga == nil {
		return operations.ExposeCreatePlan{}, fmt.Errorf("expose mutation workflow is incomplete")
	}
	workflow.mu.Lock()
	defer workflow.mu.Unlock()
	if workflow.planned == nil || publicPlan.Result.ResourceIDs["expose_id"] != workflow.planned.Expose.ID ||
		publicPlan.Result.Command != "expose" || publicPlan.Impact != ImpactNone {
		return operations.ExposeCreatePlan{}, fmt.Errorf("%w: expose public plan does not match retained domain plan", ErrInvalidMutationPlan)
	}
	return *workflow.planned, nil
}

var _ MutationWorkflow = (*ExposeCreateMutationWorkflow)(nil)
var _ AuthoritativeDeferredWriter = (*ExposeCreateMutationWorkflow)(nil)
