package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

var (
	joinSystemPaths = store.DefaultPaths
	joinLoadRole    = loadSystemHostRole
	joinBuild       = buildSystemNodeJoiner
	joinOpenTTY     = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

func isJoinInvocation(args []string) bool {
	for _, argument := range args {
		if argument == "--json" {
			continue
		}
		return argument == "join"
	}
	return false
}

type joinArguments struct {
	Transport model.TransportKind
	Presets   []string
	DryRun    bool
	Yes       bool
	JSON      bool
	ShowHelp  bool
}

func executeJoin(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseJoinArguments(args)
	if parsed.ShowHelp {
		printJoinHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "join failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitJoinFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := joinSystemPaths()
	role, err := joinLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitJoinFailure(emitter, output.CategoryValidation, "invalid_host_state", "join requires an initialized node")
	}
	if role != RoleNode {
		return emitJoinFailure(emitter, output.CategoryValidation, "unsupported_role", "join is available only on a private node")
	}
	joiner, err := joinBuild(paths)
	if err != nil {
		category, code, message := classifyJoinError(err)
		return emitJoinFailure(emitter, category, code, message)
	}
	workflow, err := NewNodeJoinMutationWorkflow(joiner, parsed.Transport, parsed.Presets)
	if err != nil {
		category, code, message := classifyJoinError(err)
		return emitJoinFailure(emitter, category, code, message)
	}
	var terminal PromptIO
	var closer io.Closer
	if !parsed.DryRun {
		terminal, closer, err = joinOpenTTY()
		if err != nil {
			return emitJoinFailure(emitter, output.CategoryValidation, "controlling_tty_required", "join requires hidden invite input from a controlling TTY")
		}
		defer closer.Close()
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "join", Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes, JSON: parsed.JSON,
	}, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyJoinError(err)
		return emitJoinFailure(emitter, category, code, message)
	}
	code, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func parseJoinArguments(args []string) (joinArguments, error) {
	parsed := joinArguments{Presets: []string{}}
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
			parsed.ShowHelp = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported join option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.ShowHelp {
		return parsed, nil
	}
	if len(positionals) < 2 || positionals[0] != "join" {
		return parsed, fmt.Errorf("join requires an explicit standard or restricted transport")
	}
	parsed.Transport = model.TransportKind(positionals[1])
	parsed.Presets = append(parsed.Presets, positionals[2:]...)
	if err := enrollment.ValidateNodeJoinIntent(parsed.Transport, parsed.Presets); err != nil {
		return parsed, err
	}
	return parsed, nil
}

func buildSystemNodeJoiner(paths store.Paths) (NodeJoiner, error) {
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, err
	}
	exchanger, err := enrollment.NewHTTPSNodeJoinExchanger(0, nil)
	if err != nil {
		return nil, err
	}
	return enrollment.NewNodeJoinWorkflow(state, secrets, exchanger, enrollment.NodeJoinRuntime{WireGuardRunner: wireguard.ExecRunner{}})
}

func classifyJoinError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, enrollment.ErrJoinUncertain):
		return output.CategoryUnavailable, "join_outcome_uncertain", "gateway commit may have completed; inspect both hosts before retrying"
	case errors.Is(err, enrollment.ErrJoinNotReady), errors.Is(err, enrollment.ErrPublicEnrollmentUnavailable), errors.Is(err, ErrGatewayUnavailable):
		return output.CategoryUnavailable, "join_unavailable", "the gateway or a mandatory join path is unavailable"
	case errors.Is(err, enrollment.ErrNodeAlreadyJoined), errors.Is(err, enrollment.ErrJoinConflict), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "join_conflict", singleLineGatewayInitMessage(err.Error())
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrInteractionRefused), errors.Is(err, ErrPromptInput),
		errors.Is(err, enrollment.ErrInviteTokenInvalid), errors.Is(err, enrollment.ErrInviteExpired),
		errors.Is(err, enrollment.ErrInviteCancelled), errors.Is(err, enrollment.ErrInviteConsumed):
		return output.CategoryValidation, "join_validation", singleLineGatewayInitMessage(err.Error())
	default:
		return output.CategoryInternal, "join_internal_error", "vpnctl could not join the private node"
	}
}

func emitJoinFailure(emitter *ResultEmitter, category output.ExitCategory, warningCode, warningMessage string) int {
	result := output.NewResult("join", output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printJoinHelp(writer io.Writer) {
	fmt.Fprint(writer, `Join an initialized private node to a gateway.

Usage:
  vpnctl join <standard|restricted> [preset...] [--dry-run] [--yes] [--json]

The initial transport and every initial preset are explicit. The one-time
invite is read only from a hidden controlling-TTY prompt.
`)
}

type NodeJoiner interface {
	PlanJoin(model.TransportKind, []string) (enrollment.NodeJoinPlan, error)
	Join(context.Context, *output.Secret, model.TransportKind, []string) (enrollment.NodeJoinResult, error)
}

// NodeJoinMutationWorkflow keeps token input in the common hidden-input
// boundary. Plan is read-only; key generation and public enrollment begin only
// in Apply after the explicit availability confirmation.
type NodeJoinMutationWorkflow struct {
	joiner    NodeJoiner
	transport model.TransportKind
	presets   []string
	planned   bool
}

func NewNodeJoinMutationWorkflow(joiner NodeJoiner, transportKind model.TransportKind, presets []string) (*NodeJoinMutationWorkflow, error) {
	if joiner == nil {
		return nil, fmt.Errorf("node joiner is required")
	}
	if err := enrollment.ValidateNodeJoinIntent(transportKind, presets); err != nil {
		return nil, err
	}
	return &NodeJoinMutationWorkflow{
		joiner: joiner, transport: transportKind, presets: append([]string{}, presets...),
	}, nil
}

func (workflow *NodeJoinMutationWorkflow) Plan(_ context.Context, inputs *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.joiner == nil {
		return MutationPlan{}, fmt.Errorf("node join workflow is incomplete")
	}
	token := inputs.Copy(StepInviteToken)
	defer wipeBytes(token)
	if len(token) == 0 {
		return MutationPlan{}, fmt.Errorf("join requires a hidden invite token")
	}
	joinPlan, err := workflow.joiner.PlanJoin(workflow.transport, workflow.presets)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.planned = true
	return MutationPlan{
		Impact: ImpactAvailability,
		Result: output.NewResult("join", output.StatusOK, output.CategorySuccess, output.SafeObject{
			"changed": true, "generation": joinPlan.CurrentStateGeneration + 1,
			"active_transport": string(workflow.transport), "presets": append([]string{}, workflow.presets...),
		}),
	}, nil
}

func (workflow *NodeJoinMutationWorkflow) Apply(ctx context.Context, _ MutationPlan, inputs *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.joiner == nil || !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("node join was not planned")
	}
	tokenBytes := inputs.Take(StepInviteToken)
	defer wipeBytes(tokenBytes)
	token, err := output.NewSecret(tokenBytes)
	if err != nil {
		return AppliedMutation{}, fmt.Errorf("read hidden invite token: %w", err)
	}
	defer token.Destroy()
	result, err := workflow.joiner.Join(ctx, &token, workflow.transport, workflow.presets)
	if err != nil {
		return AppliedMutation{}, err
	}
	public := output.NewResult("join", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": result.LocalStateGeneration,
		"gateway_generation": result.GatewayStateGeneration,
		"active_transport":   string(result.ActiveTransport), "presets": append([]string{}, result.Presets...),
	})
	public.ResourceIDs["node_id"] = result.NodeID
	return AppliedMutation{Result: public}, nil
}

var _ MutationWorkflow = (*NodeJoinMutationWorkflow)(nil)
