package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

type handshakeHostViewer interface {
	Show(context.Context) (transport.HandshakeHostView, error)
}

var (
	transportHostSystemPaths  = store.DefaultPaths
	transportHostLoadRole     = loadSystemHostRole
	transportHostBuildViewer  = buildSystemHandshakeHostViewer
	transportHostBuildManager = buildSystemHandshakeHostManager
	transportHostOpenTTY      = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

func isTransportHostShowInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, nil)
	return len(positionals) >= 3 && positionals[0] == "transport" && positionals[1] == "host" && positionals[2] == "show"
}

func isTransportHostPrepareInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, nil)
	return len(positionals) >= 3 && positionals[0] == "transport" && positionals[1] == "host" && positionals[2] == "prepare"
}

func isTransportHostCommitInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, nil)
	return len(positionals) >= 3 && positionals[0] == "transport" && positionals[1] == "host" && positionals[2] == "commit"
}

func isTransportHostRollbackInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, nil)
	return len(positionals) >= 3 && positionals[0] == "transport" && positionals[1] == "host" && positionals[2] == "rollback"
}

type transportHostPrepareArguments struct {
	Hostname string
	DryRun   bool
	JSON     bool
	Help     bool
}

func executeTransportHostPrepare(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseTransportHostPrepareArguments(args)
	if parsed.Help {
		printTransportHostPrepareHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "transport host prepare failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitTransportHostMutationFailure(emitter, "transport.host.prepare", output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := transportHostSystemPaths()
	role, err := transportHostLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitTransportHostMutationFailure(emitter, "transport.host.prepare", output.CategoryValidation, "invalid_host_state", "transport host prepare requires an initialized gateway")
	}
	request := MutationRequest{CommandID: "transport.host.prepare", Role: role, DryRun: parsed.DryRun, JSON: parsed.JSON}
	if _, _, err := V2CommandRegistry().ResolveMutationMode(request); err != nil {
		category, code, message := classifyTransportHostMutationError(err)
		return emitTransportHostMutationFailure(emitter, "transport.host.prepare", category, code, message)
	}
	manager, err := transportHostBuildManager(paths)
	if err != nil {
		return emitTransportHostMutationFailure(emitter, "transport.host.prepare", output.CategoryInternal, "transport_host_unavailable", "vpnctl could not construct the handshake-host manager")
	}
	workflow, err := NewHandshakeHostPrepareWorkflow(manager, parsed.Hostname)
	if err != nil {
		return emitTransportHostMutationFailure(emitter, "transport.host.prepare", output.CategoryValidation, "invalid_arguments", err.Error())
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), request, nil, workflow, nil)
	if err != nil {
		category, code, message := classifyTransportHostMutationError(err)
		return emitTransportHostMutationFailure(emitter, "transport.host.prepare", category, code, message)
	}
	exit, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parseTransportHostPrepareArguments(args []string) (transportHostPrepareArguments, error) {
	parsed := transportHostPrepareArguments{}
	positionals := make([]string, 0, len(args))
	seen := make(map[string]bool)
	for _, argument := range args {
		switch argument {
		case "--json", "--dry-run":
			if seen[argument] {
				return parsed, fmt.Errorf("%s may be supplied only once", argument)
			}
			seen[argument] = true
			if argument == "--json" {
				parsed.JSON = true
			} else {
				parsed.DryRun = true
			}
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported transport host prepare option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) != 4 || positionals[0] != "transport" || positionals[1] != "host" || positionals[2] != "prepare" {
		return parsed, fmt.Errorf("usage: vpnctl transport host prepare <host> [--dry-run] [--json]")
	}
	parsed.Hostname = positionals[3]
	selection := model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1,
		CandidateID: "manual", Hostname: parsed.Hostname, SelectedAt: time.Unix(1, 0).UTC(),
	}
	if err := selection.Validate(); err != nil {
		return parsed, fmt.Errorf("handshake host must be a canonical lower-case DNS hostname: %w", err)
	}
	return parsed, nil
}

type transportHostCommitArguments struct {
	CommandID string
	DryRun    bool
	Yes       bool
	JSON      bool
	Help      bool
}

func executeTransportHostCommitOrRollback(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseTransportHostCommitArguments(args)
	if parsed.Help {
		printTransportHostCommitHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "transport host mutation failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitTransportHostMutationFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := transportHostSystemPaths()
	role, err := transportHostLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitTransportHostMutationFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_host_state", "transport host mutation requires an initialized gateway")
	}
	request := MutationRequest{CommandID: parsed.CommandID, Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes, JSON: parsed.JSON}
	if _, _, err := V2CommandRegistry().ResolveMutationMode(request); err != nil {
		category, code, message := classifyTransportHostMutationError(err)
		return emitTransportHostMutationFailure(emitter, parsed.CommandID, category, code, message)
	}
	manager, err := transportHostBuildManager(paths)
	if err != nil {
		return emitTransportHostMutationFailure(emitter, parsed.CommandID, output.CategoryInternal, "transport_host_unavailable", "vpnctl could not construct the handshake-host manager")
	}
	var workflow MutationWorkflow
	if parsed.CommandID == "transport.host.commit" {
		workflow, err = NewHandshakeHostCommitWorkflow(manager)
	} else {
		workflow, err = NewHandshakeHostRollbackWorkflow(manager)
	}
	if err != nil {
		return emitTransportHostMutationFailure(emitter, parsed.CommandID, output.CategoryInternal, "transport_host_unavailable", "vpnctl could not construct the handshake-host workflow")
	}
	var terminal PromptIO
	var closer io.Closer
	if !parsed.Yes && !parsed.DryRun {
		terminal, closer, err = transportHostOpenTTY()
		if err != nil {
			return emitTransportHostMutationFailure(emitter, parsed.CommandID, output.CategoryValidation, "controlling_tty_required", "transport host confirmation requires a controlling TTY or --yes")
		}
		defer closer.Close()
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), request, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyTransportHostMutationError(err)
		return emitTransportHostMutationFailure(emitter, parsed.CommandID, category, code, message)
	}
	exit, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parseTransportHostCommitArguments(args []string) (transportHostCommitArguments, error) {
	parsed := transportHostCommitArguments{CommandID: "transport.host.commit"}
	positionals := make([]string, 0, len(args))
	seen := make(map[string]bool)
	for _, argument := range args {
		switch argument {
		case "--json", "--dry-run", "--yes":
			if seen[argument] {
				return parsed, fmt.Errorf("%s may be supplied only once", argument)
			}
			seen[argument] = true
			switch argument {
			case "--json":
				parsed.JSON = true
			case "--dry-run":
				parsed.DryRun = true
			case "--yes":
				parsed.Yes = true
			}
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported transport host mutation option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if len(positionals) >= 3 && positionals[2] == "rollback" {
		parsed.CommandID = "transport.host.rollback"
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) != 3 || positionals[0] != "transport" || positionals[1] != "host" || (positionals[2] != "commit" && positionals[2] != "rollback") {
		return parsed, fmt.Errorf("usage: vpnctl transport host <commit|rollback> [--dry-run] [--yes] [--json]")
	}
	return parsed, nil
}

type transportHostShowArguments struct {
	JSON bool
	Help bool
}

func executeTransportHostShow(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseTransportHostShowArguments(args)
	if parsed.Help {
		printTransportHostShowHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "transport host show failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitTransportHostFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := transportHostSystemPaths()
	role, err := transportHostLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitTransportHostFailure(emitter, output.CategoryValidation, "invalid_host_state", "transport host show requires an initialized gateway")
	}
	if role != RoleGateway {
		return emitTransportHostFailure(emitter, output.CategoryValidation, "unsupported_role", "transport host show is available only on the gateway")
	}
	viewer, err := transportHostBuildViewer(paths)
	if err != nil {
		return emitTransportHostFailure(emitter, output.CategoryInternal, "transport_host_unavailable", "vpnctl could not construct the handshake-host observer")
	}
	var result output.Result
	err = V2CommandRegistry().Dispatch("transport.host.show", role, func(CommandSpec) error {
		view, showErr := viewer.Show(context.Background())
		if showErr == nil {
			result = HandshakeHostShowOutput(view)
		}
		return showErr
	})
	if err != nil {
		category, code, message := classifyTransportHostError(err)
		return emitTransportHostFailure(emitter, category, code, message)
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parseTransportHostShowArguments(args []string) (transportHostShowArguments, error) {
	parsed := transportHostShowArguments{}
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
				return parsed, fmt.Errorf("unsupported transport host show option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) != 3 || positionals[0] != "transport" || positionals[1] != "host" || positionals[2] != "show" {
		return parsed, fmt.Errorf("usage: vpnctl transport host show [--json]")
	}
	return parsed, nil
}

// HandshakeHostManager requires a runtime for its complete lifecycle API, but
// Show never reaches it. Keeping a separate rejecting runtime preserves the
// inspection command's capability-limited construction boundary.
func buildSystemHandshakeHostViewer(paths store.Paths) (handshakeHostViewer, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	prober, err := transport.NewTLSHandshakeHostProber(transport.TLSHandshakeHostProbeOptions{})
	if err != nil {
		return nil, err
	}
	return transport.NewHandshakeHostManager(stateStore, prober, rejectingHandshakeHostRuntime{}, nil, nil)
}

func buildSystemHandshakeHostManager(paths store.Paths) (HandshakeHostGatewayManager, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, err
	}
	runtime, err := controller.NewSystemGatewayHandshakeHostRuntime(paths, stateStore, secrets)
	if err != nil {
		return nil, err
	}
	prober, err := transport.NewTLSHandshakeHostProber(transport.TLSHandshakeHostProbeOptions{})
	if err != nil {
		return nil, err
	}
	return transport.NewHandshakeHostManager(stateStore, prober, runtime, nil, nil)
}

type rejectingHandshakeHostRuntime struct{}

func (rejectingHandshakeHostRuntime) Prepare(context.Context, model.State) (transport.HandshakeHostGatewayActivation, error) {
	return nil, errors.New("read-only handshake-host viewer cannot prepare runtime state")
}

func classifyTransportHostError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole):
		return output.CategoryValidation, "unsupported_role", "transport host show is available only on the gateway"
	case errors.Is(err, store.ErrStateNotFound):
		return output.CategoryValidation, "invalid_host_state", "transport host show requires an initialized gateway"
	default:
		return output.CategoryInternal, "transport_host_internal_error", "vpnctl could not inspect the active handshake host"
	}
}

func classifyTransportHostMutationError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags), errors.Is(err, ErrInteractionRefused),
		errors.Is(err, transport.ErrHandshakeHostChangeNotFound), errors.Is(err, transport.ErrHandshakeHostRollbackExpired):
		return output.CategoryValidation, "transport_host_invalid", "the transport host request or current replacement state is invalid"
	case errors.Is(err, transport.ErrHandshakeHostChangeExists), errors.Is(err, transport.ErrHandshakeHostRollbackPending),
		errors.Is(err, transport.ErrHandshakeHostPlanStale), errors.Is(err, transport.ErrHandshakeHostImpactChanged),
		errors.Is(err, controller.ErrHandshakeHostRuntimeConflict), errors.Is(err, controller.ErrHandshakeHostRuntimeDrift),
		errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "transport_host_conflict", "another handshake-host replacement or rollback window conflicts with this request"
	case errors.Is(err, transport.ErrNoHandshakeHostCandidate):
		return output.CategoryUnavailable, "transport_host_probe_failed", "the explicitly selected handshake host did not pass the required TLS probe"
	case errors.Is(err, transport.ErrHandshakeHostCommitUncertain), errors.Is(err, transport.ErrHandshakeHostFinalizePending):
		return output.CategoryUnavailable, "transport_host_uncertain", "the handshake-host runtime or authoritative state requires explicit inspection and repair"
	default:
		return output.CategoryUnavailable, "transport_host_operation_failed", "vpnctl could not complete the handshake-host operation; the active host was not changed unless reported as uncertain"
	}
}

func emitTransportHostMutationFailure(emitter *ResultEmitter, command string, category output.ExitCategory, code, message string) int {
	result := output.NewResult(command, output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: singleLineGatewayInitMessage(message)})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func emitTransportHostFailure(emitter *ResultEmitter, category output.ExitCategory, warningCode, warningMessage string) int {
	result := output.NewResult("transport.host.show", output.StatusFailed, category, output.SafeObject{})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func printTransportHostShowHelp(writer io.Writer) {
	fmt.Fprint(writer, `Inspect the gateway's explicitly pinned restricted-transport handshake host.

Usage:
  vpnctl transport host show [--json]

The command probes only the active pinned host. It never selects, prepares, or
switches to another hostname automatically.
`)
}

func printTransportHostPrepareHelp(writer io.Writer) {
	fmt.Fprint(writer, `Validate and stage one explicit replacement for the gateway handshake host.

Usage:
  vpnctl transport host prepare <host> [--dry-run] [--json]

Planning probes exactly the supplied hostname and reports every affected node
and client. It never changes the live listener; activation requires a separate
transport host commit operation.
`)
}

func printTransportHostCommitHelp(writer io.Writer) {
	fmt.Fprint(writer, `Commit or roll back the one staged gateway handshake-host replacement.

Usage:
  vpnctl transport host commit [--dry-run] [--yes] [--json]
  vpnctl transport host rollback [--dry-run] [--yes] [--json]

Both operations require explicit confirmation unless --yes is supplied.
Candidate publication is validated, health-gated, and automatically restored
to the exact previous listener generation when activation fails.
`)
}
