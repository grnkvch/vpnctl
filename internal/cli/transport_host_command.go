package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

type handshakeHostViewer interface {
	Show(context.Context) (transport.HandshakeHostView, error)
}

var (
	transportHostSystemPaths = store.DefaultPaths
	transportHostLoadRole    = loadSystemHostRole
	transportHostBuildViewer = buildSystemHandshakeHostViewer
)

func isTransportHostShowInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, nil)
	return len(positionals) >= 3 && positionals[0] == "transport" && positionals[1] == "host" && positionals[2] == "show"
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

// The public viewer is intentionally constructed with an interface that has
// no mutation method. HandshakeHostManager requires a runtime for its complete
// lifecycle API, but Show never reaches it; keeping the rejecting runtime here
// makes that invariant explicit until the mutation commands construct their
// own system runtime.
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
