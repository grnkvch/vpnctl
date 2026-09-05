package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	nodeLifecycleSystemPaths = store.DefaultPaths
	nodeLifecycleLoadRole    = loadSystemHostRole
	nodeLifecycleBuilder     = func(paths store.Paths) (NodeLifecycleOperator, error) {
		stateStore, err := store.NewStateStore(paths)
		if err != nil {
			return nil, err
		}
		secrets, err := store.NewSecretStore(paths)
		if err != nil {
			return nil, err
		}
		return controller.NewSystemGatewayNodeLifecycleManager(paths, stateStore, secrets)
	}
	nodeLifecycleOpenTTY = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

func isNodeLifecycleInvocation(args []string) bool {
	positionals := commandPositionals(args)
	return len(positionals) >= 2 && positionals[0] == "node" && (positionals[1] == "revoke" || positionals[1] == "delete")
}

type nodeLifecycleArguments struct {
	CommandID string
	Reference string
	DryRun    bool
	Yes       bool
	JSON      bool
	Help      bool
}

func executeNodeLifecycle(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseNodeLifecycleArguments(args)
	if parsed.Help {
		fmt.Fprint(stdout, "Revoke or delete a gateway-managed private node.\n\nUsage:\n  vpnctl node revoke <name-or-id> [--dry-run] [--yes] [--json]\n  vpnctl node delete <name-or-id> [--dry-run] [--yes] [--json]\n")
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "node failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitNodeLifecycleFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := nodeLifecycleSystemPaths()
	role, err := nodeLifecycleLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitNodeLifecycleFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_host_state", "node lifecycle commands require an initialized gateway")
	}
	if _, _, err := V2CommandRegistry().ResolveMutationMode(MutationRequest{CommandID: parsed.CommandID, Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes}); err != nil {
		category, code, message := classifyNodeLifecycleError(err)
		return emitNodeLifecycleFailure(emitter, parsed.CommandID, category, code, message)
	}
	manager, err := nodeLifecycleBuilder(paths)
	if err != nil {
		return emitNodeLifecycleFailure(emitter, parsed.CommandID, output.CategoryInternal, "node_lifecycle_unavailable", "vpnctl could not construct the node lifecycle service")
	}
	var workflow MutationWorkflow
	if parsed.CommandID == "node.revoke" {
		workflow, err = NewNodeRevokeMutationWorkflow(manager, parsed.Reference)
	} else {
		workflow, err = NewNodeDeleteMutationWorkflow(manager, parsed.Reference)
	}
	if err != nil {
		category, code, message := classifyNodeLifecycleError(err)
		return emitNodeLifecycleFailure(emitter, parsed.CommandID, category, code, message)
	}
	var terminal PromptIO
	var closer io.Closer
	if !parsed.Yes && !parsed.DryRun {
		terminal, closer, err = nodeLifecycleOpenTTY()
		if err != nil {
			return emitNodeLifecycleFailure(emitter, parsed.CommandID, output.CategoryValidation, "controlling_tty_required", "node lifecycle confirmation requires a controlling TTY or --yes")
		}
		defer closer.Close()
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: parsed.CommandID, Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes, JSON: parsed.JSON,
	}, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyNodeLifecycleError(err)
		return emitNodeLifecycleFailure(emitter, parsed.CommandID, category, code, message)
	}
	exit, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parseNodeLifecycleArguments(args []string) (nodeLifecycleArguments, error) {
	parsed := nodeLifecycleArguments{CommandID: "node.revoke"}
	positionals := make([]string, 0, 3)
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
				return parsed, fmt.Errorf("unsupported node lifecycle option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) != 3 || positionals[0] != "node" || (positionals[1] != "revoke" && positionals[1] != "delete") {
		return parsed, fmt.Errorf("node revoke/delete requires exactly one name or ID")
	}
	parsed.CommandID = "node." + positionals[1]
	parsed.Reference = positionals[2]
	return parsed, nil
}

func classifyNodeLifecycleError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags), errors.Is(err, ErrInteractionRefused):
		return output.CategoryValidation, "node_lifecycle_request_invalid", "the node lifecycle request or host role is invalid"
	case errors.Is(err, enrollment.ErrNodeNotFound), errors.Is(err, enrollment.ErrNodeDeleteRequiresRevoke):
		return output.CategoryValidation, "node_lifecycle_invalid", "the node does not exist or must be revoked before deletion"
	case errors.Is(err, enrollment.ErrNodeLifecycleStale), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "node_lifecycle_conflict", "the node lifecycle plan conflicts with current state"
	case errors.Is(err, enrollment.ErrNodeLifecycleUncertain), errors.Is(err, enrollment.ErrNodeCleanupPending):
		return output.CategoryUnavailable, "node_lifecycle_incomplete", "the authoritative transition may require repair"
	default:
		return output.CategoryInternal, "node_lifecycle_failed", "vpnctl could not complete the node lifecycle operation"
	}
}

func emitNodeLifecycleFailure(emitter *ResultEmitter, commandID string, category output.ExitCategory, code, message string) int {
	if commandID != "node.revoke" && commandID != "node.delete" {
		commandID = "node.revoke"
	}
	result := output.NewResult(commandID, output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}
