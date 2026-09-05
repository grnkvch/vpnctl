package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type nodeCatalogAPI interface {
	List() (enrollment.NodeList, error)
	Show(string) (enrollment.NodeShow, error)
}

var (
	nodeCatalogSystemPaths = store.DefaultPaths
	nodeCatalogLoadRole    = loadSystemHostRole
	nodeCatalogBuilder     = func(paths store.Paths) (nodeCatalogAPI, error) {
		stateStore, err := store.NewStateStore(paths)
		if err != nil {
			return nil, err
		}
		return enrollment.NewNodeCatalog(stateStore)
	}
)

func isNodeCatalogInvocation(args []string) bool {
	positionals := commandPositionals(args)
	return len(positionals) >= 2 && positionals[0] == "node" && (positionals[1] == "list" || positionals[1] == "show")
}

type nodeCatalogArguments struct {
	CommandID string
	Reference string
	JSON      bool
	Help      bool
}

func executeNodeCatalog(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseNodeCatalogArguments(args)
	if parsed.Help {
		fmt.Fprint(stdout, "Inspect gateway-managed private nodes.\n\nUsage:\n  vpnctl node list [--json]\n  vpnctl node show <name-or-id> [--json]\n")
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "node failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitNodeCatalogFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := nodeCatalogSystemPaths()
	role, err := nodeCatalogLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitNodeCatalogFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_host_state", "node inspection requires an initialized gateway")
	}
	var result output.Result
	err = V2CommandRegistry().Dispatch(parsed.CommandID, role, func(CommandSpec) error {
		catalog, buildErr := nodeCatalogBuilder(paths)
		if buildErr != nil {
			return buildErr
		}
		switch parsed.CommandID {
		case "node.list":
			list, listErr := catalog.List()
			if listErr != nil {
				return listErr
			}
			result = NodeListOutput(list)
		case "node.show":
			show, showErr := catalog.Show(parsed.Reference)
			if showErr != nil {
				return showErr
			}
			result = NodeShowOutput(show)
		default:
			return fmt.Errorf("unsupported node catalog command %s", parsed.CommandID)
		}
		return nil
	})
	if err != nil {
		category, code, message := classifyNodeCatalogError(err)
		return emitNodeCatalogFailure(emitter, parsed.CommandID, category, code, message)
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		fmt.Fprintf(stderr, "node failed: %v\n", err)
		return ExitInternal
	}
	return exit
}

func parseNodeCatalogArguments(args []string) (nodeCatalogArguments, error) {
	parsed := nodeCatalogArguments{CommandID: "node.list"}
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
				return parsed, fmt.Errorf("unsupported node option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) < 2 || positionals[0] != "node" {
		return parsed, fmt.Errorf("node requires list or show")
	}
	switch positionals[1] {
	case "list":
		parsed.CommandID = "node.list"
		if len(positionals) != 2 {
			return parsed, fmt.Errorf("node list accepts no arguments")
		}
	case "show":
		parsed.CommandID = "node.show"
		if len(positionals) != 3 {
			return parsed, fmt.Errorf("node show requires exactly one name or ID")
		}
		parsed.Reference = positionals[2]
	default:
		return parsed, fmt.Errorf("node requires list or show")
	}
	return parsed, nil
}

func classifyNodeCatalogError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole):
		return output.CategoryValidation, "unsupported_role", "node inspection is available only on a gateway"
	case errors.Is(err, enrollment.ErrNodeNotFound):
		return output.CategoryValidation, "node_not_found", "the requested node does not exist"
	default:
		return output.CategoryInternal, "node_catalog_failed", "vpnctl could not inspect the node catalog"
	}
}

func emitNodeCatalogFailure(emitter *ResultEmitter, commandID string, category output.ExitCategory, code, message string) int {
	data := output.SafeObject{"items": []output.SafeObject{}}
	if commandID == "node.show" {
		data = output.SafeObject{"resource": output.SafeObject{}}
	}
	result := output.NewResult(commandID, output.StatusFailed, category, data)
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func commandPositionals(args []string) []string {
	positionals := make([]string, 0, len(args))
	for _, argument := range args {
		if strings.HasPrefix(argument, "-") {
			continue
		}
		positionals = append(positionals, argument)
	}
	return positionals
}
