package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type clientCatalogAPI interface {
	List() (routing.ClientList, error)
	Show(string) (routing.ClientShow, error)
}

var (
	clientCatalogSystemPaths = store.DefaultPaths
	clientCatalogLoadRole    = loadSystemHostRole
	clientCatalogBuilder     = func(paths store.Paths) (clientCatalogAPI, error) {
		stateStore, err := store.NewStateStore(paths)
		if err != nil {
			return nil, err
		}
		secrets, err := store.NewSecretStore(paths)
		if err != nil {
			return nil, err
		}
		return routing.NewClientManager(paths, stateStore, secrets, routing.ClientManagerRuntime{})
	}
)

func isClientCatalogInvocation(args []string) bool {
	positionals := commandPositionals(args)
	return len(positionals) >= 2 && positionals[0] == "client" && (positionals[1] == "list" || positionals[1] == "show")
}

type clientCatalogArguments struct {
	CommandID string
	Reference string
	JSON      bool
	Help      bool
}

func executeClientCatalog(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseClientCatalogArguments(args)
	if parsed.Help {
		fmt.Fprint(stdout, "Inspect gateway-managed personal clients.\n\nUsage:\n  vpnctl client list [--json]\n  vpnctl client show <name-or-id> [--json]\n")
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "client failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitClientCatalogFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := clientCatalogSystemPaths()
	role, err := clientCatalogLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitClientCatalogFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_host_state", "client inspection requires an initialized gateway")
	}

	var result output.Result
	err = V2CommandRegistry().Dispatch(parsed.CommandID, role, func(CommandSpec) error {
		catalog, buildErr := clientCatalogBuilder(paths)
		if buildErr != nil {
			return buildErr
		}
		switch parsed.CommandID {
		case "client.list":
			list, listErr := catalog.List()
			if listErr != nil {
				return listErr
			}
			result = ClientListOutput(list)
		case "client.show":
			show, showErr := catalog.Show(parsed.Reference)
			if showErr != nil {
				return showErr
			}
			result = ClientShowOutput(show)
		}
		return nil
	})
	if err != nil {
		category, code, message := classifyClientCatalogError(err)
		return emitClientCatalogFailure(emitter, parsed.CommandID, category, code, message)
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		fmt.Fprintf(stderr, "client failed: %v\n", err)
		return ExitInternal
	}
	return exit
}

func parseClientCatalogArguments(args []string) (clientCatalogArguments, error) {
	parsed := clientCatalogArguments{CommandID: "client.list"}
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
				return parsed, fmt.Errorf("unsupported client option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) < 2 || positionals[0] != "client" {
		return parsed, fmt.Errorf("client requires list or show")
	}
	switch positionals[1] {
	case "list":
		parsed.CommandID = "client.list"
		if len(positionals) != 2 {
			return parsed, fmt.Errorf("client list accepts no arguments")
		}
	case "show":
		parsed.CommandID = "client.show"
		if len(positionals) != 3 {
			return parsed, fmt.Errorf("client show requires exactly one name or ID")
		}
		parsed.Reference = positionals[2]
	default:
		return parsed, fmt.Errorf("client requires list or show")
	}
	return parsed, nil
}

func ClientListOutput(list routing.ClientList) output.Result {
	items := make([]output.SafeObject, 0, len(list.Items))
	rows := make([][]string, 0, len(list.Items))
	for _, item := range list.Items {
		items = append(items, clientViewOutput(item))
		rows = append(rows, []string{item.ID, item.Name, string(item.Lifecycle), item.OverlayIPv4, string(item.Health)})
	}
	result := output.NewResult("client.list", output.StatusOK, output.CategorySuccess, output.SafeObject{"items": items})
	_ = result.AddHumanTable("clients", []string{"id", "name", "lifecycle", "overlay_ipv4", "health"}, rows)
	return result
}

func ClientShowOutput(show routing.ClientShow) output.Result {
	result := output.NewResult("client.show", output.StatusOK, output.CategorySuccess, output.SafeObject{"resource": clientViewOutput(show.Resource)})
	if show.Resource.ID != "" {
		result.ResourceIDs["client_id"] = show.Resource.ID
	}
	return result
}

func clientViewOutput(view routing.ClientView) output.SafeObject {
	resource := output.SafeObject{
		"id": view.ID, "name": view.Name, "platform": view.Platform, "lifecycle": string(view.Lifecycle),
		"overlay_ipv4": view.OverlayIPv4, "assigned_presets": append([]string{}, view.AssignedPresets...),
		"credential_generation": view.CredentialGeneration, "policy_generation": view.PolicyGeneration,
		"active_transport": string(view.ActiveTransport), "transport_state": string(view.TransportState),
		"export_state": string(view.ExportState), "health": string(view.Health), "created_at": view.CreatedAt.UTC().Format(time.RFC3339),
	}
	if view.RevokedAt != nil {
		resource["revoked_at"] = view.RevokedAt.UTC().Format(time.RFC3339)
	}
	return resource
}

func classifyClientCatalogError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole):
		return output.CategoryValidation, "unsupported_role", "client inspection is available only on a gateway"
	case errors.Is(err, routing.ErrClientNotFound):
		return output.CategoryValidation, "client_not_found", "the requested client does not exist"
	default:
		return output.CategoryInternal, "client_catalog_failed", "vpnctl could not inspect the client catalog"
	}
}

func emitClientCatalogFailure(emitter *ResultEmitter, commandID string, category output.ExitCategory, code, message string) int {
	data := output.SafeObject{"items": []output.SafeObject{}}
	if commandID == "client.show" {
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
