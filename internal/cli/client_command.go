package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

var (
	clientMutationSystemPaths = store.DefaultPaths
	clientMutationLoadRole    = loadSystemHostRole
	clientMutationBuilder     = buildSystemClientMutationService
	clientMutationOpenTTY     = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

type systemClientMutationService struct {
	manager  *routing.ClientManager
	exporter *routing.ClientExporter
	secrets  *store.SecretStore
	runtime  clientGatewayRuntime
}

type clientGatewayRuntime interface {
	Reconcile(context.Context) error
}

var errClientRuntimePending = errors.New("gateway client runtime reconciliation is pending")

func buildSystemClientMutationService(paths store.Paths) (clientMutationAPI, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, err
	}
	manager, err := routing.NewClientManager(paths, stateStore, secrets, routing.ClientManagerRuntime{})
	if err != nil {
		return nil, err
	}
	exporter, err := routing.NewClientExporter(paths, stateStore, secrets)
	if err != nil {
		return nil, err
	}
	runtime, err := controller.NewSystemGatewayClientRuntime(paths, stateStore, secrets)
	if err != nil {
		return nil, err
	}
	return &systemClientMutationService{manager: manager, exporter: exporter, secrets: secrets, runtime: runtime}, nil
}

func (service *systemClientMutationService) PlanAdd(request routing.ClientAddRequest) (routing.ClientAddPlan, error) {
	return service.manager.PlanAdd(request)
}

func (service *systemClientMutationService) CommitAdd(ctx context.Context, plan routing.ClientAddPlan) (routing.ClientAddResult, error) {
	result, err := service.manager.CommitAdd(ctx, plan)
	if err != nil {
		return result, err
	}
	if reconcileErr := service.runtime.Reconcile(ctx); reconcileErr != nil {
		return result, fmt.Errorf("%w: %v", errClientRuntimePending, reconcileErr)
	}
	return result, nil
}

func (service *systemClientMutationService) PlanRotate(reference string) (routing.ClientLifecyclePlan, error) {
	return service.manager.PlanRotate(reference)
}

func (service *systemClientMutationService) CommitRotate(ctx context.Context, plan routing.ClientLifecyclePlan) (routing.ClientLifecycleResult, error) {
	result, err := service.manager.CommitRotate(ctx, plan)
	return result, service.reconcileLifecycle(ctx, result, err)
}

func (service *systemClientMutationService) PlanRevoke(reference string) (routing.ClientLifecyclePlan, error) {
	return service.manager.PlanRevoke(reference)
}

func (service *systemClientMutationService) CommitRevoke(plan routing.ClientLifecyclePlan) (routing.ClientLifecycleResult, error) {
	result, err := service.manager.CommitRevoke(plan)
	return result, service.reconcileLifecycle(context.Background(), result, err)
}

func (service *systemClientMutationService) PlanDelete(reference string) (routing.ClientLifecyclePlan, error) {
	return service.manager.PlanDelete(reference)
}

func (service *systemClientMutationService) CommitDelete(plan routing.ClientLifecyclePlan) (routing.ClientLifecycleResult, error) {
	result, err := service.manager.CommitDelete(plan)
	return result, service.reconcileLifecycle(context.Background(), result, err)
}

func (service *systemClientMutationService) reconcileLifecycle(ctx context.Context, result routing.ClientLifecycleResult, domainErr error) error {
	if domainErr != nil && !errors.Is(domainErr, routing.ErrClientCleanupPending) {
		return domainErr
	}
	if reconcileErr := service.runtime.Reconcile(ctx); reconcileErr != nil {
		return errors.Join(domainErr, fmt.Errorf("%w: %v", errClientRuntimePending, reconcileErr))
	}
	return domainErr
}

func (service *systemClientMutationService) PlanExport(request routing.ClientExportRequest) (routing.ClientExportPlan, error) {
	privateKey, err := service.secrets.Get(transport.GatewayStandardCredentialRef)
	if err != nil {
		return routing.ClientExportPlan{}, fmt.Errorf("read gateway standard credential: %w", err)
	}
	publicKey, err := wireguard.PublicKey(context.Background(), wireguard.ExecRunner{}, strings.TrimSpace(string(privateKey)))
	if err != nil {
		return routing.ClientExportPlan{}, err
	}
	request.GatewayPublicKey = publicKey
	return service.exporter.Plan(request)
}

func (service *systemClientMutationService) CommitExport(plan routing.ClientExportPlan) (routing.ClientExportResult, error) {
	return service.exporter.Commit(plan)
}

func isClientMutationInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, map[string]bool{"--output": true})
	if len(positionals) < 2 || positionals[0] != "client" {
		return false
	}
	switch positionals[1] {
	case "add", "revoke", "delete", "rotate", "export":
		return true
	default:
		return false
	}
}

type clientMutationArguments struct {
	CommandID string
	Reference string
	Presets   []string
	Format    routing.ClientExportFormat
	Output    string
	Force     bool
	DryRun    bool
	Yes       bool
	JSON      bool
	Help      bool
}

func executeClientMutation(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseClientMutationArguments(args)
	if parsed.Help {
		printClientMutationHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "client failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitClientMutationFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := clientMutationSystemPaths()
	role, err := clientMutationLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitClientMutationFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_host_state", "client commands require an initialized gateway")
	}
	if _, _, err := V2CommandRegistry().ResolveMutationMode(MutationRequest{CommandID: parsed.CommandID, Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes}); err != nil {
		category, code, message := classifyClientMutationError(err)
		return emitClientMutationFailure(emitter, parsed.CommandID, category, code, message)
	}
	service, err := clientMutationBuilder(paths)
	if err != nil {
		return emitClientMutationFailure(emitter, parsed.CommandID, output.CategoryInternal, "client_service_unavailable", "vpnctl could not construct the client service")
	}

	var workflow MutationWorkflow
	switch parsed.CommandID {
	case "client.add":
		workflow = &clientAddMutationWorkflow{service: service, request: routing.ClientAddRequest{Name: parsed.Reference, PresetNames: parsed.Presets}}
	case "client.rotate", "client.revoke", "client.delete":
		workflow = &clientLifecycleMutationWorkflow{service: service, commandID: parsed.CommandID, reference: parsed.Reference}
	case "client.export":
		workflow = &clientExportMutationWorkflow{service: service, request: routing.ClientExportRequest{
			ClientReference: parsed.Reference, Format: parsed.Format, OutputPath: parsed.Output, Force: parsed.Force,
		}}
	}

	var terminal PromptIO
	var closer io.Closer
	if (parsed.CommandID == "client.rotate" || parsed.CommandID == "client.revoke" || parsed.CommandID == "client.delete") && !parsed.Yes && !parsed.DryRun {
		terminal, closer, err = clientMutationOpenTTY()
		if err != nil {
			return emitClientMutationFailure(emitter, parsed.CommandID, output.CategoryValidation, "controlling_tty_required", "client lifecycle confirmation requires a controlling TTY or --yes")
		}
		defer closer.Close()
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: parsed.CommandID, Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes, JSON: parsed.JSON,
	}, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyClientMutationError(err)
		return emitClientMutationFailure(emitter, parsed.CommandID, category, code, message)
	}
	exit, err := emitter.Emit(outcome.Result)
	if err != nil {
		fmt.Fprintf(stderr, "client failed: %v\n", err)
		return ExitInternal
	}
	return exit
}

func parseClientMutationArguments(args []string) (clientMutationArguments, error) {
	parsed := clientMutationArguments{CommandID: "client.add"}
	positionals := make([]string, 0, len(args))
	seen := make(map[string]bool)
	for index := 0; index < len(args); index++ {
		argument := args[index]
		name, inlineValue, inline := strings.Cut(argument, "=")
		switch name {
		case "--json", "--dry-run", "--yes", "--force":
			if inline || seen[name] {
				return parsed, fmt.Errorf("%s may be supplied only once and takes no value", name)
			}
			seen[name] = true
			switch name {
			case "--json":
				parsed.JSON = true
			case "--dry-run":
				parsed.DryRun = true
			case "--yes":
				parsed.Yes = true
			case "--force":
				parsed.Force = true
			}
		case "--output":
			if seen[name] {
				return parsed, fmt.Errorf("--output may be supplied only once")
			}
			seen[name] = true
			if inline {
				parsed.Output = inlineValue
			} else if index+1 < len(args) {
				index++
				parsed.Output = args[index]
			}
			if parsed.Output == "" {
				return parsed, fmt.Errorf("--output requires a path")
			}
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
		return parsed, fmt.Errorf("client mutation command is missing")
	}
	switch positionals[1] {
	case "add":
		parsed.CommandID = "client.add"
		if len(positionals) < 3 {
			return parsed, fmt.Errorf("client add requires a name")
		}
		parsed.Reference, parsed.Presets = positionals[2], append([]string{}, positionals[3:]...)
	case "rotate", "revoke", "delete":
		parsed.CommandID = "client." + positionals[1]
		if len(positionals) != 3 {
			return parsed, fmt.Errorf("%s requires exactly one name or ID", parsed.CommandID)
		}
		parsed.Reference = positionals[2]
	case "export":
		parsed.CommandID = "client.export"
		if len(positionals) != 4 {
			return parsed, fmt.Errorf("client export requires a name or ID and format")
		}
		parsed.Reference = positionals[2]
		parsed.Format = routing.ClientExportFormat(positionals[3])
		if parsed.Format != routing.ClientExportClash && parsed.Format != routing.ClientExportWireGuard {
			return parsed, fmt.Errorf("client export format must be clash or wireguard")
		}
	default:
		return parsed, fmt.Errorf("unsupported client mutation command")
	}
	if parsed.CommandID != "client.export" && (parsed.Output != "" || parsed.Force) {
		return parsed, fmt.Errorf("--output and --force are available only for client export")
	}
	if parsed.CommandID == "client.export" && parsed.Yes {
		return parsed, fmt.Errorf("client export does not accept --yes")
	}
	return parsed, nil
}

func commandPositionalsWithValues(args []string, valueOptions map[string]bool) []string {
	positionals := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		name, _, inline := strings.Cut(args[index], "=")
		if strings.HasPrefix(name, "-") {
			if valueOptions[name] && !inline && index+1 < len(args) {
				index++
			}
			continue
		}
		positionals = append(positionals, args[index])
	}
	return positionals
}

func classifyClientMutationError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole):
		return output.CategoryValidation, "unsupported_role", "client commands are available only on a gateway"
	case errors.Is(err, ErrMutationFlags), errors.Is(err, ErrInteractionRefused),
		errors.Is(err, routing.ErrClientNotFound), errors.Is(err, routing.ErrClientNotActive),
		errors.Is(err, routing.ErrClientDeleteRequiresRevoke), errors.Is(err, routing.ErrClientUnsupportedTransport),
		errors.Is(err, routing.ErrClientExportUnsafe):
		return output.CategoryValidation, "client_request_invalid", "the client request or current lifecycle state is invalid"
	case errors.Is(err, routing.ErrClientNameConflict), errors.Is(err, routing.ErrClientStalePlan),
		errors.Is(err, routing.ErrClientLifecycleStale), errors.Is(err, routing.ErrClientExportExists),
		errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "client_conflict", "the client name, state generation, or export destination conflicts with current state"
	default:
		return output.CategoryInternal, "client_operation_failed", "vpnctl could not complete the client operation"
	}
}

func emitClientMutationFailure(emitter *ResultEmitter, commandID string, category output.ExitCategory, code, message string) int {
	if _, found := V2CommandRegistry().Lookup(commandID); !found {
		commandID = "client.add"
	}
	result := output.NewResult(commandID, output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func printClientMutationHelp(writer io.Writer) {
	fmt.Fprint(writer, `Manage personal clients on the gateway.

Usage:
  vpnctl client add <name> [preset...] [--dry-run] [--json]
  vpnctl client rotate <name-or-id> [--dry-run] [--yes] [--json]
  vpnctl client revoke <name-or-id> [--dry-run] [--yes] [--json]
  vpnctl client delete <name-or-id> [--dry-run] [--yes] [--json]
  vpnctl client export <name-or-id> <clash|wireguard> [--output <path>] [--force] [--dry-run] [--json]
`)
}

var _ clientMutationAPI = (*systemClientMutationService)(nil)
