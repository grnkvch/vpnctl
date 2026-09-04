package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type loggingStateStore interface {
	Load() (model.State, error)
	Save(uint64, model.State) error
}

var (
	loggingSystemPaths = store.DefaultPaths
	loggingLoadRole    = loadSystemHostRole
	loggingNewStore    = func(paths store.Paths) (loggingStateStore, error) { return store.NewStateStore(paths) }
	loggingCallGateway = control.CallLocal
	loggingNow         = time.Now
	loggingNewUUID     = model.NewUUID
)

type loggingArguments struct {
	Action    string
	Scope     model.LogScope
	Level     model.LogLevel
	Duration  time.Duration
	File      bool
	DryRun    bool
	JSON      bool
	ShowHelp  bool
	CommandID string
}

func isLoggingInvocation(args []string) bool {
	for _, argument := range args {
		if argument == "--json" {
			continue
		}
		return argument == "log"
	}
	return false
}

func executeLogging(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseLoggingArguments(args)
	if parsed.ShowHelp {
		printLoggingHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "log failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitLoggingFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := loggingSystemPaths()
	role, err := loggingLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitLoggingFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_host_state", "log requires an initialized gateway or node")
	}
	stateSource, err := loggingNewStore(paths)
	if err != nil {
		return emitLoggingFailure(emitter, parsed.CommandID, output.CategoryInternal, "logging_state_unavailable", "vpnctl could not open authoritative logging state")
	}
	manager, err := operations.NewLoggingManager(stateSource, operations.ValidatingLoggingRuntime{}, operations.LoggingManagerOptions{
		Now: loggingNow, NewUUID: loggingNewUUID,
		FileDirectory: filepath.Join(paths.Root, "var", "log", "vpnctl"),
	})
	if err != nil {
		return emitLoggingFailure(emitter, parsed.CommandID, output.CategoryInternal, "logging_internal_error", "vpnctl could not initialize logging management")
	}
	baseline, err := manager.Status(context.Background())
	if err != nil {
		return emitLoggingFailure(emitter, parsed.CommandID, output.CategoryInternal, "logging_state_unavailable", "vpnctl could not load authoritative logging state")
	}
	if !loggingRoleMatches(role, baseline.Role) {
		return emitLoggingFailure(emitter, parsed.CommandID, output.CategoryConflict, "logging_role_conflict", "logging state does not match the initialized host role")
	}

	var result output.Result
	err = V2CommandRegistry().Dispatch(parsed.CommandID, role, func(CommandSpec) error {
		switch parsed.Action {
		case "status":
			result, err = loggingStatusResult(baseline)
			return err
		case "enable":
			request := operations.LoggingEnableRequest{Scope: parsed.Scope, Level: parsed.Level, Duration: parsed.Duration, File: parsed.File}
			change, err := executeLoggingEnable(context.Background(), paths, role, manager, request, parsed.DryRun)
			if err != nil {
				return err
			}
			result, err = loggingChangeResult("log.enable", parsed.Scope, change, parsed.DryRun)
			return err
		case "disable":
			change, err := executeLoggingDisable(context.Background(), paths, role, manager, parsed.Scope, parsed.DryRun)
			if err != nil {
				return err
			}
			result, err = loggingChangeResult("log.disable", parsed.Scope, change, parsed.DryRun)
			return err
		default:
			return fmt.Errorf("unsupported logging action")
		}
	})
	if err != nil {
		category, code, message := classifyLoggingError(err)
		return emitLoggingFailure(emitter, parsed.CommandID, category, code, message)
	}
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func executeLoggingEnable(ctx context.Context, paths store.Paths, role HostRole, manager *operations.LoggingManager, request operations.LoggingEnableRequest, dryRun bool) (operations.LoggingChange, error) {
	if dryRun {
		return manager.PreviewEnable(ctx, request)
	}
	if role != RoleGateway {
		return manager.Enable(ctx, request)
	}
	if _, err := manager.PreviewEnable(ctx, request); err != nil {
		return operations.LoggingChange{}, err
	}
	payload, err := json.Marshal(struct {
		Scope           model.LogScope `json:"scope"`
		Level           model.LogLevel `json:"level"`
		DurationSeconds int64          `json:"duration_seconds"`
		File            bool           `json:"file"`
	}{Scope: request.Scope, Level: request.Level, DurationSeconds: int64(request.Duration / time.Second), File: request.File})
	if err != nil {
		return operations.LoggingChange{}, err
	}
	return callGatewayLoggingMutation(ctx, paths, "log.enable", payload)
}

func executeLoggingDisable(ctx context.Context, paths store.Paths, role HostRole, manager *operations.LoggingManager, scope model.LogScope, dryRun bool) (operations.LoggingChange, error) {
	if dryRun {
		return manager.PreviewDisable(ctx, scope)
	}
	if role != RoleGateway {
		return manager.Disable(ctx, scope)
	}
	if _, err := manager.PreviewDisable(ctx, scope); err != nil {
		return operations.LoggingChange{}, err
	}
	payload, err := json.Marshal(struct {
		Scope model.LogScope `json:"scope"`
	}{Scope: scope})
	if err != nil {
		return operations.LoggingChange{}, err
	}
	return callGatewayLoggingMutation(ctx, paths, "log.disable", payload)
}

func callGatewayLoggingMutation(ctx context.Context, paths store.Paths, operation string, payload json.RawMessage) (operations.LoggingChange, error) {
	stateSource, err := loggingNewStore(paths)
	if err != nil {
		return operations.LoggingChange{}, err
	}
	state, err := stateSource.Load()
	if err != nil {
		return operations.LoggingChange{}, err
	}
	response, err := loggingCallGateway(ctx, paths.ControlSocket, control.LocalRequest{
		SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate, Operation: operation,
		ExpectedGeneration: state.Generation, Payload: append(json.RawMessage(nil), payload...),
	})
	if err != nil {
		return operations.LoggingChange{}, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	if !response.OK {
		if response.ErrorCode == "generation_conflict" {
			return operations.LoggingChange{}, store.ErrStateConflict
		}
		if response.ErrorCode == "mutation_failed" {
			return operations.LoggingChange{}, operations.ErrLoggingConflict
		}
		return operations.LoggingChange{}, fmt.Errorf("gateway logging mutation failed: %s", response.ErrorCode)
	}
	var change operations.LoggingChange
	if err := decodeClosedLoggingChange(response.Data, &change); err != nil {
		return operations.LoggingChange{}, err
	}
	if change.Role != model.RoleGateway || change.Generation != response.Generation {
		return operations.LoggingChange{}, fmt.Errorf("gateway returned inconsistent logging mutation metadata")
	}
	return change, nil
}

func decodeClosedLoggingChange(raw json.RawMessage, change *operations.LoggingChange) error {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return fmt.Errorf("gateway logging result has invalid size")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(change); err != nil {
		return fmt.Errorf("decode gateway logging result: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("decode gateway logging result: trailing data")
	}
	return nil
}

func parseLoggingArguments(args []string) (loggingArguments, error) {
	parsed := loggingArguments{CommandID: "log.status"}
	positionals := make([]string, 0, len(args))
	var levelText, durationText string
	for index := 0; index < len(args); index++ {
		argument := args[index]
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
		case "--file":
			if parsed.File {
				return parsed, fmt.Errorf("--file may be supplied only once")
			}
			parsed.File = true
		case "--level", "--for":
			if index+1 >= len(args) {
				return parsed, fmt.Errorf("%s requires a value", argument)
			}
			index++
			if argument == "--level" {
				if levelText != "" {
					return parsed, fmt.Errorf("--level may be supplied only once")
				}
				levelText = args[index]
			} else {
				if durationText != "" {
					return parsed, fmt.Errorf("--for may be supplied only once")
				}
				durationText = args[index]
			}
		case "-h", "--help", "help":
			parsed.ShowHelp = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported log option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.ShowHelp {
		return parsed, nil
	}
	if len(positionals) < 2 || positionals[0] != "log" {
		return parsed, fmt.Errorf("log requires status, enable, or disable")
	}
	parsed.Action = positionals[1]
	parsed.CommandID = "log." + parsed.Action
	switch parsed.Action {
	case "status":
		if len(positionals) != 2 || parsed.DryRun || parsed.File || levelText != "" || durationText != "" {
			return parsed, fmt.Errorf("log status accepts only --json")
		}
	case "enable":
		if len(positionals) != 3 {
			return parsed, fmt.Errorf("log enable requires exactly one scope")
		}
		parsed.Scope = model.LogScope(positionals[2])
		if !validCLILoggingScope(parsed.Scope) {
			return parsed, fmt.Errorf("unsupported logging scope %s", parsed.Scope)
		}
		parsed.Level = model.LogLevel(levelText)
		if !validCLILoggingLevel(parsed.Level) {
			return parsed, fmt.Errorf("log enable requires --level error|info|debug|trace")
		}
		if durationText == "" {
			return parsed, fmt.Errorf("log enable requires --for")
		}
		duration, err := time.ParseDuration(durationText)
		if err != nil || duration <= 0 || duration > operations.MaximumLoggingDuration || duration%time.Second != 0 {
			return parsed, fmt.Errorf("--for must be a whole-second duration no greater than 1h")
		}
		parsed.Duration = duration
	case "disable":
		if len(positionals) != 3 || parsed.File || levelText != "" || durationText != "" {
			return parsed, fmt.Errorf("log disable requires exactly one scope and accepts only --dry-run and --json")
		}
		parsed.Scope = model.LogScope(positionals[2])
		if !validCLILoggingScope(parsed.Scope) {
			return parsed, fmt.Errorf("unsupported logging scope %s", parsed.Scope)
		}
	default:
		return parsed, fmt.Errorf("unsupported log action %s", parsed.Action)
	}
	return parsed, nil
}

func loggingStatusResult(report operations.LoggingStatusReport) (output.Result, error) {
	items := make([]output.SafeObject, len(report.Active))
	rows := make([][]string, len(report.Active))
	for index, session := range report.Active {
		items[index] = loggingOptInOutput(session, true)
		rows[index] = []string{
			string(session.Scope), string(session.Level), string(session.Destination),
			strconv.FormatInt(session.RemainingSeconds, 10), session.ExpiresAt.UTC().Format(time.RFC3339),
		}
	}
	result := output.NewResult("log.status", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"role": string(report.Role), "overall": "healthy", "generation": report.Generation, "log_opt_ins": items,
	})
	if err := result.AddHumanTable("log_opt_ins", []string{"scope", "level", "destination", "remaining_seconds", "expires_at"}, rows); err != nil {
		return output.Result{}, err
	}
	return result, result.Validate()
}

func loggingChangeResult(command string, scope model.LogScope, change operations.LoggingChange, dryRun bool) (output.Result, error) {
	data := output.SafeObject{
		"changed": change.Changed, "generation": change.Generation, "scope": string(scope),
		"dry_run": dryRun, "disabled_ids": append([]string{}, change.DisabledIDs...), "expired_ids": append([]string{}, change.ExpiredIDs...),
	}
	result := output.NewResult(command, output.StatusOK, output.CategorySuccess, data)
	if change.Enabled != nil {
		data["enabled"] = loggingOptInOutput(*change.Enabled, true)
		result.ResourceIDs["logging_id"] = change.Enabled.ID
	}
	if change.Enabled != nil && !dryRun {
		result.Warnings = append(result.Warnings, output.Message{
			Code: "expanded_logging_active", Message: "Temporary expanded logging is enabled until its fixed expiration.",
			ResourceIDs: map[string]string{"logging_id": change.Enabled.ID},
		})
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "disable_logging_early", Message: "Disable this logging scope when diagnostics are complete.",
			Command: "sudo vpnctl log disable " + string(change.Enabled.Scope), ResourceIDs: map[string]string{"logging_id": change.Enabled.ID},
		})
	}
	return result, result.Validate()
}

func loggingOptInOutput(session operations.LoggingOptIn, remaining bool) output.SafeObject {
	item := output.SafeObject{
		"id": session.ID, "scope": string(session.Scope), "level": string(session.Level), "destination": string(session.Destination),
		"started_at": session.StartedAt.UTC().Format(time.RFC3339), "expires_at": session.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if remaining {
		item["remaining_seconds"] = session.RemainingSeconds
	}
	return item
}

func loggingRoleMatches(role HostRole, stateRole model.Role) bool {
	return role == RoleGateway && stateRole == model.RoleGateway || role == RoleNode && stateRole == model.RoleNode
}

func validCLILoggingScope(scope model.LogScope) bool {
	switch scope {
	case model.LogControl, model.LogTransport, model.LogRouting, model.LogDNS, model.LogTunnel, model.LogIngress, model.LogAll:
		return true
	default:
		return false
	}
}

func validCLILoggingLevel(level model.LogLevel) bool {
	switch level {
	case model.LogError, model.LogInfo, model.LogDebug, model.LogTrace:
		return true
	default:
		return false
	}
}

func classifyLoggingError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, operations.ErrLoggingConflict), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "logging_conflict", "the logging state changed or the requested scope overlaps an active opt-in"
	case errors.Is(err, operations.ErrLoggingInvalid), errors.Is(err, ErrUnsupportedRole):
		return output.CategoryValidation, "logging_validation", err.Error()
	case errors.Is(err, ErrGatewayUnavailable):
		return output.CategoryUnavailable, "gateway_unavailable", "the authoritative gateway controller is unavailable"
	default:
		return output.CategoryInternal, "logging_internal_error", "vpnctl could not apply the logging change"
	}
}

func emitLoggingFailure(emitter *ResultEmitter, commandID string, category output.ExitCategory, warningCode, warningMessage string) int {
	if commandID != "log.status" && commandID != "log.enable" && commandID != "log.disable" {
		commandID = "log.status"
	}
	result := output.NewResult(commandID, output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printLoggingHelp(writer io.Writer) {
	fmt.Fprint(writer, `Temporarily enable expanded local operational logging.

Usage:
  vpnctl log status [--json]
  vpnctl log enable <scope> --level <level> --for <duration> [--file] [--dry-run] [--json]
  vpnctl log disable <scope|all> [--dry-run] [--json]

Scopes: control, transport, routing, dns, tunnel, ingress, all.
Levels: error, info, debug, trace. Duration is required and cannot exceed 1h.
`)
}
