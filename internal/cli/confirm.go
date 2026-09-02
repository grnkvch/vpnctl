package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	confirmSystemPaths = store.DefaultPaths
	confirmLookupEnv   = os.LookupEnv
	loadConfirmRole    = loadSystemHostRole
	runWatchdogConfirm = func(ctx context.Context, paths store.Paths, transactionID, rawSSHConnection string) (operations.WatchdogConfirmation, error) {
		watchdog, err := operations.NewSystemWatchdog(paths)
		if err != nil {
			return operations.WatchdogConfirmation{}, err
		}
		return watchdog.Confirm(ctx, transactionID, rawSSHConnection)
	}
)

func executeConfirm(args []string, stdout, stderr io.Writer) int {
	transactionID, jsonMode, help, err := parseConfirmArguments(args)
	if help {
		printConfirmHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, jsonMode)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "confirm failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitConfirmResult(emitter, transactionID, false, output.CategoryValidation, "invalid_arguments", err.Error())
	}

	paths := confirmSystemPaths()
	role, err := loadConfirmRole(paths)
	if err != nil {
		return emitConfirmResult(emitter, transactionID, false, output.CategoryValidation, "invalid_host_state", "vpnctl host state is missing or invalid")
	}
	var confirmation operations.WatchdogConfirmation
	err = V2CommandRegistry().Dispatch("confirm", role, func(CommandSpec) error {
		rawSSHConnection, _ := confirmLookupEnv("SSH_CONNECTION")
		var runErr error
		confirmation, runErr = runWatchdogConfirm(context.Background(), paths, transactionID, rawSSHConnection)
		return runErr
	})
	if err == nil {
		return emitConfirmResult(emitter, confirmation.TransactionID, true, output.CategorySuccess, "", "")
	}
	if confirmation.TransactionID != "" {
		return emitConfirmResult(emitter, confirmation.TransactionID, true, output.CategoryUnavailable, "watchdog_timer_stop_failed", "network state was committed, but the watchdog timer could not be stopped")
	}
	category, code, message := classifyConfirmError(err)
	return emitConfirmResult(emitter, transactionID, false, category, code, message)
}

func parseConfirmArguments(args []string) (transactionID string, jsonMode, help bool, err error) {
	positionals := make([]string, 0, 1)
	for _, argument := range args {
		switch argument {
		case "--json":
			if jsonMode {
				return "", false, false, fmt.Errorf("--json may be supplied only once")
			}
			jsonMode = true
		case "-h", "--help":
			help = true
		default:
			if len(argument) > 0 && argument[0] == '-' {
				return "", jsonMode, false, fmt.Errorf("unknown confirm flag: %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if help {
		return "", jsonMode, true, nil
	}
	if len(positionals) != 1 {
		return "", jsonMode, false, fmt.Errorf("confirm requires exactly one transaction ID")
	}
	if !operations.ValidWatchdogID(positionals[0]) {
		return "", jsonMode, false, fmt.Errorf("transaction ID must have form fw-XXXXXX")
	}
	return positionals[0], jsonMode, false, nil
}

func loadSystemHostRole(paths store.Paths) (HostRole, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return RoleUninitialized, err
	}
	state, err := stateStore.Load()
	if errors.Is(err, store.ErrStateNotFound) {
		return RoleUninitialized, nil
	}
	if err != nil {
		return RoleUninitialized, err
	}
	switch state.Host.Role {
	case model.RoleGateway:
		return RoleGateway, nil
	case model.RoleNode:
		return RoleNode, nil
	default:
		return RoleUninitialized, fmt.Errorf("unsupported host role %q", state.Host.Role)
	}
}

func classifyConfirmError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole):
		return output.CategoryValidation, "unsupported_role", "confirm is available only on an initialized gateway"
	case errors.Is(err, operations.ErrWatchdogOriginalSession):
		return output.CategoryValidation, "new_ssh_session_required", "run confirm from a new SSH session established after network activation"
	case errors.Is(err, operations.ErrWatchdogWrongSSHPort):
		return output.CategoryValidation, "ssh_port_mismatch", "the confirming SSH session does not use the allowed listener port"
	case errors.Is(err, operations.ErrWatchdogConfirmationProof):
		return output.CategoryValidation, "ssh_session_unverified", "the current process is not running in a verifiable SSH session"
	case errors.Is(err, operations.ErrWatchdogTransactionNotFound):
		return output.CategoryValidation, "transaction_not_found", "the watchdog transaction does not exist"
	case errors.Is(err, operations.ErrWatchdogNotActivated):
		return output.CategoryConflict, "transaction_not_active", "the watchdog transaction has not reached the activation boundary"
	case errors.Is(err, operations.ErrWatchdogAlreadyCommitted):
		return output.CategoryConflict, "transaction_id_used", "the one-time watchdog transaction ID was already committed"
	case errors.Is(err, operations.ErrWatchdogExpired), errors.Is(err, operations.ErrWatchdogAlreadyRolledBack):
		return output.CategoryConflict, "transaction_expired", "the watchdog transaction expired or was rolled back"
	default:
		return output.CategoryInternal, "confirm_internal_error", "vpnctl could not complete watchdog confirmation"
	}
}

func emitConfirmResult(emitter *ResultEmitter, transactionID string, changed bool, category output.ExitCategory, warningCode, warningMessage string) int {
	status := output.StatusFailed
	if category == output.CategorySuccess {
		status = output.StatusOK
	} else if category == output.CategoryUnavailable && changed {
		status = output.StatusDegraded
	}
	result := output.NewResult("confirm", status, category, output.SafeObject{"changed": changed})
	if operations.ValidWatchdogID(transactionID) {
		result.ResourceIDs["transaction_id"] = transactionID
	}
	if warningCode != "" {
		result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: warningMessage})
	}
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printConfirmHelp(writer io.Writer) {
	fmt.Fprint(writer, `Confirm a lockout-risk network transaction from a newly established SSH session.

Usage:
  vpnctl confirm <transaction-id> [--json]
`)
}
