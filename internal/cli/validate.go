package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type validationStateStore interface {
	Load() (model.State, error)
}

var (
	validateSystemPaths = store.DefaultPaths
	validateLoadRole    = loadSystemHostRole
	validateNewStore    = func(paths store.Paths) (validationStateStore, error) { return store.NewStateStore(paths) }
)

func isValidateInvocation(args []string) bool {
	for _, argument := range args {
		if argument == "--json" {
			continue
		}
		return argument == "validate"
	}
	return false
}

func executeValidate(args []string, stdout, stderr io.Writer) int {
	jsonMode, help, err := parseValidateArguments(args)
	if help {
		fmt.Fprint(stdout, "Validate the authoritative v2 state.\n\nUsage:\n  vpnctl validate [--json]\n")
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, jsonMode)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "validate failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitValidationFailure(emitter, "invalid_arguments", err.Error())
	}

	paths := validateSystemPaths()
	role, err := validateLoadRole(paths)
	if err != nil {
		return emitInvalidState(emitter, "state_invalid", "authoritative state cannot be decoded or validated")
	}
	if role == RoleUninitialized {
		return emitInvalidState(emitter, "state_not_found", "vpnctl is not initialized on this host")
	}
	stateStore, err := validateNewStore(paths)
	if err != nil {
		return emitValidationFailure(emitter, "state_unavailable", "authoritative state cannot be opened")
	}

	var result output.Result
	err = V2CommandRegistry().Dispatch("validate", role, func(CommandSpec) error {
		state, loadErr := stateStore.Load()
		if loadErr != nil {
			return loadErr
		}
		if validateErr := state.Validate(); validateErr != nil {
			return validateErr
		}
		result = output.NewResult("validate", output.StatusOK, output.CategorySuccess, output.SafeObject{
			"valid": true, "issues": []output.SafeObject{},
		})
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrUnsupportedRole) {
			return emitValidationFailure(emitter, "unsupported_role", "validate requires an initialized gateway or node")
		}
		return emitInvalidState(emitter, "state_invalid", "authoritative state cannot be decoded or validated")
	}
	code, err := emitter.Emit(result)
	if err != nil {
		fmt.Fprintf(stderr, "validate failed: %v\n", err)
		return ExitInternal
	}
	return code
}

func parseValidateArguments(args []string) (jsonMode, help bool, err error) {
	seenCommand := false
	for _, argument := range args {
		switch argument {
		case "validate":
			if seenCommand {
				return jsonMode, false, fmt.Errorf("validate may be supplied only once")
			}
			seenCommand = true
		case "--json":
			if jsonMode {
				return jsonMode, false, fmt.Errorf("--json may be supplied only once")
			}
			jsonMode = true
		case "-h", "--help":
			help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return jsonMode, false, fmt.Errorf("unsupported validate option %s", argument)
			}
			return jsonMode, false, fmt.Errorf("unexpected validate argument %s", argument)
		}
	}
	if help {
		return jsonMode, true, nil
	}
	if !seenCommand {
		return jsonMode, false, fmt.Errorf("validate command is missing")
	}
	return jsonMode, false, nil
}

func emitInvalidState(emitter *ResultEmitter, code, message string) int {
	result := output.NewResult("validate", output.StatusFailed, output.CategoryValidation, output.SafeObject{
		"valid":  false,
		"issues": []output.SafeObject{{"code": code, "kind": "authoritative_state"}},
	})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func emitValidationFailure(emitter *ResultEmitter, code, message string) int {
	result := output.NewResult("validate", output.StatusFailed, output.CategoryValidation, output.SafeObject{
		"valid":  false,
		"issues": []output.SafeObject{{"code": code, "kind": "command"}},
	})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}
