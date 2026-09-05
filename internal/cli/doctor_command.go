package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	doctorSystemPaths = store.DefaultPaths
	doctorLoadRole    = loadSystemHostRole
	doctorBuild       = buildSystemDoctor
	doctorRun         = RunDoctorWithOptions
)

func isDoctorInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, map[string]bool{"--probe-url": true})
	return len(positionals) > 0 && positionals[0] == "doctor"
}

type doctorArguments struct {
	Scope    operations.DoctorScope
	ProbeURL operations.DoctorProbeURL
	JSON     bool
	Help     bool
}

func executeDoctor(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseDoctorArguments(args)
	if parsed.Help {
		printDoctorHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "doctor failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitDoctorFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := doctorSystemPaths()
	role, err := doctorLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitDoctorFailure(emitter, output.CategoryValidation, "invalid_host_state", "doctor requires an initialized gateway or joined node")
	}
	doctor, err := doctorBuild(paths, role)
	if err != nil {
		category, code, message := classifyDoctorCommandError(err)
		return emitDoctorFailure(emitter, category, code, message)
	}
	result, err := doctorRun(context.Background(), role, parsed.Scope, operations.DoctorOptions{ProbeURL: parsed.ProbeURL}, doctor)
	if err != nil {
		category, code, message := classifyDoctorCommandError(err)
		return emitDoctorFailure(emitter, category, code, message)
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parseDoctorArguments(args []string) (doctorArguments, error) {
	parsed := doctorArguments{Scope: operations.DoctorScopeDefault}
	positionals := make([]string, 0, len(args))
	seen := make(map[string]bool)
	for index := 0; index < len(args); index++ {
		argument := args[index]
		name, inlineValue, inline := strings.Cut(argument, "=")
		switch name {
		case "--json":
			if inline || seen[name] {
				return parsed, fmt.Errorf("--json may be supplied only once and takes no value")
			}
			seen[name], parsed.JSON = true, true
		case "--probe-url":
			if seen[name] {
				return parsed, fmt.Errorf("--probe-url may be supplied only once")
			}
			seen[name] = true
			value := inlineValue
			if !inline {
				if index+1 >= len(args) {
					return parsed, fmt.Errorf("--probe-url requires an HTTPS URL")
				}
				index++
				value = args[index]
			}
			var err error
			parsed.ProbeURL, err = operations.NewDoctorProbeURL(value)
			if err != nil {
				return parsed, err
			}
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported doctor option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) < 1 || len(positionals) > 2 || positionals[0] != "doctor" {
		return parsed, fmt.Errorf("usage: vpnctl doctor [dns|transport|tunnel|ingress] [--probe-url <https-url>] [--json]")
	}
	if len(positionals) == 2 {
		scope, err := operations.ParseDoctorScope(positionals[1])
		if err != nil {
			return parsed, err
		}
		parsed.Scope = scope
	}
	return parsed, nil
}

func printDoctorHelp(writer io.Writer) {
	fmt.Fprint(writer, `Run bounded active diagnostics without mutation.

Usage:
  vpnctl doctor [dns|transport|tunnel|ingress] [--probe-url <https-url>] [--json]

The optional URL performs one credential-free HTTPS GET without redirects.
Doctor never invokes user webhook paths or switches transports.
`)
}

func classifyDoctorCommandError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, store.ErrStateNotFound):
		return output.CategoryValidation, "doctor_request_invalid", "doctor requires valid initialized role state"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return output.CategoryUnavailable, "doctor_cancelled", "doctor did not complete within its caller deadline"
	default:
		return output.CategoryInternal, "doctor_failed", "vpnctl could not construct or run the bounded diagnostic"
	}
}

func emitDoctorFailure(emitter *ResultEmitter, category output.ExitCategory, code, message string) int {
	status := output.StatusFailed
	if category == output.CategoryUnavailable || category == output.CategoryConflict {
		status = output.StatusDegraded
	}
	result := output.NewResult("doctor", status, category, output.SafeObject{
		"role": "", "scope": string(operations.DoctorScopeDefault), "run_id": "", "overall": "failed", "checks": output.SafeList{},
	})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}
