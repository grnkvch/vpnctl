package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

var (
	transportSystemPaths    = store.DefaultPaths
	transportLoadRole       = loadSystemHostRole
	transportBuildTester    = buildSystemTransportTester
	transportBuildSwitcher  = buildSystemTransportSwitcher
	transportBuildAuthority = buildSystemTransportDeferredWriter
	transportOpenTTY        = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

type transportTester interface {
	Test(context.Context, model.TransportKind) (transport.TestExecution, error)
}

func isTransportTestInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, nil)
	return len(positionals) >= 2 && positionals[0] == "transport" && positionals[1] == "test"
}

func isTransportSwitchInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, nil)
	return len(positionals) >= 2 && positionals[0] == "transport" && positionals[1] == "switch"
}

type transportTestArguments struct {
	Target model.TransportKind
	JSON   bool
	Help   bool
}

func executeTransportTest(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseTransportTestArguments(args)
	if parsed.Help {
		printTransportTestHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "transport test failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitTransportTestFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := transportSystemPaths()
	role, err := transportLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitTransportTestFailure(emitter, output.CategoryValidation, "invalid_host_state", "transport test requires a joined private node")
	}
	if role != RoleNode {
		return emitTransportTestFailure(emitter, output.CategoryValidation, "unsupported_role", "transport test is available only on a private node")
	}
	tester, err := transportBuildTester(paths)
	if err != nil {
		category, code, message := classifyTransportTestError(err)
		return emitTransportTestFailure(emitter, category, code, message)
	}
	var execution transport.TestExecution
	err = V2CommandRegistry().Dispatch("transport.test", role, func(CommandSpec) error {
		var runErr error
		execution, runErr = tester.Test(context.Background(), parsed.Target)
		return runErr
	})
	if err != nil {
		category, code, message := classifyTransportTestError(err)
		return emitTransportTestFailure(emitter, category, code, message)
	}
	result, err := transportTestOutput(execution)
	if err != nil {
		return emitTransportTestFailure(emitter, output.CategoryInternal, "transport_test_invalid", "the transport provider returned invalid diagnostic evidence")
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parseTransportTestArguments(args []string) (transportTestArguments, error) {
	parsed := transportTestArguments{}
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
				return parsed, fmt.Errorf("unsupported transport test option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) != 3 || positionals[0] != "transport" || positionals[1] != "test" {
		return parsed, fmt.Errorf("usage: vpnctl transport test <standard|restricted> [--json]")
	}
	parsed.Target = model.TransportKind(positionals[2])
	if !validTransportCommandTarget(parsed.Target) {
		return parsed, fmt.Errorf("transport must be standard or restricted")
	}
	return parsed, nil
}

type transportSwitchArguments struct {
	Target model.TransportKind
	DryRun bool
	Defer  bool
	Yes    bool
	JSON   bool
	Help   bool
}

func executeTransportSwitch(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseTransportSwitchArguments(args)
	if parsed.Help {
		printTransportSwitchHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "transport switch failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitTransportSwitchFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error(), false)
	}
	paths := transportSystemPaths()
	role, err := transportLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitTransportSwitchFailure(emitter, output.CategoryValidation, "invalid_host_state", "transport switch requires a joined private node", false)
	}
	request := MutationRequest{
		CommandID: "transport.switch", Role: role, DryRun: parsed.DryRun, Defer: parsed.Defer, Yes: parsed.Yes, JSON: parsed.JSON,
	}
	if _, _, err := V2CommandRegistry().ResolveMutationMode(request); err != nil {
		category, code, message := classifyTransportSwitchError(err)
		return emitTransportSwitchFailure(emitter, category, code, message, false)
	}
	switcher, err := transportBuildSwitcher(paths)
	if err != nil {
		category, code, message := classifyTransportSwitchError(err)
		return emitTransportSwitchFailure(emitter, category, code, message, false)
	}
	workflow, err := NewTransportSwitchWorkflow(switcher, parsed.Target)
	if err != nil {
		return emitTransportSwitchFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error(), false)
	}
	var authority AuthoritativeDeferredWriter
	if parsed.Defer {
		authority, err = transportBuildAuthority(paths)
		if err != nil {
			category, code, message := classifyTransportSwitchError(err)
			return emitTransportSwitchFailure(emitter, category, code, message, false)
		}
	}
	var terminal PromptIO
	var closer io.Closer
	if !parsed.Yes && !parsed.DryRun {
		terminal, closer, err = transportOpenTTY()
		if err != nil {
			return emitTransportSwitchFailure(emitter, output.CategoryValidation, "controlling_tty_required", "transport switch requires a controlling TTY or --yes", false)
		}
		defer closer.Close()
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), request, terminal, workflow, authority)
	if err != nil {
		category, code, message := classifyTransportSwitchError(err)
		changed := errors.Is(err, transport.ErrTransportSwitchCommitUncertain) ||
			errors.Is(err, ErrSystemTransportDesiredPublicationPending)
		return emitTransportSwitchFailure(emitter, category, code, message, changed)
	}
	exit, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parseTransportSwitchArguments(args []string) (transportSwitchArguments, error) {
	parsed := transportSwitchArguments{}
	positionals := make([]string, 0, len(args))
	seen := make(map[string]bool)
	for _, argument := range args {
		switch argument {
		case "--json", "--dry-run", "--defer", "--yes":
			if seen[argument] {
				return parsed, fmt.Errorf("%s may be supplied only once", argument)
			}
			seen[argument] = true
			switch argument {
			case "--json":
				parsed.JSON = true
			case "--dry-run":
				parsed.DryRun = true
			case "--defer":
				parsed.Defer = true
			case "--yes":
				parsed.Yes = true
			}
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported transport switch option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) != 3 || positionals[0] != "transport" || positionals[1] != "switch" {
		return parsed, fmt.Errorf("usage: vpnctl transport switch <standard|restricted> [--dry-run|--defer] [--yes] [--json]")
	}
	parsed.Target = model.TransportKind(positionals[2])
	if !validTransportCommandTarget(parsed.Target) {
		return parsed, fmt.Errorf("transport must be standard or restricted")
	}
	if parsed.DryRun && parsed.Defer {
		return parsed, fmt.Errorf("--dry-run and --defer are mutually exclusive")
	}
	return parsed, nil
}

func transportTestOutput(execution transport.TestExecution) (output.Result, error) {
	if err := execution.Target.Validate(); err != nil || execution.StateGeneration == 0 || execution.CredentialGeneration == 0 ||
		execution.Target.OwnerKind != model.TargetNode || model.ValidateResourceID(execution.Target.OwnerID) != nil ||
		execution.Target.CredentialGeneration != execution.CredentialGeneration || execution.Selection.Validate() != nil ||
		(execution.Target.Kind != execution.Selection.Active && execution.Target.Kind != execution.Selection.Standby) ||
		!execution.Cleaned || execution.Checks.Validate() != nil {
		return output.Result{}, fmt.Errorf("transport test evidence is invalid")
	}
	items := []struct {
		name  string
		probe transport.ProbeResult
	}{
		{"control", execution.Checks.Control}, {"reverse_tunnel", execution.Checks.ReverseTunnel},
		{"selected_tcp", execution.Checks.SelectedTCP}, {"selected_udp", execution.Checks.SelectedUDP},
	}
	checks := make(output.SafeList, 0, len(items))
	status, category := output.StatusOK, output.CategorySuccess
	for _, item := range items {
		checks = append(checks, output.SafeObject{"name": item.name, "status": string(item.probe.State), "code": publicTransportProbeCode(item.probe)})
		if item.probe.State == transport.ProbeFailed {
			status, category = output.StatusDegraded, output.CategoryUnavailable
		}
	}
	result := output.NewResult("transport.test", status, category, output.SafeObject{"scope": "transport", "checks": checks})
	result.ResourceIDs["node_id"] = execution.Target.OwnerID
	result.ResourceIDs["transport"] = string(execution.Target.Kind)
	if status == output.StatusDegraded {
		result.Warnings = append(result.Warnings, output.Message{
			Code: "transport_test_failed", Message: "The explicitly tested transport did not pass every mandatory probe.",
			ResourceIDs: map[string]string{"node_id": execution.Target.OwnerID, "transport": string(execution.Target.Kind)},
		})
	}
	return result, nil
}

func publicTransportProbeCode(probe transport.ProbeResult) string {
	value := strings.ReplaceAll(probe.Code, "-", "_")
	valid := len(value) > 0 && len(value) <= 128
	for index, character := range value {
		if index == 0 {
			valid = valid && character >= 'a' && character <= 'z'
			continue
		}
		valid = valid && (character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_')
	}
	if valid {
		return value
	}
	if probe.State == transport.ProbePassed {
		return "probe_passed"
	}
	return "probe_failed"
}

func classifyTransportTestError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, store.ErrStateNotFound):
		return output.CategoryValidation, "transport_test_invalid", "transport test requires valid joined private-node state"
	case errors.Is(err, transport.ErrTransportTestStateChanged), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "transport_test_state_changed", "authoritative node state changed while the transport was being tested"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrSystemTransportRuntimeUnavailable):
		return output.CategoryUnavailable, "transport_test_unavailable", "the bounded transport test runtime is unavailable"
	default:
		return output.CategoryUnavailable, "transport_test_failed", "vpnctl could not complete and clean up the isolated transport test"
	}
}

func classifyTransportSwitchError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags), errors.Is(err, ErrInvalidMutationPlan),
		errors.Is(err, ErrInteractionRefused), errors.Is(err, ErrPromptInput), errors.Is(err, ErrConsentDeclined), errors.Is(err, store.ErrStateNotFound):
		return output.CategoryValidation, "transport_switch_invalid", "transport switch requires a valid joined node, explicit target, and required consent"
	case errors.Is(err, transport.ErrTransportSwitchStale), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "transport_switch_stale", "authoritative node state changed after the switch preview"
	case errors.Is(err, transport.ErrTransportSwitchCommitUncertain):
		return output.CategoryUnavailable, "transport_switch_uncertain", "the target may be active after an uncertain state commit; inspect status before retrying"
	case errors.Is(err, ErrSystemTransportDesiredPublicationPending):
		return output.CategoryUnavailable, "transport_switch_desired_pending", "the switch intent is registered, but local desired material is not published yet; retry the same deferred command"
	case errors.Is(err, transport.ErrTransportSwitchTargetNotReady):
		return output.CategoryUnavailable, "transport_target_not_ready", "the explicitly selected target failed a mandatory readiness check; the previous transport remains selected"
	case errors.Is(err, ErrGatewayUnavailable), errors.Is(err, operations.ErrTransportSwitchGatewayUnavailable):
		return output.CategoryUnavailable, "gateway_unavailable", "deferred transport switch requires the authoritative gateway"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, ErrSystemTransportRuntimeUnavailable):
		return output.CategoryUnavailable, "transport_switch_unavailable", "the bounded transport switch runtime is unavailable"
	default:
		return output.CategoryUnavailable, "transport_switch_failed", "vpnctl could not complete the switch; inspect the current transport before retrying"
	}
}

func emitTransportTestFailure(emitter *ResultEmitter, category output.ExitCategory, code, message string) int {
	status := output.StatusFailed
	if category == output.CategoryUnavailable || category == output.CategoryConflict {
		status = output.StatusDegraded
	}
	result := output.NewResult("transport.test", status, category, output.SafeObject{"scope": "transport", "checks": output.SafeList{}})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: singleLineGatewayInitMessage(message)})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func emitTransportSwitchFailure(emitter *ResultEmitter, category output.ExitCategory, code, message string, changed bool) int {
	status := output.StatusFailed
	if category == output.CategoryUnavailable || category == output.CategoryConflict {
		status = output.StatusDegraded
	}
	result := output.NewResult("transport.switch", status, category, output.SafeObject{"changed": changed, "generation": uint64(0)})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: singleLineGatewayInitMessage(message)})
	if code == "transport_switch_uncertain" {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "inspect_transport_switch", Message: "Inspect node status and active transport before deciding whether to retry.", Command: "vpnctl status --all",
		})
	}
	if code == "transport_switch_desired_pending" {
		result.RequiresAction = append(result.RequiresAction, output.Action{
			Code: "retry_transport_switch_defer", Message: "Retry the same transport switch with --defer after correcting the reported local issue.",
		})
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func validTransportCommandTarget(target model.TransportKind) bool {
	return target == model.TransportStandard || target == model.TransportRestricted
}

func printTransportTestHelp(writer io.Writer) {
	fmt.Fprint(writer, `Temporarily establish and test exactly one explicit node transport.

Usage:
  vpnctl transport test <standard|restricted> [--json]

The test never changes active transport, pending intent, or state generation.
Its transient candidate is removed on both success and failure.
`)
}

func printTransportSwitchHelp(writer io.Writer) {
	fmt.Fprint(writer, `Manually switch every selected node path to one explicit transport.

Usage:
  vpnctl transport switch <standard|restricted> [--dry-run] [--yes] [--json]
  vpnctl transport switch <standard|restricted> --defer [--yes] [--json]

The target must pass control, tunnel, selected TCP, and selected UDP checks.
There is no automatic fallback or fail-direct behavior.
`)
}

var _ transportTester = (*transport.NodeTester)(nil)
