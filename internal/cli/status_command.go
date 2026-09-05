package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	statusSystemPaths = store.DefaultPaths
	statusLoadRole    = loadSystemHostRole
	statusBuild       = buildSystemStatusCollector
	statusRun         = RunStatus
)

func isStatusInvocation(args []string) bool {
	positionals := commandPositionalsWithValues(args, nil)
	return len(positionals) > 0 && positionals[0] == "status"
}

type statusArguments struct {
	All  bool
	JSON bool
	Help bool
}

func executeStatus(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseStatusArguments(args)
	if parsed.Help {
		printStatusHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "status failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitStatusCommandFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}

	paths := statusSystemPaths()
	role, err := statusLoadRole(paths)
	if err != nil {
		return emitStatusCommandFailure(emitter, output.CategoryValidation, "state_invalid", "authoritative state cannot be decoded or validated")
	}
	if role == RoleUninitialized {
		return emitStatusCommandFailure(emitter, output.CategoryValidation, "state_not_found", "vpnctl is not initialized on this host")
	}
	collector, err := statusBuild(paths, role, version)
	if err != nil {
		return emitStatusCommandFailure(emitter, output.CategoryInternal, "status_unavailable", "vpnctl could not construct the passive status collector")
	}
	result, err := statusRun(context.Background(), role, parsed.All, collector)
	if err != nil {
		category, code, message := classifyStatusCommandError(err)
		return emitStatusCommandFailure(emitter, category, code, message)
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parseStatusArguments(args []string) (statusArguments, error) {
	parsed := statusArguments{}
	positionals := make([]string, 0, len(args))
	seen := make(map[string]bool)
	for _, argument := range args {
		switch argument {
		case "--all", "--json":
			if seen[argument] {
				return parsed, fmt.Errorf("%s may be supplied only once", argument)
			}
			seen[argument] = true
			if argument == "--all" {
				parsed.All = true
			} else {
				parsed.JSON = true
			}
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported status option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) != 1 || positionals[0] != "status" {
		return parsed, fmt.Errorf("usage: vpnctl status [--all] [--json]")
	}
	return parsed, nil
}

func printStatusHelp(writer io.Writer) {
	fmt.Fprint(writer, `Show passive role status without generating network traffic.

Usage:
  vpnctl status [--all] [--json]

Flags:
  --all     Expand all human-readable resource tables
  --json    Emit the complete machine-readable result
`)
}

type statusStateReader struct {
	state interface{ Load() (model.State, error) }
}

func (reader statusStateReader) ReadStatusState(ctx context.Context) (model.State, error) {
	if err := ctx.Err(); err != nil {
		return model.State{}, err
	}
	return reader.state.Load()
}

type unitStatusObserver interface {
	Observe(context.Context, model.State) (controller.Observation, error)
}

type systemPassiveStatusObserver struct {
	units unitStatusObserver
}

func (observer systemPassiveStatusObserver) ReadPassiveStatus(ctx context.Context, state model.State) (operations.PassiveStatusSnapshot, error) {
	observation, err := observer.units.Observe(ctx, state)
	if err != nil {
		return operations.PassiveStatusSnapshot{}, err
	}
	return passiveStatusFromUnits(state, observation), nil
}

func buildSystemStatusCollector(paths store.Paths, role HostRole, binaryVersion string) (*operations.StatusCollector, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	modelRole, ok := convergenceApplyModelRole(role)
	if !ok {
		return nil, fmt.Errorf("status requires an initialized host role")
	}
	planner, err := buildSystemConvergencePlanner(paths)
	if err != nil {
		return nil, err
	}
	unitObserver, err := controller.NewSystemUnitObserver(linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, err
	}
	return operations.NewStatusCollector(
		modelRole, binaryVersion, time.Now, statusStateReader{state: stateStore}, planner,
		systemPassiveStatusObserver{units: unitObserver},
	)
}

func passiveStatusFromUnits(state model.State, observation controller.Observation) operations.PassiveStatusSnapshot {
	units := make(map[string]controller.UnitObservation, len(observation.Units))
	for _, unit := range observation.Units {
		units[unit.Name] = unit
	}
	resources := make([]operations.PassiveStatusResource, 0, len(observation.Units)+len(state.Transports)+2)

	resources = append(resources, passiveControlStatus(state, units))
	if state.Host.Role == model.RoleNode && nodeStatusHasGateway(state) {
		resources = append(resources, passiveGatewayStatus(state, units))
	}
	for _, name := range linuxplatform.RoleUnitNames(state.Host.Role) {
		if name == "vpnctl-controller.service" {
			continue
		}
		resources = append(resources, passiveUnitStatus(state, operations.PassiveStatusDataPlane, statusUnitComponent(name), name, units[name]))
	}
	for _, transportState := range state.Transports {
		if transportState.State != model.TransportActive && transportState.State != model.TransportDegraded {
			continue
		}
		name := statusTransportUnit(state.Host.Role, transportState.Kind)
		resource := passiveUnitStatus(state, operations.PassiveStatusActiveTransport, "transport", statusTransportResourceID(transportState), units[name])
		if transportState.State == model.TransportDegraded {
			resource.Condition = operations.PassiveDegraded
			resource.Code = "transport_degraded"
		}
		resources = append(resources, resource)
	}
	return operations.PassiveStatusSnapshot{Resources: resources}
}

func passiveControlStatus(state model.State, units map[string]controller.UnitObservation) operations.PassiveStatusResource {
	if state.Host.Role == model.RoleGateway {
		return passiveUnitStatus(state, operations.PassiveStatusConnectivity, "control", "control", units["vpnctl-controller.service"])
	}
	return operations.PassiveStatusResource{
		Class:     operations.PassiveStatusConnectivity,
		Resource:  operations.ManagedResourceKey{Component: "control", Kind: operations.ManagedResourceState, ID: "control"},
		Condition: operations.PassiveUnavailable, Mandatory: true, Active: true,
		Version: state.Components.VPNCTLVersion, Generation: state.Generation, Code: "control_status_not_observed",
	}
}

func passiveGatewayStatus(state model.State, units map[string]controller.UnitObservation) operations.PassiveStatusResource {
	name := ""
	for _, transportState := range state.Transports {
		if transportState.State == model.TransportActive || transportState.State == model.TransportDegraded {
			name = statusTransportUnit(state.Host.Role, transportState.Kind)
			break
		}
	}
	resource := passiveUnitStatus(state, operations.PassiveStatusConnectivity, "control", "gateway", units[name])
	if name == "" {
		resource.Condition = operations.PassiveUnavailable
		resource.Code = "gateway_transport_unknown"
		resource.RuntimeSHA256 = ""
	}
	return resource
}

func passiveUnitStatus(state model.State, class operations.PassiveStatusClass, component, id string, unit controller.UnitObservation) operations.PassiveStatusResource {
	condition, code := operations.PassiveUnavailable, "unit_status_unavailable"
	if unit.LoadState != "" || unit.ActiveState != "" || unit.SubState != "" {
		condition, code = operations.PassiveDegraded, "unit_not_active"
		if unit.LoadState == "loaded" && unit.ActiveState == "active" {
			condition, code = operations.PassiveHealthy, "unit_active"
		}
	}
	resource := operations.PassiveStatusResource{
		Class: class, Resource: operations.ManagedResourceKey{Component: component, Kind: operations.ManagedResourceUnit, ID: id},
		Condition: condition, Mandatory: true, Active: true, Generation: state.Generation, Code: code,
	}
	if unit.Name != "" || unit.LoadState != "" || unit.ActiveState != "" || unit.SubState != "" {
		resource.RuntimeSHA256 = operations.ManagedFingerprint([]byte(unit.Name + "\x00" + unit.LoadState + "\x00" + unit.ActiveState + "\x00" + unit.SubState))
	}
	return resource
}

func statusUnitComponent(name string) string {
	switch {
	case strings.Contains(name, "routing"):
		return "routing"
	case strings.Contains(name, "tunnel"):
		return "tunnel"
	case strings.Contains(name, "dns"):
		return "dns"
	case strings.Contains(name, "standard"), strings.Contains(name, "restricted"):
		return "transport"
	default:
		return "runtime"
	}
}

func statusTransportUnit(role model.Role, kind model.TransportKind) string {
	if role == model.RoleNode && kind == model.TransportRestricted {
		return "vpnctl-routing.service"
	}
	if kind == model.TransportStandard {
		return "vpnctl-standard.service"
	}
	if kind == model.TransportRestricted {
		return "vpnctl-restricted.service"
	}
	return ""
}

func statusTransportResourceID(value model.Transport) string {
	return string(value.OwnerKind) + ":" + value.OwnerID + ":" + string(value.Kind)
}

func nodeStatusHasGateway(state model.State) bool {
	for _, node := range state.Nodes {
		if node.Lifecycle == model.LifecycleActive && node.Gateway != nil {
			return true
		}
	}
	return false
}

func classifyStatusCommandError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole):
		return output.CategoryValidation, "unsupported_role", "status requires an initialized gateway or node"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return output.CategoryUnavailable, "status_cancelled", "passive status collection did not complete"
	default:
		return output.CategoryInternal, "status_failed", "passive status collection failed"
	}
}

func emitStatusCommandFailure(emitter *ResultEmitter, category output.ExitCategory, code, message string) int {
	status := output.StatusFailed
	if category == output.CategoryUnavailable || category == output.CategoryConflict {
		status = output.StatusDegraded
	}
	result := output.NewResult("status", status, category, output.SafeObject{
		"overall": "failed", "generation": uint64(0),
	})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}
