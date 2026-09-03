package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type dnsStateStore interface {
	Load() (model.State, error)
	Save(uint64, model.State) error
}

var (
	dnsSystemPaths                           = store.DefaultPaths
	dnsLoadRole                              = loadSystemHostRole
	dnsNewStore                              = func(paths store.Paths) (dnsStateStore, error) { return store.NewStateStore(paths) }
	dnsDiscover                              = linuxplatform.DiscoverResolverIPv4
	dnsRunner      linuxplatform.ProbeRunner = linuxplatform.OSProbeRunner{}
	dnsCallGateway                           = control.CallLocal
	dnsPrepareNode                           = routing.PrepareNodeDNSConfigTransaction
)

func isDNSInvocation(args []string) bool {
	for _, argument := range args {
		if argument == "--json" {
			continue
		}
		return argument == "dns"
	}
	return false
}

type dnsArguments struct {
	Action    string
	IPv4      []string
	DryRun    bool
	JSON      bool
	ShowHelp  bool
	CommandID string
}

func executeDNS(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseDNSArguments(args)
	if parsed.ShowHelp {
		printDNSHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "dns failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitDNSFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := dnsSystemPaths()
	role, err := dnsLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitDNSFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_host_state", "dns requires an initialized gateway or node")
	}
	stateStore, err := dnsNewStore(paths)
	if err != nil {
		return emitDNSFailure(emitter, parsed.CommandID, output.CategoryInternal, "dns_internal_error", "vpnctl could not open authoritative state")
	}
	if parsed.Action == "show" {
		return executeDNSShow(emitter, role, stateStore)
	}

	upstreams := append([]string(nil), parsed.IPv4...)
	if parsed.Action == "reset" {
		if role == RoleGateway {
			upstreams = model.DefaultGatewayDNSUpstreams()
		} else {
			upstreams, err = dnsDiscover(paths.Root)
			if err != nil {
				return emitDNSFailure(emitter, parsed.CommandID, output.CategoryUnavailable, "dns_discovery_failed", "vpnctl could not rediscover non-stub IPv4 resolvers")
			}
		}
	}
	workflow := &dnsMutationWorkflow{paths: paths, role: role, store: stateStore, commandID: parsed.CommandID, upstreams: upstreams}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: parsed.CommandID, Role: role, DryRun: parsed.DryRun, JSON: parsed.JSON,
	}, nil, workflow, nil)
	if err != nil {
		category, code, message := classifyDNSError(err)
		return emitDNSFailure(emitter, parsed.CommandID, category, code, message)
	}
	code, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func parseDNSArguments(args []string) (dnsArguments, error) {
	parsed := dnsArguments{CommandID: "dns.show"}
	positionals := make([]string, 0, len(args))
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
		case "-h", "--help", "help":
			parsed.ShowHelp = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported dns option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.ShowHelp {
		return parsed, nil
	}
	if len(positionals) == 0 || positionals[0] != "dns" {
		return parsed, fmt.Errorf("dns command is missing")
	}
	if len(positionals) < 2 {
		return parsed, fmt.Errorf("dns requires show, set, or reset")
	}
	parsed.Action = positionals[1]
	parsed.CommandID = "dns." + parsed.Action
	switch parsed.Action {
	case "show":
		if parsed.DryRun || len(positionals) != 2 {
			return parsed, fmt.Errorf("dns show accepts only --json")
		}
	case "set":
		if len(positionals) < 3 {
			return parsed, fmt.Errorf("dns set requires one or more IPv4 resolvers")
		}
		parsed.IPv4 = append([]string(nil), positionals[2:]...)
	case "reset":
		if len(positionals) != 2 {
			return parsed, fmt.Errorf("dns reset accepts no resolver arguments")
		}
	default:
		return parsed, fmt.Errorf("unsupported dns action %s", parsed.Action)
	}
	return parsed, nil
}

func executeDNSShow(emitter *ResultEmitter, role HostRole, stateStore dnsStateStore) int {
	state, err := stateStore.Load()
	if err != nil || state.DNS == nil {
		return emitDNSFailure(emitter, "dns.show", output.CategoryInternal, "dns_state_unavailable", "vpnctl could not load role-owned DNS state")
	}
	if !roleMatchesDNSState(role, state) {
		return emitDNSFailure(emitter, "dns.show", output.CategoryConflict, "dns_scope_conflict", "DNS state does not match the initialized host role")
	}
	result := dnsShowResult(state)
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

type dnsMutationWorkflow struct {
	paths     store.Paths
	role      HostRole
	store     dnsStateStore
	commandID string
	upstreams []string
	before    model.State
	candidate model.State
	changed   bool
	planned   bool
}

func (workflow *dnsMutationWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	state, err := workflow.store.Load()
	if err != nil {
		return MutationPlan{}, err
	}
	if !roleMatchesDNSState(workflow.role, state) {
		return MutationPlan{}, fmt.Errorf("DNS state scope conflicts with host role")
	}
	candidate, changed, err := routing.ReplaceDNSUpstreams(state, workflow.upstreams)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.before, workflow.candidate, workflow.changed, workflow.planned = state, candidate, changed, true
	return MutationPlan{Impact: ImpactAvailability, Result: dnsMutationResult(workflow.commandID, candidate, changed)}, nil
}

func (workflow *dnsMutationWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("DNS mutation was not planned")
	}
	current, err := workflow.store.Load()
	if err != nil {
		return AppliedMutation{}, err
	}
	if current.Generation != workflow.before.Generation {
		return AppliedMutation{}, store.ErrStateConflict
	}
	if !workflow.changed {
		return AppliedMutation{Result: dnsMutationResult(workflow.commandID, current, false)}, nil
	}
	if workflow.role == RoleGateway {
		payload, _ := json.Marshal(struct {
			IPv4 []string `json:"ipv4"`
		}{IPv4: workflow.upstreams})
		response, err := dnsCallGateway(ctx, workflow.paths.ControlSocket, control.LocalRequest{
			SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate, Operation: workflow.commandID,
			ExpectedGeneration: workflow.before.Generation, Payload: payload,
		})
		if err != nil {
			return AppliedMutation{}, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
		}
		if !response.OK {
			if response.ErrorCode == "generation_conflict" {
				return AppliedMutation{}, store.ErrStateConflict
			}
			return AppliedMutation{}, fmt.Errorf("gateway DNS mutation failed: %s", response.ErrorCode)
		}
		resultState := workflow.candidate
		resultState.Generation = response.Generation
		return AppliedMutation{Result: dnsMutationResult(workflow.commandID, resultState, true)}, nil
	}

	transaction, err := dnsPrepareNode(workflow.paths, dnsRunner, workflow.before, workflow.candidate)
	if err != nil {
		return AppliedMutation{}, err
	}
	if err := transaction.Apply(ctx); err != nil {
		return AppliedMutation{}, err
	}
	if err := workflow.store.Save(workflow.before.Generation, workflow.candidate); err != nil {
		observed, loadErr := workflow.store.Load()
		if loadErr == nil && reflect.DeepEqual(observed, workflow.candidate) {
			return AppliedMutation{}, fmt.Errorf("authoritative state activation completed without a durable success acknowledgement: %w", err)
		}
		if loadErr != nil || !reflect.DeepEqual(observed, workflow.before) {
			return AppliedMutation{}, errors.Join(err, fmt.Errorf("authoritative state outcome is ambiguous; node DNS runtime remains on the prepared candidate"))
		}
		rollbackContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if rollbackErr := transaction.Rollback(rollbackContext); rollbackErr != nil {
			return AppliedMutation{}, errors.Join(err, fmt.Errorf("rollback node DNS runtime: %w", rollbackErr))
		}
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: dnsMutationResult(workflow.commandID, workflow.candidate, true)}, nil
}

func roleMatchesDNSState(role HostRole, state model.State) bool {
	if state.DNS == nil {
		return false
	}
	return role == RoleGateway && state.Host.Role == model.RoleGateway && state.DNS.Scope == model.DNSUpstreamGateway ||
		role == RoleNode && state.Host.Role == model.RoleNode && state.DNS.Scope == model.DNSUpstreamDirect
}

func dnsShowResult(state model.State) output.Result {
	upstreams := append([]string(nil), state.DNS.IPv4...)
	return output.NewResult("dns.show", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"scope": string(state.DNS.Scope), "generation": state.Generation, "upstreams": strings.Join(upstreams, ","),
		"resource": output.SafeObject{"scope": string(state.DNS.Scope), "ipv4": upstreams},
	})
}

func dnsMutationResult(commandID string, state model.State, changed bool) output.Result {
	return output.NewResult(commandID, output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": changed, "generation": state.Generation, "scope": string(state.DNS.Scope),
		"upstreams": strings.Join(state.DNS.IPv4, ","), "ipv4": append([]string(nil), state.DNS.IPv4...),
	})
}

func classifyDNSError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "generation_conflict", "authoritative state changed; retry the DNS command"
	case errors.Is(err, ErrGatewayUnavailable):
		return output.CategoryUnavailable, "gateway_unavailable", "the authoritative gateway controller is unavailable"
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags), strings.Contains(err.Error(), "IPv4"), strings.Contains(err.Error(), "ipv4"):
		return output.CategoryValidation, "dns_validation", err.Error()
	default:
		return output.CategoryInternal, "dns_internal_error", "vpnctl could not apply the DNS change"
	}
}

func emitDNSFailure(emitter *ResultEmitter, commandID string, category output.ExitCategory, warningCode, warningMessage string) int {
	if commandID != "dns.show" && commandID != "dns.set" && commandID != "dns.reset" {
		commandID = "dns.show"
	}
	result := output.NewResult(commandID, output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printDNSHelp(writer io.Writer) {
	fmt.Fprint(writer, `Show or change the IPv4 DNS upstreams owned by this host role.

Usage:
  vpnctl dns show [--json]
  vpnctl dns set <IPv4>... [--dry-run] [--json]
  vpnctl dns reset [--dry-run] [--json]
`)
}
