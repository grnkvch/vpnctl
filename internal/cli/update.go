package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/releasetrust"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type updateManager interface {
	Plan(context.Context, string) (lifecycle.UpdatePlan, error)
	Apply(context.Context, lifecycle.UpdatePlan) (lifecycle.UpdateResult, error)
	Discard(lifecycle.UpdatePlan) error
}

var (
	updateSystemPaths = store.DefaultPaths
	updateLoadRole    = loadSystemHostRole
	updateBuilder     = buildSystemUpdater
	updateOpenTTY     = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

type updateArguments struct {
	Version  string
	Rollback bool
	DryRun   bool
	Yes      bool
	JSON     bool
	Help     bool
}

func isUpdateInvocation(args []string) bool {
	for _, argument := range args {
		if argument == "--json" || argument == "--dry-run" || argument == "--yes" {
			continue
		}
		return argument == "update"
	}
	return false
}

func executeUpdate(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseUpdateArguments(args)
	if parsed.Help {
		printUpdateHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "update failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitUpdateFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	if parsed.Rollback {
		return emitUpdateFailure(emitter, output.CategoryValidation, "rollback_not_available", "update rollback is not available until a previous release snapshot exists")
	}
	paths := updateSystemPaths()
	role, err := updateLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitUpdateFailure(emitter, output.CategoryValidation, "invalid_host_state", "update requires an initialized gateway or node")
	}
	manager, err := updateBuilder(context.Background(), paths, role)
	if err != nil {
		category, code, message := classifyUpdateError(err)
		return emitUpdateFailure(emitter, category, code, message)
	}
	workflow, err := NewUpdateWorkflow(manager, parsed.Version)
	if err != nil {
		return emitUpdateFailure(emitter, output.CategoryInternal, "update_internal_error", "vpnctl could not prepare the update workflow")
	}
	defer workflow.Discard()
	var terminal PromptIO
	var closer io.Closer
	if !parsed.Yes && !parsed.DryRun {
		terminal, closer, _ = updateOpenTTY()
		if closer != nil {
			defer closer.Close()
		}
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "update", Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes, JSON: parsed.JSON,
	}, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyUpdateError(err)
		return emitUpdateFailure(emitter, category, code, message)
	}
	code, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func parseUpdateArguments(args []string) (updateArguments, error) {
	parsed := updateArguments{}
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
		case "--yes":
			if parsed.Yes {
				return parsed, fmt.Errorf("--yes may be supplied only once")
			}
			parsed.Yes = true
		case "--defer":
			return parsed, fmt.Errorf("update does not support --defer")
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported update option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) == 0 || positionals[0] != "update" {
		return parsed, fmt.Errorf("update command is missing")
	}
	if len(positionals) > 2 {
		return parsed, fmt.Errorf("update accepts at most one version")
	}
	if len(positionals) == 1 {
		return parsed, nil
	}
	if positionals[1] == "rollback" {
		if parsed.DryRun {
			return parsed, fmt.Errorf("update rollback does not support --dry-run")
		}
		parsed.Rollback = true
		return parsed, nil
	}
	version, err := lifecycle.CanonicalStableReleaseVersion(positionals[1])
	if err != nil {
		return parsed, err
	}
	parsed.Version = version
	return parsed, nil
}

type UpdateWorkflow struct {
	manager  updateManager
	version  string
	plan     lifecycle.UpdatePlan
	public   MutationPlan
	planned  bool
	finished bool
}

func NewUpdateWorkflow(manager updateManager, version string) (*UpdateWorkflow, error) {
	if manager == nil {
		return nil, fmt.Errorf("update manager is required")
	}
	return &UpdateWorkflow{manager: manager, version: version}, nil
}

func (workflow *UpdateWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.manager == nil || workflow.planned {
		return MutationPlan{}, fmt.Errorf("update workflow cannot be planned")
	}
	plan, err := workflow.manager.Plan(ctx, workflow.version)
	if err != nil {
		return MutationPlan{}, err
	}
	public, err := updatePlanOutput(plan)
	if err != nil {
		_ = workflow.manager.Discard(plan)
		return MutationPlan{}, err
	}
	impact := ImpactNone
	if plan.Changed && !plan.Blocked {
		impact = ImpactAvailability
	}
	workflow.plan = plan
	workflow.public = MutationPlan{Impact: impact, IrreversibleMigration: plan.Changed && !plan.Migration.Reversible, Result: public}
	workflow.planned = true
	return workflow.public, nil
}

func (workflow *UpdateWorkflow) Apply(ctx context.Context, public MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.manager == nil || !workflow.planned || workflow.finished || !reflect.DeepEqual(public, workflow.public) {
		return AppliedMutation{}, fmt.Errorf("update apply does not match the retained plan")
	}
	result, err := workflow.manager.Apply(ctx, workflow.plan)
	workflow.finished = true
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: updateResultOutput(result)}, nil
}

func (workflow *UpdateWorkflow) Discard() error {
	if workflow == nil || workflow.manager == nil || !workflow.planned || workflow.finished {
		return nil
	}
	workflow.finished = true
	return workflow.manager.Discard(workflow.plan)
}

func updatePlanOutput(plan lifecycle.UpdatePlan) (output.Result, error) {
	status, category := output.StatusOK, output.CategorySuccess
	if plan.Blocked {
		status, category = output.StatusFailed, output.CategoryConflict
	}
	result := output.NewResult("update", status, category, updatePlanData(plan))
	for _, interruption := range plan.ExpectedInterruptions {
		result.Warnings = append(result.Warnings, output.Message{Code: "expected_interruption", Message: interruption})
	}
	for _, action := range plan.RequiresAction {
		result.RequiresAction = append(result.RequiresAction, output.Action{Code: "resolve_update_compatibility", Message: action})
	}
	componentRows := make([][]string, 0, len(plan.Components))
	for _, component := range plan.Components {
		componentRows = append(componentRows, []string{
			component.Name, component.CurrentVersion, component.TargetVersion, fmt.Sprint(component.FileChanged), strings.Join(component.AffectedServices, ","),
		})
	}
	if err := result.AddHumanTable("components", []string{"name", "current", "target", "file_changed", "services"}, componentRows); err != nil {
		return output.Result{}, err
	}
	packageRows := make([][]string, 0, len(plan.Packages))
	for _, check := range plan.Packages {
		packageRows = append(packageRows, []string{check.Component, check.Package, check.InstalledVersion, fmt.Sprint(check.Compatible)})
	}
	if err := result.AddHumanTable("packages", []string{"component", "package", "installed", "compatible"}, packageRows); err != nil {
		return output.Result{}, err
	}
	if err := result.AddHumanTable("fleet_summary", []string{"compatible", "selected_protocol", "gateway_version"}, [][]string{{
		fmt.Sprint(plan.Fleet.Compatible), plan.Fleet.SelectedProtocol, plan.Fleet.GatewayVersion,
	}}); err != nil {
		return output.Result{}, err
	}
	fleetRows := make([][]string, 0, len(plan.Fleet.Nodes))
	for _, node := range plan.Fleet.Nodes {
		fleetRows = append(fleetRows, []string{node.ID, node.Name, node.ControlProtocol, fmt.Sprint(node.Compatible), node.Code})
	}
	if err := result.AddHumanTable("fleet", []string{"id", "name", "protocol", "compatible", "code"}, fleetRows); err != nil {
		return output.Result{}, err
	}
	if err := result.AddHumanTable("migration", []string{"from_schema", "to_schema", "reversible", "steps"}, [][]string{{
		fmt.Sprint(plan.Migration.FromSchema), fmt.Sprint(plan.Migration.ToSchema), fmt.Sprint(plan.Migration.Reversible), strings.Join(plan.Migration.Steps, ","),
	}}); err != nil {
		return output.Result{}, err
	}
	return result, nil
}

func updatePlanData(plan lifecycle.UpdatePlan) output.SafeObject {
	components := make(output.SafeList, 0, len(plan.Components))
	affected := make(map[string]struct{})
	for _, component := range plan.Components {
		services := append([]string{}, component.AffectedServices...)
		for _, service := range services {
			affected[service] = struct{}{}
		}
		components = append(components, output.SafeObject{
			"name": component.Name, "current_version": component.CurrentVersion, "target_version": component.TargetVersion,
			"bundled": component.Bundled, "changed": component.Changed, "file_changed": component.FileChanged, "affected_services": services,
		})
	}
	affectedServices := make([]string, 0, len(affected))
	for service := range affected {
		affectedServices = append(affectedServices, service)
	}
	sortStrings(affectedServices)
	packages := make(output.SafeList, 0, len(plan.Packages))
	for _, check := range plan.Packages {
		packages = append(packages, output.SafeObject{
			"component": check.Component, "package": check.Package, "installed_version": check.InstalledVersion, "compatible": check.Compatible,
		})
	}
	nodes := make(output.SafeList, 0, len(plan.Fleet.Nodes))
	for _, node := range plan.Fleet.Nodes {
		nodes = append(nodes, output.SafeObject{
			"id": node.ID, "name": node.Name, "control_protocol": node.ControlProtocol, "compatible": node.Compatible, "code": node.Code,
		})
	}
	return output.SafeObject{
		"changed": plan.Changed, "operation_id": plan.OperationID, "generation": plan.ExpectedStateGeneration,
		"role": string(plan.Role), "requested_version": plan.RequestedVersion, "latest_stable": plan.LatestStable,
		"current_version": plan.CurrentVersion, "target_version": plan.TargetVersion, "blocked": plan.Blocked,
		"rollback_available": plan.RollbackAvailable, "affected_services": affectedServices,
		"expected_interruptions": append([]string{}, plan.ExpectedInterruptions...), "components": components, "packages": packages,
		"fleet": output.SafeObject{
			"compatible": plan.Fleet.Compatible, "selected_protocol": plan.Fleet.SelectedProtocol,
			"gateway_version": plan.Fleet.GatewayVersion, "nodes": nodes,
		},
		"migration": output.SafeObject{
			"from_schema": plan.Migration.FromSchema, "to_schema": plan.Migration.ToSchema,
			"steps": append([]string{}, plan.Migration.Steps...), "reversible": plan.Migration.Reversible,
		},
	}
}

func updateResultOutput(result lifecycle.UpdateResult) output.Result {
	components := make(output.SafeList, 0, len(result.ComponentResults))
	for _, component := range result.ComponentResults {
		components = append(components, output.SafeObject{
			"name": component.Name, "changed": component.Changed, "healthy": component.Healthy, "rolled_back": component.RolledBack,
		})
	}
	outputResult := output.NewResult("update", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": result.Changed, "operation_id": result.OperationID, "role": string(result.Role),
		"previous_version": result.PreviousVersion, "current_version": result.CurrentVersion, "generation": result.Generation,
		"components": components, "expected_interruptions": append([]string{}, result.ExpectedInterruptions...),
	})
	for _, action := range result.RequiresAction {
		outputResult.RequiresAction = append(outputResult.RequiresAction, output.Action{Code: "update_node_locally", Message: action})
	}
	return outputResult
}

func buildSystemUpdater(_ context.Context, paths store.Paths, role HostRole) (updateManager, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	state, err := stateStore.Load()
	if err != nil {
		return nil, err
	}
	modelRole, ok := updateModelRole(role)
	if !ok || state.Host.Role != modelRole {
		return nil, fmt.Errorf("update host role conflicts with authoritative state")
	}
	publicKey, err := releasetrust.PublicKey()
	if err != nil {
		return nil, err
	}
	installer, err := lifecycle.NewReleaseBundleInstaller(paths.Root, publicKey, lifecycle.ReleasePlatform{
		OperatingSystem: state.Host.OS, Version: state.Host.OSVersion, Architecture: state.Host.Architecture,
	})
	if err != nil {
		return nil, err
	}
	source, err := lifecycle.NewUpdateReleaseSource(lifecycle.DefaultReleaseRepositoryURL, http.DefaultClient, publicKey, installer)
	if err != nil {
		return nil, err
	}
	host, err := lifecycle.NewSystemUpdateHostRuntime(paths.Root, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, err
	}
	var fleet lifecycle.UpdateFleetChecker = lifecycle.GatewayUpdateFleetChecker{}
	if modelRole == model.RoleNode {
		fleet, err = lifecycle.NewSystemNodeUpdateFleetChecker(paths, nil)
		if err != nil {
			return nil, err
		}
	}
	return lifecycle.NewUpdater(lifecycle.UpdateRuntime{
		State: stateStore, Releases: source, Bundles: installer, Fleet: fleet, Host: host,
		CurrentBundlePath: filepath.Join(paths.Root, strings.TrimPrefix(lifecycle.ReleaseInstalledBundlePath, "/")),
	})
}

func updateModelRole(role HostRole) (model.Role, bool) {
	switch role {
	case RoleGateway:
		return model.RoleGateway, true
	case RoleNode:
		return model.RoleNode, true
	default:
		return "", false
	}
}

func classifyUpdateError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, lifecycle.ErrUpdateConflict), errors.Is(err, lifecycle.ErrReleaseUpdateConflict), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "update_conflict", "authoritative state or installed release changed; retry the update"
	case errors.Is(err, lifecycle.ErrUpdateHealth):
		return output.CategoryUnavailable, "update_health_failed", "an updated component failed health checks and vpnctl restored the prior local release"
	case errors.Is(err, ErrInteractionRefused), errors.Is(err, ErrConsentDeclined), errors.Is(err, ErrPromptInput), errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags):
		return output.CategoryValidation, "update_validation", singleLineGatewayInitMessage(err.Error())
	case strings.Contains(err.Error(), "download"), strings.Contains(err.Error(), "controller could not be reached"):
		return output.CategoryUnavailable, "update_source_unavailable", "the requested release or gateway compatibility check is unavailable"
	default:
		return output.CategoryInternal, "update_internal_error", "vpnctl could not complete the local software update"
	}
}

func emitUpdateFailure(emitter *ResultEmitter, category output.ExitCategory, warningCode, warningMessage string) int {
	result := output.NewResult("update", output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor] < values[cursor-1]; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
}

func printUpdateHelp(writer io.Writer) {
	fmt.Fprint(writer, `Update the current gateway or node from one verified stable release bundle.

Usage:
  vpnctl update [version] [--dry-run] [--yes] [--json]
  vpnctl update rollback [--yes] [--json]

With no version, vpnctl checks the latest stable release only for this command.
Updates are local and manual; vpnctl never updates remote nodes automatically.
`)
}

var _ MutationWorkflow = (*UpdateWorkflow)(nil)
