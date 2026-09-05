package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type presetUpdateAPI interface {
	Plan(string) (routing.PresetUpdatePlan, error)
	Apply(routing.PresetUpdatePlan, routing.PresetUpdateMode) (routing.PresetUpdateResult, error)
}

var (
	presetUpdateSystemPaths = store.DefaultPaths
	presetUpdateLoadRole    = loadSystemHostRole
	presetUpdateBuild       = func(paths store.Paths) (presetUpdateAPI, error) {
		stateStore, err := store.NewStateStore(paths)
		if err != nil {
			return nil, err
		}
		catalog, err := routing.CurrentBuiltinPresetUpdateCatalog()
		if err != nil {
			return nil, err
		}
		return routing.NewPresetUpdater(paths, stateStore, catalog, nil)
	}
)

func isPresetUpdateInvocation(args []string) bool {
	positionals := commandPositionals(args)
	return len(positionals) >= 2 && positionals[0] == "preset" && positionals[1] == "update"
}

type presetUpdateArguments struct {
	Name   string
	DryRun bool
	Defer  bool
	JSON   bool
	Help   bool
}

func executePresetUpdate(args []string, stdout, stderr io.Writer) int {
	parsed, err := parsePresetUpdateArguments(args)
	if parsed.Help {
		printPresetUpdateHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "preset update failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitPresetUpdateFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := presetUpdateSystemPaths()
	role, err := presetUpdateLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitPresetUpdateFailure(emitter, output.CategoryValidation, "invalid_host_state", "preset update requires an initialized gateway")
	}
	request := MutationRequest{CommandID: "preset.update", Role: role, DryRun: parsed.DryRun, Defer: parsed.Defer, JSON: parsed.JSON}
	if _, _, err := V2CommandRegistry().ResolveMutationMode(request); err != nil {
		category, code, message := classifyPresetUpdateError(err)
		return emitPresetUpdateFailure(emitter, category, code, message)
	}
	updater, err := presetUpdateBuild(paths)
	if err != nil {
		return emitPresetUpdateFailure(emitter, output.CategoryInternal, "preset_update_unavailable", "vpnctl could not construct the preset updater")
	}
	mode := routing.PresetUpdateImmediate
	if parsed.Defer {
		mode = routing.PresetUpdateDeferred
	}
	workflow := &presetUpdateMutationWorkflow{updater: updater, name: parsed.Name, mode: mode}
	var authority AuthoritativeDeferredWriter
	if parsed.Defer {
		authority = workflow
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), request, nil, workflow, authority)
	if err != nil {
		category, code, message := classifyPresetUpdateError(err)
		return emitPresetUpdateFailure(emitter, category, code, message)
	}
	exit, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parsePresetUpdateArguments(args []string) (presetUpdateArguments, error) {
	parsed := presetUpdateArguments{}
	positionals := make([]string, 0, len(args))
	seen := make(map[string]bool)
	for _, argument := range args {
		switch argument {
		case "--json", "--dry-run", "--defer":
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
			}
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported preset update option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) != 3 || positionals[0] != "preset" || positionals[1] != "update" {
		return parsed, fmt.Errorf("preset update requires exactly one built-in preset name")
	}
	parsed.Name = positionals[2]
	if parsed.DryRun && parsed.Defer {
		return parsed, fmt.Errorf("--dry-run and --defer are mutually exclusive")
	}
	return parsed, nil
}

type presetUpdateMutationWorkflow struct {
	updater presetUpdateAPI
	name    string
	mode    routing.PresetUpdateMode

	mu   sync.Mutex
	plan *routing.PresetUpdatePlan
}

func (workflow *presetUpdateMutationWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	plan, err := workflow.updater.Plan(workflow.name)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.mu.Lock()
	retained := plan
	workflow.plan = &retained
	workflow.mu.Unlock()
	return MutationPlan{Impact: ImpactNone, Result: presetUpdatePreviewOutput(plan)}, nil
}

func (workflow *presetUpdateMutationWorkflow) Apply(_ context.Context, public MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	plan, err := workflow.retained(public)
	if err != nil {
		return AppliedMutation{}, err
	}
	result, err := workflow.updater.Apply(plan, routing.PresetUpdateImmediate)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: presetUpdateResultOutput(result)}, nil
}

func (workflow *presetUpdateMutationWorkflow) RegisterPending(_ context.Context, public MutationPlan) (DeferredReceipt, error) {
	plan, err := workflow.retained(public)
	if err != nil {
		return DeferredReceipt{}, err
	}
	result, err := workflow.updater.Apply(plan, routing.PresetUpdateDeferred)
	if err != nil {
		return DeferredReceipt{}, err
	}
	return DeferredReceipt{
		CommandID: "preset.update", OperationID: result.OperationID,
		AuthoritativeGeneration: result.StateGeneration, Result: presetUpdateResultOutput(result),
	}, nil
}

func (workflow *presetUpdateMutationWorkflow) retained(public MutationPlan) (routing.PresetUpdatePlan, error) {
	workflow.mu.Lock()
	defer workflow.mu.Unlock()
	if workflow.plan == nil || public.Result.Command != "preset.update" || public.Impact != ImpactNone ||
		public.Result.ResourceIDs["preset_name"] != workflow.plan.Name {
		return routing.PresetUpdatePlan{}, ErrInvalidMutationPlan
	}
	return *workflow.plan, nil
}

func presetUpdatePreviewOutput(plan routing.PresetUpdatePlan) output.Result {
	result := output.NewResult("preset.update", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": plan.NextStateGeneration,
	})
	result.ResourceIDs["preset_name"] = plan.Name
	addPresetUpdateAssignmentActions(&result, plan.Diff)
	return result
}

func presetUpdateResultOutput(value routing.PresetUpdateResult) output.Result {
	status := output.StatusOK
	if value.Mode == routing.PresetUpdateDeferred {
		status = output.StatusPending
	}
	result := output.NewResult("preset.update", status, output.CategorySuccess, output.SafeObject{
		"changed": value.SourceChanged || value.EffectiveChanged, "generation": value.StateGeneration,
	})
	result.ResourceIDs["preset_name"] = value.Name
	if value.OperationID != "" {
		result.Data["operation_id"] = value.OperationID
		result.ResourceIDs["operation_id"] = value.OperationID
	}
	addPresetUpdateAssignmentActions(&result, value.Diff)
	return result
}

func addPresetUpdateAssignmentActions(result *output.Result, diff routing.PresetDiffResult) {
	seen := make(map[string]struct{})
	for _, change := range diff.Changes {
		for _, assignment := range change.Assignments {
			key := string(assignment.TargetKind) + ":" + assignment.TargetID
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			switch assignment.TargetKind {
			case model.TargetClient:
				result.RequiresAction = append(result.RequiresAction, output.Action{
					Code: "re_export_client", Message: "Export a fresh client profile after the effective preset generation is applied.",
					Command: "vpnctl client export " + assignment.TargetID + " clash", ResourceIDs: map[string]string{"client_id": assignment.TargetID},
				})
			case model.TargetNode:
				result.RequiresAction = append(result.RequiresAction, output.Action{
					Code: "apply_node_policy", Message: "Run convergence on the assigned node after the effective preset generation is applied.",
					Command: "vpnctl apply", ResourceIDs: map[string]string{"node_id": assignment.TargetID},
				})
			}
		}
	}
}

func classifyPresetUpdateError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags), errors.Is(err, routing.ErrBuiltinPresetTemplateNotFound),
		errors.Is(err, routing.ErrBuiltinPresetTemplateNoUpdate), errors.Is(err, routing.ErrBuiltinPresetTemplateConflict),
		errors.Is(err, routing.ErrPresetUpdateInvalidCandidate):
		return output.CategoryValidation, "preset_update_invalid", "the built-in preset update is unavailable, current, or conflicts with the editable source"
	case errors.Is(err, routing.ErrPresetUpdateStale), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "preset_update_conflict", "the preset source or authoritative generation changed after review"
	case errors.Is(err, routing.ErrPresetUpdateCommitUncertain):
		return output.CategoryUnavailable, "preset_update_uncertain", "the preset update outcome is uncertain; inspect preset diff and state before retrying"
	default:
		return output.CategoryInternal, "preset_update_failed", "vpnctl could not complete the preset update"
	}
}

func emitPresetUpdateFailure(emitter *ResultEmitter, category output.ExitCategory, code, message string) int {
	result := output.NewResult("preset.update", output.StatusFailed, category, output.SafeObject{"changed": false, "generation": uint64(0)})
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func printPresetUpdateHelp(writer io.Writer) {
	fmt.Fprint(writer, `Three-way merge the next embedded built-in preset revision into its editable source.

Usage:
  vpnctl preset update <name> [--dry-run|--defer] [--json]

Immediate mode updates the source and effective generation atomically. Deferred
mode updates only the editable source and records a gateway pending operation.
`)
}

var _ MutationWorkflow = (*presetUpdateMutationWorkflow)(nil)
var _ AuthoritativeDeferredWriter = (*presetUpdateMutationWorkflow)(nil)
