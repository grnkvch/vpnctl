package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type presetCatalogAPI interface {
	List() (routing.PresetListResult, error)
	Show(string) (routing.PresetShowResult, error)
	Validate() (routing.PresetValidationResult, error)
	Diff() (routing.PresetDiffResult, error)
}

var (
	presetSystemPaths = store.DefaultPaths
	presetLoadRole    = loadSystemHostRole
	presetBuild       = func(paths store.Paths) (presetCatalogAPI, error) {
		stateStore, err := store.NewStateStore(paths)
		if err != nil {
			return nil, err
		}
		return routing.NewPresetCatalog(paths, stateStore)
	}
)

func isPresetCatalogInvocation(args []string) bool {
	positionals := commandPositionals(args)
	if len(positionals) < 2 || positionals[0] != "preset" {
		return false
	}
	switch positionals[1] {
	case "list", "show", "validate", "diff":
		return true
	default:
		return false
	}
}

type presetCatalogArguments struct {
	CommandID string
	Name      string
	JSON      bool
	Help      bool
}

func executePresetCatalog(args []string, stdout, stderr io.Writer) int {
	parsed, err := parsePresetCatalogArguments(args)
	if parsed.Help {
		printPresetCatalogHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "preset failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitPresetFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := presetSystemPaths()
	role, err := presetLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitPresetFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_host_state", "preset commands require an initialized gateway")
	}

	var result output.Result
	err = V2CommandRegistry().Dispatch(parsed.CommandID, role, func(CommandSpec) error {
		catalog, buildErr := presetBuild(paths)
		if buildErr != nil {
			return buildErr
		}
		switch parsed.CommandID {
		case "preset.list":
			value, readErr := catalog.List()
			if readErr != nil {
				return readErr
			}
			result = presetListOutput(value)
		case "preset.show":
			value, readErr := catalog.Show(parsed.Name)
			if readErr != nil {
				return readErr
			}
			result = presetShowOutput(value)
		case "preset.validate":
			value, readErr := catalog.Validate()
			if readErr != nil {
				return readErr
			}
			result = presetValidationOutput(value)
		case "preset.diff":
			value, readErr := catalog.Diff()
			if readErr != nil {
				return readErr
			}
			result = presetDiffOutput(value)
		}
		return nil
	})
	if err != nil {
		category, code, message := classifyPresetError(err)
		return emitPresetFailure(emitter, parsed.CommandID, category, code, message)
	}
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func parsePresetCatalogArguments(args []string) (presetCatalogArguments, error) {
	parsed := presetCatalogArguments{CommandID: "preset.list"}
	positionals := make([]string, 0, 3)
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
				return parsed, fmt.Errorf("unsupported preset option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) < 2 || positionals[0] != "preset" {
		return parsed, fmt.Errorf("preset requires list, show, validate, or diff")
	}
	parsed.CommandID = "preset." + positionals[1]
	switch positionals[1] {
	case "list", "validate", "diff":
		if len(positionals) != 2 {
			return parsed, fmt.Errorf("%s accepts no arguments", parsed.CommandID)
		}
	case "show":
		if len(positionals) != 3 {
			return parsed, fmt.Errorf("preset show requires exactly one name")
		}
		parsed.Name = positionals[2]
	default:
		return parsed, fmt.Errorf("preset requires list, show, validate, or diff")
	}
	return parsed, nil
}

func presetListOutput(value routing.PresetListResult) output.Result {
	items := make([]output.SafeObject, 0, len(value.Items))
	rows := make([][]string, 0, len(value.Items))
	for _, item := range value.Items {
		items = append(items, output.SafeObject{
			"name": item.Name, "source_present": item.SourcePresent, "source_valid": item.SourceValid,
			"effective_present": item.EffectivePresent, "source_changed": item.SourceChanged,
			"selector_changed": item.SelectorChanged, "builtin": item.Builtin,
			"builtin_revision": item.BuiltinRevision, "available_builtin_revision": item.AvailableBuiltinRevision,
			"assignments": presetAssignmentsOutput(item.Assignments), "issues": presetIssuesOutput(item.Issues),
		})
		rows = append(rows, []string{item.Name, fmt.Sprint(item.SourcePresent), fmt.Sprint(item.SourceValid), fmt.Sprint(item.EffectivePresent), fmt.Sprint(item.SourceChanged || item.SelectorChanged)})
	}
	result := output.NewResult("preset.list", output.StatusOK, output.CategorySuccess, output.SafeObject{"items": items})
	_ = result.AddHumanTable("presets", []string{"name", "source", "valid", "effective", "changed"}, rows)
	addPresetIssueWarnings(&result, value.Issues)
	return result
}

func presetShowOutput(value routing.PresetShowResult) output.Result {
	resource := output.SafeObject{
		"generation": value.StateGeneration, "assignments": presetAssignmentsOutput(value.Assignments), "issues": presetIssuesOutput(value.Issues),
	}
	if value.Source != nil {
		resource["source"] = output.SafeObject{
			"name": value.Source.Name, "filename": value.Source.Filename, "file_path": value.Source.Path,
			"present": value.Source.Present, "valid": value.Source.Valid, "sha256": value.Source.SHA256,
			"builtin_revision": value.Source.BuiltinRevision, "selectors": presetSelectorsOutput(value.Source.Selectors),
		}
	}
	if value.Effective != nil {
		resource["effective"] = output.SafeObject{
			"name": value.Effective.Name, "present": value.Effective.Present, "source_hash": value.Effective.SourceHash,
			"effective_hash": value.Effective.EffectiveHash, "generation": value.Effective.Generation,
			"selectors": presetSelectorsOutput(value.Effective.Selectors),
		}
	}
	if value.BuiltinUpdate != nil {
		resource["builtin_update"] = output.SafeObject{"source_revision": value.BuiltinUpdate.SourceRevision, "available_revision": value.BuiltinUpdate.AvailableRevision}
	}
	result := output.NewResult("preset.show", output.StatusOK, output.CategorySuccess, output.SafeObject{"resource": resource})
	addPresetIssueWarnings(&result, value.Issues)
	return result
}

func presetValidationOutput(value routing.PresetValidationResult) output.Result {
	status, category := output.StatusOK, output.CategorySuccess
	if !value.Valid {
		status, category = output.StatusFailed, output.CategoryValidation
	}
	result := output.NewResult("preset.validate", status, category, output.SafeObject{"valid": value.Valid, "issues": presetIssuesOutput(value.Issues)})
	addPresetIssueWarnings(&result, value.Issues)
	return result
}

func presetDiffOutput(value routing.PresetDiffResult) output.Result {
	changes := make([]output.SafeObject, 0, len(value.Changes))
	for _, change := range value.Changes {
		changes = append(changes, output.SafeObject{
			"name": change.Name, "kind": string(change.Kind), "source_changed": change.SourceChanged,
			"selector_changed": change.SelectorChanged, "added_selectors": presetSelectorsOutput(change.AddedSelectors),
			"removed_selectors": presetSelectorsOutput(change.RemovedSelectors), "assignments": presetAssignmentsOutput(change.Assignments),
		})
	}
	status, category := output.StatusOK, output.CategorySuccess
	if !value.Valid {
		status, category = output.StatusFailed, output.CategoryValidation
	}
	result := output.NewResult("preset.diff", status, category, output.SafeObject{
		"impact": "none", "changes": changes, "drift": []output.SafeObject{},
	})
	addPresetIssueWarnings(&result, value.Issues)
	return result
}

func presetAssignmentsOutput(values []routing.PresetAssignment) []output.SafeObject {
	items := make([]output.SafeObject, 0, len(values))
	for _, value := range values {
		items = append(items, output.SafeObject{"target_kind": string(value.TargetKind), "target_id": value.TargetID, "target_name": value.TargetName})
	}
	return items
}

func presetSelectorsOutput(values []model.Selector) []output.SafeObject {
	items := make([]output.SafeObject, 0, len(values))
	for _, value := range values {
		items = append(items, output.SafeObject{"kind": string(value.Kind), "value": value.Value})
	}
	return items
}

func presetIssuesOutput(values []routing.PresetIssue) []output.SafeObject {
	items := make([]output.SafeObject, 0, len(values))
	for _, value := range values {
		item := output.SafeObject{"code": value.Code, "message": value.Message}
		if value.Name != "" {
			item["name"] = value.Name
		}
		if value.Filename != "" {
			item["filename"] = value.Filename
		}
		items = append(items, item)
	}
	return items
}

func addPresetIssueWarnings(result *output.Result, issues []routing.PresetIssue) {
	for _, issue := range issues {
		code := issue.Code
		if code == "" {
			code = "preset_invalid"
		}
		message := issue.Message
		if message == "" {
			message = "A preset source is invalid."
		}
		result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	}
}

func classifyPresetError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrUnsupportedRole):
		return output.CategoryValidation, "unsupported_role", "preset commands are available only on a gateway"
	case errors.Is(err, routing.ErrPresetNotFound), errors.Is(err, routing.ErrPresetAmbiguous):
		return output.CategoryValidation, "preset_not_found", "the requested preset does not exist or is ambiguous"
	default:
		return output.CategoryInternal, "preset_inspection_failed", "vpnctl could not inspect the preset catalog"
	}
}

func emitPresetFailure(emitter *ResultEmitter, commandID string, category output.ExitCategory, code, message string) int {
	var data output.SafeObject
	switch commandID {
	case "preset.show":
		data = output.SafeObject{"resource": output.SafeObject{}}
	case "preset.validate":
		data = output.SafeObject{"valid": false, "issues": []output.SafeObject{{"code": code}}}
	case "preset.diff":
		data = output.SafeObject{"impact": "none", "changes": []output.SafeObject{}, "drift": []output.SafeObject{}}
	default:
		commandID, data = "preset.list", output.SafeObject{"items": []output.SafeObject{}}
	}
	result := output.NewResult(commandID, output.StatusFailed, category, data)
	result.Warnings = append(result.Warnings, output.Message{Code: code, Message: message})
	exit, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return exit
}

func printPresetCatalogHelp(writer io.Writer) {
	fmt.Fprint(writer, `Inspect editable preset sources and their applied effective state.

Usage:
  vpnctl preset list [--json]
  vpnctl preset show <name> [--json]
  vpnctl preset validate [--json]
  vpnctl preset diff [--json]
`)
}
