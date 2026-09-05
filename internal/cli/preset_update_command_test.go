package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type presetUpdateStub struct {
	plan       routing.PresetUpdatePlan
	result     routing.PresetUpdateResult
	planCalls  int
	applyModes []routing.PresetUpdateMode
}

func (stub *presetUpdateStub) Plan(name string) (routing.PresetUpdatePlan, error) {
	stub.planCalls++
	result := stub.plan
	result.Name = name
	return result, nil
}

func (stub *presetUpdateStub) Apply(_ routing.PresetUpdatePlan, mode routing.PresetUpdateMode) (routing.PresetUpdateResult, error) {
	stub.applyModes = append(stub.applyModes, mode)
	result := stub.result
	result.Mode = mode
	return result, nil
}

func TestExecutePresetUpdateDryRunAndDeferredReceipt(t *testing.T) {
	oldPaths, oldRole, oldBuild := presetUpdateSystemPaths, presetUpdateLoadRole, presetUpdateBuild
	t.Cleanup(func() { presetUpdateSystemPaths, presetUpdateLoadRole, presetUpdateBuild = oldPaths, oldRole, oldBuild })
	paths, _ := store.NewPaths(t.TempDir())
	stub := &presetUpdateStub{
		plan: routing.PresetUpdatePlan{
			ExpectedStateGeneration: 4, NextStateGeneration: 5,
			Diff: routing.PresetDiffResult{Valid: true, Changes: []routing.PresetChange{{
				Name: "telegram", Kind: routing.PresetModified,
				Assignments: []routing.PresetAssignment{{TargetKind: model.TargetClient, TargetID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", TargetName: "phone"}},
			}}, Issues: []routing.PresetIssue{}},
		},
		result: routing.PresetUpdateResult{
			Name: "telegram", OperationID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", SourceChanged: true, StateGeneration: 5,
			Diff: routing.PresetDiffResult{Valid: true, Changes: []routing.PresetChange{}, Issues: []routing.PresetIssue{}},
		},
	}
	presetUpdateSystemPaths = func() store.Paths { return paths }
	presetUpdateLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	presetUpdateBuild = func(store.Paths) (presetUpdateAPI, error) { return stub, nil }

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"preset", "update", "telegram", "--dry-run", "--json"}, &stdout, &stderr); code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("dry-run exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"command":"preset.update"`) || !strings.Contains(stdout.String(), `"generation":5`) ||
		!strings.Contains(stdout.String(), `"code":"re_export_client"`) || stub.planCalls != 1 || len(stub.applyModes) != 0 {
		t.Fatalf("dry-run output/calls = %q %d/%v", stdout.String(), stub.planCalls, stub.applyModes)
	}

	stdout.Reset()
	if code := Execute([]string{"--json", "preset", "update", "telegram", "--defer"}, &stdout, &stderr); code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("defer exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"pending"`) || !strings.Contains(stdout.String(), `"operation_id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd"`) ||
		len(stub.applyModes) != 1 || stub.applyModes[0] != routing.PresetUpdateDeferred {
		t.Fatalf("defer output/modes = %q %v", stdout.String(), stub.applyModes)
	}
}

func TestExecutePresetUpdateRejectsNodeBeforeBuildingUpdater(t *testing.T) {
	oldPaths, oldRole, oldBuild := presetUpdateSystemPaths, presetUpdateLoadRole, presetUpdateBuild
	t.Cleanup(func() { presetUpdateSystemPaths, presetUpdateLoadRole, presetUpdateBuild = oldPaths, oldRole, oldBuild })
	paths, _ := store.NewPaths(t.TempDir())
	presetUpdateSystemPaths = func() store.Paths { return paths }
	presetUpdateLoadRole = func(store.Paths) (HostRole, error) { return RoleNode, nil }
	presetUpdateBuild = func(store.Paths) (presetUpdateAPI, error) {
		t.Fatal("preset updater built before role rejection")
		return nil, nil
	}

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"preset", "update", "telegram", "--json"}, &stdout, &stderr); code != ExitValidation ||
		!strings.Contains(stdout.String(), `"code":"preset_update_invalid"`) {
		t.Fatalf("node update exit/output=%d %q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestParsePresetUpdateRejectsAmbiguousModesAndExtraTargets(t *testing.T) {
	for _, args := range [][]string{
		{"preset", "update", "telegram", "--dry-run", "--defer"},
		{"preset", "update", "telegram", "openai"},
		{"preset", "update", "telegram", "--yes"},
	} {
		if _, err := parsePresetUpdateArguments(args); err == nil {
			t.Fatalf("parsePresetUpdateArguments(%v) succeeded", args)
		}
	}
}
