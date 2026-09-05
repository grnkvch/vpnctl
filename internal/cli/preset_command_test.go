package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type presetCatalogStub struct{}

func (presetCatalogStub) List() (routing.PresetListResult, error) {
	return routing.PresetListResult{StateGeneration: 3, Items: []routing.PresetSummary{{Name: "telegram", SourcePresent: true, SourceValid: true, EffectivePresent: true, Assignments: []routing.PresetAssignment{}, Issues: []routing.PresetIssue{}}}, Issues: []routing.PresetIssue{}}, nil
}
func (presetCatalogStub) Show(string) (routing.PresetShowResult, error) {
	return routing.PresetShowResult{StateGeneration: 3, Source: &routing.PresetSourceView{Name: "telegram", Present: true, Valid: true, Selectors: []model.Selector{}}, Assignments: []routing.PresetAssignment{}, Issues: []routing.PresetIssue{}}, nil
}
func (presetCatalogStub) Validate() (routing.PresetValidationResult, error) {
	return routing.PresetValidationResult{StateGeneration: 3, Valid: true, SourceCount: 1, Issues: []routing.PresetIssue{}}, nil
}
func (presetCatalogStub) Diff() (routing.PresetDiffResult, error) {
	return routing.PresetDiffResult{StateGeneration: 3, Valid: true, Changes: []routing.PresetChange{}, Issues: []routing.PresetIssue{}}, nil
}

func TestExecutePresetCatalogCommandsUseStableResultShapes(t *testing.T) {
	oldPaths, oldRole, oldBuild := presetSystemPaths, presetLoadRole, presetBuild
	t.Cleanup(func() { presetSystemPaths, presetLoadRole, presetBuild = oldPaths, oldRole, oldBuild })
	paths, _ := store.NewPaths(t.TempDir())
	presetSystemPaths = func() store.Paths { return paths }
	presetLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	presetBuild = func(store.Paths) (presetCatalogAPI, error) { return presetCatalogStub{}, nil }

	for _, test := range []struct {
		args    []string
		command string
		want    string
	}{
		{[]string{"preset", "list", "--json"}, "preset.list", `"items":[{"assignments":[]`},
		{[]string{"--json", "preset", "show", "telegram"}, "preset.show", `"resource":{"assignments":[]`},
		{[]string{"preset", "validate", "--json"}, "preset.validate", `"valid":true`},
		{[]string{"preset", "diff", "--json"}, "preset.diff", `"changes":[]`},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := Execute(test.args, &stdout, &stderr); code != ExitSuccess {
			t.Fatalf("Execute(%v) code=%d stdout=%q stderr=%q", test.args, code, stdout.String(), stderr.String())
		}
		if got := stdout.String(); !strings.Contains(got, `"command":"`+test.command+`"`) || !strings.Contains(got, test.want) {
			t.Fatalf("Execute(%v) output=%q", test.args, got)
		}
	}
}

func TestPresetValidationFailureUsesValidationExit(t *testing.T) {
	result := presetValidationOutput(routing.PresetValidationResult{
		Valid: false, Issues: []routing.PresetIssue{{Code: "invalid_preset_document", Message: "invalid source"}},
	})
	if result.ExitCategory != "validation" || result.Status != "failed" || len(result.Warnings) != 1 {
		t.Fatalf("invalid preset validation result = %+v", result)
	}
}
