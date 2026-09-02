package routing

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestPresetUpdaterImmediateAppliesReviewedWholeSetGeneration(t *testing.T) {
	t.Parallel()

	base, currentSource, next, currentSelectors, wantSelectors := presetUpdateFixtures()
	_, paths, stateStore := newPresetCatalogFixture(t, map[string][]byte{"telegram.yaml": currentSource}, []model.Preset{
		catalogEffectivePreset("telegram", currentSource, currentSelectors),
	}, true)
	updater := newTestPresetUpdater(t, paths, stateStore, []BuiltinPresetTemplate{next, base})
	stateBytesBefore, err := os.ReadFile(paths.StateFile)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := updater.Plan("TELEGRAM")
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if plan.Name != "telegram" || plan.FromRevision != 1 || plan.ToRevision != 2 ||
		plan.ExpectedStateGeneration != 1 || plan.NextStateGeneration != 2 || !plan.SourceExisted {
		t.Fatalf("Plan() = %#v", plan)
	}
	change := findPresetChange(t, plan.Diff.Changes, "telegram")
	if change.Kind != PresetModified || !change.SourceChanged || !change.SelectorChanged ||
		len(change.Assignments) != 1 || change.Assignments[0].TargetID != catalogClientID {
		t.Fatalf("reviewed change = %#v", change)
	}
	if source, err := os.ReadFile(plan.SourcePath); err != nil || !bytes.Equal(source, currentSource) {
		t.Fatalf("Plan() changed source: %v", err)
	}
	if stateBytes, err := os.ReadFile(paths.StateFile); err != nil || !bytes.Equal(stateBytes, stateBytesBefore) {
		t.Fatal("Plan() changed authoritative state")
	}

	result, err := updater.Apply(plan, PresetUpdateImmediate)
	if err != nil {
		t.Fatalf("Apply(immediate) error = %v", err)
	}
	if result.Mode != PresetUpdateImmediate || !result.SourceChanged || !result.EffectiveChanged || result.StateGeneration != 2 {
		t.Fatalf("Apply(immediate) = %#v", result)
	}
	appliedSource, err := os.ReadFile(plan.SourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if revision, err := builtinPresetRevision(appliedSource, "telegram"); err != nil || revision != 2 {
		t.Fatalf("applied source revision = %d, %v", revision, err)
	}
	if info, err := os.Stat(plan.SourcePath); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("applied source mode = %v, %v", info, err)
	}
	appliedAST, err := DecodePresetDocument(appliedSource)
	if err != nil || !reflect.DeepEqual(appliedAST.Selectors, wantSelectors) {
		t.Fatalf("applied source = %#v, %v", appliedAST, err)
	}
	appliedState, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if appliedState.Generation != 2 || len(appliedState.Presets) != 1 || appliedState.Presets[0].Generation != 2 ||
		appliedState.Presets[0].SourceHash != sourceSHA256(appliedSource) ||
		!reflect.DeepEqual(appliedState.Presets[0].Selectors, wantSelectors) {
		t.Fatalf("applied preset state = %#v", appliedState.Presets)
	}
	if len(appliedState.Policies) != 1 || appliedState.Policies[0].Generation != 2 ||
		!reflect.DeepEqual(appliedState.Policies[0].Selectors, wantSelectors) {
		t.Fatalf("applied policy = %#v", appliedState.Policies)
	}
	assertNoPresetUpdateTemporaries(t, paths.PresetsDir)
}

func TestPresetUpdaterDeferredChangesOnlyUserOwnedSource(t *testing.T) {
	t.Parallel()

	base, currentSource, next, currentSelectors, wantSelectors := presetUpdateFixtures()
	_, paths, stateStore := newPresetCatalogFixture(t, map[string][]byte{"telegram.yaml": currentSource}, []model.Preset{
		catalogEffectivePreset("telegram", currentSource, currentSelectors),
	}, true)
	updater := newTestPresetUpdater(t, paths, stateStore, []BuiltinPresetTemplate{base, next})
	stateBefore, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	stateBytesBefore, err := os.ReadFile(paths.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := updater.Plan("telegram")
	if err != nil {
		t.Fatal(err)
	}

	result, err := updater.Apply(plan, PresetUpdateDeferred)
	if err != nil {
		t.Fatalf("Apply(deferred) error = %v", err)
	}
	if result.Mode != PresetUpdateDeferred || !result.SourceChanged || result.EffectiveChanged || result.StateGeneration != 1 {
		t.Fatalf("Apply(deferred) = %#v", result)
	}
	source, err := os.ReadFile(plan.SourcePath)
	if err != nil {
		t.Fatal(err)
	}
	ast, err := DecodePresetDocument(source)
	if err != nil || !reflect.DeepEqual(ast.Selectors, wantSelectors) {
		t.Fatalf("deferred source = %#v, %v", ast, err)
	}
	assertCatalogStateUnchanged(t, stateStore, paths, stateBefore, stateBytesBefore)
	catalog, err := NewPresetCatalog(paths, stateStore)
	if err != nil {
		t.Fatal(err)
	}
	diff, err := catalog.Diff()
	if err != nil || !diff.Valid || !findPresetChange(t, diff.Changes, "telegram").SelectorChanged {
		t.Fatalf("deferred Diff() = %#v, %v", diff, err)
	}
	assertNoPresetUpdateTemporaries(t, paths.PresetsDir)
}

func TestPresetUpdaterImmediateLeavesUnrelatedValidManualEditPending(t *testing.T) {
	t.Parallel()

	base, currentSource, next, currentSelectors, _ := presetUpdateFixtures()
	openAIEffectiveSource := catalogPresetSource("openai", []model.Selector{{Kind: model.SelectorDomain, Value: "api.openai.com"}})
	openAIPendingSource := catalogPresetSource("openai", []model.Selector{
		{Kind: model.SelectorDomain, Value: "api.openai.com"},
		{Kind: model.SelectorDomainSuffix, Value: "chatgpt.com"},
	})
	openAIEffective := catalogEffectivePreset("openai", openAIEffectiveSource, []model.Selector{{Kind: model.SelectorDomain, Value: "api.openai.com"}})
	_, paths, stateStore := newPresetCatalogFixture(t, map[string][]byte{
		"telegram.yaml": currentSource,
		"openai.yaml":   openAIPendingSource,
	}, []model.Preset{
		catalogEffectivePreset("telegram", currentSource, currentSelectors),
		openAIEffective,
	}, false)
	updater := newTestPresetUpdater(t, paths, stateStore, []BuiltinPresetTemplate{base, next})
	plan, err := updater.Plan("telegram")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Diff.Changes) != 1 || plan.Diff.Changes[0].Name != "telegram" {
		t.Fatalf("targeted update plan included unrelated pending edit: %#v", plan.Diff.Changes)
	}
	if _, err := updater.Apply(plan, PresetUpdateImmediate); err != nil {
		t.Fatal(err)
	}
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	var gotOpenAI model.Preset
	for _, preset := range state.Presets {
		if preset.Name == "openai" {
			gotOpenAI = preset
		}
	}
	if !reflect.DeepEqual(gotOpenAI, openAIEffective) {
		t.Fatalf("unrelated effective preset changed\nwant: %#v\n got: %#v", openAIEffective, gotOpenAI)
	}
	catalog, err := NewPresetCatalog(paths, stateStore)
	if err != nil {
		t.Fatal(err)
	}
	diff, err := catalog.Diff()
	if err != nil {
		t.Fatal(err)
	}
	openAIChange := findPresetChange(t, diff.Changes, "openai")
	if openAIChange.Kind != PresetModified || !openAIChange.SelectorChanged {
		t.Fatalf("unrelated source no longer pending: %#v", openAIChange)
	}
}

func TestPresetUpdaterRollsSourceBackWhenStateCommitFailsBeforeActivation(t *testing.T) {
	t.Parallel()

	base, currentSource, next, currentSelectors, _ := presetUpdateFixtures()
	_, paths, stateStore := newPresetCatalogFixture(t, map[string][]byte{"telegram.yaml": currentSource}, []model.Preset{
		catalogEffectivePreset("telegram", currentSource, currentSelectors),
	}, true)
	injected := errors.New("injected state write failure")
	failing := &presetUpdateFailingState{delegate: stateStore, err: injected}
	updater := newTestPresetUpdater(t, paths, failing, []BuiltinPresetTemplate{base, next})
	stateBefore, _ := stateStore.Load()
	stateBytesBefore, _ := os.ReadFile(paths.StateFile)
	plan, err := updater.Plan("telegram")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := updater.Apply(plan, PresetUpdateImmediate); !errors.Is(err, injected) {
		t.Fatalf("Apply() error = %v, want injected failure", err)
	}
	source, err := os.ReadFile(plan.SourcePath)
	if err != nil || !bytes.Equal(source, currentSource) {
		t.Fatalf("source rollback = %q, %v", source, err)
	}
	assertCatalogStateUnchanged(t, stateStore, paths, stateBefore, stateBytesBefore)
	assertNoPresetUpdateTemporaries(t, paths.PresetsDir)
}

func TestPresetUpdaterDoesNotRollBackSourceAfterCommittedButUncertainStateWrite(t *testing.T) {
	t.Parallel()

	base, currentSource, next, currentSelectors, wantSelectors := presetUpdateFixtures()
	_, paths, stateStore := newPresetCatalogFixture(t, map[string][]byte{"telegram.yaml": currentSource}, []model.Preset{
		catalogEffectivePreset("telegram", currentSource, currentSelectors),
	}, true)
	uncertain := &presetUpdateCommittedErrorState{delegate: stateStore, err: errors.New("directory fsync failed")}
	updater := newTestPresetUpdater(t, paths, uncertain, []BuiltinPresetTemplate{base, next})
	plan, err := updater.Plan("telegram")
	if err != nil {
		t.Fatal(err)
	}

	result, err := updater.Apply(plan, PresetUpdateImmediate)
	if !errors.Is(err, ErrPresetUpdateCommitUncertain) || !result.EffectiveChanged || result.StateGeneration != 2 {
		t.Fatalf("Apply() = %#v, %v, want committed uncertain result", result, err)
	}
	source, readErr := os.ReadFile(plan.SourcePath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	ast, decodeErr := DecodePresetDocument(source)
	if decodeErr != nil || !reflect.DeepEqual(ast.Selectors, wantSelectors) {
		t.Fatalf("committed source = %#v, %v", ast, decodeErr)
	}
	state, loadErr := stateStore.Load()
	if loadErr != nil || state.Generation != 2 || !reflect.DeepEqual(state.Presets[0].Selectors, wantSelectors) {
		t.Fatalf("committed state = %#v, %v", state, loadErr)
	}
}

func TestPresetUpdaterRemovesExplicitRestoreWhenStateCommitFails(t *testing.T) {
	t.Parallel()

	base := testBuiltinPresetTemplate("telegram", 1, []model.Selector{{Kind: model.SelectorDomain, Value: "one.example.com"}})
	next := testBuiltinPresetTemplate("telegram", 2, []model.Selector{{Kind: model.SelectorDomain, Value: "two.example.com"}})
	_, paths, stateStore := newPresetCatalogFixture(t, nil, []model.Preset{
		catalogEffectivePreset("telegram", base.Source, baseSelectors(t, base)),
	}, false)
	failing := &presetUpdateFailingState{delegate: stateStore, err: errors.New("injected restore state failure")}
	updater := newTestPresetUpdater(t, paths, failing, []BuiltinPresetTemplate{base, next})
	stateBefore, _ := stateStore.Load()
	stateBytesBefore, _ := os.ReadFile(paths.StateFile)
	plan, err := updater.Plan("telegram")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := updater.Apply(plan, PresetUpdateImmediate); err == nil {
		t.Fatal("Apply() error = nil")
	}
	if _, err := os.Lstat(plan.SourcePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restored source remains after failed commit: %v", err)
	}
	assertCatalogStateUnchanged(t, stateStore, paths, stateBefore, stateBytesBefore)
	assertNoPresetUpdateTemporaries(t, paths.PresetsDir)
}

func TestPresetUpdaterConflictAndStaleReviewNeverOverwriteSourceOrState(t *testing.T) {
	t.Parallel()

	base := testBuiltinPresetTemplate("telegram", 1, []model.Selector{{Kind: model.SelectorDomain, Value: "conflict.example.com"}})
	conflictingSelectors := canonicalPresetSelectors([]model.Selector{
		{Kind: model.SelectorDomain, Value: "conflict.example.com"},
		{Kind: model.SelectorDomain, Value: "conflict.example.com", Exclude: true},
	})
	conflictingSource := renderBuiltinPresetSource(PresetAST{SchemaVersion: PresetDocumentSchemaVersion, Name: "telegram", Selectors: conflictingSelectors}, 1)
	next := testBuiltinPresetTemplate("telegram", 2, []model.Selector{{Kind: model.SelectorDomain, Value: "replacement.example.com"}})
	_, paths, stateStore := newPresetCatalogFixture(t, map[string][]byte{"telegram.yaml": conflictingSource}, []model.Preset{
		catalogEffectivePreset("telegram", conflictingSource, conflictingSelectors),
	}, false)
	updater := newTestPresetUpdater(t, paths, stateStore, []BuiltinPresetTemplate{base, next})
	stateBefore, _ := stateStore.Load()
	stateBytesBefore, _ := os.ReadFile(paths.StateFile)

	if _, err := updater.Plan("telegram"); !errors.Is(err, ErrBuiltinPresetTemplateConflict) {
		t.Fatalf("Plan(conflict) error = %v", err)
	}
	source, _ := os.ReadFile(filepath.Join(paths.PresetsDir, "telegram.yaml"))
	if !bytes.Equal(source, conflictingSource) {
		t.Fatal("conflicting plan changed source")
	}
	assertCatalogStateUnchanged(t, stateStore, paths, stateBefore, stateBytesBefore)

	safeCurrent := base.Source
	_, stalePaths, staleStateStore := newPresetCatalogFixture(t, map[string][]byte{"telegram.yaml": safeCurrent}, []model.Preset{
		catalogEffectivePreset("telegram", safeCurrent, baseSelectors(t, base)),
	}, false)
	staleUpdater := newTestPresetUpdater(t, stalePaths, staleStateStore, []BuiltinPresetTemplate{base, next})
	plan, err := staleUpdater.Plan("telegram")
	if err != nil {
		t.Fatal(err)
	}
	staleSource := append([]byte("# operator changed after review\n"), safeCurrent...)
	writeCatalogPreset(t, stalePaths, "telegram.yaml", staleSource)
	if _, err := staleUpdater.Apply(plan, PresetUpdateDeferred); !errors.Is(err, ErrPresetUpdateStale) {
		t.Fatalf("Apply(stale) error = %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(stalePaths.PresetsDir, "telegram.yaml"))
	if !bytes.Equal(got, staleSource) {
		t.Fatal("stale apply overwrote operator edit")
	}
}

func TestPresetUpdaterExplicitlyRestoresDeletedBuiltinAndRejectsUnrelatedInvalidSet(t *testing.T) {
	t.Parallel()

	base := testBuiltinPresetTemplate("telegram", 1, []model.Selector{{Kind: model.SelectorDomain, Value: "one.example.com"}})
	next := testBuiltinPresetTemplate("telegram", 2, []model.Selector{{Kind: model.SelectorDomain, Value: "two.example.com"}})
	oldSource := base.Source
	_, paths, stateStore := newPresetCatalogFixture(t, nil, []model.Preset{
		catalogEffectivePreset("telegram", oldSource, baseSelectors(t, base)),
	}, false)
	updater := newTestPresetUpdater(t, paths, stateStore, []BuiltinPresetTemplate{base, next})
	stateBefore, _ := stateStore.Load()
	stateBytesBefore, _ := os.ReadFile(paths.StateFile)

	plan, err := updater.Plan("telegram")
	if err != nil {
		t.Fatalf("Plan(restore) error = %v", err)
	}
	if plan.SourceExisted || plan.FromRevision != 0 || plan.ToRevision != 2 {
		t.Fatalf("restore plan = %#v", plan)
	}
	if _, err := updater.Apply(plan, PresetUpdateDeferred); err != nil {
		t.Fatalf("Apply(restore deferred) error = %v", err)
	}
	restored, err := os.ReadFile(filepath.Join(paths.PresetsDir, "telegram.yaml"))
	if err != nil || !bytes.Equal(restored, next.Source) {
		t.Fatalf("restored source = %q, %v", restored, err)
	}
	assertCatalogStateUnchanged(t, stateStore, paths, stateBefore, stateBytesBefore)

	writeCatalogPreset(t, paths, "telegram.yaml", base.Source)
	writeCatalogPreset(t, paths, "openai.yaml", []byte("schema_version: 1\nname: openai\ninclude:\n  - type: unknown\n    value: example.com\nexclude: []\n"))
	invalidPlanState, _ := stateStore.Load()
	invalidStateBytes, _ := os.ReadFile(paths.StateFile)
	if _, err := updater.Plan("telegram"); !errors.Is(err, ErrPresetUpdateInvalidCandidate) {
		t.Fatalf("Plan(invalid whole set) error = %v", err)
	}
	source, _ := os.ReadFile(filepath.Join(paths.PresetsDir, "telegram.yaml"))
	if !bytes.Equal(source, base.Source) {
		t.Fatal("invalid whole-set plan changed target source")
	}
	assertCatalogStateUnchanged(t, stateStore, paths, invalidPlanState, invalidStateBytes)
}

func TestPresetCatalogReportsAvailableBuiltinUpdateAndExplicitRestore(t *testing.T) {
	t.Parallel()

	base := testBuiltinPresetTemplate("telegram", 1, []model.Selector{{Kind: model.SelectorDomain, Value: "one.example.com"}})
	next := testBuiltinPresetTemplate("telegram", 2, []model.Selector{{Kind: model.SelectorDomain, Value: "two.example.com"}})
	_, paths, stateStore := newPresetCatalogFixture(t, map[string][]byte{"telegram.yaml": base.Source}, []model.Preset{
		catalogEffectivePreset("telegram", base.Source, baseSelectors(t, base)),
	}, false)
	updates, err := NewBuiltinPresetUpdateCatalog([]BuiltinPresetTemplate{base, next})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewPresetCatalogWithUpdates(paths, stateStore, updates)
	if err != nil {
		t.Fatal(err)
	}
	list, err := catalog.List()
	if err != nil {
		t.Fatal(err)
	}
	summary := findPresetSummary(t, list.Items, "telegram")
	if !summary.Builtin || summary.BuiltinRevision != 1 || summary.AvailableBuiltinRevision != 2 {
		t.Fatalf("built-in list summary = %#v", summary)
	}
	shown, err := catalog.Show("telegram")
	if err != nil || shown.BuiltinUpdate == nil || shown.BuiltinUpdate.SourceRevision != 1 || shown.BuiltinUpdate.AvailableRevision != 2 {
		t.Fatalf("built-in show = %#v, %v", shown, err)
	}

	if err := os.Remove(filepath.Join(paths.PresetsDir, "telegram.yaml")); err != nil {
		t.Fatal(err)
	}
	list, err = catalog.List()
	if err != nil {
		t.Fatal(err)
	}
	summary = findPresetSummary(t, list.Items, "telegram")
	if !summary.Builtin || summary.BuiltinRevision != 0 || summary.AvailableBuiltinRevision != 2 {
		t.Fatalf("deleted built-in list summary = %#v", summary)
	}
}

func presetUpdateFixtures() (BuiltinPresetTemplate, []byte, BuiltinPresetTemplate, []model.Selector, []model.Selector) {
	baseSelectors := canonicalPresetSelectors([]model.Selector{
		{Kind: model.SelectorDomain, Value: "api.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "old.example.com"},
	})
	base := testBuiltinPresetTemplate("telegram", 1, baseSelectors)
	currentSelectors := canonicalPresetSelectors([]model.Selector{
		{Kind: model.SelectorDomain, Value: "api.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "old.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "user.example.com"},
		{Kind: model.SelectorDomain, Value: "private.example.com", Exclude: true},
	})
	currentSource := renderBuiltinPresetSource(PresetAST{SchemaVersion: PresetDocumentSchemaVersion, Name: "telegram", Selectors: currentSelectors}, 1)
	next := testBuiltinPresetTemplate("telegram", 2, []model.Selector{
		{Kind: model.SelectorDomain, Value: "api.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "new.example.com"},
	})
	want := canonicalPresetSelectors([]model.Selector{
		{Kind: model.SelectorDomain, Value: "api.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "new.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "user.example.com"},
		{Kind: model.SelectorDomain, Value: "private.example.com", Exclude: true},
	})
	return base, currentSource, next, currentSelectors, want
}

func newTestPresetUpdater(t *testing.T, paths store.Paths, state PresetUpdateStateStore, templates []BuiltinPresetTemplate) *PresetUpdater {
	t.Helper()
	catalog, err := NewBuiltinPresetUpdateCatalog(templates)
	if err != nil {
		t.Fatal(err)
	}
	updater, err := NewPresetUpdater(paths, state, catalog, func() time.Time {
		return time.Date(2026, time.September, 2, 15, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	return updater
}

func baseSelectors(t *testing.T, template BuiltinPresetTemplate) []model.Selector {
	t.Helper()
	ast, err := DecodePresetDocument(template.Source)
	if err != nil {
		t.Fatal(err)
	}
	return ast.Selectors
}

func assertNoPresetUpdateTemporaries(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".preset-update-") {
			t.Fatalf("preset update temporary remains: %s", entry.Name())
		}
	}
}

type presetUpdateFailingState struct {
	delegate *store.StateStore
	err      error
}

func (state *presetUpdateFailingState) Load() (model.State, error) {
	return state.delegate.Load()
}

func (state *presetUpdateFailingState) Save(uint64, model.State) error {
	return state.err
}

type presetUpdateCommittedErrorState struct {
	delegate *store.StateStore
	err      error
}

func (state *presetUpdateCommittedErrorState) Load() (model.State, error) {
	return state.delegate.Load()
}

func (state *presetUpdateCommittedErrorState) Save(expected uint64, candidate model.State) error {
	if err := state.delegate.Save(expected, candidate); err != nil {
		return err
	}
	return state.err
}
