package routing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	ErrPresetUpdateInvalidCandidate = errors.New("preset update candidate is invalid")
	ErrPresetUpdateStale            = errors.New("preset update plan is stale")
	ErrPresetUpdateCommitUncertain  = errors.New("preset update commit outcome is uncertain")
)

type PresetUpdateStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

type PresetTemplateUpdateSource interface {
	Update(name string, fromRevision uint64) (BuiltinPresetTemplateUpdate, error)
	Latest(name string) (BuiltinPresetTemplate, error)
}

type PresetUpdateCandidateError struct {
	Issues []PresetIssue
}

func (candidate *PresetUpdateCandidateError) Error() string {
	if candidate == nil || len(candidate.Issues) == 0 {
		return ErrPresetUpdateInvalidCandidate.Error()
	}
	return fmt.Sprintf("%s: %s", ErrPresetUpdateInvalidCandidate, candidate.Issues[0].Message)
}

func (candidate *PresetUpdateCandidateError) Unwrap() error {
	return ErrPresetUpdateInvalidCandidate
}

type PresetUpdatePlan struct {
	Name                    string
	FromRevision            uint64
	ToRevision              uint64
	ExpectedStateGeneration uint64
	NextStateGeneration     uint64
	SourcePath              string
	SourceExisted           bool
	CurrentSourceHash       string
	MergedSourceHash        string
	Diff                    PresetDiffResult

	beforeSetHash    string
	candidateSetHash string
	sourceBefore     []byte
	sourceAfter      []byte
}

type PresetUpdateMode string

const (
	PresetUpdateImmediate PresetUpdateMode = "immediate"
	PresetUpdateDeferred  PresetUpdateMode = "deferred"
)

type PresetUpdateResult struct {
	Name             string
	Mode             PresetUpdateMode
	FromRevision     uint64
	ToRevision       uint64
	SourceChanged    bool
	EffectiveChanged bool
	StateGeneration  uint64
	Diff             PresetDiffResult
}

type PresetUpdater struct {
	paths   store.Paths
	state   PresetUpdateStateStore
	updates PresetTemplateUpdateSource
	now     func() time.Time
}

func NewPresetUpdater(paths store.Paths, state PresetUpdateStateStore, updates PresetTemplateUpdateSource, now func() time.Time) (*PresetUpdater, error) {
	if state == nil || updates == nil {
		return nil, fmt.Errorf("preset updater requires state and built-in template dependencies")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths {
		return nil, fmt.Errorf("preset updater paths do not match the system root")
	}
	if now == nil {
		now = time.Now
	}
	return &PresetUpdater{paths: paths, state: state, updates: updates, now: now}, nil
}

// Plan is read-only. The returned source and whole-set diff are the exact
// candidate that Apply will require before either deferred or immediate mode.
func (updater *PresetUpdater) Plan(name string) (PresetUpdatePlan, error) {
	if updater == nil {
		return PresetUpdatePlan{}, fmt.Errorf("preset updater is required")
	}
	if err := validatePresetName(name); err != nil {
		return PresetUpdatePlan{}, err
	}
	state, err := updater.loadGatewayState()
	if err != nil {
		return PresetUpdatePlan{}, err
	}
	sources, setIssues, err := inspectPresetSources(updater.paths.PresetsDir)
	if err != nil {
		return PresetUpdatePlan{}, err
	}
	beforeSetHash := presetSourceSetHash(sources, setIssues)
	key := strings.ToLower(name)
	matching := presetSourcesByKey(sources, key)
	if len(matching) > 1 {
		return PresetUpdatePlan{}, &BuiltinPresetTemplateConflictError{Name: name, Reason: "multiple source files match the built-in preset name", Matchers: []string{}}
	}

	var merge BuiltinPresetTemplateMerge
	var sourceBefore []byte
	sourceExisted := len(matching) == 1
	if sourceExisted {
		current := sources[matching[0]]
		if !current.view.Valid {
			return PresetUpdatePlan{}, &BuiltinPresetTemplateConflictError{Name: name, Reason: "current user source is invalid", Matchers: []string{}}
		}
		sourceBefore, err = readPresetSourceFile(current.view.Path)
		if err != nil || sourceSHA256(sourceBefore) != current.view.SHA256 {
			return PresetUpdatePlan{}, fmt.Errorf("%w: preset source changed during planning", ErrPresetUpdateStale)
		}
		revision, revisionErr := builtinPresetRevision(sourceBefore, current.view.Name)
		if revisionErr != nil {
			return PresetUpdatePlan{}, &BuiltinPresetTemplateConflictError{Name: name, Reason: revisionErr.Error(), Matchers: []string{}}
		}
		update, updateErr := updater.updates.Update(current.view.Name, revision)
		if updateErr != nil {
			return PresetUpdatePlan{}, updateErr
		}
		merge, err = MergeBuiltinPresetTemplate(update, sourceBefore)
		if err != nil {
			return PresetUpdatePlan{}, err
		}
	} else {
		latest, latestErr := updater.updates.Latest(name)
		if latestErr != nil {
			return PresetUpdatePlan{}, latestErr
		}
		merge, err = mergeForExplicitRestore(latest)
		if err != nil {
			return PresetUpdatePlan{}, err
		}
	}

	candidateSources := replacePresetSource(sources, inspectPresetSourceData(updater.paths.PresetsDir, merge.Name+".yaml", merge.Source))
	candidateInspection := analyzePresetSources(state, candidateSources, setIssues)
	if len(candidateInspection.issues) != 0 {
		return PresetUpdatePlan{}, &PresetUpdateCandidateError{Issues: clonePresetIssues(candidateInspection.issues)}
	}
	diff := filterPresetDiff(diffPresetInspection(candidateInspection), merge.Name)
	nextGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return PresetUpdatePlan{}, fmt.Errorf("plan preset update state generation: %w", err)
	}
	return PresetUpdatePlan{
		Name: merge.Name, FromRevision: merge.FromRevision, ToRevision: merge.ToRevision,
		ExpectedStateGeneration: state.Generation, NextStateGeneration: nextGeneration,
		SourcePath: filepath.Join(updater.paths.PresetsDir, merge.Name+".yaml"), SourceExisted: sourceExisted,
		CurrentSourceHash: merge.CurrentHash, MergedSourceHash: merge.MergedHash, Diff: clonePresetDiff(diff),
		beforeSetHash: beforeSetHash, candidateSetHash: presetSourceSetHash(candidateSources, setIssues),
		sourceBefore: append([]byte(nil), sourceBefore...), sourceAfter: append([]byte(nil), merge.Source...),
	}, nil
}

func (updater *PresetUpdater) Apply(plan PresetUpdatePlan, mode PresetUpdateMode) (PresetUpdateResult, error) {
	if updater == nil {
		return PresetUpdateResult{}, fmt.Errorf("preset updater is required")
	}
	if mode != PresetUpdateImmediate && mode != PresetUpdateDeferred {
		return PresetUpdateResult{}, fmt.Errorf("unsupported preset update mode %q", mode)
	}
	if err := updater.validatePlan(plan); err != nil {
		return PresetUpdateResult{}, err
	}
	state, err := updater.loadGatewayState()
	if err != nil {
		return PresetUpdateResult{}, err
	}
	if state.Generation != plan.ExpectedStateGeneration {
		return PresetUpdateResult{}, fmt.Errorf("%w: expected state generation %d, current %d", ErrPresetUpdateStale, plan.ExpectedStateGeneration, state.Generation)
	}
	sources, setIssues, err := inspectPresetSources(updater.paths.PresetsDir)
	if err != nil {
		return PresetUpdateResult{}, err
	}
	if presetSourceSetHash(sources, setIssues) != plan.beforeSetHash {
		return PresetUpdateResult{}, fmt.Errorf("%w: preset source set changed after review", ErrPresetUpdateStale)
	}
	candidateSources := replacePresetSource(sources, inspectPresetSourceData(updater.paths.PresetsDir, plan.Name+".yaml", plan.sourceAfter))
	if presetSourceSetHash(candidateSources, setIssues) != plan.candidateSetHash {
		return PresetUpdateResult{}, fmt.Errorf("%w: reviewed candidate no longer matches source set", ErrPresetUpdateStale)
	}
	candidateInspection := analyzePresetSources(state, candidateSources, setIssues)
	if len(candidateInspection.issues) != 0 {
		return PresetUpdateResult{}, &PresetUpdateCandidateError{Issues: clonePresetIssues(candidateInspection.issues)}
	}
	diff := filterPresetDiff(diffPresetInspection(candidateInspection), plan.Name)
	var candidateState model.State
	if mode == PresetUpdateImmediate {
		candidateState, err = buildAppliedPresetState(state, candidateSources, plan.Name, updater.now().UTC())
		if err != nil {
			return PresetUpdateResult{}, err
		}
	}
	stagedPath, err := stagePresetSource(updater.paths.PresetsDir, plan.sourceAfter)
	if err != nil {
		return PresetUpdateResult{}, err
	}
	defer os.Remove(stagedPath)
	latestSources, latestSetIssues, err := inspectPresetSources(updater.paths.PresetsDir)
	if err != nil {
		return PresetUpdateResult{}, err
	}
	if presetSourceSetHash(latestSources, latestSetIssues) != plan.beforeSetHash {
		return PresetUpdateResult{}, fmt.Errorf("%w: preset source set changed while staging", ErrPresetUpdateStale)
	}
	if err := verifyPresetSource(updater.paths.PresetsDir, plan.Name+".yaml", plan.SourceExisted, plan.sourceBefore); err != nil {
		return PresetUpdateResult{}, err
	}
	result := PresetUpdateResult{
		Name: plan.Name, Mode: mode, FromRevision: plan.FromRevision, ToRevision: plan.ToRevision,
		SourceChanged: true, StateGeneration: state.Generation, Diff: clonePresetDiff(diff),
	}
	if err := activatePresetSource(updater.paths.PresetsDir, stagedPath, plan.Name+".yaml"); err != nil {
		activeSource, readErr := readPresetSourceFile(plan.SourcePath)
		if readErr == nil && bytes.Equal(activeSource, plan.sourceAfter) {
			return result, fmt.Errorf("%w: source is active but durability confirmation failed: %v", ErrPresetUpdateCommitUncertain, err)
		}
		return PresetUpdateResult{}, err
	}
	if mode == PresetUpdateDeferred {
		return result, nil
	}
	if err := updater.state.Save(state.Generation, candidateState); err != nil {
		loaded, loadErr := updater.state.Load()
		if loadErr == nil && reflect.DeepEqual(loaded, candidateState) {
			result.EffectiveChanged = true
			result.StateGeneration = candidateState.Generation
			return result, fmt.Errorf("%w: state is active but durability confirmation failed: %v", ErrPresetUpdateCommitUncertain, err)
		}
		if loadErr != nil || loaded.Generation != state.Generation || !reflect.DeepEqual(loaded, state) {
			return result, fmt.Errorf("%w: cannot prove authoritative generation after write failure: %v", ErrPresetUpdateCommitUncertain, err)
		}
		rollbackErr := rollbackPresetSource(updater.paths.PresetsDir, plan.Name+".yaml", plan.SourceExisted, plan.sourceBefore, plan.sourceAfter)
		return PresetUpdateResult{}, joinPresetUpdateRollbackError(err, rollbackErr)
	}
	result.EffectiveChanged = true
	result.StateGeneration = candidateState.Generation
	return result, nil
}

func (updater *PresetUpdater) loadGatewayState() (model.State, error) {
	state, err := updater.state.Load()
	if err != nil {
		return model.State{}, fmt.Errorf("load authoritative preset state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return model.State{}, fmt.Errorf("validate authoritative preset state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return model.State{}, fmt.Errorf("preset update requires gateway state")
	}
	return state, nil
}

func (updater *PresetUpdater) validatePlan(plan PresetUpdatePlan) error {
	if err := validatePresetName(plan.Name); err != nil {
		return err
	}
	if plan.ToRevision == 0 || plan.ToRevision <= plan.FromRevision || plan.ExpectedStateGeneration == 0 ||
		plan.NextStateGeneration != plan.ExpectedStateGeneration+1 || len(plan.sourceAfter) == 0 ||
		plan.SourcePath != filepath.Join(updater.paths.PresetsDir, plan.Name+".yaml") || sourceSHA256(plan.sourceAfter) != plan.MergedSourceHash {
		return fmt.Errorf("preset update plan is invalid")
	}
	if plan.SourceExisted {
		if len(plan.sourceBefore) == 0 || sourceSHA256(plan.sourceBefore) != plan.CurrentSourceHash {
			return fmt.Errorf("preset update plan source precondition is invalid")
		}
	} else if len(plan.sourceBefore) != 0 || plan.CurrentSourceHash != "" || plan.FromRevision != 0 {
		return fmt.Errorf("preset restore plan source precondition is invalid")
	}
	return nil
}

func mergeForExplicitRestore(latest BuiltinPresetTemplate) (BuiltinPresetTemplateMerge, error) {
	latest, err := validateBuiltinPresetTemplate(latest)
	if err != nil {
		return BuiltinPresetTemplateMerge{}, fmt.Errorf("validate restored built-in preset template: %w", err)
	}
	digest := sha256.Sum256(latest.Source)
	ast, err := DecodePresetDocument(latest.Source)
	if err != nil {
		return BuiltinPresetTemplateMerge{}, err
	}
	return BuiltinPresetTemplateMerge{
		Name: latest.Name, ToRevision: latest.Revision, MergedHash: hex.EncodeToString(digest[:]),
		CurrentSelectors: []model.Selector{}, MergedSelectors: append([]model.Selector(nil), ast.Selectors...),
		AddedSelectors: append([]model.Selector(nil), ast.Selectors...), RemovedSelectors: []model.Selector{}, Source: append([]byte(nil), latest.Source...),
	}, nil
}

func presetSourcesByKey(sources []inspectedPresetSource, key string) []int {
	result := make([]int, 0, 1)
	for index := range sources {
		if sources[index].key == key {
			result = append(result, index)
		}
	}
	return result
}

func replacePresetSource(sources []inspectedPresetSource, replacement inspectedPresetSource) []inspectedPresetSource {
	result := make([]inspectedPresetSource, 0, len(sources)+1)
	for _, source := range sources {
		if source.key != replacement.key {
			result = append(result, cloneInspectedPresetSource(source))
		}
	}
	result = append(result, cloneInspectedPresetSource(replacement))
	sort.Slice(result, func(left, right int) bool { return result[left].view.Filename < result[right].view.Filename })
	return result
}

func cloneInspectedPresetSource(source inspectedPresetSource) inspectedPresetSource {
	source.view = clonePresetSourceView(source.view)
	source.ast.Selectors = append([]model.Selector(nil), source.ast.Selectors...)
	return source
}

func presetSourceSetHash(sources []inspectedPresetSource, setIssues []PresetIssue) string {
	hash := sha256.New()
	ordered := make([]inspectedPresetSource, len(sources))
	for index := range sources {
		ordered[index] = cloneInspectedPresetSource(sources[index])
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].view.Filename < ordered[right].view.Filename })
	for _, source := range ordered {
		writePresetHashField(hash, source.key)
		writePresetHashField(hash, source.view.Filename)
		writePresetHashField(hash, source.view.SHA256)
		writePresetHashField(hash, strconv.FormatBool(source.view.Valid))
		for _, issue := range source.view.Issues {
			writePresetHashField(hash, issue.Code)
			writePresetHashField(hash, issue.Name)
			writePresetHashField(hash, issue.Filename)
			writePresetHashField(hash, issue.Message)
		}
	}
	issues := clonePresetIssues(setIssues)
	sortPresetIssues(issues)
	for _, issue := range issues {
		writePresetHashField(hash, issue.Code)
		writePresetHashField(hash, issue.Name)
		writePresetHashField(hash, issue.Filename)
		writePresetHashField(hash, issue.Message)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func buildAppliedPresetState(before model.State, sources []inspectedPresetSource, targetName string, appliedAt time.Time) (model.State, error) {
	if appliedAt.IsZero() {
		return model.State{}, fmt.Errorf("preset apply time is required")
	}
	if err := validatePresetName(targetName); err != nil {
		return model.State{}, err
	}
	after := before
	nextStateGeneration, err := model.NextGeneration(before.Generation)
	if err != nil {
		return model.State{}, err
	}
	after.Generation = nextStateGeneration
	targetKey := strings.ToLower(targetName)
	var targetSource *inspectedPresetSource
	for index := range sources {
		if sources[index].key == targetKey {
			if targetSource != nil {
				return model.State{}, fmt.Errorf("preset update target source is ambiguous")
			}
			targetSource = &sources[index]
		}
	}
	if targetSource == nil || !targetSource.view.Valid {
		return model.State{}, fmt.Errorf("preset update target source is missing or invalid")
	}
	previous := make(map[string]model.Preset, len(before.Presets))
	for _, preset := range before.Presets {
		previous[strings.ToLower(preset.Name)] = preset
	}
	targetPreset := model.Preset{
		SchemaVersion: model.ResourceSchemaVersion, Name: targetSource.ast.Name, SourceHash: targetSource.view.SHA256,
		EffectiveHash: effectivePresetHash(targetSource.ast), Selectors: append([]model.Selector(nil), targetSource.ast.Selectors...), AppliedAt: appliedAt,
	}
	if old, found := previous[targetKey]; found {
		if old.SourceHash == targetPreset.SourceHash && old.EffectiveHash == targetPreset.EffectiveHash && presetSelectorsEqual(old.Selectors, targetPreset.Selectors) {
			targetPreset.Generation = old.Generation
			targetPreset.AppliedAt = old.AppliedAt
		} else {
			targetPreset.Generation, err = model.NextGeneration(old.Generation)
			if err != nil {
				return model.State{}, fmt.Errorf("advance preset %s generation: %w", targetPreset.Name, err)
			}
		}
	} else {
		targetPreset.Generation = 1
	}
	after.Presets = make([]model.Preset, 0, len(before.Presets)+1)
	replaced := false
	for _, preset := range before.Presets {
		if strings.EqualFold(preset.Name, targetName) {
			after.Presets = append(after.Presets, targetPreset)
			replaced = true
		} else {
			preset.Selectors = append([]model.Selector(nil), preset.Selectors...)
			after.Presets = append(after.Presets, preset)
		}
	}
	if !replaced {
		after.Presets = append(after.Presets, targetPreset)
	}
	sort.Slice(after.Presets, func(left, right int) bool { return presetNameLess(after.Presets[left].Name, after.Presets[right].Name) })
	presetMap := make(map[string]model.Preset, len(after.Presets))
	for _, preset := range after.Presets {
		presetMap[strings.ToLower(preset.Name)] = preset
	}
	after.Policies = make([]model.Policy, len(before.Policies))
	for index, old := range before.Policies {
		policy := old
		if !containsPresetName(old.PresetNames, targetName) {
			policy.PresetNames = append([]string(nil), old.PresetNames...)
			policy.Selectors = append([]model.Selector(nil), old.Selectors...)
			after.Policies[index] = policy
			continue
		}
		selectors, effectiveHash, err := effectivePolicy(old.PresetNames, presetMap)
		if err != nil {
			return model.State{}, err
		}
		if old.EffectiveHash != effectiveHash || !presetSelectorsEqual(old.Selectors, selectors) {
			policy.Generation, err = model.NextGeneration(old.Generation)
			if err != nil {
				return model.State{}, fmt.Errorf("advance policy generation: %w", err)
			}
			policy.Selectors = selectors
			policy.EffectiveHash = effectiveHash
		} else {
			policy.Selectors = append([]model.Selector(nil), old.Selectors...)
		}
		after.Policies[index] = policy
	}
	if err := model.ValidateTransition(before, after); err != nil {
		return model.State{}, fmt.Errorf("validate applied preset state: %w", err)
	}
	return after, nil
}

func containsPresetName(names []string, want string) bool {
	for _, name := range names {
		if strings.EqualFold(name, want) {
			return true
		}
	}
	return false
}

func effectivePresetHash(ast PresetAST) string {
	hash := sha256.New()
	writePresetHashField(hash, ast.Name)
	for _, selector := range canonicalPresetSelectors(ast.Selectors) {
		writePresetHashField(hash, string(selector.Kind))
		writePresetHashField(hash, selector.Value)
		writePresetHashField(hash, strconv.FormatBool(selector.Exclude))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func effectivePolicy(names []string, presets map[string]model.Preset) ([]model.Selector, string, error) {
	orderedNames := append([]string(nil), names...)
	sort.Slice(orderedNames, func(left, right int) bool { return presetNameLess(orderedNames[left], orderedNames[right]) })
	hash := sha256.New()
	selectorSet := make(map[string]model.Selector)
	for _, name := range orderedNames {
		preset, found := presets[strings.ToLower(name)]
		if !found {
			return nil, "", fmt.Errorf("policy references missing preset %s", name)
		}
		writePresetHashField(hash, strings.ToLower(preset.Name))
		writePresetHashField(hash, preset.EffectiveHash)
		for _, selector := range preset.Selectors {
			selectorSet[presetSelectorKey(selector)] = selector
		}
	}
	selectors := make([]model.Selector, 0, len(selectorSet))
	for _, selector := range selectorSet {
		selectors = append(selectors, selector)
	}
	sort.Slice(selectors, func(left, right int) bool { return presetSelectorLess(selectors[left], selectors[right]) })
	return selectors, hex.EncodeToString(hash.Sum(nil)), nil
}

func writePresetHashField(hash interface{ Write([]byte) (int, error) }, value string) {
	_, _ = hash.Write([]byte(strconv.Itoa(len(value))))
	_, _ = hash.Write([]byte{':'})
	_, _ = hash.Write([]byte(value))
}

func stagePresetSource(directoryPath string, source []byte) (string, error) {
	if err := validatePresetSourceDirectory(directoryPath); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(directoryPath, ".preset-update-*.yaml.tmp")
	if err != nil {
		return "", fmt.Errorf("create preset source candidate: %w", err)
	}
	path := file.Name()
	closed := false
	keep := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o644); err != nil {
		return "", fmt.Errorf("set preset source candidate mode: %w", err)
	}
	if _, err := file.Write(source); err != nil {
		return "", fmt.Errorf("write preset source candidate: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync preset source candidate: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close preset source candidate: %w", err)
	}
	closed = true
	keep = true
	return path, nil
}

func verifyPresetSource(directoryPath, filename string, expectedPresent bool, expected []byte) error {
	path := filepath.Join(directoryPath, filename)
	data, err := readPresetSourceFile(path)
	if !expectedPresent {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err == nil {
			return fmt.Errorf("%w: preset source was created after review", ErrPresetUpdateStale)
		}
		return fmt.Errorf("verify absent preset source: %w", err)
	}
	if err != nil {
		return fmt.Errorf("%w: preset source is no longer readable: %v", ErrPresetUpdateStale, err)
	}
	if !bytes.Equal(data, expected) {
		return fmt.Errorf("%w: preset source changed after review", ErrPresetUpdateStale)
	}
	return nil
}

func activatePresetSource(directoryPath, stagedPath, filename string) error {
	if filepath.Dir(stagedPath) != directoryPath || filepath.Base(stagedPath) == stagedPath {
		return fmt.Errorf("preset source candidate must be staged in its destination directory")
	}
	if err := os.Rename(stagedPath, filepath.Join(directoryPath, filename)); err != nil {
		return fmt.Errorf("activate preset source: %w", err)
	}
	return syncPresetDirectory(directoryPath)
}

func rollbackPresetSource(directoryPath, filename string, existed bool, original, activated []byte) error {
	current, err := readPresetSourceFile(filepath.Join(directoryPath, filename))
	if err != nil || !bytes.Equal(current, activated) {
		return fmt.Errorf("refuse preset source rollback because activated source changed")
	}
	if !existed {
		if err := os.Remove(filepath.Join(directoryPath, filename)); err != nil {
			return fmt.Errorf("remove restored preset source after failed commit: %w", err)
		}
		return syncPresetDirectory(directoryPath)
	}
	staged, err := stagePresetSource(directoryPath, original)
	if err != nil {
		return err
	}
	defer os.Remove(staged)
	return activatePresetSource(directoryPath, staged, filename)
}

func validatePresetSourceDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect preset source directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("preset source directory must be a real directory")
	}
	return nil
}

func syncPresetDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open preset source directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync preset source directory: %w", err)
	}
	return nil
}

func joinPresetUpdateRollbackError(operationErr, rollbackErr error) error {
	if rollbackErr == nil {
		return operationErr
	}
	return fmt.Errorf("%w; preset source rollback failed: %v", operationErr, rollbackErr)
}

func sourceSHA256(source []byte) string {
	digest := sha256.Sum256(source)
	return hex.EncodeToString(digest[:])
}

func filterPresetDiff(diff PresetDiffResult, name string) PresetDiffResult {
	filtered := PresetDiffResult{
		StateGeneration: diff.StateGeneration, Valid: diff.Valid,
		Changes: []PresetChange{}, Issues: clonePresetIssues(diff.Issues),
	}
	for _, change := range diff.Changes {
		if strings.EqualFold(change.Name, name) {
			filtered.Changes = append(filtered.Changes, clonePresetDiff(PresetDiffResult{Changes: []PresetChange{change}}).Changes[0])
		}
	}
	return filtered
}

func clonePresetDiff(diff PresetDiffResult) PresetDiffResult {
	diff.Issues = clonePresetIssues(diff.Issues)
	diff.Changes = append(make([]PresetChange, 0, len(diff.Changes)), diff.Changes...)
	for index := range diff.Changes {
		diff.Changes[index].AddedSelectors = append([]model.Selector(nil), diff.Changes[index].AddedSelectors...)
		diff.Changes[index].RemovedSelectors = append([]model.Selector(nil), diff.Changes[index].RemovedSelectors...)
		diff.Changes[index].Assignments = clonePresetAssignments(diff.Changes[index].Assignments)
	}
	return diff
}
