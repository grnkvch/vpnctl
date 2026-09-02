package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	PresetMaximumDocuments      = 1024
	PresetMaximumDirectoryItems = 4096
	PresetMaximumSetSelectors   = 32768
)

var (
	ErrPresetNotFound  = errors.New("preset does not exist")
	ErrPresetAmbiguous = errors.New("preset source is ambiguous")
	ErrPresetAssigned  = errors.New("preset is still assigned")
)

type PresetStateReader interface {
	Load() (model.State, error)
}

type PresetCatalog struct {
	paths store.Paths
	state PresetStateReader
}

type PresetIssue struct {
	Code     string
	Name     string
	Filename string
	Message  string
}

type PresetAssignment struct {
	TargetKind model.TargetKind
	TargetID   string
	TargetName string
}

type PresetSourceView struct {
	Name      string
	Filename  string
	Path      string
	Present   bool
	Valid     bool
	SHA256    string
	Selectors []model.Selector
	Issues    []PresetIssue
}

type PresetEffectiveView struct {
	Name          string
	Present       bool
	SourceHash    string
	EffectiveHash string
	Generation    uint64
	Selectors     []model.Selector
}

type PresetSummary struct {
	Name             string
	SourcePresent    bool
	SourceValid      bool
	EffectivePresent bool
	SourceChanged    bool
	SelectorChanged  bool
	Assignments      []PresetAssignment
	Issues           []PresetIssue
}

type PresetListResult struct {
	StateGeneration uint64
	Items           []PresetSummary
	Issues          []PresetIssue
}

type PresetShowResult struct {
	StateGeneration uint64
	Source          *PresetSourceView
	Effective       *PresetEffectiveView
	Assignments     []PresetAssignment
	Issues          []PresetIssue
}

type PresetValidationResult struct {
	StateGeneration uint64
	Valid           bool
	SourceCount     int
	Issues          []PresetIssue
}

type PresetChangeKind string

const (
	PresetAdded    PresetChangeKind = "added"
	PresetModified PresetChangeKind = "modified"
	PresetDeleted  PresetChangeKind = "deleted"
)

type PresetChange struct {
	Name             string
	Kind             PresetChangeKind
	SourceChanged    bool
	SelectorChanged  bool
	AddedSelectors   []model.Selector
	RemovedSelectors []model.Selector
	Assignments      []PresetAssignment
}

type PresetDiffResult struct {
	StateGeneration uint64
	Valid           bool
	Changes         []PresetChange
	Issues          []PresetIssue
}

type PresetDeleteCheck struct {
	Name        string
	Allowed     bool
	Assignments []PresetAssignment
}

func NewPresetCatalog(paths store.Paths, state PresetStateReader) (*PresetCatalog, error) {
	if state == nil {
		return nil, fmt.Errorf("preset catalog state reader is required")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths {
		return nil, fmt.Errorf("preset catalog paths do not match the system root")
	}
	return &PresetCatalog{paths: paths, state: state}, nil
}

func (catalog *PresetCatalog) List() (PresetListResult, error) {
	inspection, err := catalog.inspect()
	if err != nil {
		return PresetListResult{}, err
	}
	items := make([]PresetSummary, 0, len(inspection.sources)+len(inspection.effective))
	seen := make(map[string]struct{}, len(inspection.sources))
	for _, source := range inspection.sources {
		key := source.key
		if key == "" {
			key = "\x00" + source.view.Filename
		}
		effective, active := inspection.effective[key]
		summary := summarizePreset(source.view, effective, active, inspection.assignments[key])
		summary.Issues = appendMatchingPresetIssues(summary.Issues, inspection.issues, summary.Name)
		items = append(items, summary)
		seen[key] = struct{}{}
	}
	for key, effective := range inspection.effective {
		if _, found := seen[key]; found {
			continue
		}
		summary := summarizePreset(PresetSourceView{Name: effective.Name}, effective, true, inspection.assignments[key])
		summary.Issues = appendMatchingPresetIssues(summary.Issues, inspection.issues, summary.Name)
		items = append(items, summary)
	}
	sort.SliceStable(items, func(left, right int) bool {
		return presetNameLess(items[left].Name, items[right].Name)
	})
	return PresetListResult{StateGeneration: inspection.state.Generation, Items: items, Issues: clonePresetIssues(inspection.issues)}, nil
}

func (catalog *PresetCatalog) Show(name string) (PresetShowResult, error) {
	if err := validatePresetName(name); err != nil {
		return PresetShowResult{}, err
	}
	inspection, err := catalog.inspect()
	if err != nil {
		return PresetShowResult{}, err
	}
	key := strings.ToLower(name)
	var source *PresetSourceView
	for index := range inspection.sources {
		if inspection.sources[index].key != key {
			continue
		}
		if source != nil {
			return PresetShowResult{}, fmt.Errorf("%w: %s", ErrPresetAmbiguous, name)
		}
		view := clonePresetSourceView(inspection.sources[index].view)
		source = &view
	}
	var effective *PresetEffectiveView
	if active, found := inspection.effective[key]; found {
		view := clonePresetEffectiveView(active)
		effective = &view
	}
	if source == nil && effective == nil {
		return PresetShowResult{}, fmt.Errorf("%w: %s", ErrPresetNotFound, name)
	}
	issues := make([]PresetIssue, 0)
	if source != nil {
		issues = append(issues, source.Issues...)
	}
	issues = appendMatchingPresetIssues(issues, inspection.issues, name)
	return PresetShowResult{
		StateGeneration: inspection.state.Generation, Source: source, Effective: effective,
		Assignments: clonePresetAssignments(inspection.assignments[key]), Issues: issues,
	}, nil
}

func (catalog *PresetCatalog) Validate() (PresetValidationResult, error) {
	inspection, err := catalog.inspect()
	if err != nil {
		return PresetValidationResult{}, err
	}
	return PresetValidationResult{
		StateGeneration: inspection.state.Generation, Valid: len(inspection.issues) == 0,
		SourceCount: len(inspection.sources), Issues: clonePresetIssues(inspection.issues),
	}, nil
}

func (catalog *PresetCatalog) Diff() (PresetDiffResult, error) {
	inspection, err := catalog.inspect()
	if err != nil {
		return PresetDiffResult{}, err
	}
	result := PresetDiffResult{
		StateGeneration: inspection.state.Generation, Valid: len(inspection.issues) == 0,
		Changes: []PresetChange{}, Issues: clonePresetIssues(inspection.issues),
	}
	if !result.Valid {
		return result, nil
	}
	sources := make(map[string]inspectedPresetSource, len(inspection.sources))
	names := make(map[string]string, len(inspection.sources)+len(inspection.effective))
	for _, source := range inspection.sources {
		key := source.key
		if key == "" {
			continue
		}
		sources[key] = source
		names[key] = source.view.Name
	}
	for key, effective := range inspection.effective {
		if _, found := names[key]; !found {
			names[key] = effective.Name
		}
	}
	keys := make([]string, 0, len(names))
	for key := range names {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		source, sourcePresent := sources[key]
		effective, effectivePresent := inspection.effective[key]
		change, changed := diffPreset(names[key], source, sourcePresent, effective, effectivePresent, inspection.assignments[key])
		if changed {
			result.Changes = append(result.Changes, change)
		}
	}
	return result, nil
}

// CheckDelete is a read-only guard for reviewed source-removal workflows. It
// also rejects a preset already removed manually while assignments remain.
func (catalog *PresetCatalog) CheckDelete(name string) (PresetDeleteCheck, error) {
	if err := validatePresetName(name); err != nil {
		return PresetDeleteCheck{}, err
	}
	inspection, err := catalog.inspect()
	if err != nil {
		return PresetDeleteCheck{}, err
	}
	key := strings.ToLower(name)
	found := false
	for _, source := range inspection.sources {
		if source.key == key {
			found = true
			break
		}
	}
	if _, active := inspection.effective[key]; active {
		found = true
	}
	if !found {
		return PresetDeleteCheck{}, fmt.Errorf("%w: %s", ErrPresetNotFound, name)
	}
	assignments := clonePresetAssignments(inspection.assignments[key])
	check := PresetDeleteCheck{Name: name, Allowed: len(assignments) == 0, Assignments: assignments}
	if !check.Allowed {
		return check, fmt.Errorf("%w: %s has %d assignment(s)", ErrPresetAssigned, name, len(assignments))
	}
	return check, nil
}

type inspectedPresetSource struct {
	view PresetSourceView
	ast  PresetAST
	key  string
}

type presetCatalogInspection struct {
	state       model.State
	sources     []inspectedPresetSource
	effective   map[string]PresetEffectiveView
	assignments map[string][]PresetAssignment
	issues      []PresetIssue
}

func (catalog *PresetCatalog) inspect() (presetCatalogInspection, error) {
	if catalog == nil {
		return presetCatalogInspection{}, fmt.Errorf("preset catalog is required")
	}
	state, err := catalog.state.Load()
	if err != nil {
		return presetCatalogInspection{}, fmt.Errorf("load authoritative preset state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return presetCatalogInspection{}, fmt.Errorf("validate authoritative preset state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return presetCatalogInspection{}, fmt.Errorf("preset catalog requires gateway state")
	}
	sources, issues, err := inspectPresetSources(catalog.paths.PresetsDir)
	if err != nil {
		return presetCatalogInspection{}, err
	}
	effective := make(map[string]PresetEffectiveView, len(state.Presets))
	for _, preset := range state.Presets {
		selectors := canonicalPresetSelectors(preset.Selectors)
		effective[strings.ToLower(preset.Name)] = PresetEffectiveView{
			Name: preset.Name, Present: true, SourceHash: preset.SourceHash, EffectiveHash: preset.EffectiveHash,
			Generation: preset.Generation, Selectors: selectors,
		}
	}
	assignments := collectPresetAssignments(state)
	sourceNames := make(map[string]struct{}, len(sources))
	validSourceNames := make(map[string]struct{}, len(sources))
	sourceCounts := make(map[string]int, len(sources))
	for _, source := range sources {
		if source.key != "" {
			sourceCounts[source.key]++
			sourceNames[source.key] = struct{}{}
		}
	}
	validASTs := make([]PresetAST, 0, len(sources))
	for index := range sources {
		if !sources[index].view.Valid {
			continue
		}
		key := sources[index].key
		if sourceCounts[key] > 1 {
			issue := newPresetIssue("duplicate_preset_name", sources[index].view.Name, sources[index].view.Filename, "multiple source files declare the same preset name")
			sources[index].view.Valid = false
			sources[index].view.Issues = append(sources[index].view.Issues, issue)
			issues = append(issues, issue)
			continue
		}
		validSourceNames[key] = struct{}{}
		validASTs = append(validASTs, sources[index].ast)
	}
	if len(issues) == 0 {
		if _, err := NormalizePresetComposition(validASTs); err != nil {
			issues = append(issues, newPresetIssue("invalid_preset_set", "", "", err.Error()))
		}
	}
	for name, assigned := range assignments {
		if len(assigned) == 0 {
			continue
		}
		if _, present := sourceNames[name]; !present {
			displayName := name
			if preset, found := effective[name]; found {
				displayName = preset.Name
			}
			issues = append(issues, newPresetIssue("assigned_preset_missing", displayName, displayName+".yaml", "assigned preset source is missing; unassign it before deletion"))
		} else if _, valid := validSourceNames[name]; !valid {
			displayName := name
			if preset, found := effective[name]; found {
				displayName = preset.Name
			}
			issues = append(issues, newPresetIssue("assigned_preset_invalid", displayName, displayName+".yaml", "assigned preset source is invalid; the prior effective generation remains active"))
		}
	}
	sortPresetIssues(issues)
	return presetCatalogInspection{state: state, sources: sources, effective: effective, assignments: assignments, issues: issues}, nil
}

func inspectPresetSources(directoryPath string) ([]inspectedPresetSource, []PresetIssue, error) {
	before, err := os.Lstat(directoryPath)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect preset source directory: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, nil, fmt.Errorf("preset source directory must be a real directory")
	}
	directory, err := os.Open(directoryPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open preset source directory: %w", err)
	}
	defer directory.Close()
	after, err := directory.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, nil, fmt.Errorf("preset source directory changed while opening")
	}
	entries, err := directory.ReadDir(PresetMaximumDirectoryItems + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("read preset source directory: %w", err)
	}
	if len(entries) > PresetMaximumDirectoryItems {
		return nil, nil, fmt.Errorf("preset source directory exceeds %d entries", PresetMaximumDirectoryItems)
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	sources := make([]inspectedPresetSource, 0, len(entries))
	issues := []PresetIssue{}
	totalSelectors := 0
	for _, entry := range entries {
		filename := entry.Name()
		if filepath.Ext(filename) != ".yaml" {
			continue
		}
		if len(sources) >= PresetMaximumDocuments {
			issues = append(issues, newPresetIssue("too_many_preset_documents", "", "", fmt.Sprintf("preset source set exceeds %d YAML documents", PresetMaximumDocuments)))
			break
		}
		source := inspectPresetSourceFile(directoryPath, filename)
		sources = append(sources, source)
		issues = append(issues, source.view.Issues...)
		totalSelectors += len(source.view.Selectors)
		if totalSelectors > PresetMaximumSetSelectors {
			issues = append(issues, newPresetIssue("too_many_preset_selectors", "", "", fmt.Sprintf("preset source set exceeds %d total selectors", PresetMaximumSetSelectors)))
			break
		}
	}
	return sources, issues, nil
}

func inspectPresetSourceFile(directoryPath, filename string) inspectedPresetSource {
	baseName := strings.TrimSuffix(filename, ".yaml")
	view := PresetSourceView{Name: safePresetName(baseName), Filename: safePresetFilename(filename), Present: true, Issues: []PresetIssue{}}
	if view.Filename != "" {
		view.Path = filepath.Join(directoryPath, view.Filename)
	}
	if err := validatePresetName(baseName); err != nil {
		issue := newPresetIssue("invalid_preset_filename", "", view.Filename, "preset YAML filename must be <valid-name>.yaml")
		view.Issues = append(view.Issues, issue)
		return inspectedPresetSource{view: view}
	}
	key := strings.ToLower(baseName)
	data, err := readPresetSourceFile(filepath.Join(directoryPath, filename))
	if err != nil {
		issue := newPresetIssue("unsafe_preset_source", baseName, view.Filename, err.Error())
		view.Issues = append(view.Issues, issue)
		return inspectedPresetSource{view: view, key: key}
	}
	digest := sha256.Sum256(data)
	view.SHA256 = hex.EncodeToString(digest[:])
	ast, err := DecodePresetDocument(data)
	if err != nil {
		issue := newPresetIssue("invalid_preset_document", baseName, view.Filename, err.Error())
		view.Issues = append(view.Issues, issue)
		return inspectedPresetSource{view: view, key: key}
	}
	if ast.Name != baseName {
		issue := newPresetIssue("preset_name_mismatch", ast.Name, view.Filename, "preset document name must equal its YAML filename")
		view.Issues = append(view.Issues, issue)
		return inspectedPresetSource{view: view, ast: ast, key: key}
	}
	view.Valid = true
	view.Selectors = append([]model.Selector(nil), ast.Selectors...)
	return inspectedPresetSource{view: view, ast: ast, key: key}
}

func readPresetSourceFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect preset source: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("preset source must be a regular file and not a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open preset source: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, fmt.Errorf("preset source changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, PresetMaximumDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read preset source: %w", err)
	}
	if len(data) > PresetMaximumDocumentBytes {
		return nil, fmt.Errorf("preset source exceeds %d bytes", PresetMaximumDocumentBytes)
	}
	return data, nil
}

func collectPresetAssignments(state model.State) map[string][]PresetAssignment {
	assignments := make(map[string][]PresetAssignment)
	for _, node := range state.Nodes {
		for _, name := range node.AssignedPresets {
			key := strings.ToLower(name)
			assignments[key] = append(assignments[key], PresetAssignment{TargetKind: model.TargetNode, TargetID: node.ID, TargetName: node.Name})
		}
	}
	for _, client := range state.Clients {
		for _, name := range client.AssignedPresets {
			key := strings.ToLower(name)
			assignments[key] = append(assignments[key], PresetAssignment{TargetKind: model.TargetClient, TargetID: client.ID, TargetName: client.Name})
		}
	}
	for key := range assignments {
		sort.Slice(assignments[key], func(left, right int) bool {
			if assignments[key][left].TargetKind != assignments[key][right].TargetKind {
				return assignments[key][left].TargetKind < assignments[key][right].TargetKind
			}
			if assignments[key][left].TargetName != assignments[key][right].TargetName {
				return assignments[key][left].TargetName < assignments[key][right].TargetName
			}
			return assignments[key][left].TargetID < assignments[key][right].TargetID
		})
	}
	return assignments
}

func summarizePreset(source PresetSourceView, effective PresetEffectiveView, effectivePresent bool, assignments []PresetAssignment) PresetSummary {
	name := source.Name
	if name == "" {
		name = effective.Name
	}
	summary := PresetSummary{
		Name: name, SourcePresent: source.Present, SourceValid: source.Valid, EffectivePresent: effectivePresent,
		Assignments: clonePresetAssignments(assignments), Issues: clonePresetIssues(source.Issues),
	}
	if source.Valid && effectivePresent {
		summary.SourceChanged = source.SHA256 != effective.SourceHash
		summary.SelectorChanged = !presetSelectorsEqual(source.Selectors, effective.Selectors)
	} else {
		summary.SourceChanged = source.Present != effectivePresent || (source.Present && !source.Valid)
		summary.SelectorChanged = source.Present != effectivePresent
	}
	return summary
}

func diffPreset(name string, source inspectedPresetSource, sourcePresent bool, effective PresetEffectiveView, effectivePresent bool, assignments []PresetAssignment) (PresetChange, bool) {
	change := PresetChange{Name: name, Assignments: clonePresetAssignments(assignments), AddedSelectors: []model.Selector{}, RemovedSelectors: []model.Selector{}}
	switch {
	case sourcePresent && !effectivePresent:
		change.Kind = PresetAdded
		change.SourceChanged = true
		change.SelectorChanged = true
		change.AddedSelectors = append(change.AddedSelectors, source.view.Selectors...)
	case !sourcePresent && effectivePresent:
		change.Kind = PresetDeleted
		change.SourceChanged = true
		change.SelectorChanged = true
		change.RemovedSelectors = append(change.RemovedSelectors, effective.Selectors...)
	case sourcePresent && effectivePresent:
		change.SourceChanged = source.view.SHA256 != effective.SourceHash
		change.AddedSelectors, change.RemovedSelectors = diffPresetSelectors(source.view.Selectors, effective.Selectors)
		change.SelectorChanged = len(change.AddedSelectors) != 0 || len(change.RemovedSelectors) != 0
		if !change.SourceChanged && !change.SelectorChanged {
			return PresetChange{}, false
		}
		change.Kind = PresetModified
	default:
		return PresetChange{}, false
	}
	return change, true
}

func diffPresetSelectors(candidate, effective []model.Selector) (added, removed []model.Selector) {
	candidateSet := make(map[string]model.Selector, len(candidate))
	effectiveSet := make(map[string]model.Selector, len(effective))
	for _, selector := range candidate {
		candidateSet[presetSelectorKey(selector)] = selector
	}
	for _, selector := range effective {
		effectiveSet[presetSelectorKey(selector)] = selector
	}
	for key, selector := range candidateSet {
		if _, found := effectiveSet[key]; !found {
			added = append(added, selector)
		}
	}
	for key, selector := range effectiveSet {
		if _, found := candidateSet[key]; !found {
			removed = append(removed, selector)
		}
	}
	sort.Slice(added, func(left, right int) bool { return presetSelectorLess(added[left], added[right]) })
	sort.Slice(removed, func(left, right int) bool { return presetSelectorLess(removed[left], removed[right]) })
	if added == nil {
		added = []model.Selector{}
	}
	if removed == nil {
		removed = []model.Selector{}
	}
	return added, removed
}

func canonicalPresetSelectors(selectors []model.Selector) []model.Selector {
	result := append([]model.Selector(nil), selectors...)
	sort.Slice(result, func(left, right int) bool { return presetSelectorLess(result[left], result[right]) })
	return result
}

func presetSelectorsEqual(left, right []model.Selector) bool {
	if len(left) != len(right) {
		return false
	}
	left = canonicalPresetSelectors(left)
	right = canonicalPresetSelectors(right)
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func presetSelectorKey(selector model.Selector) string {
	return string(selector.Kind) + "\x00" + selector.Value + fmt.Sprintf("\x00%t", selector.Exclude)
}

func presetNameLess(left, right string) bool {
	leftLower, rightLower := strings.ToLower(left), strings.ToLower(right)
	if leftLower != rightLower {
		return leftLower < rightLower
	}
	return left < right
}

func newPresetIssue(code, name, filename, message string) PresetIssue {
	return PresetIssue{Code: code, Name: name, Filename: safePresetFilename(filename), Message: safePresetIssueMessage(message)}
}

func safePresetFilename(value string) string {
	if len(value) > 255 || strings.ContainsAny(value, "\x00\r\n") {
		return ""
	}
	return value
}

func safePresetName(value string) string {
	if len(value) > 63 || strings.ContainsAny(value, "\x00\r\n\t") {
		return ""
	}
	return value
}

func safePresetIssueMessage(value string) string {
	value = strings.Map(func(character rune) rune {
		if character == '\x00' || character == '\r' || character == '\n' || character == '\t' {
			return ' '
		}
		return character
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return "preset source is invalid"
	}
	characters := []rune(value)
	if len(characters) > 512 {
		value = string(characters[:512])
	}
	return value
}

func sortPresetIssues(issues []PresetIssue) {
	sort.Slice(issues, func(left, right int) bool {
		leftIssue, rightIssue := issues[left], issues[right]
		if leftIssue.Code != rightIssue.Code {
			return leftIssue.Code < rightIssue.Code
		}
		leftLower, rightLower := strings.ToLower(leftIssue.Name), strings.ToLower(rightIssue.Name)
		if leftLower != rightLower {
			return leftLower < rightLower
		}
		if leftIssue.Name != rightIssue.Name {
			return leftIssue.Name < rightIssue.Name
		}
		if leftIssue.Filename != rightIssue.Filename {
			return leftIssue.Filename < rightIssue.Filename
		}
		return leftIssue.Message < rightIssue.Message
	})
}

func clonePresetIssues(values []PresetIssue) []PresetIssue {
	return append(make([]PresetIssue, 0, len(values)), values...)
}

func clonePresetAssignments(values []PresetAssignment) []PresetAssignment {
	return append(make([]PresetAssignment, 0, len(values)), values...)
}

func clonePresetSourceView(view PresetSourceView) PresetSourceView {
	view.Selectors = append([]model.Selector(nil), view.Selectors...)
	view.Issues = clonePresetIssues(view.Issues)
	return view
}

func clonePresetEffectiveView(view PresetEffectiveView) PresetEffectiveView {
	view.Selectors = append([]model.Selector(nil), view.Selectors...)
	return view
}

func containsPresetIssue(issues []PresetIssue, want PresetIssue) bool {
	for _, issue := range issues {
		if issue == want {
			return true
		}
	}
	return false
}

func appendMatchingPresetIssues(destination, candidates []PresetIssue, name string) []PresetIssue {
	result := clonePresetIssues(destination)
	for _, issue := range candidates {
		if strings.EqualFold(issue.Name, name) && !containsPresetIssue(result, issue) {
			result = append(result, issue)
		}
	}
	sortPresetIssues(result)
	return result
}
