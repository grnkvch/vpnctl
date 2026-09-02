package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const builtinPresetTemplateMarker = "# vpnctl built-in-template: "

var (
	ErrBuiltinPresetTemplateNotFound = errors.New("built-in preset template does not exist")
	ErrBuiltinPresetTemplateNoUpdate = errors.New("built-in preset template is already current")
	ErrBuiltinPresetTemplateConflict = errors.New("built-in preset template merge conflict")
)

// BuiltinPresetTemplateUpdate is one adjacent, reviewable release transition.
// Keeping the base source is required for a real three-way merge.
type BuiltinPresetTemplateUpdate struct {
	Base BuiltinPresetTemplate
	Next BuiltinPresetTemplate
}

type BuiltinPresetTemplateMerge struct {
	Name             string
	FromRevision     uint64
	ToRevision       uint64
	CurrentHash      string
	MergedHash       string
	CurrentSelectors []model.Selector
	MergedSelectors  []model.Selector
	AddedSelectors   []model.Selector
	RemovedSelectors []model.Selector
	Source           []byte
}

type BuiltinPresetTemplateConflictError struct {
	Name     string
	Reason   string
	Matchers []string
}

func (conflict *BuiltinPresetTemplateConflictError) Error() string {
	if conflict == nil {
		return ErrBuiltinPresetTemplateConflict.Error()
	}
	if len(conflict.Matchers) == 0 {
		return fmt.Sprintf("%s: %s: %s", ErrBuiltinPresetTemplateConflict, conflict.Name, conflict.Reason)
	}
	return fmt.Sprintf("%s: %s: %s (%s)", ErrBuiltinPresetTemplateConflict, conflict.Name, conflict.Reason, strings.Join(conflict.Matchers, ", "))
}

func (conflict *BuiltinPresetTemplateConflictError) Unwrap() error {
	return ErrBuiltinPresetTemplateConflict
}

// BuiltinPresetUpdateCatalog retains adjacent embedded revisions. Releases
// must keep every base that may still appear in an operator-owned source.
type BuiltinPresetUpdateCatalog struct {
	versions map[string][]BuiltinPresetTemplate
}

func NewBuiltinPresetUpdateCatalog(templates []BuiltinPresetTemplate) (*BuiltinPresetUpdateCatalog, error) {
	if templates == nil {
		return nil, fmt.Errorf("built-in preset template history must be a present array")
	}
	catalog := &BuiltinPresetUpdateCatalog{versions: make(map[string][]BuiltinPresetTemplate)}
	for index, template := range templates {
		canonical, err := validateBuiltinPresetTemplate(template)
		if err != nil {
			return nil, fmt.Errorf("built-in preset template history[%d]: %w", index, err)
		}
		key := strings.ToLower(canonical.Name)
		catalog.versions[key] = append(catalog.versions[key], canonical)
	}
	for name := range catalog.versions {
		versions := catalog.versions[name]
		sort.Slice(versions, func(left, right int) bool { return versions[left].Revision < versions[right].Revision })
		for index := range versions {
			if index > 0 && (versions[index].Name != versions[0].Name || versions[index].Filename != versions[0].Filename || versions[index].Revision != versions[index-1].Revision+1) {
				return nil, fmt.Errorf("built-in preset template %s revisions must use one canonical name and consecutive revisions", versions[index].Name)
			}
		}
		catalog.versions[name] = versions
	}
	return catalog, nil
}

func CurrentBuiltinPresetUpdateCatalog() (*BuiltinPresetUpdateCatalog, error) {
	templates, err := BuiltinPresetTemplateHistory()
	if err != nil {
		return nil, err
	}
	return NewBuiltinPresetUpdateCatalog(templates)
}

func (catalog *BuiltinPresetUpdateCatalog) Update(name string, fromRevision uint64) (BuiltinPresetTemplateUpdate, error) {
	if catalog == nil {
		return BuiltinPresetTemplateUpdate{}, fmt.Errorf("built-in preset update catalog is required")
	}
	if err := validatePresetName(name); err != nil {
		return BuiltinPresetTemplateUpdate{}, err
	}
	versions := catalog.versions[strings.ToLower(name)]
	if len(versions) == 0 {
		return BuiltinPresetTemplateUpdate{}, fmt.Errorf("%w: %s", ErrBuiltinPresetTemplateNotFound, name)
	}
	for index, template := range versions {
		if template.Revision != fromRevision {
			continue
		}
		if index+1 == len(versions) {
			return BuiltinPresetTemplateUpdate{}, fmt.Errorf("%w: %s revision %d", ErrBuiltinPresetTemplateNoUpdate, template.Name, fromRevision)
		}
		return BuiltinPresetTemplateUpdate{Base: cloneBuiltinPresetTemplate(template), Next: cloneBuiltinPresetTemplate(versions[index+1])}, nil
	}
	return BuiltinPresetTemplateUpdate{}, &BuiltinPresetTemplateConflictError{
		Name: name, Reason: fmt.Sprintf("source revision %d has no embedded merge base", fromRevision), Matchers: []string{},
	}
}

func (catalog *BuiltinPresetUpdateCatalog) Latest(name string) (BuiltinPresetTemplate, error) {
	if catalog == nil {
		return BuiltinPresetTemplate{}, fmt.Errorf("built-in preset update catalog is required")
	}
	if err := validatePresetName(name); err != nil {
		return BuiltinPresetTemplate{}, err
	}
	versions := catalog.versions[strings.ToLower(name)]
	if len(versions) == 0 {
		return BuiltinPresetTemplate{}, fmt.Errorf("%w: %s", ErrBuiltinPresetTemplateNotFound, name)
	}
	return cloneBuiltinPresetTemplate(versions[len(versions)-1]), nil
}

func MergeBuiltinPresetTemplate(update BuiltinPresetTemplateUpdate, currentSource []byte) (BuiltinPresetTemplateMerge, error) {
	base, err := validateBuiltinPresetTemplate(update.Base)
	if err != nil {
		return BuiltinPresetTemplateMerge{}, fmt.Errorf("validate merge base: %w", err)
	}
	next, err := validateBuiltinPresetTemplate(update.Next)
	if err != nil {
		return BuiltinPresetTemplateMerge{}, fmt.Errorf("validate merge target: %w", err)
	}
	if base.Name != next.Name || base.Filename != next.Filename || next.Revision != base.Revision+1 {
		return BuiltinPresetTemplateMerge{}, fmt.Errorf("built-in preset update must contain adjacent revisions of one template")
	}
	currentAST, err := DecodePresetDocument(currentSource)
	if err != nil {
		return BuiltinPresetTemplateMerge{}, &BuiltinPresetTemplateConflictError{Name: base.Name, Reason: "current user source is invalid", Matchers: []string{}}
	}
	if currentAST.Name != base.Name {
		return BuiltinPresetTemplateMerge{}, &BuiltinPresetTemplateConflictError{Name: base.Name, Reason: "current user source declares a different preset name", Matchers: []string{}}
	}
	currentRevision, err := builtinPresetRevision(currentSource, base.Name)
	if err != nil {
		return BuiltinPresetTemplateMerge{}, &BuiltinPresetTemplateConflictError{Name: base.Name, Reason: err.Error(), Matchers: []string{}}
	}
	if currentRevision != base.Revision {
		return BuiltinPresetTemplateMerge{}, &BuiltinPresetTemplateConflictError{
			Name: base.Name, Reason: fmt.Sprintf("current source revision %d does not match merge base revision %d", currentRevision, base.Revision), Matchers: []string{},
		}
	}
	baseAST, _ := DecodePresetDocument(base.Source)
	nextAST, _ := DecodePresetDocument(next.Source)
	mergedSelectors, conflicts := mergePresetSelectorMembership(baseAST.Selectors, currentAST.Selectors, nextAST.Selectors)
	if len(conflicts) != 0 {
		return BuiltinPresetTemplateMerge{}, &BuiltinPresetTemplateConflictError{
			Name: base.Name, Reason: "operator and built-in template changed the same matcher incompatibly", Matchers: conflicts,
		}
	}
	mergedAST := PresetAST{SchemaVersion: PresetDocumentSchemaVersion, Name: base.Name, Selectors: mergedSelectors}
	if err := mergedAST.Validate(); err != nil {
		return BuiltinPresetTemplateMerge{}, &BuiltinPresetTemplateConflictError{Name: base.Name, Reason: "merged source would violate the public preset schema", Matchers: []string{}}
	}
	mergedSource := renderBuiltinPresetSource(mergedAST, next.Revision)
	if _, err := DecodePresetDocument(mergedSource); err != nil {
		return BuiltinPresetTemplateMerge{}, fmt.Errorf("validate rendered built-in preset merge: %w", err)
	}
	currentDigest := sha256.Sum256(currentSource)
	mergedDigest := sha256.Sum256(mergedSource)
	added, removed := diffPresetSelectors(mergedSelectors, currentAST.Selectors)
	return BuiltinPresetTemplateMerge{
		Name: base.Name, FromRevision: base.Revision, ToRevision: next.Revision,
		CurrentHash: hex.EncodeToString(currentDigest[:]), MergedHash: hex.EncodeToString(mergedDigest[:]),
		CurrentSelectors: append([]model.Selector(nil), currentAST.Selectors...), MergedSelectors: append([]model.Selector(nil), mergedSelectors...),
		AddedSelectors: added, RemovedSelectors: removed, Source: mergedSource,
	}, nil
}

type presetMatcherKey struct {
	kind  model.SelectorKind
	value string
}

type presetMatcherMembership uint8

const (
	presetMatcherIncluded presetMatcherMembership = 1 << iota
	presetMatcherExcluded
)

func mergePresetSelectorMembership(base, current, next []model.Selector) ([]model.Selector, []string) {
	baseSet := presetMatcherMemberships(base)
	currentSet := presetMatcherMemberships(current)
	nextSet := presetMatcherMemberships(next)
	keySet := make(map[presetMatcherKey]struct{}, len(baseSet)+len(currentSet)+len(nextSet))
	for key := range baseSet {
		keySet[key] = struct{}{}
	}
	for key := range currentSet {
		keySet[key] = struct{}{}
	}
	for key := range nextSet {
		keySet[key] = struct{}{}
	}
	keys := make([]presetMatcherKey, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].kind != keys[right].kind {
			return keys[left].kind < keys[right].kind
		}
		return keys[left].value < keys[right].value
	})
	selectors := make([]model.Selector, 0, len(base)+len(current)+len(next))
	conflicts := make([]string, 0)
	for _, key := range keys {
		baseMembership := baseSet[key]
		currentMembership := currentSet[key]
		nextMembership := nextSet[key]
		var merged presetMatcherMembership
		switch {
		case currentMembership == baseMembership:
			merged = nextMembership
		case nextMembership == baseMembership, currentMembership == nextMembership:
			merged = currentMembership
		default:
			conflicts = append(conflicts, string(key.kind)+":"+key.value)
			continue
		}
		if merged&presetMatcherIncluded != 0 {
			selectors = append(selectors, model.Selector{Kind: key.kind, Value: key.value})
		}
		if merged&presetMatcherExcluded != 0 {
			selectors = append(selectors, model.Selector{Kind: key.kind, Value: key.value, Exclude: true})
		}
	}
	sort.Slice(selectors, func(left, right int) bool { return presetSelectorLess(selectors[left], selectors[right]) })
	return selectors, conflicts
}

func presetMatcherMemberships(selectors []model.Selector) map[presetMatcherKey]presetMatcherMembership {
	result := make(map[presetMatcherKey]presetMatcherMembership, len(selectors))
	for _, selector := range selectors {
		key := presetMatcherKey{kind: selector.Kind, value: selector.Value}
		if selector.Exclude {
			result[key] |= presetMatcherExcluded
		} else {
			result[key] |= presetMatcherIncluded
		}
	}
	return result
}

func renderBuiltinPresetSource(ast PresetAST, revision uint64) []byte {
	var source strings.Builder
	fmt.Fprintf(&source, "%s%s@%d\n", builtinPresetTemplateMarker, ast.Name, revision)
	source.WriteString("# Editable vpnctl preset source. Changes become active only after reviewed apply.\n")
	fmt.Fprintf(&source, "schema_version: %d\nname: %s\ninclude:\n", PresetDocumentSchemaVersion, ast.Name)
	for _, selector := range ast.Selectors {
		if selector.Exclude {
			continue
		}
		fmt.Fprintf(&source, "  - type: %s\n    value: %s\n", selector.Kind, selector.Value)
	}
	source.WriteString("exclude:")
	hasExcludes := false
	for _, selector := range ast.Selectors {
		if !selector.Exclude {
			continue
		}
		if !hasExcludes {
			source.WriteByte('\n')
			hasExcludes = true
		}
		fmt.Fprintf(&source, "  - type: %s\n    value: %s\n", selector.Kind, selector.Value)
	}
	if !hasExcludes {
		source.WriteString(" []\n")
	}
	return []byte(source.String())
}

func builtinPresetRevision(source []byte, expectedName string) (uint64, error) {
	found := false
	var revision uint64
	for _, line := range strings.Split(string(source), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, builtinPresetTemplateMarker) {
			continue
		}
		if found {
			return 0, fmt.Errorf("current source contains multiple built-in template revision markers")
		}
		found = true
		value := strings.TrimPrefix(line, builtinPresetTemplateMarker)
		name, revisionText, ok := strings.Cut(value, "@")
		if !ok || name != expectedName || revisionText == "" || strings.Contains(revisionText, "@") {
			return 0, fmt.Errorf("current source contains an invalid built-in template revision marker")
		}
		parsed, err := strconv.ParseUint(revisionText, 10, 64)
		if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != revisionText {
			return 0, fmt.Errorf("current source contains an invalid built-in template revision marker")
		}
		revision = parsed
	}
	if !found {
		// Revision 1 predates the marker and is the only safe implicit base.
		return 1, nil
	}
	return revision, nil
}

func validateBuiltinPresetTemplate(template BuiltinPresetTemplate) (BuiltinPresetTemplate, error) {
	if err := validatePresetName(template.Name); err != nil {
		return BuiltinPresetTemplate{}, err
	}
	if template.Filename != template.Name+".yaml" || template.Revision == 0 {
		return BuiltinPresetTemplate{}, fmt.Errorf("built-in preset template requires canonical filename and positive revision")
	}
	ast, err := DecodePresetDocument(template.Source)
	if err != nil {
		return BuiltinPresetTemplate{}, err
	}
	if ast.Name != template.Name {
		return BuiltinPresetTemplate{}, fmt.Errorf("built-in preset template name does not match its source")
	}
	revision, err := builtinPresetRevision(template.Source, template.Name)
	if err != nil || revision != template.Revision {
		return BuiltinPresetTemplate{}, fmt.Errorf("built-in preset template source revision does not match metadata")
	}
	digest := sha256.Sum256(template.Source)
	if template.SHA256 != hex.EncodeToString(digest[:]) {
		return BuiltinPresetTemplate{}, fmt.Errorf("built-in preset template SHA-256 does not match source")
	}
	return cloneBuiltinPresetTemplate(template), nil
}

func cloneBuiltinPresetTemplate(template BuiltinPresetTemplate) BuiltinPresetTemplate {
	template.Source = append([]byte(nil), template.Source...)
	return template
}
