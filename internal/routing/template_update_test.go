package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestMergeBuiltinPresetTemplatePreservesUserChangesAndAppliesUpstreamDelta(t *testing.T) {
	t.Parallel()

	base := testBuiltinPresetTemplate("telegram", 1, []model.Selector{
		{Kind: model.SelectorDomain, Value: "api.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "old.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "tracking.example.com", Exclude: true},
	})
	current := renderBuiltinPresetSource(PresetAST{SchemaVersion: PresetDocumentSchemaVersion, Name: "telegram", Selectors: canonicalPresetSelectors([]model.Selector{
		{Kind: model.SelectorDomain, Value: "api.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "old.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "user.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "tracking.example.com", Exclude: true},
		{Kind: model.SelectorDomain, Value: "private.example.com", Exclude: true},
	})}, 1)
	next := testBuiltinPresetTemplate("telegram", 2, []model.Selector{
		{Kind: model.SelectorDomain, Value: "api.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "new.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "tracking.example.com", Exclude: true},
	})

	merged, err := MergeBuiltinPresetTemplate(BuiltinPresetTemplateUpdate{Base: base, Next: next}, current)
	if err != nil {
		t.Fatalf("MergeBuiltinPresetTemplate() error = %v", err)
	}
	want := canonicalPresetSelectors([]model.Selector{
		{Kind: model.SelectorDomain, Value: "api.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "new.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "user.example.com"},
		{Kind: model.SelectorDomain, Value: "private.example.com", Exclude: true},
		{Kind: model.SelectorDomainSuffix, Value: "tracking.example.com", Exclude: true},
	})
	if merged.Name != "telegram" || merged.FromRevision != 1 || merged.ToRevision != 2 || !reflect.DeepEqual(merged.MergedSelectors, want) {
		t.Fatalf("merge = %#v, want preserved user and applied upstream selectors", merged)
	}
	if revision, err := builtinPresetRevision(merged.Source, "telegram"); err != nil || revision != 2 {
		t.Fatalf("merged marker revision = %d, %v", revision, err)
	}
	parsed, err := DecodePresetDocument(merged.Source)
	if err != nil || !reflect.DeepEqual(parsed.Selectors, want) {
		t.Fatalf("merged source AST = %#v, %v", parsed, err)
	}
	if got, wantAdded := merged.AddedSelectors, canonicalPresetSelectors([]model.Selector{{Kind: model.SelectorDomainSuffix, Value: "new.example.com"}}); !reflect.DeepEqual(got, wantAdded) {
		t.Fatalf("added selectors = %#v, want %#v", got, wantAdded)
	}
	if got, wantRemoved := merged.RemovedSelectors, canonicalPresetSelectors([]model.Selector{{Kind: model.SelectorDomainSuffix, Value: "old.example.com"}}); !reflect.DeepEqual(got, wantRemoved) {
		t.Fatalf("removed selectors = %#v, want %#v", got, wantRemoved)
	}
	currentDigest := sha256.Sum256(current)
	mergedDigest := sha256.Sum256(merged.Source)
	if merged.CurrentHash != hex.EncodeToString(currentDigest[:]) || merged.MergedHash != hex.EncodeToString(mergedDigest[:]) {
		t.Fatal("merge did not report exact source hashes")
	}
}

func TestMergeBuiltinPresetTemplateRejectsOverlappingIncompatibleChange(t *testing.T) {
	t.Parallel()

	base := testBuiltinPresetTemplate("telegram", 1, []model.Selector{{Kind: model.SelectorDomain, Value: "conflict.example.com"}})
	current := renderBuiltinPresetSource(PresetAST{SchemaVersion: PresetDocumentSchemaVersion, Name: "telegram", Selectors: canonicalPresetSelectors([]model.Selector{
		{Kind: model.SelectorDomain, Value: "conflict.example.com"},
		{Kind: model.SelectorDomain, Value: "conflict.example.com", Exclude: true},
	})}, 1)
	next := testBuiltinPresetTemplate("telegram", 2, []model.Selector{{Kind: model.SelectorDomain, Value: "replacement.example.com"}})

	_, err := MergeBuiltinPresetTemplate(BuiltinPresetTemplateUpdate{Base: base, Next: next}, current)
	var conflict *BuiltinPresetTemplateConflictError
	if !errors.As(err, &conflict) || !errors.Is(err, ErrBuiltinPresetTemplateConflict) {
		t.Fatalf("MergeBuiltinPresetTemplate() error = %v, want typed conflict", err)
	}
	if !reflect.DeepEqual(conflict.Matchers, []string{"domain:conflict.example.com"}) {
		t.Fatalf("conflict matchers = %v", conflict.Matchers)
	}
}

func TestBuiltinPresetUpdateCatalogRequiresKnownAdjacentBase(t *testing.T) {
	t.Parallel()

	base := testBuiltinPresetTemplate("telegram", 1, []model.Selector{{Kind: model.SelectorDomain, Value: "one.example.com"}})
	next := testBuiltinPresetTemplate("telegram", 2, []model.Selector{{Kind: model.SelectorDomain, Value: "two.example.com"}})
	catalog, err := NewBuiltinPresetUpdateCatalog([]BuiltinPresetTemplate{next, base})
	if err != nil {
		t.Fatalf("NewBuiltinPresetUpdateCatalog() error = %v", err)
	}
	update, err := catalog.Update("TELEGRAM", 1)
	if err != nil || update.Base.Revision != 1 || update.Next.Revision != 2 {
		t.Fatalf("Update(1) = %#v, %v", update, err)
	}
	update.Base.Source[0] ^= 0xff
	again, err := catalog.Update("telegram", 1)
	if err != nil || reflect.DeepEqual(again.Base.Source, update.Base.Source) {
		t.Fatal("catalog returned aliased template source")
	}
	if _, err := catalog.Update("telegram", 2); !errors.Is(err, ErrBuiltinPresetTemplateNoUpdate) {
		t.Fatalf("Update(current) error = %v", err)
	}
	if _, err := catalog.Update("telegram", 9); !errors.Is(err, ErrBuiltinPresetTemplateConflict) {
		t.Fatalf("Update(unknown base) error = %v", err)
	}
	if _, err := catalog.Update("missing", 1); !errors.Is(err, ErrBuiltinPresetTemplateNotFound) {
		t.Fatalf("Update(missing) error = %v", err)
	}
}

func TestBuiltinPresetRevisionMarkerIsStrictWithLegacyRevisionOneFallback(t *testing.T) {
	t.Parallel()

	legacy := []byte("schema_version: 1\nname: telegram\ninclude:\n  - type: domain\n    value: example.com\nexclude: []\n")
	if revision, err := builtinPresetRevision(legacy, "telegram"); err != nil || revision != 1 {
		t.Fatalf("legacy revision = %d, %v", revision, err)
	}
	for name, source := range map[string][]byte{
		"wrong name":      []byte("# vpnctl built-in-template: other@1\n" + string(legacy)),
		"zero":            []byte("# vpnctl built-in-template: telegram@0\n" + string(legacy)),
		"non canonical":   []byte("# vpnctl built-in-template: telegram@01\n" + string(legacy)),
		"multiple":        []byte("# vpnctl built-in-template: telegram@1\n# vpnctl built-in-template: telegram@1\n" + string(legacy)),
		"extra separator": []byte("# vpnctl built-in-template: telegram@1@2\n" + string(legacy)),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if revision, err := builtinPresetRevision(source, "telegram"); err == nil {
				t.Fatalf("builtinPresetRevision() = %d, want error", revision)
			}
		})
	}
}

func testBuiltinPresetTemplate(name string, revision uint64, selectors []model.Selector) BuiltinPresetTemplate {
	ast := PresetAST{SchemaVersion: PresetDocumentSchemaVersion, Name: name, Selectors: canonicalPresetSelectors(selectors)}
	source := renderBuiltinPresetSource(ast, revision)
	digest := sha256.Sum256(source)
	return BuiltinPresetTemplate{
		Name: name, Filename: name + ".yaml", Revision: revision,
		SHA256: hex.EncodeToString(digest[:]), Source: source,
	}
}

func TestCurrentBuiltinPresetTemplatesCarryMatchingRevisionMarkers(t *testing.T) {
	t.Parallel()

	templates, err := BuiltinPresetTemplates()
	if err != nil {
		t.Fatal(err)
	}
	for _, template := range templates {
		revision, err := builtinPresetRevision(template.Source, template.Name)
		if err != nil || revision != template.Revision || !strings.Contains(string(template.Source), builtinPresetTemplateMarker) {
			t.Fatalf("template %s marker = %d, %v", template.Name, revision, err)
		}
	}
	catalog, err := CurrentBuiltinPresetUpdateCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Update("telegram", BuiltinPresetTemplateRevision); !errors.Is(err, ErrBuiltinPresetTemplateNoUpdate) {
		t.Fatalf("current catalog Update() error = %v", err)
	}
}
