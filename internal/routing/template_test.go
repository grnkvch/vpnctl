package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestBuiltinPresetTemplatesAreStableValidAndProviderNeutral(t *testing.T) {
	t.Parallel()

	templates, err := BuiltinPresetTemplates()
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"telegram", "openai", "anthropic"}
	wantSelectors := map[string][]model.Selector{
		"telegram": {
			{Kind: model.SelectorDomainSuffix, Value: "t.me"},
			{Kind: model.SelectorDomainSuffix, Value: "telegram.org"},
		},
		"openai": {
			{Kind: model.SelectorDomainSuffix, Value: "chatgpt.com"},
			{Kind: model.SelectorDomainSuffix, Value: "openai.com"},
		},
		"anthropic": {
			{Kind: model.SelectorDomainSuffix, Value: "anthropic.com"},
			{Kind: model.SelectorDomainSuffix, Value: "claude.ai"},
		},
	}
	if len(templates) != len(wantNames) {
		t.Fatalf("template count = %d, want %d", len(templates), len(wantNames))
	}
	for index, template := range templates {
		if template.Name != wantNames[index] || template.Filename != template.Name+".yaml" || template.Revision != BuiltinPresetTemplateRevision {
			t.Fatalf("template[%d] metadata = %+v", index, template)
		}
		digest := sha256.Sum256(template.Source)
		if template.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("template %s digest = %s", template.Name, template.SHA256)
		}
		ast, err := DecodePresetDocument(template.Source)
		if err != nil {
			t.Fatalf("decode template %s: %v", template.Name, err)
		}
		if ast.Name != template.Name || !reflect.DeepEqual(ast.Selectors, wantSelectors[template.Name]) {
			t.Fatalf("template %s AST = %+v", template.Name, ast)
		}
		lower := strings.ToLower(string(template.Source))
		for _, forbidden := range []string{"action:", "outbound:", "mihomo:"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("template %s contains provider/action field %q", template.Name, forbidden)
			}
		}
	}
}

func TestBuiltinPresetTemplateCatalogReturnsIndependentSources(t *testing.T) {
	t.Parallel()

	first, err := BuiltinPresetTemplates()
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), first[0].Source...)
	first[0].Source[0] ^= 0xff
	second, err := BuiltinPresetTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second[0].Source, original) {
		t.Fatal("caller mutation changed the embedded preset catalog")
	}
}
