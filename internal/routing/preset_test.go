package routing

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestDecodePresetDocumentBuildsCanonicalProviderNeutralAST(t *testing.T) {
	t.Parallel()
	source := []byte(
		"schema_version: 1\n" +
			"name: telegram\n" +
			"include:\n" +
			"  - type: ip-cidr\n" +
			"    value: 149.154.160.0/20\n" +
			"  - type: domain-suffix\n" +
			"    value: telegram.org\n" +
			"  - type: domain\n" +
			"    value: api.telegram.org\n" +
			"exclude:\n" +
			"  - type: domain\n" +
			"    value: direct.telegram.org\n",
	)
	ast, err := DecodePresetDocument(source)
	if err != nil {
		t.Fatal(err)
	}
	expected := PresetAST{
		SchemaVersion: PresetDocumentSchemaVersion,
		Name:          "telegram",
		Selectors: []model.Selector{
			{Kind: model.SelectorDomain, Value: "api.telegram.org"},
			{Kind: model.SelectorDomainSuffix, Value: "telegram.org"},
			{Kind: model.SelectorIPCIDR, Value: "149.154.160.0/20"},
			{Kind: model.SelectorDomain, Value: "direct.telegram.org", Exclude: true},
		},
	}
	if !reflect.DeepEqual(ast, expected) {
		t.Fatalf("AST = %#v, want %#v", ast, expected)
	}
	if err := ast.Validate(); err != nil {
		t.Fatalf("normalized AST is invalid: %v", err)
	}
}

func TestPresetNormalizationIsIndependentOfSelectorOrder(t *testing.T) {
	t.Parallel()
	include := []PresetDocumentSelector{
		{Type: model.SelectorDomain, Value: "api.telegram.org"},
		{Type: model.SelectorDomainSuffix, Value: "telegram.org"},
		{Type: model.SelectorIPCIDR, Value: "149.154.160.0/20"},
		{Type: model.SelectorIPCIDR, Value: "2001:67c:4e8::/48"},
	}
	exclude := []PresetDocumentSelector{
		{Type: model.SelectorDomain, Value: "direct.telegram.org"},
		{Type: model.SelectorIPCIDR, Value: "149.154.167.0/24"},
	}
	baseline, err := (PresetDocument{
		SchemaVersion: PresetDocumentSchemaVersion, Name: "telegram", Include: include, Exclude: exclude,
	}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewSource(71))
	for iteration := 0; iteration < 250; iteration++ {
		candidateInclude := append([]PresetDocumentSelector(nil), include...)
		candidateExclude := append([]PresetDocumentSelector(nil), exclude...)
		random.Shuffle(len(candidateInclude), func(left, right int) {
			candidateInclude[left], candidateInclude[right] = candidateInclude[right], candidateInclude[left]
		})
		random.Shuffle(len(candidateExclude), func(left, right int) {
			candidateExclude[left], candidateExclude[right] = candidateExclude[right], candidateExclude[left]
		})
		candidate, err := (PresetDocument{
			SchemaVersion: PresetDocumentSchemaVersion, Name: "telegram", Include: candidateInclude, Exclude: candidateExclude,
		}).Normalize()
		if err != nil || !reflect.DeepEqual(candidate, baseline) {
			t.Fatalf("permutation %d = %#v, %v; baseline %#v", iteration, candidate, err, baseline)
		}
	}
}

func TestDecodePresetDocumentRejectsActionsOutboundsUnknownTypesAndAmbiguity(t *testing.T) {
	t.Parallel()
	validPrefix := "schema_version: 1\nname: telegram\n"
	validInclude := "include:\n  - type: domain-suffix\n    value: telegram.org\n"
	validExclude := "exclude: []\n"
	tests := map[string]string{
		"empty":                     "",
		"root-sequence":             "- telegram\n",
		"wrong-version":             strings.Replace(validPrefix+validInclude+validExclude, "schema_version: 1", "schema_version: 2", 1),
		"missing-include":           validPrefix + validExclude,
		"empty-include":             validPrefix + "include: []\n" + validExclude,
		"missing-exclude":           validPrefix + validInclude,
		"routing-action":            validPrefix + "action: proxy\n" + validInclude + validExclude,
		"outbound-name":             validPrefix + "outbound: DIRECT\n" + validInclude + validExclude,
		"raw-mihomo":                validPrefix + "mihomo: {rules: [MATCH,DIRECT]}\n" + validInclude + validExclude,
		"unknown-selector":          validPrefix + "include:\n  - type: geosite\n    value: telegram\n" + validExclude,
		"selector-action":           validPrefix + "include:\n  - type: domain\n    value: telegram.org\n    action: direct\n" + validExclude,
		"selector-outbound":         validPrefix + "include:\n  - type: domain\n    value: telegram.org\n    outbound: proxy\n" + validExclude,
		"upper-case-domain":         validPrefix + "include:\n  - type: domain\n    value: Telegram.org\n" + validExclude,
		"trailing-dot-domain":       validPrefix + "include:\n  - type: domain\n    value: telegram.org.\n" + validExclude,
		"invalid-domain-character":  validPrefix + "include:\n  - type: domain\n    value: tele_gram.org\n" + validExclude,
		"host-bits-prefix":          validPrefix + "include:\n  - type: ip-cidr\n    value: 149.154.161.1/20\n" + validExclude,
		"non-canonical-prefix":      validPrefix + "include:\n  - type: ip-cidr\n    value: 2001:0db8::/32\n" + validExclude,
		"duplicate-include":         validPrefix + validInclude + "  - type: domain-suffix\n    value: telegram.org\n" + validExclude,
		"duplicate-root-key":        validPrefix + "name: duplicate\n" + validInclude + validExclude,
		"multiple-documents":        validPrefix + validInclude + validExclude + "---\n" + validPrefix + validInclude + validExclude,
		"anchor-and-alias":          validPrefix + "include: &rules\n  - type: domain\n    value: telegram.org\nexclude: *rules\n",
		"custom-provider-tag":       validPrefix + "include:\n  - !mihomo {type: domain, value: telegram.org}\n" + validExclude,
		"non-string-selector-value": validPrefix + "include:\n  - type: domain\n    value: true\n" + validExclude,
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			if ast, err := DecodePresetDocument([]byte(source)); err == nil {
				t.Fatalf("DecodePresetDocument accepted invalid source as %#v", ast)
			}
		})
	}
	oversized := bytes.Repeat([]byte{'x'}, PresetMaximumDocumentBytes+1)
	if _, err := DecodePresetDocument(oversized); err == nil {
		t.Fatal("DecodePresetDocument accepted oversized source")
	}
}

func TestPresetDocumentRejectsMoreThanBoundedSelectors(t *testing.T) {
	t.Parallel()
	document := PresetDocument{
		SchemaVersion: PresetDocumentSchemaVersion,
		Name:          "bounded",
		Include:       make([]PresetDocumentSelector, PresetMaximumSelectors+1),
		Exclude:       []PresetDocumentSelector{},
	}
	for index := range document.Include {
		document.Include[index] = PresetDocumentSelector{Type: model.SelectorDomain, Value: fmt.Sprintf("d-%d.example", index)}
	}
	if _, err := document.Normalize(); err == nil {
		t.Fatal("Normalize accepted more than the selector bound")
	}
}

func FuzzDecodePresetDocument(f *testing.F) {
	f.Add([]byte("schema_version: 1\nname: x\ninclude:\n  - type: domain\n    value: example.com\nexclude: []\n"))
	f.Add([]byte("action: DIRECT\n"))
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, source []byte) {
		ast, err := DecodePresetDocument(source)
		if err == nil {
			if err := ast.Validate(); err != nil {
				t.Fatalf("decoder returned invalid AST: %#v: %v", ast, err)
			}
		}
	})
}
