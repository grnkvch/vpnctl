package routing

import (
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestPresetCompositionAppliesLocalExclusionBeforeCrossPresetUnion(t *testing.T) {
	t.Parallel()

	alpha := mustNormalizePresetDocument(t, PresetDocument{
		SchemaVersion: PresetDocumentSchemaVersion,
		Name:          "alpha",
		Include: []PresetDocumentSelector{
			{Type: model.SelectorDomainSuffix, Value: "example.com"},
			{Type: model.SelectorIPCIDR, Value: "10.0.0.0/8"},
			{Type: model.SelectorIPCIDR, Value: "2001:db8::/32"},
		},
		Exclude: []PresetDocumentSelector{
			{Type: model.SelectorDomainSuffix, Value: "private.example.com"},
			{Type: model.SelectorIPCIDR, Value: "10.1.0.0/16"},
			{Type: model.SelectorIPCIDR, Value: "2001:db8:1::/48"},
		},
	})
	beta := mustNormalizePresetDocument(t, PresetDocument{
		SchemaVersion: PresetDocumentSchemaVersion,
		Name:          "beta",
		Include: []PresetDocumentSelector{
			{Type: model.SelectorDomain, Value: "api.private.example.com"},
			{Type: model.SelectorIPCIDR, Value: "10.1.2.0/24"},
			{Type: model.SelectorIPCIDR, Value: "2001:db8:1:2::/64"},
		},
		Exclude: []PresetDocumentSelector{},
	})
	composition, err := NormalizePresetComposition([]PresetAST{beta, alpha})
	if err != nil {
		t.Fatal(err)
	}
	if got := presetCompositionNames(composition); !reflect.DeepEqual(got, []string{"alpha", "beta"}) {
		t.Fatalf("canonical preset order = %v", got)
	}

	domainCases := map[string]bool{
		"example.com":                 true,
		"www.example.com":             true,
		"other.private.example.com":   false,
		"api.private.example.com":     true,
		"sub.api.private.example.com": false,
		"notexample.com":              false,
	}
	for domain, want := range domainCases {
		selected, err := composition.SelectsDomain(domain)
		if err != nil || selected != want {
			t.Errorf("SelectsDomain(%q) = %t, %v; want %t", domain, selected, err, want)
		}
	}

	ipCases := map[string]bool{
		"10.2.3.4":        true,
		"10.1.3.4":        false,
		"10.1.2.3":        true,
		"::ffff:10.1.2.3": true,
		"11.1.2.3":        false,
		"2001:db8:2::1":   true,
		"2001:db8:1:3::1": false,
		"2001:db8:1:2::1": true,
		"2001:db9::1":     false,
	}
	for value, want := range ipCases {
		selected, err := composition.SelectsIP(netip.MustParseAddr(value))
		if err != nil || selected != want {
			t.Errorf("SelectsIP(%q) = %t, %v; want %t", value, selected, err, want)
		}
	}

	alphaOnly, err := NormalizePresetComposition([]PresetAST{alpha})
	if err != nil {
		t.Fatal(err)
	}
	if selected, err := alphaOnly.SelectsDomain("api.private.example.com"); err != nil || selected {
		t.Fatalf("alpha exclusion did not win locally: selected=%t err=%v", selected, err)
	}
	if selected, err := alphaOnly.SelectsIP(netip.MustParseAddr("10.1.2.3")); err != nil || selected {
		t.Fatalf("alpha IP exclusion did not win locally: selected=%t err=%v", selected, err)
	}
}

func TestPresetCompositionOrderIndependenceProperty(t *testing.T) {
	t.Parallel()

	documents := presetCompositionPropertyDocuments()
	baseline, err := normalizePresetDocuments(documents)
	if err != nil {
		t.Fatal(err)
	}
	property := func(seed uint64) bool {
		candidate := clonePresetDocuments(documents)
		random := rand.New(rand.NewSource(int64(seed)))
		for index := range candidate {
			random.Shuffle(len(candidate[index].Include), func(left, right int) {
				candidate[index].Include[left], candidate[index].Include[right] = candidate[index].Include[right], candidate[index].Include[left]
			})
			random.Shuffle(len(candidate[index].Exclude), func(left, right int) {
				candidate[index].Exclude[left], candidate[index].Exclude[right] = candidate[index].Exclude[right], candidate[index].Exclude[left]
			})
		}
		random.Shuffle(len(candidate), func(left, right int) {
			candidate[left], candidate[right] = candidate[right], candidate[left]
		})
		normalized, err := normalizePresetDocuments(candidate)
		return err == nil && reflect.DeepEqual(normalized, baseline)
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}

func TestCrossPresetReselectionProperty(t *testing.T) {
	t.Parallel()

	property := func(value uint16) bool {
		domain := fmt.Sprintf("host-%d.private.example.com", value)
		alpha, err := (PresetDocument{
			SchemaVersion: PresetDocumentSchemaVersion, Name: "alpha",
			Include: []PresetDocumentSelector{{Type: model.SelectorDomainSuffix, Value: "example.com"}},
			Exclude: []PresetDocumentSelector{{Type: model.SelectorDomainSuffix, Value: "private.example.com"}},
		}).Normalize()
		if err != nil {
			return false
		}
		beta, err := (PresetDocument{
			SchemaVersion: PresetDocumentSchemaVersion, Name: "beta",
			Include: []PresetDocumentSelector{{Type: model.SelectorDomain, Value: domain}},
			Exclude: []PresetDocumentSelector{},
		}).Normalize()
		if err != nil {
			return false
		}
		alphaOnly, err := NormalizePresetComposition([]PresetAST{alpha})
		if err != nil {
			return false
		}
		withoutReselection, err := alphaOnly.SelectsDomain(domain)
		if err != nil || withoutReselection {
			return false
		}
		union, err := NormalizePresetComposition([]PresetAST{beta, alpha})
		if err != nil {
			return false
		}
		withReselection, err := union.SelectsDomain(domain)
		return err == nil && withReselection
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}

func TestPresetCompositionRejectsAmbiguityAndInvalidDestinations(t *testing.T) {
	t.Parallel()

	preset := mustNormalizePresetDocument(t, PresetDocument{
		SchemaVersion: PresetDocumentSchemaVersion, Name: "alpha",
		Include: []PresetDocumentSelector{{Type: model.SelectorDomainSuffix, Value: "example.com"}},
		Exclude: []PresetDocumentSelector{},
	})
	duplicate := preset
	duplicate.Name = "Alpha"
	if _, err := NormalizePresetComposition([]PresetAST{preset, duplicate}); err == nil {
		t.Fatal("composition accepted duplicate case-insensitive preset names")
	}
	if _, err := NormalizePresetComposition(nil); err == nil {
		t.Fatal("composition accepted a nil preset set")
	}
	empty, err := NormalizePresetComposition([]PresetAST{})
	if err != nil {
		t.Fatal(err)
	}
	if selected, err := empty.SelectsDomain("example.com"); err != nil || selected {
		t.Fatalf("empty composition selected a domain: %t, %v", selected, err)
	}
	composition, err := NormalizePresetComposition([]PresetAST{preset})
	if err != nil {
		t.Fatal(err)
	}
	preset.Selectors[0].Value = "mutated.example"
	if selected, err := composition.SelectsDomain("example.com"); err != nil || !selected {
		t.Fatalf("input mutation changed normalized composition: %t, %v", selected, err)
	}
	for _, domain := range []string{"Example.com", ".example.com", "example.com."} {
		if _, err := composition.SelectsDomain(domain); err == nil {
			t.Fatalf("composition accepted invalid domain %q", domain)
		}
	}
	if _, err := composition.SelectsIP(netip.Addr{}); err == nil {
		t.Fatal("composition accepted an invalid IP address")
	}
	if _, err := composition.SelectsIP(netip.MustParseAddr("fe80::1").WithZone("eth0")); err == nil {
		t.Fatal("composition accepted a zoned IP address")
	}
}

func presetCompositionPropertyDocuments() []PresetDocument {
	return []PresetDocument{
		{
			SchemaVersion: PresetDocumentSchemaVersion, Name: "zeta",
			Include: []PresetDocumentSelector{
				{Type: model.SelectorIPCIDR, Value: "10.0.0.0/8"},
				{Type: model.SelectorDomain, Value: "api.example.com"},
				{Type: model.SelectorDomainSuffix, Value: "example.com"},
			},
			Exclude: []PresetDocumentSelector{
				{Type: model.SelectorIPCIDR, Value: "10.1.0.0/16"},
				{Type: model.SelectorDomain, Value: "direct.example.com"},
			},
		},
		{
			SchemaVersion: PresetDocumentSchemaVersion, Name: "alpha",
			Include: []PresetDocumentSelector{
				{Type: model.SelectorDomainSuffix, Value: "example.net"},
				{Type: model.SelectorIPCIDR, Value: "2001:db8::/32"},
			},
			Exclude: []PresetDocumentSelector{
				{Type: model.SelectorDomain, Value: "direct.example.net"},
				{Type: model.SelectorIPCIDR, Value: "2001:db8:1::/48"},
			},
		},
	}
}

func normalizePresetDocuments(documents []PresetDocument) (PresetComposition, error) {
	presets := make([]PresetAST, len(documents))
	for index, document := range documents {
		preset, err := document.Normalize()
		if err != nil {
			return PresetComposition{}, err
		}
		presets[index] = preset
	}
	return NormalizePresetComposition(presets)
}

func clonePresetDocuments(documents []PresetDocument) []PresetDocument {
	cloned := make([]PresetDocument, len(documents))
	for index, document := range documents {
		cloned[index] = document
		cloned[index].Include = append([]PresetDocumentSelector(nil), document.Include...)
		cloned[index].Exclude = append([]PresetDocumentSelector(nil), document.Exclude...)
	}
	return cloned
}

func mustNormalizePresetDocument(t *testing.T, document PresetDocument) PresetAST {
	t.Helper()
	preset, err := document.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return preset
}

func presetCompositionNames(composition PresetComposition) []string {
	names := make([]string, len(composition.Presets))
	for index, preset := range composition.Presets {
		names[index] = preset.Name
	}
	return names
}
