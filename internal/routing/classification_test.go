package routing

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestClassificationBoundaryMakesUnsupportedRecognitionExplicit(t *testing.T) {
	t.Parallel()
	selectors := []model.Selector{
		{Kind: model.SelectorDomain, Value: "api.example.com"},
		{Kind: model.SelectorDomainSuffix, Value: "example.net"},
		{Kind: model.SelectorIPCIDR, Value: "192.0.2.0/24"},
	}
	report, err := InspectClassificationBoundary(selectors)
	if err != nil || report.Validate() != nil {
		t.Fatalf("InspectClassificationBoundary() = %+v, %v", report, err)
	}
	if report.DomainSelectors != 2 || report.AddressSelectors != 1 || report.SelectedAction != "gateway_or_block" ||
		report.UnmatchedAction != "direct" || report.GlobalDoHDotBlocked {
		t.Fatalf("classification report = %+v", report)
	}
	warnings := report.Warnings()
	wantCodes := []string{"classification_boundary"}
	gotCodes := make([]string, len(warnings))
	for index, warning := range warnings {
		gotCodes[index] = warning.Code
		if !strings.Contains(warning.Message, "DoH") || !strings.Contains(warning.Message, "DoT") ||
			!strings.Contains(warning.Message, "hardcoded IP") || !strings.Contains(warning.Message, "unmatched") || !strings.Contains(warning.Message, "direct") {
			t.Fatalf("classification warning is ambiguous: %+v", warning)
		}
	}
	if !reflect.DeepEqual(gotCodes, wantCodes) {
		t.Fatalf("classification warning codes = %v", gotCodes)
	}
	if object := report.SafeObject(); object["global_doh_dot_blocked"] != false || object["hardcoded_ip"] != "address_selector_required" {
		t.Fatalf("classification safe object = %+v", object)
	}
}

func TestHiddenResolutionAndHardcodedIPRemainUnmatchedWithoutAddressSelector(t *testing.T) {
	t.Parallel()
	composition := PresetComposition{Presets: []PresetSelection{{
		Name:     "domain-only",
		Includes: []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "example.com"}},
		Excludes: []model.Selector{},
	}}}
	ir, err := CompileMatcherIR(composition)
	if err != nil {
		t.Fatal(err)
	}
	if selected, err := ir.SelectsIP(netip.MustParseAddr("203.0.113.77")); err != nil || selected {
		t.Fatalf("unselected hardcoded IP classification = %t, %v", selected, err)
	}
	guardConfig := nodeRoutingGuardFixture(t).Config()
	guardConfig.Matcher = ir
	guard, err := RenderNodeRoutingGuardConfig(guardConfig)
	if err != nil {
		t.Fatal(err)
	}
	definition := string(guard.NFTablesDefinition())
	for _, unsupported := range []string{"tcp dport 853", "udp dport 853", "cloudflare-dns.com", "dns.google", "quad9"} {
		if strings.Contains(definition, unsupported) {
			t.Fatalf("routing guard generated unsupported global DoH/DoT policy %q", unsupported)
		}
	}
}

func TestClassificationBoundaryRejectsAbsentOrInvalidSelectorInput(t *testing.T) {
	t.Parallel()
	if _, err := InspectClassificationBoundary(nil); err == nil {
		t.Fatal("nil classification selector set was accepted")
	}
	if _, err := InspectClassificationBoundary([]model.Selector{{Kind: model.SelectorDomain, Value: "INVALID"}}); err == nil {
		t.Fatal("invalid classification selector was accepted")
	}
}
