package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/routing"
)

func TestClassificationBoundaryStatusAndDoctorStayHealthyButExplicit(t *testing.T) {
	t.Parallel()
	report, err := routing.InspectClassificationBoundary([]model.Selector{{Kind: model.SelectorDomainSuffix, Value: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	results := []output.Result{
		ClassificationStatusOutput(model.RoleNode, 7, report),
		ClassificationDoctorOutput(report),
	}
	for _, result := range results {
		if err := result.Validate(); err != nil {
			t.Fatalf("%s result invalid: %v", result.Command, err)
		}
		if result.Status != output.StatusOK || result.ExitCategory != output.CategorySuccess || len(result.Warnings) != 1 || result.Warnings[0].Code != "classification_boundary" || len(result.RequiresAction) != 0 {
			t.Fatalf("%s classification result = %+v", result.Command, result)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		text := string(encoded)
		for _, required := range []string{"gateway_or_block", "unmatched_action", "global_doh_dot_blocked", "hardcoded_ip"} {
			if !strings.Contains(text, required) {
				t.Fatalf("%s diagnostics omit %q: %s", result.Command, required, text)
			}
		}
		for _, forbidden := range []string{"block_all_doh", "block_all_dot", "production-ready recognition"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s diagnostics claim unsupported behavior %q", result.Command, forbidden)
			}
		}
	}
}
