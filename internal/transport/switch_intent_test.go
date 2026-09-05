package transport

import (
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestSwitchIntentTargetRoundTripAndStableIdentities(t *testing.T) {
	t.Parallel()
	target, err := NewSwitchIntentTarget("22000000-0000-4000-8000-000000000001", model.TransportRestricted, 9)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSwitchIntentTarget(target.String())
	if err != nil || parsed != target || parsed.DesiredNodeGeneration != 11 {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	first, err := SwitchRequestID(target, model.TransportStandard, 12)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := SwitchRequestID(target, model.TransportStandard, 12)
	changed, _ := SwitchRequestID(target, model.TransportStandard, 13)
	operation, err := SwitchOperationID(first)
	if err != nil || model.ValidateResourceID(first) != nil || model.ValidateResourceID(operation) != nil ||
		first != second || first == changed || first == operation {
		t.Fatalf("request identities first=%q second=%q changed=%q operation=%q err=%v", first, second, changed, operation, err)
	}
}

func TestSwitchIntentTargetRejectsNonCanonicalOrInconsistentValues(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"restricted",
		"v2:22000000-0000-4000-8000-000000000001:restricted:9:11",
		"v1:bad:restricted:9:11",
		"v1:22000000-0000-4000-8000-000000000001:auto:9:11",
		"v1:22000000-0000-4000-8000-000000000001:restricted:09:11",
		"v1:22000000-0000-4000-8000-000000000001:restricted:9:10",
	} {
		if _, err := ParseSwitchIntentTarget(value); err == nil {
			t.Fatalf("ParseSwitchIntentTarget(%q) succeeded", value)
		}
	}
}
