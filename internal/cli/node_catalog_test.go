package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestNodeCatalogOutputsAreValidAndContainNoCredentialLayout(t *testing.T) {
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	view := enrollment.NodeView{
		ID: "20000000-0000-4000-8000-000000000004", Name: "private-node",
		Lifecycle: model.LifecycleActive, OverlayIPv4: "10.67.0.2", AssignedPresets: []string{"telegram"},
		CredentialGeneration: 1, PolicyGeneration: 1, ActiveTransport: model.TransportRestricted,
		Transports: []enrollment.NodeTransportView{
			{Kind: model.TransportRestricted, State: model.TransportActive, Protocol: model.ProtocolTCP, Port: 8443, HandshakeHost: "www.microsoft.com"},
			{Kind: model.TransportStandard, State: model.TransportStandby, Protocol: model.ProtocolUDP, Port: 51820},
		},
		ControlCertificate: enrollment.NodeCertificateView{Fingerprint: "sha256:" + strings.Repeat("a", 64), NotAfter: now.Add(180 * 24 * time.Hour), Generation: 1},
		CreatedAt:          now,
	}
	results := []output.Result{
		NodeListOutput(enrollment.NodeList{StateGeneration: 3, Items: []enrollment.NodeView{view}}),
		NodeShowOutput(enrollment.NodeShow{StateGeneration: 3, Resource: view}),
	}
	for _, result := range results {
		if err := result.Validate(); err != nil {
			t.Fatalf("%s Validate() error = %v", result.Command, err)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"credential_ref", "certificate_ref", "private_key", "public_key", "config_hash", "secret", "token"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("%s output contains %q: %s", result.Command, forbidden, encoded)
			}
		}
	}
	if results[1].ResourceIDs["node_id"] != view.ID {
		t.Fatalf("node.show resource IDs = %+v", results[1].ResourceIDs)
	}
}

func TestEmptyNodeListOutputKeepsRequiredArray(t *testing.T) {
	result := NodeListOutput(enrollment.NodeList{StateGeneration: 1, Items: []enrollment.NodeView{}})
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	items, ok := result.Data["items"].([]output.SafeObject)
	if !ok || len(items) != 0 {
		t.Fatalf("items = %#v", result.Data["items"])
	}
}
