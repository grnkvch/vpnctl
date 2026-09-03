package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestGatewayNodeCatalogListsAndShowsSecretFreeJoinedIdentity(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	if _, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportRestricted, []string{"telegram"}); err != nil {
		t.Fatal(err)
	}
	catalog, err := NewNodeCatalog(fixture.gatewayState)
	if err != nil {
		t.Fatal(err)
	}
	list, err := catalog.List()
	if err != nil {
		t.Fatal(err)
	}
	if list.StateGeneration != 3 || len(list.Items) != 1 {
		t.Fatalf("List() = %+v", list)
	}
	view := list.Items[0]
	if view.ID != joinTestNodeID || view.Name != "private-node" || view.OverlayIPv4 != "10.67.0.2" ||
		view.ActiveTransport != model.TransportRestricted || len(view.Transports) != 2 ||
		view.ControlCertificate.Fingerprint == "" || view.ControlCertificate.Generation != 1 {
		t.Fatalf("node view = %+v", view)
	}
	for _, reference := range []string{"PRIVATE-NODE", joinTestNodeID} {
		show, showErr := catalog.Show(reference)
		if showErr != nil || show.Resource.ID != joinTestNodeID || show.StateGeneration != list.StateGeneration {
			t.Fatalf("Show(%q) = %+v, %v", reference, show, showErr)
		}
	}
	for _, invalid := range []string{"", " private-node", "missing"} {
		if _, showErr := catalog.Show(invalid); !errors.Is(showErr, ErrNodeNotFound) {
			t.Fatalf("Show(%q) error = %v", invalid, showErr)
		}
	}
	encoded, err := json.Marshal(struct {
		List NodeList `json:"list"`
		View NodeView `json:"view"`
	}{List: list, View: view})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"credential_ref", "certificate_ref", "private_key", "public_key", "config_hash", "secret", "token"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("catalog projection contains %q: %s", forbidden, encoded)
		}
	}
	references, err := NewNodeCredentialReferences(joinTestNodeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range references.Values() {
		secret, readErr := fixture.nodeSecrets.Get(reference)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Contains(encoded, secret) {
			clear(secret)
			t.Fatalf("catalog projection contains credential bytes from %s", reference)
		}
		clear(secret)
	}
}

func TestNodeCatalogRequiresGatewayState(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	catalog, err := NewNodeCatalog(fixture.nodeState)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.List(); err == nil || !strings.Contains(err.Error(), "requires gateway state") {
		t.Fatalf("List() error = %v", err)
	}
}
