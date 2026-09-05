package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type nodeCatalogStub struct {
	list      enrollment.NodeList
	show      enrollment.NodeShow
	listCalls int
	showCalls int
}

func (catalog *nodeCatalogStub) List() (enrollment.NodeList, error) {
	catalog.listCalls++
	return catalog.list, nil
}

func (catalog *nodeCatalogStub) Show(string) (enrollment.NodeShow, error) {
	catalog.showCalls++
	return catalog.show, nil
}

func TestExecuteNodeListAndShowUseGatewayCatalog(t *testing.T) {
	oldPaths, oldRole, oldBuilder := nodeCatalogSystemPaths, nodeCatalogLoadRole, nodeCatalogBuilder
	t.Cleanup(func() {
		nodeCatalogSystemPaths, nodeCatalogLoadRole, nodeCatalogBuilder = oldPaths, oldRole, oldBuilder
	})
	paths, _ := store.NewPaths(t.TempDir())
	view := enrollment.NodeView{
		ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Name: "bot-server", Lifecycle: model.LifecycleActive,
		OverlayIPv4: "10.67.0.2", AssignedPresets: []string{"telegram"}, CredentialGeneration: 1,
		PolicyGeneration: 1, ActiveTransport: model.TransportRestricted, Transports: []enrollment.NodeTransportView{},
		ControlCertificate: enrollment.NodeCertificateView{Fingerprint: strings.Repeat("a", 64), NotAfter: time.Date(2031, 9, 5, 0, 0, 0, 0, time.UTC), Generation: 1},
		CreatedAt:          time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC),
	}
	catalog := &nodeCatalogStub{list: enrollment.NodeList{StateGeneration: 2, Items: []enrollment.NodeView{view}}, show: enrollment.NodeShow{StateGeneration: 2, Resource: view}}
	nodeCatalogSystemPaths = func() store.Paths { return paths }
	nodeCatalogLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	nodeCatalogBuilder = func(store.Paths) (nodeCatalogAPI, error) { return catalog, nil }

	for _, test := range []struct {
		args       []string
		command    string
		projection string
	}{
		{args: []string{"--json", "node", "list"}, command: "node.list", projection: `"items":[{"active_transport":"restricted"`},
		{args: []string{"node", "show", "bot-server", "--json"}, command: "node.show", projection: `"node_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"`},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := Execute(test.args, &stdout, &stderr); code != ExitSuccess {
			t.Fatalf("Execute(%v) code=%d stdout=%q stderr=%q", test.args, code, stdout.String(), stderr.String())
		}
		if got := stdout.String(); !strings.Contains(got, `"command":"`+test.command+`"`) || !strings.Contains(got, test.projection) {
			t.Fatalf("Execute(%v) unexpected output: %q", test.args, got)
		}
	}
	if catalog.listCalls != 1 || catalog.showCalls != 1 {
		t.Fatalf("catalog calls list/show = %d/%d", catalog.listCalls, catalog.showCalls)
	}
}

func TestExecuteNodeCatalogRoleGatePrecedesBuilder(t *testing.T) {
	oldPaths, oldRole, oldBuilder := nodeCatalogSystemPaths, nodeCatalogLoadRole, nodeCatalogBuilder
	t.Cleanup(func() {
		nodeCatalogSystemPaths, nodeCatalogLoadRole, nodeCatalogBuilder = oldPaths, oldRole, oldBuilder
	})
	paths, _ := store.NewPaths(t.TempDir())
	nodeCatalogSystemPaths = func() store.Paths { return paths }
	nodeCatalogLoadRole = func(store.Paths) (HostRole, error) { return RoleNode, nil }
	nodeCatalogBuilder = func(store.Paths) (nodeCatalogAPI, error) {
		t.Fatal("node catalog built before role rejection")
		return nil, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"node", "list", "--json"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("Execute(node list on node) code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"code":"unsupported_role"`) {
		t.Fatalf("missing role failure: %q", stdout.String())
	}
}
