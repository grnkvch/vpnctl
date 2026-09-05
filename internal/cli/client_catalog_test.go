package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type clientCatalogStub struct {
	list routing.ClientList
	show routing.ClientShow
}

func (catalog clientCatalogStub) List() (routing.ClientList, error)       { return catalog.list, nil }
func (catalog clientCatalogStub) Show(string) (routing.ClientShow, error) { return catalog.show, nil }

func TestExecuteClientListAndShowEmitSecretFreeViews(t *testing.T) {
	oldPaths, oldRole, oldBuilder := clientCatalogSystemPaths, clientCatalogLoadRole, clientCatalogBuilder
	t.Cleanup(func() {
		clientCatalogSystemPaths, clientCatalogLoadRole, clientCatalogBuilder = oldPaths, oldRole, oldBuilder
	})
	paths, _ := store.NewPaths(t.TempDir())
	view := routing.ClientView{
		ID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", Name: "iphone", Platform: "generic", Lifecycle: model.LifecycleActive,
		OverlayIPv4: "10.66.0.2", AssignedPresets: []string{"telegram"}, CredentialGeneration: 2, PolicyGeneration: 3,
		ActiveTransport: model.TransportStandard, TransportState: model.TransportActive,
		ExportState: routing.ClientExportStale, Health: routing.ClientHealthHealthy, CreatedAt: time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC),
	}
	catalog := clientCatalogStub{list: routing.ClientList{StateGeneration: 4, Items: []routing.ClientView{view}}, show: routing.ClientShow{StateGeneration: 4, Resource: view}}
	clientCatalogSystemPaths = func() store.Paths { return paths }
	clientCatalogLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	clientCatalogBuilder = func(store.Paths) (clientCatalogAPI, error) { return catalog, nil }

	for _, test := range []struct {
		args    []string
		command string
		want    string
	}{
		{[]string{"client", "list", "--json"}, "client.list", `"export_state":"stale"`},
		{[]string{"--json", "client", "show", "iphone"}, "client.show", `"client_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"`},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if code := Execute(test.args, &stdout, &stderr); code != ExitSuccess {
			t.Fatalf("Execute(%v) code=%d stdout=%q stderr=%q", test.args, code, stdout.String(), stderr.String())
		}
		got := stdout.String()
		if !strings.Contains(got, `"command":"`+test.command+`"`) || !strings.Contains(got, test.want) {
			t.Fatalf("Execute(%v) unexpected output: %q", test.args, got)
		}
		for _, forbidden := range []string{"private_key", "credential_ref", "secret"} {
			if strings.Contains(got, forbidden) {
				t.Errorf("Execute(%v) leaked %q: %q", test.args, forbidden, got)
			}
		}
	}
}

func TestExecuteClientCatalogRoleGatePrecedesBuilder(t *testing.T) {
	oldPaths, oldRole, oldBuilder := clientCatalogSystemPaths, clientCatalogLoadRole, clientCatalogBuilder
	t.Cleanup(func() {
		clientCatalogSystemPaths, clientCatalogLoadRole, clientCatalogBuilder = oldPaths, oldRole, oldBuilder
	})
	paths, _ := store.NewPaths(t.TempDir())
	clientCatalogSystemPaths = func() store.Paths { return paths }
	clientCatalogLoadRole = func(store.Paths) (HostRole, error) { return RoleNode, nil }
	clientCatalogBuilder = func(store.Paths) (clientCatalogAPI, error) {
		t.Fatal("client catalog built before role rejection")
		return nil, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"client", "list", "--json"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("Execute(client list on node) code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"code":"unsupported_role"`) {
		t.Fatalf("missing role failure: %q", stdout.String())
	}
}
