package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestExecuteTransportHostShowUsesGatewayViewerAndStableJSON(t *testing.T) {
	originalPaths, originalRole, originalViewer := transportHostSystemPaths, transportHostLoadRole, transportHostBuildViewer
	t.Cleanup(func() {
		transportHostSystemPaths, transportHostLoadRole, transportHostBuildViewer = originalPaths, originalRole, originalViewer
	})
	transportHostSystemPaths = func() store.Paths { return store.Paths{} }
	transportHostLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	selectedAt := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	selection := model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1,
		CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: selectedAt,
	}
	viewer := &recordingHandshakeHostViewer{view: transport.HandshakeHostView{
		Active: selection, StateGeneration: 7,
		Health: transport.HandshakeHostHealth{
			Condition: transport.HealthHealthy, Code: "handshake-host-healthy", Selection: selection,
		},
	}}
	transportHostBuildViewer = func(store.Paths) (handshakeHostViewer, error) { return viewer, nil }

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"--json", "transport", "host", "show"}, &stdout, &stderr)
	if code != ExitSuccess || stderr.Len() != 0 || viewer.calls != 1 {
		t.Fatalf("transport host show code=%d calls=%d stdout=%q stderr=%q", code, viewer.calls, stdout.String(), stderr.String())
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	data, _ := document["data"].(map[string]any)
	if document["command"] != "transport.host.show" || document["status"] != "ok" ||
		data["active"] != "www.microsoft.com" || data["health"] != "healthy" || data["generation"] != float64(7) {
		t.Fatalf("transport host show document = %#v", document)
	}
	encoded := stdout.String()
	for _, forbidden := range []string{"password", "credential_ref", "private_key", "secret"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("transport host show output contains %q: %s", forbidden, encoded)
		}
	}
}

func TestExecuteTransportHostShowRejectsNodeBeforeBuildingViewer(t *testing.T) {
	originalPaths, originalRole, originalViewer := transportHostSystemPaths, transportHostLoadRole, transportHostBuildViewer
	t.Cleanup(func() {
		transportHostSystemPaths, transportHostLoadRole, transportHostBuildViewer = originalPaths, originalRole, originalViewer
	})
	transportHostSystemPaths = func() store.Paths { return store.Paths{} }
	transportHostLoadRole = func(store.Paths) (HostRole, error) { return RoleNode, nil }
	built := false
	transportHostBuildViewer = func(store.Paths) (handshakeHostViewer, error) {
		built = true
		return nil, errors.New("must not build")
	}

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"transport", "host", "show", "--json"}, &stdout, &stderr)
	if code != ExitValidation || built || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"code":"unsupported_role"`) {
		t.Fatalf("node transport host show code=%d built=%t stdout=%q stderr=%q", code, built, stdout.String(), stderr.String())
	}
}

func TestExecuteTransportHostShowValidatesArgumentsBeforeViewer(t *testing.T) {
	originalViewer := transportHostBuildViewer
	t.Cleanup(func() { transportHostBuildViewer = originalViewer })
	built := false
	transportHostBuildViewer = func(store.Paths) (handshakeHostViewer, error) {
		built = true
		return nil, errors.New("must not build")
	}

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"transport", "host", "show", "unexpected", "--json"}, &stdout, &stderr)
	if code != ExitValidation || built || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"code":"invalid_arguments"`) {
		t.Fatalf("invalid transport host show code=%d built=%t stdout=%q stderr=%q", code, built, stdout.String(), stderr.String())
	}
}

type recordingHandshakeHostViewer struct {
	view  transport.HandshakeHostView
	err   error
	calls int
}

func (viewer *recordingHandshakeHostViewer) Show(context.Context) (transport.HandshakeHostView, error) {
	viewer.calls++
	return viewer.view, viewer.err
}
