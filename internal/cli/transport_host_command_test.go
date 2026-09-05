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
	resource, _ := data["resource"].(map[string]any)
	if document["command"] != "transport.host.show" || document["status"] != "ok" ||
		resource["active"] != "www.microsoft.com" || resource["health"] != "healthy" || resource["generation"] != float64(7) {
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

func TestExecuteTransportHostPrepareSupportsDryRunAndImmediateStaging(t *testing.T) {
	originalPaths, originalRole, originalManager := transportHostSystemPaths, transportHostLoadRole, transportHostBuildManager
	t.Cleanup(func() {
		transportHostSystemPaths, transportHostLoadRole, transportHostBuildManager = originalPaths, originalRole, originalManager
	})
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manager := newRecordingHandshakeHostGatewayManager()
	transportHostSystemPaths = func() store.Paths { return paths }
	transportHostLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	transportHostBuildManager = func(store.Paths) (HandshakeHostGatewayManager, error) { return manager, nil }

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"--json", "transport", "host", "prepare", "www.apple.com", "--dry-run"}, &stdout, &stderr)
	if code != ExitSuccess || stderr.Len() != 0 || manager.planPrepareCalls != 1 || manager.prepareCalls != 0 {
		t.Fatalf("dry-run prepare code=%d calls=%d/%d stdout=%q stderr=%q", code, manager.planPrepareCalls, manager.prepareCalls, stdout.String(), stderr.String())
	}
	for _, fragment := range []string{`"command":"transport.host.prepare"`, `"changed":true`, `"candidate":"www.apple.com"`, lifecycleCLINodeID, lifecycleCLIClientID} {
		if !strings.Contains(stdout.String(), fragment) {
			t.Fatalf("dry-run output lacks %q: %s", fragment, stdout.String())
		}
	}

	stdout.Reset()
	code = Execute([]string{"transport", "host", "prepare", "www.apple.com", "--json"}, &stdout, &stderr)
	if code != ExitSuccess || stderr.Len() != 0 || manager.planPrepareCalls != 2 || manager.prepareCalls != 1 {
		t.Fatalf("immediate prepare code=%d calls=%d/%d stdout=%q stderr=%q", code, manager.planPrepareCalls, manager.prepareCalls, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"pending"`) || !strings.Contains(stdout.String(), `"code":"commit_handshake_host"`) {
		t.Fatalf("immediate prepare output = %s", stdout.String())
	}
}

func TestExecuteTransportHostPrepareRejectsRoleAndArgumentsBeforeBuildingManager(t *testing.T) {
	originalPaths, originalRole, originalManager := transportHostSystemPaths, transportHostLoadRole, transportHostBuildManager
	t.Cleanup(func() {
		transportHostSystemPaths, transportHostLoadRole, transportHostBuildManager = originalPaths, originalRole, originalManager
	})
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	transportHostSystemPaths = func() store.Paths { return paths }
	built := false
	transportHostBuildManager = func(store.Paths) (HandshakeHostGatewayManager, error) {
		built = true
		return nil, errors.New("must not build")
	}

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"transport", "host", "prepare", "www.apple.com", "extra", "--json"}, &stdout, &stderr)
	if code != ExitValidation || built || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"code":"invalid_arguments"`) {
		t.Fatalf("invalid prepare code=%d built=%t stdout=%q stderr=%q", code, built, stdout.String(), stderr.String())
	}
	stdout.Reset()
	code = Execute([]string{"transport", "host", "prepare", "WWW.Example.COM", "--json"}, &stdout, &stderr)
	if code != ExitValidation || built || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"code":"invalid_arguments"`) {
		t.Fatalf("non-canonical prepare code=%d built=%t stdout=%q stderr=%q", code, built, stdout.String(), stderr.String())
	}

	stdout.Reset()
	transportHostLoadRole = func(store.Paths) (HostRole, error) { return RoleNode, nil }
	code = Execute([]string{"transport", "host", "prepare", "www.apple.com", "--json"}, &stdout, &stderr)
	if code != ExitValidation || built || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"code":"transport_host_invalid"`) {
		t.Fatalf("node prepare code=%d built=%t stdout=%q stderr=%q", code, built, stdout.String(), stderr.String())
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
