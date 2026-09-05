package operations

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestStagedNodeRoleConvergenceSnapshotCoversExactInstalledResources(t *testing.T) {
	t.Parallel()

	request, err := linuxplatform.RenderNodeRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := StagedNodeRoleConvergenceSnapshot(1, request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot.Desired, snapshot.Applied) || snapshot.Pending == nil || len(snapshot.Pending) != 0 || len(snapshot.Applied.Resources) != 5 {
		t.Fatalf("initial node snapshot = %+v", snapshot)
	}
	wantIDs := []string{
		"role.node\x00file\x00/etc/vpnctl/generated/node/bootstrap.conf",
		"role.node\x00unit\x00vpnctl-routing-guard.service",
		"role.node\x00unit\x00vpnctl-routing.service",
		"role.node\x00unit\x00vpnctl-standard.service",
		"role.node\x00unit\x00vpnctl-tunnel-client.service",
	}
	gotIDs := make([]string, len(snapshot.Applied.Resources))
	for index, resource := range snapshot.Applied.Resources {
		gotIDs[index] = resourceOrder(resource.Key)
		if resource.ApplyImpact != ConvergenceImpactAvailability || resource.RemoveImpact != ConvergenceImpactAvailability {
			t.Fatalf("resource impact = %+v", resource)
		}
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("resource IDs = %q, want %q", gotIDs, wantIDs)
	}
	encoded, _ := json.Marshal(snapshot)
	if strings.Contains(string(encoded), "enrollment_status=unjoined") || strings.Contains(string(encoded), "ExecStart=") {
		t.Fatalf("convergence snapshot exposed rendered material: %s", encoded)
	}
}

func TestNodeInitializationConvergencePublisherIsIdempotentAndRejectsDifferentBaseline(t *testing.T) {
	t.Parallel()

	path := newConvergenceSnapshotStorePath(t)
	store, _ := NewFileConvergenceSnapshotStore(path)
	publisher, err := NewNodeInitializationConvergencePublisher(store)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := linuxplatform.RenderNodeRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	if err := publisher.PublishNodeInitialization(context.Background(), 1, request); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := publisher.PublishNodeInitialization(context.Background(), 1, request); err != nil {
		t.Fatalf("idempotent publish: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("idempotent publication rewrote baseline")
	}
	request.Configs[0].Content = []byte("schema_version=1\nrole=node\nchanged=true\n")
	if err := publisher.PublishNodeInitialization(context.Background(), 1, request); !errors.Is(err, ErrConvergenceSnapshotConflict) {
		t.Fatalf("different baseline error = %v", err)
	}
	final, _ := os.ReadFile(path)
	if !reflect.DeepEqual(before, final) {
		t.Fatal("conflicting publication changed baseline")
	}
}

func TestStagedNodeRoleConvergenceSnapshotRejectsActivatingOrMalformedRequest(t *testing.T) {
	t.Parallel()

	request, _ := linuxplatform.RenderNodeRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	request.Units[0].Enable = true
	if _, err := StagedNodeRoleConvergenceSnapshot(1, request); err == nil {
		t.Fatal("enabled node unit was accepted as staged baseline")
	}
	request, _ = linuxplatform.RenderNodeRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	request.Configs[0].Name = filepath.Join("..", "escape")
	if _, err := StagedNodeRoleConvergenceSnapshot(1, request); err == nil {
		t.Fatal("escaping node config was accepted")
	}
}
