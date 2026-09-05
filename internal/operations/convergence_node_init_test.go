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

func TestActiveNodeRoleConvergenceSnapshotCapturesEnabledRuntime(t *testing.T) {
	t.Parallel()

	request, _ := linuxplatform.RenderNodeRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	for index := range request.Units {
		request.Units[index].Enable = true
	}
	request.Configs = append(request.Configs,
		linuxplatform.RoleConfigFile{Name: "node-standard.ready", Content: []byte("generation=2\n")},
		linuxplatform.RoleConfigFile{Name: "standard.conf", Content: []byte("private-key-not-serialized\n")},
	)
	snapshot, err := ActiveNodeRoleConvergenceSnapshot(2, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Applied.Resources) != 7 {
		t.Fatalf("active node resource count = %d", len(snapshot.Applied.Resources))
	}
	encoded, _ := json.Marshal(snapshot)
	if strings.Contains(string(encoded), "private-key-not-serialized") {
		t.Fatalf("active snapshot exposed config material: %s", encoded)
	}
	for _, resource := range snapshot.Applied.Resources {
		if resource.Key.Kind != ManagedResourceUnit {
			continue
		}
		unit := request.Units[0]
		for _, candidate := range request.Units {
			if candidate.Name == resource.Key.ID {
				unit = candidate
				break
			}
		}
		content := unit.Content
		if content[len(content)-1] != '\n' {
			content = append(append([]byte{}, content...), '\n')
		}
		subState := "running"
		if unit.Name == "vpnctl-routing-guard.service" {
			subState = "exited"
		}
		want, err := ManagedUnitRuntimeFingerprint(ManagedUnitRuntime{
			FileType: "regular", Mode: "0644", ContentSHA256: ManagedFingerprint(content),
			LoadState: "loaded", ActiveState: "active", SubState: subState, Enablement: "enabled",
		})
		if err != nil || resource.RuntimeSHA256 != want {
			t.Fatalf("active unit resource %s = %+v, want %s (%v)", unit.Name, resource, want, err)
		}
	}
}

func TestNodeServiceConvergencePublisherAdvancesAndRecoversExactGeneration(t *testing.T) {
	t.Parallel()

	request, _ := linuxplatform.RenderNodeRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	configs := []linuxplatform.RoleConfigFile{{Name: "node-standard.ready", Content: []byte("generation=2\n")}}
	for _, missing := range []bool{false, true} {
		name := "advance"
		if missing {
			name = "recover-missing"
		}
		t.Run(name, func(t *testing.T) {
			path := newConvergenceSnapshotStorePath(t)
			store, _ := NewFileConvergenceSnapshotStore(path)
			if !missing {
				initial, _ := StagedNodeRoleConvergenceSnapshot(1, request)
				if err := store.Initialize(context.Background(), initial); err != nil {
					t.Fatal(err)
				}
			}
			publisher, err := NewNodeServiceConvergencePublisher(store, linuxplatform.DefaultVPNCTLBinaryPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := publisher.PublishActiveNodeGeneration(context.Background(), 2, configs); err != nil {
				t.Fatal(err)
			}
			if err := publisher.PublishActiveNodeGeneration(context.Background(), 2, configs); err != nil {
				t.Fatalf("idempotent active publish: %v", err)
			}
			got, err := store.Read(context.Background())
			if err != nil || got.Applied.Generation != 2 || !reflect.DeepEqual(got.Desired, got.Applied) || len(got.Applied.Resources) != 6 {
				t.Fatalf("active baseline = %+v, %v", got, err)
			}
			changed := cloneRoleConfigs(configs)
			changed[0].Content = []byte("generation=2\nchanged=true\n")
			if err := publisher.PublishActiveNodeGeneration(context.Background(), 2, changed); !errors.Is(err, ErrConvergenceSnapshotConflict) {
				t.Fatalf("changed same-generation baseline error = %v", err)
			}
		})
	}
}
