package operations

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

func TestInitialGatewayRoleConvergenceSnapshotCoversExactServiceSet(t *testing.T) {
	t.Parallel()

	request := initialGatewayConvergenceRequest(t)
	snapshot, err := InitialGatewayRoleConvergenceSnapshot(1, request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot.Desired, snapshot.Applied) || snapshot.Pending == nil || len(snapshot.Pending) != 0 || len(snapshot.Applied.Resources) != 13 {
		t.Fatalf("initial gateway snapshot = %+v", snapshot)
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
		activeState, subState := "active", "running"
		if unit.Name == "vpnctl-tunnel-server.service" {
			activeState, subState = "inactive", "dead"
		}
		want, err := ManagedUnitRuntimeFingerprint(ManagedUnitRuntime{
			FileType: "regular", Mode: "0644", ContentSHA256: ManagedFingerprint(content),
			LoadState: "loaded", ActiveState: activeState, SubState: subState, Enablement: "enabled",
		})
		if err != nil || resource.RuntimeSHA256 != want {
			t.Fatalf("gateway unit resource %s = %+v, want %s (%v)", unit.Name, resource, want, err)
		}
	}
	encoded, _ := json.Marshal(snapshot)
	if strings.Contains(string(encoded), "private = rendered-secret") || strings.Contains(string(encoded), "ExecStart=") {
		t.Fatalf("gateway snapshot exposed rendered material: %s", encoded)
	}
}

func TestActiveGatewayRoleConvergenceSnapshotIncludesTunnelGeneration(t *testing.T) {
	t.Parallel()

	request := activeGatewayConvergenceRequest(t)
	snapshot, err := ActiveGatewayRoleConvergenceSnapshot(3, request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshot.Desired, snapshot.Applied) || len(snapshot.Applied.Resources) != 17 {
		t.Fatalf("active gateway snapshot = %+v", snapshot)
	}
	encoded, _ := json.Marshal(snapshot)
	if strings.Contains(string(encoded), "private\\n") || strings.Contains(string(encoded), "certificate\\n") || strings.Contains(string(encoded), "server\\n") {
		t.Fatalf("active gateway snapshot exposed rendered material: %s", encoded)
	}
	for _, resource := range snapshot.Applied.Resources {
		if resource.Key.Kind != ManagedResourceUnit || resource.Key.ID != "vpnctl-tunnel-server.service" {
			continue
		}
		unit := request.Units[0]
		for _, candidate := range request.Units {
			if candidate.Name == resource.Key.ID {
				unit = candidate
				break
			}
		}
		content := append([]byte(nil), unit.Content...)
		if content[len(content)-1] != '\n' {
			content = append(content, '\n')
		}
		want, err := ManagedUnitRuntimeFingerprint(ManagedUnitRuntime{
			FileType: "regular", Mode: "0644", ContentSHA256: ManagedFingerprint(content),
			LoadState: "loaded", ActiveState: "active", SubState: "running", Enablement: "enabled",
		})
		if err != nil || resource.RuntimeSHA256 != want {
			t.Fatalf("active tunnel unit = %+v, want %s (%v)", resource, want, err)
		}
		return
	}
	t.Fatal("active gateway snapshot has no tunnel-server unit")
}

func TestGatewayInitializationConvergencePublisherIsIdempotentAndConflicting(t *testing.T) {
	t.Parallel()

	path := newConvergenceSnapshotStorePath(t)
	store, _ := NewFileConvergenceSnapshotStore(path)
	publisher, err := NewGatewayInitializationConvergencePublisher(store)
	if err != nil {
		t.Fatal(err)
	}
	request := initialGatewayConvergenceRequest(t)
	if err := publisher.PublishGatewayInitialization(context.Background(), 1, request); err != nil {
		t.Fatal(err)
	}
	if err := publisher.PublishGatewayInitialization(context.Background(), 1, request); err != nil {
		t.Fatalf("idempotent gateway publish: %v", err)
	}
	got, err := store.Read(context.Background())
	if err != nil || got.Applied.Generation != 1 || len(got.Applied.Resources) != 13 {
		t.Fatalf("gateway baseline = %+v, %v", got, err)
	}
	changed := cloneGatewayRoleRequest(request)
	changed.Configs[0].Content = []byte("changed\n")
	if err := publisher.PublishGatewayInitialization(context.Background(), 1, changed); !errors.Is(err, ErrConvergenceSnapshotConflict) {
		t.Fatalf("changed gateway baseline error = %v", err)
	}
}

func TestGatewayServiceConvergencePreparationRollsBackOrCommitsExactCAS(t *testing.T) {
	t.Parallel()

	path := newConvergenceSnapshotStorePath(t)
	store, _ := NewFileConvergenceSnapshotStore(path)
	initial, _ := InitialGatewayRoleConvergenceSnapshot(1, initialGatewayConvergenceRequest(t))
	if err := store.Initialize(context.Background(), initial); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewGatewayServiceConvergencePublisher(store)
	if err != nil {
		t.Fatal(err)
	}
	request := activeGatewayConvergenceRequest(t)
	prepared, err := publisher.PrepareActiveGatewayGeneration(context.Background(), 3, request)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Read(context.Background()); got.Applied.Generation != 3 {
		t.Fatalf("staged generation = %d", got.Applied.Generation)
	}
	if err := prepared.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Read(context.Background()); !reflect.DeepEqual(got, initial) {
		t.Fatalf("rolled back gateway baseline = %+v, want %+v", got, initial)
	}

	prepared, err = publisher.PrepareActiveGatewayGeneration(context.Background(), 3, request)
	if err != nil {
		t.Fatal(err)
	}
	prepared.Commit()
	if err := prepared.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback after commit: %v", err)
	}
	if got, _ := store.Read(context.Background()); got.Applied.Generation != 3 {
		t.Fatalf("committed generation = %d", got.Applied.Generation)
	}
	if _, err := publisher.PrepareActiveGatewayGeneration(context.Background(), 3, request); err != nil {
		t.Fatalf("idempotent stage: %v", err)
	}
	changed := cloneGatewayRoleRequest(request)
	changed.Configs[0].Content = []byte("changed\n")
	if _, err := publisher.PrepareActiveGatewayGeneration(context.Background(), 3, changed); !errors.Is(err, ErrConvergenceSnapshotConflict) {
		t.Fatalf("changed same-generation stage error = %v", err)
	}
}

func TestGatewayServiceConvergenceRecoveryCanReconstructMissingOrAdvanceOlderBaseline(t *testing.T) {
	t.Parallel()

	request := activeGatewayConvergenceRequest(t)
	for _, seed := range []bool{false, true} {
		path := newConvergenceSnapshotStorePath(t)
		store, _ := NewFileConvergenceSnapshotStore(path)
		if seed {
			initial, _ := InitialGatewayRoleConvergenceSnapshot(1, initialGatewayConvergenceRequest(t))
			if err := store.Initialize(context.Background(), initial); err != nil {
				t.Fatal(err)
			}
		}
		publisher, _ := NewGatewayServiceConvergencePublisher(store)
		if err := publisher.PublishActiveGatewayGeneration(context.Background(), 3, request); err != nil {
			t.Fatalf("seed=%t publish: %v", seed, err)
		}
		got, err := store.Read(context.Background())
		if err != nil || got.Applied.Generation != 3 || len(got.Applied.Resources) != 17 {
			t.Fatalf("seed=%t recovered = %+v, %v", seed, got, err)
		}
	}
}

func TestGatewayServiceConvergenceRefusesPendingOrNewerBaseline(t *testing.T) {
	t.Parallel()

	initial, _ := InitialGatewayRoleConvergenceSnapshot(1, initialGatewayConvergenceRequest(t))
	desiredResources := append([]ManagedResource(nil), initial.Desired.Resources...)
	desiredResources[0].RevisionSHA256 = ManagedFingerprint([]byte("pending revision"))
	desired, _ := NewConvergenceManifest(2, desiredResources)
	pending := ConvergenceSnapshot{
		Desired: desired,
		Applied: cloneManifest(initial.Applied),
		Pending: []PendingOperation{{
			ID: "pending-gateway-change", Type: "transport-switch", TargetKind: "gateway", TargetID: "gateway",
			ExpectedGeneration: 1, DesiredGeneration: 2,
			Resources: []ManagedResourceKey{desiredResources[0].Key},
		}},
	}
	path := newConvergenceSnapshotStorePath(t)
	store, _ := NewFileConvergenceSnapshotStore(path)
	if err := store.Initialize(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	publisher, _ := NewGatewayServiceConvergencePublisher(store)
	if _, err := publisher.PrepareActiveGatewayGeneration(context.Background(), 3, activeGatewayConvergenceRequest(t)); !errors.Is(err, ErrConvergenceSnapshotConflict) {
		t.Fatalf("pending gateway baseline error = %v", err)
	}
}

func TestInitialGatewayRoleConvergenceSnapshotRejectsIncompleteOrTunnelActiveRequest(t *testing.T) {
	t.Parallel()

	request := initialGatewayConvergenceRequest(t)
	request.Configs = request.Configs[:len(request.Configs)-1]
	if _, err := InitialGatewayRoleConvergenceSnapshot(1, request); err == nil {
		t.Fatal("incomplete gateway config set was accepted")
	}
	request = initialGatewayConvergenceRequest(t)
	request.Configs = append(request.Configs, linuxplatform.RoleConfigFile{Name: tunnel.FRPServerReadyFileName, Content: []byte("ready\n")})
	if _, err := InitialGatewayRoleConvergenceSnapshot(1, request); err == nil {
		t.Fatal("active tunnel marker was accepted in initial gateway baseline")
	}
}

func initialGatewayConvergenceRequest(t *testing.T) linuxplatform.RoleInstallationRequest {
	t.Helper()
	request, err := linuxplatform.RenderGatewayRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	request.Configs = append(request.Configs,
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSConfigFileName, Content: []byte("dns\n")},
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSReadyFileName, Content: []byte("ready\n")},
	)
	for _, name := range transport.GatewayListenerFileNames() {
		content := []byte("ready\n")
		if name == transport.StandardConfigFileName || name == transport.RestrictedConfigFileName {
			content = []byte("private = rendered-secret\n")
		}
		request.Configs = append(request.Configs, linuxplatform.RoleConfigFile{Name: name, Content: content})
	}
	return request
}

func activeGatewayConvergenceRequest(t *testing.T) linuxplatform.RoleInstallationRequest {
	t.Helper()
	request := initialGatewayConvergenceRequest(t)
	request.Configs = append(request.Configs,
		linuxplatform.RoleConfigFile{Name: tunnel.FRPServerConfigFileName, Content: []byte("server\n")},
		linuxplatform.RoleConfigFile{Name: tunnel.FRPServerReadyFileName, Content: []byte("ready\n")},
		linuxplatform.RoleConfigFile{Name: tunnel.FRPServerCertificateName, Content: []byte("certificate\n")},
		linuxplatform.RoleConfigFile{Name: tunnel.FRPServerPrivateKeyName, Content: []byte("private\n")},
	)
	return request
}

func cloneGatewayRoleRequest(request linuxplatform.RoleInstallationRequest) linuxplatform.RoleInstallationRequest {
	result := request
	result.Units = append([]linuxplatform.RoleUnitFile{}, request.Units...)
	result.Configs = cloneRoleConfigs(request.Configs)
	return result
}
