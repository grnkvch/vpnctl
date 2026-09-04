package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestGatewayPurgeRequiresForceAndKeepsBackupsByDefault(t *testing.T) {
	state := uninstallGatewayState(t)
	runtime := newRecordingUninstallRuntime(model.RoleGateway)
	purger, _ := NewPurger(&memoryUninstallState{state: state}, runtime)
	blocked, err := purger.Plan(context.Background(), PurgeOptions{})
	if err != nil || !blocked.Blocked || !blocked.ForceRequired || blocked.IncludeBackups || len(blocked.Preserved) != 1 {
		t.Fatalf("blocked purge plan = %+v, %v", blocked, err)
	}
	if _, err := purger.Apply(context.Background(), blocked); !errors.Is(err, ErrUninstallForceRequired) {
		t.Fatalf("blocked purge Apply() error = %v", err)
	}
	if want := []string{"inspect", "inspect-purge"}; !reflect.DeepEqual(runtime.calls, want) {
		t.Fatalf("blocked purge calls = %v", runtime.calls)
	}

	runtime.calls = nil
	forced, err := purger.Plan(context.Background(), PurgeOptions{Force: true})
	if err != nil || forced.Blocked || !forced.Force {
		t.Fatalf("forced purge plan = %+v, %v", forced, err)
	}
	result, err := purger.Apply(context.Background(), forced)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"inspect", "inspect-purge", "inspect", "inspect-purge", "stop", "dns", "network", "purge-swap", "runtime", "data", "binary"}
	if !reflect.DeepEqual(runtime.calls, want) || !result.DataPurged || result.BackupsRemoved || !result.BinaryRemoved {
		t.Fatalf("forced purge result/calls = %+v / %v", result, runtime.calls)
	}
}

func TestGatewayPurgeIncludeBackupsRemovesArchives(t *testing.T) {
	state := uninstallGatewayState(t)
	runtime := newRecordingUninstallRuntime(model.RoleGateway)
	purger, _ := NewPurger(&memoryUninstallState{state: state}, runtime)
	plan, err := purger.Plan(context.Background(), PurgeOptions{Force: true, IncludeBackups: true})
	if err != nil || !plan.IncludeBackups || len(plan.Preserved) != 0 {
		t.Fatalf("include-backups plan = %+v, %v", plan, err)
	}
	result, err := purger.Apply(context.Background(), plan)
	if err != nil || !result.BackupsRemoved || !result.IncludeBackups {
		t.Fatalf("include-backups result = %+v, %v", result, err)
	}
}

func TestNodePurgeOnlineRevokesBeforeIrreversibleLocalMutation(t *testing.T) {
	state := enrolledNodeUpdateState(t, time.Now().UTC().Truncate(time.Second), 9, gatewayTestManifest())
	runtime := newRecordingUninstallRuntime(model.RoleNode)
	runtime.revocation = UninstallNodeRevocation{Confirmed: true, GatewayGeneration: 10}
	purger, _ := NewPurger(&memoryUninstallState{state: state}, runtime)
	plan, err := purger.Plan(context.Background(), PurgeOptions{})
	if err != nil || plan.NodeID != state.Nodes[0].ID || !plan.NodeRevokeRequired {
		t.Fatalf("online node purge plan = %+v, %v", plan, err)
	}
	result, err := purger.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"inspect", "inspect-purge", "inspect", "inspect-purge", "revoke", "stop", "dns", "network", "purge-swap", "runtime", "data", "binary"}
	if !reflect.DeepEqual(runtime.calls, want) || !result.NodeRevoked || result.GatewayGeneration != 10 {
		t.Fatalf("online node purge result/calls = %+v / %v", result, runtime.calls)
	}
}

func TestNodePurgeUnavailableGatewayLeavesLocalDataUntouched(t *testing.T) {
	state := enrolledNodeUpdateState(t, time.Now().UTC().Truncate(time.Second), 9, gatewayTestManifest())
	runtime := newRecordingUninstallRuntime(model.RoleNode)
	runtime.revokeErr = errors.New("offline")
	purger, _ := NewPurger(&memoryUninstallState{state: state}, runtime)
	plan, _ := purger.Plan(context.Background(), PurgeOptions{})
	if _, err := purger.Apply(context.Background(), plan); !errors.Is(err, ErrUninstallGatewayUnavailable) {
		t.Fatalf("offline purge error = %v", err)
	}
	if want := []string{"inspect", "inspect-purge", "inspect", "inspect-purge", "revoke"}; !reflect.DeepEqual(runtime.calls, want) {
		t.Fatalf("offline purge mutated local host: %v", runtime.calls)
	}
}

func TestNodePurgeLocalOnlySkipsGatewayAndRejectsBackupDeletion(t *testing.T) {
	state := enrolledNodeUpdateState(t, time.Now().UTC().Truncate(time.Second), 9, gatewayTestManifest())
	runtime := newRecordingUninstallRuntime(model.RoleNode)
	purger, _ := NewPurger(&memoryUninstallState{state: state}, runtime)
	if _, err := purger.Plan(context.Background(), PurgeOptions{IncludeBackups: true}); !errors.Is(err, ErrUninstallRoleFlag) {
		t.Fatalf("node include-backups error = %v", err)
	}
	runtime.calls = nil
	plan, err := purger.Plan(context.Background(), PurgeOptions{LocalOnly: true})
	if err != nil || !plan.LocalOnly {
		t.Fatalf("local-only purge plan = %+v, %v", plan, err)
	}
	result, err := purger.Apply(context.Background(), plan)
	if err != nil || result.NodeRevoked || !result.LocalOnly {
		t.Fatalf("local-only purge result = %+v, %v", result, err)
	}
	for _, call := range runtime.calls {
		if call == "revoke" {
			t.Fatalf("local-only purge contacted gateway: %v", runtime.calls)
		}
	}
}

func TestPurgeNeverRemovesBinaryWhenDataErasureFails(t *testing.T) {
	state := initialNodeState("91000000-0000-4000-8000-000000000004", time.Now().UTC().Truncate(time.Second), gatewayTestManifest(), []string{"192.0.2.53"})
	runtime := newRecordingUninstallRuntime(model.RoleNode)
	runtime.dataErr = errors.New("injected")
	purger, _ := NewPurger(&memoryUninstallState{state: state}, runtime)
	plan, _ := purger.Plan(context.Background(), PurgeOptions{})
	if _, err := purger.Apply(context.Background(), plan); err == nil {
		t.Fatal("purge succeeded despite data erasure failure")
	}
	if runtime.calls[len(runtime.calls)-1] != "data" {
		t.Fatalf("binary was not last: %v", runtime.calls)
	}
}
