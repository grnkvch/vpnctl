package lifecycle

import (
	"context"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestManagedSwapLifecycleUninstallPersistsDisabledOwnershipAndPurgeDoesNotRewriteState(t *testing.T) {
	t.Parallel()

	root := newGatewaySystemRoot(t)
	paths, _ := store.NewPaths(root)
	layout, _ := NewGatewayLayoutInstaller(paths)
	plan, err := layout.PlanFresh()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := layout.Apply(plan); err != nil {
		t.Fatal(err)
	}
	stateStore, _ := store.NewStateStore(paths)
	state := initialGatewayState(
		gatewayTestHostID,
		time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC),
		linuxplatform.GatewayNetworkPlan{PublicIPv4: "8.8.8.8", ExternalInterface: "eth0", ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR},
		2222,
		gatewayTestManifest(),
	)
	state.Host.ManagedSwap = &model.ManagedSwap{
		Path: linuxplatform.ManagedSwapLogicalPath, SizeBytes: int64(linuxplatform.ManagedSwapSizeBytes), Enabled: true,
	}
	if err := stateStore.Save(0, state); err != nil {
		t.Fatal(err)
	}
	platform := &recordingManagedSwapLifecyclePlatform{}
	lifecycle, err := NewManagedSwapLifecycle(stateStore, platform)
	if err != nil {
		t.Fatal(err)
	}

	result, err := lifecycle.Uninstall(context.Background())
	if err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}
	if !result.Changed || result.Generation != 2 || platform.deactivateCalls != 1 || platform.lastPurge {
		t.Fatalf("uninstall result/platform = %+v/%+v", result, platform)
	}
	after, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != 2 || after.Host.ManagedSwap == nil || after.Host.ManagedSwap.Enabled || after.Host.ManagedSwap.Path != linuxplatform.ManagedSwapLogicalPath {
		t.Fatalf("state after uninstall = %+v", after.Host.ManagedSwap)
	}

	result, err = lifecycle.Uninstall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Generation != 2 || platform.deactivateCalls != 2 {
		t.Fatalf("idempotent uninstall = %+v calls=%d", result, platform.deactivateCalls)
	}

	result, err = lifecycle.Purge(context.Background())
	if err != nil {
		t.Fatalf("Purge() error = %v", err)
	}
	if !result.Changed || result.Generation != 2 || platform.deactivateCalls != 3 || !platform.lastPurge {
		t.Fatalf("purge result/platform = %+v/%+v", result, platform)
	}
	unchanged, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Generation != 2 || unchanged.Host.ManagedSwap == nil {
		t.Fatalf("swap sub-step rewrote state before outer purge: %+v", unchanged)
	}
}

func TestManagedSwapLifecycleWithoutOwnedResourceIsNoOp(t *testing.T) {
	t.Parallel()

	root := newGatewaySystemRoot(t)
	paths, _ := store.NewPaths(root)
	layout, _ := NewGatewayLayoutInstaller(paths)
	plan, _ := layout.PlanFresh()
	if _, err := layout.Apply(plan); err != nil {
		t.Fatal(err)
	}
	stateStore, _ := store.NewStateStore(paths)
	state := initialGatewayState(
		gatewayTestHostID,
		time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC),
		linuxplatform.GatewayNetworkPlan{PublicIPv4: "8.8.8.8", ExternalInterface: "eth0", ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR},
		2222,
		gatewayTestManifest(),
	)
	if err := stateStore.Save(0, state); err != nil {
		t.Fatal(err)
	}
	platform := &recordingManagedSwapLifecyclePlatform{}
	lifecycle, _ := NewManagedSwapLifecycle(stateStore, platform)
	result, err := lifecycle.Uninstall(context.Background())
	if err != nil || result.Changed || result.Generation != 1 || platform.deactivateCalls != 0 {
		t.Fatalf("Uninstall() = %+v, %v; platform=%+v", result, err, platform)
	}
	result, err = lifecycle.Purge(context.Background())
	if err != nil || result.Changed || result.Generation != 1 || platform.deactivateCalls != 0 {
		t.Fatalf("Purge() = %+v, %v; platform=%+v", result, err, platform)
	}
}

type recordingManagedSwapLifecyclePlatform struct {
	deactivateCalls int
	lastPurge       bool
}

func (platform *recordingManagedSwapLifecyclePlatform) Status(_ context.Context, owned *model.ManagedSwap) (linuxplatform.ManagedSwapStatus, error) {
	status := linuxplatform.ManagedSwapStatus{Drift: []string{}}
	if owned != nil {
		status.Owned = true
		status.Path = owned.Path
		status.SizeBytes = uint64(owned.SizeBytes)
		status.FilePresent = true
		status.Enabled = owned.Enabled
		status.Active = owned.Enabled
		status.UnitPresent = owned.Enabled
		status.Healthy = true
	}
	return status, nil
}

func (platform *recordingManagedSwapLifecyclePlatform) Deactivate(_ context.Context, _ model.ManagedSwap, purge bool) error {
	platform.deactivateCalls++
	platform.lastPurge = purge
	return nil
}
