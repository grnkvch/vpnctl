package controller

import (
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

// NewSystemNodeInitializer composes only node-local adapters. It deliberately
// omits the gateway network activator and lockout-watchdog dependencies because
// role-only node initialization does not modify routing or firewall state.
func NewSystemNodeInitializer(paths store.Paths, snapshot linuxplatform.HostSnapshot, release lifecycle.InitReleaseSource, binaryPath string) (*lifecycle.NodeInitializer, error) {
	if release == nil {
		return nil, fmt.Errorf("create node initializer: local release bundle is required")
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, fmt.Errorf("create node state store: %w", err)
	}
	layout, err := lifecycle.NewNodeLayoutInstaller(paths)
	if err != nil {
		return nil, fmt.Errorf("create node layout installer: %w", err)
	}
	roleInstaller, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, fmt.Errorf("create node role installer: %w", err)
	}
	binary := binaryPath
	if binary == "" {
		binary = linuxplatform.DefaultVPNCTLBinaryPath
	}
	return lifecycle.NewNodeInitializer(lifecycle.NodeInitRuntime{
		Paths: paths, Snapshot: snapshot, Release: release, BinaryPath: binary,
		State: stateStore, Layout: layout, Roles: roleInstaller,
	})
}
