package controller

import (
	"context"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

// SystemGatewayClientRuntime republishes the two gateway listener
// configurations after a client identity or credential transition. The
// authoritative transition happens first and is fail-closed; if publication
// fails, repair can retry this idempotent reconciliation from current state.
type SystemGatewayClientRuntime struct {
	state     *store.StateStore
	listeners *transport.GatewayListenerProvisioner
	roles     *linuxplatform.RoleSystemdInstaller
	runner    linuxplatform.ProbeRunner
}

func NewSystemGatewayClientRuntime(paths store.Paths, state *store.StateStore, secrets *store.SecretStore) (*SystemGatewayClientRuntime, error) {
	return newSystemGatewayClientRuntime(paths, state, secrets, linuxplatform.OSProbeRunner{}, wireguard.ExecRunner{})
}

func newSystemGatewayClientRuntime(
	paths store.Paths,
	state *store.StateStore,
	secrets *store.SecretStore,
	runner linuxplatform.ProbeRunner,
	keyRunner wireguard.Runner,
) (*SystemGatewayClientRuntime, error) {
	if state == nil || secrets == nil {
		return nil, fmt.Errorf("system gateway client runtime stores are required")
	}
	if runner == nil || keyRunner == nil {
		return nil, fmt.Errorf("system gateway client runtime runners are required")
	}
	listeners, err := transport.NewGatewayListenerProvisioner(secrets, keyRunner, nil)
	if err != nil {
		return nil, err
	}
	roles, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, runner)
	if err != nil {
		return nil, err
	}
	return &SystemGatewayClientRuntime{state: state, listeners: listeners, roles: roles, runner: runner}, nil
}

func (runtime *SystemGatewayClientRuntime) Reconcile(ctx context.Context) error {
	if ctx == nil || runtime == nil || runtime.state == nil || runtime.listeners == nil || runtime.roles == nil || runtime.runner == nil {
		return fmt.Errorf("system gateway client runtime is incomplete")
	}
	state, err := runtime.state.Load()
	if err != nil {
		return fmt.Errorf("load gateway client state: %w", err)
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return fmt.Errorf("system client reconciliation requires valid gateway state")
	}
	listenerFiles, err := runtime.listeners.Provision(ctx, state)
	if err != nil {
		return fmt.Errorf("render gateway client listeners: %w", err)
	}
	request, err := linuxplatform.RenderGatewayRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	if err != nil {
		return err
	}
	for _, file := range listenerFiles.ConfigFiles() {
		request.Configs = append(request.Configs, linuxplatform.RoleConfigFile{Name: file.Name, Content: file.Content})
	}
	if _, err := runtime.roles.Apply(ctx, request); err != nil {
		return fmt.Errorf("publish gateway client listeners: %w", err)
	}
	for _, unit := range []string{"vpnctl-standard.service", "vpnctl-restricted.service"} {
		result, runErr := runtime.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"restart", unit}})
		if runErr != nil || result.ExitCode != 0 {
			return fmt.Errorf("restart gateway client listener %s", unit)
		}
	}
	return nil
}
