package controller

import (
	"context"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

type gatewayInitWatchdogAdapter struct {
	watchdog *operations.Watchdog
}

func (adapter gatewayInitWatchdogAdapter) Arm(ctx context.Context, input lifecycle.GatewayInitWatchdogArm) (lifecycle.GatewayInitWatchdogTransaction, error) {
	transaction, err := adapter.watchdog.Arm(ctx, operations.WatchdogArmInput{
		AllowedSSHPort: input.AllowedSSHPort, Origin: input.Origin, NetworkScope: input.NetworkScope,
	})
	if err != nil {
		return lifecycle.GatewayInitWatchdogTransaction{}, err
	}
	return lifecycle.GatewayInitWatchdogTransaction{ID: transaction.ID}, nil
}

func (adapter gatewayInitWatchdogAdapter) MarkActivated(ctx context.Context, transactionID string) error {
	return adapter.watchdog.MarkActivated(ctx, transactionID)
}

func (adapter gatewayInitWatchdogAdapter) RollbackNow(ctx context.Context, transactionID string) error {
	return adapter.watchdog.RollbackNow(ctx, transactionID)
}

// NewSystemGatewayInitializer composes the production Linux adapters around
// the read-only snapshot and verified bundle manifest supplied by the caller.
// Host discovery remains outside so CLI dry-run and apply use one frozen view.
func NewSystemGatewayInitializer(paths store.Paths, snapshot linuxplatform.HostSnapshot, manifest model.ComponentManifest, binaryPath string) (*lifecycle.GatewayInitializer, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, fmt.Errorf("create gateway state store: %w", err)
	}
	layout, err := lifecycle.NewGatewayLayoutInstaller(paths)
	if err != nil {
		return nil, fmt.Errorf("create gateway layout installer: %w", err)
	}
	roleInstaller, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, fmt.Errorf("create gateway role installer: %w", err)
	}
	watchdogUnits, err := linuxplatform.NewWatchdogUnitInstaller(paths.Root, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, fmt.Errorf("create watchdog unit installer: %w", err)
	}
	watchdog, err := operations.NewSystemWatchdog(paths)
	if err != nil {
		return nil, fmt.Errorf("create gateway watchdog: %w", err)
	}
	managedSwap, err := linuxplatform.NewManagedSwapManager(paths.Root, paths.StateDir, linuxplatform.OSProbeRunner{})
	if err != nil {
		return nil, fmt.Errorf("create managed swap manager: %w", err)
	}
	secretStore, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, fmt.Errorf("create gateway identity secret store: %w", err)
	}
	identity, err := control.NewGatewayIdentityProvisioner(secretStore, control.GatewayIdentityRuntime{})
	if err != nil {
		return nil, fmt.Errorf("create gateway identity provisioner: %w", err)
	}
	publicCertificate, err := ingress.NewPublicCertificateProvisioner(secretStore, ingress.PublicCertificateRuntime{})
	if err != nil {
		return nil, fmt.Errorf("create public ingress certificate provisioner: %w", err)
	}
	handshakeHosts, err := transport.NewBundledHandshakeHostSelector()
	if err != nil {
		return nil, fmt.Errorf("create gateway handshake-host selector: %w", err)
	}
	listeners, err := transport.NewGatewayListenerProvisioner(secretStore, wireguard.ExecRunner{}, nil)
	if err != nil {
		return nil, fmt.Errorf("create gateway transport listener provisioner: %w", err)
	}
	binary := binaryPath
	if binary == "" {
		binary = linuxplatform.DefaultVPNCTLBinaryPath
	}
	return lifecycle.NewGatewayInitializer(lifecycle.GatewayInitRuntime{
		Paths: paths, Snapshot: snapshot, Manifest: manifest, BinaryPath: binary,
		State: stateStore, Layout: layout, Roles: roleInstaller, WatchdogUnits: watchdogUnits,
		Watchdog: gatewayInitWatchdogAdapter{watchdog: watchdog}, Network: linuxplatform.NewOSNetworkManager(), Swap: managedSwap, Identity: identity,
		PublicCertificate: publicCertificate,
		HandshakeHosts:    handshakeHosts, Transports: listeners,
	})
}
