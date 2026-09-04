package main

import (
	"context"
	"fmt"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type systemV1MigrationWatchdog struct {
	watchdog   *operations.Watchdog
	store      *operations.WatchdogStore
	supervisor *operations.SystemdWatchdogSupervisor
	network    *linuxplatform.NetworkManager
}

func newSystemV1MigrationWatchdog(root string) (*systemV1MigrationWatchdog, error) {
	paths, err := store.NewPaths(root)
	if err != nil {
		return nil, err
	}
	runner := linuxplatform.OSProbeRunner{}
	supervisor := operations.NewSystemdWatchdogSupervisor(runner)
	network := linuxplatform.NewOSNetworkManager()
	watchdog, err := operations.NewWatchdog(paths, network, supervisor)
	if err != nil {
		return nil, err
	}
	transactionStore, err := operations.NewWatchdogStore(paths)
	if err != nil {
		return nil, err
	}
	return &systemV1MigrationWatchdog{watchdog: watchdog, store: transactionStore, supervisor: supervisor, network: network}, nil
}

func (watchdog *systemV1MigrationWatchdog) ArmPrepared(ctx context.Context, sshPort int, origin *linuxplatform.SSHConnection, prepared func(lifecycle.V1MigrationWatchdogTransaction) error) (lifecycle.V1MigrationWatchdogTransaction, error) {
	if watchdog == nil || watchdog.watchdog == nil || prepared == nil {
		return lifecycle.V1MigrationWatchdogTransaction{}, fmt.Errorf("migration watchdog is incomplete")
	}
	transaction, err := watchdog.watchdog.ArmWithPreparedHook(ctx, operations.WatchdogArmInput{
		AllowedSSHPort: sshPort, Origin: origin, NetworkScope: linuxplatform.GatewayInitNetworkScope(),
	}, func(transaction operations.WatchdogTransaction) error {
		return prepared(lifecycle.V1MigrationWatchdogTransaction{
			ID: transaction.ID, PriorNFTablesPresent: transaction.Network.NFTables.Present,
		})
	})
	if err != nil {
		return lifecycle.V1MigrationWatchdogTransaction{}, err
	}
	return lifecycle.V1MigrationWatchdogTransaction{
		ID: transaction.ID, PriorNFTablesPresent: transaction.Network.NFTables.Present,
	}, nil
}

func (watchdog *systemV1MigrationWatchdog) EnsureTimer(ctx context.Context, transactionID string) error {
	if watchdog == nil || watchdog.supervisor == nil {
		return fmt.Errorf("migration watchdog is incomplete")
	}
	return watchdog.supervisor.StartTimer(ctx, transactionID)
}

func (watchdog *systemV1MigrationWatchdog) MarkActivated(ctx context.Context, transactionID string) error {
	if watchdog == nil || watchdog.watchdog == nil {
		return fmt.Errorf("migration watchdog is incomplete")
	}
	return watchdog.watchdog.MarkActivated(ctx, transactionID)
}

func (watchdog *systemV1MigrationWatchdog) Status(_ context.Context, transactionID string) (lifecycle.V1MigrationWatchdogStatus, error) {
	if watchdog == nil || watchdog.store == nil {
		return "", fmt.Errorf("migration watchdog is incomplete")
	}
	status, err := watchdog.store.Status(transactionID)
	if err != nil {
		return "", err
	}
	switch status {
	case operations.WatchdogStatusArmed:
		return lifecycle.V1MigrationWatchdogArmed, nil
	case operations.WatchdogStatusActive:
		return lifecycle.V1MigrationWatchdogActive, nil
	case operations.WatchdogStatusCommitted:
		return lifecycle.V1MigrationWatchdogCommitted, nil
	case operations.WatchdogStatusRolledBack:
		return lifecycle.V1MigrationWatchdogRolledBack, nil
	default:
		return "", fmt.Errorf("unknown watchdog state %q", status)
	}
}

func (watchdog *systemV1MigrationWatchdog) Restore(ctx context.Context, transactionID string) error {
	if watchdog == nil || watchdog.store == nil || watchdog.supervisor == nil || watchdog.network == nil {
		return fmt.Errorf("migration watchdog is incomplete")
	}
	status, err := watchdog.store.Status(transactionID)
	if err != nil {
		return err
	}
	if err := watchdog.supervisor.StopTimer(ctx, transactionID); err != nil {
		return err
	}
	if status == operations.WatchdogStatusCommitted {
		transaction, err := watchdog.store.Load(transactionID)
		if err != nil {
			return err
		}
		return watchdog.network.Restore(ctx, transaction.Network)
	}
	return watchdog.store.Rollback(ctx, transactionID, watchdog.network, time.Now().UTC())
}

var _ lifecycle.V1MigrationNetworkWatchdog = (*systemV1MigrationWatchdog)(nil)
