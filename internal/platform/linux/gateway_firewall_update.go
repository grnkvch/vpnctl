package linux

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// GatewayFirewallUpdate retains the exact previously owned inet/vpnctl table
// until the caller commits the authoritative state transition. Rollback is
// retryable when restoring the snapshot fails.
type GatewayFirewallUpdate interface {
	Commit()
	Rollback(context.Context) error
}

// PrepareGatewayFirewallUpdate atomically replaces an existing, structurally
// validated inet/vpnctl table and returns an exact rollback handle. Callers
// must serialize the operation with the authoritative Gateway mutation lock;
// this method never creates an ownership claim for an absent table.
func (manager *NetworkManager) PrepareGatewayFirewallUpdate(
	ctx context.Context,
	firewall GatewayFirewallArtifact,
) (GatewayFirewallUpdate, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil {
		return nil, fmt.Errorf("network manager is incomplete")
	}
	batch, err := firewall.Transaction(true)
	if err != nil {
		return nil, fmt.Errorf("build gateway firewall update: %w", err)
	}
	prior, err := manager.snapshotNFTables(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot gateway firewall before update: %w", err)
	}
	if !prior.Present {
		return nil, fmt.Errorf("existing owned gateway firewall is required")
	}
	if _, err := manager.runChecked(ctx, ProbeCommand{Name: "nft", Args: []string{"--check", "--file", "-"}, Stdin: batch}); err != nil {
		return nil, fmt.Errorf("validate gateway firewall update: %w", err)
	}
	if _, err := manager.runChecked(ctx, ProbeCommand{Name: "nft", Args: []string{"--file", "-"}, Stdin: batch}); err != nil {
		return nil, fmt.Errorf("apply gateway firewall update: %w", err)
	}
	return &gatewayFirewallUpdate{manager: manager, prior: prior}, nil
}

type gatewayFirewallUpdate struct {
	mu       sync.Mutex
	manager  *NetworkManager
	prior    NFTablesSnapshot
	finished bool
}

func (update *gatewayFirewallUpdate) Commit() {
	if update == nil {
		return
	}
	update.mu.Lock()
	defer update.mu.Unlock()
	if update.finished {
		return
	}
	update.finished = true
	update.prior = NFTablesSnapshot{}
}

func (update *gatewayFirewallUpdate) Rollback(ctx context.Context) error {
	if update == nil || ctx == nil {
		return fmt.Errorf("gateway firewall update rollback is incomplete")
	}
	update.mu.Lock()
	defer update.mu.Unlock()
	if update.finished {
		return nil
	}
	if update.manager == nil {
		return fmt.Errorf("gateway firewall update manager is unavailable")
	}
	if err := update.manager.restoreNFTables(ctx, update.prior); err != nil {
		return errors.Join(fmt.Errorf("restore gateway firewall before join"), err)
	}
	update.finished = true
	update.prior = NFTablesSnapshot{}
	return nil
}

var _ GatewayFirewallUpdate = (*gatewayFirewallUpdate)(nil)
