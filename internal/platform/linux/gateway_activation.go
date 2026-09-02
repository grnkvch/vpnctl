package linux

import (
	"context"
	"fmt"
)

var gatewayInitSysctls = []SysctlSnapshot{
	{Name: "net.ipv4.conf.all.accept_redirects", Value: "0"},
	{Name: "net.ipv4.conf.all.rp_filter", Value: "1"},
	{Name: "net.ipv4.conf.all.src_valid_mark", Value: "1"},
	{Name: "net.ipv4.ip_forward", Value: "1"},
}

// GatewayInitNetworkScope is the complete mutable sysctl boundary used by
// gateway initialization. The nftables table and reserved route/rule ranges
// are already fixed by OwnedNetworkScope and cannot be broadened by callers.
func GatewayInitNetworkScope() OwnedNetworkScope {
	names := make([]string, len(gatewayInitSysctls))
	for index, sysctl := range gatewayInitSysctls {
		names[index] = sysctl.Name
	}
	return OwnedNetworkScope{Sysctls: names}
}

// ActivateGateway validates the complete nftables batch before mutation,
// installs only inet/vpnctl, and enables forwarding only after the fail-closed
// policy is active. Callers must arm the independent watchdog first.
func (manager *NetworkManager) ActivateGateway(ctx context.Context, firewall GatewayFirewallArtifact) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil {
		return fmt.Errorf("network manager is incomplete")
	}
	batch, err := firewall.Transaction(false)
	if err != nil {
		return fmt.Errorf("build gateway firewall transaction: %w", err)
	}
	if _, err := manager.runChecked(ctx, ProbeCommand{Name: "nft", Args: []string{"--check", "--file", "-"}, Stdin: batch}); err != nil {
		return fmt.Errorf("validate gateway firewall: %w", err)
	}
	if _, err := manager.runChecked(ctx, ProbeCommand{Name: "nft", Args: []string{"--file", "-"}, Stdin: batch}); err != nil {
		return fmt.Errorf("activate gateway firewall: %w", err)
	}
	for _, sysctl := range gatewayInitSysctls {
		if _, err := manager.runChecked(ctx, ProbeCommand{Name: "sysctl", Args: []string{"-q", "-w", sysctl.Name + "=" + sysctl.Value}}); err != nil {
			return fmt.Errorf("activate gateway sysctl %s: %w", sysctl.Name, err)
		}
	}
	return nil
}
