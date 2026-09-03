package routing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	NodeRoutingGuardInstallAction   = "install"
	NodeRoutingGuardNotReadyAction  = "not-ready"
	NodeRoutingGuardWaitReadyAction = "wait-ready"

	nodeRoutingGuardReadyTimeout = 15 * time.Second
	nodeRoutingGuardPollInterval = 250 * time.Millisecond
)

type NodeRoutingGuardManager struct {
	runner  linuxplatform.ProbeRunner
	network *linuxplatform.NetworkManager
	wait    func(context.Context, time.Duration) error
}

func NewNodeRoutingGuardManager(runner linuxplatform.ProbeRunner) (*NodeRoutingGuardManager, error) {
	if runner == nil {
		return nil, fmt.Errorf("node routing guard runner is required")
	}
	network, err := linuxplatform.NewNetworkManager(runner)
	if err != nil {
		return nil, err
	}
	return &NodeRoutingGuardManager{runner: runner, network: network, wait: waitNodeRoutingGuardInterval}, nil
}

// Install puts the fail-closed boundary in place before the userspace routing
// engine can start. A partial failure restores the exact prior vpnctl-owned
// table, route tables, policy priorities, and affected sysctls.
func (manager *NodeRoutingGuardManager) Install(ctx context.Context, candidate NodeRoutingGuardCandidate) (returnErr error) {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil || manager.network == nil {
		return fmt.Errorf("node routing guard manager is incomplete")
	}
	config := candidate.Config()
	if err := config.Validate(); err != nil {
		return err
	}
	if len(candidate.NFTablesDefinition()) == 0 {
		return fmt.Errorf("node routing guard candidate has no nftables definition")
	}
	scope := linuxplatform.OwnedNetworkScope{Sysctls: []string{
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.all.src_valid_mark",
		"net.ipv4.conf." + config.DirectRoute.Interface + ".rp_filter",
	}}
	if config.ActiveTransport == model.TransportStandard && config.DirectRoute.Interface != NodeRoutingStandardInterface {
		scope.Sysctls = append(scope.Sysctls, "net.ipv4.conf."+NodeRoutingStandardInterface+".rp_filter")
	}
	prior, err := manager.network.Snapshot(ctx, scope)
	if err != nil {
		return fmt.Errorf("snapshot node routing guard state: %w", err)
	}
	if err := validatePriorNodeRoutingGuardOwnership(prior); err != nil {
		return err
	}
	mutated := false
	defer func() {
		if returnErr == nil || !mutated {
			return
		}
		restoreContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if restoreErr := manager.network.Restore(restoreContext, prior); restoreErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("restore prior node routing guard state: %w", restoreErr))
		}
	}()

	for _, name := range scope.Sysctls {
		mutated = true
		if err := manager.runChecked(ctx, linuxplatform.ProbeCommand{Name: "sysctl", Args: []string{"-q", "-w", name + "=1"}}); err != nil {
			return fmt.Errorf("enable node routing guard sysctl %s: %w", name, err)
		}
	}
	selectedRoute := []string{"-4", "route", "replace", "unreachable", "default", "metric", strconv.Itoa(linuxplatform.VPNCTLUnreachableRouteMetric), "table", linuxplatform.VPNCTLSelectedRouteTable, "proto", "static"}
	if err := manager.runChecked(ctx, linuxplatform.ProbeCommand{Name: "ip", Args: selectedRoute}); err != nil {
		return fmt.Errorf("install selected unreachable route: %w", err)
	}
	for _, route := range nodeRoutingGatewayRoutes(config) {
		if err := manager.runChecked(ctx, linuxplatform.ProbeCommand{Name: "ip", Args: route}); err != nil {
			return fmt.Errorf("install gateway recovery route: %w", err)
		}
	}
	for _, rule := range nodeRoutingPolicyRules() {
		if priorHasPolicyRule(prior, rule.priority) {
			continue
		}
		arguments := []string{"-4", "rule", "add", "priority", strconv.Itoa(rule.priority), "fwmark", rule.mark + "/" + nftMark(linuxplatform.VPNCTLMarkMask), "table", rule.table}
		if err := manager.runChecked(ctx, linuxplatform.ProbeCommand{Name: "ip", Args: arguments}); err != nil {
			return fmt.Errorf("install node routing policy rule %d: %w", rule.priority, err)
		}
	}
	nftables := candidate.NFTablesDefinition()
	if prior.NFTables.Present {
		nftables = append([]byte("delete table "+linuxplatform.VPNCTLNFTablesFamily+" "+linuxplatform.VPNCTLNFTablesTable+"\n"), nftables...)
	}
	if err := manager.applyNFTablesBatch(ctx, nftables); err != nil {
		return fmt.Errorf("install node routing guard table: %w", err)
	}
	return nil
}

func nodeRoutingGatewayRoutes(config NodeRoutingGuardConfig) [][]string {
	base := []string{"-4", "route", "replace"}
	if config.ActiveTransport == "" {
		route := append(append([]string(nil), base...), "default")
		if config.DirectRoute.GatewayIPv4 != "" {
			route = append(route, "via", config.DirectRoute.GatewayIPv4)
		}
		return [][]string{append(route, "dev", config.DirectRoute.Interface, "table", linuxplatform.VPNCTLGatewayRouteTable, "proto", "static")}
	}
	recovery := append(append([]string(nil), base...), config.GatewayIPv4+"/32")
	if config.DirectRoute.GatewayIPv4 != "" {
		recovery = append(recovery, "via", config.DirectRoute.GatewayIPv4)
	}
	recovery = append(recovery, "dev", config.DirectRoute.Interface, "table", linuxplatform.VPNCTLGatewayRouteTable, "proto", "static")
	var fallback []string
	if config.ActiveTransport == model.TransportStandard {
		fallback = append(append([]string(nil), base...), "default", "dev", NodeRoutingStandardInterface,
			"table", linuxplatform.VPNCTLGatewayRouteTable, "proto", "static")
	} else {
		fallback = append(append([]string(nil), base...), "unreachable", "default", "metric",
			strconv.Itoa(linuxplatform.VPNCTLUnreachableRouteMetric), "table", linuxplatform.VPNCTLGatewayRouteTable, "proto", "static")
	}
	return [][]string{recovery, fallback}
}

// NotReady closes the classifier first and only then removes the low-metric
// TUN route. It is safe to repeat after a routing-process crash or failed boot.
func (manager *NodeRoutingGuardManager) NotReady(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil {
		return fmt.Errorf("node routing guard manager is incomplete")
	}
	if err := manager.assertOwnedTable(ctx); err != nil {
		return err
	}
	if err := manager.switchReadiness(ctx, "not_ready"); err != nil {
		return err
	}
	result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "ip", Args: []string{
		"-4", "route", "del", "default", "dev", NodeRoutingTUNDevice,
		"metric", strconv.Itoa(linuxplatform.VPNCTLReadyTUNRouteMetric), "table", linuxplatform.VPNCTLSelectedRouteTable,
	}})
	if err != nil {
		return fmt.Errorf("remove ready TUN route: %w", err)
	}
	if result.ExitCode != 0 && !nodeRoutingRouteAlreadyAbsent(result) {
		return commandResultError("remove ready TUN route", result)
	}
	return nil
}

// Ready adds the safe route before opening the readiness chain. If the atomic
// chain switch fails, it removes the just-added route and leaves not-ready in
// force.
func (manager *NodeRoutingGuardManager) Ready(ctx context.Context) (returnErr error) {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil {
		return fmt.Errorf("node routing guard manager is incomplete")
	}
	if err := manager.assertOwnedTable(ctx); err != nil {
		return err
	}
	link, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "ip", Args: []string{"-o", "link", "show", "dev", NodeRoutingTUNDevice}})
	if err != nil {
		return fmt.Errorf("observe ready TUN: %w", err)
	}
	if link.ExitCode != 0 || !validNodeRoutingTUN(string(link.Stdout)) {
		return fmt.Errorf("node routing TUN is not ready")
	}
	routeArguments := []string{"-4", "route", "replace", "default", "dev", NodeRoutingTUNDevice,
		"metric", strconv.Itoa(linuxplatform.VPNCTLReadyTUNRouteMetric), "table", linuxplatform.VPNCTLSelectedRouteTable, "proto", "static"}
	if err := manager.runChecked(ctx, linuxplatform.ProbeCommand{Name: "ip", Args: routeArguments}); err != nil {
		return fmt.Errorf("install ready TUN route: %w", err)
	}
	if err := manager.switchReadiness(ctx, "ready"); err != nil {
		removeResult, removeErr := manager.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "ip", Args: []string{
			"-4", "route", "del", "default", "dev", NodeRoutingTUNDevice,
			"metric", strconv.Itoa(linuxplatform.VPNCTLReadyTUNRouteMetric), "table", linuxplatform.VPNCTLSelectedRouteTable,
		}})
		if removeErr != nil || removeResult.ExitCode != 0 && !nodeRoutingRouteAlreadyAbsent(removeResult) {
			return errors.Join(err, fmt.Errorf("remove TUN route after failed ready switch"))
		}
		return err
	}
	return nil
}

func (manager *NodeRoutingGuardManager) WaitReady(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil || manager.wait == nil {
		return fmt.Errorf("node routing guard manager is incomplete")
	}
	readyContext, cancel := context.WithTimeout(ctx, nodeRoutingGuardReadyTimeout)
	defer cancel()
	for {
		ready, err := manager.routingEngineReady(readyContext)
		if err != nil {
			_ = manager.NotReady(ctx)
			return err
		}
		if ready {
			if err := manager.Ready(readyContext); err != nil {
				_ = manager.NotReady(ctx)
				return err
			}
			return nil
		}
		if err := manager.wait(readyContext, nodeRoutingGuardPollInterval); err != nil {
			_ = manager.NotReady(ctx)
			if errors.Is(err, context.DeadlineExceeded) {
				return fmt.Errorf("node routing engine did not become ready within %s", nodeRoutingGuardReadyTimeout)
			}
			return err
		}
	}
}

func (manager *NodeRoutingGuardManager) routingEngineReady(ctx context.Context) (bool, error) {
	probes := []struct {
		command  linuxplatform.ProbeCommand
		validate func(string) bool
	}{
		{command: linuxplatform.ProbeCommand{Name: "ip", Args: []string{"-o", "link", "show", "dev", NodeRoutingTUNDevice}}, validate: validNodeRoutingTUN},
		{command: linuxplatform.ProbeCommand{Name: "ss", Args: []string{"-H", "-lunp", "sport = :1053"}}, validate: validNodeRoutingDNSListener},
		{command: linuxplatform.ProbeCommand{Name: "ss", Args: []string{"-H", "-ltnp", "sport = :1053"}}, validate: validNodeRoutingDNSListener},
	}
	for _, probe := range probes {
		result, err := manager.runner.Run(ctx, probe.command)
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, fmt.Errorf("observe node routing engine readiness: %w", err)
		}
		if result.ExitCode != 0 || !probe.validate(string(result.Stdout)) {
			return false, nil
		}
	}
	return true, nil
}

func (manager *NodeRoutingGuardManager) assertOwnedTable(ctx context.Context) error {
	result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "nft", Args: []string{
		"--stateless", "-nn", "list", "table", linuxplatform.VPNCTLNFTablesFamily, linuxplatform.VPNCTLNFTablesTable,
	}})
	if err != nil {
		return fmt.Errorf("inspect node routing guard table: %w", err)
	}
	if result.ExitCode != 0 || !strings.Contains(string(result.Stdout), NodeRoutingGuardOwnerComment) {
		return fmt.Errorf("node routing guard table is absent or not owned by the node guard")
	}
	return nil
}

func (manager *NodeRoutingGuardManager) switchReadiness(ctx context.Context, target string) error {
	if target != "ready" && target != "not_ready" {
		return fmt.Errorf("unsupported node routing readiness target")
	}
	batch := []byte("flush chain " + linuxplatform.VPNCTLNFTablesFamily + " " + linuxplatform.VPNCTLNFTablesTable + " readiness\n" +
		"add rule " + linuxplatform.VPNCTLNFTablesFamily + " " + linuxplatform.VPNCTLNFTablesTable + " readiness jump " + target + "\n")
	if err := manager.applyNFTablesBatch(ctx, batch); err != nil {
		return fmt.Errorf("switch node routing guard to %s: %w", strings.ReplaceAll(target, "_", "-"), err)
	}
	return nil
}

func (manager *NodeRoutingGuardManager) applyNFTablesBatch(ctx context.Context, batch []byte) error {
	if err := manager.runChecked(ctx, linuxplatform.ProbeCommand{Name: "nft", Args: []string{"--check", "--file", "-"}, Stdin: batch}); err != nil {
		return fmt.Errorf("validate nftables batch: %w", err)
	}
	if err := manager.runChecked(ctx, linuxplatform.ProbeCommand{Name: "nft", Args: []string{"--file", "-"}, Stdin: batch}); err != nil {
		return fmt.Errorf("apply nftables batch: %w", err)
	}
	return nil
}

func (manager *NodeRoutingGuardManager) runChecked(ctx context.Context, command linuxplatform.ProbeCommand) error {
	result, err := manager.runner.Run(ctx, command)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if result.ExitCode != 0 {
		return commandResultError(command.Name+" "+strings.Join(command.Args, " "), result)
	}
	return nil
}

func validatePriorNodeRoutingGuardOwnership(snapshot linuxplatform.NetworkSnapshot) error {
	if snapshot.NFTables.Present {
		if !strings.Contains(snapshot.NFTables.Definition, NodeRoutingGuardOwnerComment) {
			return fmt.Errorf("existing inet/vpnctl table is not owned by the node routing guard")
		}
		return nil
	}
	if len(snapshot.Routes) != 0 || len(snapshot.PolicyRules) != 0 {
		return fmt.Errorf("vpnctl routing tables or policy priorities exist without the owned node guard table")
	}
	return nil
}

type nodeRoutingPolicyRule struct {
	priority int
	mark     string
	table    string
}

func nodeRoutingPolicyRules() []nodeRoutingPolicyRule {
	return []nodeRoutingPolicyRule{
		{priority: linuxplatform.VPNCTLRecoveryRulePriority, mark: nftMark(linuxplatform.VPNCTLRecoveryMark), table: linuxplatform.VPNCTLGatewayRouteTable},
		{priority: linuxplatform.VPNCTLIngressRulePriority, mark: nftMark(linuxplatform.VPNCTLIngressResponseMark), table: linuxplatform.VPNCTLGatewayRouteTable},
		{priority: linuxplatform.VPNCTLSelectedRulePriority, mark: nftMark(linuxplatform.VPNCTLSelectedMark), table: linuxplatform.VPNCTLSelectedRouteTable},
	}
}

func priorHasPolicyRule(snapshot linuxplatform.NetworkSnapshot, priority int) bool {
	for _, rule := range snapshot.PolicyRules {
		if rule.Priority == priority {
			return true
		}
	}
	return false
}

func commandResultError(action string, result linuxplatform.ProbeResult) error {
	detail := strings.TrimSpace(string(result.Stderr))
	if detail == "" {
		detail = strings.TrimSpace(string(result.Stdout))
	}
	if detail == "" {
		detail = fmt.Sprintf("exit code %d", result.ExitCode)
	}
	return fmt.Errorf("%s: %s", action, detail)
}

func nodeRoutingRouteAlreadyAbsent(result linuxplatform.ProbeResult) bool {
	detail := strings.ToLower(string(result.Stderr) + " " + string(result.Stdout))
	return strings.Contains(detail, "no such process") || strings.Contains(detail, "cannot find device") ||
		strings.Contains(detail, "fib table does not exist")
}

func waitNodeRoutingGuardInterval(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func RunNodeRoutingGuardService(ctx context.Context, paths store.Paths, runner linuxplatform.ProbeRunner, action string) error {
	manager, err := NewNodeRoutingGuardManager(runner)
	if err != nil {
		return err
	}
	switch action {
	case NodeRoutingGuardInstallAction:
		candidate, err := loadNodeRoutingGuardCandidate(paths)
		if err != nil {
			return err
		}
		return manager.Install(ctx, candidate)
	case NodeRoutingGuardNotReadyAction:
		return manager.NotReady(ctx)
	case NodeRoutingGuardWaitReadyAction:
		if _, err := loadNodeRoutingGuardCandidate(paths); err != nil {
			return err
		}
		return manager.WaitReady(ctx)
	default:
		return fmt.Errorf("unsupported node routing guard action")
	}
}

func loadNodeRoutingGuardCandidate(paths store.Paths) (NodeRoutingGuardCandidate, error) {
	wantConfigDir := filepath.Join(paths.Root, "etc", "vpnctl")
	wantStateDir := filepath.Join(paths.Root, "var", "lib", "vpnctl")
	if paths.Root == "" || !filepath.IsAbs(paths.Root) || filepath.Clean(paths.Root) != paths.Root ||
		paths.ConfigDir != wantConfigDir || paths.StateDir != wantStateDir {
		return NodeRoutingGuardCandidate{}, fmt.Errorf("node routing guard paths are invalid")
	}
	path := nodeRoutingGuardConfigPath(paths)
	info, err := os.Lstat(path)
	if err != nil {
		return NodeRoutingGuardCandidate{}, fmt.Errorf("inspect node routing guard config: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return NodeRoutingGuardCandidate{}, fmt.Errorf("node routing guard config must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximumNodeRoutingGuardConfigBytes {
		return NodeRoutingGuardCandidate{}, fmt.Errorf("node routing guard config must be root-only and bounded")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return NodeRoutingGuardCandidate{}, fmt.Errorf("read node routing guard config: %w", err)
	}
	config, err := decodeNodeRoutingGuardConfig(content)
	if err != nil {
		return NodeRoutingGuardCandidate{}, err
	}
	candidate, err := RenderNodeRoutingGuardConfig(config)
	if err != nil {
		return NodeRoutingGuardCandidate{}, err
	}
	if !bytes.Equal(content, candidate.Bytes()) {
		return NodeRoutingGuardCandidate{}, fmt.Errorf("node routing guard config is not canonical")
	}
	return candidate, nil
}

func nodeRoutingGuardConfigPath(paths store.Paths) string {
	return filepath.Join(paths.ConfigDir, "generated", "node", NodeRoutingGuardConfigFileName)
}
