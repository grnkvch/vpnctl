package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"golang.org/x/sys/unix"
)

const (
	NodeDNSIntegrationInstallAction = "install"
	NodeDNSIntegrationRestoreAction = "restore"
)

type NodeDNSOriginalState struct {
	SchemaVersion    int      `json:"schema_version"`
	LinkName         string   `json:"link_name"`
	DNS              []string `json:"dns"`
	Domains          []string `json:"domains"`
	DefaultRoute     bool     `json:"default_route"`
	ResolvConfTarget string   `json:"resolv_conf_target"`
}

func (snapshot NodeDNSOriginalState) Validate(root string) error {
	if snapshot.SchemaVersion != NodeDNSIntegrationSchemaVersion || !nodeRoutingInterfacePattern.MatchString(snapshot.LinkName) ||
		snapshot.LinkName == "lo" || snapshot.ResolvConfTarget != nodeDNSResolvedStubPath(root) {
		return fmt.Errorf("invalid original node DNS snapshot")
	}
	for _, values := range [][]string{snapshot.DNS, snapshot.Domains} {
		for _, value := range values {
			if value == "" || len(value) > 255 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t ") {
				return fmt.Errorf("invalid original node DNS snapshot value")
			}
		}
	}
	return nil
}

type NodeDNSIntegrationManager struct {
	paths  store.Paths
	runner linuxplatform.ProbeRunner
}

func NewNodeDNSIntegrationManager(paths store.Paths, runner linuxplatform.ProbeRunner) (*NodeDNSIntegrationManager, error) {
	if runner == nil {
		return nil, fmt.Errorf("node DNS integration runner is required")
	}
	wantConfig := filepath.Join(paths.Root, "etc", "vpnctl")
	wantState := filepath.Join(paths.Root, "var", "lib", "vpnctl")
	wantRuntime := filepath.Join(paths.Root, "run", "vpnctl")
	if paths.Root == "" || !filepath.IsAbs(paths.Root) || filepath.Clean(paths.Root) != paths.Root ||
		paths.ConfigDir != wantConfig || paths.StateDir != wantState || paths.RuntimeDir != wantRuntime {
		return nil, fmt.Errorf("node DNS integration paths are invalid")
	}
	return &NodeDNSIntegrationManager{paths: paths, runner: runner}, nil
}

func (manager *NodeDNSIntegrationManager) Install(ctx context.Context, candidate NodeDNSIntegrationCandidate) (returnErr error) {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil {
		return fmt.Errorf("node DNS integration manager is incomplete")
	}
	if err := candidate.Config().Validate(); err != nil {
		return err
	}
	if err := manager.preflight(ctx, candidate); err != nil {
		return err
	}
	if err := ensureNodeDNSDirectory(nodeDNSResolvedDropinDirectory(manager.paths), 0o755); err != nil {
		return err
	}
	if err := ensureNodeDNSDirectory(nodeRoutingStatePath(manager.paths), 0o700); err != nil {
		return err
	}

	snapshotPath := nodeDNSResolvedSnapshotPath(manager.paths)
	snapshot, snapshotPresent, err := loadNodeDNSOriginalState(snapshotPath, manager.paths.Root)
	if err != nil {
		return err
	}
	tablePresent, tableOwned, err := manager.inspectTable(ctx)
	if err != nil {
		return err
	}
	dropinPresent, err := validateNodeDNSDropin(nodeDNSResolvedDropinPath(manager.paths), candidate.ResolvedDropin())
	if err != nil {
		return err
	}
	if tablePresent && !tableOwned {
		return fmt.Errorf("existing node DNS nftables table is not vpnctl-owned")
	}
	if !snapshotPresent {
		if tablePresent || dropinPresent {
			return fmt.Errorf("node DNS integration artifacts exist without an original snapshot")
		}
		snapshot, err = manager.observeOriginal(ctx, candidate.Config().LinkName)
		if err != nil {
			return err
		}
	} else if snapshot.LinkName != candidate.Config().LinkName {
		return fmt.Errorf("node DNS integration link differs from the original snapshot")
	}

	nftables := candidate.NFTablesDefinition()
	if tablePresent {
		nftables = append([]byte("delete table "+NodeDNSNFTablesFamily+" "+NodeDNSNFTablesTable+"\n"), nftables...)
	}
	if err := manager.runChecked(ctx, linuxplatform.ProbeCommand{Name: "nft", Args: []string{"--check", "--file", "-"}, Stdin: nftables}); err != nil {
		return fmt.Errorf("validate node DNS capture: %w", err)
	}
	if !snapshotPresent {
		if err := writeNodeDNSExclusiveJSON(snapshotPath, snapshot); err != nil {
			return err
		}
		snapshotPresent = true
	}
	defer func() {
		if returnErr == nil || !snapshotPresent {
			return
		}
		rollbackContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if restoreErr := manager.Restore(rollbackContext); restoreErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("restore node DNS after failed install: %w", restoreErr))
		}
	}()

	if err := manager.runChecked(ctx, linuxplatform.ProbeCommand{Name: "nft", Args: []string{"--file", "-"}, Stdin: nftables}); err != nil {
		return fmt.Errorf("apply node DNS capture: %w", err)
	}
	if err := installNodeDNSFile(nodeDNSResolvedDropinPath(manager.paths), candidate.ResolvedDropin(), 0o644); err != nil {
		return err
	}
	if err := manager.activateResolved(ctx, candidate.Config().LinkName); err != nil {
		return err
	}
	return manager.verifyApplied(ctx, candidate.Config().LinkName)
}

func (manager *NodeDNSIntegrationManager) Restore(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil {
		return fmt.Errorf("node DNS integration manager is incomplete")
	}
	snapshot, present, err := loadNodeDNSOriginalState(nodeDNSResolvedSnapshotPath(manager.paths), manager.paths.Root)
	if err != nil {
		return err
	}
	tablePresent, tableOwned, err := manager.inspectTable(ctx)
	if err != nil {
		return err
	}
	dropinPresent, err := validateNodeDNSDropin(nodeDNSResolvedDropinPath(manager.paths), nodeDNSResolvedDropin)
	if err != nil {
		return err
	}
	if !present {
		if tablePresent || dropinPresent {
			return fmt.Errorf("refusing node DNS restoration without an original snapshot")
		}
		return nil
	}
	if tablePresent && !tableOwned {
		return fmt.Errorf("existing node DNS nftables table is not vpnctl-owned")
	}
	currentTarget, err := manager.readResolvConfTarget(ctx)
	if err != nil {
		return err
	}
	if currentTarget != snapshot.ResolvConfTarget {
		return fmt.Errorf("resolv.conf target changed after node DNS activation")
	}
	if dropinPresent {
		if err := os.Remove(nodeDNSResolvedDropinPath(manager.paths)); err != nil {
			return fmt.Errorf("remove node DNS resolved drop-in: %w", err)
		}
		if err := syncNodeDNSDirectory(nodeDNSResolvedDropinDirectory(manager.paths)); err != nil {
			return err
		}
	}
	if err := manager.runChecked(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"restart", "systemd-resolved.service"}}); err != nil {
		return fmt.Errorf("restart systemd-resolved for restoration: %w", err)
	}
	if err := manager.restoreLink(ctx, snapshot); err != nil {
		return err
	}
	if tablePresent {
		if err := manager.runChecked(ctx, linuxplatform.ProbeCommand{Name: "nft", Args: []string{"delete", "table", NodeDNSNFTablesFamily, NodeDNSNFTablesTable}}); err != nil {
			return fmt.Errorf("remove node DNS capture: %w", err)
		}
	}
	if err := os.Remove(nodeDNSResolvedSnapshotPath(manager.paths)); err != nil {
		return fmt.Errorf("remove original node DNS snapshot: %w", err)
	}
	return syncNodeDNSDirectory(nodeRoutingStatePath(manager.paths))
}

func (manager *NodeDNSIntegrationManager) preflight(ctx context.Context, candidate NodeDNSIntegrationCandidate) error {
	version, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemd", Args: []string{"--version"}})
	if err != nil {
		return fmt.Errorf("inspect systemd version: %w", err)
	}
	versionFields := strings.Fields(string(version.Stdout))
	if version.ExitCode != 0 || len(versionFields) < 2 || versionFields[0] != "systemd" || versionFields[1] != "255" {
		return fmt.Errorf("node DNS integration requires systemd 255")
	}
	checks := []struct {
		action  string
		command linuxplatform.ProbeCommand
	}{
		{action: "systemd-resolved", command: linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"is-active", "--quiet", "systemd-resolved.service"}}},
		{action: "underlay link", command: linuxplatform.ProbeCommand{Name: "ip", Args: []string{"link", "show", "dev", candidate.Config().LinkName}}},
	}
	for _, check := range checks {
		if err := manager.runChecked(ctx, check.command); err != nil {
			return fmt.Errorf("validate node DNS %s: %w", check.action, err)
		}
	}
	target, err := manager.readResolvConfTarget(ctx)
	if err != nil {
		return err
	}
	if target != nodeDNSResolvedStubPath(manager.paths.Root) {
		return fmt.Errorf("node DNS integration requires resolv.conf on the systemd-resolved stub")
	}
	return nil
}

func (manager *NodeDNSIntegrationManager) observeOriginal(ctx context.Context, linkName string) (NodeDNSOriginalState, error) {
	dns, err := manager.readLinkValues(ctx, "dns", linkName)
	if err != nil {
		return NodeDNSOriginalState{}, err
	}
	domains, err := manager.readLinkValues(ctx, "domain", linkName)
	if err != nil {
		return NodeDNSOriginalState{}, err
	}
	defaultRoute, err := manager.readLinkValues(ctx, "default-route", linkName)
	if err != nil {
		return NodeDNSOriginalState{}, err
	}
	if len(defaultRoute) != 1 || defaultRoute[0] != "yes" && defaultRoute[0] != "no" {
		return NodeDNSOriginalState{}, fmt.Errorf("systemd-resolved returned an invalid link default-route value")
	}
	target, err := manager.readResolvConfTarget(ctx)
	if err != nil {
		return NodeDNSOriginalState{}, err
	}
	snapshot := NodeDNSOriginalState{
		SchemaVersion: NodeDNSIntegrationSchemaVersion, LinkName: linkName, DNS: dns, Domains: domains,
		DefaultRoute: defaultRoute[0] == "yes", ResolvConfTarget: target,
	}
	return snapshot, snapshot.Validate(manager.paths.Root)
}

func (manager *NodeDNSIntegrationManager) activateResolved(ctx context.Context, linkName string) error {
	commands := []linuxplatform.ProbeCommand{
		{Name: "systemctl", Args: []string{"restart", "systemd-resolved.service"}},
		{Name: "resolvectl", Args: []string{"domain", linkName, NodeDNSUnderlayHoldDomain}},
		{Name: "resolvectl", Args: []string{"flush-caches"}},
	}
	for _, command := range commands {
		if err := manager.runChecked(ctx, command); err != nil {
			return fmt.Errorf("activate node DNS integration: %w", err)
		}
	}
	return nil
}

func (manager *NodeDNSIntegrationManager) restoreLink(ctx context.Context, snapshot NodeDNSOriginalState) error {
	dns := append([]string{"dns", snapshot.LinkName}, snapshot.DNS...)
	if len(snapshot.DNS) == 0 {
		dns = append(dns, "")
	}
	domains := append([]string{"domain", snapshot.LinkName}, snapshot.Domains...)
	if len(snapshot.Domains) == 0 {
		domains = append(domains, "")
	}
	defaultRoute := "no"
	if snapshot.DefaultRoute {
		defaultRoute = "yes"
	}
	for _, command := range []linuxplatform.ProbeCommand{
		{Name: "resolvectl", Args: dns},
		{Name: "resolvectl", Args: domains},
		{Name: "resolvectl", Args: []string{"default-route", snapshot.LinkName, defaultRoute}},
		{Name: "resolvectl", Args: []string{"flush-caches"}},
	} {
		if err := manager.runChecked(ctx, command); err != nil {
			return fmt.Errorf("restore original node DNS link state: %w", err)
		}
	}
	return nil
}

func (manager *NodeDNSIntegrationManager) verifyApplied(ctx context.Context, linkName string) error {
	dns, err := manager.runOutput(ctx, linuxplatform.ProbeCommand{Name: "resolvectl", Args: []string{"dns"}})
	if err != nil || !strings.Contains(dns, "Global: 127.0.0.1:1053") {
		return fmt.Errorf("systemd-resolved did not activate the node DNS server")
	}
	domains, err := manager.runOutput(ctx, linuxplatform.ProbeCommand{Name: "resolvectl", Args: []string{"domain"}})
	if err != nil || !strings.Contains(domains, "Global: ~.") {
		return fmt.Errorf("systemd-resolved did not activate the node DNS route domain")
	}
	linkDomains, err := manager.readLinkValues(ctx, "domain", linkName)
	if err != nil || len(linkDomains) != 1 || linkDomains[0] != NodeDNSUnderlayHoldDomain {
		return fmt.Errorf("systemd-resolved underlay route domain was not isolated")
	}
	return nil
}

func (manager *NodeDNSIntegrationManager) inspectTable(ctx context.Context) (bool, bool, error) {
	result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "nft", Args: []string{
		"--stateless", "-nn", "list", "table", NodeDNSNFTablesFamily, NodeDNSNFTablesTable,
	}})
	if err != nil {
		return false, false, fmt.Errorf("inspect node DNS nftables table: %w", err)
	}
	if result.ExitCode != 0 {
		detail := strings.ToLower(string(result.Stderr) + " " + string(result.Stdout))
		if strings.Contains(detail, "no such file") || strings.Contains(detail, "does not exist") {
			return false, false, nil
		}
		return false, false, commandResultError("inspect node DNS nftables table", result)
	}
	return true, strings.Contains(string(result.Stdout), NodeDNSNFTablesOwnerComment), nil
}

func (manager *NodeDNSIntegrationManager) readLinkValues(ctx context.Context, field, linkName string) ([]string, error) {
	output, err := manager.runOutput(ctx, linuxplatform.ProbeCommand{Name: "resolvectl", Args: []string{field, linkName}})
	if err != nil {
		return nil, fmt.Errorf("read systemd-resolved link %s: %w", field, err)
	}
	line := strings.TrimSpace(output)
	colon := strings.Index(line, ":")
	if colon < 0 || !strings.Contains(line[:colon], "("+linkName+")") {
		return nil, fmt.Errorf("systemd-resolved returned an invalid link %s record", field)
	}
	return strings.Fields(strings.TrimSpace(line[colon+1:])), nil
}

func (manager *NodeDNSIntegrationManager) readResolvConfTarget(ctx context.Context) (string, error) {
	output, err := manager.runOutput(ctx, linuxplatform.ProbeCommand{Name: "readlink", Args: []string{"-f", nodeDNSResolvConfPath(manager.paths)}})
	if err != nil {
		return "", fmt.Errorf("inspect resolv.conf target: %w", err)
	}
	return strings.TrimSpace(output), nil
}

func (manager *NodeDNSIntegrationManager) runOutput(ctx context.Context, command linuxplatform.ProbeCommand) (string, error) {
	result, err := manager.runner.Run(ctx, command)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", commandResultError(command.Name+" "+strings.Join(command.Args, " "), result)
	}
	return string(result.Stdout), nil
}

func (manager *NodeDNSIntegrationManager) runChecked(ctx context.Context, command linuxplatform.ProbeCommand) error {
	_, err := manager.runOutput(ctx, command)
	return err
}

func RunNodeDNSIntegrationService(ctx context.Context, paths store.Paths, runner linuxplatform.ProbeRunner, action string) error {
	manager, err := NewNodeDNSIntegrationManager(paths, runner)
	if err != nil {
		return err
	}
	switch action {
	case NodeDNSIntegrationInstallAction:
		candidate, err := loadNodeDNSIntegrationCandidate(paths)
		if err != nil {
			return err
		}
		return manager.Install(ctx, candidate)
	case NodeDNSIntegrationRestoreAction:
		return manager.Restore(ctx)
	default:
		return fmt.Errorf("unsupported node DNS integration action")
	}
}

func loadNodeDNSIntegrationCandidate(paths store.Paths) (NodeDNSIntegrationCandidate, error) {
	content, err := readNodeDNSBoundedFile(nodeDNSIntegrationConfigPath(paths), maximumNodeDNSConfigBytes, 0o600)
	if err != nil {
		return NodeDNSIntegrationCandidate{}, fmt.Errorf("read node DNS integration config: %w", err)
	}
	config, err := decodeNodeDNSIntegrationConfig(content)
	if err != nil {
		return NodeDNSIntegrationCandidate{}, err
	}
	candidate, err := RenderNodeDNSIntegrationConfig(config.LinkName)
	if err != nil {
		return NodeDNSIntegrationCandidate{}, err
	}
	if !bytes.Equal(content, candidate.Bytes()) {
		return NodeDNSIntegrationCandidate{}, fmt.Errorf("node DNS integration config is not canonical")
	}
	return candidate, nil
}

func loadNodeDNSOriginalState(path, root string) (NodeDNSOriginalState, bool, error) {
	content, err := readNodeDNSBoundedFile(path, maximumNodeDNSSnapshotBytes, 0o600)
	if errors.Is(err, fs.ErrNotExist) {
		return NodeDNSOriginalState{}, false, nil
	}
	if err != nil {
		return NodeDNSOriginalState{}, false, fmt.Errorf("read original node DNS snapshot: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var snapshot NodeDNSOriginalState
	if err := decoder.Decode(&snapshot); err != nil {
		return NodeDNSOriginalState{}, false, fmt.Errorf("decode original node DNS snapshot: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return NodeDNSOriginalState{}, false, fmt.Errorf("decode original node DNS snapshot: trailing data")
	}
	if err := snapshot.Validate(root); err != nil {
		return NodeDNSOriginalState{}, false, err
	}
	return snapshot, true, nil
}

func writeNodeDNSExclusiveJSON(path string, value NodeDNSOriginalState) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return installNodeDNSExclusiveFile(path, append(content, '\n'), 0o600)
}

func installNodeDNSFile(path string, content []byte, mode fs.FileMode) error {
	if current, err := readNodeDNSBoundedFile(path, int64(len(content))+1, mode); err == nil {
		if !bytes.Equal(current, content) {
			return fmt.Errorf("refusing to replace drifted node DNS file %s", path)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return installNodeDNSExclusiveFile(path, content, mode)
}

func installNodeDNSExclusiveFile(path string, content []byte, mode fs.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".vpnctl-node-dns-*.tmp")
	if err != nil {
		return fmt.Errorf("create node DNS temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("node DNS target already exists: %s", path)
		}
		return fmt.Errorf("activate node DNS file: %w", err)
	}
	return syncNodeDNSDirectory(directory)
}

func readNodeDNSBoundedFile(path string, maximum int64, mode fs.FileMode) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("open node DNS file %s", path)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != mode || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("node DNS file %s is not a bounded regular file with mode %04o", path, mode)
	}
	return io.ReadAll(io.LimitReader(file, maximum+1))
}

func validateNodeDNSDropin(path string, expected []byte) (bool, error) {
	content, err := readNodeDNSBoundedFile(path, int64(len(expected))+1, 0o644)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(content, expected) {
		return false, fmt.Errorf("node DNS resolved drop-in drifted")
	}
	return true, nil
}

func ensureNodeDNSDirectory(path string, mode fs.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create node DNS directory %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != mode {
		return fmt.Errorf("node DNS directory %s is not an owned real directory", path)
	}
	return nil
}

func syncNodeDNSDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func nodeDNSIntegrationConfigPath(paths store.Paths) string {
	return filepath.Join(paths.ConfigDir, "generated", "node", NodeDNSIntegrationConfigName)
}

func nodeDNSResolvedDropinDirectory(paths store.Paths) string {
	return filepath.Join(paths.Root, "run", "systemd", "resolved.conf.d")
}

func nodeDNSResolvedDropinPath(paths store.Paths) string {
	return filepath.Join(nodeDNSResolvedDropinDirectory(paths), NodeDNSResolvedDropinName)
}

func nodeDNSResolvedSnapshotPath(paths store.Paths) string {
	return filepath.Join(nodeRoutingStatePath(paths), NodeDNSResolvedSnapshotName)
}

func nodeDNSResolvConfPath(paths store.Paths) string {
	return filepath.Join(paths.Root, "etc", "resolv.conf")
}

func nodeDNSResolvedStubPath(root string) string {
	return filepath.Join(root, "run", "systemd", "resolve", "stub-resolv.conf")
}
