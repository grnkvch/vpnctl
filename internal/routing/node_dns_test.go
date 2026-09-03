package routing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestRenderNodeDNSIntegrationOwnsOnlyClassicDNSCapture(t *testing.T) {
	t.Parallel()
	candidate, err := RenderNodeDNSIntegrationConfig("eth0")
	if err != nil {
		t.Fatal(err)
	}
	nftables := string(candidate.NFTablesDefinition())
	for _, required := range []string{
		"table inet vpnctl_dns {",
		`comment "vpnctl:v2:node-dns-integration"`,
		"type nat hook output priority -151; policy accept;",
		"meta mark & 0xff000000 == 0x01000000 counter name provider_mark_bypass return",
		"meta mark & 0xff000000 == 0x03000000 counter name provider_mark_bypass return",
		"ip daddr 127.0.0.0/8 udp dport 53 counter name resolved_stub_passthrough return",
		"ip daddr 127.0.0.0/8 tcp dport 53 counter name resolved_stub_passthrough return",
		"udp dport 53 counter name classic_udp_captured redirect to :1053",
		"tcp dport 53 counter name classic_tcp_captured redirect to :1053",
	} {
		if !strings.Contains(nftables, required) {
			t.Errorf("node DNS capture lacks %q:\n%s", required, nftables)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "masquerade", " dport 853", "queue", " log ", "skuid", "meta cgroup"} {
		if strings.Contains(nftables, forbidden) {
			t.Errorf("node DNS capture contains unsafe or expanded behavior %q:\n%s", forbidden, nftables)
		}
	}
	if NodeDNSCapturePriority >= linuxplatform.VPNCTLNFTablesManglePriority {
		t.Fatalf("DNS capture priority %d must run before routing guard %d", NodeDNSCapturePriority, linuxplatform.VPNCTLNFTablesManglePriority)
	}
	if got := string(candidate.ResolvedDropin()); got != string(nodeDNSResolvedDropin) {
		t.Fatalf("resolved drop-in = %q", got)
	}
	decoded, err := decodeNodeDNSIntegrationConfig(candidate.Bytes())
	if err != nil || decoded != candidate.Config() {
		t.Fatalf("DNS integration round trip = %+v, %v", decoded, err)
	}
	repeated, err := RenderNodeDNSIntegrationConfig("eth0")
	if err != nil || !bytes.Equal(repeated.Bytes(), candidate.Bytes()) || !bytes.Equal(repeated.NFTablesDefinition(), candidate.NFTablesDefinition()) {
		t.Fatalf("DNS integration render is not deterministic: %v", err)
	}
	defensive := candidate.NFTablesDefinition()
	defensive[0] = 'X'
	if bytes.Equal(defensive, candidate.NFTablesDefinition()) {
		t.Fatal("node DNS integration exposed mutable nftables bytes")
	}
}

func TestNodeDNSIntegrationInstallAndRestoreExactOriginalState(t *testing.T) {
	t.Parallel()
	paths, candidate := nodeDNSServiceFixture(t)
	runner := newNodeDNSIntegrationRunner(paths.Root)
	manager, err := NewNodeDNSIntegrationManager(paths, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(context.Background(), candidate); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if runner.mutatedBeforeSnapshot {
		t.Fatal("node DNS integration mutated the host before persisting its original snapshot")
	}
	assertNodeDNSApplied(t, paths, runner)
	firstSnapshot, err := os.ReadFile(nodeDNSResolvedSnapshotPath(paths))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(context.Background(), candidate); err != nil {
		t.Fatalf("idempotent Install() error = %v", err)
	}
	secondSnapshot, err := os.ReadFile(nodeDNSResolvedSnapshotPath(paths))
	if err != nil || !bytes.Equal(firstSnapshot, secondSnapshot) {
		t.Fatalf("idempotent install replaced original snapshot: %v", err)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	assertNodeDNSRestored(t, paths, runner)
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatalf("idempotent Restore() error = %v", err)
	}
	joined := runner.joinedCalls()
	assertCallOrder(t, joined,
		"resolvectl dns eth0",
		"nft --file -",
		"systemctl restart systemd-resolved.service",
		"resolvectl domain eth0 ~vpnctl-underlay.invalid",
	)
	for _, required := range []string{
		"resolvectl dns eth0 198.18.0.2 198.18.0.3",
		"resolvectl domain eth0 ~. corp.example",
		"resolvectl default-route eth0 yes",
		"nft delete table inet vpnctl_dns",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("restoration lacks %q:\n%s", required, joined)
		}
	}
}

func TestNodeDNSIntegrationRestoresEmptyPerLinkDNSAndDomains(t *testing.T) {
	t.Parallel()
	paths, candidate := nodeDNSServiceFixture(t)
	runner := newNodeDNSIntegrationRunner(paths.Root)
	runner.dns = []string{}
	runner.domains = []string{}
	runner.defaultRoute = false
	runner.originalDNS = []string{}
	runner.originalDomains = []string{}
	runner.originalDefaultRoute = false
	manager, _ := NewNodeDNSIntegrationManager(paths, runner)
	if err := manager.Install(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertNodeDNSRestored(t, paths, runner)
	joined := runner.joinedCalls()
	if !strings.Contains(joined, "resolvectl dns eth0 \n") || !strings.Contains(joined, "resolvectl domain eth0 \n") {
		t.Fatalf("empty original link values were not explicitly reset:\n%s", joined)
	}
}

func TestNodeDNSIntegrationFailedActivationRollsBack(t *testing.T) {
	t.Parallel()
	for _, failOn := range []string{
		"nft --file -",
		"systemctl restart systemd-resolved.service",
		"resolvectl domain eth0 ~vpnctl-underlay.invalid",
		"resolvectl dns",
	} {
		t.Run(failOn, func(t *testing.T) {
			t.Parallel()
			paths, candidate := nodeDNSServiceFixture(t)
			runner := newNodeDNSIntegrationRunner(paths.Root)
			runner.failOnceKey = failOn
			manager, err := NewNodeDNSIntegrationManager(paths, runner)
			if err != nil {
				t.Fatal(err)
			}
			err = manager.Install(context.Background(), candidate)
			if err == nil || !runner.failed {
				t.Fatalf("Install() error = %v", err)
			}
			assertNodeDNSRestored(t, paths, runner)
			if !strings.Contains(runner.joinedCalls(), "resolvectl default-route eth0 yes") {
				t.Fatalf("failed activation did not restore original link state:\n%s", runner.joinedCalls())
			}
		})
	}
}

func TestNodeDNSIntegrationRefusesForeignOrUnsnapshottedArtifacts(t *testing.T) {
	t.Parallel()
	for name, prepare := range map[string]func(*testing.T, store.Paths, *nodeDNSIntegrationRunner){
		"owned table without snapshot": func(_ *testing.T, _ store.Paths, runner *nodeDNSIntegrationRunner) {
			runner.tableDefinition = string(renderNodeDNSCaptureNFTables())
		},
		"foreign table without snapshot": func(_ *testing.T, _ store.Paths, runner *nodeDNSIntegrationRunner) {
			runner.tableDefinition = "table inet vpnctl_dns { comment \"foreign\" }"
		},
		"drop-in without snapshot": func(t *testing.T, paths store.Paths, _ *nodeDNSIntegrationRunner) {
			t.Helper()
			if err := os.Mkdir(nodeDNSResolvedDropinDirectory(paths), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(nodeDNSResolvedDropinPath(paths), nodeDNSResolvedDropin, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			paths, candidate := nodeDNSServiceFixture(t)
			runner := newNodeDNSIntegrationRunner(paths.Root)
			prepare(t, paths, runner)
			manager, _ := NewNodeDNSIntegrationManager(paths, runner)
			if err := manager.Install(context.Background(), candidate); err == nil {
				t.Fatal("node DNS integration claimed an artifact without an original snapshot")
			}
			if _, err := os.Stat(nodeDNSResolvedSnapshotPath(paths)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refused install unexpectedly wrote a snapshot: %v", err)
			}
		})
	}
}

func TestNodeDNSIntegrationServiceRequiresCanonicalPrivateConfig(t *testing.T) {
	t.Parallel()
	paths, _ := nodeDNSServiceFixture(t)
	runner := newNodeDNSIntegrationRunner(paths.Root)
	if err := RunNodeDNSIntegrationService(context.Background(), paths, runner, NodeDNSIntegrationInstallAction); err != nil {
		t.Fatalf("install service error = %v", err)
	}
	if err := RunNodeDNSIntegrationService(context.Background(), paths, runner, NodeDNSIntegrationRestoreAction); err != nil {
		t.Fatalf("restore service error = %v", err)
	}
	before := len(runner.calls)
	configPath := nodeDNSIntegrationConfigPath(paths)
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RunNodeDNSIntegrationService(context.Background(), paths, runner, NodeDNSIntegrationInstallAction); err == nil {
		t.Fatal("public DNS integration config was accepted")
	}
	if len(runner.calls) != before {
		t.Fatal("unsafe DNS integration config performed host commands")
	}
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(paths.Root, "config-target")
	if err := os.WriteFile(target, []byte("foreign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, configPath); err != nil {
		t.Fatal(err)
	}
	if err := RunNodeDNSIntegrationService(context.Background(), paths, runner, NodeDNSIntegrationInstallAction); err == nil {
		t.Fatal("symlink DNS integration config was accepted")
	}
	if len(runner.calls) != before {
		t.Fatal("symlink DNS integration config performed host commands")
	}
	if err := RunNodeDNSIntegrationService(context.Background(), paths, runner, "remove"); err == nil {
		t.Fatal("unsupported DNS integration action succeeded")
	}
}

func TestNodeDNSIntegrationRejectsUnsafeInputsBeforeMutation(t *testing.T) {
	t.Parallel()
	paths, candidate := nodeDNSServiceFixture(t)
	for name, mutate := range map[string]func(*nodeDNSIntegrationRunner){
		"wrong systemd":     func(runner *nodeDNSIntegrationRunner) { runner.systemdVersion = "systemd 256\n" },
		"inactive resolved": func(runner *nodeDNSIntegrationRunner) { runner.inactiveResolved = true },
		"wrong resolv.conf": func(runner *nodeDNSIntegrationRunner) {
			runner.resolvConfTarget = filepath.Join(paths.Root, "tmp", "foreign-resolv.conf")
		},
		"missing link": func(runner *nodeDNSIntegrationRunner) { runner.missingLink = true },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := newNodeDNSIntegrationRunner(paths.Root)
			mutate(runner)
			manager, _ := NewNodeDNSIntegrationManager(paths, runner)
			if err := manager.Install(context.Background(), candidate); err == nil {
				t.Fatal("unsafe DNS precondition was accepted")
			}
			if runner.hasMutation() {
				t.Fatalf("unsafe DNS precondition caused mutation:\n%s", runner.joinedCalls())
			}
		})
	}
	for _, link := range []string{"", "lo", "vpnctl0", "vpnctl-wg", "eth0; nft"} {
		if _, err := RenderNodeDNSIntegrationConfig(link); err == nil {
			t.Errorf("unsafe DNS integration link %q rendered", link)
		}
	}
}

func TestNodeDNSCaptureNFTablesParsesWithNativeNFT(t *testing.T) {
	binary := os.Getenv("VPNCTL_NFT")
	if binary == "" {
		t.Skip("set VPNCTL_NFT to a Linux nft binary for native parser validation")
	}
	candidate, err := RenderNodeDNSIntegrationConfig("eth0")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "--check", "--file", "-")
	command.Stdin = bytes.NewReader(candidate.NFTablesDefinition())
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("native nft rejected node DNS capture: %v:\n%s\nrules:\n%s", err, output, candidate.NFTablesDefinition())
	}
}

func nodeDNSServiceFixture(t *testing.T) (store.Paths, NodeDNSIntegrationCandidate) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		filepath.Join(paths.ConfigDir, "generated", "node"),
		nodeRoutingStatePath(paths),
		filepath.Join(paths.Root, "run", "systemd", "resolve"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	candidate, err := RenderNodeDNSIntegrationConfig("eth0")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nodeDNSIntegrationConfigPath(paths), candidate.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return paths, candidate
}

func assertNodeDNSApplied(t *testing.T, paths store.Paths, runner *nodeDNSIntegrationRunner) {
	t.Helper()
	for path, mode := range map[string]os.FileMode{
		nodeDNSResolvedSnapshotPath(paths): 0o600,
		nodeDNSResolvedDropinPath(paths):   0o644,
	} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
			t.Fatalf("applied DNS artifact %s = %v, %v", path, info, err)
		}
	}
	if !strings.Contains(runner.tableDefinition, NodeDNSNFTablesOwnerComment) || !runner.globalApplied ||
		!reflect.DeepEqual(runner.domains, []string{NodeDNSUnderlayHoldDomain}) {
		t.Fatalf("DNS integration not applied: table=%q global=%t domains=%v", runner.tableDefinition, runner.globalApplied, runner.domains)
	}
}

func assertNodeDNSRestored(t *testing.T, paths store.Paths, runner *nodeDNSIntegrationRunner) {
	t.Helper()
	for _, path := range []string{nodeDNSResolvedSnapshotPath(paths), nodeDNSResolvedDropinPath(paths)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("restored DNS artifact remains at %s: %v", path, err)
		}
	}
	if runner.tableDefinition != "" || runner.globalApplied ||
		!reflect.DeepEqual(runner.dns, runner.originalDNS) || !reflect.DeepEqual(runner.domains, runner.originalDomains) || runner.defaultRoute != runner.originalDefaultRoute {
		t.Fatalf("DNS original state not restored: table=%q global=%t dns=%v domains=%v default=%t",
			runner.tableDefinition, runner.globalApplied, runner.dns, runner.domains, runner.defaultRoute)
	}
}

type nodeDNSIntegrationRunner struct {
	root                  string
	calls                 []linuxplatform.ProbeCommand
	systemdVersion        string
	inactiveResolved      bool
	missingLink           bool
	resolvConfTarget      string
	tableDefinition       string
	globalApplied         bool
	dns                   []string
	domains               []string
	defaultRoute          bool
	originalDNS           []string
	originalDomains       []string
	originalDefaultRoute  bool
	failOnceKey           string
	failed                bool
	mutatedBeforeSnapshot bool
}

func newNodeDNSIntegrationRunner(root string) *nodeDNSIntegrationRunner {
	dns := []string{"198.18.0.2", "198.18.0.3"}
	domains := []string{"~.", "corp.example"}
	return &nodeDNSIntegrationRunner{
		root: root, systemdVersion: "systemd 255 (255.4-1ubuntu8.5)\n", resolvConfTarget: nodeDNSResolvedStubPath(root),
		dns: append([]string(nil), dns...), domains: append([]string(nil), domains...), defaultRoute: true,
		originalDNS: dns, originalDomains: domains, originalDefaultRoute: true,
	}
}

func (runner *nodeDNSIntegrationRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	runner.calls = append(runner.calls, linuxplatform.ProbeCommand{Name: command.Name, Args: append([]string(nil), command.Args...), Stdin: append([]byte(nil), command.Stdin...)})
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	if key == runner.failOnceKey && !runner.failed {
		runner.failed = true
		return linuxplatform.ProbeResult{ExitCode: 1, Stderr: []byte("injected node DNS failure")}, nil
	}
	switch {
	case key == "systemd --version":
		return linuxplatform.ProbeResult{Stdout: []byte(runner.systemdVersion)}, nil
	case key == "systemctl is-active --quiet systemd-resolved.service":
		if runner.inactiveResolved {
			return linuxplatform.ProbeResult{ExitCode: 3, Stderr: []byte("inactive")}, nil
		}
		return linuxplatform.ProbeResult{}, nil
	case key == "ip link show dev eth0":
		if runner.missingLink {
			return linuxplatform.ProbeResult{ExitCode: 1, Stderr: []byte("Device does not exist")}, nil
		}
		return linuxplatform.ProbeResult{}, nil
	case key == "nft --check --file -":
		return linuxplatform.ProbeResult{}, nil
	case key == "readlink -f "+filepath.Join(runner.root, "etc", "resolv.conf"):
		return linuxplatform.ProbeResult{Stdout: []byte(runner.resolvConfTarget + "\n")}, nil
	case key == "nft --stateless -nn list table inet vpnctl_dns":
		if runner.tableDefinition == "" {
			return linuxplatform.ProbeResult{ExitCode: 1, Stderr: []byte("No such file or directory")}, nil
		}
		return linuxplatform.ProbeResult{Stdout: []byte(runner.tableDefinition)}, nil
	case key == "nft --file -":
		if _, err := os.Stat(filepath.Join(runner.root, "var", "lib", "vpnctl", "routing", NodeDNSResolvedSnapshotName)); err != nil {
			runner.mutatedBeforeSnapshot = true
		}
		runner.tableDefinition = string(command.Stdin)
		return linuxplatform.ProbeResult{}, nil
	case key == "nft delete table inet vpnctl_dns":
		runner.tableDefinition = ""
		return linuxplatform.ProbeResult{}, nil
	case key == "systemctl restart systemd-resolved.service":
		_, err := os.Stat(filepath.Join(runner.root, "run", "systemd", "resolved.conf.d", NodeDNSResolvedDropinName))
		runner.globalApplied = err == nil
		return linuxplatform.ProbeResult{}, nil
	case key == "resolvectl dns":
		if runner.globalApplied {
			return linuxplatform.ProbeResult{Stdout: []byte("Global: 127.0.0.1:1053\n")}, nil
		}
		return linuxplatform.ProbeResult{Stdout: []byte("Global:\n")}, nil
	case key == "resolvectl domain":
		if runner.globalApplied {
			return linuxplatform.ProbeResult{Stdout: []byte("Global: ~.\n")}, nil
		}
		return linuxplatform.ProbeResult{Stdout: []byte("Global:\n")}, nil
	case key == "resolvectl dns eth0":
		return linuxplatform.ProbeResult{Stdout: []byte("Link 2 (eth0): " + strings.Join(runner.dns, " ") + "\n")}, nil
	case key == "resolvectl domain eth0":
		return linuxplatform.ProbeResult{Stdout: []byte("Link 2 (eth0): " + strings.Join(runner.domains, " ") + "\n")}, nil
	case key == "resolvectl default-route eth0":
		value := "no"
		if runner.defaultRoute {
			value = "yes"
		}
		return linuxplatform.ProbeResult{Stdout: []byte("Link 2 (eth0): " + value + "\n")}, nil
	case strings.HasPrefix(key, "resolvectl dns eth0 "):
		runner.dns = normalizedNodeDNSTestValues(command.Args[2:])
		return linuxplatform.ProbeResult{}, nil
	case strings.HasPrefix(key, "resolvectl domain eth0 "):
		runner.domains = normalizedNodeDNSTestValues(command.Args[2:])
		return linuxplatform.ProbeResult{}, nil
	case strings.HasPrefix(key, "resolvectl default-route eth0 "):
		runner.defaultRoute = command.Args[2] == "yes"
		return linuxplatform.ProbeResult{}, nil
	case key == "resolvectl flush-caches":
		return linuxplatform.ProbeResult{}, nil
	default:
		return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected node DNS command %s", key)
	}
}

func normalizedNodeDNSTestValues(values []string) []string {
	if len(values) == 1 && values[0] == "" {
		return []string{}
	}
	return append([]string(nil), values...)
}

func (runner *nodeDNSIntegrationRunner) joinedCalls() string {
	lines := make([]string, len(runner.calls))
	for index, call := range runner.calls {
		lines[index] = strings.Join(append([]string{call.Name}, call.Args...), " ")
	}
	return strings.Join(lines, "\n")
}

func (runner *nodeDNSIntegrationRunner) hasMutation() bool {
	for _, call := range runner.calls {
		key := strings.Join(append([]string{call.Name}, call.Args...), " ")
		if key == "nft --file -" || key == "nft delete table inet vpnctl_dns" ||
			key == "systemctl restart systemd-resolved.service" || strings.HasPrefix(key, "resolvectl domain eth0 ") ||
			strings.HasPrefix(key, "resolvectl dns eth0 ") || strings.HasPrefix(key, "resolvectl default-route eth0 ") {
			return true
		}
	}
	return false
}
