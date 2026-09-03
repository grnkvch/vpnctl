package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestRenderNodeRoutingGuardUsesAcceptedMarksAndFailClosedChains(t *testing.T) {
	t.Parallel()
	candidate := nodeRoutingGuardFixture(t)
	content := string(candidate.NFTablesDefinition())
	for _, required := range []string{
		"table inet vpnctl {",
		`comment "vpnctl:v2:node-routing-guard"`,
		"type filter hook prerouting priority -150; policy accept;",
		"type route hook output priority -150; policy accept;",
		"ct mark & 0xff000000 == 0x01000000 meta mark set ct mark",
		"ct mark & 0xff000000 == 0x02000000 meta mark set ct mark",
		"ct mark & 0xff000000 == 0x03000000 meta mark set ct mark",
		"ct mark & 0xff000000 == 0x04000000 meta mark set ct mark",
		"ip daddr 203.0.113.44 tcp dport 443 meta mark set (meta mark & 0x00ffffff) | 0x03000000 ct mark set meta mark return",
		"ip daddr 203.0.113.44 tcp dport 8443 meta mark set (meta mark & 0x00ffffff) | 0x03000000 ct mark set meta mark return",
		"ip daddr 203.0.113.44 udp dport 51820 meta mark set (meta mark & 0x00ffffff) | 0x03000000 ct mark set meta mark return",
		`iifname "vpnctl-wg" ct state new tcp dport 17000 meta mark set (meta mark & 0x00ffffff) | 0x04000000 ct mark set meta mark return`,
		"chain readiness {\n    jump not_ready\n  }",
		"ct state established,related meta mark & 0xff000000 == 0x01000000 return\n    drop",
		"ip6 daddr @selected_resolved_v6 meta mark set (meta mark & 0x00ffffff) | 0x02000000 ct mark set meta mark drop",
		"ip daddr @selected_resolved_v4 meta mark set (meta mark & 0x00ffffff) | 0x02000000 ct mark set meta mark return",
		"ip daddr 10.1.2.0/24 meta mark set (meta mark & 0x00ffffff) | 0x02000000 ct mark set meta mark return",
		"ip daddr 10.1.0.0/16 meta mark set (meta mark & 0x00ffffff) | 0x01000000 ct mark set meta mark return",
		"ip6 daddr 2001:db8:1:2::/64 meta mark set (meta mark & 0x00ffffff) | 0x02000000 ct mark set meta mark drop",
	} {
		if !strings.Contains(content, required) {
			t.Errorf("node routing guard lacks %q:\n%s", required, content)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "masquerade", "redirect", "queue", "log ", "0x00000000 ==", "jump ready\n  }\n\n  chain not_ready"} {
		if strings.Contains(content, forbidden) {
			t.Errorf("node routing guard contains unsafe behavior %q:\n%s", forbidden, content)
		}
	}
	assertGuardOrder(t, content, "ip daddr 10.1.2.0/24", "ip daddr 10.1.0.0/16", "ip daddr 10.0.0.0/8")
	assertGuardOrder(t, content, "ip6 daddr 2001:db8:1:2::/64", "ip6 daddr 2001:db8:1::/48", "ip6 daddr 2001:db8::/32")

	config := candidate.Config()
	wantRecovery := []NodeRoutingRecoveryPort{{Protocol: NodeRoutingTCP, Port: 443}, {Protocol: NodeRoutingTCP, Port: 8443}, {Protocol: NodeRoutingUDP, Port: 51820}}
	if !reflect.DeepEqual(config.RecoveryPorts, wantRecovery) {
		t.Fatalf("normalized recovery ports = %+v, want %+v", config.RecoveryPorts, wantRecovery)
	}
	decoded, err := decodeNodeRoutingGuardConfig(candidate.Bytes())
	if err != nil || !reflect.DeepEqual(decoded, config) {
		t.Fatalf("guard JSON round trip = %+v, %v", decoded, err)
	}
	repeated, err := RenderNodeRoutingGuardConfig(config)
	if err != nil || !bytes.Equal(repeated.Bytes(), candidate.Bytes()) || !bytes.Equal(repeated.NFTablesDefinition(), candidate.NFTablesDefinition()) {
		t.Fatalf("guard render is not deterministic: %v", err)
	}
	defensive := candidate.NFTablesDefinition()
	defensive[0] = 'X'
	if bytes.Equal(defensive, candidate.NFTablesDefinition()) {
		t.Fatal("NFTablesDefinition exposed mutable storage")
	}
}

func TestNodeRoutingGuardRejectsBroadRecoveryAndMalformedConfig(t *testing.T) {
	t.Parallel()
	base := nodeRoutingGuardFixture(t).Config()
	for name, mutate := range map[string]func(*NodeRoutingGuardConfig){
		"missing recovery": func(value *NodeRoutingGuardConfig) { value.RecoveryPorts = nil },
		"duplicate recovery": func(value *NodeRoutingGuardConfig) {
			value.RecoveryPorts = append(value.RecoveryPorts, value.RecoveryPorts[0])
		},
		"unknown protocol":        func(value *NodeRoutingGuardConfig) { value.RecoveryPorts[0].Protocol = "any" },
		"zero port":               func(value *NodeRoutingGuardConfig) { value.RecoveryPorts[0].Port = 0 },
		"invalid gateway":         func(value *NodeRoutingGuardConfig) { value.GatewayIPv4 = "0.0.0.0/0" },
		"invalid route interface": func(value *NodeRoutingGuardConfig) { value.DirectRoute.Interface = "eth0;ip" },
		"invalid next hop":        func(value *NodeRoutingGuardConfig) { value.DirectRoute.GatewayIPv4 = "::1" },
		"invalid ingress":         func(value *NodeRoutingGuardConfig) { value.IngressEndpoints[0].Interface = "*" },
		"invalid matcher":         func(value *NodeRoutingGuardConfig) { value.Matcher.SchemaVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			value.Matcher = cloneNodeRoutingMatcherIR(base.Matcher)
			value.RecoveryPorts = append([]NodeRoutingRecoveryPort(nil), base.RecoveryPorts...)
			value.IngressEndpoints = append([]NodeRoutingIngressEndpoint(nil), base.IngressEndpoints...)
			mutate(&value)
			if _, err := RenderNodeRoutingGuardConfig(value); err == nil {
				t.Fatal("invalid node routing guard config rendered")
			}
		})
	}

	tampered := strings.Replace(string(nodeRoutingGuardFixture(t).Bytes()), `"gateway_ipv4":`, "\"scope\": \"process\",\n  \"gateway_ipv4\":", 1)
	if _, err := decodeNodeRoutingGuardConfig([]byte(tampered)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown-field decode error = %v", err)
	}
	trailing := append(nodeRoutingGuardFixture(t).Bytes(), []byte(`{"extra":true}`)...)
	if _, err := decodeNodeRoutingGuardConfig(trailing); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing JSON decode error = %v", err)
	}
}

func TestNodeRoutingGuardInstallOrdersKernelBoundaryAndRollsBackFailure(t *testing.T) {
	t.Parallel()
	candidate := nodeRoutingGuardFixture(t)
	runner := newNodeRoutingGuardRunner()
	manager, err := NewNodeRoutingGuardManager(runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(context.Background(), candidate); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	joined := runner.joinedCalls()
	for _, required := range []string{
		"sysctl -q -w net.ipv4.conf.all.rp_filter=1",
		"sysctl -q -w net.ipv4.conf.all.src_valid_mark=1",
		"sysctl -q -w net.ipv4.conf.eth0.rp_filter=1",
		"ip -4 route replace unreachable default metric 42760 table 20001 proto static",
		"ip -4 route replace default via 192.0.2.1 dev eth0 table 20002 proto static",
		"ip -4 rule add priority 10000 fwmark 0x03000000/0xff000000 table 20002",
		"ip -4 rule add priority 10010 fwmark 0x04000000/0xff000000 table 20002",
		"ip -4 rule add priority 10020 fwmark 0x02000000/0xff000000 table 20001",
		"nft --check --file -", "nft --file -",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("guard installation lacks %q:\n%s", required, joined)
		}
	}
	assertCallOrder(t, joined,
		"ip -4 route replace unreachable default metric 42760 table 20001 proto static",
		"ip -4 rule add priority 10020 fwmark 0x02000000/0xff000000 table 20001",
		"nft --file -",
	)
	if got := string(runner.lastAppliedNFT); !strings.Contains(got, "jump not_ready") || strings.Contains(got, "flush ruleset") {
		t.Fatalf("installed nftables batch is not fail-closed:\n%s", got)
	}

	failed := newNodeRoutingGuardRunner()
	failed.failNFTApply = true
	failedManager, _ := NewNodeRoutingGuardManager(failed)
	err = failedManager.Install(context.Background(), candidate)
	if err == nil || !strings.Contains(err.Error(), "injected nft apply failure") {
		t.Fatalf("failed Install() error = %v", err)
	}
	rollbackCalls := failed.joinedCalls()
	for _, required := range []string{
		"ip -4 route flush table 20001",
		"ip -6 route flush table 20002",
		"ip -4 rule del priority 10000 fwmark 0x03000000/0xff000000 table 20002",
		"ip -4 rule del priority 10020 fwmark 0x02000000/0xff000000 table 20001",
		"sysctl -q -w net.ipv4.conf.all.rp_filter=0",
		"sysctl -q -w net.ipv4.conf.all.src_valid_mark=0",
		"sysctl -q -w net.ipv4.conf.eth0.rp_filter=0",
	} {
		if !strings.Contains(rollbackCalls, required) {
			t.Errorf("failed install did not restore %q:\n%s", required, rollbackCalls)
		}
	}
}

func TestNodeRoutingGuardReadyAndCrashTransitionsUseSafeOrder(t *testing.T) {
	t.Parallel()
	runner := newNodeRoutingGuardRunner()
	runner.tableDefinition = string(nodeRoutingGuardFixture(t).NFTablesDefinition())
	runner.tunReady = true
	manager, _ := NewNodeRoutingGuardManager(runner)
	if err := manager.Ready(context.Background()); err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
	readyCalls := runner.joinedCalls()
	assertCallOrder(t, readyCalls,
		"ip -4 route replace default dev vpnctl0 metric 10 table 20001 proto static",
		"nft --file -",
	)
	if !strings.Contains(string(runner.lastAppliedNFT), "readiness jump ready") {
		t.Fatalf("ready switch batch = %q", runner.lastAppliedNFT)
	}

	runner.calls = nil
	if err := manager.NotReady(context.Background()); err != nil {
		t.Fatalf("NotReady() error = %v", err)
	}
	notReadyCalls := runner.joinedCalls()
	assertCallOrder(t, notReadyCalls,
		"nft --file -",
		"ip -4 route del default dev vpnctl0 metric 10 table 20001",
	)
	if !strings.Contains(string(runner.lastAppliedNFT), "readiness jump not_ready") {
		t.Fatalf("not-ready switch batch = %q", runner.lastAppliedNFT)
	}
}

func TestNodeRoutingGuardWaitReadyKeepsBootClosedUntilAllListenersExist(t *testing.T) {
	t.Parallel()
	runner := newNodeRoutingGuardRunner()
	runner.tableDefinition = string(nodeRoutingGuardFixture(t).NFTablesDefinition())
	manager, _ := NewNodeRoutingGuardManager(runner)
	waits := 0
	manager.wait = func(context.Context, time.Duration) error {
		waits++
		runner.tunReady = true
		runner.dnsReady = true
		return nil
	}
	if err := manager.WaitReady(context.Background()); err != nil {
		t.Fatalf("WaitReady() error = %v", err)
	}
	if waits != 1 {
		t.Fatalf("readiness wait count = %d, want 1", waits)
	}
	joined := runner.joinedCalls()
	assertCallOrder(t, joined,
		"ip -o link show dev vpnctl0",
		"ip -4 route replace default dev vpnctl0 metric 10 table 20001 proto static",
		"nft --file -",
	)
}

func TestNodeRoutingGuardServiceRequiresCanonicalRootOnlyConfig(t *testing.T) {
	t.Parallel()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(paths.ConfigDir, "generated", "node")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := nodeRoutingGuardConfigPath(paths)
	candidate := nodeRoutingGuardFixture(t)
	if err := os.WriteFile(path, candidate.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := newNodeRoutingGuardRunner()
	if err := RunNodeRoutingGuardService(context.Background(), paths, runner, NodeRoutingGuardInstallAction); err != nil {
		t.Fatalf("RunNodeRoutingGuardService() error = %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	before := len(runner.calls)
	if err := RunNodeRoutingGuardService(context.Background(), paths, runner, NodeRoutingGuardInstallAction); err == nil || !strings.Contains(err.Error(), "root-only") {
		t.Fatalf("public config error = %v", err)
	}
	if len(runner.calls) != before {
		t.Fatal("unsafe config performed host commands")
	}
	if err := RunNodeRoutingGuardService(context.Background(), paths, runner, "remove"); err == nil {
		t.Fatal("unsupported guard action succeeded")
	}
}

func TestNodeRoutingGuardNFTablesParsesWithNativeNFT(t *testing.T) {
	binary := os.Getenv("VPNCTL_NFT")
	if binary == "" {
		t.Skip("set VPNCTL_NFT to a Linux nft binary for native parser validation")
	}
	candidate := nodeRoutingGuardFixture(t)
	command := exec.Command(binary, "--check", "--file", "-")
	command.Stdin = bytes.NewReader(candidate.NFTablesDefinition())
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("native nft rejected node routing guard: %v:\n%s\nrules:\n%s", err, output, candidate.NFTablesDefinition())
	}
}

func TestNodeRoutingGuardConstantsMatchAcceptedManifest(t *testing.T) {
	t.Parallel()
	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "v2", "COMPONENT_LIMITS.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Limits struct {
			Routing struct {
				MarkMask               string `json:"mark_mask"`
				PreservedMarkMask      string `json:"preserved_mark_mask"`
				DirectMark             string `json:"direct_mark"`
				SelectedMark           string `json:"selected_mark"`
				RecoveryMark           string `json:"recovery_mark"`
				IngressResponseMark    string `json:"ingress_response_mark"`
				NFTOutputPriority      int    `json:"nft_output_priority"`
				NFTPreroutingPriority  int    `json:"nft_prerouting_priority"`
				RecoveryRulePriority   int    `json:"recovery_rule_priority"`
				IngressRulePriority    int    `json:"ingress_rule_priority"`
				SelectedRulePriority   int    `json:"selected_rule_priority"`
				SelectedTable          int    `json:"selected_table"`
				GatewayTable           int    `json:"gateway_table"`
				UnreachableRouteMetric int    `json:"unreachable_metric"`
				ReadyTUNRouteMetric    int    `json:"tun_metric"`
			} `json:"routing"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	routing := manifest.Limits.Routing
	want := []any{
		"0xff000000", "0x00ffffff", "0x01000000", "0x02000000", "0x03000000", "0x04000000",
		-150, -150, 10000, 10010, 10020, 20001, 20002, 42760, 10,
	}
	got := []any{
		routing.MarkMask, routing.PreservedMarkMask, routing.DirectMark, routing.SelectedMark, routing.RecoveryMark, routing.IngressResponseMark,
		routing.NFTOutputPriority, routing.NFTPreroutingPriority, routing.RecoveryRulePriority, routing.IngressRulePriority,
		routing.SelectedRulePriority, routing.SelectedTable, routing.GatewayTable, routing.UnreachableRouteMetric, routing.ReadyTUNRouteMetric,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("accepted routing manifest values = %v, want %v", got, want)
	}
	production := []any{
		nftMark(linuxplatform.VPNCTLMarkMask), nftMark(linuxplatform.VPNCTLPreservedMarkMask), nftMark(linuxplatform.VPNCTLDirectMark),
		nftMark(linuxplatform.VPNCTLSelectedMark), nftMark(linuxplatform.VPNCTLRecoveryMark), nftMark(linuxplatform.VPNCTLIngressResponseMark),
		linuxplatform.VPNCTLNFTablesManglePriority, linuxplatform.VPNCTLNFTablesManglePriority,
		linuxplatform.VPNCTLRecoveryRulePriority, linuxplatform.VPNCTLIngressRulePriority, linuxplatform.VPNCTLSelectedRulePriority,
		mustAtoi(t, linuxplatform.VPNCTLSelectedRouteTable), mustAtoi(t, linuxplatform.VPNCTLGatewayRouteTable),
		linuxplatform.VPNCTLUnreachableRouteMetric, linuxplatform.VPNCTLReadyTUNRouteMetric,
	}
	if !reflect.DeepEqual(production, want) {
		t.Fatalf("production routing values = %v, want manifest %v", production, want)
	}
}

func nodeRoutingGuardFixture(t *testing.T) NodeRoutingGuardCandidate {
	t.Helper()
	matcher := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy).Matcher
	candidate, err := RenderNodeRoutingGuardConfig(NodeRoutingGuardConfig{
		Matcher:     matcher,
		GatewayIPv4: "203.0.113.44",
		DirectRoute: NodeRoutingDirectRoute{Interface: "eth0", GatewayIPv4: "192.0.2.1"},
		RecoveryPorts: []NodeRoutingRecoveryPort{
			{Protocol: NodeRoutingUDP, Port: 51820},
			{Protocol: NodeRoutingTCP, Port: 8443},
			{Protocol: NodeRoutingTCP, Port: 443},
		},
		IngressEndpoints: []NodeRoutingIngressEndpoint{{Interface: "vpnctl-wg", Protocol: NodeRoutingTCP, Port: 17000}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func assertGuardOrder(t *testing.T, content string, values ...string) {
	t.Helper()
	previous := -1
	for _, value := range values {
		index := strings.Index(content, value)
		if index < 0 || index <= previous {
			t.Fatalf("guard order %v is not preserved:\n%s", values, content)
		}
		previous = index
	}
}

func assertCallOrder(t *testing.T, calls string, values ...string) {
	t.Helper()
	previous := -1
	for _, value := range values {
		index := strings.Index(calls, value)
		if index < 0 || index <= previous {
			t.Fatalf("call order %v is not preserved:\n%s", values, calls)
		}
		previous = index
	}
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	result, err := strconv.Atoi(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type nodeRoutingGuardRunner struct {
	calls           []linuxplatform.ProbeCommand
	tableDefinition string
	lastAppliedNFT  []byte
	failNFTApply    bool
	rulesInstalled  bool
	tunReady        bool
	dnsReady        bool
}

func newNodeRoutingGuardRunner() *nodeRoutingGuardRunner { return &nodeRoutingGuardRunner{} }

func (runner *nodeRoutingGuardRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	runner.calls = append(runner.calls, linuxplatform.ProbeCommand{Name: command.Name, Args: append([]string(nil), command.Args...), Stdin: append([]byte(nil), command.Stdin...)})
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	switch {
	case key == "nft --json list tables":
		if runner.tableDefinition == "" {
			return linuxplatform.ProbeResult{Stdout: []byte(`{"nftables":[]}`)}, nil
		}
		return linuxplatform.ProbeResult{Stdout: []byte(`{"nftables":[{"table":{"family":"inet","name":"vpnctl"}}]}`)}, nil
	case key == "nft --stateless -nn list table inet vpnctl":
		if runner.tableDefinition == "" {
			return linuxplatform.ProbeResult{ExitCode: 1, Stderr: []byte("No such file or directory")}, nil
		}
		return linuxplatform.ProbeResult{Stdout: []byte(runner.tableDefinition)}, nil
	case key == "nft --check --file -":
		return linuxplatform.ProbeResult{}, nil
	case key == "nft --file -":
		if runner.failNFTApply {
			runner.failNFTApply = false
			return linuxplatform.ProbeResult{ExitCode: 1, Stderr: []byte("injected nft apply failure")}, nil
		}
		runner.lastAppliedNFT = append([]byte(nil), command.Stdin...)
		if strings.Contains(string(command.Stdin), "table inet vpnctl {") {
			runner.tableDefinition = string(command.Stdin)
		}
		return linuxplatform.ProbeResult{}, nil
	case strings.HasPrefix(key, "ip -json -4 route show table "), strings.HasPrefix(key, "ip -json -6 route show table "):
		return linuxplatform.ProbeResult{Stdout: []byte("[]")}, nil
	case key == "ip -json -4 rule show":
		if !runner.rulesInstalled {
			return linuxplatform.ProbeResult{Stdout: []byte("[]")}, nil
		}
		return linuxplatform.ProbeResult{Stdout: []byte(`[
{"priority":10000,"from":"all","table":20002,"fwmark":"0x03000000","fwmask":"0xff000000"},
{"priority":10010,"from":"all","table":20002,"fwmark":"0x04000000","fwmask":"0xff000000"},
{"priority":10020,"from":"all","table":20001,"fwmark":"0x02000000","fwmask":"0xff000000"}
]`)}, nil
	case key == "ip -json -6 rule show":
		return linuxplatform.ProbeResult{Stdout: []byte("[]")}, nil
	case strings.HasPrefix(key, "sysctl -n "):
		return linuxplatform.ProbeResult{Stdout: []byte("0\n")}, nil
	case strings.HasPrefix(key, "ip -4 rule add "):
		runner.rulesInstalled = true
		return linuxplatform.ProbeResult{}, nil
	case strings.HasPrefix(key, "ip -4 rule del "):
		if strings.Contains(key, "priority 10020") {
			runner.rulesInstalled = false
		}
		return linuxplatform.ProbeResult{}, nil
	case key == "ip -o link show dev vpnctl0":
		if !runner.tunReady {
			return linuxplatform.ProbeResult{ExitCode: 1}, nil
		}
		return linuxplatform.ProbeResult{Stdout: []byte("7: vpnctl0: <POINTOPOINT,UP,LOWER_UP> mtu 1400 state UNKNOWN\n")}, nil
	case key == "ss -H -lunp sport = :1053", key == "ss -H -ltnp sport = :1053":
		if !runner.dnsReady {
			return linuxplatform.ProbeResult{ExitCode: 1}, nil
		}
		return linuxplatform.ProbeResult{Stdout: []byte(`UNCONN 0 0 127.0.0.1:1053 0.0.0.0:* users:(("mihomo",pid=7,fd=8))`)}, nil
	default:
		return linuxplatform.ProbeResult{}, nil
	}
}

func (runner *nodeRoutingGuardRunner) joinedCalls() string {
	lines := make([]string, len(runner.calls))
	for index, call := range runner.calls {
		lines[index] = strings.Join(append([]string{call.Name}, call.Args...), " ")
	}
	return strings.Join(lines, "\n")
}
