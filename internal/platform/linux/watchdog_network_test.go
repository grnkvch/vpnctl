package linux

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNetworkManagerSnapshotsOnlyOwnedResources(t *testing.T) {
	t.Parallel()

	runner := newWatchdogRunner(map[string]ProbeResult{
		watchdogCommandKey("nft", "--json", "list", "tables"): {
			Stdout: []byte(`{"nftables":[{"table":{"family":"inet","name":"foreign"}},{"table":{"family":"inet","name":"vpnctl"}}]}`),
		},
		watchdogCommandKey("nft", "--stateless", "-nn", "list", "table", "inet", "vpnctl"): {
			Stdout: []byte("table inet vpnctl {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"),
		},
		watchdogCommandKey("ip", "-json", "-4", "route", "show", "table", "20001"): {
			Stdout: []byte(`[{"dst":"default","table":20001,"protocol":"static","type":"unreachable","metric":42760}]`),
		},
		watchdogCommandKey("ip", "-json", "-4", "route", "show", "table", "20002"): {
			Stdout: []byte(`[{"dst":"default","gateway":"10.67.0.1","dev":"vpnctl-wg","table":20002,"protocol":"static"}]`),
		},
		watchdogCommandKey("ip", "-json", "-6", "route", "show", "table", "20001"): {Stdout: []byte(`[]`)},
		watchdogCommandKey("ip", "-json", "-6", "route", "show", "table", "20002"): {Stdout: []byte(`[]`)},
		watchdogCommandKey("ip", "-json", "-4", "rule", "show"): {
			Stdout: []byte(`[{"priority":0,"from":"all","table":"local"},{"priority":10000,"from":"all","table":20002,"fwmark":"0x03000000","fwmask":"0xff000000"},{"priority":12000,"from":"all","table":"main","fwmark":"0x1234","fwmask":"0xffff"},{"priority":32766,"from":"all","table":"main"}]`),
		},
		watchdogCommandKey("ip", "-json", "-6", "rule", "show"):                {Stdout: []byte(`[{"priority":0,"from":"all","table":"local"}]`)},
		watchdogCommandKey("sysctl", "-n", "net.ipv4.conf.all.src_valid_mark"): {Stdout: []byte("0\n")},
		watchdogCommandKey("sysctl", "-n", "net.ipv4.ip_forward"):              {Stdout: []byte("1\n")},
	})
	manager, err := NewNetworkManager(runner)
	if err != nil {
		t.Fatalf("NewNetworkManager() error = %v", err)
	}
	snapshot, err := manager.Snapshot(context.Background(), OwnedNetworkScope{Sysctls: []string{
		"net.ipv4.ip_forward", "net.ipv4.conf.all.src_valid_mark",
	}})
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if !snapshot.NFTables.Present || strings.Contains(snapshot.NFTables.Definition, "foreign") {
		t.Fatalf("unexpected nftables snapshot: %+v", snapshot.NFTables)
	}
	if len(snapshot.Routes) != 2 || len(snapshot.PolicyRules) != 1 || len(snapshot.Sysctls) != 2 {
		t.Fatalf("unexpected owned snapshot: %+v", snapshot)
	}
	if snapshot.PolicyRules[0].Priority != 10000 || snapshot.PolicyRules[0].FWMark != "0x03000000" {
		t.Fatalf("unexpected normalized policy rule: %+v", snapshot.PolicyRules[0])
	}
	if got := []string{snapshot.Sysctls[0].Name, snapshot.Sysctls[1].Name}; !reflect.DeepEqual(got, []string{
		"net.ipv4.conf.all.src_valid_mark", "net.ipv4.ip_forward",
	}) {
		t.Fatalf("sysctls are not deterministic: %v", got)
	}
}

func TestNetworkManagerRejectsReservedForeignRuleAndUnsafeSysctlBeforeMutation(t *testing.T) {
	t.Parallel()

	runner := newWatchdogRunner(map[string]ProbeResult{
		watchdogCommandKey("nft", "--json", "list", "tables"):                      {Stdout: []byte(`{"nftables":[]}`)},
		watchdogCommandKey("ip", "-json", "-4", "route", "show", "table", "20001"): {Stdout: []byte(`[]`)},
		watchdogCommandKey("ip", "-json", "-4", "route", "show", "table", "20002"): {Stdout: []byte(`[]`)},
		watchdogCommandKey("ip", "-json", "-6", "route", "show", "table", "20001"): {Stdout: []byte(`[]`)},
		watchdogCommandKey("ip", "-json", "-6", "route", "show", "table", "20002"): {Stdout: []byte(`[]`)},
		watchdogCommandKey("ip", "-json", "-4", "rule", "show"): {
			Stdout: []byte(`[{"priority":10020,"from":"all","table":20001,"fwmark":"0x01000000","fwmask":"0xff000000"}]`),
		},
		watchdogCommandKey("ip", "-json", "-6", "rule", "show"): {Stdout: []byte(`[]`)},
	})
	manager, _ := NewNetworkManager(runner)
	if _, err := manager.Snapshot(context.Background(), OwnedNetworkScope{}); err == nil || !strings.Contains(err.Error(), "non-vpnctl") {
		t.Fatalf("Snapshot(reserved foreign rule) error = %v", err)
	}
	before := len(runner.calls)
	if _, err := manager.Snapshot(context.Background(), OwnedNetworkScope{Sysctls: []string{"kernel.hostname"}}); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("Snapshot(unsafe sysctl) error = %v", err)
	}
	if len(runner.calls) != before {
		t.Fatal("unsafe sysctl scope performed host probes")
	}
}

func TestNetworkManagerTreatsMissingOwnedFIBTableAsEmpty(t *testing.T) {
	t.Parallel()

	missing := ProbeResult{ExitCode: 2, Stderr: []byte("Error: ipv6: FIB table does not exist.\nDump terminated\n")}
	runner := newWatchdogRunner(map[string]ProbeResult{
		watchdogCommandKey("nft", "--json", "list", "tables"):                      {Stdout: []byte(`{"nftables":[]}`)},
		watchdogCommandKey("ip", "-json", "-4", "route", "show", "table", "20001"): {Stdout: []byte(`[]`)},
		watchdogCommandKey("ip", "-json", "-4", "route", "show", "table", "20002"): {Stdout: []byte(`[]`)},
		watchdogCommandKey("ip", "-json", "-6", "route", "show", "table", "20001"): missing,
		watchdogCommandKey("ip", "-json", "-6", "route", "show", "table", "20002"): missing,
		watchdogCommandKey("ip", "-json", "-4", "rule", "show"):                    {Stdout: []byte(`[]`)},
		watchdogCommandKey("ip", "-json", "-6", "rule", "show"):                    {Stdout: []byte(`[]`)},
	})
	manager, _ := NewNetworkManager(runner)
	snapshot, err := manager.Snapshot(context.Background(), OwnedNetworkScope{})
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if len(snapshot.Routes) != 0 {
		t.Fatalf("missing FIB produced routes: %+v", snapshot.Routes)
	}
}

func TestNetworkManagerRestoreTouchesOnlyFixedOwnership(t *testing.T) {
	t.Parallel()

	definition := "table inet vpnctl {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n"
	snapshot := NetworkSnapshot{
		SchemaVersion: NetworkSnapshotSchemaVersion,
		NFTables:      NFTablesSnapshot{Present: true, Definition: definition},
		Routes: []Route{
			{Family: "ipv4", Destination: "default", Table: "20001", Protocol: "static", Type: "unreachable", Metric: 42760},
			{Family: "ipv4", Destination: "default", Gateway: "10.67.0.1", Device: "vpnctl-wg", Table: "20002", Protocol: "static"},
		},
		PolicyRules: []PolicyRule{ownedPolicyRules[10020]},
		Sysctls:     []SysctlSnapshot{{Name: "net.ipv4.ip_forward", Value: "0"}},
	}
	runner := newWatchdogRunner(map[string]ProbeResult{
		watchdogCommandKey("nft", "--json", "list", "tables"): {Stdout: []byte(`{"nftables":[{"table":{"family":"inet","name":"foreign_keep"}},{"table":{"family":"inet","name":"vpnctl"}}]}`)},
		watchdogCommandKey("nft", "--stateless", "-nn", "list", "table", "inet", "vpnctl"): {
			Stdout: []byte("table inet vpnctl {\n\tchain candidate { }\n}\n"),
		},
		watchdogCommandKey("ip", "-json", "-4", "rule", "show"): {
			Stdout: []byte(`[{"priority":10000,"from":"all","table":20002,"fwmark":"0x03000000","fwmask":"0xff000000"},{"priority":10010,"from":"all","table":20002,"fwmark":"0x04000000","fwmask":"0xff000000"},{"priority":10020,"from":"all","table":20001,"fwmark":"0x02000000","fwmask":"0xff000000"},{"priority":12000,"from":"all","table":"main","fwmark":"0x1234","fwmask":"0xffff"}]`),
		},
	})
	manager, _ := NewNetworkManager(runner)
	if err := manager.Restore(context.Background(), snapshot); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}

	joined := runner.joinedCalls()
	for _, required := range []string{
		"nft --check --file -", "nft --file -",
		"ip -4 route flush table 20001", "ip -6 route flush table 20002",
		"ip -4 rule del priority 10000 fwmark 0x03000000/0xff000000 table 20002",
		"ip -4 rule add priority 10020 fwmark 0x02000000/0xff000000 table 20001",
		"sysctl -q -w net.ipv4.ip_forward=0",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("restore calls missing %q:\n%s", required, joined)
		}
	}
	for _, forbidden := range []string{"flush ruleset", "foreign_keep", "table 21000", "priority 12000", "kernel.hostname"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("restore touched foreign surface %q:\n%s", forbidden, joined)
		}
	}
	for _, call := range runner.calls {
		if call.Name == "nft" && reflect.DeepEqual(call.Args, []string{"--file", "-"}) {
			text := string(call.Stdin)
			if !strings.Contains(text, "delete table inet vpnctl\n"+definition) || strings.Contains(text, "foreign_keep") {
				t.Fatalf("unexpected nftables rollback batch:\n%s", text)
			}
		}
	}
}

func TestNetworkManagerRestoresForwardingBeforeDependentSysctls(t *testing.T) {
	t.Parallel()

	snapshot := NetworkSnapshot{
		SchemaVersion: NetworkSnapshotSchemaVersion,
		Routes:        []Route{},
		PolicyRules:   []PolicyRule{},
		Sysctls: []SysctlSnapshot{
			{Name: "net.ipv4.conf.all.accept_redirects", Value: "0"},
			{Name: "net.ipv4.ip_forward", Value: "0"},
		},
	}
	runner := newWatchdogRunner(map[string]ProbeResult{
		watchdogCommandKey("nft", "--json", "list", "tables"):              {Stdout: []byte(`{"nftables":[]}`)},
		watchdogCommandKey("ip", "-json", "-4", "rule", "show"):            {Stdout: []byte(`[]`)},
		watchdogCommandKey("ip", "-6", "route", "flush", "table", "20001"): {ExitCode: 2, Stderr: []byte("FIB table does not exist")},
		watchdogCommandKey("ip", "-6", "route", "flush", "table", "20002"): {ExitCode: 2, Stderr: []byte("FIB table does not exist")},
	})
	manager, _ := NewNetworkManager(runner)
	if err := manager.Restore(context.Background(), snapshot); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	joined := runner.joinedCalls()
	forwarding := strings.Index(joined, "sysctl -q -w net.ipv4.ip_forward=0")
	redirects := strings.Index(joined, "sysctl -q -w net.ipv4.conf.all.accept_redirects=0")
	if forwarding < 0 || redirects < 0 || forwarding > redirects {
		t.Fatalf("dependent sysctl restore order is unsafe:\n%s", joined)
	}
}

func TestNetworkManagerRestoreAttemptsLaterClassesAfterFailure(t *testing.T) {
	t.Parallel()

	snapshot := NetworkSnapshot{
		SchemaVersion: NetworkSnapshotSchemaVersion,
		Routes:        []Route{},
		PolicyRules:   []PolicyRule{},
		Sysctls:       []SysctlSnapshot{{Name: "net.ipv4.ip_forward", Value: "0"}},
	}
	runner := newWatchdogRunner(map[string]ProbeResult{
		watchdogCommandKey("nft", "--json", "list", "tables"):              {Stdout: []byte(`{"nftables":[]}`)},
		watchdogCommandKey("ip", "-4", "route", "flush", "table", "20001"): {ExitCode: 2, Stderr: []byte("injected route error")},
		watchdogCommandKey("ip", "-json", "-4", "rule", "show"):            {Stdout: []byte(`[]`)},
	})
	manager, _ := NewNetworkManager(runner)
	err := manager.Restore(context.Background(), snapshot)
	if err == nil || !strings.Contains(err.Error(), "injected route error") {
		t.Fatalf("Restore() error = %v", err)
	}
	if !strings.Contains(runner.joinedCalls(), "sysctl -q -w net.ipv4.ip_forward=0") {
		t.Fatal("Restore() did not attempt sysctl after route failure")
	}
}

func TestNetworkSnapshotRejectsArbitraryNFTablesCommandsAndRoutes(t *testing.T) {
	t.Parallel()

	tests := []NetworkSnapshot{
		{SchemaVersion: 1, NFTables: NFTablesSnapshot{Present: true, Definition: "table inet vpnctl { }\ndelete table inet foreign"}, Routes: []Route{}, PolicyRules: []PolicyRule{}, Sysctls: []SysctlSnapshot{}},
		{SchemaVersion: 1, Routes: []Route{{Family: "ipv4", Destination: "default", Table: "main"}}, PolicyRules: []PolicyRule{}, Sysctls: []SysctlSnapshot{}},
		{SchemaVersion: 1, Routes: []Route{}, PolicyRules: []PolicyRule{}, Sysctls: []SysctlSnapshot{{Name: "kernel.hostname", Value: "1"}}},
	}
	for index, snapshot := range tests {
		if err := snapshot.Validate(); !errors.Is(err, ErrInvalidNetworkSnapshot) {
			t.Errorf("snapshot %d Validate() error = %v", index, err)
		}
	}
}

func TestRenderWatchdogUnitsPinsIndependent120SecondTimer(t *testing.T) {
	t.Parallel()

	units, err := RenderWatchdogUnits(DefaultVPNCTLBinaryPath)
	if err != nil {
		t.Fatalf("RenderWatchdogUnits() error = %v", err)
	}
	if len(units) != 2 || units[0].Name != WatchdogServiceUnitName || units[1].Name != WatchdogTimerUnitName {
		t.Fatalf("unexpected watchdog units: %+v", units)
	}
	service := string(units[0].Content)
	timer := string(units[1].Content)
	for _, required := range []string{
		"ExecStart=/usr/local/bin/vpnctl __watchdog-rollback %i", "Restart=on-failure",
		"StandardOutput=null", "StandardError=null", "CAP_NET_ADMIN",
	} {
		if !strings.Contains(service, required) {
			t.Errorf("watchdog service missing %q", required)
		}
	}
	for _, required := range []string{"OnActiveSec=120s", "AccuracySec=1ms", "RandomizedDelaySec=0", "RemainAfterElapse=no"} {
		if !strings.Contains(timer, required) {
			t.Errorf("watchdog timer missing %q", required)
		}
	}
	if _, err := RenderWatchdogUnits("relative/vpnctl"); err == nil {
		t.Fatal("RenderWatchdogUnits() accepted a relative binary")
	}
	if _, err := WatchdogTimerInstance("../../escape"); err == nil {
		t.Fatal("WatchdogTimerInstance() accepted an unsafe ID")
	}
}

type watchdogRunner struct {
	results map[string]ProbeResult
	calls   []ProbeCommand
}

func newWatchdogRunner(results map[string]ProbeResult) *watchdogRunner {
	return &watchdogRunner{results: results}
}

func (runner *watchdogRunner) Run(_ context.Context, command ProbeCommand) (ProbeResult, error) {
	runner.calls = append(runner.calls, ProbeCommand{Name: command.Name, Args: append([]string(nil), command.Args...), Stdin: append([]byte(nil), command.Stdin...)})
	if result, found := runner.results[watchdogCommandKey(command.Name, command.Args...)]; found {
		return result, nil
	}
	return ProbeResult{}, nil
}

func (runner *watchdogRunner) joinedCalls() string {
	lines := make([]string, 0, len(runner.calls))
	for _, call := range runner.calls {
		lines = append(lines, call.Name+" "+strings.Join(call.Args, " "))
	}
	return strings.Join(lines, "\n")
}

func watchdogCommandKey(name string, args ...string) string {
	return name + "\x00" + strings.Join(args, "\x00")
}
