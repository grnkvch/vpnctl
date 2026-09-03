package routing

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestReplaceDNSUpstreamsChangesOnlyRoleOwnedList(t *testing.T) {
	t.Parallel()
	before := gatewayDNSState()
	after, changed, err := ReplaceDNSUpstreams(before, []string{"9.9.9.9", "149.112.112.112"})
	if err != nil || !changed || after.Generation != before.Generation+1 {
		t.Fatalf("ReplaceDNSUpstreams() = generation %d, changed %t, %v", after.Generation, changed, err)
	}
	if !reflect.DeepEqual(after.DNS.IPv4, []string{"9.9.9.9", "149.112.112.112"}) || after.DNS.Scope != model.DNSUpstreamGateway {
		t.Fatalf("replacement DNS state = %+v", after.DNS)
	}
	after.DNS.IPv4[0] = "4.4.4.4"
	if before.DNS.IPv4[0] != "1.1.1.1" {
		t.Fatal("replacement mutated original DNS slice")
	}
	idempotent, changed, err := ReplaceDNSUpstreams(before, model.DefaultGatewayDNSUpstreams())
	if err != nil || changed || idempotent.Generation != before.Generation {
		t.Fatalf("idempotent replacement = generation %d, changed %t, %v", idempotent.Generation, changed, err)
	}
	for _, invalid := range [][]string{nil, {"127.0.0.1"}, {"2001:db8::53"}, {"9.9.9.9", "9.9.9.9"}} {
		if _, _, err := ReplaceDNSUpstreams(before, invalid); err == nil {
			t.Fatalf("invalid upstreams %v were accepted", invalid)
		}
	}
}

func TestRewriteNodeRoutingDNSPreservesPolicyAndDirectModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []RoutingDNSMode{NodeRoutingDNSPolicy, NodeRoutingDNSDirect} {
		t.Run(string(mode), func(t *testing.T) {
			request := nodeRoutingRenderFixture(t, mode)
			request.ActiveOutbound = nodeRoutingStandardBinding()
			candidate, err := RenderNodeRoutingConfig(request)
			if err != nil {
				t.Fatal(err)
			}
			updated, gotMode, err := RewriteNodeRoutingDNS(candidate.Bytes(), request.DirectDNSServers, []string{"9.9.9.9"})
			if err != nil || gotMode != mode {
				t.Fatalf("RewriteNodeRoutingDNS() mode=%s error=%v", gotMode, err)
			}
			if err := ValidateNodeRoutingConfig(updated, mode); err != nil {
				t.Fatalf("updated config invalid: %v\n%s", err, updated)
			}
			text := string(updated)
			if strings.Contains(text, "192.0.2.53") || strings.Contains(text, "198.51.100.53") || !strings.Contains(text, "udp://9.9.9.9:53#VPNCTL-DIRECT-DNS") {
				t.Fatalf("direct DNS was not replaced exactly:\n%s", text)
			}
			if mode == NodeRoutingDNSPolicy {
				if !strings.Contains(text, "udp://10.67.0.1:53#VPNCTL-GATEWAY") || !strings.Contains(text, "nameserver-policy:") {
					t.Fatalf("policy gateway path changed:\n%s", text)
				}
			} else if strings.Contains(text, "nameserver-policy:") {
				t.Fatalf("direct mode gained policy routing:\n%s", text)
			}
			if _, _, err := RewriteNodeRoutingDNS(candidate.Bytes(), []string{"4.4.4.4"}, []string{"9.9.9.9"}); err == nil {
				t.Fatal("authoritative/config DNS drift was accepted")
			}
		})
	}
}

func TestGatewayDNSConfigTransactionRestartsOnlyForwarderAndRollsBack(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(paths.ConfigDir, "generated", "gateway")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	before := gatewayDNSState()
	after, _, _ := ReplaceDNSUpstreams(before, []string{"9.9.9.9"})
	oldBytes := mustGatewayDNSBytes(t, before)
	path := filepath.Join(directory, GatewayDNSConfigFileName)
	if err := os.WriteFile(path, oldBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &dnsUpdateRunner{}
	transaction, err := PrepareGatewayDNSConfigTransaction(paths, runner, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	if config, err := DecodeGatewayDNSConfig(content); err != nil || !reflect.DeepEqual(config.UpstreamIPv4, []string{"9.9.9.9"}) {
		t.Fatalf("applied config = %+v, %v", config, err)
	}
	if err := transaction.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	content, _ = os.ReadFile(path)
	if !bytes.Equal(content, oldBytes) || !reflect.DeepEqual(runner.calls, []string{"systemctl restart vpnctl-dns.service", "systemctl restart vpnctl-dns.service"}) {
		t.Fatalf("rollback bytes/calls = %t / %v", bytes.Equal(content, oldBytes), runner.calls)
	}
}

func TestGatewayDNSConfigTransactionRestoresFileWhenRestartFails(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths, _ := store.NewPaths(root)
	directory := filepath.Join(paths.ConfigDir, "generated", "gateway")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	before := gatewayDNSState()
	after, _, _ := ReplaceDNSUpstreams(before, []string{"9.9.9.9"})
	oldBytes := mustGatewayDNSBytes(t, before)
	path := filepath.Join(directory, GatewayDNSConfigFileName)
	if err := os.WriteFile(path, oldBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &dnsUpdateRunner{failFirst: true}
	transaction, err := PrepareGatewayDNSConfigTransaction(paths, runner, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Apply(context.Background()); err == nil {
		t.Fatal("failed restart was accepted")
	}
	content, _ := os.ReadFile(path)
	if !bytes.Equal(content, oldBytes) || len(runner.calls) != 2 {
		t.Fatalf("failed activation did not restore prior config: calls=%v", runner.calls)
	}
}

func TestDNSConfigTransactionRefusesDriftBetweenPrepareAndApply(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths, _ := store.NewPaths(root)
	directory := filepath.Join(paths.ConfigDir, "generated", "gateway")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	before := gatewayDNSState()
	after, _, _ := ReplaceDNSUpstreams(before, []string{"9.9.9.9"})
	path := filepath.Join(directory, GatewayDNSConfigFileName)
	if err := os.WriteFile(path, mustGatewayDNSBytes(t, before), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &dnsUpdateRunner{}
	transaction, err := PrepareGatewayDNSConfigTransaction(paths, runner, before, after)
	if err != nil {
		t.Fatal(err)
	}
	drift := []byte("operator edit\n")
	if err := os.WriteFile(path, drift, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Apply(context.Background()); err == nil {
		t.Fatal("config drift after prepare was overwritten")
	}
	content, _ := os.ReadFile(path)
	if !bytes.Equal(content, drift) || len(runner.calls) != 0 {
		t.Fatalf("drift was changed or service restarted: content=%q calls=%v", content, runner.calls)
	}
}

func TestNodeDNSConfigTransactionPreservesModeAndRestartsOnlyMihomo(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths, _ := store.NewPaths(root)
	directory := filepath.Join(paths.ConfigDir, "generated", "node")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	request := nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy)
	request.ActiveOutbound = nodeRoutingStandardBinding()
	rendered, err := RenderNodeRoutingConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, NodeRoutingConfigFileName)
	if err := os.WriteFile(path, rendered.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	before := model.State{
		Host: model.Host{Role: model.RoleNode}, Nodes: []model.Node{{}},
		DNS: &model.DNSUpstreamState{SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamDirect, IPv4: append([]string(nil), request.DirectDNSServers...)},
	}
	after := before
	after.DNS = &model.DNSUpstreamState{SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamDirect, IPv4: []string{"9.9.9.9"}}
	runner := &dnsUpdateRunner{}
	transaction, err := PrepareNodeDNSConfigTransaction(paths, runner, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if err := transaction.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	content, _ := os.ReadFile(path)
	if err := ValidateNodeRoutingConfig(content, NodeRoutingDNSPolicy); err != nil || !strings.Contains(string(content), "udp://9.9.9.9:53#VPNCTL-DIRECT-DNS") {
		t.Fatalf("updated node DNS config invalid: %v\n%s", err, content)
	}
	if !reflect.DeepEqual(runner.calls, []string{"systemctl restart vpnctl-routing.service"}) {
		t.Fatalf("node runtime calls = %v", runner.calls)
	}
}

type dnsUpdateRunner struct {
	calls     []string
	failFirst bool
}

func (runner *dnsUpdateRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	runner.calls = append(runner.calls, command.Name+" "+strings.Join(command.Args, " "))
	if runner.failFirst {
		runner.failFirst = false
		return linuxplatform.ProbeResult{ExitCode: 1}, errors.New("injected restart failure")
	}
	return linuxplatform.ProbeResult{}, nil
}
