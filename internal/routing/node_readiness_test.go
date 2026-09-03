package routing

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestNodeRoutingReadinessGateRequiresServiceTUNAndBothDNSProtocols(t *testing.T) {
	t.Parallel()
	candidate := nodeRoutingReadinessCandidate(t)
	result := passedNodeRoutingReadiness(candidate.Descriptor())
	prober := &staticNodeRoutingReadinessProber{result: result}
	gate, err := NewNodeRoutingReadinessGate(prober)
	if err != nil {
		t.Fatal(err)
	}
	ready, observed, err := gate.Check(context.Background(), candidate)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !ready.Valid() || !observed.Ready() || ready.Descriptor() != candidate.Descriptor() || ready.Readiness() != result {
		t.Fatalf("ready candidate = %#v, observed = %#v", ready, observed)
	}
	copyBytes := ready.Bytes()
	copyBytes[0] = 'x'
	if ready.Bytes()[0] != candidate.Bytes()[0] {
		t.Fatal("ready candidate bytes are not defensive copies")
	}
	if (NodeRoutingReadyCandidate{}).Valid() {
		t.Fatal("zero ready candidate passed validation")
	}

	for name, fail := range map[string]func(*NodeRoutingReadinessResult){
		"service": func(value *NodeRoutingReadinessResult) {
			value.Service = NodeRoutingProbeResult{State: NodeRoutingProbeFailed, Code: "node-routing-service-unavailable"}
		},
		"tun": func(value *NodeRoutingReadinessResult) {
			value.TUN = NodeRoutingProbeResult{State: NodeRoutingProbeFailed, Code: "node-routing-tun-unavailable"}
		},
		"dns udp": func(value *NodeRoutingReadinessResult) {
			value.DNSUDP = NodeRoutingProbeResult{State: NodeRoutingProbeFailed, Code: "node-routing-dns-udp-unavailable"}
		},
		"dns tcp": func(value *NodeRoutingReadinessResult) {
			value.DNSTCP = NodeRoutingProbeResult{State: NodeRoutingProbeFailed, Code: "node-routing-dns-tcp-unavailable"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			failed := result
			fail(&failed)
			failedGate, _ := NewNodeRoutingReadinessGate(&staticNodeRoutingReadinessProber{result: failed})
			ready, observed, err := failedGate.Check(context.Background(), candidate)
			if err == nil || !errors.Is(err, ErrNodeRoutingNotReady) || ready.Valid() || observed.Ready() {
				t.Fatalf("failed readiness = ready:%#v observed:%#v err:%v", ready, observed, err)
			}
		})
	}
}

func TestNodeRoutingReadinessGateRejectsStaleEvidenceAndInvalidCandidate(t *testing.T) {
	t.Parallel()
	candidate := nodeRoutingReadinessCandidate(t)
	stale := passedNodeRoutingReadiness(candidate.Descriptor())
	stale.Candidate.ConfigHash = strings.Repeat("a", 64)
	gate, _ := NewNodeRoutingReadinessGate(&staticNodeRoutingReadinessProber{result: stale})
	if _, _, err := gate.Check(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "another candidate") {
		t.Fatalf("stale readiness evidence error = %v", err)
	}

	mutated := candidate
	mutated.content = []byte(strings.Replace(string(candidate.Bytes()), "auto-route: false", "auto-route: true", 1))
	prober := &staticNodeRoutingReadinessProber{result: passedNodeRoutingReadiness(mutated.Descriptor())}
	gate, _ = NewNodeRoutingReadinessGate(prober)
	if _, _, err := gate.Check(context.Background(), mutated); err == nil || !strings.Contains(err.Error(), "host-wide") {
		t.Fatalf("invalid candidate readiness error = %v", err)
	}
	if prober.calls != 0 {
		t.Fatal("invalid node routing candidate reached readiness probe")
	}
}

func TestNodeRoutingSystemReadinessProberBindsInstalledArtifactAndPassivelyObservesRuntime(t *testing.T) {
	t.Parallel()
	paths, _, _ := nodeRoutingServicePaths(t)
	candidate := nodeRoutingReadinessCandidate(t)
	runner := &nodeRoutingReadinessRunner{results: map[string]linuxplatform.ProbeResult{
		"systemctl is-active --quiet vpnctl-routing.service": {},
		"ip -o link show dev vpnctl0":                        {Stdout: []byte("7: vpnctl0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1400 state UNKNOWN mode DEFAULT\n")},
		"ss -H -lunp sport = :1053":                          {Stdout: []byte(`UNCONN 0 0 127.0.0.1:1053 0.0.0.0:* users:(("mihomo",pid=41,fd=8))` + "\n")},
		"ss -H -ltnp sport = :1053":                          {Stdout: []byte(`LISTEN 0 4096 127.0.0.1:1053 0.0.0.0:* users:(("mihomo",pid=41,fd=9))` + "\n")},
	}}
	prober, err := NewNodeRoutingSystemReadinessProber(paths, runner)
	if err != nil {
		t.Fatal(err)
	}
	result, err := prober.Probe(context.Background(), candidate)
	if err != nil || !result.Ready() {
		t.Fatalf("Probe() = %#v, %v", result, err)
	}
	wantCalls := []string{
		"systemctl is-active --quiet vpnctl-routing.service",
		"ip -o link show dev vpnctl0",
		"ss -H -lunp sport = :1053",
		"ss -H -ltnp sport = :1053",
	}
	if fmt.Sprint(runner.calls) != fmt.Sprint(wantCalls) {
		t.Fatalf("passive readiness calls = %v, want %v", runner.calls, wantCalls)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "start") || strings.Contains(call, "restart") || strings.Contains(call, "curl") || strings.Contains(call, "dig") {
			t.Fatalf("readiness mutated or generated traffic: %s", call)
		}
	}
}

func TestNodeRoutingSystemReadinessProberRejectsConfigDriftAndUnsafeRuntimeShape(t *testing.T) {
	t.Parallel()
	paths, configPath, _ := nodeRoutingServicePaths(t)
	candidate := nodeRoutingReadinessCandidate(t)
	if err := os.WriteFile(configPath, append(candidate.Bytes(), []byte("# drift\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &nodeRoutingReadinessRunner{results: map[string]linuxplatform.ProbeResult{}}
	prober, err := NewNodeRoutingSystemReadinessProber(paths, runner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prober.Probe(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("config drift error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatal("config drift reached runtime observation")
	}

	if err := os.WriteFile(configPath, candidate.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.results = map[string]linuxplatform.ProbeResult{
		"systemctl is-active --quiet vpnctl-routing.service": {},
		"ip -o link show dev vpnctl0":                        {Stdout: []byte("7: vpnctl0: <POINTOPOINT,UP> mtu 1400\n")},
		"ss -H -lunp sport = :1053":                          {Stdout: []byte(`UNCONN 0 0 0.0.0.0:1053 0.0.0.0:* users:(("mihomo",pid=41,fd=8))` + "\n")},
		"ss -H -ltnp sport = :1053":                          {Stdout: []byte(`LISTEN 0 4096 127.0.0.1:1053 0.0.0.0:* users:(("mihomo",pid=41,fd=9))` + "\n")},
	}
	result, err := prober.Probe(context.Background(), candidate)
	if err != nil || result.DNSUDP.State != NodeRoutingProbeFailed || result.DNSTCP.State != NodeRoutingProbePassed || result.Ready() {
		t.Fatalf("unsafe listener observation = %#v, %v", result, err)
	}
}

func nodeRoutingReadinessCandidate(t *testing.T) NodeRoutingCandidate {
	t.Helper()
	candidate, err := RenderNodeRoutingConfig(nodeRoutingRenderFixture(t, NodeRoutingDNSPolicy))
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func passedNodeRoutingReadiness(descriptor NodeRoutingDescriptor) NodeRoutingReadinessResult {
	return NodeRoutingReadinessResult{
		Candidate: descriptor,
		Service:   NodeRoutingProbeResult{State: NodeRoutingProbePassed, Code: "node-routing-service-ready"},
		TUN:       NodeRoutingProbeResult{State: NodeRoutingProbePassed, Code: "node-routing-tun-ready"},
		DNSUDP:    NodeRoutingProbeResult{State: NodeRoutingProbePassed, Code: "node-routing-dns-udp-ready"},
		DNSTCP:    NodeRoutingProbeResult{State: NodeRoutingProbePassed, Code: "node-routing-dns-tcp-ready"},
	}
}

type staticNodeRoutingReadinessProber struct {
	result NodeRoutingReadinessResult
	err    error
	calls  int
}

func (prober *staticNodeRoutingReadinessProber) Probe(context.Context, NodeRoutingCandidate) (NodeRoutingReadinessResult, error) {
	prober.calls++
	return prober.result, prober.err
}

type nodeRoutingReadinessRunner struct {
	results map[string]linuxplatform.ProbeResult
	calls   []string
}

func (runner *nodeRoutingReadinessRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	runner.calls = append(runner.calls, key)
	result, found := runner.results[key]
	if !found {
		return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected readiness command %s", key)
	}
	return result, nil
}
