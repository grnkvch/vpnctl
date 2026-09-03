package transport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestRestrictedReadinessGateProducesReadyCandidateOnlyAfterTCPAndUoT(t *testing.T) {
	t.Parallel()
	candidate := restrictedReadinessCandidate(t)
	result := passedRestrictedReadiness(candidate.Descriptor())
	prober := &staticRestrictedReadinessProber{result: result}
	gate, err := NewRestrictedReadinessGate(prober)
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
	if prober.calls != 1 {
		t.Fatalf("readiness probe calls = %d, want 1", prober.calls)
	}
	copyBytes := ready.Bytes()
	copyBytes[0] = 'x'
	if ready.Bytes()[0] != candidate.Bytes()[0] {
		t.Fatal("ready candidate bytes are not defensive copies")
	}
	if (RestrictedReadyCandidate{}).Valid() {
		t.Fatal("zero ready candidate passed validation")
	}
}

func TestRestrictedReadinessGateBlocksActivationWhenUoTFails(t *testing.T) {
	t.Parallel()
	candidate := restrictedReadinessCandidate(t)
	result := passedRestrictedReadiness(candidate.Descriptor())
	result.SelectedUDP = ProbeResult{State: ProbeFailed, Code: "restricted-uot-unavailable"}
	gate, _ := NewRestrictedReadinessGate(&staticRestrictedReadinessProber{result: result})
	ready, observed, err := gate.Check(context.Background(), candidate)
	if err == nil || !errors.Is(err, ErrRestrictedNotReady) || !strings.Contains(err.Error(), "restricted-uot-unavailable") {
		t.Fatalf("broken UoT error = %v", err)
	}
	if ready.Valid() || observed.Ready() || observed.SelectedTCP.State != ProbePassed || observed.SelectedUDP.State != ProbeFailed {
		t.Fatalf("broken UoT produced activatable result: ready=%#v observed=%#v", ready, observed)
	}
}

func TestRestrictedReadinessGateRejectsStaleEvidenceAndInvalidCandidate(t *testing.T) {
	t.Parallel()
	candidate := restrictedReadinessCandidate(t)
	stale := passedRestrictedReadiness(candidate.Descriptor())
	stale.Candidate.ConfigHash = strings.Repeat("a", 64)
	gate, _ := NewRestrictedReadinessGate(&staticRestrictedReadinessProber{result: stale})
	if _, _, err := gate.Check(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "another candidate") {
		t.Fatalf("stale readiness evidence error = %v", err)
	}

	mutated := candidate
	mutated.content = []byte(strings.Replace(string(candidate.Bytes()), "udp-over-tcp: true", "udp-over-tcp: false", 1))
	prober := &staticRestrictedReadinessProber{result: passedRestrictedReadiness(mutated.Descriptor())}
	gate, _ = NewRestrictedReadinessGate(prober)
	if _, _, err := gate.Check(context.Background(), mutated); err == nil || !strings.Contains(err.Error(), "pinned UoT") {
		t.Fatalf("invalid candidate readiness error = %v", err)
	}
	if prober.calls != 0 {
		t.Fatal("invalid restricted candidate reached readiness network probe")
	}
}

func TestRestrictedReadinessConfigIsLoopbackOnlyAndNotProductionArtifact(t *testing.T) {
	t.Parallel()
	candidate := restrictedReadinessCandidate(t)
	content, err := RenderRestrictedReadinessConfig(candidate, 17890)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, required := range []string{
		"socks-port: 17890", "allow-lan: false", "bind-address: 127.0.0.1",
		"udp-over-tcp: true", "udp-over-tcp-version: 2", "REJECT-DROP",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("restricted readiness config lacks %q:\n%s", required, text)
		}
	}
	if err := ValidateNodeRestrictedConfig(content); err == nil || !strings.Contains(err.Error(), "field socks-port not found") {
		t.Fatalf("transient readiness config accepted as production artifact: %v", err)
	}
	if strings.Contains(string(candidate.Bytes()), "socks-port") {
		t.Fatal("readiness rendering mutated production candidate")
	}
	for _, port := range []int{0, 443, 8443, 65536} {
		if _, err := RenderRestrictedReadinessConfig(candidate, port); err == nil {
			t.Errorf("readiness config accepted port %d", port)
		}
	}
}

func TestRestrictedNetworkReadinessProberRejectsUnsafeEndpointsAndBounds(t *testing.T) {
	t.Parallel()
	challenge := []byte("vpnctl-readiness")
	for name, fixture := range map[string]struct {
		proxy   string
		target  string
		timeout time.Duration
	}{
		"public proxy":      {proxy: "203.0.113.1:17890", target: "127.0.0.1:18080", timeout: time.Second},
		"public target":     {proxy: "127.0.0.1:17890", target: "203.0.113.1:18080", timeout: time.Second},
		"same endpoint":     {proxy: "127.0.0.1:17890", target: "127.0.0.1:17890", timeout: time.Second},
		"unbounded timeout": {proxy: "127.0.0.1:17890", target: "127.0.0.1:18080", timeout: time.Minute},
		"too-short timeout": {proxy: "127.0.0.1:17890", target: "127.0.0.1:18080", timeout: time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewRestrictedNetworkReadinessProber(fixture.proxy, fixture.target, challenge, challenge, fixture.timeout); err == nil {
				t.Fatal("unsafe restricted readiness probe input was accepted")
			}
		})
	}
	if _, err := NewRestrictedNetworkReadinessProber("127.0.0.1:17890", "127.0.0.1:18080", nil, challenge, time.Second); err == nil {
		t.Fatal("empty TCP challenge was accepted")
	}
	if _, err := NewRestrictedNetworkReadinessProber("127.0.0.1:17890", "127.0.0.1:18080", challenge, challenge, 0); err != nil {
		t.Fatalf("default restricted readiness timeout rejected: %v", err)
	}
}

func TestRestrictedRetryProbeUsesSameBoundedPath(t *testing.T) {
	t.Parallel()
	calls := 0
	err := restrictedRetryProbe(context.Background(), time.Second, func(context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("cold connection")
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Fatalf("restricted retry = %v after %d calls", err, calls)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	err = restrictedRetryProbe(cancelled, time.Second, func(context.Context) error {
		calls++
		return errors.New("must remain unavailable")
	})
	if err == nil || calls > 1 {
		t.Fatalf("cancelled restricted retry = %v after %d calls", err, calls)
	}
}

func restrictedReadinessCandidate(t *testing.T) RestrictedNodeCandidate {
	t.Helper()
	node := restrictedNodeFixture()
	candidate, err := RenderNodeRestrictedConfig(NodeRestrictedRenderRequest{
		Transport: restrictedTransportFixture(model.TargetNode, node.ID, model.TransportStandby, 4, "www.microsoft.com"),
		Node:      node, GatewayPublicIPv4: "203.0.113.10", ServerPassword: restrictedServerPassword(0x61),
		IdentitySecret: restrictedIdentitySecretBytes(t, 0x62), Component: restrictedComponentPin(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func passedRestrictedReadiness(descriptor CandidateDescriptor) RestrictedReadinessResult {
	return RestrictedReadinessResult{
		Candidate:   descriptor,
		SelectedTCP: ProbeResult{State: ProbePassed, Code: "restricted-selected-tcp-ready"},
		SelectedUDP: ProbeResult{State: ProbePassed, Code: "restricted-uot-ready"},
	}
}

type staticRestrictedReadinessProber struct {
	result RestrictedReadinessResult
	err    error
	calls  int
}

func (prober *staticRestrictedReadinessProber) Probe(context.Context, RestrictedNodeCandidate) (RestrictedReadinessResult, error) {
	prober.calls++
	return prober.result, prober.err
}
