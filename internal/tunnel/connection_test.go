package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestFRPClientConnectionProberRequiresOneExactPinnedProcessConnection(t *testing.T) {
	candidate := testFRPClientCandidate(t)
	endpoint, err := candidate.ServerEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	runner := &frpConnectionRunner{results: []linuxplatform.ProbeResult{
		{},
		{Stdout: []byte("0 0 10.67.0.2:45000 10.67.0.1:17000 users:((\"other\",pid=4,fd=3))\n")},
		{Stdout: []byte("0 0 10.67.0.2:45000 10.67.0.1:17000 users:((\"frpc\",pid=8,fd=3))\n")},
	}}
	prober, err := newFRPClientConnectionProber(runner, 100*time.Millisecond, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := prober.Probe(context.Background(), candidate); err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	want := linuxplatform.ProbeCommand{Name: "ss", Args: []string{"-H", "-tnp", "state", "established", "dst", endpoint.String()}}
	for _, command := range runner.commands {
		if !reflect.DeepEqual(command, want) {
			t.Fatalf("connection command = %+v, want %+v", command, want)
		}
	}
}

func TestFRPClientConnectionProberFailsClosedOnAmbiguityTimeoutAndRunnerFailure(t *testing.T) {
	candidate := testFRPClientCandidate(t)
	line := "0 0 10.67.0.2:45000 10.67.0.1:17000 users:((\"frpc\",pid=8,fd=3))\n"
	for _, test := range []struct {
		name   string
		runner *frpConnectionRunner
	}{
		{name: "ambiguous", runner: &frpConnectionRunner{repeat: linuxplatform.ProbeResult{Stdout: []byte(line + line)}}},
		{name: "wrong endpoint", runner: &frpConnectionRunner{repeat: linuxplatform.ProbeResult{Stdout: []byte("0 0 10.67.0.2:45000 10.67.0.9:17000 users:((\"frpc\",pid=8,fd=3))\n")}}},
		{name: "runner failure", runner: &frpConnectionRunner{err: errors.New("exec unavailable")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			prober, err := newFRPClientConnectionProber(test.runner, 8*time.Millisecond, time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			if err := prober.Probe(context.Background(), candidate); err == nil {
				t.Fatal("Probe() succeeded")
			}
		})
	}
}

func testFRPClientCandidate(t *testing.T) FRPCandidate {
	t.Helper()
	provider, err := NewFRPProvider("/", testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	value, err := provider.Render(context.Background(), RenderRequest{Plan: Plan{
		HostRole: "node", HostID: testNodeHostID, Generation: 2,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{{
			NodeID: "10000000-0000-4000-8000-000000000001", Generation: 2, CredentialGeneration: 1,
			ActiveTransport: "restricted", Mappings: []Mapping{},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return value.(FRPCandidate)
}

type frpConnectionRunner struct {
	results  []linuxplatform.ProbeResult
	repeat   linuxplatform.ProbeResult
	err      error
	commands []linuxplatform.ProbeCommand
}

func (runner *frpConnectionRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	runner.commands = append(runner.commands, command)
	if runner.err != nil {
		return linuxplatform.ProbeResult{}, runner.err
	}
	if len(runner.results) != 0 {
		result := runner.results[0]
		runner.results = runner.results[1:]
		return result, nil
	}
	return runner.repeat, nil
}
