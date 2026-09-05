package tunnel

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFRPClientStatusRecoveryProberDistinguishesTransportFromUpstreamFailure(t *testing.T) {
	t.Parallel()

	const password = "abababababababababababababababababababababababababababababababab"
	mapping := FRPClientRecoveryMapping{
		Name: "node-a-expose-a", LocalAddr: "127.0.0.1:3000", RemoteAddr: "10.67.0.1:20000",
	}
	status := &recoveryStatusSource{}
	prober, err := NewFRPClientStatusRecoveryProber(status, password, []FRPClientRecoveryMapping{mapping})
	if err != nil {
		t.Fatal(err)
	}
	base := FRPProxyStatus{
		Name: mapping.Name, Type: "tcp", LocalAddr: mapping.LocalAddr, RemoteAddr: mapping.RemoteAddr,
	}
	for _, test := range []struct {
		name  string
		phase string
		err   string
		want  FRPClientRecoveryState
	}{
		{name: "running", phase: "running", want: FRPClientRecoveryConnected},
		{name: "local upstream down", phase: "check failed", err: "synthetic", want: FRPClientRecoveryConnected},
		{name: "mapping starting", phase: "wait start", want: FRPClientRecoveryIndeterminate},
		{name: "transport retry", phase: "start error", err: "synthetic", want: FRPClientRecoveryUnavailable},
		{name: "transport closed", phase: "closed", want: FRPClientRecoveryUnavailable},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Status = test.phase
			candidate.Err = test.err
			status.set([]FRPProxyStatus{candidate}, nil)
			if got := prober.RecoveryState(context.Background()); got != test.want {
				t.Fatalf("RecoveryState() = %v, want %v", got, test.want)
			}
		})
	}
	status.set(nil, errors.New("synthetic-secret-canary"))
	if got := prober.RecoveryState(context.Background()); got != FRPClientRecoveryUnavailable {
		t.Fatalf("unavailable status endpoint state = %v", got)
	}
	mismatched := base
	mismatched.Status = "running"
	mismatched.RemoteAddr = "10.67.0.1:20001"
	status.set([]FRPProxyStatus{mismatched}, nil)
	if got := prober.RecoveryState(context.Background()); got != FRPClientRecoveryUnavailable {
		t.Fatalf("mismatched status state = %v", got)
	}
}

func TestFRPClientStatusRecoveryProberRejectsUnsafeTargets(t *testing.T) {
	t.Parallel()

	valid := FRPClientRecoveryMapping{Name: "mapping", LocalAddr: "127.0.0.1:3000", RemoteAddr: "10.67.0.1:20000"}
	for _, test := range []struct {
		name     string
		password string
		mappings []FRPClientRecoveryMapping
	}{
		{name: "short password", password: "ab", mappings: []FRPClientRecoveryMapping{valid}},
		{name: "no mappings", password: recoveryTestPassword, mappings: []FRPClientRecoveryMapping{}},
		{name: "public server", password: recoveryTestPassword, mappings: []FRPClientRecoveryMapping{{Name: "mapping", LocalAddr: "127.0.0.1:3000", RemoteAddr: "203.0.113.1:20000"}}},
		{name: "non-loopback upstream", password: recoveryTestPassword, mappings: []FRPClientRecoveryMapping{{Name: "mapping", LocalAddr: "10.67.0.2:3000", RemoteAddr: "10.67.0.1:20000"}}},
		{name: "duplicate", password: recoveryTestPassword, mappings: []FRPClientRecoveryMapping{valid, valid}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewFRPClientStatusRecoveryProber(&recoveryStatusSource{}, test.password, test.mappings); err == nil {
				t.Fatal("unsafe recovery target was accepted")
			}
		})
	}
}

func TestFRPClientRecoveryGuardRecyclesOnlyOnceUntilConnectionReturns(t *testing.T) {
	process := &blockingRecoveryProcess{started: make(chan int, 8)}
	prober := &atomicRecoveryProber{observed: make(chan FRPClientRecoveryState, 64)}
	prober.state.Store(uint32(FRPClientRecoveryConnected))
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	timing := frpClientRecoveryTiming{guardDelay: 20 * time.Millisecond, pollInterval: 2 * time.Millisecond, stopTimeout: 100 * time.Millisecond}
	go func() {
		result <- runFRPClientProcessWithRecovery(ctx, process, "/frpc", []string{"-c", "/frpc.toml"}, prober, timing)
	}()

	waitRecoveryProcessStart(t, process.started, 1)
	waitRecoveryState(t, prober.observed, FRPClientRecoveryConnected)
	prober.state.Store(uint32(FRPClientRecoveryUnavailable))
	waitRecoveryProcessStart(t, process.started, 2)

	prober.state.Store(uint32(FRPClientRecoveryIndeterminate))
	select {
	case call := <-process.started:
		t.Fatalf("recovery guard recycled repeatedly without confirmed connection: call %d", call)
	case <-time.After(50 * time.Millisecond):
	}

	prober.state.Store(uint32(FRPClientRecoveryConnected))
	waitRecoveryState(t, prober.observed, FRPClientRecoveryConnected)
	prober.state.Store(uint32(FRPClientRecoveryUnavailable))
	waitRecoveryProcessStart(t, process.started, 3)
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("recovery supervisor cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("recovery supervisor did not stop")
	}
	if process.maximumActive() != 1 {
		t.Fatalf("maximum active frpc children = %d, want 1", process.maximumActive())
	}
}

func TestFRPClientRecoveryGuardLeavesInitialProviderRetryInPlace(t *testing.T) {
	process := &blockingRecoveryProcess{started: make(chan int, 4)}
	prober := &atomicRecoveryProber{observed: make(chan FRPClientRecoveryState, 32)}
	prober.state.Store(uint32(FRPClientRecoveryUnavailable))
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- runFRPClientProcessWithRecovery(ctx, process, "/frpc", nil, prober, frpClientRecoveryTiming{
			guardDelay: 20 * time.Millisecond, pollInterval: 2 * time.Millisecond, stopTimeout: 100 * time.Millisecond,
		})
	}()
	waitRecoveryProcessStart(t, process.started, 1)
	waitRecoveryState(t, prober.observed, FRPClientRecoveryUnavailable)
	select {
	case call := <-process.started:
		t.Fatalf("never-connected frpc was recycled: call %d", call)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("recovery supervisor cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("recovery supervisor did not stop")
	}
}

const recoveryTestPassword = "abababababababababababababababababababababababababababababababab"

type recoveryStatusSource struct {
	mu       sync.Mutex
	statuses []FRPProxyStatus
	err      error
}

func (source *recoveryStatusSource) set(statuses []FRPProxyStatus, err error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.statuses = append([]FRPProxyStatus(nil), statuses...)
	source.err = err
}

func (source *recoveryStatusSource) Status(context.Context, string) ([]FRPProxyStatus, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	return append([]FRPProxyStatus(nil), source.statuses...), source.err
}

type atomicRecoveryProber struct {
	state    atomic.Uint32
	observed chan FRPClientRecoveryState
}

func (prober *atomicRecoveryProber) RecoveryState(context.Context) FRPClientRecoveryState {
	state := FRPClientRecoveryState(prober.state.Load())
	select {
	case prober.observed <- state:
	default:
	}
	return state
}

type blockingRecoveryProcess struct {
	mu        sync.Mutex
	calls     int
	active    int
	maxActive int
	started   chan int
}

func (process *blockingRecoveryProcess) Run(ctx context.Context, _ string, _ []string) error {
	process.mu.Lock()
	process.calls++
	call := process.calls
	process.active++
	if process.active > process.maxActive {
		process.maxActive = process.active
	}
	process.mu.Unlock()
	process.started <- call
	<-ctx.Done()
	process.mu.Lock()
	process.active--
	process.mu.Unlock()
	return ctx.Err()
}

func (process *blockingRecoveryProcess) maximumActive() int {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.maxActive
}

func waitRecoveryProcessStart(t *testing.T, starts <-chan int, want int) {
	t.Helper()
	select {
	case got := <-starts:
		if got != want {
			t.Fatalf("frpc start = %d, want %d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("frpc start %d was not observed", want)
	}
}

func waitRecoveryState(t *testing.T, observed <-chan FRPClientRecoveryState, want FRPClientRecoveryState) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case got := <-observed:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("recovery state %v was not observed", want)
		}
	}
}

var _ FRPClientStatusSource = (*recoveryStatusSource)(nil)
var _ FRPClientRecoveryProber = (*atomicRecoveryProber)(nil)
var _ FRPProcessRunner = (*blockingRecoveryProcess)(nil)
