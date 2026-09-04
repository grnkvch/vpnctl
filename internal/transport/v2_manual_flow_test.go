package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

// TestV2ManualTransportRoundTrip is the source-level stateful acceptance for
// task 16.3. It deliberately reuses one authoritative node state and one pair
// of provider runtimes across both test/switch directions so a stale role,
// extra activation, or hidden fallback cannot be concealed by a fresh fixture.
func TestV2ManualTransportRoundTrip(t *testing.T) {
	t.Parallel()

	trace := []string{}
	stateStore := &switchStateStore{state: nodeTransportTestState(t), trace: &trace}
	standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
	restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
	registry, err := NewRegistry(standard, restricted)
	if err != nil {
		t.Fatal(err)
	}
	tester, err := NewNodeTester(stateStore, registry, TestLimits{
		Total: time.Second, Step: 500 * time.Millisecond, Cleanup: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	switcher, err := NewNodeSwitcher(stateStore, registry, SwitchLimits{
		Total: time.Second, Step: 500 * time.Millisecond, Drain: 250 * time.Millisecond, Rollback: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	before := stateStore.state
	restrictedTest, err := tester.Test(context.Background(), model.TransportRestricted)
	if err != nil || !restrictedTest.Ready() {
		t.Fatalf("test restricted from standard = %+v, %v", restrictedTest, err)
	}
	if stateStore.state.Generation != before.Generation || stateStore.state.Nodes[0].ActiveTransport != model.TransportStandard ||
		standard.role != RuntimeActive || restricted.role != RuntimeStandby {
		t.Fatalf("restricted test changed production state/roles: state=%d/%s roles=%s/%s",
			stateStore.state.Generation, stateStore.state.Nodes[0].ActiveTransport, standard.role, restricted.role)
	}

	toRestricted, err := switcher.Plan(model.TransportRestricted)
	if err != nil {
		t.Fatal(err)
	}
	restrictedResult, err := switcher.Apply(context.Background(), toRestricted)
	if err != nil || !restrictedResult.Changed || restrictedResult.Active != model.TransportRestricted {
		t.Fatalf("switch to restricted = %+v, %v", restrictedResult, err)
	}
	assertSwitchState(t, stateStore.state, model.TransportRestricted, before.Generation+1)
	if standard.role != RuntimeStandby || restricted.role != RuntimeActive {
		t.Fatalf("restricted steady-state roles = %s/%s", standard.role, restricted.role)
	}

	standardTest, err := tester.Test(context.Background(), model.TransportStandard)
	if err != nil || !standardTest.Ready() {
		t.Fatalf("test standard from restricted = %+v, %v", standardTest, err)
	}
	if stateStore.state.Nodes[0].ActiveTransport != model.TransportRestricted ||
		standard.role != RuntimeStandby || restricted.role != RuntimeActive {
		t.Fatalf("standard test changed restricted production state/roles: state=%s roles=%s/%s",
			stateStore.state.Nodes[0].ActiveTransport, standard.role, restricted.role)
	}

	toStandard, err := switcher.Plan(model.TransportStandard)
	if err != nil {
		t.Fatal(err)
	}
	standardResult, err := switcher.Apply(context.Background(), toStandard)
	if err != nil || !standardResult.Changed || standardResult.Active != model.TransportStandard {
		t.Fatalf("switch to standard = %+v, %v", standardResult, err)
	}
	assertSwitchState(t, stateStore.state, model.TransportStandard, before.Generation+2)
	if standard.role != RuntimeActive || restricted.role != RuntimeStandby {
		t.Fatalf("standard steady-state roles = %s/%s", standard.role, restricted.role)
	}

	// A failed explicit target is a negative result, never an authorization to
	// change the active role or advance authoritative state.
	restricted.result.SelectedUDP = ProbeResult{State: ProbeFailed, Code: "uot-unavailable"}
	failedPlan, err := switcher.Plan(model.TransportRestricted)
	if err != nil {
		t.Fatal(err)
	}
	failedGeneration := stateStore.state.Generation
	if _, err := switcher.Apply(context.Background(), failedPlan); !errors.Is(err, ErrTransportSwitchTargetNotReady) {
		t.Fatalf("failed restricted switch error = %v", err)
	}
	assertSwitchState(t, stateStore.state, model.TransportStandard, failedGeneration)
	if standard.role != RuntimeActive || restricted.role != RuntimeStandby {
		t.Fatalf("failed target changed steady state roles = %s/%s", standard.role, restricted.role)
	}

	// An active outage is observed only through the manually selected provider.
	// The standby provider call count must not move.
	standard.condition = HealthUnavailable
	selection, err := NewSelection(model.TransportStandard)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Identity{
		OwnerKind: model.TargetNode, OwnerID: stateStore.state.Nodes[0].ID,
		CredentialGeneration: stateStore.state.Nodes[0].CredentialGeneration,
	}, selection, registry)
	if err != nil {
		t.Fatal(err)
	}
	standbyCalls := len(restricted.calls)
	health, err := manager.ObserveActive(context.Background())
	if err != nil || health.Condition != HealthUnavailable || health.Role != RuntimeActive {
		t.Fatalf("active outage observation = %+v, %v", health, err)
	}
	if len(restricted.calls) != standbyCalls || manager.Selection().Active != model.TransportStandard {
		t.Fatalf("active outage touched standby or changed selection: calls=%d/%d selection=%+v",
			standbyCalls, len(restricted.calls), manager.Selection())
	}
}
