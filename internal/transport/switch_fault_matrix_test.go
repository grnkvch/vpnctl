package transport

import (
	"context"
	"errors"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestNodeTransportSwitchFaultMatrixPreservesOneManualProductionPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		providerStage string
		stateFailure  bool
	}{
		{name: "target prepare", providerStage: "prepare"},
		{name: "target validation", providerStage: "validate"},
		{name: "selected flow probes", providerStage: "test"},
		{name: "atomic activation", providerStage: "activate"},
		{name: "post-activation health", providerStage: "health"},
		{name: "old path drain", providerStage: "drain"},
		{name: "authoritative state commit", stateFailure: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := nodeTransportTestState(t)
			trace := []string{}
			store := &switchStateStore{state: state, trace: &trace}
			if test.stateFailure {
				store.saveErr = errors.New("injected state commit failure")
			}
			standard := newSwitchProvider(model.TransportStandard, RuntimeActive, &trace)
			restricted := newSwitchProvider(model.TransportRestricted, RuntimeStandby, &trace)
			switch test.providerStage {
			case "drain":
				standard.failStage = test.providerStage
			default:
				restricted.failStage = test.providerStage
			}
			registry, err := NewRegistry(standard, restricted)
			if err != nil {
				t.Fatal(err)
			}
			switcher, err := NewNodeSwitcher(store, registry, SwitchLimits{})
			if err != nil {
				t.Fatal(err)
			}
			plan, err := switcher.Plan(model.TransportRestricted)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := switcher.Apply(context.Background(), plan); err == nil {
				t.Fatal("fault-injected transport switch succeeded")
			}
			if standard.role != RuntimeActive || restricted.role != RuntimeStandby {
				t.Fatalf("fault changed manual production selection: standard=%s restricted=%s trace=%v", standard.role, restricted.role, trace)
			}
			assertSwitchState(t, store.state, model.TransportStandard, 9)
			if restricted.bundleActivations > 1 || standard.bundleActivations > 1 {
				t.Fatalf("fault caused repeated or automatic activation: standard=%d restricted=%d", standard.bundleActivations, restricted.bundleActivations)
			}
		})
	}
}
