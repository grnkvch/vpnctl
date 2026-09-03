package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestTransportSwitchWorkflowImmediateUsesConfirmedCommonMutationBoundary(t *testing.T) {
	t.Parallel()

	switcher := &recordingTransportSwitcher{plan: switchMutationPlan(), result: switchMutationResult()}
	workflow, err := NewTransportSwitchWorkflow(switcher, model.TransportRestricted)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "transport.switch", Role: RoleNode, Yes: true,
	}, nil, workflow, nil)
	if err != nil {
		t.Fatalf("RunMutation() error = %v", err)
	}
	if outcome.Mode != MutationImmediate || outcome.Result.Status != output.StatusOK || switcher.plans != 1 || switcher.applies != 1 {
		t.Fatalf("immediate outcome=%+v plans/applies=%d/%d", outcome, switcher.plans, switcher.applies)
	}
	if got := outcome.Result.Data["active"]; got != string(model.TransportRestricted) {
		t.Fatalf("active output = %#v", got)
	}
}

func TestTransportSwitchWorkflowDeferRegistersExactTargetWithoutLocalApply(t *testing.T) {
	t.Parallel()

	switcher := &recordingTransportSwitcher{plan: switchMutationPlan(), result: switchMutationResult()}
	workflow, _ := NewTransportSwitchWorkflow(switcher, model.TransportRestricted)
	authority := &transportSwitchAuthority{}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "transport.switch", Role: RoleNode, Defer: true, Yes: true,
	}, nil, workflow, authority)
	if err != nil {
		t.Fatalf("RunMutation(--defer) error = %v", err)
	}
	if outcome.Mode != MutationDeferred || outcome.Result.Status != output.StatusPending || outcome.OperationID == "" || outcome.AuthoritativeGeneration != 13 {
		t.Fatalf("deferred outcome = %+v", outcome)
	}
	if switcher.plans != 1 || switcher.applies != 0 || authority.calls != 1 || authority.target != string(model.TransportRestricted) || authority.current != string(model.TransportStandard) {
		t.Fatalf("deferred calls target/current = %d/%d/%d %q/%q", switcher.plans, switcher.applies, authority.calls, authority.target, authority.current)
	}
}

func TestTransportSwitchWorkflowDeferRequiresReachableGatewayAndConsent(t *testing.T) {
	t.Parallel()

	switcher := &recordingTransportSwitcher{plan: switchMutationPlan(), result: switchMutationResult()}
	workflow, _ := NewTransportSwitchWorkflow(switcher, model.TransportRestricted)
	_, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "transport.switch", Role: RoleNode, Defer: true, Yes: true,
	}, nil, workflow, nil)
	if !errors.Is(err, ErrGatewayUnavailable) || switcher.plans != 0 || switcher.applies != 0 {
		t.Fatalf("missing gateway error=%v plans/applies=%d/%d", err, switcher.plans, switcher.applies)
	}

	workflow, _ = NewTransportSwitchWorkflow(switcher, model.TransportRestricted)
	_, err = V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "transport.switch", Role: RoleNode, Defer: true,
	}, nil, workflow, &transportSwitchAuthority{})
	if !errors.Is(err, ErrInteractionRefused) || switcher.applies != 0 {
		t.Fatalf("unconfirmed defer error=%v applies=%d", err, switcher.applies)
	}
}

type recordingTransportSwitcher struct {
	plan    transport.SwitchPlan
	result  transport.SwitchResult
	plans   int
	applies int
}

func (switcher *recordingTransportSwitcher) Plan(target model.TransportKind) (transport.SwitchPlan, error) {
	switcher.plans++
	if target != switcher.plan.Target {
		return transport.SwitchPlan{}, errors.New("unexpected target")
	}
	return switcher.plan, nil
}

func (switcher *recordingTransportSwitcher) Apply(_ context.Context, plan transport.SwitchPlan) (transport.SwitchResult, error) {
	switcher.applies++
	if plan.Target != switcher.plan.Target {
		return transport.SwitchResult{}, errors.New("unexpected applied target")
	}
	return switcher.result, nil
}

type transportSwitchAuthority struct {
	calls   int
	target  string
	current string
}

func (authority *transportSwitchAuthority) RegisterPending(_ context.Context, plan MutationPlan) (DeferredReceipt, error) {
	authority.calls++
	authority.target, _ = plan.Result.Data["target"].(string)
	authority.current, _ = plan.Result.Data["current"].(string)
	return DeferredReceipt{
		CommandID: "transport.switch", OperationID: "30000000-0000-4000-8000-000000000001", AuthoritativeGeneration: 13,
		Result: output.NewResult("transport.switch", output.StatusPending, output.CategorySuccess, output.SafeObject{
			"changed": true, "current": authority.current, "target": authority.target, "generation": uint64(13),
		}),
	}, nil
}

func switchMutationPlan() transport.SwitchPlan {
	return transport.SwitchPlan{
		NodeID: "20000000-0000-4000-8000-000000000001", Current: model.TransportStandard, Target: model.TransportRestricted,
		ExpectedStateGeneration: 9, NextStateGeneration: 10, Changed: true,
	}
}

func switchMutationResult() transport.SwitchResult {
	return transport.SwitchResult{
		NodeID: "20000000-0000-4000-8000-000000000001", Previous: model.TransportStandard, Active: model.TransportRestricted,
		Changed: true, StateGeneration: 10, ActiveHealth: transport.Health{Condition: transport.HealthHealthy},
	}
}

var _ TransportSwitcher = (*recordingTransportSwitcher)(nil)
