package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestNodeJoinMutationUsesOnlyHiddenTokenAfterConfirmation(t *testing.T) {
	joiner := &recordingNodeJoiner{}
	workflow, err := NewNodeJoinMutationWorkflow(joiner, model.TransportRestricted, []string{"telegram"})
	if err != nil {
		t.Fatal(err)
	}
	inputs := &InteractionInputs{values: map[string][]byte{StepInviteToken: []byte("secret-token-canary")}}
	defer inputs.Destroy()
	plan, err := workflow.Plan(context.Background(), inputs)
	if err != nil || plan.Impact != ImpactAvailability || joiner.calls != 0 || joiner.planCalls != 1 {
		t.Fatalf("Plan() = %+v, %v; calls=%d plans=%d", plan, err, joiner.calls, joiner.planCalls)
	}
	applied, err := workflow.Apply(context.Background(), plan, inputs)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if joiner.calls != 1 || joiner.token != "secret-token-canary" || joiner.transport != model.TransportRestricted ||
		len(joiner.presets) != 1 || joiner.presets[0] != "telegram" {
		t.Fatalf("joiner = %+v", joiner)
	}
	if applied.Result.ResourceIDs["node_id"] == "" || applied.Result.Data["generation"] != uint64(2) {
		t.Fatalf("applied result = %+v", applied.Result)
	}
	if len(inputs.Copy(StepInviteToken)) != 0 {
		t.Fatal("Apply() left the invite token in interaction inputs")
	}
}

func TestNodeJoinMutationRejectsInvalidIntentAndMissingHiddenToken(t *testing.T) {
	joiner := &recordingNodeJoiner{}
	if _, err := NewNodeJoinMutationWorkflow(joiner, model.TransportKind("auto"), []string{}); err == nil {
		t.Fatal("constructor accepted automatic transport")
	}
	if _, err := NewNodeJoinMutationWorkflow(joiner, model.TransportStandard, nil); err == nil {
		t.Fatal("constructor accepted an omitted preset array")
	}
	workflow, err := NewNodeJoinMutationWorkflow(joiner, model.TransportStandard, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := workflow.Plan(context.Background(), &InteractionInputs{values: map[string][]byte{}}); err == nil {
		t.Fatal("Plan() accepted a missing hidden invite token")
	}
	if joiner.calls != 0 {
		t.Fatal("invalid planning invoked join")
	}
}

func TestNodeJoinMutationRejectsAlreadyJoinedNodeDuringReadOnlyPlan(t *testing.T) {
	joiner := &recordingNodeJoiner{planErr: enrollment.ErrNodeAlreadyJoined}
	workflow, err := NewNodeJoinMutationWorkflow(joiner, model.TransportStandard, []string{})
	if err != nil {
		t.Fatal(err)
	}
	inputs := &InteractionInputs{values: map[string][]byte{StepInviteToken: []byte("secret-token-canary")}}
	defer inputs.Destroy()
	if _, err := workflow.Plan(context.Background(), inputs); !errors.Is(err, enrollment.ErrNodeAlreadyJoined) {
		t.Fatalf("Plan() error = %v", err)
	}
	if joiner.planCalls != 1 || joiner.calls != 0 || string(inputs.Copy(StepInviteToken)) != "secret-token-canary" {
		t.Fatalf("rejected plan changed inputs or applied join: plans=%d calls=%d token=%q",
			joiner.planCalls, joiner.calls, inputs.Copy(StepInviteToken))
	}
}

func TestSystemNodeJoinerActivatesOnlyCommittedLocalGeneration(t *testing.T) {
	core := &recordingNodeJoiner{}
	activation := &recordingCommittedNodeActivation{}
	joiner, err := newSystemNodeJoiner(core, activation)
	if err != nil {
		t.Fatal(err)
	}
	token, err := output.NewSecret([]byte("secret-token-canary"))
	if err != nil {
		t.Fatal(err)
	}
	defer token.Destroy()
	result, err := joiner.Join(context.Background(), &token, model.TransportRestricted, []string{"telegram"})
	if err != nil || result.LocalStateGeneration != 2 || activation.calls != 1 || activation.generation != 2 {
		t.Fatalf("Join() = %+v, %v; activation=%+v", result, err, activation)
	}

	activation.err = errors.New("systemd unavailable")
	result, err = joiner.Join(context.Background(), &token, model.TransportRestricted, []string{"telegram"})
	if !errors.Is(err, enrollment.ErrNodeActivationPending) || result.LocalStateGeneration != 2 || activation.calls != 2 {
		t.Fatalf("pending Join() = %+v, %v; activation=%+v", result, err, activation)
	}
	category, code, message := classifyJoinError(err)
	if category != output.CategoryUnavailable || code != "join_activation_pending" || !strings.Contains(message, "join is committed") {
		t.Fatalf("pending classification = %s %s %q", category, code, message)
	}
}

type recordingNodeJoiner struct {
	planCalls int
	planErr   error
	calls     int
	token     string
	transport model.TransportKind
	presets   []string
}

type recordingCommittedNodeActivation struct {
	calls      int
	generation uint64
	err        error
}

func (activation *recordingCommittedNodeActivation) Activate(_ context.Context, generation uint64) error {
	activation.calls++
	activation.generation = generation
	return activation.err
}

func (joiner *recordingNodeJoiner) PlanJoin(transportKind model.TransportKind, presets []string) (enrollment.NodeJoinPlan, error) {
	joiner.planCalls++
	if joiner.planErr != nil {
		return enrollment.NodeJoinPlan{}, joiner.planErr
	}
	return enrollment.NodeJoinPlan{Transport: transportKind, Presets: append([]string{}, presets...), CurrentStateGeneration: 1}, nil
}

func (joiner *recordingNodeJoiner) Join(_ context.Context, token *output.Secret, transportKind model.TransportKind, presets []string) (enrollment.NodeJoinResult, error) {
	joiner.calls++
	if token == nil {
		return enrollment.NodeJoinResult{}, errors.New("missing token")
	}
	if err := token.Use(func(value []byte) error {
		joiner.token = string(value)
		return nil
	}); err != nil {
		return enrollment.NodeJoinResult{}, err
	}
	joiner.transport = transportKind
	joiner.presets = append([]string{}, presets...)
	return enrollment.NodeJoinResult{
		NodeID: "20000000-0000-4000-8000-000000000004", LocalStateGeneration: 2,
	}, nil
}
