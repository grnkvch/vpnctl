package cli

import (
	"errors"
	"reflect"
	"testing"
)

func TestEveryV2CommandResolvesItsFrozenConsentClass(t *testing.T) {
	t.Parallel()

	registry := V2CommandRegistry()
	for _, spec := range registry.Commands() {
		spec := spec
		t.Run(spec.ID, func(t *testing.T) {
			request := InteractionRequest{
				CommandID: spec.ID,
				Role:      spec.Roles[0],
				Impact:    ImpactNone,
				HasTTY:    true,
			}
			plan := mustPlanInteraction(t, registry, request)
			consent := stepsInPhase(plan, InteractionConsent)
			switch spec.Consent {
			case ConsentNone, ConsentConditional:
				assertPromptKinds(t, consent)
			case ConsentConfirm:
				assertPromptKinds(t, consent, PromptConfirm)
			case ConsentConfirmTypedIfIrreversible:
				assertPromptKinds(t, consent, PromptConfirm)
			case ConsentTyped:
				assertPromptKinds(t, consent, PromptTyped)
				if consent[0].Exact != "purge "+string(request.Role) {
					t.Fatalf("typed phrase = %q", consent[0].Exact)
				}
			default:
				t.Fatalf("unhandled consent class %q", spec.Consent)
			}

			if spec.Consent == ConsentConditional {
				request.Impact = ImpactDestructive
				destructive := mustPlanInteraction(t, registry, request)
				assertPromptKinds(t, stepsInPhase(destructive, InteractionConsent), PromptConfirm)
			}
			if spec.Consent == ConsentConfirmTypedIfIrreversible {
				request.IrreversibleMigration = true
				irreversible := mustPlanInteraction(t, registry, request)
				steps := stepsInPhase(irreversible, InteractionConsent)
				assertPromptKinds(t, steps, PromptConfirm, PromptTyped)
				if steps[1].Exact != "accept irreversible migration" {
					t.Fatalf("irreversible phrase = %q", steps[1].Exact)
				}
			}
		})
	}
}

func TestEveryV2CommandAppliesYesTTYDryRunAndJSONRules(t *testing.T) {
	t.Parallel()

	registry := V2CommandRegistry()
	for _, spec := range registry.Commands() {
		spec := spec
		t.Run(spec.ID, func(t *testing.T) {
			base := InteractionRequest{
				CommandID: spec.ID,
				Role:      spec.Roles[0],
				Impact:    ImpactDestructive,
				HasTTY:    false,
			}
			if spec.Consent == ConsentConfirmTypedIfIrreversible {
				base.IrreversibleMigration = true
			}

			withoutJSON := mustPlanInteraction(t, registry, base)
			withJSONRequest := base
			withJSONRequest.JSON = true
			withJSON := mustPlanInteraction(t, registry, withJSONRequest)
			if !reflect.DeepEqual(withoutJSON, withJSON) {
				t.Fatal("--json changed interaction or consent")
			}
			assertEveryStepUsesResolver(t, withoutJSON, base)

			yesRequest := base
			yesRequest.Yes = true
			yesPlan := mustPlanInteraction(t, registry, yesRequest)
			assertEveryStepUsesResolver(t, yesPlan, yesRequest)
			for _, step := range stepsInPhase(yesPlan, InteractionConsent) {
				if step.Prompt == PromptConfirm && step.Decision.Action != "proceed" {
					t.Errorf("--yes did not satisfy yes/no consent: %+v", step)
				}
				if step.Prompt == PromptTyped && step.Decision.Action != "refuse" {
					t.Errorf("--yes bypassed typed consent: %+v", step)
				}
			}

			dryRunRequest := base
			dryRunRequest.DryRun = true
			dryRunPlan := mustPlanInteraction(t, registry, dryRunRequest)
			assertEveryStepUsesResolver(t, dryRunPlan, dryRunRequest)
			for _, step := range stepsInPhase(dryRunPlan, InteractionConsent) {
				if step.Decision.Action != "proceed" {
					t.Errorf("dry-run retained consent step: %+v", step)
				}
			}
		})
	}
}

func TestSecretFlowMatrixMatchesFrozenStdinContract(t *testing.T) {
	t.Parallel()

	want := map[string]PromptKind{
		"invite":               PromptSecretOutputOnce,
		"join":                 PromptSecretOnce,
		"node.recover.gateway": PromptSecretOutputOnce,
		"node.recover.node":    PromptSecretOnce,
		"backup":               PromptSecretTwice,
		"restore":              PromptSecretOnce,
	}
	registry := V2CommandRegistry()
	for _, spec := range registry.Commands() {
		expected := PromptNone
		if kind, found := want[spec.ID]; found {
			expected = kind
			delete(want, spec.ID)
		}
		if spec.SecretFlow != expected {
			t.Errorf("%s secret flow = %q, want %q", spec.ID, spec.SecretFlow, expected)
		}
	}
	if len(want) != 0 {
		t.Fatalf("secret matrix references absent commands: %v", want)
	}
}

func TestIrreversibleAndBackupDeletionKeepSecondTypedBarrier(t *testing.T) {
	t.Parallel()

	registry := V2CommandRegistry()
	update := mustPlanInteraction(t, registry, InteractionRequest{
		CommandID:             "update",
		Role:                  RoleGateway,
		Impact:                ImpactAvailability,
		HasTTY:                false,
		Yes:                   true,
		JSON:                  true,
		IrreversibleMigration: true,
	})
	assertPromptKinds(t, stepsInPhase(update, InteractionConsent), PromptConfirm, PromptTyped)
	if update.Steps[0].Decision.Action != "proceed" || update.Steps[1].Decision.Action != "refuse" {
		t.Fatalf("irreversible --yes plan = %+v", update)
	}

	purge := mustPlanInteraction(t, registry, InteractionRequest{
		CommandID:      "purge",
		Role:           RoleGateway,
		Impact:         ImpactDestructive,
		HasTTY:         true,
		Yes:            true,
		IncludeBackups: true,
	})
	steps := stepsInPhase(purge, InteractionConsent)
	assertPromptKinds(t, steps, PromptTyped, PromptTyped)
	if steps[0].Exact != "purge gateway" || steps[1].Exact != "delete backups" {
		t.Fatalf("purge phrases = %q, %q", steps[0].Exact, steps[1].Exact)
	}
}

func TestNonInteractiveRefusalHappensBeforeAnyPrompt(t *testing.T) {
	t.Parallel()

	plan := mustPlanInteraction(t, V2CommandRegistry(), InteractionRequest{
		CommandID: "join",
		Role:      RoleNode,
		Impact:    ImpactAvailability,
		HasTTY:    false,
		Yes:       true,
		JSON:      true,
	})
	terminal := &fakePromptIO{}
	inputs, err := ReadInteractionInputs(plan, terminal)
	if !errors.Is(err, ErrInteractionRefused) || inputs != nil {
		t.Fatalf("ReadInteractionInputs() = inputs=%v error=%v", inputs, err)
	}
	if terminal.reads != 0 || terminal.writes != 0 {
		t.Fatalf("refused interaction touched terminal: reads=%d writes=%d", terminal.reads, terminal.writes)
	}
}

func TestPromptExecutionRequiresExactConsentAndHiddenSecrets(t *testing.T) {
	t.Parallel()

	t.Run("typed is exact and case sensitive", func(t *testing.T) {
		plan := mustPlanInteraction(t, V2CommandRegistry(), InteractionRequest{
			CommandID: "purge", Role: RoleNode, Impact: ImpactDestructive, HasTTY: true,
		})
		_, err := ReadInteractionInputs(plan, &fakePromptIO{visible: []string{"Purge node"}})
		if !errors.Is(err, ErrConsentDeclined) {
			t.Fatalf("typed mismatch error = %v", err)
		}
	})

	t.Run("yes-no vocabulary", func(t *testing.T) {
		plan := mustPlanInteraction(t, V2CommandRegistry(), InteractionRequest{
			CommandID: "repair", Role: RoleGateway, Impact: ImpactAvailability, HasTTY: true,
		})
		inputs, err := ReadInteractionInputs(plan, &fakePromptIO{visible: []string{" YES "}})
		if err != nil {
			t.Fatalf("ReadInteractionInputs() error = %v", err)
		}
		inputs.Destroy()
	})

	t.Run("one hidden secret retries empty", func(t *testing.T) {
		plan := mustPlanInteraction(t, V2CommandRegistry(), InteractionRequest{
			CommandID: "join", Role: RoleNode, Impact: ImpactAvailability, HasTTY: true, Yes: true,
		})
		terminal := &fakePromptIO{hidden: [][]byte{{}, []byte("token")}}
		inputs, err := ReadInteractionInputs(plan, terminal)
		if err != nil {
			t.Fatalf("ReadInteractionInputs() error = %v", err)
		}
		if got := string(inputs.Take(StepInviteToken)); got != "token" {
			t.Fatalf("invite token = %q", got)
		}
		inputs.Destroy()
	})

	t.Run("new passphrase retries mismatched pair", func(t *testing.T) {
		plan := mustPlanInteraction(t, V2CommandRegistry(), InteractionRequest{
			CommandID: "backup", Role: RoleGateway, Impact: ImpactNone, HasTTY: true,
		})
		terminal := &fakePromptIO{hidden: [][]byte{
			[]byte("first"), []byte("wrong"), []byte("second"), []byte("second"),
		}}
		inputs, err := ReadInteractionInputs(plan, terminal)
		if err != nil {
			t.Fatalf("ReadInteractionInputs() error = %v", err)
		}
		secret := inputs.Take(StepBackupPassphrase)
		if string(secret) != "second" {
			t.Fatalf("backup passphrase = %q", secret)
		}
		wipeBytes(secret)
		inputs.Destroy()
	})
}

func TestOneTimeSecretOutputIsTTYOnlyAndSuppressedForDryRun(t *testing.T) {
	t.Parallel()

	registry := V2CommandRegistry()
	request := InteractionRequest{
		CommandID: "invite", Role: RoleGateway, Impact: ImpactNone, HasTTY: true,
	}
	plan := mustPlanInteraction(t, registry, request)
	terminal := &fakePromptIO{}
	if err := WriteInteractionSecret(plan, terminal, []byte("secret")); err != nil {
		t.Fatalf("WriteInteractionSecret() error = %v", err)
	}
	if terminal.writes != 1 || string(terminal.written) != "secret" {
		t.Fatalf("secret writes=%d value=%q", terminal.writes, terminal.written)
	}

	request.DryRun = true
	dryRun := mustPlanInteraction(t, registry, request)
	terminal = &fakePromptIO{}
	if err := WriteInteractionSecret(dryRun, terminal, []byte("must-not-appear")); err != nil {
		t.Fatalf("dry-run WriteInteractionSecret() error = %v", err)
	}
	if terminal.writes != 0 {
		t.Fatalf("dry-run emitted %d secrets", terminal.writes)
	}

	ordinary := mustPlanInteraction(t, registry, InteractionRequest{
		CommandID: "status", Role: RoleGateway, Impact: ImpactNone,
	})
	if err := WriteInteractionSecret(ordinary, terminal, []byte("unexpected")); !errors.Is(err, ErrPromptInput) {
		t.Fatalf("ordinary command secret output error = %v", err)
	}
}

func TestInteractionRejectsInvalidSpecialCases(t *testing.T) {
	t.Parallel()

	registry := V2CommandRegistry()
	tests := []InteractionRequest{
		{CommandID: "missing", Role: RoleGateway, Impact: ImpactNone},
		{CommandID: "status", Role: "proxy", Impact: ImpactNone},
		{CommandID: "invite", Role: RoleNode, Impact: ImpactNone},
		{CommandID: "status", Role: RoleGateway, Impact: "catastrophic"},
		{CommandID: "purge", Role: RoleNode, Impact: ImpactDestructive, IncludeBackups: true},
		{CommandID: "repair", Role: RoleGateway, Impact: ImpactAvailability, IrreversibleMigration: true},
	}
	for _, request := range tests {
		if _, err := registry.PlanInteraction(request); err == nil {
			t.Errorf("PlanInteraction(%+v) unexpectedly succeeded", request)
		}
	}
}

func mustPlanInteraction(t *testing.T, registry CommandRegistry, request InteractionRequest) InteractionPlan {
	t.Helper()
	plan, err := registry.PlanInteraction(request)
	if err != nil {
		t.Fatalf("PlanInteraction(%+v): %v", request, err)
	}
	return plan
}

func stepsInPhase(plan InteractionPlan, phase InteractionPhase) []InteractionStep {
	steps := make([]InteractionStep, 0)
	for _, step := range plan.Steps {
		if step.Phase == phase {
			steps = append(steps, step)
		}
	}
	return steps
}

func assertPromptKinds(t *testing.T, steps []InteractionStep, want ...PromptKind) {
	t.Helper()
	if len(steps) != len(want) {
		t.Fatalf("step count = %d, want %d: %+v", len(steps), len(want), steps)
	}
	for index := range want {
		if steps[index].Prompt != want[index] {
			t.Errorf("step %d prompt = %q, want %q", index, steps[index].Prompt, want[index])
		}
	}
}

func assertEveryStepUsesResolver(t *testing.T, plan InteractionPlan, request InteractionRequest) {
	t.Helper()
	wantRefusal := ""
	for _, step := range plan.Steps {
		want := ResolvePrompt(PromptRequest{
			Kind: step.Prompt, HasTTY: request.HasTTY, Yes: request.Yes, DryRun: request.DryRun,
		})
		if !reflect.DeepEqual(step.Decision, want) {
			t.Errorf("step %s decision = %+v, want %+v", step.ID, step.Decision, want)
		}
		if wantRefusal == "" && want.Action == "refuse" {
			wantRefusal = want.Reason
		}
	}
	if plan.RefusalReason != wantRefusal {
		t.Errorf("refusal = %q, want %q", plan.RefusalReason, wantRefusal)
	}
}

type fakePromptIO struct {
	visible []string
	hidden  [][]byte
	reads   int
	writes  int
	written []byte
}

func (terminal *fakePromptIO) ReadVisible(_ InteractionStep) (string, error) {
	terminal.reads++
	if len(terminal.visible) == 0 {
		return "", errors.New("no visible input")
	}
	value := terminal.visible[0]
	terminal.visible = terminal.visible[1:]
	return value, nil
}

func (terminal *fakePromptIO) ReadHidden(_ InteractionStep, _ int) ([]byte, error) {
	terminal.reads++
	if len(terminal.hidden) == 0 {
		return nil, errors.New("no hidden input")
	}
	value := terminal.hidden[0]
	terminal.hidden = terminal.hidden[1:]
	return append([]byte(nil), value...), nil
}

func (terminal *fakePromptIO) WriteSecret(_ InteractionStep, secret []byte) error {
	terminal.writes++
	terminal.written = append([]byte(nil), secret...)
	return nil
}
