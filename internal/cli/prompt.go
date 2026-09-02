package cli

import (
	"errors"
	"fmt"
	"strings"
)

const maxSecretAttempts = 3

var (
	ErrConsentDeclined = errors.New("operator did not grant consent")
	ErrPromptInput     = errors.New("invalid prompt input")
)

// PromptIO isolates the controlling-terminal implementation from command
// orchestration and makes it possible to verify that refusal happens before
// any prompt or mutation.
type PromptIO interface {
	ReadVisible(InteractionStep) (string, error)
	ReadHidden(InteractionStep, int) ([]byte, error)
	WriteSecret(InteractionStep, []byte) error
}

// InteractionInputs owns hidden values read during pre-mutation interaction.
// Callers must Destroy them as soon as command validation or execution ends.
type InteractionInputs struct {
	values map[string][]byte
}

func (inputs *InteractionInputs) Take(stepID string) []byte {
	if inputs == nil {
		return nil
	}
	value := inputs.values[stepID]
	delete(inputs.values, stepID)
	return value
}

// Copy returns a caller-owned copy for validation without transferring or
// extending ownership of the retained hidden input. The caller must wipe it.
func (inputs *InteractionInputs) Copy(stepID string) []byte {
	if inputs == nil {
		return nil
	}
	return append([]byte(nil), inputs.values[stepID]...)
}

func (inputs *InteractionInputs) Destroy() {
	if inputs == nil {
		return
	}
	for id, value := range inputs.values {
		wipeBytes(value)
		delete(inputs.values, id)
	}
}

// ReadInteractionInputs executes all input and consent steps only after the
// complete plan has proven that every required channel exists. Output steps are
// deliberately deferred until the authoritative operation succeeds.
func ReadInteractionInputs(plan InteractionPlan, terminal PromptIO) (*InteractionInputs, error) {
	if err := requireInteractionPhases(plan, InteractionInput, InteractionConsent, InteractionOutput); err != nil {
		return nil, err
	}
	return readInteractionPhases(plan, terminal, InteractionInput, InteractionConsent)
}

// ReadSecretInputs performs only hidden pre-plan input. It also preflights the
// one-time output channel so a secret-issuing operation cannot activate a token
// when no controlling TTY was available at command start.
func ReadSecretInputs(plan InteractionPlan, terminal PromptIO) (*InteractionInputs, error) {
	if err := requireInteractionPhases(plan, InteractionInput, InteractionOutput); err != nil {
		return nil, err
	}
	return readInteractionPhases(plan, terminal, InteractionInput)
}

// ReadConsent performs the post-plan consent phase. The complete interaction
// plan, including any required one-time output, is checked before prompting.
func ReadConsent(plan InteractionPlan, terminal PromptIO) error {
	if err := requireInteractionPhases(plan, InteractionConsent, InteractionOutput); err != nil {
		return err
	}
	inputs, err := readInteractionPhases(plan, terminal, InteractionConsent)
	if inputs != nil {
		inputs.Destroy()
	}
	return err
}

func readInteractionPhases(plan InteractionPlan, terminal PromptIO, phases ...InteractionPhase) (*InteractionInputs, error) {
	selected := make(map[InteractionPhase]struct{}, len(phases))
	for _, phase := range phases {
		selected[phase] = struct{}{}
	}
	inputs := &InteractionInputs{values: make(map[string][]byte)}
	fail := func(err error) (*InteractionInputs, error) {
		inputs.Destroy()
		return nil, err
	}
	for _, step := range plan.Steps {
		if _, run := selected[step.Phase]; !run || step.Decision.Action == "proceed" {
			continue
		}
		if step.Decision.Action != "prompt" {
			return fail(fmt.Errorf("%w: unsupported action %q for step %s", ErrPromptInput, step.Decision.Action, step.ID))
		}
		if terminal == nil {
			return fail(fmt.Errorf("%w: prompt terminal is unavailable", ErrPromptInput))
		}

		switch step.Prompt {
		case PromptConfirm:
			answer, err := terminal.ReadVisible(step)
			if err != nil {
				return fail(fmt.Errorf("%w: %s: %v", ErrPromptInput, step.ID, err))
			}
			confirmed, valid := parseConfirmation(answer)
			if !valid {
				return fail(fmt.Errorf("%w: %s accepts only y/yes/n/no", ErrPromptInput, step.ID))
			}
			if !confirmed {
				return fail(fmt.Errorf("%w: %s", ErrConsentDeclined, step.ID))
			}
		case PromptTyped:
			answer, err := terminal.ReadVisible(step)
			if err != nil {
				return fail(fmt.Errorf("%w: %s: %v", ErrPromptInput, step.ID, err))
			}
			if answer != step.Exact {
				return fail(fmt.Errorf("%w: %s", ErrConsentDeclined, step.ID))
			}
		case PromptSecretOnce:
			value, err := readRequiredSecret(terminal, step)
			if err != nil {
				return fail(err)
			}
			inputs.values[step.ID] = value
		case PromptSecretTwice:
			value, err := readMatchingSecret(terminal, step)
			if err != nil {
				return fail(err)
			}
			inputs.values[step.ID] = value
		default:
			return fail(fmt.Errorf("%w: unsupported prompt kind %q", ErrPromptInput, step.Prompt))
		}
	}
	return inputs, nil
}

func requireInteractionPhases(plan InteractionPlan, phases ...InteractionPhase) error {
	selected := make(map[InteractionPhase]struct{}, len(phases))
	for _, phase := range phases {
		selected[phase] = struct{}{}
	}
	for _, step := range plan.Steps {
		if _, checked := selected[step.Phase]; checked && step.Decision.Action == "refuse" {
			return fmt.Errorf("%w: %s: %s", ErrInteractionRefused, plan.CommandID, step.Decision.Reason)
		}
	}
	return nil
}

// WriteInteractionSecret writes a newly issued token exactly once through the
// preflighted controlling-terminal channel. It must be called after successful
// authoritative commit and before a success document is emitted.
func WriteInteractionSecret(plan InteractionPlan, terminal PromptIO, secret []byte) error {
	if err := plan.RequireAllowed(); err != nil {
		return err
	}
	foundOutput := false
	for _, step := range plan.Steps {
		if step.Phase != InteractionOutput {
			continue
		}
		foundOutput = true
		if step.Decision.Action == "proceed" {
			continue
		}
		if step.Decision.Action != "write" || terminal == nil {
			return fmt.Errorf("%w: secret output channel is unavailable", ErrPromptInput)
		}
		if len(secret) == 0 {
			return fmt.Errorf("%w: one-time secret is empty", ErrPromptInput)
		}
		return terminal.WriteSecret(step, secret)
	}
	if !foundOutput && len(secret) != 0 {
		return fmt.Errorf("%w: command has no one-time secret output", ErrPromptInput)
	}
	return nil
}

func parseConfirmation(value string) (confirmed bool, valid bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "y", "yes":
		return true, true
	case "", "n", "no":
		return false, true
	default:
		return false, false
	}
}

func readRequiredSecret(terminal PromptIO, step InteractionStep) ([]byte, error) {
	for attempt := 1; attempt <= maxSecretAttempts; attempt++ {
		value, err := terminal.ReadHidden(step, 1)
		if err != nil {
			wipeBytes(value)
			return nil, fmt.Errorf("%w: %s: %v", ErrPromptInput, step.ID, err)
		}
		if len(value) != 0 {
			return value, nil
		}
		wipeBytes(value)
	}
	return nil, fmt.Errorf("%w: %s is empty after %d attempts", ErrPromptInput, step.ID, maxSecretAttempts)
}

func readMatchingSecret(terminal PromptIO, step InteractionStep) ([]byte, error) {
	for attempt := 1; attempt <= maxSecretAttempts; attempt++ {
		first, err := terminal.ReadHidden(step, 1)
		if err != nil {
			wipeBytes(first)
			return nil, fmt.Errorf("%w: %s: %v", ErrPromptInput, step.ID, err)
		}
		second, err := terminal.ReadHidden(step, 2)
		if err != nil {
			wipeBytes(first)
			wipeBytes(second)
			return nil, fmt.Errorf("%w: %s confirmation: %v", ErrPromptInput, step.ID, err)
		}
		matches := len(first) != 0 && equalBytes(first, second)
		wipeBytes(second)
		if matches {
			return first, nil
		}
		wipeBytes(first)
	}
	return nil, fmt.Errorf("%w: %s did not match after %d attempts", ErrPromptInput, step.ID, maxSecretAttempts)
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
