package cli

import (
	"errors"
	"fmt"
)

// ImpactClass is produced by a fully rendered operation plan. Conditional
// consent uses it to distinguish an ordinary reconciliation from one that can
// interrupt availability or destroy managed state.
type ImpactClass string

const (
	ImpactNone         ImpactClass = "none"
	ImpactAvailability ImpactClass = "availability"
	ImpactDestructive  ImpactClass = "destructive"
)

type InteractionPhase string

const (
	InteractionInput   InteractionPhase = "input"
	InteractionConsent InteractionPhase = "consent"
	InteractionOutput  InteractionPhase = "output"
)

const (
	StepInviteToken           = "invite_token"
	StepRecoveryToken         = "recovery_token"
	StepBackupPassphrase      = "backup_passphrase"
	StepRestorePassphrase     = "restore_passphrase"
	StepImpactConfirmation    = "impact_confirmation"
	StepPurgeConfirmation     = "purge_confirmation"
	StepBackupDeletion        = "backup_deletion_confirmation"
	StepIrreversibleMigration = "irreversible_migration_confirmation"
	StepOneTimeSecretOutput   = "one_time_secret_output"
)

var ErrInteractionRefused = errors.New("command interaction refused before mutation")

type InteractionRequest struct {
	CommandID             string
	Role                  HostRole
	Impact                ImpactClass
	HasTTY                bool
	Yes                   bool
	JSON                  bool
	DryRun                bool
	IncludeBackups        bool
	IrreversibleMigration bool
}

// InteractionStep contains only public prompt metadata. Secret values and
// entered confirmations are deliberately absent so the plan is safe to render.
type InteractionStep struct {
	ID       string
	Phase    InteractionPhase
	Prompt   PromptKind
	Exact    string
	Decision PromptDecision
}

type InteractionPlan struct {
	CommandID     string
	Steps         []InteractionStep
	RefusalReason string
}

func (plan InteractionPlan) Allowed() bool { return plan.RefusalReason == "" }

func (plan InteractionPlan) RequireAllowed() error {
	if plan.Allowed() {
		return nil
	}
	return fmt.Errorf("%w: %s: %s", ErrInteractionRefused, plan.CommandID, plan.RefusalReason)
}

// PlanInteraction resolves all TTY and consent requirements before a command
// is allowed to mutate state. JSON is intentionally not consulted: it changes
// output formatting and can never grant consent.
func (registry CommandRegistry) PlanInteraction(request InteractionRequest) (InteractionPlan, error) {
	spec, found := registry.commands[request.CommandID]
	if !found {
		return InteractionPlan{}, fmt.Errorf("%w: %s", ErrUnknownCommand, request.CommandID)
	}
	if !validHostRole(request.Role) {
		return InteractionPlan{}, fmt.Errorf("invalid host role %q", request.Role)
	}
	if !spec.AllowsRole(request.Role) {
		return InteractionPlan{}, &RoleError{
			CommandID: request.CommandID,
			Role:      request.Role,
			Allowed:   append([]HostRole(nil), spec.Roles...),
		}
	}
	if !validImpact(request.Impact) {
		return InteractionPlan{}, fmt.Errorf("invalid impact class %q", request.Impact)
	}
	if request.IncludeBackups && (request.CommandID != "purge" || request.Role != RoleGateway) {
		return InteractionPlan{}, fmt.Errorf("include-backups interaction is only valid for gateway purge")
	}
	if request.IrreversibleMigration && request.CommandID != "update" {
		return InteractionPlan{}, fmt.Errorf("irreversible migration interaction is only valid for update")
	}

	plan := InteractionPlan{CommandID: request.CommandID}
	appendStep := func(id string, phase InteractionPhase, prompt PromptKind, exact string) {
		decision := ResolvePrompt(PromptRequest{
			Kind:   prompt,
			HasTTY: request.HasTTY,
			Yes:    request.Yes,
			DryRun: request.DryRun,
		})
		plan.Steps = append(plan.Steps, InteractionStep{
			ID:       id,
			Phase:    phase,
			Prompt:   prompt,
			Exact:    exact,
			Decision: decision,
		})
		if plan.RefusalReason == "" && decision.Action == "refuse" {
			plan.RefusalReason = decision.Reason
		}
	}

	switch spec.SecretFlow {
	case PromptSecretOnce:
		appendStep(secretInputStepID(spec.ID), InteractionInput, spec.SecretFlow, "")
	case PromptSecretTwice:
		appendStep(StepBackupPassphrase, InteractionInput, spec.SecretFlow, "")
	}

	switch spec.Consent {
	case ConsentNone:
	case ConsentConfirm:
		appendStep(StepImpactConfirmation, InteractionConsent, PromptConfirm, "")
	case ConsentConditional:
		if request.Impact == ImpactAvailability || request.Impact == ImpactDestructive {
			appendStep(StepImpactConfirmation, InteractionConsent, PromptConfirm, "")
		}
	case ConsentConfirmTypedIfIrreversible:
		appendStep(StepImpactConfirmation, InteractionConsent, PromptConfirm, "")
		if request.IrreversibleMigration {
			appendStep(StepIrreversibleMigration, InteractionConsent, PromptTyped, "accept irreversible migration")
		}
	case ConsentTyped:
		appendStep(StepPurgeConfirmation, InteractionConsent, PromptTyped, "purge "+string(request.Role))
	}
	if request.IncludeBackups {
		appendStep(StepBackupDeletion, InteractionConsent, PromptTyped, "delete backups")
	}

	if spec.SecretFlow == PromptSecretOutputOnce {
		appendStep(StepOneTimeSecretOutput, InteractionOutput, spec.SecretFlow, "")
	}
	return plan, nil
}

func validImpact(impact ImpactClass) bool {
	return impact == ImpactNone || impact == ImpactAvailability || impact == ImpactDestructive
}

func secretInputStepID(commandID string) string {
	switch commandID {
	case "join":
		return StepInviteToken
	case "node.recover.node":
		return StepRecoveryToken
	case "restore":
		return StepRestorePassphrase
	default:
		return "secret_input"
	}
}
