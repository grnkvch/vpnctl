package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/output"
)

type MutationMode string

const (
	MutationImmediate MutationMode = "immediate"
	MutationDryRun    MutationMode = "dry_run"
	MutationDeferred  MutationMode = "deferred"
)

var (
	ErrMutationFlags       = errors.New("unsupported mutation flags")
	ErrGatewayUnavailable  = errors.New("authoritative gateway writer is unavailable")
	ErrInvalidMutationPlan = errors.New("invalid mutation plan")
)

type MutationRequest struct {
	CommandID      string
	Role           HostRole
	DryRun         bool
	Defer          bool
	Yes            bool
	JSON           bool
	IncludeBackups bool
}

// MutationPlan is a read-only proposal. Planning implementations must not
// write desired state, pending operations, files, or services.
type MutationPlan struct {
	Impact                ImpactClass
	IrreversibleMigration bool
	Result                output.Result
}

type MutationWorkflow interface {
	Plan(context.Context, *InteractionInputs) (MutationPlan, error)
	Apply(context.Context, MutationPlan, *InteractionInputs) (AppliedMutation, error)
}

// AppliedMutation keeps a one-time token in the opaque output.Secret type. The
// common runner writes it only to the preflighted controlling TTY and destroys
// it before returning, so it cannot enter normal human or JSON rendering.
type AppliedMutation struct {
	Result        output.Result
	OneTimeSecret *output.Secret
}

// AuthoritativeDeferredWriter is implemented by the gateway controller client:
// a local Unix-socket client on a gateway and an authenticated control client
// on a node. There is intentionally no local/offline defer fallback.
type AuthoritativeDeferredWriter interface {
	RegisterPending(context.Context, MutationPlan) (DeferredReceipt, error)
}

type DeferredReceipt struct {
	CommandID               string
	OperationID             string
	AuthoritativeGeneration uint64
	Result                  output.Result
}

type MutationOutcome struct {
	Mode                    MutationMode
	Plan                    MutationPlan
	Result                  output.Result
	OperationID             string
	AuthoritativeGeneration uint64
}

func (registry CommandRegistry) ResolveMutationMode(request MutationRequest) (CommandSpec, MutationMode, error) {
	spec, found := registry.commands[request.CommandID]
	if !found {
		return CommandSpec{}, "", fmt.Errorf("%w: %s", ErrUnknownCommand, request.CommandID)
	}
	if !validHostRole(request.Role) {
		return CommandSpec{}, "", fmt.Errorf("invalid host role %q", request.Role)
	}
	if !spec.AllowsRole(request.Role) {
		return CommandSpec{}, "", &RoleError{
			CommandID: request.CommandID,
			Role:      request.Role,
			Allowed:   append([]HostRole(nil), spec.Roles...),
		}
	}
	if request.DryRun && request.Defer {
		return CommandSpec{}, "", fmt.Errorf("%w: --dry-run and --defer are mutually exclusive", ErrMutationFlags)
	}
	if request.DryRun {
		if !spec.DryRun {
			return CommandSpec{}, "", fmt.Errorf("%w: command %s does not support --dry-run", ErrMutationFlags, spec.ID)
		}
		return cloneCommandSpec(spec), MutationDryRun, nil
	}
	if request.Defer {
		supported := spec.Defer == DeferYes || (spec.Defer == DeferNodeOnly && request.Role == RoleNode)
		if !supported {
			return CommandSpec{}, "", fmt.Errorf("%w: command %s does not support --defer for role %s", ErrMutationFlags, spec.ID, request.Role)
		}
		return cloneCommandSpec(spec), MutationDeferred, nil
	}
	return cloneCommandSpec(spec), MutationImmediate, nil
}

// RunMutation is the common v2 mutation boundary. It keeps hidden input before
// read-only planning, consent after the complete plan, and selects exactly one
// of dry-run, authoritative defer, or immediate apply.
func (registry CommandRegistry) RunMutation(
	ctx context.Context,
	request MutationRequest,
	terminal PromptIO,
	workflow MutationWorkflow,
	authority AuthoritativeDeferredWriter,
) (MutationOutcome, error) {
	if ctx == nil {
		return MutationOutcome{}, fmt.Errorf("context is required")
	}
	spec, mode, err := registry.ResolveMutationMode(request)
	if err != nil {
		return MutationOutcome{}, err
	}
	if workflow == nil {
		return MutationOutcome{}, fmt.Errorf("mutation workflow is required")
	}
	if mode == MutationDeferred && authority == nil {
		return MutationOutcome{}, fmt.Errorf("%w: command %s", ErrGatewayUnavailable, spec.ID)
	}

	interactionRequest := InteractionRequest{
		CommandID:      spec.ID,
		Role:           request.Role,
		Impact:         ImpactNone,
		HasTTY:         terminal != nil,
		Yes:            request.Yes,
		JSON:           request.JSON,
		DryRun:         mode == MutationDryRun,
		IncludeBackups: request.IncludeBackups,
	}
	prePlan, err := registry.PlanInteraction(interactionRequest)
	if err != nil {
		return MutationOutcome{}, err
	}
	inputs, err := ReadSecretInputs(prePlan, terminal)
	if err != nil {
		return MutationOutcome{}, err
	}
	defer inputs.Destroy()

	planned, err := workflow.Plan(ctx, inputs)
	if err != nil {
		return MutationOutcome{}, fmt.Errorf("plan mutation: %w", err)
	}
	resultCommand := mutationResultCommand(spec)
	if err := planned.validate(resultCommand); err != nil {
		return MutationOutcome{}, err
	}

	interactionRequest.Impact = planned.Impact
	interactionRequest.IrreversibleMigration = planned.IrreversibleMigration
	interactionPlan, err := registry.PlanInteraction(interactionRequest)
	if err != nil {
		return MutationOutcome{}, err
	}
	if err := ReadConsent(interactionPlan, terminal); err != nil {
		return MutationOutcome{}, err
	}

	outcome := MutationOutcome{Mode: mode, Plan: planned}
	switch mode {
	case MutationDryRun:
		outcome.Result = planned.Result
		return outcome, nil
	case MutationDeferred:
		receipt, err := authority.RegisterPending(ctx, planned)
		if err != nil {
			return MutationOutcome{}, fmt.Errorf("register authoritative pending state: %w", err)
		}
		if err := receipt.validate(spec.ID, resultCommand); err != nil {
			return MutationOutcome{}, err
		}
		outcome.Result = receipt.Result
		outcome.OperationID = receipt.OperationID
		outcome.AuthoritativeGeneration = receipt.AuthoritativeGeneration
		return outcome, nil
	case MutationImmediate:
		applied, err := workflow.Apply(ctx, planned, inputs)
		if err != nil {
			return MutationOutcome{}, fmt.Errorf("apply mutation: %w", err)
		}
		if applied.OneTimeSecret != nil {
			defer applied.OneTimeSecret.Destroy()
		}
		if err := validateMutationResult(resultCommand, applied.Result); err != nil {
			return MutationOutcome{}, err
		}
		expectsSecret := spec.SecretFlow == PromptSecretOutputOnce
		if expectsSecret != (applied.OneTimeSecret != nil) {
			return MutationOutcome{}, fmt.Errorf("%w: one-time secret presence does not match command contract", ErrInvalidMutationPlan)
		}
		if applied.OneTimeSecret != nil {
			if err := applied.OneTimeSecret.Use(func(secret []byte) error {
				return WriteInteractionSecret(interactionPlan, terminal, secret)
			}); err != nil {
				return MutationOutcome{}, fmt.Errorf("write one-time secret: %w", err)
			}
		}
		outcome.Result = applied.Result
		return outcome, nil
	default:
		return MutationOutcome{}, fmt.Errorf("%w: unsupported mode %q", ErrMutationFlags, mode)
	}
}

func (plan MutationPlan) validate(commandID string) error {
	if !validImpact(plan.Impact) {
		return fmt.Errorf("%w: impact %q is unsupported", ErrInvalidMutationPlan, plan.Impact)
	}
	if err := validateMutationResult(commandID, plan.Result); err != nil {
		return err
	}
	return nil
}

func (receipt DeferredReceipt) validate(commandID, resultCommand string) error {
	if receipt.CommandID != commandID {
		return fmt.Errorf("%w: deferred receipt command %q does not match %q", ErrInvalidMutationPlan, receipt.CommandID, commandID)
	}
	if receipt.OperationID == "" || receipt.AuthoritativeGeneration == 0 {
		return fmt.Errorf("%w: deferred receipt lacks operation ID or authoritative generation", ErrInvalidMutationPlan)
	}
	if receipt.Result.Status != output.StatusPending {
		return fmt.Errorf("%w: deferred result status must be pending", ErrInvalidMutationPlan)
	}
	return validateMutationResult(resultCommand, receipt.Result)
}

func validateMutationResult(commandID string, result output.Result) error {
	if err := result.Validate(); err != nil {
		return fmt.Errorf("%w: result: %v", ErrInvalidMutationPlan, err)
	}
	if result.Command != commandID {
		return fmt.Errorf("%w: result command %q does not match %q", ErrInvalidMutationPlan, result.Command, commandID)
	}
	return nil
}

func mutationResultCommand(spec CommandSpec) string {
	if separator := strings.LastIndexByte(spec.ResultContract, ':'); separator >= 0 {
		return spec.ResultContract[separator+1:]
	}
	return spec.ID
}
