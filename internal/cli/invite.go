package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type inviteCommandService interface {
	InviteIssuer
	InviteCanceller
}

var (
	inviteSystemPaths = store.DefaultPaths
	inviteLoadRole    = loadSystemHostRole
	inviteCallGateway = control.CallLocal
	inviteBuild       = buildSystemInviteService
	inviteOpenTTY     = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

func isInviteInvocation(args []string) bool {
	for _, argument := range args {
		if argument == "--json" {
			continue
		}
		return argument == "invite"
	}
	return false
}

type inviteArguments struct {
	CommandID string
	NodeName  string
	InviteID  string
	DryRun    bool
	JSON      bool
	ShowHelp  bool
}

func executeInvite(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseInviteArguments(args)
	if parsed.ShowHelp {
		printInviteHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "invite failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitInviteFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := inviteSystemPaths()
	role, err := inviteLoadRole(paths)
	if err != nil || role == RoleUninitialized {
		return emitInviteFailure(emitter, parsed.CommandID, output.CategoryValidation, "invalid_host_state", "invite requires an initialized gateway")
	}
	if role != RoleGateway {
		return emitInviteFailure(emitter, parsed.CommandID, output.CategoryValidation, "unsupported_role", "invite commands are gateway-only")
	}
	service, err := inviteBuild(paths)
	if err != nil {
		category, code, message := classifyInviteError(err)
		return emitInviteFailure(emitter, parsed.CommandID, category, code, message)
	}
	var workflow MutationWorkflow
	switch parsed.CommandID {
	case "invite":
		workflow, err = NewInviteIssueWorkflow(service, parsed.NodeName)
	case "invite.cancel":
		workflow, err = NewInviteCancelWorkflow(service, parsed.InviteID)
	default:
		err = fmt.Errorf("unsupported invite command")
	}
	if err != nil {
		category, code, message := classifyInviteError(err)
		return emitInviteFailure(emitter, parsed.CommandID, category, code, message)
	}
	var terminal PromptIO
	var closer io.Closer
	if parsed.CommandID == "invite" && !parsed.DryRun {
		terminal, closer, err = inviteOpenTTY()
		if err != nil {
			return emitInviteFailure(emitter, parsed.CommandID, output.CategoryValidation, "controlling_tty_required", "invite token output requires a controlling TTY")
		}
		defer closer.Close()
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: parsed.CommandID, Role: role, DryRun: parsed.DryRun, JSON: parsed.JSON,
	}, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyInviteError(err)
		return emitInviteFailure(emitter, parsed.CommandID, category, code, message)
	}
	code, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func parseInviteArguments(args []string) (inviteArguments, error) {
	parsed := inviteArguments{CommandID: "invite"}
	positionals := make([]string, 0, 3)
	for _, argument := range args {
		switch argument {
		case "--json":
			if parsed.JSON {
				return parsed, fmt.Errorf("--json may be supplied only once")
			}
			parsed.JSON = true
		case "--dry-run":
			if parsed.DryRun {
				return parsed, fmt.Errorf("--dry-run may be supplied only once")
			}
			parsed.DryRun = true
		case "-h", "--help", "help":
			parsed.ShowHelp = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported invite option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.ShowHelp {
		return parsed, nil
	}
	if len(positionals) < 2 || positionals[0] != "invite" {
		return parsed, fmt.Errorf("invite requires a node name or cancel action")
	}
	if positionals[1] == "cancel" {
		parsed.CommandID = "invite.cancel"
		if len(positionals) != 3 {
			return parsed, fmt.Errorf("invite cancel requires exactly one invite ID")
		}
		parsed.InviteID = positionals[2]
		return parsed, nil
	}
	if len(positionals) != 2 {
		return parsed, fmt.Errorf("invite requires exactly one node name")
	}
	parsed.NodeName = positionals[1]
	return parsed, nil
}

type systemInviteService struct {
	paths   store.Paths
	manager *enrollment.InviteManager
}

func buildSystemInviteService(paths store.Paths) (inviteCommandService, error) {
	state, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	manager, err := enrollment.NewInviteManager(state, nil, nil)
	if err != nil {
		return nil, err
	}
	return &systemInviteService{paths: paths, manager: manager}, nil
}

func (service *systemInviteService) PlanIssue(nodeName string) (enrollment.InviteIssuePlan, error) {
	return service.manager.PlanIssue(nodeName)
}

func (service *systemInviteService) CommitIssue(ctx context.Context, plan enrollment.InviteIssuePlan) (enrollment.InviteIssueResult, error) {
	payload, err := json.Marshal(controller.GatewayInviteIssuePayload{Plan: plan})
	if err != nil {
		return enrollment.InviteIssueResult{}, err
	}
	response, err := inviteCallGateway(ctx, service.paths.ControlSocket, control.LocalRequest{
		SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate,
		Operation: enrollment.InviteIssueOperation, ExpectedGeneration: plan.ExpectedStateGeneration, Payload: payload,
	})
	if err != nil {
		return enrollment.InviteIssueResult{}, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	if !response.OK {
		if response.ErrorCode == "generation_conflict" {
			return enrollment.InviteIssueResult{}, store.ErrStateConflict
		}
		return enrollment.InviteIssueResult{}, fmt.Errorf("gateway invite issue failed: %s", response.ErrorCode)
	}
	var data controller.GatewayInviteIssueData
	if err := control.DecodeRPCPayload(response.Data, &data); err != nil {
		return enrollment.InviteIssueResult{}, fmt.Errorf("decode gateway invite issue: %w", err)
	}
	token, err := output.NewSecretString(data.Token)
	data.Token = ""
	if err != nil {
		return enrollment.InviteIssueResult{}, err
	}
	return enrollment.InviteIssueResult{Invite: data.Invite, StateGeneration: response.Generation, Token: &token}, nil
}

func (service *systemInviteService) PlanCancel(inviteID string) (enrollment.InviteCancelPlan, error) {
	return service.manager.PlanCancel(inviteID)
}

func (service *systemInviteService) CommitCancel(plan enrollment.InviteCancelPlan) (enrollment.InviteCancelResult, error) {
	payload, err := json.Marshal(controller.GatewayInviteCancelPayload{
		InviteID: plan.InviteID, ExpectedStateGeneration: plan.ExpectedStateGeneration,
	})
	if err != nil {
		return enrollment.InviteCancelResult{}, err
	}
	response, err := inviteCallGateway(context.Background(), service.paths.ControlSocket, control.LocalRequest{
		SchemaVersion: control.LocalSchemaVersion, Method: control.LocalMutate,
		Operation: enrollment.InviteCancelOperation, ExpectedGeneration: plan.ExpectedStateGeneration, Payload: payload,
	})
	if err != nil {
		return enrollment.InviteCancelResult{}, fmt.Errorf("%w: %v", ErrGatewayUnavailable, err)
	}
	if !response.OK {
		if response.ErrorCode == "generation_conflict" {
			return enrollment.InviteCancelResult{}, store.ErrStateConflict
		}
		return enrollment.InviteCancelResult{}, fmt.Errorf("gateway invite cancellation failed: %s", response.ErrorCode)
	}
	var data controller.GatewayInviteCancelData
	if err := control.DecodeRPCPayload(response.Data, &data); err != nil {
		return enrollment.InviteCancelResult{}, err
	}
	return enrollment.InviteCancelResult{
		InviteID: data.InviteID, NodeName: data.NodeName, Changed: data.Changed, StateGeneration: response.Generation,
	}, nil
}

func classifyInviteError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, ErrGatewayUnavailable):
		return output.CategoryUnavailable, "gateway_unavailable", "the authoritative gateway controller is unavailable"
	case errors.Is(err, store.ErrStateConflict), errors.Is(err, enrollment.ErrInvitePlanStale), errors.Is(err, enrollment.ErrInviteNameConflict), errors.Is(err, enrollment.ErrInviteConsumed):
		return output.CategoryConflict, "invite_conflict", singleLineGatewayInitMessage(err.Error())
	case errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrInteractionRefused), errors.Is(err, ErrPromptInput), errors.Is(err, enrollment.ErrInviteNotFound):
		return output.CategoryValidation, "invite_validation", singleLineGatewayInitMessage(err.Error())
	default:
		return output.CategoryInternal, "invite_internal_error", "vpnctl could not change the invitation"
	}
}

func emitInviteFailure(emitter *ResultEmitter, commandID string, category output.ExitCategory, warningCode, warningMessage string) int {
	if commandID != "invite" && commandID != "invite.cancel" {
		commandID = "invite"
	}
	result := output.NewResult(commandID, output.StatusFailed, category, output.SafeObject{"changed": false})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printInviteHelp(writer io.Writer) {
	fmt.Fprint(writer, `Issue or cancel a one-time private-node invite.

Usage:
  vpnctl invite <node-name> [--dry-run] [--json]
  vpnctl invite cancel <invite-id> [--dry-run] [--json]

An issued token is written exactly once to the controlling TTY and never to
stdout, JSON, logs, or gateway state.
`)
}

type InviteIssuer interface {
	PlanIssue(nodeName string) (enrollment.InviteIssuePlan, error)
	CommitIssue(context.Context, enrollment.InviteIssuePlan) (enrollment.InviteIssueResult, error)
}

type InviteCanceller interface {
	PlanCancel(inviteID string) (enrollment.InviteCancelPlan, error)
	CommitCancel(enrollment.InviteCancelPlan) (enrollment.InviteCancelResult, error)
}

type InviteIssueWorkflow struct {
	issuer   InviteIssuer
	nodeName string
	plan     enrollment.InviteIssuePlan
	planned  bool
}

func NewInviteIssueWorkflow(issuer InviteIssuer, nodeName string) (*InviteIssueWorkflow, error) {
	if issuer == nil {
		return nil, fmt.Errorf("invite issuer is required")
	}
	if nodeName == "" {
		return nil, fmt.Errorf("invite node name is required")
	}
	return &InviteIssueWorkflow{issuer: issuer, nodeName: nodeName}, nil
}

func (workflow *InviteIssueWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.issuer == nil {
		return MutationPlan{}, fmt.Errorf("invite issue workflow is incomplete")
	}
	plan, err := workflow.issuer.PlanIssue(workflow.nodeName)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan = plan
	workflow.planned = true
	return MutationPlan{Impact: ImpactNone, Result: inviteIssueOutput(plan.ExpiresAt, false, "")}, nil
}

func (workflow *InviteIssueWorkflow) Apply(ctx context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.issuer == nil || !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("invite issue was not planned")
	}
	result, err := workflow.issuer.CommitIssue(ctx, workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	if result.Token == nil {
		return AppliedMutation{}, fmt.Errorf("invite issuer returned no one-time token")
	}
	return AppliedMutation{
		Result:        inviteIssueOutput(result.Invite.ExpiresAt, true, result.Invite.ID),
		OneTimeSecret: result.Token,
	}, nil
}

type InviteCancelWorkflow struct {
	canceller InviteCanceller
	inviteID  string
	plan      enrollment.InviteCancelPlan
	planned   bool
}

func NewInviteCancelWorkflow(canceller InviteCanceller, inviteID string) (*InviteCancelWorkflow, error) {
	if canceller == nil {
		return nil, fmt.Errorf("invite canceller is required")
	}
	if inviteID == "" {
		return nil, fmt.Errorf("invite ID is required")
	}
	return &InviteCancelWorkflow{canceller: canceller, inviteID: inviteID}, nil
}

func (workflow *InviteCancelWorkflow) Plan(_ context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.canceller == nil {
		return MutationPlan{}, fmt.Errorf("invite cancellation workflow is incomplete")
	}
	plan, err := workflow.canceller.PlanCancel(workflow.inviteID)
	if err != nil {
		return MutationPlan{}, err
	}
	workflow.plan = plan
	workflow.planned = true
	return MutationPlan{Impact: ImpactNone, Result: inviteCancelOutput(plan.InviteID, plan.Changed, plan.NextStateGeneration)}, nil
}

func (workflow *InviteCancelWorkflow) Apply(_ context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.canceller == nil || !workflow.planned {
		return AppliedMutation{}, fmt.Errorf("invite cancellation was not planned")
	}
	result, err := workflow.canceller.CommitCancel(workflow.plan)
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: inviteCancelOutput(result.InviteID, result.Changed, result.StateGeneration)}, nil
}

func inviteIssueOutput(expiresAt time.Time, displayed bool, inviteID string) output.Result {
	result := output.NewResult("invite", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"displayed_to_tty": displayed,
		"expires_at":       expiresAt.UTC().Format(time.RFC3339),
	})
	if inviteID != "" {
		result.ResourceIDs["invite_id"] = inviteID
	}
	return result
}

func inviteCancelOutput(inviteID string, changed bool, generation uint64) output.Result {
	result := output.NewResult("invite.cancel", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": changed, "generation": generation,
	})
	result.ResourceIDs["invite_id"] = inviteID
	return result
}

var _ MutationWorkflow = (*InviteIssueWorkflow)(nil)
var _ MutationWorkflow = (*InviteCancelWorkflow)(nil)
