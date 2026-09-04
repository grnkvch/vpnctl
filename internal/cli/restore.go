package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type restoreManager interface {
	Plan(context.Context, lifecycle.GatewayRestoreInput, []byte) (lifecycle.GatewayRestorePlan, error)
	Apply(context.Context, lifecycle.GatewayRestorePlan) (lifecycle.GatewayRestoreResult, error)
	Discard(lifecycle.GatewayRestorePlan) error
}

var (
	restoreSystemPaths = store.DefaultPaths
	restoreLoadRole    = loadSystemHostRole
	restoreBuilder     = buildSystemGatewayRestorer
	restoreLookupEnv   = os.LookupEnv
	restoreOpenTTY     = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

type restoreArguments struct {
	ArchivePath string
	PublicIPv4  string
	Replace     bool
	DryRun      bool
	Yes         bool
	JSON        bool
	Help        bool
}

func isRestoreInvocation(args []string) bool {
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--public-ip":
			index++
		case strings.HasPrefix(argument, "--public-ip="):
		case argument == "--json" || argument == "--dry-run" || argument == "--yes" || argument == "--replace" || argument == "--help" || argument == "-h":
		default:
			return argument == "restore"
		}
	}
	return false
}

func executeRestore(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseRestoreArguments(args)
	if parsed.Help {
		printRestoreHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "restore failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitRestoreFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error())
	}
	paths := restoreSystemPaths()
	role, err := restoreLoadRole(paths)
	if err != nil {
		return emitRestoreFailure(emitter, output.CategoryValidation, "invalid_host_state", "vpnctl host state is invalid")
	}
	manager, err := restoreBuilder(context.Background(), paths)
	if err != nil {
		category, code, message := classifyRestoreError(err)
		return emitRestoreFailure(emitter, category, code, message)
	}
	workflow, err := NewRestoreWorkflow(manager, lifecycle.GatewayRestoreInput{
		ArchivePath: parsed.ArchivePath, PublicIPv4: parsed.PublicIPv4, Replace: parsed.Replace,
	})
	if err != nil {
		return emitRestoreFailure(emitter, output.CategoryInternal, "restore_internal_error", "vpnctl could not prepare the restore workflow")
	}
	defer workflow.Discard()

	// Restore dry-run must still authenticate and fully prevalidate the archive,
	// so its single passphrase prompt is never skipped.
	terminal, closer, _ := restoreOpenTTY()
	if closer != nil {
		defer closer.Close()
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "restore", Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes, JSON: parsed.JSON,
	}, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyRestoreError(err)
		return emitRestoreFailure(emitter, category, code, message)
	}
	code, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func parseRestoreArguments(args []string) (restoreArguments, error) {
	parsed := restoreArguments{}
	positionals := make([]string, 0, 2)
	seenPublicIP := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--json":
			if parsed.JSON {
				return parsed, fmt.Errorf("--json may be supplied only once")
			}
			parsed.JSON = true
		case argument == "--dry-run":
			if parsed.DryRun {
				return parsed, fmt.Errorf("--dry-run may be supplied only once")
			}
			parsed.DryRun = true
		case argument == "--yes":
			if parsed.Yes {
				return parsed, fmt.Errorf("--yes may be supplied only once")
			}
			parsed.Yes = true
		case argument == "--replace":
			if parsed.Replace {
				return parsed, fmt.Errorf("--replace may be supplied only once")
			}
			parsed.Replace = true
		case argument == "--defer":
			return parsed, fmt.Errorf("restore does not support --defer")
		case argument == "-h" || argument == "--help" || argument == "help":
			parsed.Help = true
		case argument == "--public-ip":
			if seenPublicIP {
				return parsed, fmt.Errorf("--public-ip may be supplied only once")
			}
			index++
			if index >= len(args) || args[index] == "" {
				return parsed, fmt.Errorf("--public-ip requires a value")
			}
			seenPublicIP = true
			parsed.PublicIPv4 = args[index]
		case strings.HasPrefix(argument, "--public-ip="):
			if seenPublicIP {
				return parsed, fmt.Errorf("--public-ip may be supplied only once")
			}
			seenPublicIP = true
			parsed.PublicIPv4 = strings.TrimPrefix(argument, "--public-ip=")
			if parsed.PublicIPv4 == "" {
				return parsed, fmt.Errorf("--public-ip requires a value")
			}
		case strings.HasPrefix(argument, "-"):
			return parsed, fmt.Errorf("unsupported restore option %s", argument)
		default:
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) == 0 || positionals[0] != "restore" {
		return parsed, fmt.Errorf("restore command is missing")
	}
	if len(positionals) != 2 {
		return parsed, fmt.Errorf("restore requires exactly one archive path")
	}
	if !seenPublicIP {
		return parsed, fmt.Errorf("restore requires --public-ip")
	}
	absolute, err := filepath.Abs(positionals[1])
	if err != nil {
		return parsed, fmt.Errorf("resolve restore archive path: %w", err)
	}
	parsed.ArchivePath = filepath.Clean(absolute)
	return parsed, nil
}

type RestoreWorkflow struct {
	manager  restoreManager
	input    lifecycle.GatewayRestoreInput
	plan     lifecycle.GatewayRestorePlan
	public   MutationPlan
	planned  bool
	finished bool
}

func NewRestoreWorkflow(manager restoreManager, input lifecycle.GatewayRestoreInput) (*RestoreWorkflow, error) {
	if manager == nil {
		return nil, fmt.Errorf("restore manager is required")
	}
	return &RestoreWorkflow{manager: manager, input: input}, nil
}

func (workflow *RestoreWorkflow) Plan(ctx context.Context, inputs *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.manager == nil || workflow.planned {
		return MutationPlan{}, fmt.Errorf("restore workflow cannot be planned")
	}
	passphrase := inputs.Take(StepRestorePassphrase)
	if len(passphrase) == 0 {
		return MutationPlan{}, fmt.Errorf("restore passphrase is unavailable")
	}
	plan, err := workflow.manager.Plan(ctx, workflow.input, passphrase)
	if err != nil {
		return MutationPlan{}, err
	}
	impact := ImpactAvailability
	if plan.ReplacingInitialized {
		impact = ImpactDestructive
	}
	public := MutationPlan{Impact: impact, Result: restorePlanOutput(plan)}
	workflow.plan, workflow.public, workflow.planned = plan, public, true
	return public, nil
}

func (workflow *RestoreWorkflow) Apply(ctx context.Context, public MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.manager == nil || !workflow.planned || workflow.finished || !reflect.DeepEqual(public, workflow.public) {
		return AppliedMutation{}, fmt.Errorf("restore apply does not match the retained plan")
	}
	result, err := workflow.manager.Apply(ctx, workflow.plan)
	workflow.finished = true
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: restoreResultOutput(result)}, nil
}

func (workflow *RestoreWorkflow) Discard() error {
	if workflow == nil || workflow.manager == nil || !workflow.planned || workflow.finished {
		return nil
	}
	workflow.finished = true
	return workflow.manager.Discard(workflow.plan)
}

func restorePlanOutput(plan lifecycle.GatewayRestorePlan) output.Result {
	result := output.NewResult("restore", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": true, "generation": plan.TargetGeneration,
		"affected_services": stringSafeList(plan.AffectedServices), "expected_interruptions": stringSafeList(plan.ExpectedInterruptions),
	})
	result.ResourceIDs["gateway"] = plan.GatewayID
	return result
}

func restoreResultOutput(value lifecycle.GatewayRestoreResult) output.Result {
	result := output.NewResult("restore", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed": value.Changed, "generation": value.Generation,
		"affected_services": stringSafeList(value.AffectedServices), "expected_interruptions": stringSafeList(value.ExpectedInterruptions),
	})
	result.ResourceIDs["gateway"] = value.GatewayID
	if value.EmergencySnapshot != nil {
		result.Data["snapshot_id"] = value.EmergencySnapshot.ID
		result.ResourceIDs["snapshot"] = value.EmergencySnapshot.ID
	}
	return result
}

func stringSafeList(values []string) output.SafeList {
	result := make(output.SafeList, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func buildSystemGatewayRestorer(ctx context.Context, paths store.Paths) (restoreManager, error) {
	discoverer, err := linuxplatform.NewDiscoverer(paths.Root)
	if err != nil {
		return nil, err
	}
	snapshot, err := discoverer.Discover(ctx)
	if err != nil {
		return nil, err
	}
	release, err := buildSystemInitRelease(paths, snapshot)
	if err != nil {
		return nil, err
	}
	sshConnection, _ := restoreLookupEnv("SSH_CONNECTION")
	return controller.NewSystemGatewayRestorer(paths, snapshot, release, linuxplatform.DefaultVPNCTLBinaryPath, sshConnection)
}

func classifyRestoreError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, lifecycle.ErrGatewayRestoreArchiveInvalid), errors.Is(err, lifecycle.ErrBackupArchiveInvalid),
		errors.Is(err, lifecycle.ErrBackupAuthentication):
		return output.CategoryValidation, "restore_archive_invalid", "the backup archive, passphrase, or authenticated payload is invalid"
	case errors.Is(err, lifecycle.ErrGatewayRestoreReplaceNeeded):
		return output.CategoryConflict, "restore_replace_required", "the host is already a gateway; review the impact and rerun with --replace"
	case errors.Is(err, lifecycle.ErrGatewayRestoreConflict), errors.Is(err, linuxplatform.ErrGatewayPreflightConflict):
		return output.CategoryConflict, "restore_conflict", singleLineGatewayInitMessage(err.Error())
	case errors.Is(err, lifecycle.ErrReleaseInstallConflict):
		return output.CategoryConflict, "restore_release_conflict", "installed component files differ from the verified restore release"
	case errors.Is(err, lifecycle.ErrGatewayRestoreEndpointMove):
		return output.CategoryValidation, "restore_endpoint_move_unsupported", "this iteration restores only to the archive public IP"
	case errors.Is(err, lifecycle.ErrGatewayRestoreIncompatible), errors.Is(err, linuxplatform.ErrUnsupportedHost),
		errors.Is(err, linuxplatform.ErrInvalidGatewayNetwork), errors.Is(err, linuxplatform.ErrSSHPortUnverified),
		errors.Is(err, ErrInteractionRefused), errors.Is(err, ErrPromptInput), errors.Is(err, ErrConsentDeclined),
		errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags):
		return output.CategoryValidation, "restore_validation", singleLineGatewayInitMessage(err.Error())
	case errors.Is(err, os.ErrPermission):
		return output.CategoryUnavailable, "restore_host_unavailable", "the gateway host is not writable"
	default:
		return output.CategoryInternal, "restore_internal_error", "vpnctl could not restore the gateway"
	}
}

func emitRestoreFailure(emitter *ResultEmitter, category output.ExitCategory, warningCode, warningMessage string) int {
	result := output.NewResult("restore", output.StatusFailed, category, output.SafeObject{"changed": false, "generation": 0})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printRestoreHelp(writer io.Writer) {
	fmt.Fprint(writer, `Restore a gateway backup without merging it into existing state.

Usage:
  vpnctl restore <archive-path> --public-ip <IPv4> [--replace] [--dry-run] [--yes] [--json]

The passphrase is read once from the controlling terminal, including for
--dry-run. Restoring an initialized gateway requires explicit --replace and
creates a durable emergency snapshot before convergence.
`)
}

var _ MutationWorkflow = (*RestoreWorkflow)(nil)
