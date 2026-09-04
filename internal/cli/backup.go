package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const emptyBackupSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

type backupManager interface {
	Plan(context.Context, string) (lifecycle.GatewayBackupPlan, error)
	Apply(context.Context, lifecycle.GatewayBackupPlan, []byte) (lifecycle.GatewayBackupResult, error)
	Discard(lifecycle.GatewayBackupPlan) error
}

var (
	backupSystemPaths = store.DefaultPaths
	backupLoadRole    = loadSystemHostRole
	backupBuilder     = buildSystemBackupper
	backupOpenTTY     = func() (PromptIO, io.Closer, error) {
		terminal, err := OpenControllingTerminal()
		if err != nil {
			return nil, nil, err
		}
		return terminal, terminal, nil
	}
)

type backupArguments struct {
	OutputPath string
	DryRun     bool
	Yes        bool
	JSON       bool
	Help       bool
}

func isBackupInvocation(args []string) bool {
	for _, argument := range args {
		if argument == "--json" || argument == "--dry-run" || argument == "--yes" {
			continue
		}
		return argument == "backup"
	}
	return false
}

func executeBackup(args []string, stdout, stderr io.Writer) int {
	parsed, err := parseBackupArguments(args)
	if parsed.Help {
		printBackupHelp(stdout)
		return ExitSuccess
	}
	emitter, emitterErr := NewResultEmitter(stdout, stderr, parsed.JSON)
	if emitterErr != nil {
		fmt.Fprintf(stderr, "backup failed: %v\n", emitterErr)
		return ExitInternal
	}
	if err != nil {
		return emitBackupFailure(emitter, output.CategoryValidation, "invalid_arguments", err.Error(), parsed.OutputPath)
	}
	paths := backupSystemPaths()
	role, err := backupLoadRole(paths)
	if err != nil || role != RoleGateway {
		return emitBackupFailure(emitter, output.CategoryValidation, "invalid_host_state", "backup requires an initialized gateway", parsed.OutputPath)
	}
	manager, err := backupBuilder(context.Background(), paths)
	if err != nil {
		category, code, message := classifyBackupError(err)
		return emitBackupFailure(emitter, category, code, message, parsed.OutputPath)
	}
	workflow, err := NewBackupWorkflow(manager, parsed.OutputPath)
	if err != nil {
		return emitBackupFailure(emitter, output.CategoryInternal, "backup_internal_error", "vpnctl could not prepare the backup workflow", parsed.OutputPath)
	}
	defer workflow.Discard()
	var terminal PromptIO
	var closer io.Closer
	if !parsed.DryRun {
		terminal, closer, _ = backupOpenTTY()
		if closer != nil {
			defer closer.Close()
		}
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "backup", Role: role, DryRun: parsed.DryRun, Yes: parsed.Yes, JSON: parsed.JSON,
	}, terminal, workflow, nil)
	if err != nil {
		category, code, message := classifyBackupError(err)
		return emitBackupFailure(emitter, category, code, message, parsed.OutputPath)
	}
	code, err := emitter.Emit(outcome.Result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func parseBackupArguments(args []string) (backupArguments, error) {
	parsed := backupArguments{}
	positionals := make([]string, 0, len(args))
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
		case "--yes":
			if parsed.Yes {
				return parsed, fmt.Errorf("--yes may be supplied only once")
			}
			parsed.Yes = true
		case "--defer":
			return parsed, fmt.Errorf("backup does not support --defer")
		case "-h", "--help", "help":
			parsed.Help = true
		default:
			if strings.HasPrefix(argument, "-") {
				return parsed, fmt.Errorf("unsupported backup option %s", argument)
			}
			positionals = append(positionals, argument)
		}
	}
	if parsed.Help {
		return parsed, nil
	}
	if len(positionals) == 0 || positionals[0] != "backup" {
		return parsed, fmt.Errorf("backup command is missing")
	}
	if len(positionals) > 2 {
		return parsed, fmt.Errorf("backup accepts at most one archive path")
	}
	if len(positionals) == 2 {
		parsed.OutputPath = positionals[1]
	}
	return parsed, nil
}

type BackupWorkflow struct {
	manager  backupManager
	path     string
	plan     lifecycle.GatewayBackupPlan
	public   MutationPlan
	planned  bool
	finished bool
}

func NewBackupWorkflow(manager backupManager, path string) (*BackupWorkflow, error) {
	if manager == nil {
		return nil, fmt.Errorf("backup manager is required")
	}
	return &BackupWorkflow{manager: manager, path: path}, nil
}

func (workflow *BackupWorkflow) Plan(ctx context.Context, _ *InteractionInputs) (MutationPlan, error) {
	if workflow == nil || workflow.manager == nil || workflow.planned {
		return MutationPlan{}, fmt.Errorf("backup workflow cannot be planned")
	}
	plan, err := workflow.manager.Plan(ctx, workflow.path)
	if err != nil {
		return MutationPlan{}, err
	}
	public := MutationPlan{Impact: ImpactNone, Result: backupPlanOutput(plan)}
	workflow.plan, workflow.public, workflow.planned = plan, public, true
	return public, nil
}

func (workflow *BackupWorkflow) Apply(ctx context.Context, public MutationPlan, inputs *InteractionInputs) (AppliedMutation, error) {
	if workflow == nil || workflow.manager == nil || !workflow.planned || workflow.finished || !reflect.DeepEqual(public, workflow.public) {
		return AppliedMutation{}, fmt.Errorf("backup apply does not match the retained plan")
	}
	passphrase := inputs.Take(StepBackupPassphrase)
	if len(passphrase) == 0 {
		return AppliedMutation{}, fmt.Errorf("backup passphrase is unavailable")
	}
	result, err := workflow.manager.Apply(ctx, workflow.plan, passphrase)
	workflow.finished = true
	if err != nil {
		return AppliedMutation{}, err
	}
	return AppliedMutation{Result: backupResultOutput(result)}, nil
}

func (workflow *BackupWorkflow) Discard() error {
	if workflow == nil || workflow.manager == nil || !workflow.planned || workflow.finished {
		return nil
	}
	workflow.finished = true
	return workflow.manager.Discard(workflow.plan)
}

func backupPlanOutput(plan lifecycle.GatewayBackupPlan) output.Result {
	result := output.NewResult("backup", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"output_path": plan.OutputPath, "file_mode": "0600", "sha256": emptyBackupSHA256,
	})
	result.ResourceIDs["backup"] = plan.BackupID
	return result
}

func backupResultOutput(value lifecycle.GatewayBackupResult) output.Result {
	result := output.NewResult("backup", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"output_path": value.OutputPath, "file_mode": fmt.Sprintf("%04o", value.FileMode.Perm()), "sha256": value.SHA256,
	})
	result.ResourceIDs["backup"] = value.BackupID
	return result
}

func buildSystemBackupper(_ context.Context, paths store.Paths) (backupManager, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	secretStore, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, err
	}
	payloads, err := lifecycle.NewGatewayBackupPayloadSource(paths, secretStore)
	if err != nil {
		return nil, err
	}
	return lifecycle.NewGatewayBackupper(lifecycle.GatewayBackupRuntime{
		State: stateStore, Payloads: payloads, BackupsDir: paths.BackupsDir,
	})
}

func classifyBackupError(err error) (output.ExitCategory, string, string) {
	switch {
	case errors.Is(err, lifecycle.ErrBackupExists):
		return output.CategoryConflict, "backup_exists", "the backup target already exists; choose a new archive path"
	case errors.Is(err, lifecycle.ErrBackupConflict), errors.Is(err, store.ErrStateConflict):
		return output.CategoryConflict, "backup_conflict", "authoritative gateway state changed; retry the backup"
	case errors.Is(err, ErrInteractionRefused), errors.Is(err, ErrPromptInput), errors.Is(err, ErrUnsupportedRole), errors.Is(err, ErrMutationFlags):
		return output.CategoryValidation, "backup_validation", singleLineGatewayInitMessage(err.Error())
	case errors.Is(err, os.ErrPermission):
		return output.CategoryUnavailable, "backup_output_unavailable", "the backup destination is not writable"
	default:
		return output.CategoryInternal, "backup_internal_error", "vpnctl could not create the encrypted gateway backup"
	}
}

func emitBackupFailure(emitter *ResultEmitter, category output.ExitCategory, warningCode, warningMessage, outputPath string) int {
	if outputPath == "" || strings.ContainsAny(outputPath, "\x00\r\n") {
		outputPath = "unavailable"
	}
	result := output.NewResult("backup", output.StatusFailed, category, output.SafeObject{
		"output_path": outputPath, "file_mode": "0600", "sha256": emptyBackupSHA256,
	})
	result.Warnings = append(result.Warnings, output.Message{Code: warningCode, Message: singleLineGatewayInitMessage(warningMessage)})
	code, err := emitter.Emit(result)
	if err != nil {
		return ExitInternal
	}
	return code
}

func printBackupHelp(writer io.Writer) {
	fmt.Fprint(writer, `Create a passphrase-encrypted portable gateway backup.

Usage:
  vpnctl backup [archive-path] [--dry-run] [--json]

The passphrase and confirmation are read only from the controlling terminal.
Existing archive targets are never overwritten.
`)
}

var _ MutationWorkflow = (*BackupWorkflow)(nil)
