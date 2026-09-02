package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestEveryV2CommandEnforcesFrozenDryRunAndDeferSupport(t *testing.T) {
	t.Parallel()

	registry := V2CommandRegistry()
	for _, spec := range registry.Commands() {
		spec := spec
		for _, role := range spec.Roles {
			role := role
			t.Run(spec.ID+"/"+string(role), func(t *testing.T) {
				base := MutationRequest{CommandID: spec.ID, Role: role}
				_, mode, err := registry.ResolveMutationMode(base)
				if err != nil || mode != MutationImmediate {
					t.Fatalf("immediate mode = %q, %v", mode, err)
				}

				dryRun := base
				dryRun.DryRun = true
				_, mode, err = registry.ResolveMutationMode(dryRun)
				if spec.DryRun {
					if err != nil || mode != MutationDryRun {
						t.Errorf("supported dry-run mode = %q, %v", mode, err)
					}
				} else if !errors.Is(err, ErrMutationFlags) {
					t.Errorf("unsupported dry-run error = %v", err)
				}

				deferred := base
				deferred.Defer = true
				_, mode, err = registry.ResolveMutationMode(deferred)
				wantDefer := spec.Defer == DeferYes || (spec.Defer == DeferNodeOnly && role == RoleNode)
				if wantDefer {
					if err != nil || mode != MutationDeferred {
						t.Errorf("supported defer mode = %q, %v", mode, err)
					}
				} else if !errors.Is(err, ErrMutationFlags) {
					t.Errorf("unsupported defer error = %v", err)
				}

				both := base
				both.DryRun = true
				both.Defer = true
				if _, _, err := registry.ResolveMutationMode(both); !errors.Is(err, ErrMutationFlags) {
					t.Errorf("combined flags error = %v", err)
				}

				jsonRequest := base
				jsonRequest.JSON = true
				_, jsonMode, jsonErr := registry.ResolveMutationMode(jsonRequest)
				if jsonErr != nil || jsonMode != MutationImmediate {
					t.Errorf("--json changed mutation mode to %q, %v", jsonMode, jsonErr)
				}
			})
		}
	}
}

func TestNodeOnlyDeferMetadataIsRoleScoped(t *testing.T) {
	t.Parallel()

	spec := command("custom", "custom", "operation-v1:custom", []HostRole{RoleGateway, RoleNode}, ConsentNone, true, DeferNodeOnly)
	registry, err := NewCommandRegistry([]CommandSpec{spec})
	if err != nil {
		t.Fatalf("NewCommandRegistry() error = %v", err)
	}
	if _, mode, err := registry.ResolveMutationMode(MutationRequest{CommandID: "custom", Role: RoleNode, Defer: true}); err != nil || mode != MutationDeferred {
		t.Fatalf("node defer mode = %q, %v", mode, err)
	}
	if _, _, err := registry.ResolveMutationMode(MutationRequest{CommandID: "custom", Role: RoleGateway, Defer: true}); !errors.Is(err, ErrMutationFlags) {
		t.Fatalf("gateway node-only defer error = %v", err)
	}
}

func TestDryRunCallsOnlyReadOnlyPlanAndCreatesNoFiles(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workflow := &recordingWorkflow{
		commandID: "expose",
		applyPath: filepath.Join(root, "applied"),
	}
	authority := &recordingAuthority{
		commandID: "expose",
		writePath: filepath.Join(root, "pending"),
	}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "expose", Role: RoleNode, DryRun: true, JSON: true,
	}, nil, workflow, authority)
	if err != nil {
		t.Fatalf("RunMutation(dry-run) error = %v", err)
	}
	if outcome.Mode != MutationDryRun || outcome.Result.Command != "expose" {
		t.Fatalf("dry-run outcome = %+v", outcome)
	}
	if workflow.planCalls != 1 || workflow.applyCalls != 0 || authority.calls != 0 {
		t.Fatalf("dry-run calls: plan=%d apply=%d authority=%d", workflow.planCalls, workflow.applyCalls, authority.calls)
	}
	assertPathsAbsent(t, workflow.applyPath, authority.writePath)
}

func TestDeferRequiresSuccessfulAuthoritativeGatewayWrite(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	request := MutationRequest{CommandID: "policy.set.node", Role: RoleNode, Defer: true}

	t.Run("missing gateway", func(t *testing.T) {
		workflow := &recordingWorkflow{commandID: request.CommandID, applyPath: filepath.Join(root, "missing-local")}
		_, err := V2CommandRegistry().RunMutation(context.Background(), request, nil, workflow, nil)
		if !errors.Is(err, ErrGatewayUnavailable) {
			t.Fatalf("missing authority error = %v", err)
		}
		if workflow.planCalls != 0 || workflow.applyCalls != 0 {
			t.Fatalf("missing authority calls: plan=%d apply=%d", workflow.planCalls, workflow.applyCalls)
		}
		assertPathsAbsent(t, workflow.applyPath)
	})

	t.Run("failed gateway", func(t *testing.T) {
		workflow := &recordingWorkflow{commandID: request.CommandID, applyPath: filepath.Join(root, "failed-local")}
		authority := &recordingAuthority{commandID: request.CommandID, err: errors.New("gateway unreachable")}
		_, err := V2CommandRegistry().RunMutation(context.Background(), request, nil, workflow, authority)
		if err == nil || !errors.Is(err, authority.err) {
			t.Fatalf("failed authority error = %v", err)
		}
		if workflow.planCalls != 1 || workflow.applyCalls != 0 || authority.calls != 1 {
			t.Fatalf("failed authority calls: plan=%d apply=%d authority=%d", workflow.planCalls, workflow.applyCalls, authority.calls)
		}
		assertPathsAbsent(t, workflow.applyPath)
	})

	t.Run("recorded on gateway", func(t *testing.T) {
		workflow := &recordingWorkflow{commandID: request.CommandID, applyPath: filepath.Join(root, "success-local")}
		authority := &recordingAuthority{commandID: request.CommandID, writePath: filepath.Join(root, "gateway", "pending")}
		outcome, err := V2CommandRegistry().RunMutation(context.Background(), request, nil, workflow, authority)
		if err != nil {
			t.Fatalf("RunMutation(defer) error = %v", err)
		}
		if outcome.Mode != MutationDeferred || outcome.OperationID != "op-authoritative" || outcome.AuthoritativeGeneration != 42 || outcome.Result.Status != output.StatusPending || outcome.Result.Command != "policy.set" {
			t.Fatalf("deferred outcome = %+v", outcome)
		}
		if workflow.applyCalls != 0 || authority.calls != 1 {
			t.Fatalf("successful defer calls: apply=%d authority=%d", workflow.applyCalls, authority.calls)
		}
		assertPathsAbsent(t, workflow.applyPath)
		if _, err := os.Stat(authority.writePath); err != nil {
			t.Fatalf("authoritative pending evidence: %v", err)
		}
	})
}

func TestDeferredMutationRetainsNormalConsent(t *testing.T) {
	t.Parallel()

	request := MutationRequest{CommandID: "transport.switch", Role: RoleNode, Defer: true, JSON: true}
	workflow := &recordingWorkflow{commandID: request.CommandID, impact: ImpactAvailability}
	authority := &recordingAuthority{commandID: request.CommandID}
	if _, err := V2CommandRegistry().RunMutation(context.Background(), request, nil, workflow, authority); !errors.Is(err, ErrInteractionRefused) {
		t.Fatalf("non-interactive deferred consent error = %v", err)
	}
	if authority.calls != 0 || workflow.applyCalls != 0 {
		t.Fatalf("refused defer calls: authority=%d apply=%d", authority.calls, workflow.applyCalls)
	}

	request.Yes = true
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), request, nil, workflow, authority)
	if err != nil {
		t.Fatalf("deferred --yes error = %v", err)
	}
	if outcome.Mode != MutationDeferred || authority.calls != 1 || workflow.applyCalls != 0 {
		t.Fatalf("deferred --yes outcome=%+v authority=%d apply=%d", outcome, authority.calls, workflow.applyCalls)
	}
}

func TestImmediateMutationNeverUsesDeferredWriter(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workflow := &recordingWorkflow{commandID: "dns.set", applyPath: filepath.Join(root, "applied")}
	authority := &recordingAuthority{commandID: "dns.set", writePath: filepath.Join(root, "pending")}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "dns.set", Role: RoleNode,
	}, nil, workflow, authority)
	if err != nil {
		t.Fatalf("RunMutation(immediate) error = %v", err)
	}
	if outcome.Mode != MutationImmediate || workflow.applyCalls != 1 || authority.calls != 0 {
		t.Fatalf("immediate outcome=%+v apply=%d authority=%d", outcome, workflow.applyCalls, authority.calls)
	}
	if _, err := os.Stat(workflow.applyPath); err != nil {
		t.Fatalf("immediate apply evidence: %v", err)
	}
	assertPathsAbsent(t, authority.writePath)
}

func TestMutationPipelinePlansBeforeConsentAndJSONDoesNotConsent(t *testing.T) {
	t.Parallel()

	t.Run("interactive order", func(t *testing.T) {
		var events []string
		workflow := &recordingWorkflow{commandID: "repair", events: &events}
		terminal := &orderedPromptIO{visible: []string{"yes"}, events: &events}
		if _, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
			CommandID: "repair", Role: RoleGateway,
		}, terminal, workflow, nil); err != nil {
			t.Fatalf("RunMutation() error = %v", err)
		}
		if want := []string{"plan", "visible", "apply"}; !reflect.DeepEqual(events, want) {
			t.Fatalf("events = %v, want %v", events, want)
		}
	})

	t.Run("json non-interactive refusal", func(t *testing.T) {
		workflow := &recordingWorkflow{commandID: "repair"}
		_, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
			CommandID: "repair", Role: RoleGateway, JSON: true,
		}, nil, workflow, nil)
		if !errors.Is(err, ErrInteractionRefused) {
			t.Fatalf("JSON non-interactive error = %v", err)
		}
		if workflow.planCalls != 1 || workflow.applyCalls != 0 {
			t.Fatalf("JSON refusal calls: plan=%d apply=%d", workflow.planCalls, workflow.applyCalls)
		}
	})

	t.Run("yes non-interactive", func(t *testing.T) {
		workflow := &recordingWorkflow{commandID: "repair"}
		if _, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
			CommandID: "repair", Role: RoleGateway, JSON: true, Yes: true,
		}, nil, workflow, nil); err != nil {
			t.Fatalf("JSON --yes error = %v", err)
		}
		if workflow.applyCalls != 1 {
			t.Fatalf("JSON --yes apply calls = %d", workflow.applyCalls)
		}
	})
}

func TestMutationPipelineReadsRequiredSecretsBeforePlanning(t *testing.T) {
	t.Parallel()

	var events []string
	workflow := &recordingWorkflow{
		commandID:    "restore",
		secretStepID: StepRestorePassphrase,
		wantSecret:   "passphrase",
		events:       &events,
	}
	terminal := &orderedPromptIO{hidden: [][]byte{[]byte("passphrase")}, events: &events}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "restore", Role: RoleUninitialized, DryRun: true,
	}, terminal, workflow, nil)
	if err != nil {
		t.Fatalf("RunMutation(restore dry-run) error = %v", err)
	}
	if outcome.Mode != MutationDryRun || workflow.applyCalls != 0 {
		t.Fatalf("restore dry-run outcome=%+v apply=%d", outcome, workflow.applyCalls)
	}
	if want := []string{"hidden", "plan"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v", events, want)
	}

	backup := &recordingWorkflow{commandID: "backup"}
	if _, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "backup", Role: RoleGateway, DryRun: true,
	}, nil, backup, nil); err != nil {
		t.Fatalf("backup dry-run without TTY error = %v", err)
	}
	if backup.planCalls != 1 || backup.applyCalls != 0 {
		t.Fatalf("backup dry-run calls: plan=%d apply=%d", backup.planCalls, backup.applyCalls)
	}
}

func TestImmediateSecretIssuanceUsesOnlyPreflightedTTY(t *testing.T) {
	t.Parallel()

	workflow := &recordingWorkflow{commandID: "invite", oneTimeSecret: "invite-value"}
	terminal := &orderedPromptIO{}
	outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "invite", Role: RoleGateway,
	}, terminal, workflow, nil)
	if err != nil {
		t.Fatalf("RunMutation(invite) error = %v", err)
	}
	if outcome.Result.Command != "invite" || terminal.writes != 1 || string(terminal.written) != "invite-value" {
		t.Fatalf("invite outcome=%+v writes=%d secret=%q", outcome, terminal.writes, terminal.written)
	}

	workflow = &recordingWorkflow{commandID: "invite", oneTimeSecret: "must-not-exist"}
	terminal = &orderedPromptIO{}
	if _, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "invite", Role: RoleGateway, DryRun: true,
	}, terminal, workflow, nil); err != nil {
		t.Fatalf("RunMutation(invite dry-run) error = %v", err)
	}
	if workflow.applyCalls != 0 || terminal.writes != 0 {
		t.Fatalf("invite dry-run apply=%d writes=%d", workflow.applyCalls, terminal.writes)
	}
}

func TestRunMutationRejectsInvalidPlanAndDeferredReceipt(t *testing.T) {
	t.Parallel()

	workflow := &recordingWorkflow{commandID: "expose", impact: ImpactClass("unknown")}
	if _, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "expose", Role: RoleNode, DryRun: true,
	}, nil, workflow, nil); !errors.Is(err, ErrInvalidMutationPlan) {
		t.Fatalf("invalid plan error = %v", err)
	}

	workflow = &recordingWorkflow{commandID: "expose"}
	authority := &recordingAuthority{commandID: "other"}
	if _, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
		CommandID: "expose", Role: RoleNode, Defer: true,
	}, nil, workflow, authority); !errors.Is(err, ErrInvalidMutationPlan) {
		t.Fatalf("invalid receipt error = %v", err)
	}
}

type recordingWorkflow struct {
	commandID     string
	impact        ImpactClass
	irreversible  bool
	secretStepID  string
	wantSecret    string
	oneTimeSecret string
	applyPath     string
	events        *[]string
	planCalls     int
	applyCalls    int
}

func (workflow *recordingWorkflow) Plan(_ context.Context, inputs *InteractionInputs) (MutationPlan, error) {
	workflow.planCalls++
	appendEvent(workflow.events, "plan")
	if workflow.secretStepID != "" {
		secret := inputs.Copy(workflow.secretStepID)
		defer wipeBytes(secret)
		if string(secret) != workflow.wantSecret {
			return MutationPlan{}, errors.New("planned without expected hidden input")
		}
	}
	impact := workflow.impact
	if impact == "" {
		impact = ImpactNone
	}
	return MutationPlan{
		Impact:                impact,
		IrreversibleMigration: workflow.irreversible,
		Result:                mutationResult(publicResultCommand(workflow.commandID), output.StatusOK),
	}, nil
}

func (workflow *recordingWorkflow) Apply(_ context.Context, _ MutationPlan, _ *InteractionInputs) (AppliedMutation, error) {
	workflow.applyCalls++
	appendEvent(workflow.events, "apply")
	if workflow.applyPath != "" {
		if err := os.MkdirAll(filepath.Dir(workflow.applyPath), 0o700); err != nil {
			return AppliedMutation{}, err
		}
		if err := os.WriteFile(workflow.applyPath, []byte("applied"), 0o600); err != nil {
			return AppliedMutation{}, err
		}
	}
	result := AppliedMutation{Result: mutationResult(publicResultCommand(workflow.commandID), output.StatusOK)}
	if workflow.oneTimeSecret != "" {
		secret, err := output.NewSecretString(workflow.oneTimeSecret)
		if err != nil {
			return AppliedMutation{}, err
		}
		result.OneTimeSecret = &secret
	}
	return result, nil
}

type recordingAuthority struct {
	commandID string
	writePath string
	err       error
	calls     int
}

func (authority *recordingAuthority) RegisterPending(_ context.Context, _ MutationPlan) (DeferredReceipt, error) {
	authority.calls++
	if authority.err != nil {
		return DeferredReceipt{}, authority.err
	}
	if authority.writePath != "" {
		if err := os.MkdirAll(filepath.Dir(authority.writePath), 0o700); err != nil {
			return DeferredReceipt{}, err
		}
		if err := os.WriteFile(authority.writePath, []byte("authoritative"), 0o600); err != nil {
			return DeferredReceipt{}, err
		}
	}
	return DeferredReceipt{
		CommandID:               authority.commandID,
		OperationID:             "op-authoritative",
		AuthoritativeGeneration: 42,
		Result:                  mutationResult(publicResultCommand(authority.commandID), output.StatusPending),
	}, nil
}

type orderedPromptIO struct {
	visible []string
	hidden  [][]byte
	events  *[]string
	writes  int
	written []byte
}

func (terminal *orderedPromptIO) ReadVisible(_ InteractionStep) (string, error) {
	appendEvent(terminal.events, "visible")
	if len(terminal.visible) == 0 {
		return "", errors.New("no visible input")
	}
	value := terminal.visible[0]
	terminal.visible = terminal.visible[1:]
	return value, nil
}

func (terminal *orderedPromptIO) ReadHidden(_ InteractionStep, _ int) ([]byte, error) {
	appendEvent(terminal.events, "hidden")
	if len(terminal.hidden) == 0 {
		return nil, errors.New("no hidden input")
	}
	value := append([]byte(nil), terminal.hidden[0]...)
	terminal.hidden = terminal.hidden[1:]
	return value, nil
}

func (terminal *orderedPromptIO) WriteSecret(_ InteractionStep, secret []byte) error {
	terminal.writes++
	terminal.written = append([]byte(nil), secret...)
	appendEvent(terminal.events, "write")
	return nil
}

func mutationResult(commandID string, status output.Status) output.Result {
	return output.NewResult(commandID, status, output.CategorySuccess, output.SafeObject{"changed": false})
}

func publicResultCommand(commandID string) string {
	spec, found := V2CommandRegistry().Lookup(commandID)
	if !found {
		return commandID
	}
	return mutationResultCommand(spec)
}

func assertPathsAbsent(t *testing.T, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("path %s exists or has unexpected error: %v", path, err)
		}
	}
}

func appendEvent(events *[]string, event string) {
	if events != nil {
		*events = append(*events, event)
	}
}
