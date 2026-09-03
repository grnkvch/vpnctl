package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

func TestExecuteGatewayInitUsesV2WorkflowAndEmitsConfirmAction(t *testing.T) {
	initializer := &recordingGatewayInitializer{}
	restore := stubGatewayInitCommand(t, initializer, RoleUninitialized, "1.1.1.1 54321 8.8.8.8 2222")
	defer restore()

	var stdout, stderr bytes.Buffer
	code := Execute([]string{
		"--json", "init", "--gateway", "--public-ip", "8.8.8.8",
		"--client-cidr", "10.76.0.0/24", "--node-cidr", "10.77.0.0/24",
		"--external-interface", "ens3", "--ssh-port", "2222", "--yes",
	}, &stdout, &stderr)
	if code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("Execute() code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if initializer.planCalls != 1 || initializer.applyCalls != 1 {
		t.Fatalf("initializer calls: plan=%d apply=%d", initializer.planCalls, initializer.applyCalls)
	}
	wantPort := 2222
	wantInput := lifecycle.GatewayInitInput{
		PublicIPv4: "8.8.8.8", ClientCIDR: "10.76.0.0/24", NodeCIDR: "10.77.0.0/24",
		ExternalInterface: "ens3", ExplicitSSHPort: &wantPort, SSHConnection: "1.1.1.1 54321 8.8.8.8 2222",
	}
	if !reflect.DeepEqual(initializer.input, wantInput) {
		t.Fatalf("gateway init input = %+v, want %+v", initializer.input, wantInput)
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.Command != "init.gateway" || result.Status != output.StatusOK || result.Data["changed"] != true || result.Data["role"] != "gateway" {
		t.Fatalf("result = %+v", result)
	}
	handshakeHost, ok := result.Data["handshake_host"].(map[string]any)
	if !ok || handshakeHost["list_version"] != float64(1) || handshakeHost["candidate_id"] != "microsoft" || handshakeHost["hostname"] != "www.microsoft.com" {
		t.Fatalf("handshake-host output = %#v", result.Data["handshake_host"])
	}
	if result.ResourceIDs["host_id"] != gatewayCLIHostID || result.ResourceIDs["transaction_id"] != "fw-ABC123" {
		t.Fatalf("resource IDs = %v", result.ResourceIDs)
	}
	if len(result.RequiresAction) != 1 || result.RequiresAction[0].Command != "vpnctl confirm fw-ABC123" {
		t.Fatalf("requires_action = %+v", result.RequiresAction)
	}
}

func TestDevelopmentComponentManifestIncludesPinnedFRP(t *testing.T) {
	t.Parallel()

	manifest := developmentComponentManifest()
	if err := manifest.Validate(); err != nil {
		t.Fatalf("developmentComponentManifest().Validate() error = %v", err)
	}
	for _, component := range manifest.Components {
		if component.Name != tunnel.FRPProviderName {
			continue
		}
		if component.Version != tunnel.FRPProviderVersion || component.SHA256 != tunnel.FRPProviderSHA256 ||
			component.Source != "vpnctl-release-bundle" || !component.Bundled {
			t.Fatalf("frp component = %+v", component)
		}
		return
	}
	t.Fatal("development component manifest does not contain frp")
}

func TestGatewayInitOutputWithUnknownSwapCapacityIsValid(t *testing.T) {
	t.Parallel()
	result := gatewayInitOutput(lifecycle.GatewayInitPlan{
		Changed: true, HostID: gatewayCLIHostID,
		Network: linuxplatform.GatewayNetworkPlan{
			PublicIPv4: "8.8.8.8", ClientCIDR: model.DefaultClientCIDR,
			NodeCIDR: model.DefaultNodeCIDR, ExternalInterface: "eth0",
		},
		SSH:           linuxplatform.SSHPortPlan{Port: 2222},
		HandshakeHost: model.HandshakeHost{SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)},
	}, lifecycle.GatewayInitResult{}, false)
	if err := result.Validate(); err != nil {
		t.Fatalf("gatewayInitOutput() validation error = %v; result=%+v", err, result)
	}
}

func TestExecuteGatewayInitDryRunDoesNotApplyOrRequestTTY(t *testing.T) {
	initializer := &recordingGatewayInitializer{}
	restore := stubGatewayInitCommand(t, initializer, RoleUninitialized, "1.1.1.1 54321 8.8.8.8 2222")
	defer restore()
	originalTTY := gatewayInitOpenTTY
	gatewayInitOpenTTY = func() (PromptIO, io.Closer, error) {
		t.Fatal("dry-run opened controlling TTY")
		return nil, nil, errors.New("unreachable")
	}
	defer func() { gatewayInitOpenTTY = originalTTY }()

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"init", "--gateway", "--public-ip", "8.8.8.8", "--dry-run", "--json"}, &stdout, &stderr)
	if code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("Execute() code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if initializer.planCalls != 1 || initializer.applyCalls != 0 {
		t.Fatalf("dry-run calls: plan=%d apply=%d", initializer.planCalls, initializer.applyCalls)
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ResourceIDs["transaction_id"] != "" || len(result.RequiresAction) != 0 || result.Data["changed"] != true {
		t.Fatalf("dry-run result = %+v", result)
	}
}

func TestExecuteGatewayInitRequiresConsentBeforeApply(t *testing.T) {
	initializer := &recordingGatewayInitializer{}
	restore := stubGatewayInitCommand(t, initializer, RoleUninitialized, "1.1.1.1 54321 8.8.8.8 2222")
	defer restore()
	originalTTY := gatewayInitOpenTTY
	terminal := &gatewayInitPrompt{answer: "yes"}
	gatewayInitOpenTTY = func() (PromptIO, io.Closer, error) { return terminal, io.NopCloser(strings.NewReader("")), nil }
	defer func() { gatewayInitOpenTTY = originalTTY }()

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"init", "--gateway", "--public-ip", "8.8.8.8"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("Execute() code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if terminal.visibleCalls != 1 || initializer.applyCalls != 1 {
		t.Fatalf("consent/apply calls = %d/%d", terminal.visibleCalls, initializer.applyCalls)
	}
}

func TestExecuteGatewayInitManagedSwapChoiceIsSeparateAndExplicit(t *testing.T) {
	t.Run("interactive accept then init consent", func(t *testing.T) {
		initializer := &recordingGatewayInitializer{offerManagedSwap: true}
		restore := stubGatewayInitCommand(t, initializer, RoleUninitialized, "1.1.1.1 54321 8.8.8.8 2222")
		defer restore()
		originalTTY := gatewayInitOpenTTY
		terminal := &sequenceGatewayInitPrompt{answers: []string{"yes", "yes"}}
		gatewayInitOpenTTY = func() (PromptIO, io.Closer, error) { return terminal, io.NopCloser(strings.NewReader("")), nil }
		defer func() { gatewayInitOpenTTY = originalTTY }()

		var stdout, stderr bytes.Buffer
		code := Execute([]string{"init", "--gateway", "--public-ip", "8.8.8.8", "--json"}, &stdout, &stderr)
		if code != ExitSuccess || stderr.Len() != 0 || terminal.visibleCalls != 2 || !initializer.appliedPlan.ManagedSwapSelected {
			t.Fatalf("accept code/prompts/selection = %d/%d/%t stdout=%q stderr=%q", code, terminal.visibleCalls, initializer.appliedPlan.ManagedSwapSelected, stdout.String(), stderr.String())
		}
		var result output.Result
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		managed := result.Data["managed_swap"].(map[string]any)
		if managed["offered"] != true || managed["selected"] != true || managed["status"] != string(linuxplatform.ManagedSwapOffered) {
			t.Fatalf("managed swap output = %+v", managed)
		}
	})

	t.Run("interactive decline continues init", func(t *testing.T) {
		initializer := &recordingGatewayInitializer{offerManagedSwap: true}
		restore := stubGatewayInitCommand(t, initializer, RoleUninitialized, "1.1.1.1 54321 8.8.8.8 2222")
		defer restore()
		originalTTY := gatewayInitOpenTTY
		terminal := &sequenceGatewayInitPrompt{answers: []string{"no", "yes"}}
		gatewayInitOpenTTY = func() (PromptIO, io.Closer, error) { return terminal, io.NopCloser(strings.NewReader("")), nil }
		defer func() { gatewayInitOpenTTY = originalTTY }()

		var stdout, stderr bytes.Buffer
		code := Execute([]string{"init", "--gateway", "--public-ip", "8.8.8.8", "--json"}, &stdout, &stderr)
		if code != ExitSuccess || stderr.Len() != 0 || terminal.visibleCalls != 2 || initializer.appliedPlan.ManagedSwapSelected {
			t.Fatalf("decline code/prompts/selection = %d/%d/%t stdout=%q stderr=%q", code, terminal.visibleCalls, initializer.appliedPlan.ManagedSwapSelected, stdout.String(), stderr.String())
		}
	})

	t.Run("yes accepts swap without tty", func(t *testing.T) {
		initializer := &recordingGatewayInitializer{offerManagedSwap: true}
		restore := stubGatewayInitCommand(t, initializer, RoleUninitialized, "1.1.1.1 54321 8.8.8.8 2222")
		defer restore()
		originalTTY := gatewayInitOpenTTY
		gatewayInitOpenTTY = func() (PromptIO, io.Closer, error) {
			t.Fatal("--yes opened controlling TTY")
			return nil, nil, nil
		}
		defer func() { gatewayInitOpenTTY = originalTTY }()

		var stdout, stderr bytes.Buffer
		code := Execute([]string{"init", "--gateway", "--public-ip", "8.8.8.8", "--yes", "--json"}, &stdout, &stderr)
		if code != ExitSuccess || stderr.Len() != 0 || !initializer.appliedPlan.ManagedSwapSelected {
			t.Fatalf("--yes code/selection = %d/%t stdout=%q stderr=%q", code, initializer.appliedPlan.ManagedSwapSelected, stdout.String(), stderr.String())
		}
	})

	t.Run("dry-run reports offer without choosing", func(t *testing.T) {
		initializer := &recordingGatewayInitializer{offerManagedSwap: true}
		restore := stubGatewayInitCommand(t, initializer, RoleUninitialized, "1.1.1.1 54321 8.8.8.8 2222")
		defer restore()
		var stdout, stderr bytes.Buffer
		code := Execute([]string{"init", "--gateway", "--public-ip", "8.8.8.8", "--dry-run", "--json"}, &stdout, &stderr)
		if code != ExitSuccess || stderr.Len() != 0 || initializer.applyCalls != 0 {
			t.Fatalf("dry-run code/apply = %d/%d stdout=%q stderr=%q", code, initializer.applyCalls, stdout.String(), stderr.String())
		}
		var result output.Result
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		managed := result.Data["managed_swap"].(map[string]any)
		if managed["offered"] != true || managed["selected"] != false {
			t.Fatalf("dry-run managed swap = %+v", managed)
		}
	})
}

func TestExecuteGatewayInitRejectsRoleFlagsBeforeBuilder(t *testing.T) {
	originalBuilder := gatewayInitBuilder
	gatewayInitBuilder = func(context.Context, store.Paths) (gatewayInitializerAPI, error) {
		t.Fatal("invalid arguments built system initializer")
		return nil, nil
	}
	defer func() { gatewayInitBuilder = originalBuilder }()

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"init", "--gateway", "--node", "--public-ip", "8.8.8.8", "--json"}, &stdout, &stderr)
	if code != ExitValidation || stderr.Len() != 0 {
		t.Fatalf("Execute() code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "invalid_arguments" || result.Data["changed"] != false {
		t.Fatalf("result = %+v", result)
	}
}

func TestExecuteGatewayInitMapsPlanValidationWithoutApply(t *testing.T) {
	initializer := &recordingGatewayInitializer{planErr: linuxplatform.ErrInvalidGatewayNetwork}
	restore := stubGatewayInitCommand(t, initializer, RoleUninitialized, "")
	defer restore()

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"init", "--gateway", "--public-ip", "8.8.8.8", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitValidation || initializer.applyCalls != 0 || stderr.Len() != 0 {
		t.Fatalf("Execute() code=%d apply=%d stdout=%q stderr=%q", code, initializer.applyCalls, stdout.String(), stderr.String())
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Warnings[0].Code != "init_validation" || result.Data["changed"] != false {
		t.Fatalf("result = %+v", result)
	}
}

func TestExecuteGatewayInitRejectsExistingNodeBeforeBuilder(t *testing.T) {
	initializer := &recordingGatewayInitializer{}
	restore := stubGatewayInitCommand(t, initializer, RoleNode, "")
	defer restore()
	originalBuilder := gatewayInitBuilder
	gatewayInitBuilder = func(context.Context, store.Paths) (gatewayInitializerAPI, error) {
		t.Fatal("node role built gateway initializer")
		return nil, nil
	}
	defer func() { gatewayInitBuilder = originalBuilder }()

	var stdout, stderr bytes.Buffer
	code := Execute([]string{"init", "--gateway", "--public-ip", "8.8.8.8", "--yes", "--json"}, &stdout, &stderr)
	if code != ExitConflict || initializer.planCalls != 0 || initializer.applyCalls != 0 || stderr.Len() != 0 {
		t.Fatalf("Execute() code=%d plan=%d apply=%d stdout=%q stderr=%q", code, initializer.planCalls, initializer.applyCalls, stdout.String(), stderr.String())
	}
}

const gatewayCLIHostID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

type recordingGatewayInitializer struct {
	input            lifecycle.GatewayInitInput
	planCalls        int
	applyCalls       int
	planErr          error
	offerManagedSwap bool
	appliedPlan      lifecycle.GatewayInitPlan
}

func (initializer *recordingGatewayInitializer) Plan(_ context.Context, input lifecycle.GatewayInitInput) (lifecycle.GatewayInitPlan, error) {
	initializer.planCalls++
	initializer.input = input
	if initializer.planErr != nil {
		return lifecycle.GatewayInitPlan{}, initializer.planErr
	}
	port := 2222
	if input.ExplicitSSHPort != nil {
		port = *input.ExplicitSSHPort
	}
	plan := lifecycle.GatewayInitPlan{
		Changed: true, HostID: gatewayCLIHostID,
		Network: linuxplatform.GatewayNetworkPlan{
			PublicIPv4: input.PublicIPv4, ClientCIDR: defaultString(input.ClientCIDR, model.DefaultClientCIDR),
			NodeCIDR: defaultString(input.NodeCIDR, model.DefaultNodeCIDR), ExternalInterface: defaultString(input.ExternalInterface, "eth0"),
		},
		SSH:           linuxplatform.SSHPortPlan{Port: port, Source: linuxplatform.SSHPortFromConnection},
		HandshakeHost: model.HandshakeHost{SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)},
	}
	if initializer.offerManagedSwap {
		plan.ManagedSwap = linuxplatform.ManagedSwapPlan{
			Disposition: linuxplatform.ManagedSwapOffered, Offered: true,
			Path: linuxplatform.ManagedSwapLogicalPath, SizeBytes: linuxplatform.ManagedSwapSizeBytes,
			DiskReserve: linuxplatform.ManagedSwapDiskReserve,
		}
	}
	return plan, nil
}

func (initializer *recordingGatewayInitializer) Apply(_ context.Context, plan lifecycle.GatewayInitPlan) (lifecycle.GatewayInitResult, error) {
	initializer.applyCalls++
	initializer.appliedPlan = plan
	return lifecycle.GatewayInitResult{Changed: true, HostID: plan.HostID, TransactionID: "fw-ABC123", Network: plan.Network}, nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

type gatewayInitPrompt struct {
	answer       string
	visibleCalls int
}

type sequenceGatewayInitPrompt struct {
	answers      []string
	visibleCalls int
}

func (prompt *sequenceGatewayInitPrompt) ReadVisible(InteractionStep) (string, error) {
	if prompt.visibleCalls >= len(prompt.answers) {
		return "", errors.New("no prompt answer")
	}
	answer := prompt.answers[prompt.visibleCalls]
	prompt.visibleCalls++
	return answer, nil
}

func (*sequenceGatewayInitPrompt) ReadHidden(InteractionStep, int) ([]byte, error) {
	return nil, errors.New("unexpected hidden prompt")
}

func (*sequenceGatewayInitPrompt) WriteSecret(InteractionStep, []byte) error {
	return errors.New("unexpected secret output")
}

func (prompt *gatewayInitPrompt) ReadVisible(InteractionStep) (string, error) {
	prompt.visibleCalls++
	return prompt.answer, nil
}

func (*gatewayInitPrompt) ReadHidden(InteractionStep, int) ([]byte, error) {
	return nil, errors.New("unexpected hidden prompt")
}

func (*gatewayInitPrompt) WriteSecret(InteractionStep, []byte) error {
	return errors.New("unexpected secret output")
}

func stubGatewayInitCommand(t *testing.T, initializer gatewayInitializerAPI, role HostRole, sshConnection string) func() {
	t.Helper()
	originalPaths := gatewayInitSystemPaths
	originalLookup := gatewayInitLookupEnv
	originalRole := gatewayInitLoadRole
	originalBuilder := gatewayInitBuilder
	paths, _ := store.NewPaths(t.TempDir())
	gatewayInitSystemPaths = func() store.Paths { return paths }
	gatewayInitLookupEnv = func(name string) (string, bool) {
		if name != "SSH_CONNECTION" {
			t.Fatalf("unexpected environment lookup %q", name)
		}
		return sshConnection, sshConnection != ""
	}
	gatewayInitLoadRole = func(got store.Paths) (HostRole, error) {
		if !reflect.DeepEqual(got, paths) {
			t.Fatalf("role paths = %+v, want %+v", got, paths)
		}
		return role, nil
	}
	gatewayInitBuilder = func(_ context.Context, got store.Paths) (gatewayInitializerAPI, error) {
		if !reflect.DeepEqual(got, paths) {
			t.Fatalf("builder paths = %+v, want %+v", got, paths)
		}
		return initializer, nil
	}
	return func() {
		gatewayInitSystemPaths = originalPaths
		gatewayInitLookupEnv = originalLookup
		gatewayInitLoadRole = originalRole
		gatewayInitBuilder = originalBuilder
	}
}
