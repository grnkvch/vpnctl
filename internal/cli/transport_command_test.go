package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestTransportTestCommandRoutesExplicitTargetAndJSON(t *testing.T) {
	paths, restore := stubTransportCommand(t, RoleNode)
	defer restore()

	tester := &transportCommandTester{execution: transportCommandExecution(true)}
	transportBuildTester = func(received store.Paths) (transportTester, error) {
		if received != paths {
			t.Fatalf("tester paths = %+v, want %+v", received, paths)
		}
		return tester, nil
	}
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"--json", "transport", "test", "restricted"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if tester.target != model.TransportRestricted || tester.calls != 1 || stderr.Len() != 0 {
		t.Fatalf("tester=%+v stderr=%q", tester, stderr.String())
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["command"] != "transport.test" || document["status"] != "ok" {
		t.Fatalf("document=%+v", document)
	}
}

func TestTransportTestCommandReportsFailedMandatoryProbeAsUnavailable(t *testing.T) {
	_, restore := stubTransportCommand(t, RoleNode)
	defer restore()
	execution := transportCommandExecution(true)
	execution.Checks.SelectedUDP = transport.ProbeResult{State: transport.ProbeFailed, Code: "restricted_uot_unavailable"}
	transportBuildTester = func(store.Paths) (transportTester, error) {
		return &transportCommandTester{execution: execution}, nil
	}
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"transport", "test", "restricted", "--json"}, &stdout, &stderr); code != ExitUnavailable {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"status":"degraded"`) || !strings.Contains(stdout.String(), "restricted_uot_unavailable") || stderr.Len() != 0 {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestTransportSwitchCommandSupportsDryRunImmediateAndDeferredModes(t *testing.T) {
	for _, test := range []struct {
		name      string
		args      []string
		wantMode  string
		wantApply int
		wantAuth  int
	}{
		{"dry run", []string{"--json", "transport", "switch", "restricted", "--dry-run"}, "ok", 0, 0},
		{"immediate", []string{"transport", "switch", "restricted", "--yes", "--json"}, "ok", 1, 0},
		{"deferred", []string{"transport", "switch", "restricted", "--defer", "--yes", "--json"}, "pending", 0, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, restore := stubTransportCommand(t, RoleNode)
			defer restore()
			switcher := &recordingTransportSwitcher{plan: switchMutationPlan(), result: switchMutationResult()}
			authority := &transportSwitchAuthority{}
			transportBuildSwitcher = func(store.Paths) (TransportSwitcher, error) { return switcher, nil }
			transportBuildAuthority = func(store.Paths) (AuthoritativeDeferredWriter, error) { return authority, nil }
			transportOpenTTY = func() (PromptIO, io.Closer, error) {
				t.Fatal("non-interactive transport switch opened a TTY")
				return nil, nil, nil
			}
			var stdout, stderr bytes.Buffer
			if code := Execute(test.args, &stdout, &stderr); code != ExitSuccess {
				t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if switcher.plans != 1 || switcher.applies != test.wantApply || authority.calls != test.wantAuth ||
				!strings.Contains(stdout.String(), `"status":"`+test.wantMode+`"`) || stderr.Len() != 0 {
				t.Fatalf("switcher=%+v authority=%+v stdout=%s stderr=%s", switcher, authority, stdout.String(), stderr.String())
			}
		})
	}
}

func TestTransportCommandsRejectInvalidArgumentsAndRolesBeforeRuntimeBuild(t *testing.T) {
	oldPaths, oldRole := transportSystemPaths, transportLoadRole
	t.Cleanup(func() { transportSystemPaths, transportLoadRole = oldPaths, oldRole })
	transportSystemPaths = func() store.Paths {
		t.Fatal("invalid transport arguments reached host paths")
		return store.Paths{}
	}
	for _, args := range [][]string{
		{"--json", "transport", "test", "auto"},
		{"--json", "transport", "switch", "restricted", "--dry-run", "--defer"},
		{"--json", "transport", "switch", "standard", "--yes", "--yes"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Execute(args, &stdout, &stderr); code != ExitValidation {
			t.Fatalf("args=%v exit=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
	}

	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	transportSystemPaths = func() store.Paths { return paths }
	transportLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	oldTester, oldSwitcher := transportBuildTester, transportBuildSwitcher
	t.Cleanup(func() { transportBuildTester, transportBuildSwitcher = oldTester, oldSwitcher })
	transportBuildTester = func(store.Paths) (transportTester, error) {
		t.Fatal("gateway transport test reached runtime builder")
		return nil, nil
	}
	transportBuildSwitcher = func(store.Paths) (TransportSwitcher, error) {
		t.Fatal("gateway transport switch reached runtime builder")
		return nil, nil
	}
	for _, args := range [][]string{{"--json", "transport", "test", "standard"}, {"--json", "transport", "switch", "standard", "--dry-run"}} {
		var stdout, stderr bytes.Buffer
		if code := Execute(args, &stdout, &stderr); code != ExitValidation {
			t.Fatalf("gateway args=%v exit=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestSystemTransportPlanningIsReadOnlyAndExecutionFailsExplicitly(t *testing.T) {
	t.Parallel()
	paths, stateStore := storeTransportCommandState(t)
	switcher, err := buildSystemTransportSwitcher(paths)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := switcher.Plan(model.TransportStandard)
	if err != nil || !plan.Changed || plan.Current != model.TransportRestricted || plan.Target != model.TransportStandard {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	before, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := switcher.Apply(context.Background(), plan); !errors.Is(err, ErrSystemTransportRuntimeUnavailable) {
		t.Fatalf("apply error=%v", err)
	}
	after, err := stateStore.Load()
	if err != nil || before.Generation != after.Generation || before.Nodes[0].ActiveTransport != after.Nodes[0].ActiveTransport {
		t.Fatalf("state changed: before=%d/%s after=%d/%s err=%v", before.Generation, before.Nodes[0].ActiveTransport, after.Generation, after.Nodes[0].ActiveTransport, err)
	}
}

func TestSystemTransportTestFailsExplicitlyAndPreservesState(t *testing.T) {
	t.Parallel()
	paths, stateStore := storeTransportCommandState(t)
	tester, err := buildSystemTransportTester(paths)
	if err != nil {
		t.Fatal(err)
	}
	before, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes, err := model.EncodeState(before)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tester.Test(context.Background(), model.TransportStandard); !errors.Is(err, ErrSystemTransportRuntimeUnavailable) {
		t.Fatalf("test error=%v", err)
	}
	after, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	afterBytes, err := model.EncodeState(after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeBytes, afterBytes) {
		t.Fatalf("transport test changed authoritative state\nbefore=%s\nafter=%s", beforeBytes, afterBytes)
	}
}

func TestSystemTransportDeferredWriterMirrorsConfirmedGatewayIntentWithoutChangingSelection(t *testing.T) {
	paths, stateStore := storeTransportCommandState(t)
	before, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	oldBuilder := transportBuildDeferredGateway
	t.Cleanup(func() { transportBuildDeferredGateway = oldBuilder })
	requestID := "73000000-0000-4000-8000-000000000011"
	operationID, err := transport.SwitchOperationID(requestID)
	if err != nil {
		t.Fatal(err)
	}
	remote := &transportDeferredGatewayFixture{receipt: transport.DeferredSwitchReceipt{
		OperationID: operationID, RequestID: requestID, NodeID: before.Nodes[0].ID,
		Current: model.TransportRestricted, Target: model.TransportStandard,
		GatewayGeneration: 11, DesiredGatewayGeneration: 12,
		ExpectedNodeGeneration: before.Generation, DesiredNodeGeneration: before.Generation + 2,
	}}
	transportBuildDeferredGateway = func(received store.Paths) (transportDeferredGateway, error) {
		if received != paths {
			t.Fatalf("remote paths=%+v, want %+v", received, paths)
		}
		return remote, nil
	}
	writer, err := buildSystemTransportDeferredWriter(paths)
	if err != nil {
		t.Fatal(err)
	}
	public := MutationPlan{Impact: ImpactAvailability, Result: output.NewResult(
		"transport.switch", output.StatusOK, output.CategorySuccess,
		output.SafeObject{
			"changed": true, "current": "restricted", "candidate": "standard", "generation": before.Generation + 1,
		},
	)}
	receipt, err := writer.RegisterPending(context.Background(), public)
	if err != nil {
		t.Fatal(err)
	}
	if remote.calls != 1 || remote.current != model.TransportRestricted || remote.target != model.TransportStandard ||
		remote.expectedNodeGeneration != before.Generation || receipt.OperationID != remote.receipt.OperationID ||
		receipt.AuthoritativeGeneration != remote.receipt.GatewayGeneration || receipt.Result.Status != output.StatusPending {
		t.Fatalf("remote=%+v receipt=%+v", remote, receipt)
	}
	after, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != before.Generation+1 || after.Nodes[0].ActiveTransport != before.Nodes[0].ActiveTransport ||
		after.Nodes[0].Gateway.PendingRequestID != requestID || after.Nodes[0].Gateway.LastKnownGatewayGeneration != 11 ||
		len(after.Operations) != len(before.Operations)+1 || after.Operations[len(after.Operations)-1].ID != operationID {
		t.Fatalf("mirrored local pending state=%+v", after)
	}
	retry := public
	retry.Result.Data["generation"] = after.Generation + 1
	second, err := writer.RegisterPending(context.Background(), retry)
	if err != nil || second.OperationID != operationID || remote.calls != 1 {
		t.Fatalf("retained retry=%+v err=%v remote calls=%d", second, err, remote.calls)
	}
}

func TestTransportSwitchCommandUsesSystemGatewayDeferredRegistration(t *testing.T) {
	paths, stateStore := storeTransportCommandState(t)
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	oldPaths, oldRole := transportSystemPaths, transportLoadRole
	oldSwitcher, oldAuthority, oldRemote := transportBuildSwitcher, transportBuildAuthority, transportBuildDeferredGateway
	t.Cleanup(func() {
		transportSystemPaths, transportLoadRole = oldPaths, oldRole
		transportBuildSwitcher, transportBuildAuthority, transportBuildDeferredGateway = oldSwitcher, oldAuthority, oldRemote
	})
	transportSystemPaths = func() store.Paths { return paths }
	transportLoadRole = func(store.Paths) (HostRole, error) { return RoleNode, nil }
	transportBuildSwitcher = buildSystemTransportSwitcher
	transportBuildAuthority = buildSystemTransportDeferredWriter
	requestID := "73000000-0000-4000-8000-000000000012"
	operationID, err := transport.SwitchOperationID(requestID)
	if err != nil {
		t.Fatal(err)
	}
	remote := &transportDeferredGatewayFixture{receipt: transport.DeferredSwitchReceipt{
		OperationID: operationID, RequestID: requestID, NodeID: state.Nodes[0].ID,
		Current: model.TransportRestricted, Target: model.TransportStandard,
		GatewayGeneration: 11, DesiredGatewayGeneration: 12,
		ExpectedNodeGeneration: state.Generation, DesiredNodeGeneration: state.Generation + 2,
	}}
	transportBuildDeferredGateway = func(store.Paths) (transportDeferredGateway, error) { return remote, nil }
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"--json", "transport", "switch", "standard", "--defer", "--yes"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if remote.calls != 1 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"status":"pending"`) ||
		!strings.Contains(stdout.String(), `"candidate":"standard"`) || !strings.Contains(stdout.String(), remote.receipt.OperationID) {
		t.Fatalf("remote=%+v stdout=%s stderr=%s", remote, stdout.String(), stderr.String())
	}
}

type transportCommandTester struct {
	execution transport.TestExecution
	err       error
	target    model.TransportKind
	calls     int
}

type transportDeferredGatewayFixture struct {
	receipt                transport.DeferredSwitchReceipt
	err                    error
	calls                  int
	current                model.TransportKind
	target                 model.TransportKind
	expectedNodeGeneration uint64
}

func (gateway *transportDeferredGatewayFixture) RegisterDeferred(
	_ context.Context,
	current model.TransportKind,
	target model.TransportKind,
	expectedNodeGeneration uint64,
) (transport.DeferredSwitchReceipt, error) {
	gateway.calls++
	gateway.current, gateway.target, gateway.expectedNodeGeneration = current, target, expectedNodeGeneration
	return gateway.receipt, gateway.err
}

func (tester *transportCommandTester) Test(_ context.Context, target model.TransportKind) (transport.TestExecution, error) {
	tester.calls++
	tester.target = target
	return tester.execution, tester.err
}

func transportCommandExecution(passed bool) transport.TestExecution {
	state := transport.ProbePassed
	if !passed {
		state = transport.ProbeFailed
	}
	probe := transport.ProbeResult{State: state, Code: "probe_ready"}
	return transport.TestExecution{
		Target: transport.CandidateDescriptor{
			OwnerKind: model.TargetNode, OwnerID: "22222222-2222-4222-8222-222222222222",
			Kind: model.TransportRestricted, CredentialGeneration: 1, ConfigHash: strings.Repeat("a", 64),
		},
		Selection:       transport.Selection{Active: model.TransportStandard, Standby: model.TransportRestricted},
		StateGeneration: 4, CredentialGeneration: 1, Cleaned: true,
		Checks: transport.TestResult{Control: probe, ReverseTunnel: probe, SelectedTCP: probe, SelectedUDP: probe},
	}
}

func stubTransportCommand(t *testing.T, role HostRole) (store.Paths, func()) {
	t.Helper()
	oldPaths, oldRole := transportSystemPaths, transportLoadRole
	oldTester, oldSwitcher, oldAuthority, oldTTY := transportBuildTester, transportBuildSwitcher, transportBuildAuthority, transportOpenTTY
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	transportSystemPaths = func() store.Paths { return paths }
	transportLoadRole = func(received store.Paths) (HostRole, error) {
		if received != paths {
			t.Fatalf("role paths=%+v, want %+v", received, paths)
		}
		return role, nil
	}
	return paths, func() {
		transportSystemPaths, transportLoadRole = oldPaths, oldRole
		transportBuildTester, transportBuildSwitcher, transportBuildAuthority, transportOpenTTY = oldTester, oldSwitcher, oldAuthority, oldTTY
	}
}

func storeTransportCommandState(t *testing.T) (store.Paths, *store.StateStore) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := cliDoctorJoinedNodeState(t)
	state.Generation = 1
	if err := stateStore.Save(0, state); err != nil {
		t.Fatal(err)
	}
	return paths, stateStore
}

var _ transportTester = (*transportCommandTester)(nil)
var _ transportDeferredGateway = (*transportDeferredGatewayFixture)(nil)
