package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type clientMutationStub struct {
	addPlan         routing.ClientAddPlan
	addResult       routing.ClientAddResult
	lifecyclePlan   routing.ClientLifecyclePlan
	lifecycleResult routing.ClientLifecycleResult
	exportPlan      routing.ClientExportPlan
	exportResult    routing.ClientExportResult
	planCalls       []string
	commitCalls     []string
	exportRequest   routing.ClientExportRequest
}

func (stub *clientMutationStub) PlanAdd(request routing.ClientAddRequest) (routing.ClientAddPlan, error) {
	stub.planCalls = append(stub.planCalls, "add:"+request.Name+":"+strings.Join(request.PresetNames, ","))
	return stub.addPlan, nil
}
func (stub *clientMutationStub) CommitAdd(context.Context, routing.ClientAddPlan) (routing.ClientAddResult, error) {
	stub.commitCalls = append(stub.commitCalls, "add")
	return stub.addResult, nil
}
func (stub *clientMutationStub) PlanRotate(string) (routing.ClientLifecyclePlan, error) {
	stub.planCalls = append(stub.planCalls, "rotate")
	return stub.lifecyclePlan, nil
}
func (stub *clientMutationStub) CommitRotate(context.Context, routing.ClientLifecyclePlan) (routing.ClientLifecycleResult, error) {
	stub.commitCalls = append(stub.commitCalls, "rotate")
	return stub.lifecycleResult, nil
}
func (stub *clientMutationStub) PlanRevoke(string) (routing.ClientLifecyclePlan, error) {
	stub.planCalls = append(stub.planCalls, "revoke")
	return stub.lifecyclePlan, nil
}
func (stub *clientMutationStub) CommitRevoke(routing.ClientLifecyclePlan) (routing.ClientLifecycleResult, error) {
	stub.commitCalls = append(stub.commitCalls, "revoke")
	return stub.lifecycleResult, nil
}
func (stub *clientMutationStub) PlanDelete(string) (routing.ClientLifecyclePlan, error) {
	stub.planCalls = append(stub.planCalls, "delete")
	return stub.lifecyclePlan, nil
}
func (stub *clientMutationStub) CommitDelete(routing.ClientLifecyclePlan) (routing.ClientLifecycleResult, error) {
	stub.commitCalls = append(stub.commitCalls, "delete")
	return stub.lifecycleResult, nil
}
func (stub *clientMutationStub) PlanExport(request routing.ClientExportRequest) (routing.ClientExportPlan, error) {
	stub.planCalls = append(stub.planCalls, "export")
	stub.exportRequest = request
	return stub.exportPlan, nil
}
func (stub *clientMutationStub) CommitExport(routing.ClientExportPlan) (routing.ClientExportResult, error) {
	stub.commitCalls = append(stub.commitCalls, "export")
	return stub.exportResult, nil
}

func TestExecuteClientAddDryRunAndLifecycleImmediateUseMutationBoundary(t *testing.T) {
	clientID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	stub := &clientMutationStub{
		addPlan:   routing.ClientAddPlan{ClientID: clientID, NextStateGeneration: 5},
		addResult: routing.ClientAddResult{Changed: true, StateGeneration: 5, Client: routing.ClientView{ID: clientID}},
		lifecyclePlan: routing.ClientLifecyclePlan{
			Command: routing.ClientRevoke, ClientID: clientID, Changed: true, NextStateGeneration: 6,
		},
		lifecycleResult: routing.ClientLifecycleResult{
			Command: routing.ClientRevoke, ClientID: clientID, Changed: true, StateGeneration: 6,
		},
	}
	restore := stubClientMutationCommand(t, stub, RoleGateway)
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"client", "add", "iphone", "telegram", "openai", "--dry-run", "--json"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("client add dry-run code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if len(stub.commitCalls) != 0 || !strings.Contains(stdout.String(), `"command":"client.add"`) || !strings.Contains(stdout.String(), `"generation":5`) {
		t.Fatalf("client add dry-run mutated or emitted wrong output: calls=%v output=%q", stub.commitCalls, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Execute([]string{"--json", "client", "revoke", "iphone", "--yes"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("client revoke code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if got := strings.Join(stub.commitCalls, ","); got != "revoke" || !strings.Contains(stdout.String(), `"command":"client.revoke"`) {
		t.Fatalf("client revoke calls/output = %q / %q", got, stdout.String())
	}
}

func TestExecuteClientExportSupportsSafeFileOptionsWithoutProfileOutput(t *testing.T) {
	clientID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	stub := &clientMutationStub{
		exportPlan: routing.ClientExportPlan{ClientID: clientID, OutputPath: "/srv/iphone.yaml", FileMode: "0600", SourceStateGeneration: 7},
		exportResult: routing.ClientExportResult{
			ClientID: clientID, OutputPath: "/srv/iphone.yaml", FileMode: "0600", SourceStateGeneration: 7,
			SCPHint: "scp root@203.0.113.10:/srv/iphone.yaml ./iphone.yaml",
		},
	}
	restore := stubClientMutationCommand(t, stub, RoleGateway)
	defer restore()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"client", "export", "iphone", "clash", "--output", "/srv/iphone.yaml", "--force", "--json"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("client export code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stub.exportRequest.OutputPath != "/srv/iphone.yaml" || !stub.exportRequest.Force || stub.exportRequest.Format != routing.ClientExportClash {
		t.Fatalf("export request = %#v", stub.exportRequest)
	}
	if !strings.Contains(stdout.String(), `"output_path":"/srv/iphone.yaml"`) || strings.Contains(stdout.String(), "proxies:") {
		t.Fatalf("unsafe or incomplete export output: %q", stdout.String())
	}
}

func TestExecuteClientMutationRejectsNodeBeforeServiceConstruction(t *testing.T) {
	oldPaths, oldRole, oldBuilder := clientMutationSystemPaths, clientMutationLoadRole, clientMutationBuilder
	t.Cleanup(func() {
		clientMutationSystemPaths, clientMutationLoadRole, clientMutationBuilder = oldPaths, oldRole, oldBuilder
	})
	paths, _ := store.NewPaths(t.TempDir())
	clientMutationSystemPaths = func() store.Paths { return paths }
	clientMutationLoadRole = func(store.Paths) (HostRole, error) { return RoleNode, nil }
	clientMutationBuilder = func(store.Paths) (clientMutationAPI, error) {
		t.Fatal("client mutation service built before role rejection")
		return nil, nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"client", "add", "iphone", "--dry-run", "--json"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("node client add code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"code":"unsupported_role"`) {
		t.Fatalf("missing role rejection: %q", stdout.String())
	}
}

func stubClientMutationCommand(t *testing.T, stub clientMutationAPI, role HostRole) func() {
	t.Helper()
	oldPaths, oldRole, oldBuilder, oldTTY := clientMutationSystemPaths, clientMutationLoadRole, clientMutationBuilder, clientMutationOpenTTY
	paths, _ := store.NewPaths(t.TempDir())
	clientMutationSystemPaths = func() store.Paths { return paths }
	clientMutationLoadRole = func(store.Paths) (HostRole, error) { return role, nil }
	clientMutationBuilder = func(store.Paths) (clientMutationAPI, error) { return stub, nil }
	clientMutationOpenTTY = func() (PromptIO, io.Closer, error) { t.Fatal("unexpected TTY open"); return nil, nil, nil }
	return func() {
		clientMutationSystemPaths, clientMutationLoadRole, clientMutationBuilder, clientMutationOpenTTY = oldPaths, oldRole, oldBuilder, oldTTY
	}
}
