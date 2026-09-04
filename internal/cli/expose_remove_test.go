package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestExposeRemoveWorkflowUsesConfirmedImmediateDryRunAndAuthoritativeDeferModes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		dryRun      bool
		deferMode   bool
		wantMode    MutationMode
		wantApply   int
		wantDefer   int
		wantChanged bool
	}{
		{name: "immediate", wantMode: MutationImmediate, wantApply: 1, wantChanged: true},
		{name: "dry run", dryRun: true, wantMode: MutationDryRun},
		{name: "deferred", deferMode: true, wantMode: MutationDeferred, wantDefer: 1, wantChanged: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := cliExposeRemovalPlan(t)
			saga := &recordingCLIExposeRemoveSaga{plan: plan}
			workflow, err := NewExposeRemoveMutationWorkflow(saga, "telegram")
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
				CommandID: "expose.remove", Role: RoleNode, DryRun: test.dryRun, Defer: test.deferMode, Yes: true,
			}, nil, workflow, workflow)
			if err != nil {
				t.Fatal(err)
			}
			if outcome.Mode != test.wantMode || outcome.Plan.Impact != ImpactAvailability || saga.planCalls != 1 ||
				saga.applyCalls != test.wantApply || saga.deferCalls != test.wantDefer ||
				outcome.Result.Data["changed"] != test.wantChanged || len(outcome.Result.RequiresAction) != 1 ||
				outcome.Result.RequiresAction[0].Code != "remove_external_webhook" {
				t.Fatalf("outcome/calls = %+v plan:%d apply:%d defer:%d", outcome, saga.planCalls, saga.applyCalls, saga.deferCalls)
			}
			encoded, err := json.Marshal(outcome.Result)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), cliExposePathCanary) || strings.Contains(string(encoded), "public_url") {
				t.Fatalf("remove JSON leaked sensitive path: %s", encoded)
			}
			if test.wantMode == MutationDeferred && (outcome.OperationID != cliExposeOperationID || outcome.AuthoritativeGeneration != 12) {
				t.Fatalf("deferred receipt = %+v", outcome)
			}
		})
	}
}

func TestExposeCatalogOutputsReportCertificateAvailabilityWithoutPath(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	view := operations.ExposeView{
		ID: cliExposeID, Name: "telegram", Upstream: "127.0.0.1:3000", RouteMode: model.RouteExact,
		BodyLimitBytes: 1 << 20, UpstreamTimeoutSeconds: 15, ConcurrentRequests: 40,
		State: model.ExposeReady, Generation: 2, CreatedAt: created,
		Certificate: operations.ExposeCertificateView{
			ID: cliExposeCertID, Fingerprint: "sha256:" + strings.Repeat("a", 64),
			NotAfter: created.AddDate(5, 0, 0), Generation: 1, Available: true,
			OutputPath: "/var/lib/vpnctl/exports/gateway.crt", PublicIPv4: "203.0.113.10",
		},
	}
	list, err := ExposeListOutput(operations.ExposeList{
		LocalStateGeneration: 9, GatewayStateGeneration: 13, GatewayReachable: true, Items: []operations.ExposeView{view},
	})
	if err != nil {
		t.Fatal(err)
	}
	if list.Status != output.StatusOK || list.Data["gateway_reachable"] != true {
		t.Fatalf("list output = %+v", list)
	}
	encoded, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"path", "tunnel_port", "public_url", cliExposePathCanary} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("list output contains %q: %s", forbidden, encoded)
		}
	}
	offline, err := ExposeShowOutput(operations.ExposeShow{
		LocalStateGeneration: 9, GatewayReachable: false, Resource: view,
	})
	if err != nil || offline.Status != output.StatusDegraded || offline.ExitCategory != output.CategoryUnavailable || len(offline.Warnings) != 1 {
		t.Fatalf("offline show output = %+v, %v", offline, err)
	}
}

type recordingCLIExposeRemoveSaga struct {
	plan       operations.ExposeRemovePlan
	planCalls  int
	applyCalls int
	deferCalls int
}

func (saga *recordingCLIExposeRemoveSaga) Plan(context.Context, string) (operations.ExposeRemovePlan, error) {
	saga.planCalls++
	return saga.plan, nil
}

func (saga *recordingCLIExposeRemoveSaga) Apply(context.Context, operations.ExposeRemovePlan) (operations.ExposeRemoveResult, error) {
	saga.applyCalls++
	return operations.ExposeRemoveResult{
		ExposeID: cliExposeID, LocalStateGeneration: 9, GatewayStateGeneration: 13, DrainSeconds: 10,
	}, nil
}

func (saga *recordingCLIExposeRemoveSaga) Defer(context.Context, operations.ExposeRemovePlan) (operations.ExposeRemoveDeferredResult, error) {
	saga.deferCalls++
	return operations.ExposeRemoveDeferredResult{
		ExposeID: cliExposeID, OperationID: cliExposeOperationID, GatewayStateGeneration: 12,
	}, nil
}

func cliExposeRemovalPlan(t *testing.T) operations.ExposeRemovePlan {
	t.Helper()
	created := cliExposeDomainPlan(t)
	target := created.Expose
	target.State = model.ExposeReady
	target.Generation = 2
	plan := operations.ExposeRemovePlan{
		Expose: target, NodeHostID: cliExposeNodeHostID, ExpectedLocalStateGeneration: 7,
		ExpectedGatewayStateGeneration: 11, GatewayID: cliExposeGatewayID, PublicIPv4: "203.0.113.10",
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	return plan
}
