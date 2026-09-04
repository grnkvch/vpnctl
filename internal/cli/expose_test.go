package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
)

const (
	cliExposeID          = "63000000-0000-4000-8000-000000000001"
	cliExposeNodeID      = "63000000-0000-4000-8000-000000000002"
	cliExposeNodeHostID  = "63000000-0000-4000-8000-000000000003"
	cliExposeGatewayID   = "63000000-0000-4000-8000-000000000004"
	cliExposeCertID      = "63000000-0000-4000-8000-000000000005"
	cliExposeOperationID = "63000000-0000-4000-8000-000000000006"
	cliExposePathCanary  = "/hooks/cli-sensitive-path-canary"
)

func TestExposeMutationWorkflowUsesCommonImmediateDryRunAndAuthoritativeDeferModes(t *testing.T) {
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
			plan := cliExposeDomainPlan(t)
			saga := &recordingCLIExposeSaga{plan: plan}
			workflow, err := NewExposeCreateMutationWorkflow(saga, ingress.ExposeCreateRequest{
				Upstream: "3000", Path: cliExposePathCanary,
			})
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := V2CommandRegistry().RunMutation(context.Background(), MutationRequest{
				CommandID: "expose", Role: RoleNode, DryRun: test.dryRun, Defer: test.deferMode,
			}, nil, workflow, workflow)
			if err != nil {
				t.Fatal(err)
			}
			if outcome.Mode != test.wantMode || saga.planCalls != 1 || saga.applyCalls != test.wantApply || saga.deferCalls != test.wantDefer ||
				outcome.Result.Data["changed"] != test.wantChanged {
				t.Fatalf("outcome/calls = %+v plan:%d apply:%d defer:%d", outcome, saga.planCalls, saga.applyCalls, saga.deferCalls)
			}
			encoded, err := json.Marshal(outcome.Result)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), cliExposePathCanary) || strings.Contains(string(encoded), "public_url") {
				t.Fatalf("mutation JSON leaked sensitive path: %s", encoded)
			}
			if test.wantMode == MutationDeferred && (outcome.OperationID != cliExposeOperationID || outcome.AuthoritativeGeneration != 12) {
				t.Fatalf("deferred receipt = %+v", outcome)
			}
		})
	}
}

type recordingCLIExposeSaga struct {
	plan       operations.ExposeCreatePlan
	planCalls  int
	applyCalls int
	deferCalls int
}

func (saga *recordingCLIExposeSaga) Plan(context.Context, ingress.ExposeCreateRequest) (operations.ExposeCreatePlan, error) {
	saga.planCalls++
	return saga.plan, nil
}

func (saga *recordingCLIExposeSaga) Apply(context.Context, operations.ExposeCreatePlan) (operations.ExposeCreateResult, error) {
	saga.applyCalls++
	return operations.NewExposeCreateResult(saga.plan, model.ExposeReady, 9, 13)
}

func (saga *recordingCLIExposeSaga) Defer(context.Context, operations.ExposeCreatePlan) (operations.ExposeCreateDeferredResult, error) {
	saga.deferCalls++
	return operations.ExposeCreateDeferredResult{
		ExposeID: cliExposeID, OperationID: cliExposeOperationID, GatewayStateGeneration: 12,
	}, nil
}

func cliExposeDomainPlan(t *testing.T) operations.ExposeCreatePlan {
	t.Helper()
	created := time.Date(2026, time.September, 4, 13, 0, 0, 0, time.UTC)
	normalizer := ingress.NewExposeNormalizer(ingress.ExposeNormalizerRuntime{
		NewUUID: func() (string, error) { return cliExposeID, nil }, Now: func() time.Time { return created },
	})
	normalized, err := normalizer.Normalize(ingress.ExposeNamespace{
		NodeID: cliExposeNodeID, StateGeneration: 11, Existing: []model.Expose{},
	}, ingress.ExposeCreateRequest{Upstream: "3000", Path: cliExposePathCanary})
	if err != nil {
		t.Fatal(err)
	}
	certificate := model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: cliExposeCertID, Kind: model.CertificatePublicIngress,
		OwnerKind: "host", OwnerID: cliExposeGatewayID, Fingerprint: "sha256:" + strings.Repeat("a", 64),
		SerialHex: "1", Subject: "CN=203.0.113.10", SANs: []string{"IP:203.0.113.10"},
		NotBefore: created, NotAfter: created.AddDate(5, 0, 0), WarningDays: 180, Generation: 1,
		CertificateRef: ingress.PublicCertificateRef, PrivateKeyRef: ingress.PublicCertificatePrivateKeyRef,
	}
	plan := operations.ExposeCreatePlan{
		Normalized: normalized,
		Expose: model.Expose{
			SchemaVersion: model.ResourceSchemaVersion, ID: cliExposeID, NodeID: cliExposeNodeID,
			Upstream: normalized.Upstream, RouteMode: normalized.RouteMode, Path: normalized.Path,
			BodyLimitBytes: normalized.Limits.BodyBytes, UpstreamTimeoutSeconds: normalized.Limits.UpstreamTimeoutSeconds,
			ConcurrentRequests: normalized.Limits.ConcurrentRequests, TunnelPort: 20000,
			State: model.ExposePending, Generation: 1, CreatedAt: created,
		},
		NodeHostID: cliExposeNodeHostID, ExpectedLocalStateGeneration: 7, ExpectedGatewayStateGeneration: 11,
		GatewayID: cliExposeGatewayID, PublicIPv4: "203.0.113.10", Certificate: certificate,
		CertificateExportPath: "/var/lib/vpnctl/exports/gateway.crt",
	}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	return plan
}
