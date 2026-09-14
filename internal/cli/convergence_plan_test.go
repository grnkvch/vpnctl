package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestConvergencePlanOutputMatchesPlanV1AndKeepsDriftSeparate(t *testing.T) {
	t.Parallel()

	before := operations.ManagedFingerprint([]byte("applied"))
	after := operations.ManagedFingerprint([]byte("desired"))
	actual := operations.ManagedFingerprint([]byte("manual-change-plaintext-canary"))
	key := operations.ManagedResourceKey{Component: "ingress", Kind: operations.ManagedResourceFile, ID: "/etc/vpnctl/nginx.conf"}
	plan := operations.ConvergencePlan{
		DesiredGeneration: 5, AppliedGeneration: 4, Impact: operations.ConvergenceImpactAvailability,
		Changes: []operations.DesiredChange{{
			OperationID: "operation-1", OperationType: "apply", TargetKind: "expose", TargetID: "telegram",
			OperationExpectedGeneration: 4, OperationDesiredGeneration: 5,
			Resource: key, Kind: operations.DesiredUpdate, Impact: operations.ConvergenceImpactAvailability,
			FromSHA256: before, ToSHA256: after,
		}},
		Drift: []operations.OwnedDrift{{
			Resource: key, Kind: operations.OwnedDriftModified, Impact: operations.ConvergenceImpactAvailability,
			ExpectedSHA256: before, ActualSHA256: actual,
		}},
	}
	result, err := ConvergencePlanOutput(plan)
	if err != nil {
		t.Fatal(err)
	}
	if result.Command != "plan" || result.Status != output.StatusPending || result.ExitCategory != output.CategorySuccess {
		t.Fatalf("result envelope = %+v", result)
	}
	if len(result.RequiresAction) != 1 || result.RequiresAction[0].Code != "review_drift" || result.RequiresAction[0].Command != "vpnctl repair" {
		t.Fatalf("requires_action = %+v", result.RequiresAction)
	}
	changes, ok := result.Data["changes"].([]output.SafeObject)
	if !ok || len(changes) != 1 || changes[0]["to_sha256"] != after || changes[0]["change"] != "update" {
		t.Fatalf("changes = %#v", result.Data["changes"])
	}
	drift, ok := result.Data["drift"].([]output.SafeObject)
	if !ok || len(drift) != 1 || drift[0]["actual_sha256"] != actual || drift[0]["drift"] != "modified" {
		t.Fatalf("drift = %#v", result.Data["drift"])
	}
	var rendered bytes.Buffer
	if err := output.RenderJSON(&rendered, result); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rendered.Bytes(), []byte("manual-change-plaintext-canary")) {
		t.Fatal("plan JSON contains observed plaintext")
	}
	var document map[string]any
	if err := json.Unmarshal(rendered.Bytes(), &document); err != nil {
		t.Fatalf("plan output is not one JSON document: %v", err)
	}
}

func TestConvergencePlanOutputPreservesEmptyArraysAndNoImpact(t *testing.T) {
	t.Parallel()

	result, err := ConvergencePlanOutput(operations.ConvergencePlan{
		DesiredGeneration: 2, AppliedGeneration: 2, Impact: operations.ConvergenceImpactNone,
		Changes: []operations.DesiredChange{}, Drift: []operations.OwnedDrift{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != output.StatusOK || result.Data["impact"] != "none" || len(result.RequiresAction) != 0 {
		t.Fatalf("no-op result = %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"changes":[]`)) || !bytes.Contains(encoded, []byte(`"drift":[]`)) {
		t.Fatalf("empty plan arrays are not preserved: %s", encoded)
	}
}

func TestGatewayReadinessConvergencePlanTurnsMissingEdgeIntoRepairableDrift(t *testing.T) {
	t.Parallel()

	base := &recordingConvergencePlanReader{plan: operations.ConvergencePlan{
		DesiredGeneration: 4, AppliedGeneration: 4, Impact: operations.ConvergenceImpactNone,
		Changes: []operations.DesiredChange{}, Drift: []operations.OwnedDrift{},
	}}
	state := model.State{Generation: 4, Host: model.Host{Role: model.RoleGateway}}
	readiness := &recordingGatewayPlanReadiness{report: lifecycle.GatewayBootstrapReadinessReport{
		SchemaVersion: lifecycle.GatewayBootstrapReadinessSchemaVersion, Generation: 4, Ready: false,
		CandidateSHA256: strings.Repeat("a", 64), Checks: []lifecycle.GatewayBootstrapReadinessCheck{
			{Kind: "package", ID: "nginx", Condition: lifecycle.GatewayReadinessMissing, Code: "package_missing", Expected: "1.24..<1.25"},
			{Kind: "listener", ID: "public_https", Condition: lifecycle.GatewayReadinessUnavailable, Code: "public_https_observation_unavailable", Expected: "0.0.0.0:443"},
		},
	}}
	reader := &gatewayReadinessConvergencePlanReader{
		base: base, state: staticGatewayPlanState{state: state}, readiness: readiness,
	}
	plan, err := reader.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if base.calls != 1 || readiness.calls != 1 || plan.Impact != operations.ConvergenceImpactAvailability || len(plan.Drift) != 2 {
		t.Fatalf("gateway readiness plan = %+v; calls=%d/%d", plan, base.calls, readiness.calls)
	}
	if plan.Drift[0].Resource.Component != "ingress" || plan.Drift[0].Kind != operations.OwnedDriftModified ||
		plan.Drift[1].Resource.Component != "package" || plan.Drift[1].Kind != operations.OwnedDriftMissing {
		t.Fatalf("gateway readiness drift = %+v", plan.Drift)
	}
	result, err := ConvergencePlanOutput(plan)
	if err != nil || result.Status != output.StatusPending || len(result.RequiresAction) != 1 || result.RequiresAction[0].Command != "vpnctl repair" {
		t.Fatalf("gateway readiness output = %+v, %v", result, err)
	}
}

func TestGatewayReadinessConvergencePlanPreservesHealthyEmptyDrift(t *testing.T) {
	t.Parallel()
	base := &recordingConvergencePlanReader{plan: operations.ConvergencePlan{
		DesiredGeneration: 4, AppliedGeneration: 4, Impact: operations.ConvergenceImpactNone,
		Changes: []operations.DesiredChange{}, Drift: []operations.OwnedDrift{},
	}}
	reader := &gatewayReadinessConvergencePlanReader{
		base: base, state: staticGatewayPlanState{state: model.State{Generation: 4, Host: model.Host{Role: model.RoleGateway}}},
		readiness: &recordingGatewayPlanReadiness{report: lifecycle.GatewayBootstrapReadinessReport{
			SchemaVersion: lifecycle.GatewayBootstrapReadinessSchemaVersion, Generation: 4, Ready: true,
			CandidateSHA256: strings.Repeat("a", 64), Checks: []lifecycle.GatewayBootstrapReadinessCheck{},
		}},
	}
	plan, err := reader.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Changes == nil || plan.Drift == nil || len(plan.Changes) != 0 || len(plan.Drift) != 0 || plan.Impact != operations.ConvergenceImpactNone {
		t.Fatalf("healthy Gateway plan = %+v", plan)
	}
}

func TestConvergencePlanOutputRejectsInvalidAggregateImpact(t *testing.T) {
	t.Parallel()

	_, err := ConvergencePlanOutput(operations.ConvergencePlan{
		DesiredGeneration: 2, AppliedGeneration: 2, Impact: operations.ConvergenceImpactDestructive,
		Changes: []operations.DesiredChange{}, Drift: []operations.OwnedDrift{},
	})
	if err == nil {
		t.Fatal("ConvergencePlanOutput accepted an invalid aggregate impact")
	}
}

func TestRunConvergencePlanIsRoleGatedBeforePlanning(t *testing.T) {
	t.Parallel()

	reader := &recordingConvergencePlanReader{plan: operations.ConvergencePlan{
		DesiredGeneration: 2, AppliedGeneration: 2, Impact: operations.ConvergenceImpactNone,
		Changes: []operations.DesiredChange{}, Drift: []operations.OwnedDrift{},
	}}
	for _, role := range []HostRole{RoleGateway, RoleNode} {
		result, err := RunConvergencePlan(context.Background(), role, reader)
		if err != nil || result.Command != "plan" {
			t.Fatalf("RunConvergencePlan(%s) = %+v, %v", role, result, err)
		}
	}
	if reader.calls != 2 {
		t.Fatalf("planner calls = %d, want 2", reader.calls)
	}
	if _, err := RunConvergencePlan(context.Background(), RoleUninitialized, reader); !errors.Is(err, ErrUnsupportedRole) {
		t.Fatalf("uninitialized RunConvergencePlan() error = %v", err)
	}
	if reader.calls != 2 {
		t.Fatal("unsupported role reached planner")
	}
}

type recordingConvergencePlanReader struct {
	plan  operations.ConvergencePlan
	calls int
}

type staticGatewayPlanState struct {
	state model.State
	err   error
}

func (state staticGatewayPlanState) Load() (model.State, error) { return state.state, state.err }

type recordingGatewayPlanReadiness struct {
	report lifecycle.GatewayBootstrapReadinessReport
	err    error
	calls  int
}

func (readiness *recordingGatewayPlanReadiness) Inspect(context.Context, model.State) (lifecycle.GatewayBootstrapReadinessReport, error) {
	readiness.calls++
	return readiness.report, readiness.err
}

func (reader *recordingConvergencePlanReader) Plan(context.Context) (operations.ConvergencePlan, error) {
	reader.calls++
	return reader.plan, nil
}
