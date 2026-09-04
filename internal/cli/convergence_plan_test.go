package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

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

func (reader *recordingConvergencePlanReader) Plan(context.Context) (operations.ConvergencePlan, error) {
	reader.calls++
	return reader.plan, nil
}
