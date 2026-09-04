package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestStatusJSONIsAlwaysFullWhileHumanAllOnlyExpandsTables(t *testing.T) {
	t.Parallel()

	report := cliStatusReport()
	concise, err := statusResult(report, false)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := statusResult(report, true)
	if err != nil {
		t.Fatal(err)
	}
	conciseJSON, err := json.Marshal(concise)
	if err != nil {
		t.Fatal(err)
	}
	expandedJSON, err := json.Marshal(expanded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(conciseJSON, expandedJSON) {
		t.Fatalf("--all changed JSON\nconcise: %s\nexpanded: %s", conciseJSON, expandedJSON)
	}
	for _, key := range []string{
		"binary_version", "manifest_binary_version", "control_protocols", "components", "counts", "resources", "runtime",
		"pending", "drift", "active_invites", "log_opt_ins", "certificates", "backups", "problems",
	} {
		if _, exists := concise.Data[key]; !exists {
			t.Fatalf("full status JSON omitted %s", key)
		}
	}

	var conciseHuman bytes.Buffer
	if err := output.RenderHuman(&conciseHuman, concise); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conciseHuman.String(), "problems:") || !strings.Contains(conciseHuman.String(), "owned_modified") {
		t.Fatalf("concise human status omitted problem: %s", conciseHuman.String())
	}
	for _, healthyDetail := range []string{"healthy-node-canary", "v1.19.30", "runtime-ready-canary"} {
		if strings.Contains(conciseHuman.String(), healthyDetail) {
			t.Fatalf("concise human status expanded healthy detail %q: %s", healthyDetail, conciseHuman.String())
		}
	}

	var expandedHuman bytes.Buffer
	if err := output.RenderHuman(&expandedHuman, expanded); err != nil {
		t.Fatal(err)
	}
	for _, detail := range []string{"components:", "resources:", "runtime:", "healthy-node-canary", "v1.19.30", "runtime-ready-canary"} {
		if !strings.Contains(expandedHuman.String(), detail) {
			t.Fatalf("expanded human status omitted %q: %s", detail, expandedHuman.String())
		}
	}
}

func TestRunStatusRejectsUnsupportedRoleBeforeCollectorRead(t *testing.T) {
	t.Parallel()

	if _, err := RunStatus(context.Background(), RoleUninitialized, false, &operations.StatusCollector{}); !errors.Is(err, ErrUnsupportedRole) {
		t.Fatalf("uninitialized status error = %v", err)
	}
}

func TestStatusOutputMapsValidationConflictAndUnavailableCategories(t *testing.T) {
	t.Parallel()

	tests := []struct {
		category operations.StatusCategory
		overall  operations.StatusOverall
		status   output.Status
		exit     output.ExitCategory
	}{
		{operations.StatusCategoryValidation, operations.StatusOverallFailed, output.StatusFailed, output.CategoryValidation},
		{operations.StatusCategoryConflict, operations.StatusOverallDegraded, output.StatusDegraded, output.CategoryConflict},
		{operations.StatusCategoryUnavailable, operations.StatusOverallDegraded, output.StatusDegraded, output.CategoryUnavailable},
	}
	for _, test := range tests {
		report := cliStatusReport()
		report.Category, report.Overall = test.category, test.overall
		if test.category != operations.StatusCategoryConflict {
			report.Problems[0].Kind = "runtime"
		}
		result, err := statusResult(report, false)
		if err != nil {
			t.Fatalf("statusResult(%s): %v", test.category, err)
		}
		if result.Status != test.status || result.ExitCategory != test.exit {
			t.Fatalf("statusResult(%s) = %s/%s", test.category, result.Status, result.ExitCategory)
		}
	}
}

func cliStatusReport() operations.StatusReport {
	driftKey := operations.ManagedResourceKey{Component: "ingress", Kind: operations.ManagedResourceFile, ID: "/etc/vpnctl/nginx.conf"}
	return operations.StatusReport{
		Role: model.RoleGateway, Overall: operations.StatusOverallDegraded, Category: operations.StatusCategoryConflict,
		Generation: 9, DesiredGeneration: 9, AppliedGeneration: 8,
		BinaryVersion: "v2.0.0", ManifestBinaryVersion: "v2.0.0", ControlProtocols: []string{"1.0"},
		Components: []operations.StatusComponent{{
			Name: "mihomo", Version: "v1.19.30", Bundled: true,
			SHA256: strings.Repeat("a", 64), Capabilities: []string{"routing"},
		}},
		Counts: map[string]int{"nodes": 1, "drift": 1},
		Resources: []operations.StatusResource{{
			Kind: "node", ID: "11111111-1111-4111-8111-111111111111", Name: "healthy-node-canary",
			State: "active", ActiveTransport: "restricted", Generation: 3,
		}},
		Runtime: []operations.PassiveStatusResource{{
			Class:     operations.PassiveStatusDataPlane,
			Resource:  operations.ManagedResourceKey{Component: "routing", Kind: operations.ManagedResourceUnit, ID: "runtime-ready-canary"},
			Condition: operations.PassiveHealthy, Mandatory: true, Active: true, Version: "v1.19.30", Generation: 8,
			RuntimeSHA256: operations.ManagedFingerprint([]byte("runtime")), Code: "process_ready",
		}},
		Pending: []operations.StatusPendingChange{},
		Drift: []operations.StatusDrift{{
			Resource: driftKey, Kind: operations.OwnedDriftModified, Impact: operations.ConvergenceImpactAvailability,
			ExpectedSHA256: operations.ManagedFingerprint([]byte("expected")), ActualSHA256: operations.ManagedFingerprint([]byte("actual")),
		}},
		ActiveInvites: []operations.StatusInvite{}, LogOptIns: []operations.StatusLogOptIn{},
		Certificates: []operations.StatusCertificate{}, Backups: []operations.StatusBackup{},
		Problems: []operations.StatusProblem{{
			Kind: "drift", ID: "ingress/file//etc/vpnctl/nginx.conf", Condition: operations.PassiveDegraded, Code: "owned_modified",
		}},
		Warnings: []operations.StatusNotice{{Code: "owned_drift", Message: "One vpnctl-owned resource differs from applied state."}},
		RequiredActions: []operations.StatusNotice{{
			Code: "repair_owned_drift", Message: "Preview repair.", Command: "sudo vpnctl repair --dry-run",
		}},
	}
}
