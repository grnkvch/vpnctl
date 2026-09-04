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

func TestDoctorResultRendersCompleteSafeChecks(t *testing.T) {
	t.Parallel()

	report := cliDoctorReport()
	result, err := doctorResult(report)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != output.StatusOK || result.ExitCategory != output.CategorySuccess || len(result.Warnings) != 0 {
		t.Fatalf("healthy doctor output = %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"role":"node"`, `"scope":"dns"`, `"run_id":"11111111-1111-4111-8111-111111111111"`, `"protocol":"dns_udp"`, `"elapsed_ms":3`} {
		if !bytes.Contains(encoded, []byte(required)) {
			t.Fatalf("doctor JSON omitted %s: %s", required, encoded)
		}
	}
	for _, forbidden := range []string{"endpoint", "health_path", "probe_url", "/telegram/webhook"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("doctor JSON leaked %q: %s", forbidden, encoded)
		}
	}
	var human bytes.Buffer
	if err := output.RenderHuman(&human, result); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"checks:", "dns.direct.udp.1", "code=dns_response_valid", "elapsed ms=3"} {
		if !strings.Contains(human.String(), value) {
			t.Fatalf("human doctor omitted %q: %s", value, human.String())
		}
	}
}

func TestDoctorFailureUsesDegradedUnavailableExit(t *testing.T) {
	t.Parallel()

	report := cliDoctorReport()
	report.Overall = operations.StatusOverallDegraded
	report.Checks[0].Status = operations.DoctorCheckFailed
	report.Checks[0].Code = "probe_timeout"
	result, err := doctorResult(report)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != output.StatusDegraded || result.ExitCategory != output.CategoryUnavailable || len(result.Warnings) != 1 ||
		result.Warnings[0].ResourceIDs["dns_path_id"] != "direct" {
		t.Fatalf("failed doctor output = %+v", result)
	}
}

func TestDoctorSkippedExternalDependencyIsSuccessfulAndExplained(t *testing.T) {
	t.Parallel()

	report := operations.DoctorReport{
		Role: model.RoleGateway, Scope: operations.DoctorScopeIngress, RunID: "11111111-1111-4111-8111-111111111111",
		Overall: operations.StatusOverallHealthy,
		Checks: []operations.DoctorCheck{{
			Name: "external.explicit_https_get", Scope: operations.DoctorScopeExternal, Kind: operations.DoctorProbeExternalHTTPS,
			Protocol: operations.DoctorProtocolHTTPS, ResourceKind: "external_dependency", ResourceID: "explicit",
			Status: operations.DoctorCheckSkipped, Code: "external_endpoint_unspecified", ElapsedMS: 0,
			Detail: "No explicit endpoint was supplied; hidden telemetry is disabled.",
		}},
	}
	result, err := doctorResult(report)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != output.StatusOK || result.ExitCategory != output.CategorySuccess || len(result.Warnings) != 0 {
		t.Fatalf("skipped external result = %+v", result)
	}
	var human bytes.Buffer
	if err := output.RenderHuman(&human, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(human.String(), "hidden telemetry is disabled") || !strings.Contains(human.String(), "status=skipped") {
		t.Fatalf("skipped external explanation missing: %s", human.String())
	}
}

func TestRunDoctorRejectsUnsupportedRoleBeforeExecution(t *testing.T) {
	t.Parallel()

	if _, err := RunDoctor(context.Background(), RoleUninitialized, operations.DoctorScopeDefault, &operations.Doctor{}); !errors.Is(err, ErrUnsupportedRole) {
		t.Fatalf("uninitialized doctor error = %v", err)
	}
}

func cliDoctorReport() operations.DoctorReport {
	return operations.DoctorReport{
		Role: model.RoleNode, Scope: operations.DoctorScopeDNS, RunID: "11111111-1111-4111-8111-111111111111",
		Overall: operations.StatusOverallHealthy,
		Checks: []operations.DoctorCheck{{
			Name: "dns.direct.udp.1", Scope: operations.DoctorScopeDNS, Kind: operations.DoctorProbeDirectDNS,
			Protocol: operations.DoctorProtocolDNSUDP, ResourceKind: "dns_path", ResourceID: "direct",
			Status: operations.DoctorCheckPassed, Code: "dns_response_valid", ElapsedMS: 3,
		}},
	}
}
