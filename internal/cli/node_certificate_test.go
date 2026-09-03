package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

func TestNodeCertificateStatusWarnsAt180DaysWithoutDegradingHealthyState(t *testing.T) {
	item := certificateHealthFixture(enrollment.NodeCertificateExpiring)
	for _, role := range []model.Role{model.RoleGateway, model.RoleNode} {
		result := NodeCertificateStatusOutput(enrollment.NodeCertificateReport{
			Role: role, StateGeneration: 9, Items: []enrollment.NodeCertificateHealth{item},
		})
		if err := result.Validate(); err != nil {
			t.Fatalf("Validate(%s) error = %v", role, err)
		}
		if result.Status != output.StatusOK || result.ExitCategory != output.CategorySuccess || result.Data["overall"] != "healthy" ||
			len(result.Warnings) != 1 || result.Warnings[0].Code != "node_certificate_expiring" ||
			len(result.RequiresAction) != 1 || result.RequiresAction[0].Code != "rotate_node_credentials" {
			t.Fatalf("status(%s) = %+v", role, result)
		}
		if result.RequiresAction[0].Command != "sudo vpnctl node rotate" {
			t.Fatalf("%s warning action = %+v", role, result.RequiresAction[0])
		}
	}
}

func TestNodeCertificateDoctorFailsExpiredCheckAndDirectsTwoHostRecovery(t *testing.T) {
	item := certificateHealthFixture(enrollment.NodeCertificateExpired)
	for _, role := range []model.Role{model.RoleGateway, model.RoleNode} {
		result := NodeCertificateDoctorOutput(enrollment.NodeCertificateReport{
			Role: role, StateGeneration: 9, Items: []enrollment.NodeCertificateHealth{item},
		})
		if err := result.Validate(); err != nil {
			t.Fatal(err)
		}
		checks, ok := result.Data["checks"].([]output.SafeObject)
		if result.Status != output.StatusDegraded || result.ExitCategory != output.CategoryUnavailable || result.Data["scope"] != "default" ||
			!ok || len(checks) != 1 || checks[0]["status"] != "failed" || len(result.Warnings) != 1 ||
			result.Warnings[0].Code != "node_certificate_expired" || len(result.RequiresAction) != 2 ||
			result.RequiresAction[0].Command != "sudo vpnctl node recover "+item.NodeID ||
			result.RequiresAction[1].Command != "sudo vpnctl node recover" {
			t.Fatalf("expired doctor output(%s) = %+v", role, result)
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"credential_ref", "certificate_ref", "private_key", "recovery_token", "secret"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("expired doctor output contains %q: %s", forbidden, encoded)
			}
		}
	}
}

func TestNodeCertificateHealthyOutputsNeedNoAction(t *testing.T) {
	report := enrollment.NodeCertificateReport{
		Role: model.RoleGateway, StateGeneration: 9,
		Items: []enrollment.NodeCertificateHealth{certificateHealthFixture(enrollment.NodeCertificateHealthy)},
	}
	for _, result := range []output.Result{NodeCertificateStatusOutput(report), NodeCertificateDoctorOutput(report)} {
		if err := result.Validate(); err != nil || result.Status != output.StatusOK || len(result.Warnings) != 0 || len(result.RequiresAction) != 0 {
			t.Fatalf("healthy %s = %+v, %v", result.Command, result, err)
		}
	}
}

func certificateHealthFixture(condition enrollment.NodeCertificateCondition) enrollment.NodeCertificateHealth {
	notAfter := time.Date(2031, time.September, 3, 12, 0, 0, 0, time.UTC)
	return enrollment.NodeCertificateHealth{
		NodeID: "20000000-0000-4000-8000-000000000004", NodeName: "private-node",
		CertificateID: "70000000-0000-4000-8000-000000000007", Fingerprint: "sha256:" + strings.Repeat("a", 64),
		CredentialGeneration: 1, NotAfter: notAfter,
		WarningStartsAt: notAfter.Add(-control.ControlRenewalWindow), WarningDays: control.ControlWarningDays,
		Condition: condition,
	}
}
