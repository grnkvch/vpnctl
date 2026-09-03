package enrollment

import (
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestNodeCertificateInspectorUsesExactWarningAndExpiryBoundariesOnBothRoles(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	if _, err := fixture.workflow.Join(t.Context(), fixture.token, model.TransportRestricted, []string{"telegram"}); err != nil {
		t.Fatal(err)
	}
	nodeState, err := fixture.nodeState.Load()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := currentNodeControlCertificate(nodeState, nodeState.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	warningBoundary := certificate.NotAfter.Add(-control.ControlRenewalWindow)
	tests := []struct {
		name string
		now  time.Time
		want NodeCertificateCondition
	}{
		{name: "before warning", now: warningBoundary.Add(-time.Second), want: NodeCertificateHealthy},
		{name: "warning boundary", now: warningBoundary, want: NodeCertificateExpiring},
		{name: "before expiry", now: certificate.NotAfter.Add(-time.Second), want: NodeCertificateExpiring},
		{name: "expiry boundary", now: certificate.NotAfter, want: NodeCertificateExpired},
		{name: "after expiry", now: certificate.NotAfter.Add(time.Second), want: NodeCertificateExpired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for role, reader := range map[model.Role]NodeStateReader{
				model.RoleGateway: fixture.gatewayState,
				model.RoleNode:    fixture.nodeState,
			} {
				inspector, err := NewNodeCertificateInspector(reader, func() time.Time { return test.now })
				if err != nil {
					t.Fatal(err)
				}
				report, err := inspector.Inspect()
				if err != nil {
					t.Fatalf("Inspect(%s) error = %v", role, err)
				}
				if report.Role != role || len(report.Items) != 1 || report.Items[0].Condition != test.want ||
					report.Items[0].WarningStartsAt != warningBoundary || report.Items[0].WarningDays != control.ControlWarningDays ||
					report.Items[0].CredentialGeneration != 1 || report.Items[0].NodeID != joinTestNodeID {
					t.Fatalf("Inspect(%s, %s) = %+v", role, test.now, report)
				}
			}
		})
	}
}

func TestNodeCertificateInspectorIsPassiveAndSkipsNonActiveNodes(t *testing.T) {
	fixture := newNodeLifecycleFixture(t, healthyNodeRevocationReport())
	defer fixture.destroy()
	before, err := fixture.gatewayState.Load()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := fixture.manager.PlanRevoke(joinTestNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.CommitRevoke(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	revoked, _ := fixture.gatewayState.Load()
	inspector, _ := NewNodeCertificateInspector(fixture.gatewayState, func() time.Time { return before.Certificates[len(before.Certificates)-1].NotAfter })
	report, err := inspector.Inspect()
	if err != nil || len(report.Items) != 0 {
		t.Fatalf("Inspect(revoked) = %+v, %v", report, err)
	}
	after, _ := fixture.gatewayState.Load()
	if !reflect.DeepEqual(revoked, after) {
		t.Fatal("passive certificate inspection changed authoritative state")
	}
}
