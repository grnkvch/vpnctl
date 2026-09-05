package operations

import (
	"errors"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestLocalRoleRepairScopeResolverAcceptsOnlyExactRoleOwnership(t *testing.T) {
	t.Parallel()

	nodeID := "11111111-1111-4111-8111-111111111111"
	tests := []struct {
		name     string
		role     model.Role
		nodeID   string
		resource ManagedResourceKey
		want     ApplyScope
		wantErr  bool
	}{
		{
			name: "gateway config", role: model.RoleGateway,
			resource: ManagedResourceKey{Component: gatewayInitConvergenceComponent, Kind: ManagedResourceFile, ID: "/etc/vpnctl/generated/gateway/bootstrap.conf"},
			want:     ApplyScope{Role: model.RoleGateway},
		},
		{
			name: "gateway unit", role: model.RoleGateway,
			resource: ManagedResourceKey{Component: gatewayInitConvergenceComponent, Kind: ManagedResourceUnit, ID: "vpnctl-controller.service"},
			want:     ApplyScope{Role: model.RoleGateway},
		},
		{
			name: "node config", role: model.RoleNode, nodeID: nodeID,
			resource: ManagedResourceKey{Component: nodeInitConvergenceComponent, Kind: ManagedResourceFile, ID: "/etc/vpnctl/generated/node/routing.yaml"},
			want:     ApplyScope{Role: model.RoleNode, NodeID: nodeID},
		},
		{
			name: "node unit", role: model.RoleNode, nodeID: nodeID,
			resource: ManagedResourceKey{Component: nodeInitConvergenceComponent, Kind: ManagedResourceUnit, ID: "vpnctl-routing.service"},
			want:     ApplyScope{Role: model.RoleNode, NodeID: nodeID},
		},
		{
			name: "cross-role component", role: model.RoleGateway,
			resource: ManagedResourceKey{Component: nodeInitConvergenceComponent, Kind: ManagedResourceUnit, ID: "vpnctl-standard.service"}, wantErr: true,
		},
		{
			name: "cross-role unit", role: model.RoleGateway,
			resource: ManagedResourceKey{Component: gatewayInitConvergenceComponent, Kind: ManagedResourceUnit, ID: "vpnctl-routing.service"}, wantErr: true,
		},
		{
			name: "nested config", role: model.RoleGateway,
			resource: ManagedResourceKey{Component: gatewayInitConvergenceComponent, Kind: ManagedResourceFile, ID: "/etc/vpnctl/generated/gateway/nested/bootstrap.conf"}, wantErr: true,
		},
		{
			name: "sibling config", role: model.RoleNode, nodeID: nodeID,
			resource: ManagedResourceKey{Component: nodeInitConvergenceComponent, Kind: ManagedResourceFile, ID: "/etc/vpnctl/generated/gateway/bootstrap.conf"}, wantErr: true,
		},
		{
			name: "network", role: model.RoleGateway,
			resource: ManagedResourceKey{Component: gatewayInitConvergenceComponent, Kind: ManagedResourceNetwork, ID: "vpnctl"}, wantErr: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resolver, err := NewLocalRoleRepairScopeResolver(test.role, test.nodeID)
			if err != nil {
				t.Fatal(err)
			}
			got, err := resolver.ResolveRepairScope(RepairAction{Resource: test.resource})
			if test.wantErr {
				if err == nil {
					t.Fatalf("ResolveRepairScope(%+v) error = nil", test.resource)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ResolveRepairScope(%+v) = %+v, %v; want %+v", test.resource, got, err, test.want)
			}
		})
	}
}

func TestLocalRoleRepairScopeResolverRejectsInvalidConstruction(t *testing.T) {
	t.Parallel()

	nodeID := "11111111-1111-4111-8111-111111111111"
	for _, input := range []struct {
		role   model.Role
		nodeID string
	}{
		{role: model.RoleGateway, nodeID: nodeID},
		{role: model.RoleNode},
		{role: model.Role("unknown")},
	} {
		if _, err := NewLocalRoleRepairScopeResolver(input.role, input.nodeID); err == nil {
			t.Fatalf("NewLocalRoleRepairScopeResolver(%q, %q) error = nil", input.role, input.nodeID)
		}
	}
}

func TestBuildRepairPlanIsReadOnlyAndRoleScoped(t *testing.T) {
	t.Parallel()

	key := ManagedResourceKey{
		Component: gatewayInitConvergenceComponent,
		Kind:      ManagedResourceFile,
		ID:        "/etc/vpnctl/generated/gateway/bootstrap.conf",
	}
	target := ManagedFingerprint([]byte("target"))
	actual := ManagedFingerprint([]byte("actual"))
	convergence := ConvergencePlan{
		DesiredGeneration: 4,
		AppliedGeneration: 3,
		Impact:            ConvergenceImpactAvailability,
		Changes:           []DesiredChange{},
		Drift: []OwnedDrift{{
			Resource: key, Kind: OwnedDriftModified, Impact: ConvergenceImpactAvailability,
			ExpectedSHA256: target, ActualSHA256: actual,
		}},
	}
	resolver, err := NewLocalRoleRepairScopeResolver(model.RoleGateway, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildRepairPlan(model.RoleGateway, "", convergence, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if plan.TargetGeneration != 3 || plan.Impact != ConvergenceImpactAvailability || len(plan.Actions) != 1 {
		t.Fatalf("repair plan = %+v", plan)
	}
	if plan.Actions[0].Scope != (ApplyScope{Role: model.RoleGateway}) || plan.Actions[0].TargetSHA256 != target || plan.Actions[0].ObservedSHA256 != actual {
		t.Fatalf("repair action = %+v", plan.Actions[0])
	}
	if !reflect.DeepEqual(plan.Convergence, convergence) {
		t.Fatal("repair planning changed the convergence input")
	}

	clean := convergence
	clean.Impact = ConvergenceImpactNone
	clean.Drift = []OwnedDrift{}
	plan, err = BuildRepairPlan(model.RoleGateway, "", clean, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Impact != ConvergenceImpactNone || plan.Actions == nil || len(plan.Actions) != 0 {
		t.Fatalf("clean repair plan = %+v", plan)
	}
}

func TestBuildRepairPlanRejectsCrossRoleResourceWithoutPartialPlan(t *testing.T) {
	t.Parallel()

	target := ManagedFingerprint([]byte("target"))
	convergence := ConvergencePlan{
		DesiredGeneration: 3, AppliedGeneration: 3,
		Impact: ConvergenceImpactAvailability, Changes: []DesiredChange{},
		Drift: []OwnedDrift{{
			Resource: ManagedResourceKey{Component: nodeInitConvergenceComponent, Kind: ManagedResourceUnit, ID: "vpnctl-standard.service"},
			Kind:     OwnedDriftMissing, Impact: ConvergenceImpactAvailability, ExpectedSHA256: target,
		}},
	}
	resolver, err := NewLocalRoleRepairScopeResolver(model.RoleGateway, "")
	if err != nil {
		t.Fatal(err)
	}
	if plan, err := BuildRepairPlan(model.RoleGateway, "", convergence, resolver); err == nil || !errors.Is(err, ErrRepairInvalid) && !errors.Is(err, ErrRepairNodeAgentUnavailable) || !reflect.DeepEqual(plan, RepairPlan{}) {
		t.Fatalf("cross-role repair plan = %+v, %v", plan, err)
	}
}
