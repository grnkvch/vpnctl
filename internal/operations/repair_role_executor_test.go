package operations

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
)

func TestLocalRoleRepairExecutorLoadsAppliedMaterialAndUsesExplicitRestart(t *testing.T) {
	t.Parallel()

	fixture := newLocalRoleRepairExecutorFixture(t, true)
	result, err := fixture.executor.RepairGateway(context.Background(), fixture.batch)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.TargetGeneration != fixture.batch.TargetGeneration || len(result.Resources) != 1 ||
		result.Resources[0].RuntimeSHA256 != fixture.batch.Actions[0].TargetSHA256 {
		t.Fatalf("repair result = %+v", result)
	}
	if fixture.host.planCalls != 1 || fixture.host.applyCalls != 1 || len(fixture.host.request.Resources) != 1 {
		t.Fatalf("host calls/request = %d/%d %+v", fixture.host.planCalls, fixture.host.applyCalls, fixture.host.request)
	}
	resource := fixture.host.request.Resources[0]
	if resource.Kind != linuxplatform.RoleRepairConfig || resource.Name != routing.GatewayDNSConfigFileName ||
		string(resource.Content) != "applied gateway dns\n" ||
		!reflect.DeepEqual(fixture.host.request.RestartUnits, []string{"vpnctl-dns.service"}) {
		t.Fatalf("role repair request = %+v", fixture.host.request)
	}
}

func TestLocalRoleRepairExecutorRefusesMissingMaterialBeforeHostPreflight(t *testing.T) {
	t.Parallel()

	fixture := newLocalRoleRepairExecutorFixture(t, false)
	if _, err := fixture.executor.RepairGateway(context.Background(), fixture.batch); !errors.Is(err, ErrAppliedMaterialUnavailable) {
		t.Fatalf("missing material error = %v", err)
	}
	if fixture.host.planCalls != 0 || fixture.host.applyCalls != 0 {
		t.Fatalf("missing material reached host: %d/%d", fixture.host.planCalls, fixture.host.applyCalls)
	}
}

func TestLocalRoleRepairExecutorRejectsObservationChangeAfterHostPlan(t *testing.T) {
	t.Parallel()

	fixture := newLocalRoleRepairExecutorFixture(t, true)
	fixture.host.afterPlan = func() {
		fixture.discovery.observed[0].RuntimeSHA256 = ManagedFingerprint([]byte("changed after host preflight"))
	}
	if _, err := fixture.executor.RepairGateway(context.Background(), fixture.batch); !errors.Is(err, ErrRepairConflict) {
		t.Fatalf("stale post-preflight repair error = %v", err)
	}
	if fixture.host.planCalls != 1 || fixture.host.applyCalls != 0 {
		t.Fatalf("stale repair host calls = %d/%d", fixture.host.planCalls, fixture.host.applyCalls)
	}
}

type localRoleRepairExecutorFixture struct {
	executor  *LocalRoleRepairExecutor
	batch     RepairExecutionBatch
	discovery *applyDiscovery
	host      *recordingLocalRoleRepairHost
}

func newLocalRoleRepairExecutorFixture(t *testing.T, publishMaterial bool) localRoleRepairExecutorFixture {
	t.Helper()
	key := ManagedResourceKey{
		Component: gatewayInitConvergenceComponent, Kind: ManagedResourceFile,
		ID: "/etc/vpnctl/generated/gateway/" + routing.GatewayDNSConfigFileName,
	}
	content := []byte("applied gateway dns\n")
	entry, err := NewAppliedFileMaterial(key, 0o600, content)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Destroy()
	applied, err := NewConvergenceManifest(7, []ManagedResource{{
		Key: key, RevisionSHA256: ManagedFingerprint([]byte("revision")), RuntimeSHA256: entry.entry.runtimeSHA256,
		ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
	}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := ConvergenceSnapshot{Desired: cloneManifest(applied), Applied: cloneManifest(applied), Pending: []PendingOperation{}}
	source := &applySnapshotSource{snapshot: snapshot}
	actual, err := NewAppliedFileMaterial(key, 0o600, []byte("manually changed dns\n"))
	if err != nil {
		t.Fatal(err)
	}
	actualRuntime := actual.entry.runtimeSHA256
	actual.Destroy()
	discovery := &applyDiscovery{observed: []OwnedResourceObservation{{
		Key: key, RuntimeSHA256: actualRuntime, RemoveImpact: ConvergenceImpactAvailability,
	}}}
	resolver, err := NewLocalRoleRepairScopeResolver(model.RoleGateway, "")
	if err != nil {
		t.Fatal(err)
	}
	path := newConvergenceSnapshotStorePath(t)
	archive := newConvergenceAppliedMaterialArchive(t, path)
	set, err := NewAppliedMaterialSet(applied, []AppliedMaterial{entry})
	if err != nil {
		t.Fatal(err)
	}
	if publishMaterial {
		if _, err := archive.Ensure(context.Background(), applied, set); err != nil {
			set.Destroy()
			t.Fatal(err)
		}
	}
	set.Destroy()
	host := &recordingLocalRoleRepairHost{}
	executor, err := NewLocalRoleRepairExecutor(model.RoleGateway, "", source, discovery, resolver, archive, host)
	if err != nil {
		t.Fatal(err)
	}
	planner, _ := NewConvergencePlanner(source, discovery)
	convergence, err := planner.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildRepairPlan(model.RoleGateway, "", convergence, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return localRoleRepairExecutorFixture{
		executor: executor, batch: repairExecutionBatch(plan), discovery: discovery, host: host,
	}
}

type recordingLocalRoleRepairHost struct {
	request    linuxplatform.RoleRepairRequest
	planCalls  int
	applyCalls int
	afterPlan  func()
}

func (host *recordingLocalRoleRepairHost) PlanRepair(
	_ context.Context,
	request linuxplatform.RoleRepairRequest,
) (*linuxplatform.RoleRepairPlan, error) {
	host.planCalls++
	host.request = cloneLinuxRoleRepairRequest(request)
	if host.afterPlan != nil {
		host.afterPlan()
	}
	return &linuxplatform.RoleRepairPlan{}, nil
}

func (host *recordingLocalRoleRepairHost) ApplyRepair(
	_ context.Context,
	plan *linuxplatform.RoleRepairPlan,
) (linuxplatform.RoleRepairResult, error) {
	host.applyCalls++
	plan.Destroy()
	resources := make([]linuxplatform.RoleRepairResourceResult, len(host.request.Resources))
	for index, resource := range host.request.Resources {
		resources[index] = linuxplatform.RoleRepairResourceResult{
			Kind: resource.Kind, Name: resource.Name, Changed: true, ContentSHA256: resource.ContentSHA256,
		}
	}
	return linuxplatform.RoleRepairResult{Resources: resources}, nil
}

func cloneLinuxRoleRepairRequest(request linuxplatform.RoleRepairRequest) linuxplatform.RoleRepairRequest {
	result := linuxplatform.RoleRepairRequest{
		Role: request.Role, Resources: make([]linuxplatform.RoleRepairResource, len(request.Resources)),
		RestartUnits: append([]string{}, request.RestartUnits...),
	}
	for index, resource := range request.Resources {
		result.Resources[index] = resource
		result.Resources[index].Content = append([]byte(nil), resource.Content...)
		if resource.UnitTarget != nil {
			target := *resource.UnitTarget
			result.Resources[index].UnitTarget = &target
		}
	}
	return result
}

var _ LocalRoleRepairHost = (*recordingLocalRoleRepairHost)(nil)
