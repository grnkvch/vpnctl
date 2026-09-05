package operations

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestNodeTransportSwitchConvergencePublisherStagesExactDesiredDiff(t *testing.T) {
	t.Parallel()
	path := newConvergenceSnapshotStorePath(t)
	store, _ := NewFileConvergenceSnapshotStore(path)
	archive := newConvergenceAppliedMaterialArchive(t, path)
	request, _ := linuxplatform.RenderNodeRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	for index := range request.Units {
		request.Units[index].Enable = true
	}
	request.Configs = append(request.Configs, linuxplatform.RoleConfigFile{Name: "transport.ready", Content: []byte("active=standard\n")})
	baseline, err := ActiveNodeRoleConvergenceSnapshot(9, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Initialize(context.Background(), baseline); err != nil {
		t.Fatal(err)
	}
	publisher, err := NewNodeTransportSwitchConvergencePublisher(store, archive, linuxplatform.DefaultVPNCTLBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	operation := transportSwitchConvergenceOperation(t, 9)
	configs := []linuxplatform.RoleConfigFile{{Name: "transport.ready", Content: []byte("active=restricted\n")}}
	if err := publisher.PublishDesired(context.Background(), operation, configs); err != nil {
		t.Fatal(err)
	}
	if err := publisher.PublishDesired(context.Background(), operation, configs); err != nil {
		t.Fatalf("idempotent desired publication: %v", err)
	}
	got, err := store.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Applied.Generation != 9 || got.Desired.Generation != 11 || len(got.Pending) != 1 ||
		got.Pending[0].ID != operation.ID || got.Pending[0].ExpectedGeneration != 9 || got.Pending[0].DesiredGeneration != 11 ||
		len(got.Pending[0].Resources) != len(got.Desired.Resources) {
		t.Fatalf("transport switch convergence snapshot=%+v", got)
	}
	loaded, err := archive.Load(context.Background(), got.Desired)
	if err != nil {
		t.Fatalf("load staged desired material: %v", err)
	}
	defer loaded.Destroy()
	observed := make([]OwnedResourceObservation, len(got.Applied.Resources))
	for index, resource := range got.Applied.Resources {
		observed[index] = OwnedResourceObservation{Key: resource.Key, RuntimeSHA256: resource.RuntimeSHA256, RemoveImpact: resource.RemoveImpact}
	}
	planner, _ := NewConvergencePlanner(staticConvergenceSource{snapshot: got}, staticOwnedDiscovery{observed: observed})
	plan, err := planner.Plan(context.Background())
	if err != nil || plan.AppliedGeneration != 9 || plan.DesiredGeneration != 11 || len(plan.Changes) != len(got.Desired.Resources) || len(plan.Drift) != 0 {
		t.Fatalf("transport switch plan=%+v err=%v", plan, err)
	}
	for _, change := range plan.Changes {
		if change.OperationID != operation.ID || change.OperationExpectedGeneration != 9 || change.OperationDesiredGeneration != 11 {
			t.Fatalf("transport switch change=%+v", change)
		}
	}
}

func TestNodeTransportSwitchConvergencePublisherDoesNotPublishWithoutMaterial(t *testing.T) {
	t.Parallel()
	path := newConvergenceSnapshotStorePath(t)
	store, _ := NewFileConvergenceSnapshotStore(path)
	request, _ := linuxplatform.RenderNodeRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	for index := range request.Units {
		request.Units[index].Enable = true
	}
	request.Configs = append(request.Configs, linuxplatform.RoleConfigFile{Name: "transport.ready", Content: []byte("active=standard\n")})
	baseline, _ := ActiveNodeRoleConvergenceSnapshot(9, request)
	if err := store.Initialize(context.Background(), baseline); err != nil {
		t.Fatal(err)
	}
	materialErr := errors.New("injected desired material failure")
	publisher, _ := NewNodeTransportSwitchConvergencePublisher(
		store, &recordingAppliedMaterialEnsurer{err: materialErr}, linuxplatform.DefaultVPNCTLBinaryPath,
	)
	err := publisher.PublishDesired(context.Background(), transportSwitchConvergenceOperation(t, 9), []linuxplatform.RoleConfigFile{
		{Name: "transport.ready", Content: []byte("active=restricted\n")},
	})
	if !errors.Is(err, materialErr) {
		t.Fatalf("desired material failure=%v", err)
	}
	got, readErr := store.Read(context.Background())
	if readErr != nil || !reflect.DeepEqual(got, baseline) {
		t.Fatalf("baseline changed without desired material: %+v, %v", got, readErr)
	}
}

func transportSwitchConvergenceOperation(t *testing.T, expectedNodeGeneration uint64) model.Operation {
	t.Helper()
	nodeID := "74000000-0000-4000-8000-000000000001"
	requestID := "74000000-0000-4000-8000-000000000002"
	operationID, err := transport.SwitchOperationID(requestID)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := transport.NewSwitchIntentTarget(nodeID, model.TransportRestricted, expectedNodeGeneration)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, time.September, 6, 12, 0, 0, 0, time.UTC)
	steps := make([]model.OperationStep, len(transport.SwitchOperationStepNames()))
	for index, name := range transport.SwitchOperationStepNames() {
		steps[index] = model.OperationStep{Name: name, State: model.OperationPending, UpdatedAt: at}
	}
	return model.Operation{
		SchemaVersion: model.ResourceSchemaVersion, ID: operationID, Type: model.OperationTransportSwitch,
		State: model.OperationPending, TargetKind: "transport", TargetID: intent.String(), RequestID: requestID,
		ExpectedGeneration: 20, DesiredGeneration: 22, Steps: steps, CreatedAt: at, UpdatedAt: at,
	}
}
