package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestStatusCommandParsesGlobalJSONAndRoutesPublicEntryPoint(t *testing.T) {
	oldPaths, oldRole, oldBuild, oldRun := statusSystemPaths, statusLoadRole, statusBuild, statusRun
	t.Cleanup(func() {
		statusSystemPaths, statusLoadRole, statusBuild, statusRun = oldPaths, oldRole, oldBuild, oldRun
	})
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	statusSystemPaths = func() store.Paths { return paths }
	statusLoadRole = func(received store.Paths) (HostRole, error) {
		if received != paths {
			t.Fatalf("role paths = %+v, want %+v", received, paths)
		}
		return RoleGateway, nil
	}
	built := false
	statusBuild = func(received store.Paths, role HostRole, binaryVersion string) (*operations.StatusCollector, error) {
		built = true
		if received != paths || role != RoleGateway || binaryVersion != version {
			t.Fatalf("build = %+v/%s/%q", received, role, binaryVersion)
		}
		return &operations.StatusCollector{}, nil
	}
	run := false
	statusRun = func(ctx context.Context, role HostRole, all bool, collector *operations.StatusCollector) (output.Result, error) {
		run = true
		if ctx == nil || role != RoleGateway || !all || collector == nil {
			t.Fatalf("run = ctx:%v role:%s all:%t collector:%v", ctx, role, all, collector)
		}
		return output.NewResult("status", output.StatusOK, output.CategorySuccess, output.SafeObject{
			"role": "gateway", "overall": "healthy", "generation": uint64(4),
		}), nil
	}

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"--json", "status", "--all"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !built || !run || stderr.Len() != 0 {
		t.Fatalf("built=%t run=%t stderr=%q", built, run, stderr.String())
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["command"] != "status" || document["status"] != "ok" {
		t.Fatalf("document = %+v", document)
	}
}

func TestStatusCommandRejectsInvalidArgumentsBeforeHostReads(t *testing.T) {
	oldPaths := statusSystemPaths
	t.Cleanup(func() { statusSystemPaths = oldPaths })
	statusSystemPaths = func() store.Paths {
		t.Fatal("invalid status arguments reached host paths")
		return store.Paths{}
	}
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"--json", "status", "--all", "--all"}, &stdout, &stderr); code != ExitValidation {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"code":"invalid_arguments"`) || stderr.Len() != 0 {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestPassiveStatusMapsGatewayUnitsWithoutNetworkProbes(t *testing.T) {
	t.Parallel()
	state := model.State{
		Generation: 7,
		Host:       model.Host{Role: model.RoleGateway},
		Components: model.ComponentManifest{VPNCTLVersion: "v2.0.0"},
		Transports: []model.Transport{{
			OwnerKind: model.TargetClient, OwnerID: "client-1", Kind: model.TransportStandard, State: model.TransportActive,
		}},
	}
	observation := activeRoleUnitObservation(state.Host.Role)
	snapshot := passiveStatusFromUnits(state, observation)

	if len(snapshot.Resources) != len(linuxplatform.RoleUnitNames(model.RoleGateway))+1 {
		t.Fatalf("resources = %+v", snapshot.Resources)
	}
	assertPassiveResource(t, snapshot, operations.PassiveStatusConnectivity, "control", operations.PassiveHealthy)
	assertPassiveResource(t, snapshot, operations.PassiveStatusActiveTransport, "client:client-1:standard", operations.PassiveHealthy)
	for _, resource := range snapshot.Resources {
		if resource.Generation != state.Generation || resource.Condition != operations.PassiveHealthy {
			t.Fatalf("resource = %+v", resource)
		}
	}
}

func TestPassiveStatusMapsJoinedNodeGatewayToSelectedTransportProcess(t *testing.T) {
	t.Parallel()
	state := model.State{
		Generation: 9,
		Host:       model.Host{Role: model.RoleNode},
		Components: model.ComponentManifest{VPNCTLVersion: "v2.0.0"},
		Nodes: []model.Node{{
			Lifecycle: model.LifecycleActive,
			Gateway:   &model.GatewayTrust{GatewayID: "gateway-1"},
		}},
		Transports: []model.Transport{{
			OwnerKind: model.TargetNode, OwnerID: "node-1", Kind: model.TransportRestricted, State: model.TransportActive,
		}},
	}
	observation := activeRoleUnitObservation(state.Host.Role)
	for index := range observation.Units {
		if observation.Units[index].Name == "vpnctl-routing.service" {
			observation.Units[index].ActiveState = "failed"
			observation.Units[index].SubState = "failed"
		}
	}
	snapshot := passiveStatusFromUnits(state, observation)

	assertPassiveResource(t, snapshot, operations.PassiveStatusConnectivity, "gateway", operations.PassiveDegraded)
	assertPassiveResource(t, snapshot, operations.PassiveStatusActiveTransport, "node:node-1:restricted", operations.PassiveDegraded)
	assertPassiveResource(t, snapshot, operations.PassiveStatusConnectivity, "control", operations.PassiveUnavailable)
}

func TestProductionStatusConvergenceGapIsExplicit(t *testing.T) {
	t.Parallel()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source, err := operations.NewFileConvergenceSnapshotSource(paths.ConvergenceFile)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := operations.NewConvergencePlanner(source, unavailableOwnedResourceDiscoverer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planner.Plan(context.Background()); err == nil || !errors.Is(err, operations.ErrConvergenceSnapshotUnavailable) {
		t.Fatalf("Plan() error = %v", err)
	}
}

func activeRoleUnitObservation(role model.Role) controller.Observation {
	result := controller.Observation{Units: []controller.UnitObservation{}, Issues: []string{}}
	for _, name := range linuxplatform.RoleUnitNames(role) {
		result.Units = append(result.Units, controller.UnitObservation{
			Name: name, LoadState: "loaded", ActiveState: "active", SubState: "running",
		})
	}
	return result
}

func assertPassiveResource(t *testing.T, snapshot operations.PassiveStatusSnapshot, class operations.PassiveStatusClass, id string, condition operations.PassiveHealth) {
	t.Helper()
	for _, resource := range snapshot.Resources {
		if resource.Class == class && resource.Resource.ID == id {
			if resource.Condition != condition {
				t.Fatalf("resource %s/%s condition=%s, want %s", class, id, resource.Condition, condition)
			}
			return
		}
	}
	t.Fatalf("resource %s/%s missing from %+v", class, id, snapshot.Resources)
}
