package cli

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestCommittedGatewayRepairPreviewsConfirmsAndReturnsWatchdogAction(t *testing.T) {
	t.Parallel()

	plan := committedGatewayRepairTestPlan(true)
	events := []string{}
	operator := &recordingCommittedGatewayRepairOperator{
		plan: plan, result: controller.GatewayRepairData{Changed: true, NetworkActivationRequired: true, TransactionID: "fw-7K3M2P"}, events: &events,
	}
	terminal := &orderedPromptIO{visible: []string{"yes"}, events: &events}
	outcome, err := RunCommittedGatewayRepair(context.Background(), false, false, false, terminal, operator)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"plan", "visible", "repair"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("gateway repair events = %v, want %v", events, want)
	}
	if outcome.Mode != MutationImmediate || outcome.Plan.Impact != ImpactAvailability || !reflect.DeepEqual(operator.approved, plan) {
		t.Fatalf("gateway repair outcome/approved = %+v / %+v", outcome, operator.approved)
	}
	if outcome.Result.ResourceIDs["host_id"] != plan.HostID || outcome.Result.ResourceIDs["transaction_id"] != "fw-7K3M2P" ||
		len(outcome.Result.RequiresAction) != 1 || outcome.Result.RequiresAction[0].Command != "vpnctl confirm fw-7K3M2P" {
		t.Fatalf("gateway repair result = %+v", outcome.Result)
	}
}

func TestCommittedGatewayRepairDryRunDoesNotMutateOrInventConfirmation(t *testing.T) {
	t.Parallel()

	operator := &recordingCommittedGatewayRepairOperator{plan: committedGatewayRepairTestPlan(true)}
	outcome, err := RunCommittedGatewayRepair(context.Background(), true, false, true, nil, operator)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Mode != MutationDryRun || operator.planCalls != 1 || operator.repairCalls != 0 || len(outcome.Result.RequiresAction) != 0 || outcome.Result.ResourceIDs["transaction_id"] != "" {
		t.Fatalf("gateway repair dry-run = %+v, calls=%d/%d", outcome, operator.planCalls, operator.repairCalls)
	}
	if outcome.Result.Data["firewall_sha256"] != strings.Repeat("b", 64) || outcome.Result.Data["initial_network_sha256"] != strings.Repeat("c", 64) {
		t.Fatalf("gateway network preview hashes = %+v", outcome.Result.Data)
	}
}

func TestCommittedGatewayRepairRejectsModifiedPublicPreview(t *testing.T) {
	t.Parallel()

	operator := &recordingCommittedGatewayRepairOperator{plan: committedGatewayRepairTestPlan(false)}
	workflow, err := NewCommittedGatewayRepairWorkflow(operator)
	if err != nil {
		t.Fatal(err)
	}
	public, err := workflow.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	public.Result.Data["network_activation_required"] = true
	if _, err := workflow.Apply(context.Background(), public, nil); !errors.Is(err, ErrInvalidMutationPlan) {
		t.Fatalf("modified gateway preview error = %v", err)
	}
	if operator.repairCalls != 0 {
		t.Fatal("modified gateway preview reached controller")
	}
}

func TestSystemCommittedGatewayRepairSendsExactPlanAndValidatesResponse(t *testing.T) {
	t.Parallel()

	plan := committedGatewayRepairTestPlan(true)
	state := &mutableCommittedGatewayRepairState{state: model.State{Generation: plan.Generation, Host: model.Host{Role: model.RoleGateway, ID: plan.HostID}}}
	callCount := 0
	repair, err := newSystemCommittedGatewayRepair(state, staticCommittedGatewayRepairPlanner{plan: plan}, "/run/vpnctl/control.sock", func(_ context.Context, socket string, request control.LocalRequest) (control.LocalResponse, error) {
		callCount++
		if socket != "/run/vpnctl/control.sock" || request.Method != control.LocalMutate || request.Operation != controller.GatewayRepairOperation || request.ExpectedGeneration != plan.Generation {
			t.Fatalf("gateway repair local request = %s / %+v", socket, request)
		}
		var payload controller.GatewayRepairPayload
		if err := control.DecodeRPCPayload(request.Payload, &payload); err != nil || !reflect.DeepEqual(payload.Plan, plan) {
			t.Fatalf("gateway repair payload = %+v, %v", payload, err)
		}
		data, _ := json.Marshal(controller.GatewayRepairData{Changed: true, NetworkActivationRequired: true, TransactionID: "fw-7K3M2P"})
		return control.LocalResponse{SchemaVersion: control.LocalSchemaVersion, OK: true, Generation: plan.Generation, Data: data}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := repair.Repair(context.Background(), plan)
	if err != nil || callCount != 1 || result.TransactionID != "fw-7K3M2P" {
		t.Fatalf("system gateway repair = %+v, %v; calls=%d", result, err, callCount)
	}

	repair.call = func(context.Context, string, control.LocalRequest) (control.LocalResponse, error) {
		return control.LocalResponse{}, errors.New("response lost")
	}
	if _, err := repair.Repair(context.Background(), plan); !errors.Is(err, ErrCommittedGatewayRepairUncertain) {
		t.Fatalf("lost gateway repair response error = %v", err)
	}

	state.state.Generation++
	callCount = 0
	repair.call = func(context.Context, string, control.LocalRequest) (control.LocalResponse, error) {
		callCount++
		return control.LocalResponse{}, nil
	}
	if _, err := repair.Repair(context.Background(), plan); !errors.Is(err, ErrCommittedGatewayRepairStale) || callCount != 0 {
		t.Fatalf("locally stale gateway repair = %v; calls=%d", err, callCount)
	}
}

func committedGatewayRepairTestPlan(network bool) controller.GatewayRepairPlan {
	services := linuxplatform.RoleUnitNames(model.RoleGateway)
	sort.Strings(services)
	artifacts := make([]controller.GatewayRepairArtifact, 0, 15)
	for _, service := range services {
		artifacts = append(artifacts, controller.GatewayRepairArtifact{Kind: "unit", Name: service, SHA256: strings.Repeat("a", 64)})
	}
	configs := append([]string{"bootstrap.conf", "gateway-controller.ready", routing.GatewayDNSConfigFileName, routing.GatewayDNSReadyFileName}, transport.GatewayListenerFileNames()...)
	for _, name := range configs {
		artifacts = append(artifacts, controller.GatewayRepairArtifact{Kind: "config", Name: name, SHA256: strings.Repeat("a", 64)})
	}
	plan := controller.GatewayRepairPlan{
		SchemaVersion: controller.GatewayRepairPlanSchemaVersion, Generation: 7,
		HostID: "78000000-0000-4000-8000-000000000001", Services: services, Artifacts: artifacts,
		NetworkActivationRequired: network,
	}
	if network {
		plan.Artifacts = append(plan.Artifacts,
			controller.GatewayRepairArtifact{Kind: "watchdog_unit", Name: linuxplatform.WatchdogServiceUnitName, SHA256: strings.Repeat("a", 64)},
			controller.GatewayRepairArtifact{Kind: "watchdog_unit", Name: linuxplatform.WatchdogTimerUnitName, SHA256: strings.Repeat("a", 64)},
		)
		plan.FirewallSHA256 = strings.Repeat("b", 64)
		plan.InitialNetworkSHA256 = strings.Repeat("c", 64)
	}
	sort.Slice(plan.Artifacts, func(left, right int) bool {
		return plan.Artifacts[left].Kind+"\x00"+plan.Artifacts[left].Name < plan.Artifacts[right].Kind+"\x00"+plan.Artifacts[right].Name
	})
	return plan
}

type recordingCommittedGatewayRepairOperator struct {
	plan        controller.GatewayRepairPlan
	result      controller.GatewayRepairData
	approved    controller.GatewayRepairPlan
	planCalls   int
	repairCalls int
	events      *[]string
}

func (operator *recordingCommittedGatewayRepairOperator) Plan(context.Context) (controller.GatewayRepairPlan, error) {
	operator.planCalls++
	if operator.events != nil {
		*operator.events = append(*operator.events, "plan")
	}
	return cloneCommittedGatewayRepairPlan(operator.plan), nil
}
func (operator *recordingCommittedGatewayRepairOperator) Repair(_ context.Context, plan controller.GatewayRepairPlan) (controller.GatewayRepairData, error) {
	operator.repairCalls++
	operator.approved = cloneCommittedGatewayRepairPlan(plan)
	if operator.events != nil {
		*operator.events = append(*operator.events, "repair")
	}
	return operator.result, nil
}

type mutableCommittedGatewayRepairState struct{ state model.State }

func (state *mutableCommittedGatewayRepairState) Load() (model.State, error) { return state.state, nil }

type staticCommittedGatewayRepairPlanner struct{ plan controller.GatewayRepairPlan }

func (planner staticCommittedGatewayRepairPlanner) Plan(context.Context, model.State) (controller.GatewayRepairPlan, error) {
	return cloneCommittedGatewayRepairPlan(planner.plan), nil
}

var _ CommittedGatewayRepairOperator = (*recordingCommittedGatewayRepairOperator)(nil)
