package controller

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestGatewayRepairPlanIsContentFreeAndSelectsBootstrapNetwork(t *testing.T) {
	t.Parallel()

	state := gatewayRepairTestState(t)
	fixture := newGatewayRepairFixture(t, state)
	plan, err := fixture.dispatcher.Plan(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.NetworkActivationRequired || plan.TunnelActive || len(plan.Services) != 5 || len(plan.Artifacts) != 15 {
		t.Fatalf("gateway bootstrap repair plan = %+v", plan)
	}
	if fixture.roles.compiles != 1 || fixture.roles.applies != 0 || fixture.watchdogUnits.applies != 0 || fixture.network.activations != 0 || fixture.watchdog.arms != 0 {
		t.Fatalf("read-only plan mutated runtime: %+v", fixture)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "rendered-secret") || strings.Contains(string(encoded), "ExecStart=") {
		t.Fatalf("gateway repair plan exposed rendered content: %s", encoded)
	}
}

func TestGatewayRepairPlanSkipsNetworkAfterCommittedWatchdog(t *testing.T) {
	t.Parallel()

	state := gatewayRepairTestState(t)
	fixture := newGatewayRepairFixture(t, state)
	fixture.status.statuses["fw-7K3M2P"] = operations.WatchdogStatusCommitted
	plan, err := fixture.dispatcher.Plan(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if plan.NetworkActivationRequired || plan.FirewallSHA256 != "" || plan.InitialNetworkSHA256 != "" || len(plan.Artifacts) != 13 {
		t.Fatalf("committed gateway service repair plan = %+v", plan)
	}
}

func TestGatewayRepairApplyUsesReviewedOrderAndReturnsConfirmation(t *testing.T) {
	t.Parallel()

	state := gatewayRepairTestState(t)
	fixture := newGatewayRepairFixture(t, state)
	plan, err := fixture.dispatcher.Plan(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(GatewayRepairPayload{Plan: plan})
	prepared, err := fixture.dispatcher.Prepare(context.Background(), state, GatewayRepairOperation, payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture.events.values = nil
	if err := prepared.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantEvents := []string{"watchdog-units", "roles", "convergence-inactive", "watchdog-arm", "network", "watchdog-activated"}
	if !reflect.DeepEqual(fixture.events.values, wantEvents) {
		t.Fatalf("gateway repair apply events = %v, want %v", fixture.events.values, wantEvents)
	}
	if !prepared.RuntimeOnly || !reflect.DeepEqual(prepared.Candidate, state) {
		t.Fatalf("gateway repair prepared mutation changed state: %+v", prepared)
	}
	var result GatewayRepairData
	if err := json.Unmarshal(prepared.Result(), &result); err != nil || !result.Changed || !result.NetworkActivationRequired || result.TransactionID != "fw-7K3M2P" {
		t.Fatalf("gateway repair result = %+v, %v", result, err)
	}
}

func TestGatewayRepairRejectsStalePlanAndNetworkMismatchBeforeActivation(t *testing.T) {
	t.Parallel()

	state := gatewayRepairTestState(t)
	fixture := newGatewayRepairFixture(t, state)
	plan, err := fixture.dispatcher.Plan(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	stale := plan
	stale.Artifacts = append([]GatewayRepairArtifact(nil), plan.Artifacts...)
	stale.Artifacts[0].SHA256 = strings.Repeat("f", 64)
	payload, _ := json.Marshal(GatewayRepairPayload{Plan: stale})
	if _, err := fixture.dispatcher.Prepare(context.Background(), state, GatewayRepairOperation, payload); !errors.Is(err, ErrGatewayRepairStale) {
		t.Fatalf("stale gateway repair error = %v", err)
	}
	if fixture.roles.applies != 0 || fixture.network.activations != 0 {
		t.Fatal("stale gateway repair reached apply")
	}

	payload, _ = json.Marshal(GatewayRepairPayload{Plan: plan})
	prepared, err := fixture.dispatcher.Prepare(context.Background(), state, GatewayRepairOperation, payload)
	if err != nil {
		t.Fatal(err)
	}
	fixture.watchdog.network.Sysctls = []linuxplatform.SysctlSnapshot{{Name: "net.ipv4.ip_forward", Value: "1"}}
	if err := prepared.Apply(context.Background()); !errors.Is(err, ErrGatewayRepairNetworkState) {
		t.Fatalf("network mismatch error = %v", err)
	}
	if fixture.network.activations != 0 || fixture.watchdog.rollbacks != 1 {
		t.Fatalf("network mismatch activation/rollback = %d/%d", fixture.network.activations, fixture.watchdog.rollbacks)
	}
}

func TestGatewayRepairRefusesPendingWatchdog(t *testing.T) {
	t.Parallel()

	state := gatewayRepairTestState(t)
	fixture := newGatewayRepairFixture(t, state)
	fixture.status.statuses["fw-7K3M2P"] = operations.WatchdogStatusActive
	if _, err := fixture.dispatcher.Plan(context.Background(), state); !errors.Is(err, ErrGatewayRepairWatchdogActive) {
		t.Fatalf("pending watchdog repair error = %v", err)
	}
	if fixture.roles.applies != 0 || fixture.network.activations != 0 || fixture.watchdog.arms != 0 {
		t.Fatal("pending watchdog repair mutated runtime")
	}
}

func gatewayRepairTestState(t *testing.T) model.State {
	t.Helper()
	_, stateStore := controllerTestState(t, model.RoleGateway)
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.DNS = &model.DNSUpstreamState{
		SchemaVersion: model.ResourceSchemaVersion,
		Scope:         model.DNSUpstreamGateway,
		IPv4:          model.DefaultGatewayDNSUpstreams(),
	}
	return state
}

type gatewayRepairFixture struct {
	dispatcher    *GatewayRepairDispatcher
	roles         *fakeGatewayRepairRoles
	watchdogUnits *fakeGatewayRepairWatchdogUnits
	watchdog      *fakeGatewayRepairWatchdog
	status        *fakeGatewayRepairWatchdogStore
	network       *fakeGatewayRepairNetwork
	events        *gatewayRepairEvents
}

func newGatewayRepairFixture(t *testing.T, state model.State) *gatewayRepairFixture {
	t.Helper()
	events := &gatewayRepairEvents{}
	request, err := linuxplatform.RenderGatewayRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	configNames := append([]string{routing.GatewayDNSConfigFileName, routing.GatewayDNSReadyFileName}, transport.GatewayListenerFileNames()...)
	for _, name := range configNames {
		request.Configs = append(request.Configs, linuxplatform.RoleConfigFile{Name: name, Content: []byte("rendered-secret:" + name + "\n")})
	}
	roles := &fakeGatewayRepairRoles{generation: state.Generation, request: request, events: events}
	initial := linuxplatform.NetworkSnapshot{
		SchemaVersion: linuxplatform.NetworkSnapshotSchemaVersion,
		Routes:        []linuxplatform.Route{}, PolicyRules: []linuxplatform.PolicyRule{}, Sysctls: []linuxplatform.SysctlSnapshot{},
	}
	status := &fakeGatewayRepairWatchdogStore{statuses: map[string]operations.WatchdogTransactionStatus{"fw-7K3M2P": operations.WatchdogStatusRolledBack}, initial: initial}
	watchdogUnits := &fakeGatewayRepairWatchdogUnits{events: events}
	watchdog := &fakeGatewayRepairWatchdog{events: events, network: initial}
	network := &fakeGatewayRepairNetwork{events: events}
	convergence := &fakeGatewayRepairConvergence{events: events}
	dispatcher, err := newGatewayRepairDispatcher(
		roles, convergence, watchdogUnits, watchdog, status, network, linuxplatform.DefaultVPNCTLBinaryPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	return &gatewayRepairFixture{dispatcher: dispatcher, roles: roles, watchdogUnits: watchdogUnits, watchdog: watchdog, status: status, network: network, events: events}
}

type gatewayRepairEvents struct{ values []string }

type fakeGatewayRepairCandidate struct {
	generation uint64
	request    linuxplatform.RoleInstallationRequest
	tunnel     bool
}

func (candidate *fakeGatewayRepairCandidate) Generation() uint64 { return candidate.generation }
func (candidate *fakeGatewayRepairCandidate) TunnelActive() bool { return candidate.tunnel }
func (candidate *fakeGatewayRepairCandidate) RoleRequest() linuxplatform.RoleInstallationRequest {
	result := candidate.request
	result.Units = append([]linuxplatform.RoleUnitFile(nil), candidate.request.Units...)
	result.Configs = append([]linuxplatform.RoleConfigFile(nil), candidate.request.Configs...)
	for index := range result.Units {
		result.Units[index].Content = append([]byte(nil), result.Units[index].Content...)
	}
	for index := range result.Configs {
		result.Configs[index].Content = append([]byte(nil), result.Configs[index].Content...)
	}
	return result
}
func (candidate *fakeGatewayRepairCandidate) Destroy() {}

type fakeGatewayRepairRoles struct {
	generation uint64
	request    linuxplatform.RoleInstallationRequest
	events     *gatewayRepairEvents
	compiles   int
	applies    int
}

func (roles *fakeGatewayRepairRoles) Compile(context.Context, model.State) (gatewayRepairRoleCandidate, error) {
	roles.compiles++
	return &fakeGatewayRepairCandidate{generation: roles.generation, request: roles.request}, nil
}
func (roles *fakeGatewayRepairRoles) Apply(context.Context, gatewayRepairRoleCandidate) error {
	roles.applies++
	roles.events.values = append(roles.events.values, "roles")
	return nil
}

type fakeGatewayRepairConvergence struct{ events *gatewayRepairEvents }

func (publisher *fakeGatewayRepairConvergence) PublishActiveGatewayGeneration(context.Context, uint64, linuxplatform.RoleInstallationRequest) error {
	publisher.events.values = append(publisher.events.values, "convergence-active")
	return nil
}
func (publisher *fakeGatewayRepairConvergence) PublishInactiveGatewayGeneration(context.Context, uint64, linuxplatform.RoleInstallationRequest) error {
	publisher.events.values = append(publisher.events.values, "convergence-inactive")
	return nil
}

type fakeGatewayRepairWatchdogUnits struct {
	events  *gatewayRepairEvents
	applies int
}

func (*fakeGatewayRepairWatchdogUnits) Plan(string) (linuxplatform.WatchdogUnitInstallationPlan, error) {
	units, err := linuxplatform.RenderWatchdogUnits(linuxplatform.DefaultVPNCTLBinaryPath)
	return linuxplatform.WatchdogUnitInstallationPlan{BinaryPath: linuxplatform.DefaultVPNCTLBinaryPath, Units: units}, err
}
func (units *fakeGatewayRepairWatchdogUnits) Apply(context.Context, linuxplatform.WatchdogUnitInstallationPlan) ([]string, error) {
	units.applies++
	units.events.values = append(units.events.values, "watchdog-units")
	return []string{}, nil
}

type fakeGatewayRepairWatchdog struct {
	events    *gatewayRepairEvents
	network   linuxplatform.NetworkSnapshot
	arms      int
	rollbacks int
}

func (watchdog *fakeGatewayRepairWatchdog) Arm(context.Context, operations.WatchdogArmInput) (operations.WatchdogTransaction, error) {
	watchdog.arms++
	watchdog.events.values = append(watchdog.events.values, "watchdog-arm")
	return operations.WatchdogTransaction{ID: "fw-7K3M2P", Network: watchdog.network}, nil
}
func (watchdog *fakeGatewayRepairWatchdog) MarkActivated(context.Context, string) error {
	watchdog.events.values = append(watchdog.events.values, "watchdog-activated")
	return nil
}
func (watchdog *fakeGatewayRepairWatchdog) RollbackNow(context.Context, string) error {
	watchdog.rollbacks++
	watchdog.events.values = append(watchdog.events.values, "watchdog-rollback")
	return nil
}

type fakeGatewayRepairWatchdogStore struct {
	statuses map[string]operations.WatchdogTransactionStatus
	initial  linuxplatform.NetworkSnapshot
}

func (store *fakeGatewayRepairWatchdogStore) TransactionIDs() ([]string, error) {
	result := make([]string, 0, len(store.statuses))
	for id := range store.statuses {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}
func (store *fakeGatewayRepairWatchdogStore) Status(id string) (operations.WatchdogTransactionStatus, error) {
	return store.statuses[id], nil
}
func (store *fakeGatewayRepairWatchdogStore) InitialNetworkSnapshot() (linuxplatform.NetworkSnapshot, error) {
	return store.initial, nil
}

type fakeGatewayRepairNetwork struct {
	events      *gatewayRepairEvents
	activations int
}

func (network *fakeGatewayRepairNetwork) ActivateGateway(context.Context, linuxplatform.GatewayFirewallArtifact) error {
	network.activations++
	network.events.values = append(network.events.values, "network")
	return nil
}
