package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestNodeInitAppliesUnjoinedRoleOnceAndSecondInitHasNoEffect(t *testing.T) {
	t.Parallel()

	harness := newNodeInitHarness(t)
	plan, err := harness.initializer.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if !plan.Changed || plan.AlreadyInitialized || plan.HostID != nodeTestHostID {
		t.Fatalf("fresh plan = %+v", plan)
	}
	wantUnits := []string{"vpnctl-routing-guard.service", "vpnctl-routing.service", "vpnctl-standard.service", "vpnctl-tunnel-client.service"}
	if !reflect.DeepEqual(plan.Units, wantUnits) {
		t.Fatalf("planned units = %v, want %v", plan.Units, wantUnits)
	}
	for _, root := range []string{harness.paths.ConfigDir, harness.paths.StateDir, harness.paths.RuntimeDir} {
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read-only plan created %s: %v", root, err)
		}
	}
	if harness.roles.applyCalls != 0 || harness.state.saveCalls != 0 {
		t.Fatal("read-only plan invoked a mutating dependency")
	}

	harness.events.values = nil
	result, err := harness.initializer.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !result.Changed || result.HostID != nodeTestHostID || !reflect.DeepEqual(result.Units, wantUnits) {
		t.Fatalf("Apply() result = %+v", result)
	}
	if want := []string{"state-load", "roles-apply", "state-save"}; !reflect.DeepEqual(harness.events.values, want) {
		t.Fatalf("apply events = %v, want %v", harness.events.values, want)
	}
	assertInitialUnjoinedNodeState(t, harness.state)
	assertNodeLayout(t, harness.paths, plan.layout)
	assertStagedNodeRoleRequest(t, harness.roles.lastApplied)

	secondPlan, err := harness.initializer.Plan(context.Background())
	if err != nil {
		t.Fatalf("second Plan() error = %v", err)
	}
	if secondPlan.Changed || !secondPlan.AlreadyInitialized || secondPlan.HostID != nodeTestHostID {
		t.Fatalf("second plan = %+v", secondPlan)
	}
	beforeApply := harness.roles.applyCalls
	harness.events.values = nil
	secondResult, err := harness.initializer.Apply(context.Background(), secondPlan)
	if err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	if secondResult.Changed || len(secondResult.Units) != 0 || harness.roles.applyCalls != beforeApply {
		t.Fatalf("second result/calls = %+v/%d", secondResult, harness.roles.applyCalls)
	}
	if !reflect.DeepEqual(harness.events.values, []string{"state-load"}) {
		t.Fatalf("second apply events = %v", harness.events.values)
	}
	if harness.idCalls != 1 {
		t.Fatalf("host identity allocations = %d", harness.idCalls)
	}
}

func TestNodeInitRejectsGatewayRoleBeforeMutation(t *testing.T) {
	t.Parallel()

	harness := newNodeInitHarness(t)
	harness.state.existing = initialGatewayState(
		gatewayTestHostID,
		time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC),
		linuxplatform.GatewayNetworkPlan{PublicIPv4: "8.8.8.8", ExternalInterface: "eth0", ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR},
		2222,
		gatewayTestManifest(),
		gatewayTestHandshakeHost(),
	)
	if _, err := harness.initializer.Plan(context.Background()); !errors.Is(err, ErrNodeRoleConflict) {
		t.Fatalf("Plan() error = %v", err)
	}
	if harness.roles.applyCalls != 0 || harness.state.saveCalls != 0 || harness.idCalls != 0 {
		t.Fatalf("role conflict mutated state: roles=%d saves=%d ids=%d", harness.roles.applyCalls, harness.state.saveCalls, harness.idCalls)
	}
	for _, root := range []string{harness.paths.ConfigDir, harness.paths.StateDir, harness.paths.RuntimeDir} {
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("role conflict created %s: %v", root, err)
		}
	}
}

func TestNodeInitUnsupportedHostMakesNoChange(t *testing.T) {
	t.Parallel()

	harness := newNodeInitHarness(t)
	harness.initializer.runtime.Snapshot.Capabilities.TUN = linuxplatform.Capability{Available: false, Detail: "missing"}
	if _, err := harness.initializer.Plan(context.Background()); !errors.Is(err, linuxplatform.ErrUnsupportedHost) {
		t.Fatalf("Plan() error = %v", err)
	}
	if harness.roles.planCalls != 0 || harness.roles.applyCalls != 0 || harness.state.saveCalls != 0 || harness.idCalls != 0 {
		t.Fatalf("unsupported host mutated/planned services: plans=%d applies=%d saves=%d ids=%d", harness.roles.planCalls, harness.roles.applyCalls, harness.state.saveCalls, harness.idCalls)
	}
}

func TestNodeInitRequiresDiscoveredDirectDNSBeforeMutation(t *testing.T) {
	t.Parallel()

	harness := newNodeInitHarness(t)
	harness.initializer.runtime.Snapshot.DNSResolversIPv4 = []string{}
	if _, err := harness.initializer.Plan(context.Background()); err == nil || !strings.Contains(err.Error(), "direct DNS") || !strings.Contains(err.Error(), "ipv4") {
		t.Fatalf("Plan() error = %v", err)
	}
	if harness.roles.planCalls != 0 || harness.roles.applyCalls != 0 || harness.state.saveCalls != 0 || harness.idCalls != 0 {
		t.Fatalf("missing DNS mutation/planning = plans:%d applies:%d saves:%d ids:%d", harness.roles.planCalls, harness.roles.applyCalls, harness.state.saveCalls, harness.idCalls)
	}
}

func TestNodeInitConcreteInstallerStagesNoGatewayOrActiveUnits(t *testing.T) {
	t.Parallel()

	root := newGatewaySystemRoot(t)
	paths, _ := store.NewPaths(root)
	foreignApplication := filepath.Join(root, "opt", "pet-project", "app")
	if err := os.MkdirAll(filepath.Dir(foreignApplication), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreignApplication, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stateStore, _ := store.NewStateStore(paths)
	layout, _ := NewNodeLayoutInstaller(paths)
	runner := &gatewayInitSystemdRunner{}
	roles, err := linuxplatform.NewRoleSystemdInstaller(root, paths.ConfigDir, runner)
	if err != nil {
		t.Fatal(err)
	}
	initializer, err := NewNodeInitializer(NodeInitRuntime{
		Paths: paths, Snapshot: validGatewaySnapshot(), Manifest: gatewayTestManifest(),
		State: stateStore, Layout: layout, Roles: roles,
		Now:       func() time.Time { return time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC) },
		NewHostID: func() (string, error) { return nodeTestHostID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := initializer.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initializer.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(root, "etc", "systemd", "system")
	for _, unit := range linuxplatform.RoleUnitNames(model.RoleNode) {
		if _, err := os.Stat(filepath.Join(unitDir, unit)); err != nil {
			t.Fatalf("node init did not install %s: %v", unit, err)
		}
	}
	for _, gatewayUnit := range []string{
		"vpnctl-controller.service", "vpnctl-dns.service", "vpnctl-restricted.service", "vpnctl-tunnel-server.service",
		linuxplatform.WatchdogServiceUnitName, linuxplatform.WatchdogTimerUnitName,
	} {
		if _, err := os.Lstat(filepath.Join(unitDir, gatewayUnit)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("node init installed gateway-only unit %s: %v", gatewayUnit, err)
		}
		if strings.Contains(strings.Join(runner.calls, "\n"), gatewayUnit) {
			t.Fatalf("node init invoked systemctl for gateway-only unit %s", gatewayUnit)
		}
	}
	if !reflect.DeepEqual(runner.calls, []string{"systemctl daemon-reload"}) {
		t.Fatalf("unjoined node systemctl calls = %v", runner.calls)
	}
	if _, err := os.Stat(filepath.Join(paths.ConfigDir, "generated", "node", "bootstrap.conf")); err != nil {
		t.Fatalf("node bootstrap config is missing: %v", err)
	}
	if data, err := os.ReadFile(foreignApplication); err != nil || string(data) != "keep\n" {
		t.Fatalf("foreign application changed: %q, %v", data, err)
	}
	assertInitialUnjoinedNodeState(t, stateStore)
	before := append([]string(nil), runner.calls...)
	second, err := initializer.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initializer.Apply(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner.calls, before) {
		t.Fatalf("second init changed systemd calls: before=%v after=%v", before, runner.calls)
	}
}

func TestNodeLayoutRefusesForeignVPNCTLRootAndPreservesApplications(t *testing.T) {
	t.Parallel()

	root := newGatewaySystemRoot(t)
	paths, _ := store.NewPaths(root)
	foreignApplication := filepath.Join(root, "opt", "pet-project", "app")
	if err := os.MkdirAll(filepath.Dir(foreignApplication), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreignApplication, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(paths.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(paths.ConfigDir, "foreign")
	if err := os.WriteFile(sentinel, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	layout, _ := NewNodeLayoutInstaller(paths)
	if _, err := layout.PlanFresh(); !errors.Is(err, ErrNodeLayoutConflict) {
		t.Fatalf("PlanFresh() error = %v", err)
	}
	for _, path := range []string{sentinel, foreignApplication} {
		if data, err := os.ReadFile(path); err != nil || string(data) != "keep\n" {
			t.Fatalf("foreign file %s changed: %q, %v", path, data, err)
		}
	}
}

const nodeTestHostID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

type nodeInitHarness struct {
	initializer *NodeInitializer
	paths       store.Paths
	state       *recordingNodeState
	roles       *recordingGatewayRoles
	events      *gatewayInitEvents
	idCalls     int
}

func newNodeInitHarness(t *testing.T) *nodeInitHarness {
	return newNodeInitHarnessWithRelease(t, nil)
}

func newNodeInitHarnessWithRelease(t *testing.T, release InitReleaseSource) *nodeInitHarness {
	t.Helper()
	root := newGatewaySystemRoot(t)
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := NewNodeLayoutInstaller(paths)
	if err != nil {
		t.Fatal(err)
	}
	events := &gatewayInitEvents{}
	state := &recordingNodeState{store: stateStore, events: events}
	roles := &recordingGatewayRoles{events: events, root: root}
	harness := &nodeInitHarness{paths: paths, state: state, roles: roles, events: events}
	initializer, err := NewNodeInitializer(NodeInitRuntime{
		Paths: paths, Snapshot: validGatewaySnapshot(), Manifest: gatewayTestManifest(), Release: release,
		State: state, Layout: layout, Roles: roles,
		Now:       func() time.Time { return time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC) },
		NewHostID: func() (string, error) { harness.idCalls++; return nodeTestHostID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.initializer = initializer
	return harness
}

type recordingNodeState struct {
	store     *store.StateStore
	events    *gatewayInitEvents
	existing  model.State
	saveCalls int
}

func (state *recordingNodeState) Load() (model.State, error) {
	state.events.add("state-load")
	if state.existing.SchemaVersion != 0 {
		return state.existing, nil
	}
	return state.store.Load()
}

func (state *recordingNodeState) Save(expected uint64, candidate model.State) error {
	state.events.add("state-save")
	state.saveCalls++
	return state.store.Save(expected, candidate)
}

func assertInitialUnjoinedNodeState(t *testing.T, stateStore NodeInitStateStore) {
	t.Helper()
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != 1 || state.Host.ID != nodeTestHostID || state.Host.Role != model.RoleNode {
		t.Fatalf("initial node state = %+v", state)
	}
	if state.Host.PublicIPv4 != "" || state.Host.ExternalInterface != "" || state.Host.SSHPort != 0 || state.Host.ClientCIDR != "" || state.Host.NodeCIDR != "" {
		t.Fatalf("node state contains gateway-only host fields: %+v", state.Host)
	}
	if len(state.Nodes) != 0 || len(state.Transports) != 0 || len(state.Certificates) != 0 || len(state.Policies) != 0 || len(state.Exposes) != 0 {
		t.Fatalf("unjoined node contains enrollment or data-plane resources: nodes=%v transports=%v certs=%v policies=%v exposes=%v", state.Nodes, state.Transports, state.Certificates, state.Policies, state.Exposes)
	}
	if state.Nodes == nil || state.Transports == nil || state.Certificates == nil {
		t.Fatal("unjoined node resource collections are not explicit empty arrays")
	}
	if state.DNS == nil || state.DNS.Scope != model.DNSUpstreamDirect || !reflect.DeepEqual(state.DNS.IPv4, []string{"198.18.0.2"}) {
		t.Fatalf("initial node direct DNS state = %+v", state.DNS)
	}
}

func assertNodeLayout(t *testing.T, paths store.Paths, plan NodeLayoutPlan) {
	t.Helper()
	for _, directory := range plan.Directories {
		info, err := os.Stat(directory.Path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != directory.Mode {
			t.Fatalf("node directory %s = %v, %v", directory.Path, info, err)
		}
	}
	for _, gatewayOnly := range []string{paths.PresetsDir, paths.ExportsDir, paths.BackupsDir, paths.WatchdogDir} {
		if _, err := os.Lstat(gatewayOnly); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("node init created gateway-only path %s: %v", gatewayOnly, err)
		}
	}
	entries, err := os.ReadDir(paths.SecretsDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unjoined node secrets = %v, %v", entries, err)
	}
}

func assertStagedNodeRoleRequest(t *testing.T, request linuxplatform.RoleInstallationRequest) {
	t.Helper()
	if request.Role != model.RoleNode {
		t.Fatalf("installed role = %s", request.Role)
	}
	for _, unit := range request.Units {
		if unit.Enable || unit.Start {
			t.Fatalf("unjoined node unit %s is active: enable=%t start=%t", unit.Name, unit.Enable, unit.Start)
		}
		if strings.Contains(unit.Name, "controller") || strings.Contains(unit.Name, "restricted") || strings.Contains(unit.Name, "tunnel-server") || strings.Contains(unit.Name, "dns") {
			t.Fatalf("node init installed gateway-only unit %s", unit.Name)
		}
	}
}
