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

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestGatewayInitAppliesOnceAndSecondIdenticalInitHasNoEffect(t *testing.T) {
	t.Parallel()

	harness := newGatewayInitHarness(t)
	input := validGatewayInitInput()
	plan, err := harness.initializer.Plan(context.Background(), input)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if !plan.Changed || plan.AlreadyInitialized {
		t.Fatalf("fresh plan flags = changed:%t already:%t", plan.Changed, plan.AlreadyInitialized)
	}
	if plan.Network.ClientCIDR != model.DefaultClientCIDR || plan.Network.NodeCIDR != model.DefaultNodeCIDR || plan.Network.ExternalInterface != "eth0" {
		t.Fatalf("fresh network plan = %+v", plan.Network)
	}
	if plan.SSH.Port != 2222 || plan.SSH.Source != linuxplatform.SSHPortFromConnection {
		t.Fatalf("fresh SSH plan = %+v", plan.SSH)
	}
	if !reflect.DeepEqual(plan.FixedListeners, []string{"443/tcp", "8443/tcp", "51820/udp"}) {
		t.Fatalf("fixed listeners = %v", plan.FixedListeners)
	}
	firewall := string(plan.firewall.Definition())
	if !strings.Contains(firewall, "elements = { 9443 }") ||
		!strings.Contains(firewall, `iifname "vpnctl-wg" ip saddr @node_v4 tcp dport @node_tcp_ports accept`) ||
		strings.Contains(firewall, "ip saddr 0.0.0.0/0 tcp dport 9443 accept") {
		t.Fatalf("control RPC firewall scope is not node-overlay-only:\n%s", firewall)
	}
	if _, err := os.Lstat(harness.paths.ConfigDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only plan created config root: %v", err)
	}
	if harness.watchdog.armCalls != 0 || harness.network.calls != 0 || harness.roles.applyCalls != 0 || harness.watchdogUnits.applyCalls != 0 {
		t.Fatalf("read-only plan mutated dependencies")
	}

	harness.events.values = nil
	result, err := harness.initializer.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if !result.Changed || result.HostID != gatewayTestHostID || result.TransactionID != "fw-ABC123" {
		t.Fatalf("Apply() result = %+v", result)
	}
	wantEvents := []string{"state-load", "identity-provision", "watchdog-units-apply", "watchdog-arm", "state-save", "roles-apply", "network-activate", "watchdog-mark"}
	if !reflect.DeepEqual(harness.events.values, wantEvents) {
		t.Fatalf("apply events = %v, want %v", harness.events.values, wantEvents)
	}
	if harness.watchdog.lastArm.AllowedSSHPort != 2222 || harness.watchdog.lastArm.Origin == nil || harness.watchdog.lastArm.Origin.ServerPort != 2222 {
		t.Fatalf("watchdog arm input = %+v", harness.watchdog.lastArm)
	}
	if harness.identity.lastRequest.GatewayID != gatewayTestHostID || harness.identity.lastRequest.NodeCIDR != model.DefaultNodeCIDR ||
		!harness.identity.lastRequest.Initialized.Equal(time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC)) {
		t.Fatalf("identity provision request = %+v", harness.identity.lastRequest)
	}
	if !reflect.DeepEqual(harness.watchdog.lastArm.NetworkScope, linuxplatform.GatewayInitNetworkScope()) {
		t.Fatalf("watchdog scope = %+v", harness.watchdog.lastArm.NetworkScope)
	}
	assertInitialGatewayState(t, harness.state)
	assertGatewayLayout(t, plan.layout)
	assertGatewayRoleRequest(t, harness.roles.lastApplied)

	harness.events.values = nil
	secondPlan, err := harness.initializer.Plan(context.Background(), input)
	if err != nil {
		t.Fatalf("second Plan() error = %v", err)
	}
	if secondPlan.Changed || !secondPlan.AlreadyInitialized || secondPlan.HostID != gatewayTestHostID {
		t.Fatalf("second plan = %+v", secondPlan)
	}
	beforeArm, beforeNetwork, beforeRoles, beforeWatchdogUnits := harness.watchdog.armCalls, harness.network.calls, harness.roles.applyCalls, harness.watchdogUnits.applyCalls
	harness.events.values = nil
	secondResult, err := harness.initializer.Apply(context.Background(), secondPlan)
	if err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	if secondResult.Changed || secondResult.TransactionID != "" {
		t.Fatalf("second result = %+v", secondResult)
	}
	if harness.watchdog.armCalls != beforeArm || harness.network.calls != beforeNetwork || harness.roles.applyCalls != beforeRoles || harness.watchdogUnits.applyCalls != beforeWatchdogUnits {
		t.Fatalf("second init invoked a mutating dependency")
	}
	if !reflect.DeepEqual(harness.events.values, []string{"state-load"}) {
		t.Fatalf("second apply events = %v", harness.events.values)
	}
}

func TestGatewayInitRejectsInvalidOrChangedInputBeforeMutation(t *testing.T) {
	t.Parallel()

	t.Run("missing public IP", func(t *testing.T) {
		harness := newGatewayInitHarness(t)
		input := validGatewayInitInput()
		input.PublicIPv4 = ""
		if _, err := harness.initializer.Plan(context.Background(), input); !errors.Is(err, linuxplatform.ErrInvalidGatewayNetwork) {
			t.Fatalf("Plan() error = %v", err)
		}
		assertNoGatewayInitMutation(t, harness)
		if harness.idCalls != 0 {
			t.Fatalf("invalid plan allocated %d host identities", harness.idCalls)
		}
	})

	t.Run("changed existing endpoint", func(t *testing.T) {
		harness := newGatewayInitHarness(t)
		plan, err := harness.initializer.Plan(context.Background(), validGatewayInitInput())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := harness.initializer.Apply(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		beforeArm, beforeNetwork, beforeRoles, beforeWatchdogUnits := harness.watchdog.armCalls, harness.network.calls, harness.roles.applyCalls, harness.watchdogUnits.applyCalls
		changed := validGatewayInitInput()
		changed.PublicIPv4 = "8.8.4.4"
		if _, err := harness.initializer.Plan(context.Background(), changed); !errors.Is(err, ErrGatewayInitConflict) {
			t.Fatalf("changed Plan() error = %v", err)
		}
		if harness.watchdog.armCalls != beforeArm || harness.network.calls != beforeNetwork || harness.roles.applyCalls != beforeRoles || harness.watchdogUnits.applyCalls != beforeWatchdogUnits {
			t.Fatal("changed repeat init mutated dependencies")
		}
	})
}

func TestGatewayInitPreflightConflictDoesNotAllocateIdentityOrMutate(t *testing.T) {
	t.Parallel()

	harness := newGatewayInitHarness(t)
	harness.initializer.runtime.Snapshot.Listeners = append(harness.initializer.runtime.Snapshot.Listeners,
		linuxplatform.Listener{Protocol: "tcp", Address: "0.0.0.0", Port: 443, Process: "nginx"})
	if _, err := harness.initializer.Plan(context.Background(), validGatewayInitInput()); !errors.Is(err, linuxplatform.ErrGatewayPreflightConflict) {
		t.Fatalf("Plan() error = %v", err)
	}
	assertNoGatewayInitMutation(t, harness)
	if harness.idCalls != 0 {
		t.Fatalf("conflicting plan allocated %d host identities", harness.idCalls)
	}
}

func TestGatewayInitNetworkFailureRequestsImmediateWatchdogRollback(t *testing.T) {
	t.Parallel()

	harness := newGatewayInitHarness(t)
	harness.network.err = errors.New("synthetic activation failure")
	plan, err := harness.initializer.Plan(context.Background(), validGatewayInitInput())
	if err != nil {
		t.Fatal(err)
	}
	harness.events.values = nil
	if _, err := harness.initializer.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "synthetic activation failure") {
		t.Fatalf("Apply() error = %v", err)
	}
	want := []string{"state-load", "identity-provision", "watchdog-units-apply", "watchdog-arm", "state-save", "roles-apply", "network-activate", "watchdog-rollback"}
	if !reflect.DeepEqual(harness.events.values, want) {
		t.Fatalf("failure events = %v, want %v", harness.events.values, want)
	}
	if harness.watchdog.rollbackID != "fw-ABC123" || harness.watchdog.markCalls != 0 {
		t.Fatalf("watchdog failure handling = rollback:%q marks:%d", harness.watchdog.rollbackID, harness.watchdog.markCalls)
	}
	if harness.identity.rollbackCalls != 0 {
		t.Fatalf("persisted control identity was rolled back: %d", harness.identity.rollbackCalls)
	}
}

func TestGatewayInitIdentityFailureStopsBeforeWatchdogAndState(t *testing.T) {
	t.Parallel()

	harness := newGatewayInitHarness(t)
	harness.identity.err = errors.New("synthetic identity failure")
	plan, err := harness.initializer.Plan(context.Background(), validGatewayInitInput())
	if err != nil {
		t.Fatal(err)
	}
	harness.events.values = nil
	if _, err := harness.initializer.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "synthetic identity failure") {
		t.Fatalf("Apply() error = %v", err)
	}
	if !reflect.DeepEqual(harness.events.values, []string{"state-load", "identity-provision"}) {
		t.Fatalf("identity failure events = %v", harness.events.values)
	}
	if harness.watchdogUnits.applyCalls != 0 || harness.watchdog.armCalls != 0 || harness.state.saveCalls != 0 || harness.roles.applyCalls != 0 || harness.network.calls != 0 {
		t.Fatal("identity failure crossed the state/network mutation boundary")
	}
}

func TestGatewayInitManagedSwapAcceptDeclineAndCapacityBranches(t *testing.T) {
	t.Parallel()

	t.Run("accept", func(t *testing.T) {
		harness := newGatewayInitHarness(t)
		harness.initializer.runtime.Snapshot.Resources = lowMemoryGatewayResources()
		harness.swap.plan = offeredGatewaySwapPlan(harness.paths)
		plan, err := harness.initializer.Plan(context.Background(), validGatewayInitInput())
		if err != nil || !plan.ManagedSwap.Offered || plan.ManagedSwapSelected {
			t.Fatalf("Plan() = %+v, %v", plan.ManagedSwap, err)
		}
		plan, err = plan.SelectManagedSwap(true)
		if err != nil || !plan.ManagedSwapSelected || plan.desiredState.Host.ManagedSwap == nil {
			t.Fatalf("SelectManagedSwap(true) = %+v, %v", plan, err)
		}
		harness.events.values = nil
		if _, err := harness.initializer.Apply(context.Background(), plan); err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
		want := []string{"state-load", "identity-provision", "watchdog-units-apply", "watchdog-arm", "swap-apply", "state-save", "roles-apply", "network-activate", "watchdog-mark"}
		if !reflect.DeepEqual(harness.events.values, want) {
			t.Fatalf("accept events = %v, want %v", harness.events.values, want)
		}
		state, err := harness.state.Load()
		if err != nil || state.Host.ManagedSwap == nil || !state.Host.ManagedSwap.Enabled || state.Host.ManagedSwap.Path != linuxplatform.ManagedSwapLogicalPath || state.Host.ManagedSwap.SizeBytes != int64(linuxplatform.ManagedSwapSizeBytes) {
			t.Fatalf("managed swap state = %+v, %v", state.Host.ManagedSwap, err)
		}
		second, err := harness.initializer.Plan(context.Background(), validGatewayInitInput())
		if err != nil || second.ManagedSwap.Disposition != linuxplatform.ManagedSwapAlreadyOwnedEnabled {
			t.Fatalf("repeat swap status = %+v, %v", second.ManagedSwap, err)
		}
		if _, err := harness.initializer.Apply(context.Background(), second); err != nil {
			t.Fatal(err)
		}
		if harness.swap.applyCalls != 1 {
			t.Fatalf("repeat init recreated swap: %d calls", harness.swap.applyCalls)
		}
	})

	t.Run("decline", func(t *testing.T) {
		harness := newGatewayInitHarness(t)
		harness.initializer.runtime.Snapshot.Resources = lowMemoryGatewayResources()
		harness.swap.plan = offeredGatewaySwapPlan(harness.paths)
		plan, err := harness.initializer.Plan(context.Background(), validGatewayInitInput())
		if err != nil {
			t.Fatal(err)
		}
		plan, err = plan.SelectManagedSwap(false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := harness.initializer.Apply(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		state, err := harness.state.Load()
		if err != nil || state.Host.ManagedSwap != nil || harness.swap.applyCalls != 0 {
			t.Fatalf("declined swap state/calls = %+v/%d, %v", state.Host.ManagedSwap, harness.swap.applyCalls, err)
		}
	})

	for _, test := range []struct {
		name        string
		disposition linuxplatform.ManagedSwapDisposition
	}{
		{name: "existing adequate", disposition: linuxplatform.ManagedSwapExistingAdequate},
		{name: "insufficient disk", disposition: linuxplatform.ManagedSwapInsufficientDisk},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			harness := newGatewayInitHarness(t)
			harness.swap.plan = linuxplatform.ManagedSwapPlan{
				Disposition: test.disposition, Path: linuxplatform.ManagedSwapLogicalPath,
				SizeBytes: linuxplatform.ManagedSwapSizeBytes, DiskReserve: linuxplatform.ManagedSwapDiskReserve,
			}
			plan, err := harness.initializer.Plan(context.Background(), validGatewayInitInput())
			if err != nil || plan.ManagedSwap.Offered {
				t.Fatalf("Plan() swap = %+v, %v", plan.ManagedSwap, err)
			}
			if _, err := harness.initializer.Apply(context.Background(), plan); err != nil {
				t.Fatal(err)
			}
			state, err := harness.state.Load()
			if err != nil || state.Host.ManagedSwap != nil || harness.swap.applyCalls != 0 {
				t.Fatalf("unavailable/existing state/calls = %+v/%d, %v", state.Host.ManagedSwap, harness.swap.applyCalls, err)
			}
		})
	}
}

func TestGatewayInitStateFailurePurgesNewManagedSwap(t *testing.T) {
	t.Parallel()

	harness := newGatewayInitHarness(t)
	harness.initializer.runtime.Snapshot.Resources = lowMemoryGatewayResources()
	harness.swap.plan = offeredGatewaySwapPlan(harness.paths)
	plan, err := harness.initializer.Plan(context.Background(), validGatewayInitInput())
	if err != nil {
		t.Fatal(err)
	}
	plan, err = plan.SelectManagedSwap(true)
	if err != nil {
		t.Fatal(err)
	}
	harness.state.saveErr = errors.New("synthetic state failure")
	harness.events.values = nil
	if _, err := harness.initializer.Apply(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "synthetic state failure") {
		t.Fatalf("Apply() error = %v", err)
	}
	want := []string{"state-load", "identity-provision", "watchdog-units-apply", "watchdog-arm", "swap-apply", "state-save", "watchdog-rollback", "swap-deactivate", "identity-rollback"}
	if !reflect.DeepEqual(harness.events.values, want) {
		t.Fatalf("rollback events = %v, want %v", harness.events.values, want)
	}
	if harness.swap.deactivateCalls != 1 {
		t.Fatalf("swap rollback calls = %d", harness.swap.deactivateCalls)
	}
	if harness.identity.rollbackCalls != 1 {
		t.Fatalf("identity rollback calls = %d", harness.identity.rollbackCalls)
	}
}

func TestGatewayInitConcreteInstallersWriteNoNodeUnits(t *testing.T) {
	t.Parallel()

	root := newGatewaySystemRoot(t)
	paths, _ := store.NewPaths(root)
	stateStore, _ := store.NewStateStore(paths)
	secretStore, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := control.NewGatewayIdentityProvisioner(secretStore, control.GatewayIdentityRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	layout, _ := NewGatewayLayoutInstaller(paths)
	runner := &gatewayInitSystemdRunner{}
	roles, err := linuxplatform.NewRoleSystemdInstaller(root, paths.ConfigDir, runner)
	if err != nil {
		t.Fatal(err)
	}
	watchdogUnits, err := linuxplatform.NewWatchdogUnitInstaller(root, runner)
	if err != nil {
		t.Fatal(err)
	}
	events := &gatewayInitEvents{}
	watchdog := &recordingGatewayWatchdog{events: events}
	network := &recordingGatewayNetwork{events: events}
	initializer, err := NewGatewayInitializer(GatewayInitRuntime{
		Paths: paths, Snapshot: validGatewaySnapshot(), Manifest: gatewayTestManifest(),
		State: stateStore, Layout: layout, Roles: roles, WatchdogUnits: watchdogUnits,
		Watchdog: watchdog, Network: network, Swap: &recordingGatewaySwap{}, Identity: identity,
		Now:       func() time.Time { return time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC) },
		NewHostID: func() (string, error) { return gatewayTestHostID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := initializer.Plan(context.Background(), validGatewayInitInput())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initializer.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Join(root, "etc", "systemd", "system")
	for _, unit := range append(linuxplatform.RoleUnitNames(model.RoleGateway), linuxplatform.WatchdogServiceUnitName, linuxplatform.WatchdogTimerUnitName) {
		if _, err := os.Stat(filepath.Join(unitDir, unit)); err != nil {
			t.Fatalf("gateway init did not install %s: %v", unit, err)
		}
	}
	for _, nodeUnit := range []string{"vpnctl-routing.service", "vpnctl-tunnel-client.service"} {
		if _, err := os.Lstat(filepath.Join(unitDir, nodeUnit)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("gateway init installed node unit %s: %v", nodeUnit, err)
		}
		if strings.Contains(strings.Join(runner.calls, "\n"), nodeUnit) {
			t.Fatalf("gateway init invoked systemctl for node unit %s", nodeUnit)
		}
	}
	if _, err := os.Stat(filepath.Join(paths.ConfigDir, "generated", "gateway", "bootstrap.conf")); err != nil {
		t.Fatalf("gateway bootstrap config is missing: %v", err)
	}
	if info, err := os.Stat(filepath.Join(paths.ConfigDir, "generated", "gateway", "gateway-controller.ready")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("gateway controller readiness marker = %v, %v", info, err)
	}
	for _, reference := range []model.SecretRef{
		model.SecretRef(control.ControlCACertificateRef), control.ControlCAPrivateKeyRef,
		model.SecretRef(control.GatewayControlCertificateRef), control.GatewayControlPrivateKeyRef,
		model.SecretRef(control.EnrollmentPublicKeyRef), control.EnrollmentPrivateKeyRef,
	} {
		content, err := secretStore.Get(reference)
		if err != nil || len(content) == 0 {
			t.Fatalf("gateway init identity %s = %d bytes, %v", reference, len(content), err)
		}
		kind, id, err := reference.Parts()
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(paths.SecretsDir, kind, id))
		if err != nil || info.Mode().Perm() != store.SecretFileMode {
			t.Fatalf("gateway init identity mode %s = %v, %v", reference, info, err)
		}
	}
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Certificates) != 2 || state.EnrollmentIdentity == nil ||
		state.Certificates[0].Kind != model.CertificateControlCA || state.Certificates[1].Kind != model.CertificateControlServer {
		t.Fatalf("gateway init identity state = certificates:%+v enrollment:%+v", state.Certificates, state.EnrollmentIdentity)
	}
	for _, certificate := range state.Certificates {
		if certificate.Kind == model.CertificatePublicIngress {
			t.Fatalf("gateway init conflated control and public ingress identities: %+v", certificate)
		}
	}
	before := append([]string(nil), runner.calls...)
	second, err := initializer.Plan(context.Background(), validGatewayInitInput())
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

func TestGatewayLayoutRefusesForeignRootWithoutMutation(t *testing.T) {
	t.Parallel()

	root := newGatewaySystemRoot(t)
	paths, _ := store.NewPaths(root)
	if err := os.Mkdir(paths.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(paths.ConfigDir, "foreign")
	if err := os.WriteFile(sentinel, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	layout, _ := NewGatewayLayoutInstaller(paths)
	if _, err := layout.PlanFresh(); !errors.Is(err, ErrGatewayLayoutConflict) {
		t.Fatalf("PlanFresh() error = %v", err)
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep\n" {
		t.Fatalf("foreign sentinel changed: %q, %v", data, err)
	}
	if _, err := os.Lstat(paths.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign conflict created state root: %v", err)
	}
}

const gatewayTestHostID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

type gatewayInitHarness struct {
	initializer   *GatewayInitializer
	paths         store.Paths
	state         *recordingGatewayState
	roles         *recordingGatewayRoles
	watchdogUnits *recordingWatchdogUnits
	watchdog      *recordingGatewayWatchdog
	network       *recordingGatewayNetwork
	swap          *recordingGatewaySwap
	identity      *recordingGatewayIdentity
	events        *gatewayInitEvents
	idCalls       int
}

func newGatewayInitHarness(t *testing.T) *gatewayInitHarness {
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
	layout, err := NewGatewayLayoutInstaller(paths)
	if err != nil {
		t.Fatal(err)
	}
	events := &gatewayInitEvents{}
	state := &recordingGatewayState{store: stateStore, events: events}
	roles := &recordingGatewayRoles{events: events, root: root}
	watchdogUnits := &recordingWatchdogUnits{events: events, root: root}
	watchdog := &recordingGatewayWatchdog{events: events}
	network := &recordingGatewayNetwork{events: events}
	swap := &recordingGatewaySwap{events: events}
	identity := newRecordingGatewayIdentity(events)
	harness := &gatewayInitHarness{paths: paths, state: state, roles: roles, watchdogUnits: watchdogUnits, watchdog: watchdog, network: network, swap: swap, identity: identity, events: events}
	runtime := GatewayInitRuntime{
		Paths: paths, Snapshot: validGatewaySnapshot(), Manifest: gatewayTestManifest(),
		State: state, Layout: layout, Roles: roles, WatchdogUnits: watchdogUnits, Watchdog: watchdog, Network: network, Swap: swap, Identity: identity,
		Now:       func() time.Time { return time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC) },
		NewHostID: func() (string, error) { harness.idCalls++; return gatewayTestHostID, nil },
	}
	initializer, err := NewGatewayInitializer(runtime)
	if err != nil {
		t.Fatal(err)
	}
	harness.initializer = initializer
	return harness
}

func newGatewaySystemRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, path := range []string{
		filepath.Join(root, "etc"), filepath.Join(root, "etc", "systemd", "system"),
		filepath.Join(root, "var"), filepath.Join(root, "var", "lib"), filepath.Join(root, "run"),
	} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func validGatewayInitInput() GatewayInitInput {
	return GatewayInitInput{
		PublicIPv4:    "8.8.8.8",
		SSHConnection: "1.1.1.1 54321 8.8.8.8 2222",
	}
}

func validGatewaySnapshot() linuxplatform.HostSnapshot {
	available := linuxplatform.Capability{Available: true, Detail: "test"}
	return linuxplatform.HostSnapshot{
		SchemaVersion: linuxplatform.HostSnapshotSchemaVersion,
		OS:            linuxplatform.OSRelease{ID: "ubuntu", VersionID: "24.04"}, KernelOS: "linux", Architecture: "amd64", EffectiveUID: 0,
		Capabilities: linuxplatform.Capabilities{
			Linux: available, AMD64: available, Ubuntu2404: available, Root: available, Systemd: available,
			TUN: available, KernelWireGuard: available, NFTables: available, PolicyRouting: available,
			ConntrackMarks: available, SystemdResolved: available, IPv4Forwarding: available,
		},
		Interfaces: []linuxplatform.NetworkInterface{{
			Index: 2, Name: "eth0", Type: "ether", State: "UP", MTU: 1500, Flags: []string{"UP"},
			Addresses: []linuxplatform.InterfaceAddress{{Family: "inet", Address: "8.8.8.8", PrefixLen: 24, Scope: "global"}},
		}},
		Routes:      []linuxplatform.Route{{Family: "ipv4", Destination: "default", Gateway: "8.8.8.1", Device: "eth0", Table: "main"}},
		PolicyRules: []linuxplatform.PolicyRule{}, ContainerNetworks: []linuxplatform.ContainerNetwork{},
		Listeners:      []linuxplatform.Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 2222, Process: `users:(("sshd",pid=100,fd=3))`}},
		NFTablesTables: []linuxplatform.NFTablesTable{},
		Services: []linuxplatform.Service{
			{Name: "systemd-resolved.service", LoadState: "loaded", ActiveState: "active"},
			{Name: "ufw.service", LoadState: "loaded", ActiveState: "inactive"},
			{Name: "firewalld.service", LoadState: "not-found", ActiveState: "inactive"},
		},
		ProbeIssues: []linuxplatform.ProbeIssue{},
	}
}

func gatewayTestManifest() model.ComponentManifest {
	return model.ComponentManifest{
		SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0-dev",
		ControlProtocols: []string{"1.0"}, StateSchemaMinimum: 1, StateSchemaMaximum: 1,
		TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1, MigrationReversible: true,
		Components: []model.ComponentPin{{
			Name: "vpnctl", Version: "v2.0.0-dev", Source: "bundle:vpnctl", Bundled: true,
			SHA256: strings.Repeat("a", 64), Capabilities: []string{"cli", "controller"},
		}},
	}
}

func assertInitialGatewayState(t *testing.T, stateStore GatewayInitStateStore) {
	t.Helper()
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != 1 || state.Host.ID != gatewayTestHostID || state.Host.Role != model.RoleGateway ||
		state.Host.PublicIPv4 != "8.8.8.8" || state.Host.ClientCIDR != model.DefaultClientCIDR || state.Host.NodeCIDR != model.DefaultNodeCIDR ||
		state.Host.ExternalInterface != "eth0" || state.Host.SSHPort != 2222 {
		t.Fatalf("initial gateway state = %+v", state)
	}
	if state.Presets == nil || len(state.Presets) != 0 || len(state.Certificates) != 2 || state.EnrollmentIdentity == nil {
		t.Fatalf("initial PKI state = presets:%v certificates:%v enrollment:%v", state.Presets, state.Certificates, state.EnrollmentIdentity)
	}
	if state.Certificates[0].Kind != model.CertificateControlCA || state.Certificates[1].Kind != model.CertificateControlServer || state.EnrollmentIdentity.Algorithm != "Ed25519" {
		t.Fatalf("initial control identity metadata = certificates:%v enrollment:%v", state.Certificates, state.EnrollmentIdentity)
	}
}

func assertGatewayLayout(t *testing.T, plan GatewayLayoutPlan) {
	t.Helper()
	for _, directory := range plan.Directories {
		info, err := os.Stat(directory.Path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != directory.Mode {
			t.Fatalf("gateway directory %s = %v, %v", directory.Path, info, err)
		}
	}
	for _, placeholder := range plan.PKIPlaceholders {
		if info, err := os.Stat(placeholder); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("PKI placeholder %s = %v, %v", placeholder, info, err)
		}
	}
}

func assertGatewayRoleRequest(t *testing.T, request linuxplatform.RoleInstallationRequest) {
	t.Helper()
	if request.Role != model.RoleGateway {
		t.Fatalf("installed role = %s", request.Role)
	}
	for _, unit := range request.Units {
		if unit.Name == "vpnctl-routing.service" || unit.Name == "vpnctl-tunnel-client.service" {
			t.Fatalf("gateway init installed node unit %s", unit.Name)
		}
		if !unit.Start || !strings.Contains(string(unit.Content), "Restart=on-failure") {
			t.Fatalf("gateway unit %s activation/content is invalid", unit.Name)
		}
	}
}

func assertNoGatewayInitMutation(t *testing.T, harness *gatewayInitHarness) {
	t.Helper()
	if harness.watchdog.armCalls != 0 || harness.network.calls != 0 || harness.roles.applyCalls != 0 || harness.watchdogUnits.applyCalls != 0 || harness.state.saveCalls != 0 || harness.swap.applyCalls != 0 || harness.identity.provisionCalls != 0 {
		t.Fatalf("unexpected mutation: watchdog=%d network=%d roles=%d watchdog_units=%d state=%d swap=%d identity=%d", harness.watchdog.armCalls, harness.network.calls, harness.roles.applyCalls, harness.watchdogUnits.applyCalls, harness.state.saveCalls, harness.swap.applyCalls, harness.identity.provisionCalls)
	}
	for _, path := range []string{harness.paths.ConfigDir, harness.paths.StateDir, harness.paths.RuntimeDir} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected path %s: %v", path, err)
		}
	}
}

type gatewayInitEvents struct{ values []string }

func (events *gatewayInitEvents) add(value string) { events.values = append(events.values, value) }

type recordingGatewayState struct {
	store     *store.StateStore
	events    *gatewayInitEvents
	saveCalls int
	saveErr   error
}

func (state *recordingGatewayState) Load() (model.State, error) {
	state.events.add("state-load")
	return state.store.Load()
}

func (state *recordingGatewayState) Save(expected uint64, candidate model.State) error {
	state.events.add("state-save")
	state.saveCalls++
	if state.saveErr != nil {
		return state.saveErr
	}
	return state.store.Save(expected, candidate)
}

type recordingGatewayRoles struct {
	events      *gatewayInitEvents
	root        string
	planCalls   int
	applyCalls  int
	lastApplied linuxplatform.RoleInstallationRequest
}

func (roles *recordingGatewayRoles) Plan(request linuxplatform.RoleInstallationRequest) (linuxplatform.RoleInstallationPlan, error) {
	roles.planCalls++
	unitFiles := make([]string, len(request.Units))
	enable := make([]string, 0, len(request.Units))
	start := make([]string, 0, len(request.Units))
	for index, unit := range request.Units {
		unitFiles[index] = filepath.Join(roles.root, "etc", "systemd", "system", unit.Name)
		if unit.Enable {
			enable = append(enable, unit.Name)
		}
		if unit.Start {
			start = append(start, unit.Name)
		}
	}
	return linuxplatform.RoleInstallationPlan{Role: request.Role, UnitFiles: unitFiles, UnitsToEnable: enable, UnitsToStart: start}, nil
}

func (roles *recordingGatewayRoles) Apply(_ context.Context, request linuxplatform.RoleInstallationRequest) (linuxplatform.RoleInstallationResult, error) {
	roles.events.add("roles-apply")
	roles.applyCalls++
	roles.lastApplied = request
	plan, _ := roles.Plan(request)
	return linuxplatform.RoleInstallationResult{Plan: plan}, nil
}

type recordingWatchdogUnits struct {
	events     *gatewayInitEvents
	root       string
	applyCalls int
}

func (units *recordingWatchdogUnits) Plan(binaryPath string) (linuxplatform.WatchdogUnitInstallationPlan, error) {
	rendered, err := linuxplatform.RenderWatchdogUnits(binaryPath)
	if err != nil {
		return linuxplatform.WatchdogUnitInstallationPlan{}, err
	}
	files := make([]string, len(rendered))
	for index, unit := range rendered {
		files[index] = filepath.Join(units.root, "etc", "systemd", "system", unit.Name)
	}
	return linuxplatform.WatchdogUnitInstallationPlan{BinaryPath: binaryPath, UnitFiles: files, Units: rendered}, nil
}

func (units *recordingWatchdogUnits) Apply(_ context.Context, plan linuxplatform.WatchdogUnitInstallationPlan) ([]string, error) {
	units.events.add("watchdog-units-apply")
	units.applyCalls++
	return append([]string(nil), plan.UnitFiles...), nil
}

type recordingGatewayWatchdog struct {
	events     *gatewayInitEvents
	armCalls   int
	markCalls  int
	lastArm    GatewayInitWatchdogArm
	rollbackID string
}

func (watchdog *recordingGatewayWatchdog) Arm(_ context.Context, input GatewayInitWatchdogArm) (GatewayInitWatchdogTransaction, error) {
	watchdog.events.add("watchdog-arm")
	watchdog.armCalls++
	watchdog.lastArm = input
	return GatewayInitWatchdogTransaction{ID: "fw-ABC123"}, nil
}

func (watchdog *recordingGatewayWatchdog) MarkActivated(_ context.Context, id string) error {
	watchdog.events.add("watchdog-mark")
	watchdog.markCalls++
	if id != "fw-ABC123" {
		return errors.New("wrong transaction ID")
	}
	return nil
}

func (watchdog *recordingGatewayWatchdog) RollbackNow(_ context.Context, id string) error {
	watchdog.events.add("watchdog-rollback")
	watchdog.rollbackID = id
	return nil
}

type recordingGatewayNetwork struct {
	events *gatewayInitEvents
	calls  int
	err    error
}

type recordingGatewaySwap struct {
	events          *gatewayInitEvents
	plan            linuxplatform.ManagedSwapPlan
	applyCalls      int
	deactivateCalls int
}

type recordingGatewayIdentity struct {
	events         *gatewayInitEvents
	provisionCalls int
	rollbackCalls  int
	lastRequest    control.GatewayIdentityRequest
	err            error
}

func newRecordingGatewayIdentity(events *gatewayInitEvents) *recordingGatewayIdentity {
	return &recordingGatewayIdentity{events: events}
}

func (identity *recordingGatewayIdentity) Provision(_ context.Context, request control.GatewayIdentityRequest) (control.GatewayIdentityInstallation, error) {
	identity.events.add("identity-provision")
	identity.provisionCalls++
	identity.lastRequest = request
	if identity.err != nil {
		return control.GatewayIdentityInstallation{}, identity.err
	}
	notBefore := request.Initialized.UTC().Add(-5 * time.Minute)
	return control.GatewayIdentityInstallation{
		Certificates: []model.Certificate{
			{
				SchemaVersion: model.ResourceSchemaVersion, ID: "11111111-1111-4111-8111-111111111111",
				Kind: model.CertificateControlCA, OwnerKind: "host", OwnerID: request.GatewayID,
				Fingerprint: "sha256:" + strings.Repeat("1", 64), SerialHex: "01", Subject: "CN=vpnctl control CA",
				SANs: []string{}, NotBefore: notBefore, NotAfter: request.Initialized.Add(control.ControlCAValidity),
				WarningDays: control.ControlWarningDays, Generation: 1,
				CertificateRef: control.ControlCACertificateRef, PrivateKeyRef: control.ControlCAPrivateKeyRef,
			},
			{
				SchemaVersion: model.ResourceSchemaVersion, ID: "22222222-2222-4222-8222-222222222222",
				Kind: model.CertificateControlServer, OwnerKind: "host", OwnerID: request.GatewayID,
				Fingerprint: "sha256:" + strings.Repeat("2", 64), SerialHex: "02", Subject: "CN=vpnctl gateway control leaf",
				SANs: []string{"IP:10.67.0.1", "urn:vpnctl:gateway:" + request.GatewayID}, NotBefore: notBefore, NotAfter: request.Initialized.Add(control.ControlLeafValidity),
				WarningDays: control.ControlWarningDays, Generation: 1,
				CertificateRef: control.GatewayControlCertificateRef, PrivateKeyRef: control.GatewayControlPrivateKeyRef,
			},
		},
		EnrollmentIdentity: model.EnrollmentIdentity{
			SchemaVersion: model.ResourceSchemaVersion, Algorithm: "Ed25519", Fingerprint: "sha256:" + strings.Repeat("3", 64),
			PublicKeyRef: control.EnrollmentPublicKeyRef, PrivateKeyRef: control.EnrollmentPrivateKeyRef, Generation: 1, CreatedAt: request.Initialized.UTC(),
		},
		OwnedReferences: []model.SecretRef{control.ControlCAPrivateKeyRef, control.GatewayControlPrivateKeyRef, control.EnrollmentPrivateKeyRef},
	}, nil
}

func (identity *recordingGatewayIdentity) Rollback(_ context.Context, _ control.GatewayIdentityInstallation) error {
	identity.events.add("identity-rollback")
	identity.rollbackCalls++
	return nil
}

func lowMemoryGatewayResources() linuxplatform.HostResources {
	return linuxplatform.HostResources{MemoryTotalBytes: 512 << 20, DiskFreeBytes: 3 << 30}
}

func offeredGatewaySwapPlan(paths store.Paths) linuxplatform.ManagedSwapPlan {
	return linuxplatform.ManagedSwapPlan{
		Disposition: linuxplatform.ManagedSwapOffered, Offered: true,
		Path: linuxplatform.ManagedSwapLogicalPath, SizeBytes: linuxplatform.ManagedSwapSizeBytes,
		MemoryBytes: 512 << 20, DiskFreeBytes: 3 << 30, DiskReserve: linuxplatform.ManagedSwapDiskReserve,
		PhysicalPath: filepath.Join(paths.StateDir, "swapfile"),
		PhysicalUnit: filepath.Join(paths.Root, "etc", "systemd", "system", linuxplatform.ManagedSwapUnitName),
	}
}

func (swap *recordingGatewaySwap) Plan(resources linuxplatform.HostResources) (linuxplatform.ManagedSwapPlan, error) {
	if swap.plan.Disposition != "" {
		return swap.plan, nil
	}
	return linuxplatform.ManagedSwapPlan{
		Disposition: linuxplatform.ManagedSwapUnknownResources,
		Path:        linuxplatform.ManagedSwapLogicalPath, SizeBytes: linuxplatform.ManagedSwapSizeBytes,
		MemoryBytes: resources.MemoryTotalBytes, ExistingBytes: resources.SwapTotalBytes,
		DiskFreeBytes: resources.DiskFreeBytes, DiskReserve: linuxplatform.ManagedSwapDiskReserve,
	}, nil
}

func (swap *recordingGatewaySwap) Apply(_ context.Context, _ linuxplatform.ManagedSwapPlan) (model.ManagedSwap, error) {
	if swap.events != nil {
		swap.events.add("swap-apply")
	}
	swap.applyCalls++
	return model.ManagedSwap{Path: linuxplatform.ManagedSwapLogicalPath, SizeBytes: int64(linuxplatform.ManagedSwapSizeBytes), Enabled: true}, nil
}

func (swap *recordingGatewaySwap) Deactivate(_ context.Context, _ model.ManagedSwap, _ bool) error {
	if swap.events != nil {
		swap.events.add("swap-deactivate")
	}
	swap.deactivateCalls++
	return nil
}

type gatewayInitSystemdRunner struct{ calls []string }

func (runner *gatewayInitSystemdRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	runner.calls = append(runner.calls, command.Name+" "+strings.Join(command.Args, " "))
	return linuxplatform.ProbeResult{}, nil
}

func (network *recordingGatewayNetwork) ActivateGateway(_ context.Context, artifact linuxplatform.GatewayFirewallArtifact) error {
	network.events.add("network-activate")
	network.calls++
	if !strings.Contains(string(artifact.Definition()), "table inet vpnctl {") {
		return errors.New("missing owned firewall")
	}
	return network.err
}
