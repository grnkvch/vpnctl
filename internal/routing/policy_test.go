package routing

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const policyNodeID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

func TestPolicyManagerAtomicallyReplacesAndClearsExplicitClientPolicy(t *testing.T) {
	t.Parallel()

	manager, _, stateStore := newClientPolicyFixture(t)
	plan, err := manager.PlanClientSet("phone", []string{"openai"})
	if err != nil {
		t.Fatalf("PlanClientSet() error = %v", err)
	}
	if !plan.Changed || plan.TargetID != catalogClientID || plan.TargetName != "phone" || plan.Deferred ||
		!plan.RequiresClientReExport || !reflect.DeepEqual(plan.PreviousPresetNames, []string{"telegram"}) ||
		!reflect.DeepEqual(plan.PresetNames, []string{"openai"}) {
		t.Fatalf("PlanClientSet() = %#v, want complete explicit-client replacement", plan)
	}
	result, err := manager.Commit(plan)
	if err != nil {
		t.Fatalf("Commit(set) error = %v", err)
	}
	if !result.Changed || !result.RequiresClientReExport || result.Pending || result.StateGeneration != 2 {
		t.Fatalf("Commit(set) = %#v", result)
	}
	public := result.OutputResult()
	if err := public.Validate(); err != nil {
		t.Fatalf("Commit(set).OutputResult().Validate() error = %v", err)
	}
	if len(public.RequiresAction) != 1 || public.RequiresAction[0].Code != "re_export_client" ||
		public.RequiresAction[0].Command != "vpnctl client export "+catalogClientID+" clash" {
		t.Fatalf("Commit(set).OutputResult().RequiresAction = %#v", public.RequiresAction)
	}
	if len(public.Warnings) != 1 || public.Warnings[0].Code != "classification_boundary" || public.Data["classification_boundary"] == nil {
		t.Fatalf("Commit(set).OutputResult() classification diagnostics = %#v / %#v", public.Warnings, public.Data)
	}
	state := loadPolicyState(t, stateStore)
	assertTargetPolicy(t, state, model.TargetClient, catalogClientID, []string{"openai"}, 2)
	if !reflect.DeepEqual(state.Clients[0].AssignedPresets, []string{"openai"}) {
		t.Fatalf("client assignment = %v, want full replacement", state.Clients[0].AssignedPresets)
	}

	noOp, err := manager.PlanClientSet(catalogClientID, []string{"openai"})
	if err != nil {
		t.Fatalf("PlanClientSet(no-op) error = %v", err)
	}
	if noOp.Changed || noOp.RequiresClientReExport {
		t.Fatalf("PlanClientSet(no-op) = %#v", noOp)
	}
	if noOpResult, err := manager.Commit(noOp); err != nil || noOpResult.Changed || noOpResult.StateGeneration != 2 {
		t.Fatalf("Commit(no-op) = %#v, %v", noOpResult, err)
	} else if public := noOpResult.OutputResult(); public.Validate() != nil || len(public.RequiresAction) != 0 {
		t.Fatalf("Commit(no-op).OutputResult() = %#v", public)
	}

	clear, err := manager.PlanClientClear("phone")
	if err != nil {
		t.Fatalf("PlanClientClear() error = %v", err)
	}
	if !clear.Changed || clear.Command != PolicyClear || clear.PresetNames == nil || len(clear.PresetNames) != 0 {
		t.Fatalf("PlanClientClear() = %#v", clear)
	}
	clearResult, err := manager.Commit(clear)
	if err != nil {
		t.Fatalf("Commit(clear) error = %v", err)
	}
	if !clearResult.RequiresClientReExport || clearResult.StateGeneration != 3 {
		t.Fatalf("Commit(clear) = %#v", clearResult)
	}
	state = loadPolicyState(t, stateStore)
	assertTargetPolicy(t, state, model.TargetClient, catalogClientID, []string{}, 3)
	if state.Clients[0].AssignedPresets == nil || len(state.Clients[0].AssignedPresets) != 0 {
		t.Fatalf("cleared client assignment = %#v, want present empty array", state.Clients[0].AssignedPresets)
	}
	secondClear, err := manager.PlanClientClear("phone")
	if err != nil || secondClear.Changed {
		t.Fatalf("PlanClientClear(already clear) = %#v, %v", secondClear, err)
	}
	if secondClearResult, err := manager.Commit(secondClear); err != nil || secondClearResult.Changed || secondClearResult.StateGeneration != 3 {
		t.Fatalf("Commit(already clear) = %#v, %v", secondClearResult, err)
	}
}

func TestPolicyManagerRejectsInvalidFullReplacementWithoutMutation(t *testing.T) {
	t.Parallel()

	manager, paths, stateStore := newClientPolicyFixture(t)
	before := loadPolicyState(t, stateStore)
	beforeBytes := readPolicyStateBytes(t, paths)

	tests := []struct {
		name string
		run  func() error
		want error
	}{
		{name: "empty set", run: func() error { _, err := manager.PlanClientSet("phone", []string{}); return err }, want: ErrPolicyEmptySet},
		{name: "unknown preset", run: func() error { _, err := manager.PlanClientSet("phone", []string{"missing"}); return err }, want: ErrPolicyUnknownPreset},
		{name: "duplicate preset", run: func() error { _, err := manager.PlanClientSet("phone", []string{"telegram", "TELEGRAM"}); return err }},
		{name: "missing explicit client", run: func() error { _, err := manager.PlanClientSet("", []string{"telegram"}); return err }, want: ErrPolicyTargetNotFound},
		{name: "unknown client", run: func() error { _, err := manager.PlanClientSet("laptop", []string{"telegram"}); return err }, want: ErrPolicyTargetNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			if err == nil || (test.want != nil && !errors.Is(err, test.want)) {
				t.Fatalf("planning error = %v, want %v", err, test.want)
			}
			assertPolicyStateUnchanged(t, stateStore, paths, before, beforeBytes)
		})
	}
	writeCatalogPreset(t, paths, "anthropic.yaml", catalogPresetSource("anthropic", []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "anthropic.com"}}))
	if _, err := manager.PlanClientSet("phone", []string{"anthropic"}); !errors.Is(err, ErrPolicyUnknownPreset) {
		t.Fatalf("PlanClientSet(source-only preset) error = %v, want ErrPolicyUnknownPreset", err)
	}
	assertPolicyStateUnchanged(t, stateStore, paths, before, beforeBytes)

	invalid := []byte("schema_version: 1\nname: openai\ninclude:\n  - type: domain-suffix\n    value: openai.com\nexclude: []\naction: direct\n")
	writeCatalogPreset(t, paths, "openai.yaml", invalid)
	if _, err := manager.PlanClientSet("phone", []string{"openai"}); !errors.Is(err, ErrPolicyInvalidPreset) {
		t.Fatalf("PlanClientSet(invalid source) error = %v, want ErrPolicyInvalidPreset", err)
	}
	assertPolicyStateUnchanged(t, stateStore, paths, before, beforeBytes)

	writeCatalogPreset(t, paths, "openai.yaml", policyPresetSources()["openai.yaml"])
	plan, err := manager.PlanClientSet("phone", []string{"openai"})
	if err != nil {
		t.Fatalf("PlanClientSet(stale source test) error = %v", err)
	}
	tampered := plan
	tampered.Desired.Selectors = []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "attacker.example"}}
	if _, err := manager.Commit(tampered); err == nil {
		t.Fatal("Commit(tampered desired policy) succeeded")
	}
	assertPolicyStateUnchanged(t, stateStore, paths, before, beforeBytes)
	writeCatalogPreset(t, paths, "openai.yaml", append([]byte("# changed after planning\n"), policyPresetSources()["openai.yaml"]...))
	if _, err := manager.Commit(plan); !errors.Is(err, ErrPolicyStalePlan) {
		t.Fatalf("Commit(stale source plan) error = %v, want ErrPolicyStalePlan", err)
	}
	assertPolicyStateUnchanged(t, stateStore, paths, before, beforeBytes)
}

func TestNodePolicyCoordinatorKeepsDeferredPolicyPendingAndAppliesLatestExplicitSet(t *testing.T) {
	t.Parallel()

	manager, gatewayStore, localApplier, localStore, localPaths := newNodePolicyFixture(t)
	coordinator := NodePolicyCoordinator{Gateway: manager, Local: localApplier}
	localBefore := readPolicyStateBytes(t, localPaths)

	deferred, err := manager.PlanCurrentNodeSet(policyNodeID, []string{"openai"}, true)
	if err != nil {
		t.Fatalf("PlanCurrentNodeSet(deferred) error = %v", err)
	}
	deferredResult, err := coordinator.Commit(deferred)
	if err != nil {
		t.Fatalf("Commit(deferred) error = %v", err)
	}
	if !deferredResult.Gateway.Changed || !deferredResult.Gateway.Pending || !deferredResult.Pending || deferredResult.Local.Changed {
		t.Fatalf("Commit(deferred) = %#v", deferredResult)
	}
	if got := readPolicyStateBytes(t, localPaths); !bytes.Equal(got, localBefore) {
		t.Fatal("deferred policy changed node-local state")
	}
	gateway := loadPolicyState(t, gatewayStore)
	assertTargetPolicy(t, gateway, model.TargetNode, policyNodeID, []string{"openai"}, 2)

	immediate, err := manager.PlanCurrentNodeSet(policyNodeID, []string{"openai"}, false)
	if err != nil {
		t.Fatalf("PlanCurrentNodeSet(immediate) error = %v", err)
	}
	if immediate.Changed {
		t.Fatalf("gateway retry plan changed already-registered desired state: %#v", immediate)
	}
	immediateResult, err := coordinator.Commit(immediate)
	if err != nil {
		t.Fatalf("Commit(immediate) error = %v", err)
	}
	if immediateResult.Pending || !immediateResult.Local.Changed || !immediateResult.Local.RoutingChanged {
		t.Fatalf("Commit(immediate) = %#v", immediateResult)
	}
	local := loadPolicyState(t, localStore)
	assertTargetPolicy(t, local, model.TargetNode, policyNodeID, []string{"openai"}, 2)
	if got, want := local.Nodes[0].Gateway.LastKnownGatewayGeneration, immediateResult.Gateway.StateGeneration; got != want {
		t.Fatalf("last known gateway generation = %d, want %d", got, want)
	}
	if immediateResult.Gateway.Desired.GatewayPolicyGeneration != 2 || immediateResult.Local.PolicyGeneration != 2 {
		t.Fatalf("gateway/local policy generations = %d/%d, want 2/2 after applying the deferred desired state",
			immediateResult.Gateway.Desired.GatewayPolicyGeneration, immediateResult.Local.PolicyGeneration)
	}

	if _, err := manager.PlanCurrentNodeSet("private-node", []string{"telegram"}, false); !errors.Is(err, ErrPolicyTargetNotFound) {
		t.Fatalf("PlanCurrentNodeSet(name) error = %v, want authenticated immutable node ID", err)
	}
	clear, err := manager.PlanCurrentNodeClear(policyNodeID, false)
	if err != nil {
		t.Fatalf("PlanCurrentNodeClear() error = %v", err)
	}
	clearResult, err := coordinator.Commit(clear)
	if err != nil || clearResult.Pending {
		t.Fatalf("Commit(clear) = %#v, %v", clearResult, err)
	}
	local = loadPolicyState(t, localStore)
	assertTargetPolicy(t, local, model.TargetNode, policyNodeID, []string{}, 3)
	trustOnly := clearResult.Gateway.Desired
	trustOnly.GatewayStateGeneration++
	trustResult, err := localApplier.Apply(trustOnly)
	if err != nil || !trustResult.Changed || trustResult.RoutingChanged {
		t.Fatalf("Apply(trust-only gateway advance) = %#v, %v", trustResult, err)
	}
	local = loadPolicyState(t, localStore)
	if local.Nodes[0].AssignedPresets == nil || len(local.Nodes[0].AssignedPresets) != 0 {
		t.Fatalf("trust-only apply lost present empty assignment: %#v", local.Nodes[0].AssignedPresets)
	}
}

func TestNodePolicyCoordinatorReportsPendingWhenLocalApplyFailsAfterGatewayCommit(t *testing.T) {
	t.Parallel()

	manager, gatewayStore, _, localStore, localPaths := newNodePolicyFixture(t)
	failing, err := NewNodePolicyApplier(failingPolicyStore{base: localStore, saveErr: errors.New("simulated local write failure")})
	if err != nil {
		t.Fatalf("NewNodePolicyApplier() error = %v", err)
	}
	coordinator := NodePolicyCoordinator{Gateway: manager, Local: failing}
	localBefore := readPolicyStateBytes(t, localPaths)
	plan, err := manager.PlanCurrentNodeSet(policyNodeID, []string{"openai"}, false)
	if err != nil {
		t.Fatalf("PlanCurrentNodeSet() error = %v", err)
	}
	result, err := coordinator.Commit(plan)
	if !errors.Is(err, ErrPolicyLocalApply) || !result.Gateway.Changed || !result.Pending {
		t.Fatalf("Commit(local failure) = %#v, %v", result, err)
	}
	assertTargetPolicy(t, loadPolicyState(t, gatewayStore), model.TargetNode, policyNodeID, []string{"openai"}, 2)
	if got := readPolicyStateBytes(t, localPaths); !bytes.Equal(got, localBefore) {
		t.Fatal("failed node-local apply changed durable local state")
	}
}

func TestPolicyManagerGatewaySaveFailureLeavesAuthoritativeStateUnchanged(t *testing.T) {
	t.Parallel()

	_, paths, stateStore := newClientPolicyFixture(t)
	before := loadPolicyState(t, stateStore)
	beforeBytes := readPolicyStateBytes(t, paths)
	failing := failingPolicyStore{base: stateStore, saveErr: errors.New("simulated gateway write failure")}
	manager, err := NewPolicyManager(paths, failing)
	if err != nil {
		t.Fatalf("NewPolicyManager() error = %v", err)
	}
	plan, err := manager.PlanClientSet("phone", []string{"openai"})
	if err != nil {
		t.Fatalf("PlanClientSet() error = %v", err)
	}
	if _, err := manager.Commit(plan); err == nil || !strings.Contains(err.Error(), "simulated gateway write failure") {
		t.Fatalf("Commit(save failure) error = %v", err)
	}
	assertPolicyStateUnchanged(t, stateStore, paths, before, beforeBytes)
}

type failingPolicyStore struct {
	base    PolicyStateStore
	saveErr error
}

func (store failingPolicyStore) Load() (model.State, error) {
	return store.base.Load()
}

func (store failingPolicyStore) Save(uint64, model.State) error {
	return store.saveErr
}

func newClientPolicyFixture(t *testing.T) (*PolicyManager, store.Paths, *store.StateStore) {
	t.Helper()
	sources := policyPresetSources()
	telegram := catalogEffectivePreset("telegram", sources["telegram.yaml"], []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "telegram.org"}})
	openAI := catalogEffectivePreset("openai", sources["openai.yaml"], []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "openai.com"}})
	_, paths, stateStore := newPresetCatalogFixture(t, sources, []model.Preset{telegram, openAI}, true)
	manager, err := NewPolicyManager(paths, stateStore)
	if err != nil {
		t.Fatalf("NewPolicyManager() error = %v", err)
	}
	return manager, paths, stateStore
}

func newNodePolicyFixture(t *testing.T) (*PolicyManager, *store.StateStore, *NodePolicyApplier, *store.StateStore, store.Paths) {
	t.Helper()
	sources := policyPresetSources()
	telegram := catalogEffectivePreset("telegram", sources["telegram.yaml"], []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "telegram.org"}})
	openAI := catalogEffectivePreset("openai", sources["openai.yaml"], []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "openai.com"}})
	_, gatewayPaths, gatewayStore := newPresetCatalogFixture(t, sources, []model.Preset{telegram, openAI}, false)
	gateway := loadPolicyState(t, gatewayStore)
	presetMap := map[string]model.Preset{"telegram": telegram, "openai": openAI}
	selectors, effectiveHash, err := effectivePolicy([]string{"telegram"}, presetMap)
	if err != nil {
		t.Fatalf("effectivePolicy(initial node) error = %v", err)
	}
	gateway.Generation = 2
	gateway.Nodes = []model.Node{policyNode(false, gateway.Host.InitializedAt)}
	gateway.Policies = []model.Policy{{
		SchemaVersion: model.ResourceSchemaVersion, TargetKind: model.TargetNode, TargetID: policyNodeID,
		PresetNames: []string{"telegram"}, Selectors: selectors, EffectiveHash: effectiveHash, Generation: 1,
	}}
	gateway.Transports = policyNodeTransports()
	if err := gatewayStore.Save(1, gateway); err != nil {
		t.Fatalf("Save(gateway node state) error = %v", err)
	}
	manager, err := NewPolicyManager(gatewayPaths, gatewayStore)
	if err != nil {
		t.Fatalf("NewPolicyManager() error = %v", err)
	}

	localPaths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatalf("NewPaths(local) error = %v", err)
	}
	if err := os.MkdirAll(localPaths.StateDir, 0o700); err != nil {
		t.Fatalf("create local state directory: %v", err)
	}
	local := gateway
	local.Generation = 1
	local.Host.Role = model.RoleNode
	local.Host.ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	local.Host.PublicIPv4 = ""
	local.Host.ExternalInterface = ""
	local.Host.SSHPort = 0
	local.Host.ClientCIDR = ""
	local.Host.NodeCIDR = ""
	local.Nodes = []model.Node{policyNode(true, gateway.Host.InitializedAt)}
	local.Clients = []model.Client{}
	local.Presets = []model.Preset{}
	local.Policies[0].Generation = 1
	local.Exposes = []model.Expose{}
	local.Certificates = []model.Certificate{}
	local.Operations = []model.Operation{}
	local.Logging = []model.LoggingSession{}
	local.Backups = []model.Backup{}
	localStore, err := store.NewStateStore(localPaths)
	if err != nil {
		t.Fatalf("NewStateStore(local) error = %v", err)
	}
	if err := localStore.Save(0, local); err != nil {
		t.Fatalf("Save(local node state) error = %v", err)
	}
	applier, err := NewNodePolicyApplier(localStore)
	if err != nil {
		t.Fatalf("NewNodePolicyApplier() error = %v", err)
	}
	return manager, gatewayStore, applier, localStore, localPaths
}

func policyNode(local bool, createdAt time.Time) model.Node {
	node := model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: policyNodeID, Name: "private-node", Lifecycle: model.LifecycleActive,
		OverlayIPv4: "10.45.0.2", CredentialGeneration: 1, AssignedPresets: []string{"telegram"},
		ActiveTransport: model.TransportStandard, IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: createdAt,
	}
	if local {
		node.Gateway = &model.GatewayTrust{
			PublicIPv4: "203.0.113.10", NodeCIDR: "10.45.0.0/24", GatewayOverlayIPv4: "10.45.0.1", ControlProtocol: "1.0",
			EnrollmentFingerprint: "sha256:" + strings.Repeat("e", 64), EnrollmentPublicKeyRef: "enrollment-public:gateway",
			ControlCAFingerprints: []string{"sha256:" + strings.Repeat("f", 64)}, ControlCACertificateRefs: []string{"control-cert:gateway-ca-g1"},
			StandardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", RestrictedServerCredentialRef: "restricted-upstream:gateway-g1",
			LastKnownGatewayGeneration: 2,
		}
	}
	return node
}

func policyPresetSources() map[string][]byte {
	return map[string][]byte{
		"telegram.yaml": catalogPresetSource("telegram", []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "telegram.org"}}),
		"openai.yaml":   catalogPresetSource("openai", []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "openai.com"}}),
	}
}

func policyNodeTransports() []model.Transport {
	return []model.Transport{
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: policyNodeID, Kind: model.TransportStandard,
			State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: 51820, CredentialGeneration: 1,
			CredentialRef: "node:standard", PublicKey: "policy-test-public-key", ConfigHash: strings.Repeat("c", 64),
		},
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: policyNodeID, Kind: model.TransportRestricted,
			State: model.TransportStandby, Provider: "mihomo", Protocol: model.ProtocolTCP, Port: 8443, CredentialGeneration: 1,
			CredentialRef: "node:restricted", HandshakeHost: "www.microsoft.com", ConfigHash: strings.Repeat("d", 64),
		},
	}
}

func loadPolicyState(t *testing.T, stateStore PolicyStateStore) model.State {
	t.Helper()
	state, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load(policy state) error = %v", err)
	}
	return state
}

func readPolicyStateBytes(t *testing.T, paths store.Paths) []byte {
	t.Helper()
	data, err := os.ReadFile(paths.StateFile)
	if err != nil {
		t.Fatalf("ReadFile(policy state) error = %v", err)
	}
	return data
}

func assertPolicyStateUnchanged(t *testing.T, stateStore PolicyStateStore, paths store.Paths, want model.State, wantBytes []byte) {
	t.Helper()
	if got := loadPolicyState(t, stateStore); !reflect.DeepEqual(got, want) {
		t.Fatalf("policy state changed\nwant: %#v\n got: %#v", want, got)
	}
	if got := readPolicyStateBytes(t, paths); !bytes.Equal(got, wantBytes) {
		t.Fatal("policy state bytes changed after rejected operation")
	}
}

func assertTargetPolicy(t *testing.T, state model.State, kind model.TargetKind, id string, names []string, generation uint64) {
	t.Helper()
	for _, policy := range state.Policies {
		if policy.TargetKind == kind && policy.TargetID == id {
			if !reflect.DeepEqual(policy.PresetNames, names) || policy.Generation != generation {
				t.Fatalf("target policy = %#v, want presets %v generation %d", policy, names, generation)
			}
			if policy.PresetNames == nil || policy.Selectors == nil {
				t.Fatalf("target policy arrays must be present: %#v", policy)
			}
			return
		}
	}
	t.Fatalf("policy for %s %s not found", kind, id)
}
