package operations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const policyRPCNodeID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

type directPolicyRPCCaller struct{ handler control.RPCHandler }

func (caller directPolicyRPCCaller) CallManagement(ctx context.Context, request control.RPCRequest) (control.RPCCallResult, error) {
	result, err := caller.handler.HandleRPC(ctx, control.RPCPeer{NodeID: request.NodeID}, request)
	return control.RPCCallResult{StatusCode: result.StatusCode, Response: result.Response}, err
}

func TestRemotePolicyGatewayPlansAndDurablyDefersOnAuthoritativeGateway(t *testing.T) {
	t.Parallel()

	manager, gatewayStore, _ := newPolicyRPCFixture(t)
	handler, err := NewPolicyGatewayRPCHandler(&sync.Mutex{}, manager, gatewayStore)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	requestIDs := []string{"10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002"}
	remote, err := NewRemotePolicyGateway(
		directPolicyRPCCaller{handler: handler}, control.RPCProtocolVersion{Major: 1}, policyRPCNodeID,
		1, 1, func() time.Time { return now }, func() (string, error) { value := requestIDs[0]; requestIDs = requestIDs[1:]; return value, nil },
		strings.NewReader(strings.Repeat("n", control.RPCNonceBytes*2)),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := remote.Plan(context.Background(), routing.PolicySet, []string{"openai"}, true)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if !plan.Changed || !plan.Deferred || plan.TargetID != policyRPCNodeID || plan.ExpectedStateGeneration != 1 || plan.NextStateGeneration != 2 {
		t.Fatalf("remote plan = %+v", plan)
	}
	if len(plan.Desired.EffectivePresets) != 1 || plan.Desired.EffectivePresets[0].Name != "openai" ||
		len(plan.Desired.Selectors) != 1 || plan.Desired.Selectors[0].Value != "openai.com" {
		t.Fatalf("remote plan lost effective preset boundaries: %+v", plan.Desired)
	}
	wireJSON, err := json.Marshal(desiredPolicyToWire(plan.Desired))
	if err != nil || bytes.Count(wireJSON, []byte(`"selectors"`)) != 1 {
		t.Fatalf("policy wire duplicated or omitted preset selectors: %s, %v", wireJSON, err)
	}
	result, err := remote.Commit(context.Background(), plan)
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	if !result.Changed || !result.Pending || model.ValidateResourceID(result.OperationID) != nil || result.StateGeneration != 2 {
		t.Fatalf("remote commit = %+v", result)
	}
	state := loadPolicyRPCState(t, gatewayStore)
	assertPolicyRPCTarget(t, state, []string{"openai"}, 1)
	if len(state.Operations) != 1 || state.Operations[0].ID != result.OperationID || state.Operations[0].Type != model.OperationApply ||
		state.Operations[0].State != model.OperationPending || state.Operations[0].TargetKind != "policy" || state.Operations[0].TargetID != policyRPCNodeID {
		t.Fatalf("deferred policy operation = %+v", state.Operations)
	}
}

func TestPolicyRPCRejectsCommitWhenPresetSourceChangesAfterPlan(t *testing.T) {
	t.Parallel()

	manager, gatewayStore, paths := newPolicyRPCFixture(t)
	handler, _ := NewPolicyGatewayRPCHandler(&sync.Mutex{}, manager, gatewayStore)
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	requestIDs := []string{"20000000-0000-4000-8000-000000000001", "20000000-0000-4000-8000-000000000002"}
	remote, err := NewRemotePolicyGateway(directPolicyRPCCaller{handler}, control.RPCProtocolVersion{Major: 1}, policyRPCNodeID, 1, 1,
		func() time.Time { return now }, func() (string, error) { value := requestIDs[0]; requestIDs = requestIDs[1:]; return value, nil },
		strings.NewReader(strings.Repeat("p", control.RPCNonceBytes*2)))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := remote.Plan(context.Background(), routing.PolicySet, []string{"openai"}, false)
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]byte("# changed\n"), policyRPCPresetSource("openai", "openai.com")...)
	if err := os.WriteFile(paths.PresetsDir+"/openai.yaml", changed, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Commit(context.Background(), plan); !errors.Is(err, routing.ErrPolicyStalePlan) {
		t.Fatalf("Commit(stale source) error = %v", err)
	}
	if got := loadPolicyRPCState(t, gatewayStore); got.Generation != 1 || len(got.Nodes[0].AssignedPresets) != 0 {
		t.Fatalf("stale RPC changed gateway state: %+v", got)
	}
}

func TestPolicyRPCDeferredNoOpStillRegistersRealPendingApply(t *testing.T) {
	t.Parallel()

	manager, gatewayStore, _ := newPolicyRPCFixture(t)
	handler, _ := NewPolicyGatewayRPCHandler(&sync.Mutex{}, manager, gatewayStore)
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	requestIDs := []string{"30000000-0000-4000-8000-000000000001", "30000000-0000-4000-8000-000000000002"}
	remote, err := NewRemotePolicyGateway(directPolicyRPCCaller{handler}, control.RPCProtocolVersion{Major: 1}, policyRPCNodeID, 1, 1,
		func() time.Time { return now }, func() (string, error) { value := requestIDs[0]; requestIDs = requestIDs[1:]; return value, nil },
		strings.NewReader(strings.Repeat("q", control.RPCNonceBytes*2)))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := remote.Plan(context.Background(), routing.PolicyClear, []string{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Changed || !plan.Deferred || plan.NextStateGeneration != 2 {
		t.Fatalf("deferred no-op plan = %+v", plan)
	}
	result, err := remote.Commit(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	state := loadPolicyRPCState(t, gatewayStore)
	if result.Changed || !result.Pending || model.ValidateResourceID(result.OperationID) != nil || state.Generation != 2 ||
		len(state.Policies) != 0 || len(state.Operations) != 1 || state.Operations[0].ID != result.OperationID {
		t.Fatalf("deferred no-op result/state = %+v / %+v", result, state)
	}
}

func newPolicyRPCFixture(t *testing.T) (*routing.PolicyManager, *store.StateStore, store.Paths) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.PresetsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	presets := make([]model.Preset, 0, 2)
	for index, value := range []struct{ name, suffix string }{{"openai", "openai.com"}, {"telegram", "telegram.org"}} {
		source := policyRPCPresetSource(value.name, value.suffix)
		if err := os.WriteFile(paths.PresetsDir+"/"+value.name+".yaml", source, 0o644); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(source)
		presets = append(presets, model.Preset{
			SchemaVersion: model.ResourceSchemaVersion, Name: value.name, SourceHash: hex.EncodeToString(digest[:]),
			EffectiveHash: strings.Repeat(string(rune('a'+index)), 64), Selectors: []model.Selector{{Kind: model.SelectorDomainSuffix, Value: value.suffix}},
			Generation: 1, AppliedAt: now,
		})
	}
	state := model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 1,
		Host: model.Host{SchemaVersion: model.ResourceSchemaVersion, ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: now,
			PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", SSHPort: 22, ClientCIDR: "10.44.0.0/24", NodeCIDR: "10.45.0.0/24"},
		HandshakeHost: &model.HandshakeHost{SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: now},
		Nodes: []model.Node{{SchemaVersion: model.ResourceSchemaVersion, ID: policyRPCNodeID, Name: "private-node", Lifecycle: model.LifecycleActive,
			OverlayIPv4: "10.45.0.2", CredentialGeneration: 1, AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
			IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: now}},
		Clients: []model.Client{}, Presets: presets, Policies: []model.Policy{},
		Transports: []model.Transport{
			{SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: policyRPCNodeID, Kind: model.TransportStandard,
				State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: 51820, CredentialGeneration: 1,
				CredentialRef: "node:standard", PublicKey: "policy-test-public-key", ConfigHash: strings.Repeat("c", 64)},
			{SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: policyRPCNodeID, Kind: model.TransportRestricted,
				State: model.TransportStandby, Provider: "mihomo", Protocol: model.ProtocolTCP, Port: 8443, CredentialGeneration: 1,
				CredentialRef: "node:restricted", HandshakeHost: "www.microsoft.com", ConfigHash: strings.Repeat("d", 64)},
		},
		Exposes: []model.Expose{}, Certificates: []model.Certificate{}, Operations: []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{}, Invites: []model.Invite{},
		Components: model.ComponentManifest{SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0-dev",
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: model.StateSchemaVersion, StateSchemaMaximum: model.StateSchemaVersion,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1, MigrationReversible: true,
			Components: []model.ComponentPin{{Name: "vpnctl", Version: "v2.0.0-dev", Source: "bundle:vpnctl", Bundled: true, SHA256: strings.Repeat("e", 64), Capabilities: []string{"cli", "controller"}}}},
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := stateStore.Save(0, state); err != nil {
		t.Fatal(err)
	}
	manager, err := routing.NewPolicyManager(paths, stateStore)
	if err != nil {
		t.Fatal(err)
	}
	return manager, stateStore, paths
}

func policyRPCPresetSource(name, suffix string) []byte {
	return []byte("schema_version: 1\nname: " + name + "\ninclude:\n  - type: domain-suffix\n    value: " + suffix + "\nexclude: []\n")
}

func loadPolicyRPCState(t *testing.T, stateStore *store.StateStore) model.State {
	t.Helper()
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func assertPolicyRPCTarget(t *testing.T, state model.State, names []string, generation uint64) {
	t.Helper()
	if len(state.Policies) != 1 || state.Policies[0].TargetID != policyRPCNodeID || state.Policies[0].Generation != generation ||
		strings.Join(state.Policies[0].PresetNames, ",") != strings.Join(names, ",") || strings.Join(state.Nodes[0].AssignedPresets, ",") != strings.Join(names, ",") {
		t.Fatalf("policy target state = policies:%+v node:%+v", state.Policies, state.Nodes[0])
	}
}
