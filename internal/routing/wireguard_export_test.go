package routing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	v1CompatibleServerPublicKey  = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	v1CompatibleClientPrivateKey = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	v1CompatibleClientPublicKey  = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
	v1CompatibleClientID         = "11111111-1111-4111-8111-111111111111"
)

func TestWireGuardProfileRendererMatchesV1GoldenWithDefaultDNS(t *testing.T) {
	t.Parallel()

	renderer, stateStore, secretStore, reference := newGoldenWireGuardRenderer(t)
	request := WireGuardProfileRequest{ClientReference: "IPHONE", GatewayPublicKey: v1CompatibleServerPublicKey}
	profile, err := renderer.Render(request)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	want, err := os.ReadFile(filepath.Join("..", "regression", "testdata", "v1", "iphone.wireguard.conf"))
	if err != nil {
		t.Fatalf("read v1 WireGuard golden: %v", err)
	}
	profileBytes := profile.Bytes()
	if !bytes.Equal(profileBytes, want) {
		t.Fatalf("v2 WireGuard profile differs from v1 golden\nwant:\n%s\n got:\n%s", want, profileBytes)
	}
	defensive := profile.Bytes()
	defensive[0] = 'X'
	if bytes.Equal(defensive, profile.Bytes()) {
		t.Fatal("WireGuardProfile.Bytes() exposed mutable secret-bearing storage")
	}
	metadataJSON, err := json.Marshal(profile)
	if err != nil || strings.Contains(string(metadataJSON), v1CompatibleClientPrivateKey) || strings.Contains(string(metadataJSON), "Content") {
		t.Fatalf("WireGuard profile metadata JSON exposed content: %s, %v", metadataJSON, err)
	}
	if profile.ClientID != v1CompatibleClientID || profile.ClientName != "iphone" || profile.SourceStateGeneration != 1 || profile.CredentialGeneration != 1 {
		t.Fatalf("profile metadata = %#v", profile)
	}
	if !strings.Contains(string(profileBytes), "Address = 10.66.0.2/24\n") ||
		!strings.Contains(string(profileBytes), "DNS = 1.1.1.1, 8.8.8.8\n") ||
		!strings.Contains(string(profileBytes), "AllowedIPs = 0.0.0.0/0\n") ||
		!strings.Contains(string(profileBytes), "PersistentKeepalive = 25\n") {
		t.Fatalf("profile lost full-tunnel/default semantics:\n%s", profileBytes)
	}
	stored, err := secretStore.Get(reference)
	if err != nil || string(stored) != v1CompatibleClientPrivateKey || !strings.Contains(string(profileBytes), string(stored)) {
		t.Fatalf("profile did not preserve the stored client private key: %q, %v", stored, err)
	}
	state := loadPolicyState(t, stateStore)
	if state.Clients[0].OverlayIPv4 != "10.66.0.2" || state.Transports[0].PublicKey != v1CompatibleClientPublicKey {
		t.Fatalf("renderer mutated identity inputs: %#v / %#v", state.Clients[0], state.Transports[0])
	}
	repeated, err := renderer.Render(request)
	if err != nil || !reflect.DeepEqual(repeated, profile) {
		t.Fatalf("repeated Render() = %#v, %v; want deterministic %#v", repeated, err, profile)
	}

	custom, err := renderer.Render(WireGuardProfileRequest{
		ClientReference: v1CompatibleClientID, GatewayPublicKey: v1CompatibleServerPublicKey, DNSServers: []string{"9.9.9.9"},
	})
	if err != nil || !strings.Contains(string(custom.Bytes()), "DNS = 9.9.9.9\n") || strings.Contains(string(custom.Bytes()), "1.1.1.1") {
		t.Fatalf("custom DNS Render() = %v\n%s", err, custom.Bytes())
	}
	if _, err := renderer.Render(WireGuardProfileRequest{ClientReference: "iphone", GatewayPublicKey: v1CompatibleServerPublicKey, DNSServers: []string{}}); err == nil {
		t.Fatal("Render(explicit empty DNS) succeeded")
	}
}

func TestWireGuardProfileContentIsIndependentFromClientPresetPolicy(t *testing.T) {
	t.Parallel()

	clientManager, paths, stateStore, secretStore, credentials, _ := newClientManagerFixture(t, nil)
	plan, err := clientManager.PlanAdd(ClientAddRequest{Name: "iphone", PresetNames: []string{"telegram"}})
	if err != nil {
		t.Fatalf("PlanAdd() error = %v", err)
	}
	created, err := clientManager.CommitAdd(context.Background(), plan)
	if err != nil {
		t.Fatalf("CommitAdd() error = %v", err)
	}
	renderer, err := NewWireGuardProfileRenderer(stateStore, secretStore)
	if err != nil {
		t.Fatalf("NewWireGuardProfileRenderer() error = %v", err)
	}
	gatewayPublicKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	before, err := renderer.Render(WireGuardProfileRequest{ClientReference: "iphone", GatewayPublicKey: gatewayPublicKey})
	if err != nil {
		t.Fatalf("Render(before policy edit) error = %v", err)
	}
	if !strings.Contains(string(before.Bytes()), credentials.generated[0].PrivateKey) || !strings.Contains(string(before.Bytes()), "Address = 10.44.0.2/24\n") {
		t.Fatalf("profile did not preserve created key/address:\n%s", before.Bytes())
	}

	policyManager, err := NewPolicyManager(paths, stateStore)
	if err != nil {
		t.Fatalf("NewPolicyManager() error = %v", err)
	}
	policyPlan, err := policyManager.PlanClientSet(created.Client.ID, []string{"openai", "anthropic"})
	if err != nil {
		t.Fatalf("PlanClientSet() error = %v", err)
	}
	if _, err := policyManager.Commit(policyPlan); err != nil {
		t.Fatalf("Commit(policy edit) error = %v", err)
	}
	after, err := renderer.Render(WireGuardProfileRequest{ClientReference: "iphone", GatewayPublicKey: gatewayPublicKey})
	if err != nil {
		t.Fatalf("Render(after policy edit) error = %v", err)
	}
	if !bytes.Equal(after.Bytes(), before.Bytes()) || after.ClientID != before.ClientID || after.CredentialGeneration != before.CredentialGeneration {
		t.Fatalf("preset-only edit changed WireGuard profile\nbefore: %#v\nafter: %#v", before, after)
	}
	if after.SourceStateGeneration <= before.SourceStateGeneration {
		t.Fatalf("state generation did not expose the policy edit: before %d after %d", before.SourceStateGeneration, after.SourceStateGeneration)
	}
	state := loadPolicyState(t, stateStore)
	assertTargetPolicy(t, state, model.TargetClient, created.Client.ID, []string{"anthropic", "openai"}, 2)
	transport := findClientTransport(t, state.Transports, created.Client.ID)
	if transport.CredentialGeneration != 1 || transport.CredentialRef == "" {
		t.Fatalf("policy edit changed standard credential metadata: %#v", transport)
	}
}

func newGoldenWireGuardRenderer(t *testing.T) (*WireGuardProfileRenderer, *store.StateStore, *store.SecretStore, model.SecretRef) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatalf("NewPaths() error = %v", err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	state := catalogGatewayState(nil, false)
	state.Host.PublicIPv4 = "198.211.99.116"
	state.Host.ClientCIDR = "10.66.0.0/24"
	state.Clients = []model.Client{{
		SchemaVersion: model.ResourceSchemaVersion, ID: v1CompatibleClientID, Name: "iphone", Platform: "ios",
		Lifecycle: model.LifecycleActive, OverlayIPv4: "10.66.0.2", CredentialGeneration: 1,
		AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
		CreatedAt: time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC),
	}}
	reference, err := model.NewSecretRef(clientStandardCredentialKind, v1CompatibleClientID+clientStandardCredentialSuffix)
	if err != nil {
		t.Fatalf("NewSecretRef() error = %v", err)
	}
	state.Transports = []model.Transport{{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetClient, OwnerID: v1CompatibleClientID,
		Kind: model.TransportStandard, State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: 51820,
		CredentialGeneration: 1, CredentialRef: reference, PublicKey: v1CompatibleClientPublicKey, ConfigHash: strings.Repeat("a", 64),
	}}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatalf("NewStateStore() error = %v", err)
	}
	if err := stateStore.Save(0, state); err != nil {
		t.Fatalf("Save(initial state) error = %v", err)
	}
	secretStore, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatalf("NewSecretStore() error = %v", err)
	}
	if err := secretStore.PutIfAbsent(reference, []byte(v1CompatibleClientPrivateKey)); err != nil {
		t.Fatalf("PutIfAbsent(client private key) error = %v", err)
	}
	renderer, err := NewWireGuardProfileRenderer(stateStore, secretStore)
	if err != nil {
		t.Fatalf("NewWireGuardProfileRenderer() error = %v", err)
	}
	return renderer, stateStore, secretStore, reference
}
