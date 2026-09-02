package routing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

func TestClientManagerCreatesFiveStableIsolatedIdentitiesAndSecretFreeViews(t *testing.T) {
	t.Parallel()

	manager, paths, stateStore, secretStore, credentials, _ := newClientManagerFixture(t, nil)
	requests := []ClientAddRequest{
		{Name: "iphone", PresetNames: []string{"telegram", "anthropic", "openai"}},
		{Name: "macbook"},
		{Name: "steamdeck"},
		{Name: "tablet"},
		{Name: "tv"},
	}
	created := make([]ClientAddResult, 0, len(requests))
	for index, request := range requests {
		plan, err := manager.PlanAdd(request)
		if err != nil {
			t.Fatalf("PlanAdd(%s) error = %v", request.Name, err)
		}
		if credentials.calls != index {
			t.Fatalf("PlanAdd(%s) generated credentials during read-only planning", request.Name)
		}
		if index == 0 && !reflect.DeepEqual(plan.PresetNames, []string{"anthropic", "openai", "telegram"}) {
			t.Fatalf("PlanAdd(iphone) presets = %v", plan.PresetNames)
		}
		if index > 0 && (plan.PresetNames == nil || len(plan.PresetNames) != 0) {
			t.Fatalf("PlanAdd(%s) presets = %#v, want explicit empty assignment", request.Name, plan.PresetNames)
		}
		result, err := manager.CommitAdd(context.Background(), plan)
		if err != nil {
			t.Fatalf("CommitAdd(%s) error = %v", request.Name, err)
		}
		if !result.Changed || result.StateGeneration != uint64(index+2) || result.Client.Name != request.Name ||
			result.Client.ExportState != ClientExportNotCreated || result.Client.Health != ClientHealthHealthy {
			t.Fatalf("CommitAdd(%s) = %#v", request.Name, result)
		}
		created = append(created, result)
	}

	state := loadPolicyState(t, stateStore)
	if state.Generation != 6 || len(state.Clients) != 5 || len(state.Transports) != 5 || len(state.Policies) != 1 {
		t.Fatalf("five-client state = generation %d, clients %d, transports %d, policies %d", state.Generation, len(state.Clients), len(state.Transports), len(state.Policies))
	}
	addresses := map[string]string{}
	publicKeys := map[string]string{}
	credentialRefs := map[model.SecretRef]string{}
	for index, result := range created {
		client := findClientByID(t, state.Clients, result.Client.ID)
		wantAddress := fmt.Sprintf("10.44.0.%d", index+2)
		if client.OverlayIPv4 != wantAddress || client.CredentialGeneration != 1 || client.ActiveTransport != model.TransportStandard {
			t.Fatalf("client %s = %#v, want stable address %s generation 1 standard", client.Name, client, wantAddress)
		}
		if prior, duplicate := addresses[client.OverlayIPv4]; duplicate {
			t.Fatalf("clients %s and %s share address %s", prior, client.Name, client.OverlayIPv4)
		}
		addresses[client.OverlayIPv4] = client.Name
		transport := findClientTransport(t, state.Transports, client.ID)
		if transport.State != model.TransportActive || transport.CredentialGeneration != 1 {
			t.Fatalf("transport for %s = %#v", client.Name, transport)
		}
		if prior, duplicate := publicKeys[transport.PublicKey]; duplicate {
			t.Fatalf("clients %s and %s share public key", prior, client.Name)
		}
		publicKeys[transport.PublicKey] = client.Name
		if prior, duplicate := credentialRefs[transport.CredentialRef]; duplicate {
			t.Fatalf("clients %s and %s share credential reference", prior, client.Name)
		}
		credentialRefs[transport.CredentialRef] = client.Name
		stored, err := secretStore.Get(transport.CredentialRef)
		if err != nil {
			t.Fatalf("Get(%s) error = %v", transport.CredentialRef, err)
		}
		if got, want := string(stored), credentials.generated[index].PrivateKey; got != want {
			t.Fatalf("private key for %s = %q, want generated credential", client.Name, got)
		}
		kind, id, _ := transport.CredentialRef.Parts()
		info, err := os.Stat(paths.SecretsDir + "/" + kind + "/" + id)
		if err != nil || info.Mode().Perm() != store.SecretFileMode {
			t.Fatalf("secret mode for %s = %v, %v", client.Name, info, err)
		}
	}
	assertTargetPolicy(t, state, model.TargetClient, created[0].Client.ID, []string{"anthropic", "openai", "telegram"}, 1)
	if !reflect.DeepEqual(state.Clients[0].AssignedPresets, []string{"anthropic", "openai", "telegram"}) {
		t.Fatalf("iphone initial assignment = %v", state.Clients[0].AssignedPresets)
	}
	for _, client := range state.Clients[1:] {
		if client.AssignedPresets == nil || len(client.AssignedPresets) != 0 {
			t.Fatalf("client %s received implicit presets: %#v", client.Name, client.AssignedPresets)
		}
	}

	list, err := manager.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := clientViewNames(list.Items), []string{"iphone", "macbook", "steamdeck", "tablet", "tv"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("List() names = %v, want %v", got, want)
	}
	shownByName, err := manager.Show("IPHONE")
	if err != nil {
		t.Fatalf("Show(name) error = %v", err)
	}
	shownByID, err := manager.Show(created[0].Client.ID)
	if err != nil || !reflect.DeepEqual(shownByID, shownByName) {
		t.Fatalf("Show(ID) = %#v, %v; Show(name) = %#v", shownByID, err, shownByName)
	}
	encoded, err := json.Marshal(struct {
		List ClientList `json:"list"`
		Show ClientShow `json:"show"`
	}{List: list, Show: shownByName})
	if err != nil {
		t.Fatalf("Marshal(secret-free views) error = %v", err)
	}
	text := string(encoded)
	for secret := range credentialRefs {
		if strings.Contains(text, string(secret)) {
			t.Fatalf("client view leaked credential reference %s: %s", secret, text)
		}
	}
	for _, pair := range credentials.generated {
		if strings.Contains(text, pair.PrivateKey) || strings.Contains(text, pair.PublicKey) {
			t.Fatalf("client view leaked key material: %s", text)
		}
	}
	for _, forbidden := range []string{"credential_ref", "private_key", "public_key", "profile"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("client view contains forbidden secret-bearing field %q: %s", forbidden, text)
		}
	}

	revokeClientForViewTest(t, stateStore, created[0].Client.ID)
	list, err = manager.List()
	if err != nil || len(list.Items) != 5 || list.Items[0].Lifecycle != model.LifecycleRevoked || list.Items[0].Health != ClientHealthDisabled {
		t.Fatalf("List() after revoke = %#v, %v", list, err)
	}
	shownByName, err = manager.Show("iphone")
	if err != nil || shownByName.Resource.Lifecycle != model.LifecycleRevoked || shownByName.Resource.RevokedAt == nil {
		t.Fatalf("Show(revoked) = %#v, %v", shownByName, err)
	}
	deleteClientForViewTest(t, stateStore, created[0].Client.ID)
	list, err = manager.List()
	if err != nil || len(list.Items) != 4 {
		t.Fatalf("List() after delete = %#v, %v", list, err)
	}
	if _, err := manager.Show("iphone"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("Show(deleted) error = %v, want ErrClientNotFound", err)
	}
}

func TestClientManagerRejectsDuplicateUnknownAndTamperedCreationWithoutSideEffects(t *testing.T) {
	t.Parallel()

	manager, paths, stateStore, _, credentials, uuid := newClientManagerFixture(t, nil)
	firstPlan, err := manager.PlanAdd(ClientAddRequest{Name: "iphone"})
	if err != nil {
		t.Fatalf("PlanAdd(iphone) error = %v", err)
	}
	if _, err := manager.CommitAdd(context.Background(), firstPlan); err != nil {
		t.Fatalf("CommitAdd(iphone) error = %v", err)
	}
	before := loadPolicyState(t, stateStore)
	beforeBytes := readPolicyStateBytes(t, paths)
	uuidCallsBefore := uuid.calls
	credentialCallsBefore := credentials.calls

	tests := []struct {
		name string
		run  func() error
		want error
	}{
		{name: "case-insensitive duplicate name", run: func() error { _, err := manager.PlanAdd(ClientAddRequest{Name: "IPHONE"}); return err }, want: ErrClientNameConflict},
		{name: "unknown initial preset", run: func() error {
			_, err := manager.PlanAdd(ClientAddRequest{Name: "laptop", PresetNames: []string{"missing"}})
			return err
		}, want: ErrPolicyUnknownPreset},
		{name: "duplicate initial preset", run: func() error {
			_, err := manager.PlanAdd(ClientAddRequest{Name: "laptop", PresetNames: []string{"telegram", "TELEGRAM"}})
			return err
		}},
		{name: "invalid name", run: func() error { _, err := manager.PlanAdd(ClientAddRequest{Name: "bad name"}); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.run()
			if err == nil || (test.want != nil && !errors.Is(err, test.want)) {
				t.Fatalf("PlanAdd() error = %v, want %v", err, test.want)
			}
			assertPolicyStateUnchanged(t, stateStore, paths, before, beforeBytes)
		})
	}
	if credentials.calls != credentialCallsBefore {
		t.Fatalf("rejected plans generated %d credentials", credentials.calls-credentialCallsBefore)
	}
	if got := uuid.calls; got != uuidCallsBefore {
		t.Fatalf("rejected plans allocated %d client IDs", got-uuidCallsBefore)
	}

	plan, err := manager.PlanAdd(ClientAddRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("PlanAdd(tamper) error = %v", err)
	}
	tampered := plan
	tampered.Name = "other"
	if _, err := manager.CommitAdd(context.Background(), tampered); err == nil {
		t.Fatal("CommitAdd(tampered plan) succeeded")
	}
	assertPolicyStateUnchanged(t, stateStore, paths, before, beforeBytes)
	if credentials.calls != credentialCallsBefore {
		t.Fatal("tampered plan generated a credential")
	}
}

func TestClientManagerCleansSecretOnKnownStateFailureAndRetainsItOnCommittedUncertainResult(t *testing.T) {
	t.Parallel()

	t.Run("known failure", func(t *testing.T) {
		manager, paths, stateStore, secretStore, credentials, _ := newClientManagerFixture(t, errors.New("simulated state failure"))
		before := loadPolicyState(t, stateStore)
		beforeBytes := readPolicyStateBytes(t, paths)
		plan, err := manager.PlanAdd(ClientAddRequest{Name: "iphone", PresetNames: []string{"telegram"}})
		if err != nil {
			t.Fatalf("PlanAdd() error = %v", err)
		}
		if _, err := manager.CommitAdd(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "simulated state failure") {
			t.Fatalf("CommitAdd() error = %v", err)
		}
		assertPolicyStateUnchanged(t, stateStore, paths, before, beforeBytes)
		reference, _ := model.NewSecretRef(clientStandardCredentialKind, plan.ClientID+clientStandardCredentialSuffix)
		if _, err := secretStore.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("Get(staged credential) error = %v, want removed secret", err)
		}
		if credentials.calls != 1 {
			t.Fatalf("credential generation calls = %d, want 1", credentials.calls)
		}
	})

	t.Run("committed uncertain", func(t *testing.T) {
		manager, _, stateStore, secretStore, _, _ := newClientManagerFixture(t, errAfterClientCommit)
		plan, err := manager.PlanAdd(ClientAddRequest{Name: "iphone"})
		if err != nil {
			t.Fatalf("PlanAdd() error = %v", err)
		}
		result, err := manager.CommitAdd(context.Background(), plan)
		if !errors.Is(err, ErrClientCommitUncertain) || !result.Changed {
			t.Fatalf("CommitAdd(committed uncertain) = %#v, %v", result, err)
		}
		state := loadPolicyState(t, stateStore)
		if len(state.Clients) != 1 || state.Clients[0].ID != plan.ClientID {
			t.Fatalf("committed uncertain state = %#v", state.Clients)
		}
		reference, _ := model.NewSecretRef(clientStandardCredentialKind, plan.ClientID+clientStandardCredentialSuffix)
		if _, err := secretStore.Get(reference); err != nil {
			t.Fatalf("committed uncertain credential was removed: %v", err)
		}
	})
}

var errAfterClientCommit = errors.New("simulated post-commit durability failure")

type clientFixtureStateStore struct {
	base    *store.StateStore
	saveErr error
}

func (fixture clientFixtureStateStore) Load() (model.State, error) {
	return fixture.base.Load()
}

func (fixture clientFixtureStateStore) Save(expected uint64, candidate model.State) error {
	if fixture.saveErr == nil {
		return fixture.base.Save(expected, candidate)
	}
	if errors.Is(fixture.saveErr, errAfterClientCommit) {
		if err := fixture.base.Save(expected, candidate); err != nil {
			return err
		}
	}
	return fixture.saveErr
}

type deterministicClientCredentials struct {
	calls     int
	generated []wireguard.KeyPair
}

func (generator *deterministicClientCredentials) GenerateClientCredential(context.Context) (wireguard.KeyPair, error) {
	generator.calls++
	pair := wireguard.KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(generator.calls)}, 32)),
		PublicKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(generator.calls + 100)}, 32)),
	}
	generator.generated = append(generator.generated, pair)
	return pair, nil
}

type countingUUIDGenerator struct {
	calls int
}

func (generator *countingUUIDGenerator) New() (string, error) {
	generator.calls++
	return fmt.Sprintf("10000000-0000-4000-8000-%012x", generator.calls), nil
}

func newClientManagerFixture(t *testing.T, saveErr error) (*ClientManager, store.Paths, *store.StateStore, *store.SecretStore, *deterministicClientCredentials, *countingUUIDGenerator) {
	t.Helper()
	sources := map[string][]byte{
		"telegram.yaml":  catalogPresetSource("telegram", []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "telegram.org"}}),
		"openai.yaml":    catalogPresetSource("openai", []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "openai.com"}}),
		"anthropic.yaml": catalogPresetSource("anthropic", []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "anthropic.com"}}),
	}
	presets := []model.Preset{
		catalogEffectivePreset("telegram", sources["telegram.yaml"], []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "telegram.org"}}),
		catalogEffectivePreset("openai", sources["openai.yaml"], []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "openai.com"}}),
		catalogEffectivePreset("anthropic", sources["anthropic.yaml"], []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "anthropic.com"}}),
	}
	_, paths, stateStore := newPresetCatalogFixture(t, sources, presets, false)
	secretStore, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatalf("NewSecretStore() error = %v", err)
	}
	uuid := &countingUUIDGenerator{}
	credentials := &deterministicClientCredentials{}
	manager, err := NewClientManager(paths, clientFixtureStateStore{base: stateStore, saveErr: saveErr}, secretStore, ClientManagerRuntime{
		Now:     func() time.Time { return time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC) },
		NewUUID: uuid.New, Credentials: credentials,
	})
	if err != nil {
		t.Fatalf("NewClientManager() error = %v", err)
	}
	return manager, paths, stateStore, secretStore, credentials, uuid
}

func findClientByID(t *testing.T, clients []model.Client, id string) model.Client {
	t.Helper()
	for _, client := range clients {
		if client.ID == id {
			return client
		}
	}
	t.Fatalf("client %s not found", id)
	return model.Client{}
}

func findClientTransport(t *testing.T, transports []model.Transport, id string) model.Transport {
	t.Helper()
	for _, transport := range transports {
		if transport.OwnerKind == model.TargetClient && transport.OwnerID == id && transport.Kind == model.TransportStandard {
			return transport
		}
	}
	t.Fatalf("standard transport for client %s not found", id)
	return model.Transport{}
}

func clientViewNames(items []ClientView) []string {
	result := make([]string, len(items))
	for index, item := range items {
		result[index] = item.Name
	}
	return result
}

func revokeClientForViewTest(t *testing.T, stateStore *store.StateStore, id string) {
	t.Helper()
	state := loadPolicyState(t, stateStore)
	candidate := state
	candidate.Generation++
	candidate.Clients = append([]model.Client{}, state.Clients...)
	candidate.Transports = append([]model.Transport{}, state.Transports...)
	for index := range candidate.Clients {
		if candidate.Clients[index].ID != id {
			continue
		}
		revoked, err := candidate.Clients[index].Revoke(time.Date(2026, time.September, 3, 13, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("Revoke(client) error = %v", err)
		}
		candidate.Clients[index] = revoked
	}
	for index := range candidate.Transports {
		if candidate.Transports[index].OwnerKind == model.TargetClient && candidate.Transports[index].OwnerID == id {
			candidate.Transports[index].State = model.TransportDisabled
		}
	}
	if err := stateStore.Save(state.Generation, candidate); err != nil {
		t.Fatalf("Save(revoked client) error = %v", err)
	}
}

func deleteClientForViewTest(t *testing.T, stateStore *store.StateStore, id string) {
	t.Helper()
	state := loadPolicyState(t, stateStore)
	candidate := state
	candidate.Generation++
	candidate.Clients = append([]model.Client{}, state.Clients...)
	for index := range candidate.Clients {
		if candidate.Clients[index].ID != id {
			continue
		}
		deleted, err := candidate.Clients[index].Delete()
		if err != nil {
			t.Fatalf("Delete(client) error = %v", err)
		}
		candidate.Clients[index] = deleted
	}
	candidate.Transports = make([]model.Transport, 0, len(state.Transports)-1)
	for _, transport := range state.Transports {
		if transport.OwnerKind != model.TargetClient || transport.OwnerID != id {
			candidate.Transports = append(candidate.Transports, transport)
		}
	}
	if err := stateStore.Save(state.Generation, candidate); err != nil {
		t.Fatalf("Save(deleted client) error = %v", err)
	}
}
