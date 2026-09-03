package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	DefaultClientPlatform          = "generic"
	clientCredentialAttempts       = 4
	clientStandardCredentialKind   = "wireguard-key"
	clientStandardCredentialSuffix = "-standard-g1"
)

var (
	ErrClientNameConflict        = errors.New("client name already exists")
	ErrClientNotFound            = errors.New("client does not exist")
	ErrClientStalePlan           = errors.New("client creation plan is stale")
	ErrClientCredentialCollision = errors.New("generated client credential collides with an existing client")
	ErrClientCommitUncertain     = errors.New("client creation commit outcome is uncertain")
)

type ClientStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

type ClientSecretStore interface {
	PutIfAbsent(reference model.SecretRef, secret []byte) error
	Delete(reference model.SecretRef) (bool, error)
}

type ClientCredentialGenerator interface {
	GenerateClientCredential(ctx context.Context) (wireguard.KeyPair, error)
}

type ExecClientCredentialGenerator struct {
	Runner wireguard.Runner
}

func (generator ExecClientCredentialGenerator) GenerateClientCredential(ctx context.Context) (wireguard.KeyPair, error) {
	return wireguard.GenerateKeyPair(ctx, generator.Runner)
}

type ClientManagerRuntime struct {
	Now         func() time.Time
	NewUUID     model.UUIDGenerator
	Credentials ClientCredentialGenerator
}

type ClientAddRequest struct {
	Name        string
	PresetNames []string
}

type ClientAddPlan struct {
	Name                    string
	Platform                string
	PresetNames             []string
	ClientID                string
	OverlayIPv4             string
	CreatedAt               time.Time
	ExpectedStateGeneration uint64
	NextStateGeneration     uint64

	sourceSetHash string
	planHash      string
}

type ClientAddResult struct {
	Changed         bool
	StateGeneration uint64
	Client          ClientView
}

type ClientExportState string

const (
	ClientExportNotCreated ClientExportState = "not-exported"
	ClientExportCurrent    ClientExportState = "current"
	ClientExportStale      ClientExportState = "stale"
)

type ClientHealth string

const (
	ClientHealthHealthy  ClientHealth = "healthy"
	ClientHealthDegraded ClientHealth = "degraded"
	ClientHealthDisabled ClientHealth = "disabled"
)

type ClientView struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	Platform             string               `json:"platform"`
	Lifecycle            model.Lifecycle      `json:"lifecycle"`
	OverlayIPv4          string               `json:"overlay_ipv4"`
	AssignedPresets      []string             `json:"assigned_presets"`
	CredentialGeneration uint64               `json:"credential_generation"`
	PolicyGeneration     uint64               `json:"policy_generation"`
	ActiveTransport      model.TransportKind  `json:"active_transport"`
	TransportState       model.TransportState `json:"transport_state"`
	ExportState          ClientExportState    `json:"export_state"`
	Health               ClientHealth         `json:"health"`
	CreatedAt            time.Time            `json:"created_at"`
	RevokedAt            *time.Time           `json:"revoked_at,omitempty"`
}

type ClientList struct {
	StateGeneration uint64       `json:"state_generation"`
	Items           []ClientView `json:"items"`
}

type ClientShow struct {
	StateGeneration uint64     `json:"state_generation"`
	Resource        ClientView `json:"resource"`
}

type ClientManager struct {
	paths   store.Paths
	state   ClientStateStore
	secrets ClientSecretStore
	runtime ClientManagerRuntime
}

func NewClientManager(paths store.Paths, state ClientStateStore, secrets ClientSecretStore, runtime ClientManagerRuntime) (*ClientManager, error) {
	if state == nil || secrets == nil {
		return nil, fmt.Errorf("client manager state and secret stores are required")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths {
		return nil, fmt.Errorf("client manager paths do not match the system root")
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	if runtime.NewUUID == nil {
		runtime.NewUUID = model.NewUUID
	}
	if runtime.Credentials == nil {
		runtime.Credentials = ExecClientCredentialGenerator{}
	}
	return &ClientManager{paths: paths, state: state, secrets: secrets, runtime: runtime}, nil
}

func (manager *ClientManager) PlanAdd(request ClientAddRequest) (ClientAddPlan, error) {
	if manager == nil {
		return ClientAddPlan{}, fmt.Errorf("client manager is required")
	}
	createdAt := manager.runtime.Now().UTC()
	if err := validateClientIdentityInput(request.Name, DefaultClientPlatform, createdAt); err != nil {
		return ClientAddPlan{}, err
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return ClientAddPlan{}, err
	}
	if clientNameExists(state.Clients, request.Name) {
		return ClientAddPlan{}, fmt.Errorf("%w: %s", ErrClientNameConflict, request.Name)
	}

	names := []string{}
	sourceSetHash := ""
	if len(request.PresetNames) > 0 {
		sources, setIssues, inspectErr := inspectPresetSources(manager.paths.PresetsDir)
		if inspectErr != nil {
			return ClientAddPlan{}, inspectErr
		}
		sourceSetHash = presetSourceSetHash(sources, setIssues)
		names, err = resolvePolicyPresetNames(state, sources, request.PresetNames)
		if err != nil {
			return ClientAddPlan{}, err
		}
	}
	clientID, err := model.AllocateUUID(clientOccupiedIDs(state), manager.runtime.NewUUID)
	if err != nil {
		return ClientAddPlan{}, fmt.Errorf("allocate client identity: %w", err)
	}
	allocator, err := model.AddressAllocatorFromState(state)
	if err != nil {
		return ClientAddPlan{}, err
	}
	overlayIPv4, err := allocator.Allocate(model.TargetClient, clientID)
	if err != nil {
		return ClientAddPlan{}, err
	}
	nextGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return ClientAddPlan{}, err
	}
	plan := ClientAddPlan{
		Name: request.Name, Platform: DefaultClientPlatform, PresetNames: append([]string{}, names...),
		ClientID: clientID, OverlayIPv4: overlayIPv4, CreatedAt: createdAt,
		ExpectedStateGeneration: state.Generation, NextStateGeneration: nextGeneration, sourceSetHash: sourceSetHash,
	}
	plan.planHash = clientAddPlanHash(plan)
	return plan, nil
}

func (manager *ClientManager) CommitAdd(ctx context.Context, plan ClientAddPlan) (ClientAddResult, error) {
	if manager == nil {
		return ClientAddResult{}, fmt.Errorf("client manager is required")
	}
	if ctx == nil {
		return ClientAddResult{}, fmt.Errorf("client creation context is required")
	}
	if err := validateClientAddPlan(plan); err != nil {
		return ClientAddResult{}, err
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return ClientAddResult{}, err
	}
	if state.Generation != plan.ExpectedStateGeneration {
		return ClientAddResult{}, fmt.Errorf("%w: expected state generation %d, current %d", ErrClientStalePlan, plan.ExpectedStateGeneration, state.Generation)
	}
	if clientNameExists(state.Clients, plan.Name) {
		return ClientAddResult{}, fmt.Errorf("%w: %s", ErrClientNameConflict, plan.Name)
	}
	if clientIDExists(state, plan.ClientID) {
		return ClientAddResult{}, fmt.Errorf("%w: client identity is already present", ErrClientStalePlan)
	}
	if len(plan.PresetNames) > 0 {
		sources, setIssues, inspectErr := inspectPresetSources(manager.paths.PresetsDir)
		if inspectErr != nil {
			return ClientAddResult{}, inspectErr
		}
		if presetSourceSetHash(sources, setIssues) != plan.sourceSetHash {
			return ClientAddResult{}, fmt.Errorf("%w: preset source set changed after planning", ErrClientStalePlan)
		}
		resolved, resolveErr := resolvePolicyPresetNames(state, sources, plan.PresetNames)
		if resolveErr != nil {
			return ClientAddResult{}, resolveErr
		}
		if !reflect.DeepEqual(resolved, plan.PresetNames) {
			return ClientAddResult{}, fmt.Errorf("%w: canonical preset assignment changed", ErrClientStalePlan)
		}
	}
	allocator, err := model.AddressAllocatorFromState(state)
	if err != nil {
		return ClientAddResult{}, err
	}
	address, err := allocator.Allocate(model.TargetClient, plan.ClientID)
	if err != nil {
		return ClientAddResult{}, err
	}
	if address != plan.OverlayIPv4 {
		return ClientAddResult{}, fmt.Errorf("%w: planned address %s is now %s", ErrClientStalePlan, plan.OverlayIPv4, address)
	}
	if err := ctx.Err(); err != nil {
		return ClientAddResult{}, err
	}
	credential, err := manager.generateUniqueCredential(ctx, state)
	if err != nil {
		return ClientAddResult{}, err
	}
	reference, err := clientStandardCredentialReference(plan.ClientID, 1)
	if err != nil {
		return ClientAddResult{}, err
	}
	candidate, err := buildClientCandidate(state, plan, credential.PublicKey, reference)
	if err != nil {
		return ClientAddResult{}, err
	}
	view, err := clientView(candidate, candidate.Clients[len(candidate.Clients)-1], ClientExportNotCreated)
	if err != nil {
		return ClientAddResult{}, err
	}
	result := ClientAddResult{Changed: true, StateGeneration: candidate.Generation, Client: view}
	privateKey := []byte(strings.TrimSpace(credential.PrivateKey))
	if err := manager.secrets.PutIfAbsent(reference, privateKey); err != nil {
		return ClientAddResult{}, fmt.Errorf("stage client credential: %w", err)
	}
	cleanup := func(cause error) error {
		_, cleanupErr := manager.secrets.Delete(reference)
		if cleanupErr != nil {
			cleanupErr = fmt.Errorf("delete staged client credential %s: %w", reference, cleanupErr)
		}
		return errors.Join(cause, cleanupErr)
	}
	if err := ctx.Err(); err != nil {
		return ClientAddResult{}, cleanup(err)
	}
	if err := manager.state.Save(state.Generation, candidate); err != nil {
		loaded, loadErr := manager.state.Load()
		if loadErr == nil && reflect.DeepEqual(loaded, candidate) {
			return result, fmt.Errorf("%w: state is active but durability confirmation failed: %v", ErrClientCommitUncertain, err)
		}
		if loadErr == nil && !clientIDExists(loaded, plan.ClientID) {
			return ClientAddResult{}, cleanup(err)
		}
		return result, fmt.Errorf("%w: cannot prove authoritative client state after write failure: %v", ErrClientCommitUncertain, err)
	}
	return result, nil
}

func (manager *ClientManager) List() (ClientList, error) {
	if manager == nil {
		return ClientList{}, fmt.Errorf("client manager is required")
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return ClientList{}, err
	}
	items := make([]ClientView, 0, len(state.Clients))
	for _, client := range state.Clients {
		if client.Lifecycle == model.LifecycleDeleted {
			continue
		}
		view, viewErr := clientView(state, client, inspectClientExportState(manager.paths, state, client))
		if viewErr != nil {
			return ClientList{}, viewErr
		}
		items = append(items, view)
	}
	sort.Slice(items, func(left, right int) bool {
		leftName, rightName := strings.ToLower(items[left].Name), strings.ToLower(items[right].Name)
		if leftName != rightName {
			return leftName < rightName
		}
		return items[left].ID < items[right].ID
	})
	return ClientList{StateGeneration: state.Generation, Items: items}, nil
}

func (manager *ClientManager) Show(reference string) (ClientShow, error) {
	if manager == nil {
		return ClientShow{}, fmt.Errorf("client manager is required")
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return ClientShow{}, err
	}
	client, err := resolveVisibleClient(state.Clients, reference)
	if err != nil {
		return ClientShow{}, err
	}
	view, err := clientView(state, client, inspectClientExportState(manager.paths, state, client))
	if err != nil {
		return ClientShow{}, err
	}
	return ClientShow{StateGeneration: state.Generation, Resource: view}, nil
}

func (manager *ClientManager) loadGatewayState() (model.State, error) {
	state, err := manager.state.Load()
	if err != nil {
		return model.State{}, fmt.Errorf("load authoritative client state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return model.State{}, fmt.Errorf("validate authoritative client state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return model.State{}, fmt.Errorf("client manager requires gateway state")
	}
	return state, nil
}

func (manager *ClientManager) generateUniqueCredential(ctx context.Context, state model.State) (wireguard.KeyPair, error) {
	existing := make(map[string]struct{})
	for _, transport := range state.Transports {
		if transport.Kind == model.TransportStandard && transport.PublicKey != "" {
			existing[transport.PublicKey] = struct{}{}
		}
	}
	for attempt := 0; attempt < clientCredentialAttempts; attempt++ {
		credential, err := manager.runtime.Credentials.GenerateClientCredential(ctx)
		if err != nil {
			return wireguard.KeyPair{}, fmt.Errorf("generate client credential: %w", err)
		}
		credential.PrivateKey = strings.TrimSpace(credential.PrivateKey)
		credential.PublicKey = strings.TrimSpace(credential.PublicKey)
		if err := wireguard.ValidateKey(credential.PrivateKey); err != nil {
			return wireguard.KeyPair{}, fmt.Errorf("generated client private key is invalid: %w", err)
		}
		if err := wireguard.ValidateKey(credential.PublicKey); err != nil {
			return wireguard.KeyPair{}, fmt.Errorf("generated client public key is invalid: %w", err)
		}
		if _, collision := existing[credential.PublicKey]; collision {
			continue
		}
		return credential, nil
	}
	return wireguard.KeyPair{}, ErrClientCredentialCollision
}

func buildClientCandidate(state model.State, plan ClientAddPlan, publicKey string, credentialRef model.SecretRef) (model.State, error) {
	presetMap := make(map[string]model.Preset, len(state.Presets))
	for _, preset := range state.Presets {
		presetMap[strings.ToLower(preset.Name)] = preset
	}
	selectors, effectiveHash, err := effectivePolicy(plan.PresetNames, presetMap)
	if err != nil {
		return model.State{}, err
	}
	client := model.Client{
		SchemaVersion: model.ResourceSchemaVersion, ID: plan.ClientID, Name: plan.Name, Platform: plan.Platform,
		Lifecycle: model.LifecycleActive, OverlayIPv4: plan.OverlayIPv4, CredentialGeneration: 1,
		AssignedPresets: append([]string{}, plan.PresetNames...), ActiveTransport: model.TransportStandard, CreatedAt: plan.CreatedAt,
	}
	transport := model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetClient, OwnerID: plan.ClientID,
		Kind: model.TransportStandard, State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: 51820,
		CredentialGeneration: 1, CredentialRef: credentialRef, PublicKey: publicKey,
		ConfigHash: clientTransportHash(plan.ClientID, 1, publicKey, credentialRef),
	}
	candidate := state
	candidate.Generation = plan.NextStateGeneration
	candidate.Clients = append(append([]model.Client{}, state.Clients...), client)
	candidate.Policies = append([]model.Policy{}, state.Policies...)
	if len(plan.PresetNames) > 0 {
		candidate.Policies = append(candidate.Policies, model.Policy{
			SchemaVersion: model.ResourceSchemaVersion, TargetKind: model.TargetClient, TargetID: plan.ClientID,
			PresetNames: append([]string{}, plan.PresetNames...), Selectors: append([]model.Selector{}, selectors...),
			EffectiveHash: effectiveHash, Generation: 1,
		})
	}
	candidate.Transports = append(append([]model.Transport{}, state.Transports...), transport)
	if err := model.ValidateTransition(state, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate client creation transition: %w", err)
	}
	return candidate, nil
}

func validateClientIdentityInput(name, platform string, createdAt time.Time) error {
	probe := model.Client{
		SchemaVersion: model.ResourceSchemaVersion, ID: "00000000-0000-4000-8000-000000000001", Name: name, Platform: platform,
		Lifecycle: model.LifecycleActive, OverlayIPv4: "192.0.2.2", CredentialGeneration: 1,
		AssignedPresets: []string{}, ActiveTransport: model.TransportStandard, CreatedAt: createdAt,
	}
	if err := probe.Validate(); err != nil {
		return fmt.Errorf("invalid client identity: %w", err)
	}
	return nil
}

func validateClientAddPlan(plan ClientAddPlan) error {
	if err := validateClientIdentityInput(plan.Name, plan.Platform, plan.CreatedAt); err != nil {
		return err
	}
	if plan.PresetNames == nil || plan.ExpectedStateGeneration == 0 || plan.ClientID == "" || plan.OverlayIPv4 == "" ||
		plan.NextStateGeneration != plan.ExpectedStateGeneration+1 || plan.planHash == "" || plan.planHash != clientAddPlanHash(plan) {
		return fmt.Errorf("client creation plan is invalid")
	}
	if len(plan.PresetNames) == 0 && plan.sourceSetHash != "" {
		return fmt.Errorf("client creation plan without presets has a source snapshot")
	}
	if len(plan.PresetNames) > 0 && plan.sourceSetHash == "" {
		return fmt.Errorf("client creation plan with presets lacks a source snapshot")
	}
	return nil
}

func clientAddPlanHash(plan ClientAddPlan) string {
	hash := sha256.New()
	for _, value := range []string{
		plan.Name, plan.Platform, plan.ClientID, plan.OverlayIPv4, plan.CreatedAt.UTC().Format(time.RFC3339Nano),
		fmt.Sprintf("%d", plan.ExpectedStateGeneration), fmt.Sprintf("%d", plan.NextStateGeneration), plan.sourceSetHash,
	} {
		writePresetHashField(hash, value)
	}
	for _, name := range plan.PresetNames {
		writePresetHashField(hash, name)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func clientStandardCredentialReference(clientID string, generation uint64) (model.SecretRef, error) {
	if generation == 0 {
		return "", fmt.Errorf("client credential generation must be positive")
	}
	return model.NewSecretRef(clientStandardCredentialKind, fmt.Sprintf("%s-standard-g%d", clientID, generation))
}

func clientTransportHash(clientID string, generation uint64, publicKey string, reference model.SecretRef) string {
	hash := sha256.New()
	for _, value := range []string{clientID, "standard", "wireguard", "udp", "51820", fmt.Sprintf("%d", generation), publicKey, string(reference)} {
		writePresetHashField(hash, value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func clientNameExists(clients []model.Client, name string) bool {
	for _, client := range clients {
		if client.Lifecycle != model.LifecycleDeleted && strings.EqualFold(client.Name, name) {
			return true
		}
	}
	return false
}

func clientIDExists(state model.State, id string) bool {
	for _, client := range state.Clients {
		if client.ID == id {
			return true
		}
	}
	return false
}

func clientOccupiedIDs(state model.State) map[string]struct{} {
	occupied := make(map[string]struct{}, 1+len(state.Nodes)+len(state.Clients)+len(state.Exposes)+len(state.Certificates)+len(state.Operations))
	occupied[state.Host.ID] = struct{}{}
	for _, node := range state.Nodes {
		occupied[node.ID] = struct{}{}
	}
	for _, client := range state.Clients {
		occupied[client.ID] = struct{}{}
	}
	for _, expose := range state.Exposes {
		occupied[expose.ID] = struct{}{}
	}
	for _, certificate := range state.Certificates {
		occupied[certificate.ID] = struct{}{}
	}
	for _, operation := range state.Operations {
		occupied[operation.ID] = struct{}{}
		if operation.RequestID != "" {
			occupied[operation.RequestID] = struct{}{}
		}
	}
	return occupied
}

func resolveVisibleClient(clients []model.Client, reference string) (model.Client, error) {
	if reference == "" || strings.TrimSpace(reference) != reference || strings.ContainsAny(reference, "\x00\r\n") {
		return model.Client{}, fmt.Errorf("%w: an explicit name or ID is required", ErrClientNotFound)
	}
	matches := make([]model.Client, 0, 1)
	for _, client := range clients {
		if client.Lifecycle == model.LifecycleDeleted {
			continue
		}
		if client.ID == reference || strings.EqualFold(client.Name, reference) {
			matches = append(matches, client)
		}
	}
	if len(matches) != 1 {
		return model.Client{}, fmt.Errorf("%w: %s", ErrClientNotFound, reference)
	}
	return matches[0], nil
}

func clientView(state model.State, client model.Client, exportState ClientExportState) (ClientView, error) {
	policyGeneration := uint64(0)
	if policy, found := findTargetPolicy(state.Policies, model.TargetClient, client.ID); found {
		policyGeneration = policy.Generation
	}
	transportState := model.TransportState("")
	for _, transport := range state.Transports {
		if transport.OwnerKind == model.TargetClient && transport.OwnerID == client.ID && transport.Kind == client.ActiveTransport {
			transportState = transport.State
			break
		}
	}
	if transportState == "" {
		if client.Lifecycle == model.LifecycleActive {
			return ClientView{}, fmt.Errorf("client %s has no active transport metadata", client.ID)
		}
		transportState = model.TransportDisabled
	}
	health := ClientHealthHealthy
	if client.Lifecycle != model.LifecycleActive || transportState == model.TransportDisabled {
		health = ClientHealthDisabled
	} else if transportState == model.TransportDegraded {
		health = ClientHealthDegraded
	}
	view := ClientView{
		ID: client.ID, Name: client.Name, Platform: client.Platform, Lifecycle: client.Lifecycle, OverlayIPv4: client.OverlayIPv4,
		AssignedPresets: append([]string{}, client.AssignedPresets...), CredentialGeneration: client.CredentialGeneration,
		PolicyGeneration: policyGeneration, ActiveTransport: client.ActiveTransport, TransportState: transportState,
		ExportState: exportState, Health: health, CreatedAt: client.CreatedAt, RevokedAt: client.RevokedAt,
	}
	if client.RevokedAt != nil {
		copy := *client.RevokedAt
		view.RevokedAt = &copy
	}
	return view, nil
}
