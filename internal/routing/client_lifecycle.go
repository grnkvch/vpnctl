package routing

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const clientLifecyclePlanMarker = "<redacted-client-lifecycle-plan>"

var (
	ErrClientLifecycleStale       = errors.New("client lifecycle plan is stale")
	ErrClientNotActive            = errors.New("client is not active")
	ErrClientDeleteRequiresRevoke = errors.New("client must be revoked before deletion")
	ErrClientUnsupportedTransport = errors.New("client has a transport not supported by credential rotation")
	ErrClientLifecycleUncertain   = errors.New("client lifecycle commit outcome is uncertain")
	ErrClientCleanupPending       = errors.New("client lifecycle cleanup remains pending")
)

type ClientLifecycleCommand string

const (
	ClientRotate ClientLifecycleCommand = "client.rotate"
	ClientRevoke ClientLifecycleCommand = "client.revoke"
	ClientDelete ClientLifecycleCommand = "client.delete"
)

type ClientLifecyclePlan struct {
	Command                  ClientLifecycleCommand `json:"command"`
	ClientID                 string                 `json:"client_id"`
	ClientName               string                 `json:"client_name"`
	Changed                  bool                   `json:"changed"`
	ExpectedStateGeneration  uint64                 `json:"expected_state_generation"`
	NextStateGeneration      uint64                 `json:"next_state_generation"`
	CredentialGeneration     uint64                 `json:"credential_generation"`
	NextCredentialGeneration uint64                 `json:"next_credential_generation"`
	ExportState              ClientExportState      `json:"export_state"`
	ArtifactPaths            []string               `json:"artifact_paths"`
	RevokedAt                *time.Time             `json:"revoked_at,omitempty"`

	reference      string
	credentialRefs []model.SecretRef
	removals       []clientArtifactRemoval
	revocationTime *time.Time
}

func (ClientLifecyclePlan) String() string   { return clientLifecyclePlanMarker }
func (ClientLifecyclePlan) GoString() string { return clientLifecyclePlanMarker }

func (plan ClientLifecyclePlan) OutputResult() output.Result {
	result := output.NewResult(string(plan.Command), output.StatusOK, output.CategorySuccess, output.SafeObject{
		"changed":    plan.Changed,
		"generation": plan.NextStateGeneration,
	})
	result.ResourceIDs = map[string]string{"client_id": plan.ClientID}
	return result
}

type ClientLifecycleResult struct {
	Command                 ClientLifecycleCommand
	ClientID                string
	ClientName              string
	Changed                 bool
	StateGeneration         uint64
	CredentialGeneration    uint64
	RequiresClientReExport  bool
	ExternalProfilesRemain  bool
	RemovedArtifactPaths    []string
	PendingCleanupPaths     []string
	ArtifactCleanupNeeded   bool
	CredentialCleanupNeeded bool
}

func (result ClientLifecycleResult) OutputResult() output.Result {
	status := output.StatusOK
	if len(result.PendingCleanupPaths) != 0 || result.ArtifactCleanupNeeded || result.CredentialCleanupNeeded {
		status = output.StatusPending
	}
	public := output.NewResult(string(result.Command), status, output.CategorySuccess, output.SafeObject{
		"changed":    result.Changed,
		"generation": result.StateGeneration,
	})
	public.ResourceIDs = map[string]string{"client_id": result.ClientID}
	if result.RequiresClientReExport {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "re_export_client", Message: "Export a fresh profile and replace the client device profile manually.",
			ResourceIDs: map[string]string{"client_id": result.ClientID},
		})
	}
	if result.ExternalProfilesRemain {
		public.Warnings = append(public.Warnings, output.Message{
			Code: "external_profiles_remain", Message: "vpnctl cannot remove copies already stored on external client devices.",
			ResourceIDs: map[string]string{"client_id": result.ClientID},
		})
	}
	for _, path := range result.PendingCleanupPaths {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "remove_client_artifact", Message: pendingClientArtifactMessage(path),
			ResourceIDs: map[string]string{"client_id": result.ClientID},
		})
	}
	if result.CredentialCleanupNeeded {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "repair_client_credentials", Message: "Run repair to remove retained obsolete client credential material.",
			ResourceIDs: map[string]string{"client_id": result.ClientID},
		})
	}
	if result.ArtifactCleanupNeeded {
		public.RequiresAction = append(public.RequiresAction, output.Action{
			Code: "repair_client_artifacts", Message: "Run repair to reconcile retained internal client export metadata.",
			ResourceIDs: map[string]string{"client_id": result.ClientID},
		})
	}
	return public
}

func pendingClientArtifactMessage(path string) string {
	const prefix = "Inspect and remove the retained client artifact: "
	if len(prefix)+len(path) <= output.MaximumSafeString && !strings.ContainsAny(path, "\x00\r\n") {
		return prefix + path
	}
	return "Inspect and remove the retained client artifact reported by repair."
}

func (manager *ClientManager) PlanRotate(reference string) (ClientLifecyclePlan, error) {
	return manager.planLifecycle(reference, ClientRotate, nil)
}

func (manager *ClientManager) PlanRevoke(reference string) (ClientLifecyclePlan, error) {
	if manager == nil {
		return ClientLifecyclePlan{}, fmt.Errorf("client manager is required")
	}
	at := manager.runtime.Now().UTC()
	return manager.planLifecycle(reference, ClientRevoke, &at)
}

func (manager *ClientManager) PlanDelete(reference string) (ClientLifecyclePlan, error) {
	return manager.planLifecycle(reference, ClientDelete, nil)
}

func (manager *ClientManager) planLifecycle(reference string, command ClientLifecycleCommand, requestedRevocation *time.Time) (ClientLifecyclePlan, error) {
	if manager == nil {
		return ClientLifecyclePlan{}, fmt.Errorf("client manager is required")
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return ClientLifecyclePlan{}, err
	}
	client, err := resolveVisibleClient(state.Clients, reference)
	if err != nil {
		return ClientLifecyclePlan{}, err
	}
	credentialRefs, transports, err := clientCredentialInputs(state, client.ID)
	if err != nil {
		return ClientLifecyclePlan{}, err
	}
	plan := ClientLifecyclePlan{
		Command: command, ClientID: client.ID, ClientName: client.Name,
		ExpectedStateGeneration: state.Generation, NextStateGeneration: state.Generation,
		CredentialGeneration: client.CredentialGeneration, NextCredentialGeneration: client.CredentialGeneration,
		ExportState:   inspectClientExportState(manager.paths, state, client),
		ArtifactPaths: knownClientExportPaths(manager.paths, client),
		reference:     reference, credentialRefs: append([]model.SecretRef(nil), credentialRefs...),
	}
	switch command {
	case ClientRotate:
		if client.Lifecycle != model.LifecycleActive {
			return ClientLifecyclePlan{}, fmt.Errorf("%w: %s", ErrClientNotActive, client.Name)
		}
		if !supportsClientRotation(transports) {
			return ClientLifecyclePlan{}, fmt.Errorf("%w: %s", ErrClientUnsupportedTransport, client.Name)
		}
		plan.NextCredentialGeneration, err = model.NextGeneration(client.CredentialGeneration)
		if err != nil {
			return ClientLifecyclePlan{}, err
		}
		plan.Changed = true
	case ClientRevoke:
		if client.Lifecycle == model.LifecycleActive {
			if requestedRevocation == nil {
				return ClientLifecyclePlan{}, fmt.Errorf("client revocation time is required")
			}
			revoked, revokeErr := client.Revoke(requestedRevocation.UTC())
			if revokeErr != nil {
				return ClientLifecyclePlan{}, revokeErr
			}
			plan.RevokedAt = cloneTimePointer(revoked.RevokedAt)
			plan.revocationTime = cloneTimePointer(revoked.RevokedAt)
			plan.Changed = true
		} else if client.Lifecycle == model.LifecycleRevoked {
			plan.RevokedAt = cloneTimePointer(client.RevokedAt)
			plan.revocationTime = cloneTimePointer(client.RevokedAt)
		} else {
			return ClientLifecyclePlan{}, fmt.Errorf("%w: %s", ErrClientNotFound, reference)
		}
	case ClientDelete:
		if client.Lifecycle != model.LifecycleRevoked {
			return ClientLifecyclePlan{}, fmt.Errorf("%w: %s", ErrClientDeleteRequiresRevoke, client.Name)
		}
		plan.Changed = true
		plan.RevokedAt = cloneTimePointer(client.RevokedAt)
		plan.removals, plan.ArtifactPaths, err = planClientArtifactRemoval(manager.paths, client)
		if err != nil {
			return ClientLifecyclePlan{}, err
		}
	default:
		return ClientLifecyclePlan{}, fmt.Errorf("unsupported client lifecycle command %q", command)
	}
	if plan.Changed {
		plan.NextStateGeneration, err = model.NextGeneration(state.Generation)
		if err != nil {
			return ClientLifecyclePlan{}, err
		}
	}
	plan.ArtifactPaths = append([]string(nil), plan.ArtifactPaths...)
	return plan, nil
}

func (manager *ClientManager) CommitRotate(ctx context.Context, plan ClientLifecyclePlan) (ClientLifecycleResult, error) {
	if manager == nil {
		return ClientLifecycleResult{}, fmt.Errorf("client manager is required")
	}
	if ctx == nil {
		return ClientLifecycleResult{}, fmt.Errorf("client rotation context is required")
	}
	fresh, err := manager.planLifecycle(plan.reference, ClientRotate, nil)
	if err != nil {
		return ClientLifecycleResult{}, err
	}
	if !sameClientLifecycleReview(plan, fresh) {
		return ClientLifecycleResult{}, ErrClientLifecycleStale
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return ClientLifecycleResult{}, err
	}
	if state.Generation != fresh.ExpectedStateGeneration {
		return ClientLifecycleResult{}, ErrClientLifecycleStale
	}
	if err := ctx.Err(); err != nil {
		return ClientLifecycleResult{}, err
	}
	credential, err := manager.generateUniqueCredential(ctx, state)
	if err != nil {
		return ClientLifecycleResult{}, err
	}
	standardReference, err := clientStandardCredentialReference(fresh.ClientID, fresh.NextCredentialGeneration)
	if err != nil {
		return ClientLifecycleResult{}, err
	}
	restrictedReference := model.SecretRef("")
	restrictedCredential := []byte(nil)
	if clientHasTransportKind(state.Transports, fresh.ClientID, model.TransportRestricted) {
		restrictedCredential, err = manager.generateRestrictedCredential(ctx)
		if err != nil {
			return ClientLifecycleResult{}, err
		}
		restrictedReference, err = clientRestrictedCredentialReference(fresh.ClientID, fresh.NextCredentialGeneration)
		if err != nil {
			return ClientLifecycleResult{}, err
		}
	}
	candidate, err := buildClientRotationCandidate(
		state, fresh.ClientID, fresh.NextCredentialGeneration, credential.PublicKey, standardReference, restrictedReference,
	)
	if err != nil {
		return ClientLifecycleResult{}, err
	}
	result := lifecycleResult(fresh, candidate.Generation)
	result.CredentialGeneration = fresh.NextCredentialGeneration
	result.RequiresClientReExport = true
	staged := make([]model.SecretRef, 0, 2)
	cleanupStaged := func(cause error) error {
		return errors.Join(cause, deleteClientCredentialRefs(manager.secrets, staged))
	}
	if err := manager.secrets.PutIfAbsent(standardReference, []byte(strings.TrimSpace(credential.PrivateKey))); err != nil {
		return ClientLifecycleResult{}, fmt.Errorf("stage rotated client credential: %w", err)
	}
	staged = append(staged, standardReference)
	if restrictedReference != "" {
		if err := manager.secrets.PutIfAbsent(restrictedReference, restrictedCredential); err != nil {
			return ClientLifecycleResult{}, cleanupStaged(fmt.Errorf("stage rotated client restricted credential: %w", err))
		}
		staged = append(staged, restrictedReference)
	}
	if err := ctx.Err(); err != nil {
		return ClientLifecycleResult{}, cleanupStaged(err)
	}
	committed, known, saveErr := manager.saveLifecycleState(state, candidate)
	if !committed {
		if known {
			return ClientLifecycleResult{}, cleanupStaged(saveErr)
		}
		return result, fmt.Errorf("%w: %v", ErrClientLifecycleUncertain, saveErr)
	}
	cleanupErr := deleteClientCredentialRefs(manager.secrets, fresh.credentialRefs)
	if cleanupErr != nil {
		result.CredentialCleanupNeeded = true
	}
	if saveErr != nil {
		return result, errors.Join(fmt.Errorf("%w: state is active but durability confirmation failed: %v", ErrClientLifecycleUncertain, saveErr), cleanupErr)
	}
	if cleanupErr != nil {
		return result, errors.Join(ErrClientCleanupPending, cleanupErr)
	}
	return result, nil
}

func (manager *ClientManager) CommitRevoke(plan ClientLifecyclePlan) (ClientLifecycleResult, error) {
	if manager == nil {
		return ClientLifecycleResult{}, fmt.Errorf("client manager is required")
	}
	fresh, err := manager.planLifecycle(plan.reference, ClientRevoke, plan.revocationTime)
	if err != nil {
		return ClientLifecycleResult{}, err
	}
	if !sameClientLifecycleReview(plan, fresh) {
		return ClientLifecycleResult{}, ErrClientLifecycleStale
	}
	if !fresh.Changed {
		result := lifecycleResult(fresh, fresh.ExpectedStateGeneration)
		if cleanupErr := deleteClientCredentialRefs(manager.secrets, fresh.credentialRefs); cleanupErr != nil {
			result.CredentialCleanupNeeded = true
			return result, errors.Join(ErrClientCleanupPending, cleanupErr)
		}
		return result, nil
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return ClientLifecycleResult{}, err
	}
	if state.Generation != fresh.ExpectedStateGeneration {
		return ClientLifecycleResult{}, ErrClientLifecycleStale
	}
	candidate, err := buildClientRevocationCandidate(state, fresh.ClientID, *fresh.RevokedAt)
	if err != nil {
		return ClientLifecycleResult{}, err
	}
	result := lifecycleResult(fresh, candidate.Generation)
	committed, known, saveErr := manager.saveLifecycleState(state, candidate)
	if !committed {
		if known {
			return ClientLifecycleResult{}, saveErr
		}
		return result, fmt.Errorf("%w: %v", ErrClientLifecycleUncertain, saveErr)
	}
	cleanupErr := deleteClientCredentialRefs(manager.secrets, fresh.credentialRefs)
	if cleanupErr != nil {
		result.CredentialCleanupNeeded = true
	}
	if saveErr != nil {
		return result, errors.Join(fmt.Errorf("%w: state is active but durability confirmation failed: %v", ErrClientLifecycleUncertain, saveErr), cleanupErr)
	}
	if cleanupErr != nil {
		return result, errors.Join(ErrClientCleanupPending, cleanupErr)
	}
	return result, nil
}

func (manager *ClientManager) CommitDelete(plan ClientLifecyclePlan) (ClientLifecycleResult, error) {
	if manager == nil {
		return ClientLifecycleResult{}, fmt.Errorf("client manager is required")
	}
	fresh, err := manager.planLifecycle(plan.reference, ClientDelete, nil)
	if err != nil {
		return ClientLifecycleResult{}, err
	}
	if !sameClientLifecycleReview(plan, fresh) {
		return ClientLifecycleResult{}, ErrClientLifecycleStale
	}
	state, err := manager.loadGatewayState()
	if err != nil {
		return ClientLifecycleResult{}, err
	}
	if state.Generation != fresh.ExpectedStateGeneration {
		return ClientLifecycleResult{}, ErrClientLifecycleStale
	}
	candidate, err := buildClientDeletionCandidate(state, fresh.ClientID)
	if err != nil {
		return ClientLifecycleResult{}, err
	}
	result := lifecycleResult(fresh, candidate.Generation)
	result.ExternalProfilesRemain = true
	committed, known, saveErr := manager.saveLifecycleState(state, candidate)
	if !committed {
		if known {
			return ClientLifecycleResult{}, saveErr
		}
		return result, fmt.Errorf("%w: %v", ErrClientLifecycleUncertain, saveErr)
	}
	credentialErr := deleteClientCredentialRefs(manager.secrets, fresh.credentialRefs)
	if credentialErr != nil {
		result.CredentialCleanupNeeded = true
	}
	pendingPaths, internalPending, artifactErr := removePlannedClientArtifacts(fresh.removals)
	result.PendingCleanupPaths = append([]string(nil), pendingPaths...)
	result.ArtifactCleanupNeeded = internalPending
	if artifactErr == nil {
		result.RemovedArtifactPaths = append([]string(nil), fresh.ArtifactPaths...)
	}
	cleanupErr := errors.Join(credentialErr, artifactErr)
	if saveErr != nil {
		return result, errors.Join(fmt.Errorf("%w: state is active but durability confirmation failed: %v", ErrClientLifecycleUncertain, saveErr), cleanupErr)
	}
	if cleanupErr != nil {
		return result, errors.Join(ErrClientCleanupPending, cleanupErr)
	}
	return result, nil
}

func lifecycleResult(plan ClientLifecyclePlan, generation uint64) ClientLifecycleResult {
	return ClientLifecycleResult{
		Command: plan.Command, ClientID: plan.ClientID, ClientName: plan.ClientName,
		Changed: plan.Changed, StateGeneration: generation, CredentialGeneration: plan.NextCredentialGeneration,
	}
}

func sameClientLifecycleReview(left, right ClientLifecyclePlan) bool {
	core := left.Command == right.Command && left.ClientID == right.ClientID && left.ClientName == right.ClientName &&
		left.Changed == right.Changed && left.ExpectedStateGeneration == right.ExpectedStateGeneration &&
		left.NextStateGeneration == right.NextStateGeneration && left.CredentialGeneration == right.CredentialGeneration &&
		left.NextCredentialGeneration == right.NextCredentialGeneration && equalTimePointers(left.RevokedAt, right.RevokedAt)
	if !core {
		return false
	}
	if left.Command != ClientDelete {
		// Artifact drift must never delay security-critical rotation/revocation.
		return true
	}
	return left.ExportState == right.ExportState && reflect.DeepEqual(left.ArtifactPaths, right.ArtifactPaths)
}

func equalTimePointers(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func clientCredentialInputs(state model.State, clientID string) ([]model.SecretRef, []model.Transport, error) {
	references := make([]model.SecretRef, 0)
	transports := make([]model.Transport, 0)
	for _, transport := range state.Transports {
		if transport.OwnerKind != model.TargetClient || transport.OwnerID != clientID {
			continue
		}
		transports = append(transports, transport)
		references = append(references, transport.CredentialRef)
	}
	if len(transports) == 0 {
		return nil, nil, fmt.Errorf("client %s has no credential-bearing transports", clientID)
	}
	return references, transports, nil
}

func supportsClientRotation(transports []model.Transport) bool {
	if len(transports) < 1 || len(transports) > 2 {
		return false
	}
	seen := make(map[model.TransportKind]struct{}, len(transports))
	for _, transport := range transports {
		if transport.Kind != model.TransportStandard && transport.Kind != model.TransportRestricted {
			return false
		}
		seen[transport.Kind] = struct{}{}
	}
	_, standard := seen[model.TransportStandard]
	return standard && len(seen) == len(transports)
}

func clientHasTransportKind(transports []model.Transport, clientID string, kind model.TransportKind) bool {
	for _, transport := range transports {
		if transport.OwnerKind == model.TargetClient && transport.OwnerID == clientID && transport.Kind == kind {
			return true
		}
	}
	return false
}

func buildClientRotationCandidate(state model.State, clientID string, generation uint64, publicKey string, standardReference, restrictedReference model.SecretRef) (model.State, error) {
	candidate := state
	nextStateGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate.Generation = nextStateGeneration
	candidate.Clients = append([]model.Client(nil), state.Clients...)
	candidate.Transports = append([]model.Transport(nil), state.Transports...)
	foundClient := false
	for index := range candidate.Clients {
		if candidate.Clients[index].ID != clientID {
			continue
		}
		advanced, err := candidate.Clients[index].AdvanceCredentialGeneration()
		if err != nil || advanced.CredentialGeneration != generation {
			return model.State{}, fmt.Errorf("advance client credential generation: %w", err)
		}
		candidate.Clients[index] = advanced
		foundClient = true
	}
	foundStandard := false
	for index := range candidate.Transports {
		transport := &candidate.Transports[index]
		if transport.OwnerKind != model.TargetClient || transport.OwnerID != clientID {
			continue
		}
		transport.CredentialGeneration = generation
		switch transport.Kind {
		case model.TransportStandard:
			transport.CredentialRef = standardReference
			transport.PublicKey = strings.TrimSpace(publicKey)
			transport.ConfigHash = clientTransportHash(clientID, generation, transport.PublicKey, standardReference)
			foundStandard = true
		case model.TransportRestricted:
			if restrictedReference == "" {
				return model.State{}, ErrClientUnsupportedTransport
			}
			transport.CredentialRef = restrictedReference
			transport.ConfigHash = clientRestrictedTransportHash(clientID, generation, restrictedReference)
		default:
			return model.State{}, ErrClientUnsupportedTransport
		}
	}
	if !foundClient || !foundStandard {
		return model.State{}, ErrClientNotFound
	}
	if err := model.ValidateTransition(state, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate client rotation transition: %w", err)
	}
	return candidate, nil
}

func buildClientRevocationCandidate(state model.State, clientID string, at time.Time) (model.State, error) {
	candidate := state
	nextStateGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate.Generation = nextStateGeneration
	candidate.Clients = append([]model.Client(nil), state.Clients...)
	candidate.Transports = append([]model.Transport(nil), state.Transports...)
	found := false
	for index := range candidate.Clients {
		if candidate.Clients[index].ID != clientID {
			continue
		}
		revoked, err := candidate.Clients[index].Revoke(at)
		if err != nil {
			return model.State{}, err
		}
		candidate.Clients[index] = revoked
		found = true
	}
	for index := range candidate.Transports {
		if candidate.Transports[index].OwnerKind == model.TargetClient && candidate.Transports[index].OwnerID == clientID {
			candidate.Transports[index].State = model.TransportDisabled
		}
	}
	if !found {
		return model.State{}, ErrClientNotFound
	}
	if err := model.ValidateTransition(state, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate client revocation transition: %w", err)
	}
	return candidate, nil
}

func buildClientDeletionCandidate(state model.State, clientID string) (model.State, error) {
	candidate := state
	nextStateGeneration, err := model.NextGeneration(state.Generation)
	if err != nil {
		return model.State{}, err
	}
	candidate.Generation = nextStateGeneration
	candidate.Clients = append([]model.Client(nil), state.Clients...)
	found := false
	for index := range candidate.Clients {
		if candidate.Clients[index].ID != clientID {
			continue
		}
		deleted, err := candidate.Clients[index].Delete()
		if err != nil {
			return model.State{}, err
		}
		deleted.AssignedPresets = []string{}
		candidate.Clients[index] = deleted
		found = true
	}
	candidate.Policies = removeClientPolicy(state.Policies, clientID)
	candidate.Transports = removeClientTransports(state.Transports, clientID)
	if !found {
		return model.State{}, ErrClientNotFound
	}
	if err := model.ValidateTransition(state, candidate); err != nil {
		return model.State{}, fmt.Errorf("validate client deletion transition: %w", err)
	}
	return candidate, nil
}

func removeClientPolicy(policies []model.Policy, clientID string) []model.Policy {
	result := make([]model.Policy, 0, len(policies))
	for _, policy := range policies {
		if policy.TargetKind != model.TargetClient || policy.TargetID != clientID {
			result = append(result, policy)
		}
	}
	return result
}

func removeClientTransports(transports []model.Transport, clientID string) []model.Transport {
	result := make([]model.Transport, 0, len(transports))
	for _, transport := range transports {
		if transport.OwnerKind != model.TargetClient || transport.OwnerID != clientID {
			result = append(result, transport)
		}
	}
	return result
}

func (manager *ClientManager) saveLifecycleState(before, candidate model.State) (committed, known bool, saveErr error) {
	if err := manager.state.Save(before.Generation, candidate); err == nil {
		return true, true, nil
	} else {
		saveErr = err
	}
	loaded, loadErr := manager.state.Load()
	if loadErr == nil && reflect.DeepEqual(loaded, candidate) {
		return true, true, saveErr
	}
	if loadErr == nil && reflect.DeepEqual(loaded, before) {
		return false, true, saveErr
	}
	return false, false, errors.Join(saveErr, loadErr)
}

func deleteClientCredentialRefs(secrets ClientSecretStore, references []model.SecretRef) error {
	unique := make(map[model.SecretRef]struct{}, len(references))
	for _, reference := range references {
		unique[reference] = struct{}{}
	}
	ordered := make([]string, 0, len(unique))
	for reference := range unique {
		ordered = append(ordered, string(reference))
	}
	sort.Strings(ordered)
	var failures []error
	for _, encoded := range ordered {
		if _, err := secrets.Delete(model.SecretRef(encoded)); err != nil {
			failures = append(failures, fmt.Errorf("delete obsolete client credential: %w", err))
		}
	}
	return errors.Join(failures...)
}

// ClientStandardCredentialAccepted is the state-level fail-closed predicate
// consumed by the standard gateway provider. An old, revoked, disabled, or
// malformed credential never matches authoritative acceptance.
func ClientStandardCredentialAccepted(state model.State, clientID, publicKey string) (bool, error) {
	if err := state.Validate(); err != nil {
		return false, fmt.Errorf("validate client credential state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return false, fmt.Errorf("client credential acceptance requires gateway state")
	}
	publicKey = strings.TrimSpace(publicKey)
	if err := wireguard.ValidateKey(publicKey); err != nil {
		return false, nil
	}
	active := false
	for _, client := range state.Clients {
		if client.ID == clientID && client.Lifecycle == model.LifecycleActive {
			active = true
			break
		}
	}
	if !active {
		return false, nil
	}
	for _, transport := range state.Transports {
		if transport.OwnerKind == model.TargetClient && transport.OwnerID == clientID && transport.Kind == model.TransportStandard {
			return transport.State != model.TransportDisabled && transport.PublicKey == publicKey, nil
		}
	}
	return false, nil
}
