package model

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"time"
)

const UUIDCollisionRetryLimit = 32

var (
	ErrGenerationOverflow = errors.New("generation overflow")
	ErrIdentityCollision  = errors.New("identity collision retry limit reached")
	ErrInvalidTransition  = errors.New("invalid state transition")
)

type UUIDGenerator func() (string, error)

func NewUUID() (string, error) {
	return newUUIDFrom(rand.Reader)
}

func AllocateUUID(occupied map[string]struct{}, generator UUIDGenerator) (string, error) {
	if generator == nil {
		generator = NewUUID
	}
	for attempt := 0; attempt < UUIDCollisionRetryLimit; attempt++ {
		id, err := generator()
		if err != nil {
			return "", fmt.Errorf("generate UUID: %w", err)
		}
		if err := validateGeneratedUUID(id); err != nil {
			return "", err
		}
		if _, collision := occupied[id]; !collision {
			if occupied != nil {
				occupied[id] = struct{}{}
			}
			return id, nil
		}
	}
	return "", ErrIdentityCollision
}

func NextGeneration(current uint64) (uint64, error) {
	if current == math.MaxUint64 {
		return 0, ErrGenerationOverflow
	}
	return current + 1, nil
}

func (node Node) AdvanceCredentialGeneration() (Node, error) {
	if node.Lifecycle != LifecycleActive {
		return Node{}, fmt.Errorf("%w: credentials can advance only for an active node", ErrInvalidTransition)
	}
	next, err := NextGeneration(node.CredentialGeneration)
	if err != nil {
		return Node{}, fmt.Errorf("node credential %w", err)
	}
	node.CredentialGeneration = next
	return node, nil
}

func (client Client) AdvanceCredentialGeneration() (Client, error) {
	if client.Lifecycle != LifecycleActive {
		return Client{}, fmt.Errorf("%w: credentials can advance only for an active client", ErrInvalidTransition)
	}
	next, err := NextGeneration(client.CredentialGeneration)
	if err != nil {
		return Client{}, fmt.Errorf("client credential %w", err)
	}
	client.CredentialGeneration = next
	return client, nil
}

func (node Node) Revoke(at time.Time) (Node, error) {
	lifecycle, revokedAt, err := transitionLifecycle(node.Lifecycle, LifecycleRevoked, node.CreatedAt, node.RevokedAt, at)
	if err != nil {
		return Node{}, err
	}
	node.Lifecycle = lifecycle
	node.RevokedAt = revokedAt
	return node, nil
}

func (client Client) Revoke(at time.Time) (Client, error) {
	lifecycle, revokedAt, err := transitionLifecycle(client.Lifecycle, LifecycleRevoked, client.CreatedAt, client.RevokedAt, at)
	if err != nil {
		return Client{}, err
	}
	client.Lifecycle = lifecycle
	client.RevokedAt = revokedAt
	return client, nil
}

func (node Node) Delete() (Node, error) {
	lifecycle, revokedAt, err := transitionLifecycle(node.Lifecycle, LifecycleDeleted, node.CreatedAt, node.RevokedAt, time.Time{})
	if err != nil {
		return Node{}, err
	}
	node.Lifecycle = lifecycle
	node.RevokedAt = revokedAt
	return node, nil
}

func (client Client) Delete() (Client, error) {
	lifecycle, revokedAt, err := transitionLifecycle(client.Lifecycle, LifecycleDeleted, client.CreatedAt, client.RevokedAt, time.Time{})
	if err != nil {
		return Client{}, err
	}
	client.Lifecycle = lifecycle
	client.RevokedAt = revokedAt
	return client, nil
}

func ValidateTransition(before, after State) error {
	if err := before.Validate(); err != nil {
		return fmt.Errorf("before state: %w", err)
	}
	expectedGeneration, err := NextGeneration(before.Generation)
	if err != nil {
		return fmt.Errorf("state %w", err)
	}
	if after.Generation != expectedGeneration {
		return transitionError("generation must advance exactly once from %d to %d", before.Generation, expectedGeneration)
	}
	if before.Host.ID != after.Host.ID {
		return transitionError("host identity is immutable")
	}
	if before.Host.Role != after.Host.Role {
		return transitionError("host role is immutable")
	}
	if !before.Host.InitializedAt.Equal(after.Host.InitializedAt) {
		return transitionError("host initialization time is immutable")
	}
	if err := after.Validate(); err != nil {
		return transitionError("after state: %v", err)
	}
	if err := validateNodeTransitions(before, after); err != nil {
		return err
	}
	if err := validateClientTransitions(before, after); err != nil {
		return err
	}
	if err := validateInviteTransitions(before.Invites, after.Invites); err != nil {
		return err
	}
	if err := validateVersionedTransitions("preset", presetsByName(before.Presets), presetsByName(after.Presets)); err != nil {
		return err
	}
	if err := validateVersionedTransitions("policy", policiesByTarget(before.Policies), policiesByTarget(after.Policies)); err != nil {
		return err
	}
	if err := validateExposeTransitions(before.Exposes, after.Exposes); err != nil {
		return err
	}
	if err := validateCertificateTransitions(before.Certificates, after.Certificates); err != nil {
		return err
	}
	if before.EnrollmentIdentity != nil {
		if after.EnrollmentIdentity == nil {
			return transitionError("enrollment signing identity cannot be removed")
		}
		if !reflect.DeepEqual(before.EnrollmentIdentity, after.EnrollmentIdentity) {
			return transitionError("enrollment signing identity is immutable")
		}
	}
	if err := validateHandshakeHostChangeTransition(before, after); err != nil {
		return err
	}
	if err := validateStableRecordIdentities(before, after); err != nil {
		return err
	}
	return nil
}

func validateInviteTransitions(before, after []Invite) error {
	previous := make(map[string]Invite, len(before))
	for _, invite := range before {
		previous[invite.ID] = invite
	}
	current := make(map[string]struct{}, len(after))
	for _, invite := range after {
		current[invite.ID] = struct{}{}
		old, exists := previous[invite.ID]
		if !exists {
			if invite.State != InviteActive || invite.CancelledAt != nil || invite.ConsumedAt != nil || invite.ConsumptionHash != "" {
				return transitionError("new invite %s must start active", invite.ID)
			}
			continue
		}
		if old.SchemaVersion != invite.SchemaVersion || old.ID != invite.ID || old.Purpose != invite.Purpose ||
			old.NodeName != invite.NodeName || old.NodeID != invite.NodeID ||
			old.CredentialGeneration != invite.CredentialGeneration || old.BindingFingerprint != invite.BindingFingerprint ||
			old.ControlProtocol != invite.ControlProtocol || old.GatewayEndpoint != invite.GatewayEndpoint ||
			old.EnrollmentFingerprint != invite.EnrollmentFingerprint || old.SecretHash != invite.SecretHash ||
			!old.IssuedAt.Equal(invite.IssuedAt) || !old.ExpiresAt.Equal(invite.ExpiresAt) {
			return transitionError("invite %s identity and secret metadata are immutable", invite.ID)
		}
		switch old.State {
		case InviteActive:
			if invite.State != InviteActive && invite.State != InviteCancelled && invite.State != InviteConsumed {
				return transitionError("invite %s cannot move from %s to %s", invite.ID, old.State, invite.State)
			}
		case InviteCancelled, InviteConsumed:
			if !reflect.DeepEqual(old, invite) {
				return transitionError("terminal invite %s is immutable", invite.ID)
			}
		}
	}
	for _, invite := range before {
		if _, exists := current[invite.ID]; !exists {
			return transitionError("invite %s cannot be removed", invite.ID)
		}
	}
	return nil
}

func validateHandshakeHostChangeTransition(before, after State) error {
	selectionChanged := !reflect.DeepEqual(before.HandshakeHost, after.HandshakeHost)
	if before.Host.Role == RoleNode {
		if after.HandshakeHostChange != nil {
			return transitionError("node state cannot persist a gateway handshake-host change")
		}
		return nil
	}
	switch {
	case reflect.DeepEqual(before.HandshakeHostChange, after.HandshakeHostChange):
		if selectionChanged {
			return transitionError("gateway handshake host cannot change while its staged replacement record is unchanged")
		}
	case before.HandshakeHostChange == nil && after.HandshakeHostChange != nil:
		if after.HandshakeHostChange.State != HandshakeHostPrepared || selectionChanged {
			return transitionError("new handshake-host replacement must start prepared without changing active selection")
		}
	case before.HandshakeHostChange != nil && before.HandshakeHostChange.State == HandshakeHostPrepared && after.HandshakeHostChange != nil:
		old, current := before.HandshakeHostChange, after.HandshakeHostChange
		if current.State != HandshakeHostCommitted || old.OperationID != current.OperationID || old.Previous != current.Previous || old.Candidate != current.Candidate ||
			!reflect.DeepEqual(old.AffectedNodeIDs, current.AffectedNodeIDs) || !reflect.DeepEqual(old.AffectedClientIDs, current.AffectedClientIDs) || !old.PreparedAt.Equal(current.PreparedAt) || !selectionChanged {
			return transitionError("prepared handshake-host replacement may only commit its reviewed candidate")
		}
	case before.HandshakeHostChange != nil && before.HandshakeHostChange.State == HandshakeHostCommitted && after.HandshakeHostChange == nil:
		if !selectionChanged || after.HandshakeHost == nil || *after.HandshakeHost != before.HandshakeHostChange.Previous {
			return transitionError("handshake-host rollback must restore its exact previous snapshot")
		}
	case before.HandshakeHostChange != nil && before.HandshakeHostChange.State == HandshakeHostCommitted && after.HandshakeHostChange != nil:
		if after.HandshakeHostChange.State != HandshakeHostPrepared || selectionChanged || *after.HandshakeHost != before.HandshakeHostChange.Candidate || after.HandshakeHostChange.OperationID == before.HandshakeHostChange.OperationID {
			return transitionError("a new handshake-host replacement may supersede only an expired committed snapshot")
		}
	default:
		return transitionError("unsupported handshake-host replacement transition")
	}
	return nil
}

func newUUIDFrom(reader io.Reader) (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(reader, raw[:]); err != nil {
		return "", fmt.Errorf("read UUID entropy: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

func validateGeneratedUUID(id string) error {
	if err := validateUUID("id", id); err != nil {
		return fmt.Errorf("generated UUID: %w", err)
	}
	if id[14] != '4' || !strings.ContainsRune("89ab", rune(id[19])) {
		return fmt.Errorf("generated UUID: must use RFC 4122 version 4 and variant bits")
	}
	return nil
}

func transitionLifecycle(current, requested Lifecycle, createdAt time.Time, revokedAt *time.Time, at time.Time) (Lifecycle, *time.Time, error) {
	if current == requested {
		return current, revokedAt, nil
	}
	switch {
	case current == LifecycleActive && requested == LifecycleRevoked:
		if err := validateTime("revoked_at", at); err != nil {
			return "", nil, transitionError("%v", err)
		}
		if at.Before(createdAt) {
			return "", nil, transitionError("revocation cannot precede creation")
		}
		copy := at
		return LifecycleRevoked, &copy, nil
	case current == LifecycleRevoked && requested == LifecycleDeleted:
		if revokedAt == nil {
			return "", nil, transitionError("revoked resource has no revocation time")
		}
		copy := *revokedAt
		return LifecycleDeleted, &copy, nil
	default:
		return "", nil, transitionError("lifecycle cannot move from %s to %s", current, requested)
	}
}

func validateNodeTransitions(before, after State) error {
	previous := make(map[string]Node, len(before.Nodes))
	for _, node := range before.Nodes {
		previous[node.ID] = node
	}
	current := make(map[string]Node, len(after.Nodes))
	for _, node := range after.Nodes {
		current[node.ID] = node
		old, exists := previous[node.ID]
		if !exists {
			if node.Lifecycle != LifecycleActive || node.CredentialGeneration != 1 {
				return transitionError("new node %s must start active at credential generation 1", node.ID)
			}
			if len(node.IdempotencyRecords) != 0 {
				return transitionError("new node %s must start with empty idempotency history", node.ID)
			}
			continue
		}
		if err := validateResourceTransition("node", old.ID, old.Name, node.Name, old.OverlayIPv4, node.OverlayIPv4, before.Host.NodeCIDR != after.Host.NodeCIDR, old.CreatedAt, node.CreatedAt, old.Lifecycle, node.Lifecycle, old.CredentialGeneration, node.CredentialGeneration); err != nil {
			return err
		}
		if node.CredentialGeneration != old.CredentialGeneration {
			if !equalStringSet(old.AssignedPresets, node.AssignedPresets) {
				return transitionError("node %s credential rotation changed preset assignments", node.ID)
			}
			if !reflect.DeepEqual(policyFor(before.Policies, TargetNode, node.ID), policyFor(after.Policies, TargetNode, node.ID)) {
				return transitionError("node %s credential rotation changed its policy", node.ID)
			}
			if !equalStringSet(exposeIDsForNode(before.Exposes, node.ID), exposeIDsForNode(after.Exposes, node.ID)) {
				return transitionError("node %s credential rotation changed its expose identities", node.ID)
			}
		}
		if err := validateIdempotencyTransition(old, node); err != nil {
			return err
		}
	}
	for id, node := range previous {
		if _, exists := current[id]; !exists && node.Lifecycle == LifecycleActive {
			return transitionError("active node %s cannot be removed before revoke", id)
		}
	}
	return nil
}

func validateIdempotencyTransition(before, after Node) error {
	retained := make(map[string]IdempotencyRecord, len(after.IdempotencyRecords))
	for _, record := range after.IdempotencyRecords {
		retained[record.RequestID] = record
	}
	for _, old := range before.IdempotencyRecords {
		if current, exists := retained[old.RequestID]; exists && !reflect.DeepEqual(current, old) {
			return transitionError("node %s idempotency result %s is immutable", after.ID, old.RequestID)
		}
	}
	return nil
}

func validateClientTransitions(before, after State) error {
	previous := make(map[string]Client, len(before.Clients))
	for _, client := range before.Clients {
		previous[client.ID] = client
	}
	current := make(map[string]Client, len(after.Clients))
	for _, client := range after.Clients {
		current[client.ID] = client
		old, exists := previous[client.ID]
		if !exists {
			if client.Lifecycle != LifecycleActive || client.CredentialGeneration != 1 {
				return transitionError("new client %s must start active at credential generation 1", client.ID)
			}
			continue
		}
		if err := validateResourceTransition("client", old.ID, old.Name, client.Name, old.OverlayIPv4, client.OverlayIPv4, before.Host.ClientCIDR != after.Host.ClientCIDR, old.CreatedAt, client.CreatedAt, old.Lifecycle, client.Lifecycle, old.CredentialGeneration, client.CredentialGeneration); err != nil {
			return err
		}
		if client.CredentialGeneration != old.CredentialGeneration {
			if !equalStringSet(old.AssignedPresets, client.AssignedPresets) {
				return transitionError("client %s credential rotation changed preset assignments", client.ID)
			}
			if !reflect.DeepEqual(policyFor(before.Policies, TargetClient, client.ID), policyFor(after.Policies, TargetClient, client.ID)) {
				return transitionError("client %s credential rotation changed its policy", client.ID)
			}
		}
	}
	for id, client := range previous {
		if _, exists := current[id]; !exists && client.Lifecycle == LifecycleActive {
			return transitionError("active client %s cannot be removed before revoke", id)
		}
	}
	return nil
}

func validateResourceTransition(kind, id, oldName, newName, oldIP, newIP string, allowAddressMigration bool, oldCreatedAt, newCreatedAt time.Time, oldLifecycle, newLifecycle Lifecycle, oldCredentialGeneration, newCredentialGeneration uint64) error {
	if oldIP != newIP && !allowAddressMigration {
		return transitionError("%s %s overlay address may change only with its pool", kind, id)
	}
	if !oldCreatedAt.Equal(newCreatedAt) {
		return transitionError("%s %s creation time is immutable", kind, id)
	}
	if oldLifecycle != newLifecycle && !((oldLifecycle == LifecycleActive && newLifecycle == LifecycleRevoked) || (oldLifecycle == LifecycleRevoked && newLifecycle == LifecycleDeleted)) {
		return transitionError("%s %s lifecycle cannot move from %s to %s", kind, id, oldLifecycle, newLifecycle)
	}
	if newCredentialGeneration < oldCredentialGeneration {
		return transitionError("%s %s credential generation decreased", kind, id)
	}
	if newCredentialGeneration > oldCredentialGeneration {
		expected, err := NextGeneration(oldCredentialGeneration)
		if err != nil {
			return fmt.Errorf("%s %s credential %w", kind, id, err)
		}
		if newCredentialGeneration != expected {
			return transitionError("%s %s credential generation must advance exactly once", kind, id)
		}
		if newLifecycle != LifecycleActive {
			return transitionError("%s %s credentials cannot rotate while non-active", kind, id)
		}
		if oldName != newName {
			return transitionError("%s %s credential rotation changed its name", kind, id)
		}
	}
	return nil
}

type versionedResource struct {
	generation uint64
}

func validateVersionedTransitions(kind string, before, after map[string]versionedResource) error {
	for id, current := range after {
		previous, exists := before[id]
		if !exists {
			if current.generation != 1 {
				return transitionError("new %s %s must start at generation 1", kind, id)
			}
			continue
		}
		if current.generation < previous.generation {
			return transitionError("%s %s generation decreased", kind, id)
		}
		if current.generation > previous.generation {
			expected, err := NextGeneration(previous.generation)
			if err != nil {
				return fmt.Errorf("%s %s %w", kind, id, err)
			}
			if current.generation != expected {
				return transitionError("%s %s generation must advance exactly once", kind, id)
			}
		}
	}
	return nil
}

func presetsByName(values []Preset) map[string]versionedResource {
	result := make(map[string]versionedResource, len(values))
	for _, value := range values {
		result[strings.ToLower(value.Name)] = versionedResource{generation: value.Generation}
	}
	return result
}

func policiesByTarget(values []Policy) map[string]versionedResource {
	result := make(map[string]versionedResource, len(values))
	for _, value := range values {
		result[targetKey(value.TargetKind, value.TargetID)] = versionedResource{generation: value.Generation}
	}
	return result
}

func exposesByID(values []Expose) map[string]versionedResource {
	result := make(map[string]versionedResource, len(values))
	for _, value := range values {
		result[value.ID] = versionedResource{generation: value.Generation}
	}
	return result
}

func certificatesByID(values []Certificate) map[string]versionedResource {
	result := make(map[string]versionedResource, len(values))
	for _, value := range values {
		result[value.ID] = versionedResource{generation: value.Generation}
	}
	return result
}

func validateExposeTransitions(before, after []Expose) error {
	previous := make(map[string]Expose, len(before))
	for _, expose := range before {
		previous[expose.ID] = expose
	}
	if err := validateVersionedTransitions("expose", exposesByID(before), exposesByID(after)); err != nil {
		return err
	}
	for _, expose := range after {
		old, exists := previous[expose.ID]
		if !exists {
			continue
		}
		if old.NodeID != expose.NodeID || !old.CreatedAt.Equal(expose.CreatedAt) {
			return transitionError("expose %s owner and creation time are immutable", expose.ID)
		}
	}
	return nil
}

func validateCertificateTransitions(before, after []Certificate) error {
	previous := make(map[string]Certificate, len(before))
	for _, certificate := range before {
		previous[certificate.ID] = certificate
	}
	if err := validateVersionedTransitions("certificate", certificatesByID(before), certificatesByID(after)); err != nil {
		return err
	}
	for _, certificate := range after {
		old, exists := previous[certificate.ID]
		if !exists {
			continue
		}
		if old.Kind != certificate.Kind || old.OwnerKind != certificate.OwnerKind || old.OwnerID != certificate.OwnerID {
			return transitionError("certificate %s kind and owner are immutable", certificate.ID)
		}
		if old.CredentialGeneration != certificate.CredentialGeneration {
			return transitionError("certificate %s credential generation is immutable", certificate.ID)
		}
	}
	return nil
}

func validateStableRecordIdentities(before, after State) error {
	operations := make(map[string]Operation, len(before.Operations))
	for _, operation := range before.Operations {
		operations[operation.ID] = operation
	}
	for _, operation := range after.Operations {
		old, exists := operations[operation.ID]
		if !exists {
			if operation.State != OperationPending || !operation.UpdatedAt.Equal(operation.CreatedAt) {
				return transitionError("new operation %s must start pending at its creation time", operation.ID)
			}
			for _, step := range operation.Steps {
				if step.State != OperationPending || !step.UpdatedAt.Equal(operation.CreatedAt) {
					return transitionError("new operation %s steps must start pending at its creation time", operation.ID)
				}
			}
			continue
		}
		if err := validateOperationEvolution(old, operation); err != nil {
			return err
		}
	}
	currentOperations := make(map[string]struct{}, len(after.Operations))
	for _, operation := range after.Operations {
		currentOperations[operation.ID] = struct{}{}
	}
	for _, operation := range before.Operations {
		if _, exists := currentOperations[operation.ID]; !exists && !terminalOperationState(operation.State) {
			return transitionError("non-terminal operation %s cannot be removed", operation.ID)
		}
	}

	logging := make(map[string]LoggingSession, len(before.Logging))
	for _, session := range before.Logging {
		logging[session.ID] = session
	}
	for _, session := range after.Logging {
		old, exists := logging[session.ID]
		if exists && (old.Scope != session.Scope || !old.StartedAt.Equal(session.StartedAt)) {
			return transitionError("logging session %s identity fields are immutable", session.ID)
		}
	}

	backups := make(map[string]Backup, len(before.Backups))
	for _, backup := range before.Backups {
		backups[backup.ID] = backup
	}
	for _, backup := range after.Backups {
		old, exists := backups[backup.ID]
		if exists && !reflect.DeepEqual(old, backup) {
			return transitionError("completed backup %s metadata is immutable", backup.ID)
		}
	}
	return nil
}

func validateOperationEvolution(before, after Operation) error {
	if before.Type != after.Type || before.TargetKind != after.TargetKind || before.TargetID != after.TargetID ||
		before.RequestID != after.RequestID || before.ExpectedGeneration != after.ExpectedGeneration ||
		before.DesiredGeneration != after.DesiredGeneration || !before.CreatedAt.Equal(after.CreatedAt) {
		return transitionError("operation %s identity and generation fields are immutable", after.ID)
	}
	if after.UpdatedAt.Before(before.UpdatedAt) {
		return transitionError("operation %s update time moved backwards", after.ID)
	}
	if before.State != after.State && !canTransitionOperation(before.State, after.State) {
		return transitionError("operation %s cannot move from %s to %s", after.ID, before.State, after.State)
	}
	if len(before.Steps) != len(after.Steps) {
		return transitionError("operation %s step plan is immutable", after.ID)
	}
	for index := range before.Steps {
		oldStep := before.Steps[index]
		newStep := after.Steps[index]
		if oldStep.Name != newStep.Name {
			return transitionError("operation %s step plan is immutable", after.ID)
		}
		if newStep.UpdatedAt.Before(oldStep.UpdatedAt) {
			return transitionError("operation %s step %s update time moved backwards", after.ID, oldStep.Name)
		}
		if oldStep.State == newStep.State {
			if !oldStep.UpdatedAt.Equal(newStep.UpdatedAt) {
				return transitionError("operation %s step %s timestamp changed without a state transition", after.ID, oldStep.Name)
			}
		} else if !canTransitionOperation(oldStep.State, newStep.State) {
			return transitionError("operation %s step %s cannot move from %s to %s", after.ID, oldStep.Name, oldStep.State, newStep.State)
		}
	}
	return nil
}

func policyFor(policies []Policy, kind TargetKind, id string) *Policy {
	for index := range policies {
		if policies[index].TargetKind == kind && policies[index].TargetID == id {
			copy := policies[index]
			return &copy
		}
	}
	return nil
}

func exposeIDsForNode(exposes []Expose, nodeID string) []string {
	ids := make([]string, 0)
	for _, expose := range exposes {
		if expose.NodeID == nodeID {
			ids = append(ids, expose.ID)
		}
	}
	return ids
}

func transitionError(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTransition, fmt.Sprintf(format, arguments...))
}
