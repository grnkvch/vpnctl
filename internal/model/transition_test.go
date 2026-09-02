package model

import (
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

func TestNewUUIDProperties(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 1024)
	for index := 0; index < 1024; index++ {
		id, err := NewUUID()
		if err != nil {
			t.Fatalf("NewUUID() error = %v", err)
		}
		if err := validateGeneratedUUID(id); err != nil {
			t.Fatalf("NewUUID() = %q: %v", id, err)
		}
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("NewUUID() collision at sample %d: %s", index, id)
		}
		seen[id] = struct{}{}
	}
}

func TestAllocateUUIDCollisionHandling(t *testing.T) {
	t.Parallel()

	collision := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	available := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	sequence := []string{collision, collision, available}
	calls := 0
	occupied := map[string]struct{}{collision: {}}
	id, err := AllocateUUID(occupied, func() (string, error) {
		id := sequence[calls]
		calls++
		return id, nil
	})
	if err != nil {
		t.Fatalf("AllocateUUID() error = %v", err)
	}
	if id != available || calls != 3 {
		t.Fatalf("AllocateUUID() = %q after %d calls, want %q after 3", id, calls, available)
	}
	if _, reserved := occupied[available]; !reserved {
		t.Fatal("AllocateUUID() did not reserve the returned identity")
	}

	calls = 0
	_, err = AllocateUUID(map[string]struct{}{collision: {}}, func() (string, error) {
		calls++
		return collision, nil
	})
	if !errors.Is(err, ErrIdentityCollision) || calls != UUIDCollisionRetryLimit {
		t.Fatalf("AllocateUUID() error = %v after %d calls", err, calls)
	}

	sourceError := errors.New("entropy unavailable")
	_, err = AllocateUUID(nil, func() (string, error) { return "", sourceError })
	if !errors.Is(err, sourceError) {
		t.Fatalf("AllocateUUID() generator error = %v", err)
	}

	_, err = AllocateUUID(nil, func() (string, error) { return "not-a-uuid", nil })
	if err == nil || !strings.Contains(err.Error(), "generated UUID") {
		t.Fatalf("AllocateUUID() invalid UUID error = %v", err)
	}
}

func TestAllocateUUIDCollisionProperty(t *testing.T) {
	t.Parallel()

	property := func(sample uint8) bool {
		collisions := int(sample) % UUIDCollisionRetryLimit
		collision := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		available := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		calls := 0
		id, err := AllocateUUID(map[string]struct{}{collision: {}}, func() (string, error) {
			calls++
			if calls <= collisions {
				return collision, nil
			}
			return available, nil
		})
		return err == nil && id == available && calls == collisions+1
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 512}); err != nil {
		t.Fatal(err)
	}
}

func TestUUIDEntropyFailure(t *testing.T) {
	t.Parallel()

	_, err := newUUIDFrom(io.LimitReader(strings.NewReader("short"), 5))
	if err == nil || !strings.Contains(err.Error(), "entropy") {
		t.Fatalf("newUUIDFrom() error = %v", err)
	}
}

func TestUniqueExistingNamesProperty(t *testing.T) {
	t.Parallel()

	property := func(value uint64) bool {
		state := gatewayState()
		duplicate := state.Nodes[0]
		duplicate.ID = fmt.Sprintf("%08x-0000-4000-8000-%012x", uint32(value), value&0xffffffffffff)
		if duplicate.ID == state.Nodes[0].ID {
			duplicate.ID = "66666666-6666-4666-8666-666666666666"
		}
		duplicate.Name = strings.ToUpper(duplicate.Name)
		state.Nodes = append(state.Nodes, duplicate)
		err := state.Validate()
		return err != nil && strings.Contains(err.Error(), "duplicates active node name")
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 512}); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialGenerationPreservesResourceProperty(t *testing.T) {
	t.Parallel()

	nodeProperty := func(generation uint64) bool {
		if generation == 0 || generation == math.MaxUint64 {
			return true
		}
		before := gatewayState().Nodes[0]
		before.CredentialGeneration = generation
		after, err := before.AdvanceCredentialGeneration()
		if err != nil || after.CredentialGeneration != generation+1 {
			return false
		}
		after.CredentialGeneration = before.CredentialGeneration
		return reflect.DeepEqual(after, before)
	}
	if err := quick.Check(nodeProperty, &quick.Config{MaxCount: 512}); err != nil {
		t.Fatalf("node rotation property: %v", err)
	}

	clientProperty := func(generation uint64) bool {
		if generation == 0 || generation == math.MaxUint64 {
			return true
		}
		before := gatewayState().Clients[0]
		before.CredentialGeneration = generation
		after, err := before.AdvanceCredentialGeneration()
		if err != nil || after.CredentialGeneration != generation+1 {
			return false
		}
		after.CredentialGeneration = before.CredentialGeneration
		return reflect.DeepEqual(after, before)
	}
	if err := quick.Check(clientProperty, &quick.Config{MaxCount: 512}); err != nil {
		t.Fatalf("client rotation property: %v", err)
	}
}

func TestValidateCredentialRotationTransition(t *testing.T) {
	t.Parallel()

	before := gatewayState()
	after := cloneState(t, before)
	after.Generation++
	after.Nodes[0].CredentialGeneration++
	for index := range after.Transports[:2] {
		after.Transports[index].CredentialGeneration++
		after.Transports[index].CredentialRef += "-g4"
		after.Transports[index].ConfigHash = digest("2")
	}
	if err := ValidateTransition(before, after); err != nil {
		t.Fatalf("ValidateTransition() error = %v", err)
	}

	changedPolicy := cloneState(t, after)
	changedPolicy.Policies[0].Generation++
	changedPolicy.Policies[0].EffectiveHash = digest("3")
	if err := ValidateTransition(before, changedPolicy); err == nil || !strings.Contains(err.Error(), "rotation changed its policy") {
		t.Fatalf("ValidateTransition() changed policy error = %v", err)
	}

	changedExpose := cloneState(t, after)
	changedExpose.Exposes = []Expose{}
	if err := ValidateTransition(before, changedExpose); err == nil || !strings.Contains(err.Error(), "expose identities") {
		t.Fatalf("ValidateTransition() changed exposes error = %v", err)
	}

	changedIdentity := cloneState(t, after)
	changedIdentity.Nodes[0].Name = "replacement"
	if err := ValidateTransition(before, changedIdentity); err == nil || !strings.Contains(err.Error(), "rotation changed its name") {
		t.Fatalf("ValidateTransition() changed identity error = %v", err)
	}
}

func TestLifecycleTransitionOrdering(t *testing.T) {
	t.Parallel()

	created := utc(2026, time.September, 2, 10, 0)
	revokedAt := created.Add(time.Hour)
	node := gatewayState().Nodes[0]

	if _, err := node.Delete(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("active Node.Delete() error = %v", err)
	}
	revoked, err := node.Revoke(revokedAt)
	if err != nil {
		t.Fatalf("Node.Revoke() error = %v", err)
	}
	if revoked.ID != node.ID || revoked.Lifecycle != LifecycleRevoked || revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(revokedAt) {
		t.Fatalf("Node.Revoke() = %#v", revoked)
	}
	secondRevoke, err := revoked.Revoke(revokedAt.Add(time.Hour))
	if err != nil || !reflect.DeepEqual(secondRevoke, revoked) {
		t.Fatalf("idempotent Node.Revoke() = %#v, %v", secondRevoke, err)
	}
	deleted, err := revoked.Delete()
	if err != nil {
		t.Fatalf("Node.Delete() error = %v", err)
	}
	if deleted.ID != node.ID || deleted.Lifecycle != LifecycleDeleted || !reflect.DeepEqual(deleted.RevokedAt, revoked.RevokedAt) {
		t.Fatalf("Node.Delete() = %#v", deleted)
	}
	if _, err := deleted.Revoke(revokedAt); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("deleted Node.Revoke() error = %v", err)
	}
	if _, err := node.Revoke(created.Add(-time.Second)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("early Node.Revoke() error = %v", err)
	}

	client := gatewayState().Clients[0]
	revokedClient, err := client.Revoke(revokedAt)
	if err != nil {
		t.Fatalf("Client.Revoke() error = %v", err)
	}
	deletedClient, err := revokedClient.Delete()
	if err != nil {
		t.Fatalf("Client.Delete() error = %v", err)
	}
	if deletedClient.ID != client.ID || deletedClient.Lifecycle != LifecycleDeleted {
		t.Fatalf("Client.Delete() = %#v", deletedClient)
	}
}

func TestLifecycleOrderingProperty(t *testing.T) {
	t.Parallel()

	property := func(offset uint32) bool {
		node := gatewayState().Nodes[0]
		at := node.CreatedAt.Add(time.Duration(offset) * time.Second)
		if _, err := node.Delete(); !errors.Is(err, ErrInvalidTransition) {
			return false
		}
		revoked, err := node.Revoke(at)
		if err != nil {
			return false
		}
		deleted, err := revoked.Delete()
		return err == nil && deleted.ID == node.ID && deleted.Lifecycle == LifecycleDeleted && deleted.RevokedAt != nil && deleted.RevokedAt.Equal(at)
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 512}); err != nil {
		t.Fatal(err)
	}
}

func TestStateLifecycleTransitionOrdering(t *testing.T) {
	t.Parallel()

	before := gatewayState()
	directDelete := cloneState(t, before)
	directDelete.Generation++
	directDelete.Nodes[0].Lifecycle = LifecycleDeleted
	revokedAt := directDelete.Nodes[0].CreatedAt.Add(time.Hour)
	directDelete.Nodes[0].RevokedAt = &revokedAt
	directDelete.Nodes[0].AssignedPresets = []string{}
	directDelete.Policies = directDelete.Policies[1:]
	directDelete.Transports = directDelete.Transports[2:]
	directDelete.Exposes = []Expose{}
	directDelete.Certificates = directDelete.Certificates[:1]
	if err := ValidateTransition(before, directDelete); err == nil || !strings.Contains(err.Error(), "lifecycle cannot move") {
		t.Fatalf("ValidateTransition() direct delete error = %v", err)
	}

	revoked := cloneState(t, before)
	revoked.Generation++
	revoked.Nodes[0], _ = revoked.Nodes[0].Revoke(revokedAt)
	revoked.Transports[0].State = TransportDisabled
	revoked.Transports[1].State = TransportDisabled
	revoked.Exposes[0].State = ExposeDisabled
	if err := ValidateTransition(before, revoked); err != nil {
		t.Fatalf("ValidateTransition() revoke error = %v", err)
	}

	deleted := cloneState(t, revoked)
	deleted.Generation++
	deleted.Nodes[0], _ = deleted.Nodes[0].Delete()
	deleted.Nodes[0].AssignedPresets = []string{}
	deleted.Policies = deleted.Policies[1:]
	deleted.Transports = deleted.Transports[2:]
	deleted.Exposes = []Expose{}
	deleted.Certificates = deleted.Certificates[:1]
	if err := ValidateTransition(revoked, deleted); err != nil {
		t.Fatalf("ValidateTransition() delete error = %v", err)
	}

	removed := cloneState(t, deleted)
	removed.Generation++
	removed.Nodes = []Node{}
	if err := ValidateTransition(deleted, removed); err != nil {
		t.Fatalf("ValidateTransition() tombstone removal error = %v", err)
	}
}

func TestTransitionRejectsIdentityReplacementAndGenerationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*State)
		want   string
	}{
		{name: "host id", mutate: func(state *State) { state.Host.ID = nodeHostID }, want: "host identity"},
		{name: "host role", mutate: func(state *State) { state.Host.Role = RoleNode }, want: "host role"},
		{name: "generation unchanged", mutate: func(state *State) { state.Generation-- }, want: "advance exactly once"},
		{name: "generation jump", mutate: func(state *State) { state.Generation++ }, want: "advance exactly once"},
		{name: "remove active node", mutate: func(state *State) {
			state.Nodes = []Node{}
			state.Policies = state.Policies[1:]
			state.Transports = state.Transports[2:]
			state.Exposes = []Expose{}
			state.Certificates = state.Certificates[:1]
		}, want: "cannot be removed before revoke"},
		{name: "change overlay address", mutate: func(state *State) { state.Nodes[0].OverlayIPv4 = "10.67.0.3" }, want: "overlay address is immutable"},
		{name: "credential generation jump", mutate: func(state *State) {
			state.Nodes[0].CredentialGeneration += 2
			state.Transports[0].CredentialGeneration += 2
			state.Transports[1].CredentialGeneration += 2
		}, want: "advance exactly once"},
		{name: "credential generation decrease", mutate: func(state *State) {
			state.Nodes[0].CredentialGeneration--
			state.Transports[0].CredentialGeneration--
			state.Transports[1].CredentialGeneration--
		}, want: "decreased"},
		{name: "preset generation jump", mutate: func(state *State) { state.Presets[0].Generation += 2 }, want: "generation must advance exactly once"},
		{name: "expose ownership", mutate: func(state *State) { state.Exposes[0].CreatedAt = state.Exposes[0].CreatedAt.Add(time.Second) }, want: "owner and creation time are immutable"},
		{name: "certificate kind", mutate: func(state *State) { state.Certificates[0].Kind = CertificateControlServer }, want: "kind and owner are immutable"},
		{name: "operation identity", mutate: func(state *State) { state.Operations[0].TargetID = "openai" }, want: "operation"},
		{name: "logging identity", mutate: func(state *State) { state.Logging[0].Scope = LogRouting }, want: "logging session"},
		{name: "backup metadata", mutate: func(state *State) { state.Backups[0].SHA256 = digest("4") }, want: "backup"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			before := gatewayState()
			after := cloneState(t, before)
			after.Generation++
			test.mutate(&after)
			err := ValidateTransition(before, after)
			if err == nil || !errors.Is(err, ErrInvalidTransition) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateTransition() error = %v, want invalid transition containing %q", err, test.want)
			}
		})
	}
}

func TestGenerationOverflow(t *testing.T) {
	t.Parallel()

	if next, err := NextGeneration(math.MaxUint64 - 1); err != nil || next != math.MaxUint64 {
		t.Fatalf("NextGeneration(max-1) = %d, %v", next, err)
	}
	if _, err := NextGeneration(math.MaxUint64); !errors.Is(err, ErrGenerationOverflow) {
		t.Fatalf("NextGeneration(max) error = %v", err)
	}

	before := gatewayState()
	before.Generation = math.MaxUint64
	after := cloneState(t, before)
	if err := ValidateTransition(before, after); !errors.Is(err, ErrGenerationOverflow) {
		t.Fatalf("ValidateTransition() state overflow error = %v", err)
	}

	node := gatewayState().Nodes[0]
	node.CredentialGeneration = math.MaxUint64
	if _, err := node.AdvanceCredentialGeneration(); !errors.Is(err, ErrGenerationOverflow) {
		t.Fatalf("Node.AdvanceCredentialGeneration() error = %v", err)
	}
	client := gatewayState().Clients[0]
	client.CredentialGeneration = math.MaxUint64
	if _, err := client.AdvanceCredentialGeneration(); !errors.Is(err, ErrGenerationOverflow) {
		t.Fatalf("Client.AdvanceCredentialGeneration() error = %v", err)
	}
}

func TestNextGenerationProperty(t *testing.T) {
	t.Parallel()

	property := func(current uint64) bool {
		next, err := NextGeneration(current)
		if current == math.MaxUint64 {
			return next == 0 && errors.Is(err, ErrGenerationOverflow)
		}
		return err == nil && next == current+1 && next > current
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1024}); err != nil {
		t.Fatal(err)
	}
}
