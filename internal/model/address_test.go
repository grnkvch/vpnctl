package model

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

func TestAddressAllocatorUsesIndependentDefaultPools(t *testing.T) {
	t.Parallel()

	allocator, err := NewAddressAllocator(DefaultClientCIDR, DefaultNodeCIDR, nil)
	if err != nil {
		t.Fatalf("NewAddressAllocator() error = %v", err)
	}
	clientAddress, err := allocator.Allocate(TargetClient, clientID)
	if err != nil {
		t.Fatalf("Allocate(client) error = %v", err)
	}
	nodeAddress, err := allocator.Allocate(TargetNode, nodeID)
	if err != nil {
		t.Fatalf("Allocate(node) error = %v", err)
	}
	if clientAddress != "10.66.0.2" || nodeAddress != "10.67.0.2" {
		t.Fatalf("allocated client/node = %s/%s", clientAddress, nodeAddress)
	}

	repeated, err := allocator.Allocate(TargetClient, clientID)
	if err != nil || repeated != clientAddress {
		t.Fatalf("stable Allocate(client) = %q, %v", repeated, err)
	}
	next, err := allocator.Allocate(TargetClient, testUUID(10))
	if err != nil || next != "10.66.0.3" {
		t.Fatalf("next Allocate(client) = %q, %v", next, err)
	}
}

func TestAddressAllocatorExhaustionAndReservedAddresses(t *testing.T) {
	t.Parallel()

	allocator, err := NewAddressAllocator("10.80.0.0/30", "10.80.0.4/30", nil)
	if err != nil {
		t.Fatalf("NewAddressAllocator() error = %v", err)
	}
	address, err := allocator.Allocate(TargetClient, clientID)
	if err != nil || address != "10.80.0.2" {
		t.Fatalf("Allocate() = %q, %v", address, err)
	}
	if _, err := allocator.Allocate(TargetClient, testUUID(11)); !errors.Is(err, ErrAddressPoolExhausted) {
		t.Fatalf("second Allocate() error = %v", err)
	}

	for _, reserved := range []string{"10.80.0.0", "10.80.0.1", "10.80.0.3", "10.80.0.4"} {
		if err := allocator.Reserve(TargetClient, testUUID(12), reserved); !errors.Is(err, ErrAddressConflict) {
			t.Errorf("Reserve(%s) error = %v", reserved, err)
		}
	}
	if _, err := NewAddressAllocator("10.80.0.0/31", "10.80.0.4/30", nil); err == nil || !strings.Contains(err.Error(), "must provide") {
		t.Fatalf("NewAddressAllocator(/31) error = %v", err)
	}
}

func TestAddressAllocatorRejectsPoolAndAssignmentConflicts(t *testing.T) {
	t.Parallel()

	if _, err := NewAddressAllocator("10.66.0.0/24", "10.66.0.128/25", nil); !errors.Is(err, ErrAddressConflict) {
		t.Fatalf("overlapping NewAddressAllocator() error = %v", err)
	}
	allocator, err := NewAddressAllocator(DefaultClientCIDR, DefaultNodeCIDR, nil)
	if err != nil {
		t.Fatalf("NewAddressAllocator() error = %v", err)
	}
	if err := allocator.Reserve(TargetClient, clientID, "10.66.0.42"); err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if err := allocator.Reserve(TargetClient, clientID, "10.66.0.42"); err != nil {
		t.Fatalf("idempotent Reserve() error = %v", err)
	}
	if err := allocator.Reserve(TargetClient, clientID, "10.66.0.43"); !errors.Is(err, ErrAddressConflict) {
		t.Fatalf("identity reassignment error = %v", err)
	}
	if err := allocator.Reserve(TargetClient, testUUID(20), "10.66.0.42"); !errors.Is(err, ErrAddressConflict) {
		t.Fatalf("duplicate address error = %v", err)
	}
	if err := allocator.Reserve(TargetNode, nodeID, "10.66.0.44"); !errors.Is(err, ErrAddressConflict) {
		t.Fatalf("wrong pool error = %v", err)
	}
	if _, err := allocator.Allocate(TargetKind("peer"), nodeID); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown target error = %v", err)
	}
}

func TestAddressReleaseDoesNotMoveRetainedIdentities(t *testing.T) {
	t.Parallel()

	allocator, err := NewAddressAllocator(DefaultClientCIDR, DefaultNodeCIDR, nil)
	if err != nil {
		t.Fatalf("NewAddressAllocator() error = %v", err)
	}
	firstID := testUUID(30)
	secondID := testUUID(31)
	thirdID := testUUID(32)
	first, _ := allocator.Allocate(TargetClient, firstID)
	second, _ := allocator.Allocate(TargetClient, secondID)
	if released, err := allocator.Release(TargetClient, firstID); err != nil || !released {
		t.Fatalf("Release() = %t, %v", released, err)
	}
	if released, err := allocator.Release(TargetClient, firstID); err != nil || released {
		t.Fatalf("idempotent Release() = %t, %v", released, err)
	}
	if retained, found := allocator.Lookup(TargetClient, secondID); !found || retained != second {
		t.Fatalf("retained assignment = %q, %t", retained, found)
	}
	reused, err := allocator.Allocate(TargetClient, thirdID)
	if err != nil || reused != first {
		t.Fatalf("reused assignment = %q, %v; want %q", reused, err, first)
	}
}

func TestAddressAllocatorRestoreProperty(t *testing.T) {
	t.Parallel()

	property := func(sample uint8) bool {
		count := int(sample)%100 + 1
		allocator, err := NewAddressAllocator(DefaultClientCIDR, DefaultNodeCIDR, nil)
		if err != nil {
			return false
		}
		for index := 0; index < count; index++ {
			if _, err := allocator.Allocate(TargetClient, testUUID(uint64(index+100))); err != nil {
				return false
			}
		}
		snapshot := allocator.Assignments()
		restored, err := NewAddressAllocator(DefaultClientCIDR, DefaultNodeCIDR, snapshot)
		if err != nil || !reflect.DeepEqual(restored.Assignments(), snapshot) {
			return false
		}
		for _, assignment := range snapshot {
			address, err := restored.Allocate(assignment.Kind, assignment.ID)
			if err != nil || address != assignment.Address {
				return false
			}
		}
		next, err := restored.Allocate(TargetClient, testUUID(uint64(count+100)))
		return err == nil && next == fmt.Sprintf("10.66.0.%d", count+2)
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 256}); err != nil {
		t.Fatal(err)
	}
}

func TestAddressRemainsStableAcrossCredentialRotation(t *testing.T) {
	t.Parallel()

	before := gatewayState()
	beforeAllocator, err := AddressAllocatorFromState(before)
	if err != nil {
		t.Fatalf("AddressAllocatorFromState(before) error = %v", err)
	}
	after := cloneState(t, before)
	after.Generation++
	after.Nodes[0].CredentialGeneration++
	after.Transports[0].CredentialGeneration++
	after.Transports[1].CredentialGeneration++
	if err := ValidateTransition(before, after); err != nil {
		t.Fatalf("ValidateTransition(rotation) error = %v", err)
	}
	afterAllocator, err := AddressAllocatorFromState(after)
	if err != nil {
		t.Fatalf("AddressAllocatorFromState(after) error = %v", err)
	}
	beforeAddress, _ := beforeAllocator.Lookup(TargetNode, nodeID)
	afterAddress, _ := afterAllocator.Lookup(TargetNode, nodeID)
	if beforeAddress != afterAddress || beforeAddress != "10.67.0.2" {
		t.Fatalf("node address changed across rotation: %q -> %q", beforeAddress, afterAddress)
	}
}

func TestAddressMayChangeOnlyDuringMatchingPoolMigration(t *testing.T) {
	t.Parallel()

	before := gatewayState()
	after := cloneState(t, before)
	after.Generation++
	after.Host.NodeCIDR = "10.68.0.0/24"
	after.Nodes[0].OverlayIPv4 = "10.68.0.2"
	if err := ValidateTransition(before, after); err != nil {
		t.Fatalf("ValidateTransition(node pool migration) error = %v", err)
	}

	wrongPool := cloneState(t, after)
	wrongPool.Clients[0].OverlayIPv4 = "10.66.0.3"
	if err := ValidateTransition(before, wrongPool); err == nil || !strings.Contains(err.Error(), "only with its pool") {
		t.Fatalf("ValidateTransition(unrelated address migration) error = %v", err)
	}
}

func TestV1AddressReservationIsPreserved(t *testing.T) {
	t.Parallel()

	allocator, err := NewAddressAllocator(DefaultClientCIDR, DefaultNodeCIDR, nil)
	if err != nil {
		t.Fatalf("NewAddressAllocator() error = %v", err)
	}
	mappedV1ID := testUUID(500)
	if err := allocator.Reserve(TargetClient, mappedV1ID, "10.66.0.42"); err != nil {
		t.Fatalf("Reserve(v1 address) error = %v", err)
	}
	stable, err := allocator.Allocate(TargetClient, mappedV1ID)
	if err != nil || stable != "10.66.0.42" {
		t.Fatalf("Allocate(mapped v1 identity) = %q, %v", stable, err)
	}
	restored, err := NewAddressAllocator(DefaultClientCIDR, DefaultNodeCIDR, allocator.Assignments())
	if err != nil {
		t.Fatalf("restore allocator error = %v", err)
	}
	stable, found := restored.Lookup(TargetClient, mappedV1ID)
	if !found || stable != "10.66.0.42" {
		t.Fatalf("restored v1 assignment = %q, %t", stable, found)
	}
	firstFree, err := restored.Allocate(TargetClient, testUUID(501))
	if err != nil || firstFree != "10.66.0.2" {
		t.Fatalf("Allocate(after v1 reserve) = %q, %v", firstFree, err)
	}
}

func TestAddressAllocatorFromStateRetainsRevokedAndReleasesDeleted(t *testing.T) {
	t.Parallel()

	state := gatewayState()
	revokedAt := state.Nodes[0].CreatedAt.Add(time.Hour)
	state.Nodes[0], _ = state.Nodes[0].Revoke(revokedAt)
	state.Transports[0].State = TransportDisabled
	state.Transports[1].State = TransportDisabled
	state.Exposes[0].State = ExposeDisabled

	state.Clients[0], _ = state.Clients[0].Revoke(revokedAt)
	state.Clients[0], _ = state.Clients[0].Delete()
	state.Clients[0].AssignedPresets = []string{}
	state.Policies = state.Policies[:1]
	state.Transports = state.Transports[:2]

	allocator, err := AddressAllocatorFromState(state)
	if err != nil {
		t.Fatalf("AddressAllocatorFromState() error = %v", err)
	}
	if address, found := allocator.Lookup(TargetNode, nodeID); !found || address != "10.67.0.2" {
		t.Fatalf("revoked node assignment = %q, %t", address, found)
	}
	if _, found := allocator.Lookup(TargetClient, clientID); found {
		t.Fatal("deleted client assignment was retained")
	}
	address, err := allocator.Allocate(TargetClient, testUUID(600))
	if err != nil || address != "10.66.0.2" {
		t.Fatalf("Allocate(after deleted client) = %q, %v", address, err)
	}
}

func TestStateRejectsInvalidPoolAssignments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*State)
		want   string
	}{
		{name: "node in client pool", mutate: func(state *State) { state.Nodes[0].OverlayIPv4 = "10.66.0.3" }, want: "not usable"},
		{name: "client gateway address", mutate: func(state *State) { state.Clients[0].OverlayIPv4 = "10.66.0.1" }, want: "not usable"},
		{name: "duplicate client address", mutate: func(state *State) {
			duplicate := state.Clients[0]
			duplicate.ID = testUUID(700)
			duplicate.Name = "ipad"
			state.Clients = append(state.Clients, duplicate)
		}, want: "already owned"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := cloneState(t, gatewayState())
			test.mutate(&state)
			err := state.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func testUUID(value uint64) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", uint32(value), value&0xffffffffffff)
}
