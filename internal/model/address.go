package model

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

const (
	DefaultClientCIDR = "10.66.0.0/24"
	DefaultNodeCIDR   = "10.67.0.0/24"
)

var (
	ErrAddressPoolExhausted = errors.New("address pool exhausted")
	ErrAddressConflict      = errors.New("address assignment conflict")
)

type AddressAssignment struct {
	Kind    TargetKind
	ID      string
	Address string
}

type AddressAllocator struct {
	pools       map[TargetKind]ipv4Pool
	assignments map[string]AddressAssignment
	used        map[TargetKind]map[uint32]string
}

type ipv4Pool struct {
	prefix netip.Prefix
	first  uint32
	last   uint32
}

func NewAddressAllocator(clientCIDR, nodeCIDR string, restored []AddressAssignment) (*AddressAllocator, error) {
	clientPool, err := newIPv4Pool("client_cidr", clientCIDR)
	if err != nil {
		return nil, err
	}
	nodePool, err := newIPv4Pool("node_cidr", nodeCIDR)
	if err != nil {
		return nil, err
	}
	if clientPool.prefix.Overlaps(nodePool.prefix) {
		return nil, fmt.Errorf("%w: client and node pools overlap", ErrAddressConflict)
	}
	allocator := &AddressAllocator{
		pools: map[TargetKind]ipv4Pool{
			TargetClient: clientPool,
			TargetNode:   nodePool,
		},
		assignments: make(map[string]AddressAssignment, len(restored)),
		used: map[TargetKind]map[uint32]string{
			TargetClient: make(map[uint32]string),
			TargetNode:   make(map[uint32]string),
		},
	}
	for index, assignment := range restored {
		if err := allocator.Reserve(assignment.Kind, assignment.ID, assignment.Address); err != nil {
			return nil, fmt.Errorf("restore assignment %d: %w", index, err)
		}
	}
	return allocator, nil
}

func AddressAllocatorFromState(state State) (*AddressAllocator, error) {
	if err := state.Validate(); err != nil {
		return nil, fmt.Errorf("validate state: %w", err)
	}
	if state.Host.Role != RoleGateway {
		return nil, fmt.Errorf("address allocator requires gateway state")
	}
	assignments := make([]AddressAssignment, 0, len(state.Clients)+len(state.Nodes))
	for _, client := range state.Clients {
		if client.Lifecycle != LifecycleDeleted {
			assignments = append(assignments, AddressAssignment{Kind: TargetClient, ID: client.ID, Address: client.OverlayIPv4})
		}
	}
	for _, node := range state.Nodes {
		if node.Lifecycle != LifecycleDeleted {
			assignments = append(assignments, AddressAssignment{Kind: TargetNode, ID: node.ID, Address: node.OverlayIPv4})
		}
	}
	return NewAddressAllocator(state.Host.ClientCIDR, state.Host.NodeCIDR, assignments)
}

func (allocator *AddressAllocator) Allocate(kind TargetKind, id string) (string, error) {
	pool, err := allocator.pool(kind)
	if err != nil {
		return "", err
	}
	if err := validateUUID("id", id); err != nil {
		return "", err
	}
	key := targetKey(kind, id)
	if assignment, exists := allocator.assignments[key]; exists {
		return assignment.Address, nil
	}
	for candidate := uint64(pool.first); candidate <= uint64(pool.last); candidate++ {
		address := uint32(candidate)
		if _, occupied := allocator.used[kind][address]; occupied {
			continue
		}
		text := uint32ToIPv4(address).String()
		allocator.assignments[key] = AddressAssignment{Kind: kind, ID: id, Address: text}
		allocator.used[kind][address] = id
		return text, nil
	}
	return "", fmt.Errorf("%w: %s pool %s", ErrAddressPoolExhausted, kind, pool.prefix)
}

func (allocator *AddressAllocator) Reserve(kind TargetKind, id, addressText string) error {
	pool, err := allocator.pool(kind)
	if err != nil {
		return err
	}
	if err := validateUUID("id", id); err != nil {
		return err
	}
	address, err := netip.ParseAddr(addressText)
	if err != nil || !address.Is4() || address.String() != addressText {
		return fmt.Errorf("address: must be a canonical IPv4 address")
	}
	numeric := ipv4ToUint32(address)
	if !pool.prefix.Contains(address) || numeric < pool.first || numeric > pool.last {
		return fmt.Errorf("%w: address %s is not usable in %s pool %s", ErrAddressConflict, address, kind, pool.prefix)
	}
	key := targetKey(kind, id)
	if existing, assigned := allocator.assignments[key]; assigned {
		if existing.Address == addressText {
			return nil
		}
		return fmt.Errorf("%w: %s %s already owns %s", ErrAddressConflict, kind, id, existing.Address)
	}
	if owner, occupied := allocator.used[kind][numeric]; occupied {
		return fmt.Errorf("%w: address %s is already owned by %s", ErrAddressConflict, address, owner)
	}
	allocator.assignments[key] = AddressAssignment{Kind: kind, ID: id, Address: addressText}
	allocator.used[kind][numeric] = id
	return nil
}

func (allocator *AddressAllocator) Release(kind TargetKind, id string) (bool, error) {
	if _, err := allocator.pool(kind); err != nil {
		return false, err
	}
	if err := validateUUID("id", id); err != nil {
		return false, err
	}
	key := targetKey(kind, id)
	assignment, exists := allocator.assignments[key]
	if !exists {
		return false, nil
	}
	address, _ := netip.ParseAddr(assignment.Address)
	delete(allocator.used[kind], ipv4ToUint32(address))
	delete(allocator.assignments, key)
	return true, nil
}

func (allocator *AddressAllocator) Lookup(kind TargetKind, id string) (string, bool) {
	if allocator == nil {
		return "", false
	}
	assignment, exists := allocator.assignments[targetKey(kind, id)]
	if !exists {
		return "", false
	}
	return assignment.Address, true
}

func (allocator *AddressAllocator) Assignments() []AddressAssignment {
	if allocator == nil {
		return nil
	}
	result := make([]AddressAssignment, 0, len(allocator.assignments))
	for _, assignment := range allocator.assignments {
		result = append(result, assignment)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Kind != result[right].Kind {
			return result[left].Kind < result[right].Kind
		}
		return result[left].ID < result[right].ID
	})
	return result
}

func (allocator *AddressAllocator) pool(kind TargetKind) (ipv4Pool, error) {
	if allocator == nil {
		return ipv4Pool{}, fmt.Errorf("address allocator is nil")
	}
	pool, exists := allocator.pools[kind]
	if !exists {
		return ipv4Pool{}, fmt.Errorf("unsupported address target %q", kind)
	}
	return pool, nil
}

func newIPv4Pool(path, value string) (ipv4Pool, error) {
	prefix, err := validateIPv4Prefix(path, value)
	if err != nil {
		return ipv4Pool{}, err
	}
	base := uint64(ipv4ToUint32(prefix.Addr()))
	size := uint64(1) << (32 - prefix.Bits())
	if size < 4 {
		return ipv4Pool{}, invalid(path, "must provide network, gateway, one identity, and broadcast addresses")
	}
	return ipv4Pool{
		prefix: prefix,
		first:  uint32(base + 2),
		last:   uint32(base + size - 2),
	}, nil
}

func ipv4ToUint32(address netip.Addr) uint32 {
	raw := address.As4()
	return binary.BigEndian.Uint32(raw[:])
}

func uint32ToIPv4(value uint32) netip.Addr {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return netip.AddrFrom4(raw)
}
