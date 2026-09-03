package tunnel

import (
	"errors"
	"fmt"
	"sort"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	DefaultLoopbackPortFirst = 20000
	DefaultLoopbackPortLast  = 29999
)

var (
	ErrLoopbackPoolExhausted = errors.New("tunnel loopback port pool exhausted")
	ErrLoopbackPortConflict  = errors.New("tunnel loopback port conflict")
)

type PortAssignment struct {
	ExposeID string
	Port     int
}

type PortRemap struct {
	ExposeID     string
	PreviousPort int
	Port         int
}

// LoopbackAllocator owns only internal gateway ports. unavailable represents
// foreign or already-bound loopback listeners and is never released by vpnctl.
type LoopbackAllocator struct {
	first       int
	last        int
	assignments map[string]PortAssignment
	used        map[int]string
	unavailable map[int]struct{}
}

func NewLoopbackAllocator(first, last int, restored []PortAssignment) (*LoopbackAllocator, error) {
	allocator, remaps, err := RestoreLoopbackAllocator(first, last, restored, nil)
	if err != nil {
		return nil, err
	}
	if len(remaps) != 0 {
		return nil, fmt.Errorf("%w: saved assignment is outside range %d-%d", ErrLoopbackPortConflict, first, last)
	}
	return allocator, nil
}

// RestoreLoopbackAllocator preserves every usable saved assignment, then
// deterministically remaps unavailable or out-of-range saved ports. It returns
// no allocator on exhaustion, so callers can stage state, tunnel, and ingress
// from one complete result before publishing anything.
func RestoreLoopbackAllocator(first, last int, restored []PortAssignment, unavailable []int) (*LoopbackAllocator, []PortRemap, error) {
	if err := validatePortRange(first, last); err != nil {
		return nil, nil, err
	}
	allocator := &LoopbackAllocator{
		first:       first,
		last:        last,
		assignments: make(map[string]PortAssignment, len(restored)),
		used:        make(map[int]string, len(restored)),
		unavailable: make(map[int]struct{}, len(unavailable)),
	}
	for index, port := range unavailable {
		if port < 1 || port > 65535 {
			return nil, nil, fmt.Errorf("unavailable port %d at index %d is outside 1..65535", port, index)
		}
		if port >= first && port <= last {
			allocator.unavailable[port] = struct{}{}
		}
	}

	ordered := append([]PortAssignment(nil), restored...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].ExposeID < ordered[right].ExposeID })
	seenIDs := make(map[string]struct{}, len(ordered))
	savedPorts := make(map[int]string, len(ordered))
	for index, assignment := range ordered {
		if err := validateUUID("tunnel expose ID", assignment.ExposeID); err != nil {
			return nil, nil, fmt.Errorf("restore assignment %d: %w", index, err)
		}
		if assignment.Port < 1024 || assignment.Port > 65535 {
			return nil, nil, fmt.Errorf("restore assignment %d: port must be between 1024 and 65535", index)
		}
		if _, duplicate := seenIDs[assignment.ExposeID]; duplicate {
			return nil, nil, fmt.Errorf("%w: expose %s has multiple saved assignments", ErrLoopbackPortConflict, assignment.ExposeID)
		}
		if owner, duplicate := savedPorts[assignment.Port]; duplicate {
			return nil, nil, fmt.Errorf("%w: saved port %d is shared by exposes %s and %s", ErrLoopbackPortConflict, assignment.Port, owner, assignment.ExposeID)
		}
		seenIDs[assignment.ExposeID] = struct{}{}
		savedPorts[assignment.Port] = assignment.ExposeID
	}

	needsRemap := make([]PortAssignment, 0)
	for _, assignment := range ordered {
		if assignment.Port < first || assignment.Port > last {
			needsRemap = append(needsRemap, assignment)
			continue
		}
		if _, occupied := allocator.unavailable[assignment.Port]; occupied {
			needsRemap = append(needsRemap, assignment)
			continue
		}
		allocator.assignments[assignment.ExposeID] = assignment
		allocator.used[assignment.Port] = assignment.ExposeID
	}

	remaps := make([]PortRemap, 0, len(needsRemap))
	for _, assignment := range needsRemap {
		port, err := allocator.Allocate(assignment.ExposeID)
		if err != nil {
			return nil, nil, fmt.Errorf("restore expose %s: %w", assignment.ExposeID, err)
		}
		remaps = append(remaps, PortRemap{ExposeID: assignment.ExposeID, PreviousPort: assignment.Port, Port: port})
	}
	return allocator, remaps, nil
}

func DefaultLoopbackAllocator(restored []PortAssignment, unavailable []int) (*LoopbackAllocator, []PortRemap, error) {
	return RestoreLoopbackAllocator(DefaultLoopbackPortFirst, DefaultLoopbackPortLast, restored, unavailable)
}

func DefaultLoopbackAllocatorFromExposes(exposes []model.Expose, unavailable []int) (*LoopbackAllocator, []PortRemap, error) {
	assignments := make([]PortAssignment, 0, len(exposes))
	for index, expose := range exposes {
		if err := expose.Validate(); err != nil {
			return nil, nil, fmt.Errorf("persisted expose %d: %w", index, err)
		}
		assignments = append(assignments, PortAssignment{ExposeID: expose.ID, Port: expose.TunnelPort})
	}
	return DefaultLoopbackAllocator(assignments, unavailable)
}

func (allocator *LoopbackAllocator) Allocate(exposeID string) (int, error) {
	if err := allocator.valid(); err != nil {
		return 0, err
	}
	if err := validateUUID("tunnel expose ID", exposeID); err != nil {
		return 0, err
	}
	if assignment, exists := allocator.assignments[exposeID]; exists {
		return assignment.Port, nil
	}
	for port := allocator.first; port <= allocator.last; port++ {
		if _, occupied := allocator.used[port]; occupied {
			continue
		}
		if _, occupied := allocator.unavailable[port]; occupied {
			continue
		}
		allocator.assignments[exposeID] = PortAssignment{ExposeID: exposeID, Port: port}
		allocator.used[port] = exposeID
		return port, nil
	}
	return 0, fmt.Errorf("%w: range %d-%d", ErrLoopbackPoolExhausted, allocator.first, allocator.last)
}

func (allocator *LoopbackAllocator) Reserve(exposeID string, port int) error {
	if err := allocator.valid(); err != nil {
		return err
	}
	if err := validateUUID("tunnel expose ID", exposeID); err != nil {
		return err
	}
	if port < allocator.first || port > allocator.last {
		return fmt.Errorf("%w: port %d is outside range %d-%d", ErrLoopbackPortConflict, port, allocator.first, allocator.last)
	}
	if _, occupied := allocator.unavailable[port]; occupied {
		return fmt.Errorf("%w: port %d is unavailable", ErrLoopbackPortConflict, port)
	}
	if existing, assigned := allocator.assignments[exposeID]; assigned {
		if existing.Port == port {
			return nil
		}
		return fmt.Errorf("%w: expose %s already owns port %d", ErrLoopbackPortConflict, exposeID, existing.Port)
	}
	if owner, occupied := allocator.used[port]; occupied {
		return fmt.Errorf("%w: port %d is already owned by expose %s", ErrLoopbackPortConflict, port, owner)
	}
	allocator.assignments[exposeID] = PortAssignment{ExposeID: exposeID, Port: port}
	allocator.used[port] = exposeID
	return nil
}

func (allocator *LoopbackAllocator) Release(exposeID string) (bool, error) {
	if err := allocator.valid(); err != nil {
		return false, err
	}
	if err := validateUUID("tunnel expose ID", exposeID); err != nil {
		return false, err
	}
	assignment, exists := allocator.assignments[exposeID]
	if !exists {
		return false, nil
	}
	delete(allocator.assignments, exposeID)
	delete(allocator.used, assignment.Port)
	return true, nil
}

func (allocator *LoopbackAllocator) Lookup(exposeID string) (int, bool) {
	if allocator == nil {
		return 0, false
	}
	assignment, exists := allocator.assignments[exposeID]
	return assignment.Port, exists
}

func (allocator *LoopbackAllocator) Assignments() []PortAssignment {
	if allocator == nil {
		return nil
	}
	result := make([]PortAssignment, 0, len(allocator.assignments))
	for _, assignment := range allocator.assignments {
		result = append(result, assignment)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ExposeID < result[right].ExposeID })
	return result
}

func (allocator *LoopbackAllocator) valid() error {
	if allocator == nil {
		return fmt.Errorf("tunnel loopback allocator is nil")
	}
	return nil
}

func validatePortRange(first, last int) error {
	if first < 1024 || last > 65535 || first > last {
		return fmt.Errorf("tunnel loopback port range must be ordered within 1024..65535")
	}
	return nil
}
