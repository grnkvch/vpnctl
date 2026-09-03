package tunnel

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	testExposeA = "10000000-0000-4000-8000-000000000001"
	testExposeB = "10000000-0000-4000-8000-000000000002"
	testExposeC = "10000000-0000-4000-8000-000000000003"
	testNodeA   = "20000000-0000-4000-8000-000000000001"
	testNodeB   = "20000000-0000-4000-8000-000000000002"
)

func TestLoopbackAllocatorStableReleaseAndExhaustion(t *testing.T) {
	t.Parallel()

	allocator, err := NewLoopbackAllocator(20000, 20001, nil)
	if err != nil {
		t.Fatalf("NewLoopbackAllocator() error = %v", err)
	}
	first, err := allocator.Allocate(testExposeA)
	if err != nil || first != 20000 {
		t.Fatalf("Allocate(first) = %d, %v", first, err)
	}
	repeated, err := allocator.Allocate(testExposeA)
	if err != nil || repeated != first {
		t.Fatalf("Allocate(stable) = %d, %v", repeated, err)
	}
	second, err := allocator.Allocate(testExposeB)
	if err != nil || second != 20001 {
		t.Fatalf("Allocate(second) = %d, %v", second, err)
	}
	if _, err := allocator.Allocate(testExposeC); !errors.Is(err, ErrLoopbackPoolExhausted) {
		t.Fatalf("Allocate(exhausted) error = %v", err)
	}
	if released, err := allocator.Release(testExposeA); err != nil || !released {
		t.Fatalf("Release(first) = %t, %v", released, err)
	}
	if released, err := allocator.Release(testExposeA); err != nil || released {
		t.Fatalf("Release(idempotent) = %t, %v", released, err)
	}
	reused, err := allocator.Allocate(testExposeC)
	if err != nil || reused != first {
		t.Fatalf("Allocate(reuse) = %d, %v", reused, err)
	}
}

func TestLoopbackAllocatorReserveConflicts(t *testing.T) {
	t.Parallel()

	allocator, _, err := RestoreLoopbackAllocator(20000, 20002, nil, []int{20002})
	if err != nil {
		t.Fatal(err)
	}
	if err := allocator.Reserve(testExposeA, 20000); err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
	if err := allocator.Reserve(testExposeA, 20000); err != nil {
		t.Fatalf("Reserve(idempotent) error = %v", err)
	}
	for name, testCase := range map[string]struct {
		exposeID string
		port     int
	}{
		"identity reassignment": {testExposeA, 20001},
		"duplicate port":        {testExposeB, 20000},
		"unavailable":           {testExposeB, 20002},
		"outside range":         {testExposeB, 19999},
	} {
		t.Run(name, func(t *testing.T) {
			if err := allocator.Reserve(testCase.exposeID, testCase.port); !errors.Is(err, ErrLoopbackPortConflict) {
				t.Fatalf("Reserve() error = %v", err)
			}
		})
	}
}

func TestLoopbackRestorePreservesAndDeterministicallyRemaps(t *testing.T) {
	t.Parallel()

	restored := []PortAssignment{
		{ExposeID: testExposeB, Port: 20001},
		{ExposeID: testExposeA, Port: 20000},
	}
	wantInput := append([]PortAssignment(nil), restored...)
	allocator, remaps, err := RestoreLoopbackAllocator(20000, 20002, restored, []int{20000})
	if err != nil {
		t.Fatalf("RestoreLoopbackAllocator() error = %v", err)
	}
	if !reflect.DeepEqual(restored, wantInput) {
		t.Fatalf("restore mutated caller input: %#v", restored)
	}
	if got, found := allocator.Lookup(testExposeB); !found || got != 20001 {
		t.Fatalf("preserved assignment = %d, %t", got, found)
	}
	if got, found := allocator.Lookup(testExposeA); !found || got != 20002 {
		t.Fatalf("remapped assignment = %d, %t", got, found)
	}
	wantRemaps := []PortRemap{{ExposeID: testExposeA, PreviousPort: 20000, Port: 20002}}
	if !reflect.DeepEqual(remaps, wantRemaps) {
		t.Fatalf("remaps = %#v, want %#v", remaps, wantRemaps)
	}
	wantAssignments := []PortAssignment{{ExposeID: testExposeA, Port: 20002}, {ExposeID: testExposeB, Port: 20001}}
	if got := allocator.Assignments(); !reflect.DeepEqual(got, wantAssignments) {
		t.Fatalf("assignments = %#v, want %#v", got, wantAssignments)
	}
}

func TestLoopbackRestoreFailsAtomicallyOnExhaustion(t *testing.T) {
	t.Parallel()

	allocator, remaps, err := RestoreLoopbackAllocator(20000, 20001, []PortAssignment{
		{ExposeID: testExposeA, Port: 20000},
		{ExposeID: testExposeB, Port: 20001},
	}, []int{20000, 20001})
	if !errors.Is(err, ErrLoopbackPoolExhausted) {
		t.Fatalf("RestoreLoopbackAllocator() error = %v", err)
	}
	if allocator != nil || remaps != nil {
		t.Fatalf("exhausted restore leaked a partial plan: %#v, %#v", allocator, remaps)
	}
}

func TestLoopbackRestoreOrdersMultipleRemapsByExposeIdentity(t *testing.T) {
	t.Parallel()

	allocator, remaps, err := RestoreLoopbackAllocator(20000, 20003, []PortAssignment{
		{ExposeID: testExposeB, Port: 20001},
		{ExposeID: testExposeA, Port: 20000},
	}, []int{20000, 20001})
	if err != nil {
		t.Fatalf("RestoreLoopbackAllocator() error = %v", err)
	}
	want := []PortRemap{
		{ExposeID: testExposeA, PreviousPort: 20000, Port: 20002},
		{ExposeID: testExposeB, PreviousPort: 20001, Port: 20003},
	}
	if !reflect.DeepEqual(remaps, want) {
		t.Fatalf("remaps = %#v, want %#v", remaps, want)
	}
	if got := allocator.Assignments(); !reflect.DeepEqual(got, []PortAssignment{
		{ExposeID: testExposeA, Port: 20002},
		{ExposeID: testExposeB, Port: 20003},
	}) {
		t.Fatalf("assignments = %#v", got)
	}
}

func TestLoopbackRestoreRemapsLegacyOutOfRangeAssignment(t *testing.T) {
	t.Parallel()

	allocator, remaps, err := RestoreLoopbackAllocator(20000, 20000, []PortAssignment{
		{ExposeID: testExposeA, Port: 18111},
	}, nil)
	if err != nil {
		t.Fatalf("RestoreLoopbackAllocator() error = %v", err)
	}
	want := []PortRemap{{ExposeID: testExposeA, PreviousPort: 18111, Port: 20000}}
	if !reflect.DeepEqual(remaps, want) {
		t.Fatalf("remaps = %#v, want %#v", remaps, want)
	}
	if got, found := allocator.Lookup(testExposeA); !found || got != 20000 {
		t.Fatalf("legacy assignment = %d, %t", got, found)
	}
}

func TestLoopbackRestoreRejectsPersistedCollisions(t *testing.T) {
	t.Parallel()

	for name, assignments := range map[string][]PortAssignment{
		"duplicate expose": {{ExposeID: testExposeA, Port: 20000}, {ExposeID: testExposeA, Port: 20001}},
		"duplicate port":   {{ExposeID: testExposeA, Port: 20000}, {ExposeID: testExposeB, Port: 20000}},
	} {
		t.Run(name, func(t *testing.T) {
			allocator, remaps, err := RestoreLoopbackAllocator(20000, 20002, assignments, nil)
			if !errors.Is(err, ErrLoopbackPortConflict) {
				t.Fatalf("RestoreLoopbackAllocator() error = %v", err)
			}
			if allocator != nil || remaps != nil {
				t.Fatalf("conflicted restore leaked a partial plan: %#v, %#v", allocator, remaps)
			}
		})
	}
}

func TestDefaultLoopbackAllocatorRestoresPersistedExposePorts(t *testing.T) {
	t.Parallel()

	exposes := []model.Expose{
		testExpose(testExposeA, testNodeA, "first", 20000, model.ExposeReady),
		testExpose(testExposeB, testNodeA, "second", 20001, model.ExposeDisabled),
	}
	allocator, remaps, err := DefaultLoopbackAllocatorFromExposes(exposes, []int{20000})
	if err != nil {
		t.Fatalf("DefaultLoopbackAllocatorFromExposes() error = %v", err)
	}
	if len(remaps) != 1 || remaps[0].ExposeID != testExposeA || remaps[0].Port != 20002 {
		t.Fatalf("remaps = %#v", remaps)
	}
	if got, found := allocator.Lookup(testExposeB); !found || got != 20001 {
		t.Fatalf("disabled expose assignment = %d, %t", got, found)
	}
}

func TestDefaultLoopbackRangeMatchesDevelopmentManifest(t *testing.T) {
	t.Parallel()

	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "v2", "COMPONENT_LIMITS.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Limits struct {
			ReverseTunnel struct {
				First    int `json:"loopback_port_first"`
				Last     int `json:"loopback_port_last"`
				Capacity int `json:"loopback_port_capacity"`
			} `json:"reverse_tunnel"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		t.Fatal(err)
	}
	limits := manifest.Limits.ReverseTunnel
	if limits.First != DefaultLoopbackPortFirst || limits.Last != DefaultLoopbackPortLast || limits.Capacity != DefaultLoopbackPortLast-DefaultLoopbackPortFirst+1 {
		t.Fatalf("reverse tunnel loopback limits drifted: %+v", limits)
	}
}

func testExpose(id, nodeID, name string, port int, state model.ExposeState) model.Expose {
	return model.Expose{
		SchemaVersion:          model.ResourceSchemaVersion,
		ID:                     id,
		NodeID:                 nodeID,
		Name:                   name,
		Upstream:               "127.0.0.1:3000",
		RouteMode:              model.RouteExact,
		Path:                   "/" + name,
		BodyLimitBytes:         1 << 20,
		UpstreamTimeoutSeconds: 30,
		ConcurrentRequests:     16,
		TunnelPort:             port,
		State:                  state,
		Generation:             1,
		CreatedAt:              time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC),
	}
}
