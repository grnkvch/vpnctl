package tunnel

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestMappingNameUsesImmutableFullIdentity(t *testing.T) {
	t.Parallel()

	name, err := MappingName(testNodeA, testExposeA)
	if err != nil {
		t.Fatalf("MappingName() error = %v", err)
	}
	want := "vpnctl-n-20000000000040008000000000000001-e-10000000000040008000000000000001"
	if name != want {
		t.Fatalf("MappingName() = %q, want %q", name, want)
	}
	if len(name) != 76 {
		t.Fatalf("mapping name length = %d, want 76", len(name))
	}

	expose := testExpose(testExposeA, testNodeA, "editable-label", 20000, model.ExposeReady)
	first, err := MappingFromExpose(expose)
	if err != nil {
		t.Fatal(err)
	}
	expose.Name = "renamed-label"
	second, err := MappingFromExpose(expose)
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != second.Name {
		t.Fatalf("editable expose label changed mapping identity: %q -> %q", first.Name, second.Name)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("Mapping.Validate() error = %v", err)
	}
}

func TestNodeSessionMultiplexesAllMappingsInOneRender(t *testing.T) {
	t.Parallel()

	node := testNode(testNodeA)
	exposes := []model.Expose{
		testExpose(testExposeB, testNodeA, "second", 20001, model.ExposeReady),
		testExpose(testExposeA, testNodeA, "first", 20000, model.ExposePending),
		testExpose(testExposeC, testNodeA, "disabled", 20002, model.ExposeDisabled),
	}
	session, err := NewNodeSession(node, exposes, 7)
	if err != nil {
		t.Fatalf("NewNodeSession() error = %v", err)
	}
	if len(session.Mappings) != 2 {
		t.Fatalf("active mappings = %d, want 2", len(session.Mappings))
	}
	if session.Mappings[0].ExposeID != testExposeA || session.Mappings[1].ExposeID != testExposeB {
		t.Fatalf("mappings are not deterministic: %#v", session.Mappings)
	}

	provider := &recordingProvider{}
	request := RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: "30000000-0000-4000-8000-000000000001", Generation: 7,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{session},
	}}
	candidate, err := provider.Render(context.Background(), request)
	if err != nil {
		t.Fatalf("Provider.Render() error = %v", err)
	}
	if provider.renderCalls != 1 || provider.lastNodeSessions != 1 || provider.lastMappingCount != 2 {
		t.Fatalf("render topology = calls:%d sessions:%d mappings:%d", provider.renderCalls, provider.lastNodeSessions, provider.lastMappingCount)
	}
	if err := provider.Validate(context.Background(), candidate); err != nil {
		t.Fatalf("Provider.Validate() error = %v", err)
	}
}

func TestPlanRejectsCrossNodeMappingAndGlobalPortCollision(t *testing.T) {
	t.Parallel()

	first, err := NewNodeSession(testNode(testNodeA), []model.Expose{
		testExpose(testExposeA, testNodeA, "first", 20000, model.ExposeReady),
	}, 3)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewNodeSession(testNode(testNodeB), []model.Expose{
		testExpose(testExposeB, testNodeB, "second", 20000, model.ExposeReady),
	}, 3)
	if err != nil {
		t.Fatal(err)
	}
	plan := Plan{
		HostRole: model.RoleGateway, HostID: "30000000-0000-4000-8000-000000000001", Generation: 3,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{first, second},
	}
	if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), "shared by exposes") {
		t.Fatalf("duplicate global loopback port error = %v", err)
	}

	crossNode := first
	crossNode.Mappings = append([]Mapping(nil), first.Mappings...)
	crossNode.Mappings[0].NodeID = testNodeB
	crossNode.Mappings[0].Name, _ = MappingName(testNodeB, crossNode.Mappings[0].ExposeID)
	if err := crossNode.Validate(); err == nil || !strings.Contains(err.Error(), "belongs to node") {
		t.Fatalf("cross-node mapping error = %v", err)
	}
}

func TestMappingRejectsNonLoopbackAndNonTCPEndpoints(t *testing.T) {
	t.Parallel()

	mapping, err := MappingFromExpose(testExpose(testExposeA, testNodeA, "first", 20000, model.ExposeReady))
	if err != nil {
		t.Fatal(err)
	}
	mapping.Protocol = model.ProtocolUDP
	if err := mapping.Validate(); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("UDP mapping error = %v", err)
	}
	mapping, _ = MappingFromExpose(testExpose(testExposeA, testNodeA, "first", 20000, model.ExposeReady))
	mapping.GatewayEndpoint = netip.MustParseAddrPort("127.0.0.2:20000")
	if err := mapping.Validate(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("non-loopback mapping error = %v", err)
	}
	if _, err := MappingFromExpose(testExpose(testExposeA, testNodeA, "first", 18111, model.ExposeReady)); err == nil || !strings.Contains(err.Error(), "managed range") {
		t.Fatalf("out-of-range mapping error = %v", err)
	}
}

func TestCandidateDescriptorValidation(t *testing.T) {
	t.Parallel()

	descriptor := CandidateDescriptor{
		Provider: "test-provider", HostRole: model.RoleGateway,
		HostID: "30000000-0000-4000-8000-000000000001", Generation: 1,
		ConfigHash: strings.Repeat("a", 64),
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("CandidateDescriptor.Validate() error = %v", err)
	}
	descriptor.ConfigHash = "secret-value"
	if err := descriptor.Validate(); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("invalid candidate hash error = %v", err)
	}
}

func testNode(id string) model.Node {
	return model.Node{
		SchemaVersion: model.ResourceSchemaVersion,
		ID:            id, Name: "private-node", Lifecycle: model.LifecycleActive,
		OverlayIPv4: "10.67.0.2", CredentialGeneration: 1,
		AssignedPresets: []string{}, ActiveTransport: model.TransportRestricted,
		IdempotencyRecords: []model.IdempotencyRecord{},
		CreatedAt:          time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC),
	}
}

type recordingProvider struct {
	renderCalls      int
	lastNodeSessions int
	lastMappingCount int
}

var _ Provider = (*recordingProvider)(nil)

func (provider *recordingProvider) Name() string { return "test-provider" }

func (provider *recordingProvider) Render(_ context.Context, request RenderRequest) (Candidate, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	provider.renderCalls++
	provider.lastNodeSessions = len(request.Plan.Nodes)
	for _, node := range request.Plan.Nodes {
		provider.lastMappingCount += len(node.Mappings)
	}
	return recordingCandidate{descriptor: CandidateDescriptor{
		Provider: provider.Name(), HostRole: request.Plan.HostRole, HostID: request.Plan.HostID,
		Generation: request.Plan.Generation, NodeID: request.Plan.Nodes[0].NodeID,
		CredentialGeneration: request.Plan.Nodes[0].CredentialGeneration,
		ActiveTransport:      request.Plan.Nodes[0].ActiveTransport,
		ConfigHash:           strings.Repeat("a", 64),
	}}, nil
}

func (provider *recordingProvider) Validate(_ context.Context, candidate Candidate) error {
	return candidate.Descriptor().Validate()
}

type recordingCandidate struct{ descriptor CandidateDescriptor }

func (candidate recordingCandidate) Descriptor() CandidateDescriptor { return candidate.descriptor }
