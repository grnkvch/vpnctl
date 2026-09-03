package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const MappingNamePrefix = "vpnctl-n-"

var (
	canonicalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	providerNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	configHashPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	domainPattern        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// Provider renders a complete desired tunnel topology. The interface is
// deliberately unaware of frp, systemd, files, and credentials: providers own
// their candidate contents, while orchestration owns atomic activation.
type Provider interface {
	Name() string
	Render(context.Context, RenderRequest) (Candidate, error)
	Validate(context.Context, Candidate) error
}

// Candidate keeps provider-specific configuration opaque. Its descriptor is
// safe to use for generation checks and drift detection.
type Candidate interface {
	Descriptor() CandidateDescriptor
}

type CandidateDescriptor struct {
	Provider   string
	HostRole   model.Role
	HostID     string
	Generation uint64
	ConfigHash string
}

func (descriptor CandidateDescriptor) Validate() error {
	if !providerNamePattern.MatchString(descriptor.Provider) {
		return fmt.Errorf("tunnel provider must be a canonical lower-case name")
	}
	if descriptor.HostRole != model.RoleGateway && descriptor.HostRole != model.RoleNode {
		return fmt.Errorf("unsupported tunnel host role %q", descriptor.HostRole)
	}
	if err := validateUUID("tunnel host ID", descriptor.HostID); err != nil {
		return err
	}
	if descriptor.Generation == 0 {
		return fmt.Errorf("tunnel candidate generation must be positive")
	}
	if !configHashPattern.MatchString(descriptor.ConfigHash) {
		return fmt.Errorf("tunnel config hash must be a SHA-256 hex digest")
	}
	return nil
}

type RenderRequest struct {
	Plan Plan
}

func (request RenderRequest) Validate() error {
	if err := request.Plan.Validate(); err != nil {
		return fmt.Errorf("validate tunnel render request: %w", err)
	}
	return nil
}

// Plan models one shared gateway service or one node process. Mappings live
// inside NodeSession so adding an expose cannot imply a second daemon or
// persistent connection.
type Plan struct {
	HostRole   model.Role
	HostID     string
	Generation uint64
	Nodes      []NodeSession
}

func (plan Plan) Validate() error {
	if plan.HostRole != model.RoleGateway && plan.HostRole != model.RoleNode {
		return fmt.Errorf("unsupported tunnel host role %q", plan.HostRole)
	}
	if err := validateUUID("tunnel host ID", plan.HostID); err != nil {
		return err
	}
	if plan.Generation == 0 {
		return fmt.Errorf("tunnel plan generation must be positive")
	}
	if plan.Nodes == nil {
		return fmt.Errorf("tunnel node sessions must be present")
	}
	if plan.HostRole == model.RoleNode && len(plan.Nodes) != 1 {
		return fmt.Errorf("node tunnel plan must contain exactly one node session")
	}

	nodeIDs := make(map[string]struct{}, len(plan.Nodes))
	ports := make(map[uint16]string)
	for index, node := range plan.Nodes {
		if err := node.Validate(); err != nil {
			return fmt.Errorf("node session %d: %w", index, err)
		}
		if _, duplicate := nodeIDs[node.NodeID]; duplicate {
			return fmt.Errorf("node session %d duplicates node %s", index, node.NodeID)
		}
		nodeIDs[node.NodeID] = struct{}{}
		for _, mapping := range node.Mappings {
			port := mapping.GatewayEndpoint.Port()
			if prior, duplicate := ports[port]; duplicate {
				return fmt.Errorf("gateway loopback port %d is shared by exposes %s and %s", port, prior, mapping.ExposeID)
			}
			ports[port] = mapping.ExposeID
		}
	}
	return nil
}

type NodeSession struct {
	NodeID          string
	Generation      uint64
	ActiveTransport model.TransportKind
	Mappings        []Mapping
}

func (session NodeSession) Validate() error {
	if err := validateUUID("tunnel node ID", session.NodeID); err != nil {
		return err
	}
	if session.Generation == 0 {
		return fmt.Errorf("tunnel node generation must be positive")
	}
	if session.ActiveTransport != model.TransportStandard && session.ActiveTransport != model.TransportRestricted {
		return fmt.Errorf("unsupported active tunnel transport %q", session.ActiveTransport)
	}
	if session.Mappings == nil {
		return fmt.Errorf("tunnel mappings must be present")
	}

	exposeIDs := make(map[string]struct{}, len(session.Mappings))
	names := make(map[string]struct{}, len(session.Mappings))
	ports := make(map[uint16]struct{}, len(session.Mappings))
	for index, mapping := range session.Mappings {
		if err := mapping.Validate(); err != nil {
			return fmt.Errorf("mapping %d: %w", index, err)
		}
		if mapping.NodeID != session.NodeID {
			return fmt.Errorf("mapping %d belongs to node %s, not %s", index, mapping.NodeID, session.NodeID)
		}
		if _, duplicate := exposeIDs[mapping.ExposeID]; duplicate {
			return fmt.Errorf("mapping %d duplicates expose %s", index, mapping.ExposeID)
		}
		if _, duplicate := names[mapping.Name]; duplicate {
			return fmt.Errorf("mapping %d duplicates name %s", index, mapping.Name)
		}
		if _, duplicate := ports[mapping.GatewayEndpoint.Port()]; duplicate {
			return fmt.Errorf("mapping %d duplicates gateway loopback port %d", index, mapping.GatewayEndpoint.Port())
		}
		exposeIDs[mapping.ExposeID] = struct{}{}
		names[mapping.Name] = struct{}{}
		ports[mapping.GatewayEndpoint.Port()] = struct{}{}
	}
	return nil
}

type Mapping struct {
	ExposeID        string
	NodeID          string
	Name            string
	Protocol        model.NetworkProtocol
	GatewayEndpoint netip.AddrPort
	NodeUpstream    string
	Generation      uint64
}

func MappingFromExpose(expose model.Expose) (Mapping, error) {
	if err := expose.Validate(); err != nil {
		return Mapping{}, fmt.Errorf("validate expose: %w", err)
	}
	name, err := MappingName(expose.NodeID, expose.ID)
	if err != nil {
		return Mapping{}, err
	}
	mapping := Mapping{
		ExposeID:        expose.ID,
		NodeID:          expose.NodeID,
		Name:            name,
		Protocol:        model.ProtocolTCP,
		GatewayEndpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(expose.TunnelPort)),
		NodeUpstream:    expose.Upstream,
		Generation:      expose.Generation,
	}
	if err := mapping.Validate(); err != nil {
		return Mapping{}, err
	}
	return mapping, nil
}

func (mapping Mapping) Validate() error {
	if err := validateUUID("tunnel expose ID", mapping.ExposeID); err != nil {
		return err
	}
	if err := validateUUID("tunnel mapping node ID", mapping.NodeID); err != nil {
		return err
	}
	wantName, _ := MappingName(mapping.NodeID, mapping.ExposeID)
	if mapping.Name != wantName {
		return fmt.Errorf("tunnel mapping name %q does not match deterministic name %q", mapping.Name, wantName)
	}
	if mapping.Protocol != model.ProtocolTCP {
		return fmt.Errorf("unsupported tunnel mapping protocol %q", mapping.Protocol)
	}
	if !mapping.GatewayEndpoint.IsValid() || mapping.GatewayEndpoint.Addr() != netip.MustParseAddr("127.0.0.1") {
		return fmt.Errorf("tunnel gateway endpoint must use canonical IPv4 loopback 127.0.0.1")
	}
	if port := int(mapping.GatewayEndpoint.Port()); port < DefaultLoopbackPortFirst || port > DefaultLoopbackPortLast {
		return fmt.Errorf("tunnel gateway endpoint port must be inside managed range %d-%d", DefaultLoopbackPortFirst, DefaultLoopbackPortLast)
	}
	if err := validateUpstream(mapping.NodeUpstream); err != nil {
		return err
	}
	if mapping.Generation == 0 {
		return fmt.Errorf("tunnel mapping generation must be positive")
	}
	return nil
}

func MappingName(nodeID, exposeID string) (string, error) {
	if err := validateUUID("tunnel node ID", nodeID); err != nil {
		return "", err
	}
	if err := validateUUID("tunnel expose ID", exposeID); err != nil {
		return "", err
	}
	return MappingNamePrefix + strings.ReplaceAll(nodeID, "-", "") + "-e-" + strings.ReplaceAll(exposeID, "-", ""), nil
}

func NewNodeSession(node model.Node, exposes []model.Expose, generation uint64) (NodeSession, error) {
	if err := node.Validate(); err != nil {
		return NodeSession{}, fmt.Errorf("validate node: %w", err)
	}
	if generation == 0 {
		return NodeSession{}, fmt.Errorf("tunnel node generation must be positive")
	}
	mappings := make([]Mapping, 0, len(exposes))
	for index, expose := range exposes {
		if expose.NodeID != node.ID || expose.State == model.ExposeDisabled {
			continue
		}
		mapping, err := MappingFromExpose(expose)
		if err != nil {
			return NodeSession{}, fmt.Errorf("expose %d: %w", index, err)
		}
		mappings = append(mappings, mapping)
	}
	sort.Slice(mappings, func(left, right int) bool { return mappings[left].Name < mappings[right].Name })
	session := NodeSession{NodeID: node.ID, Generation: generation, ActiveTransport: node.ActiveTransport, Mappings: mappings}
	if err := session.Validate(); err != nil {
		return NodeSession{}, err
	}
	return session, nil
}

func validateUUID(label, value string) error {
	if !canonicalUUIDPattern.MatchString(value) {
		return fmt.Errorf("%s must be a canonical lower-case UUID", label)
	}
	return nil
}

func validateUpstream(value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || portText == "" {
		return fmt.Errorf("tunnel node upstream must be normalized host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("tunnel node upstream contains an invalid port")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if address.String() != host {
			return fmt.Errorf("tunnel node upstream contains a non-canonical IP address")
		}
		return nil
	}
	if host == "localhost" {
		return nil
	}
	if !domainPattern.MatchString(host) || strings.Contains(host, "..") {
		return fmt.Errorf("tunnel node upstream contains an invalid DNS name")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("tunnel node upstream contains an invalid DNS label")
		}
	}
	return nil
}
