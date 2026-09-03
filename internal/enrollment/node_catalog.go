package enrollment

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

var ErrNodeNotFound = errors.New("node does not exist")

type NodeStateReader interface {
	Load() (model.State, error)
}

// NodeTransportView deliberately omits credential references, public keys,
// config hashes, and provider-specific authentication material.
type NodeTransportView struct {
	Kind          model.TransportKind   `json:"kind"`
	State         model.TransportState  `json:"state"`
	Protocol      model.NetworkProtocol `json:"protocol"`
	Port          int                   `json:"port"`
	HandshakeHost string                `json:"handshake_host,omitempty"`
}

type NodeCertificateView struct {
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"not_after"`
	Generation  uint64    `json:"generation"`
}

// NodeView is the only node projection intended for list/show output. It has
// no opaque refs: even non-secret references reveal credential layout and are
// unnecessary to operate the resource.
type NodeView struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	Lifecycle            model.Lifecycle     `json:"lifecycle"`
	OverlayIPv4          string              `json:"overlay_ipv4"`
	AssignedPresets      []string            `json:"assigned_presets"`
	CredentialGeneration uint64              `json:"credential_generation"`
	PolicyGeneration     uint64              `json:"policy_generation"`
	ActiveTransport      model.TransportKind `json:"active_transport"`
	Transports           []NodeTransportView `json:"transports"`
	ControlCertificate   NodeCertificateView `json:"control_certificate"`
	CreatedAt            time.Time           `json:"created_at"`
	RevokedAt            *time.Time          `json:"revoked_at,omitempty"`
}

type NodeList struct {
	StateGeneration uint64     `json:"state_generation"`
	Items           []NodeView `json:"items"`
}

type NodeShow struct {
	StateGeneration uint64   `json:"state_generation"`
	Resource        NodeView `json:"resource"`
}

type NodeCatalog struct {
	state NodeStateReader
}

func NewNodeCatalog(state NodeStateReader) (*NodeCatalog, error) {
	if state == nil {
		return nil, fmt.Errorf("node catalog state reader is required")
	}
	return &NodeCatalog{state: state}, nil
}

func (catalog *NodeCatalog) List() (NodeList, error) {
	state, err := catalog.loadGatewayState()
	if err != nil {
		return NodeList{}, err
	}
	items := make([]NodeView, 0, len(state.Nodes))
	for _, node := range state.Nodes {
		if node.Lifecycle == model.LifecycleDeleted {
			continue
		}
		view, err := buildNodeView(state, node)
		if err != nil {
			return NodeList{}, err
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
	return NodeList{StateGeneration: state.Generation, Items: items}, nil
}

func (catalog *NodeCatalog) Show(reference string) (NodeShow, error) {
	state, err := catalog.loadGatewayState()
	if err != nil {
		return NodeShow{}, err
	}
	node, err := resolveVisibleNode(state.Nodes, reference)
	if err != nil {
		return NodeShow{}, err
	}
	view, err := buildNodeView(state, node)
	if err != nil {
		return NodeShow{}, err
	}
	return NodeShow{StateGeneration: state.Generation, Resource: view}, nil
}

func (catalog *NodeCatalog) loadGatewayState() (model.State, error) {
	if catalog == nil || catalog.state == nil {
		return model.State{}, fmt.Errorf("node catalog is incomplete")
	}
	state, err := catalog.state.Load()
	if err != nil {
		return model.State{}, fmt.Errorf("load authoritative node state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return model.State{}, fmt.Errorf("validate authoritative node state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return model.State{}, fmt.Errorf("node catalog requires gateway state")
	}
	return state, nil
}

func resolveVisibleNode(nodes []model.Node, reference string) (model.Node, error) {
	if reference == "" || strings.TrimSpace(reference) != reference || strings.ContainsAny(reference, "\x00\r\n") {
		return model.Node{}, fmt.Errorf("%w: an explicit name or ID is required", ErrNodeNotFound)
	}
	var matches []model.Node
	for _, node := range nodes {
		if node.Lifecycle == model.LifecycleDeleted {
			continue
		}
		if node.ID == reference || strings.EqualFold(node.Name, reference) {
			matches = append(matches, node)
		}
	}
	if len(matches) != 1 {
		return model.Node{}, fmt.Errorf("%w: %s", ErrNodeNotFound, reference)
	}
	return matches[0], nil
}

func buildNodeView(state model.State, node model.Node) (NodeView, error) {
	view := NodeView{
		ID: node.ID, Name: node.Name, Lifecycle: node.Lifecycle, OverlayIPv4: node.OverlayIPv4,
		AssignedPresets: append([]string{}, node.AssignedPresets...), CredentialGeneration: node.CredentialGeneration,
		ActiveTransport: node.ActiveTransport, Transports: []NodeTransportView{}, CreatedAt: node.CreatedAt,
	}
	if node.RevokedAt != nil {
		copy := *node.RevokedAt
		view.RevokedAt = &copy
	}
	for _, policy := range state.Policies {
		if policy.TargetKind == model.TargetNode && policy.TargetID == node.ID {
			view.PolicyGeneration = policy.Generation
			break
		}
	}
	for _, record := range state.Transports {
		if record.OwnerKind != model.TargetNode || record.OwnerID != node.ID {
			continue
		}
		view.Transports = append(view.Transports, NodeTransportView{
			Kind: record.Kind, State: record.State, Protocol: record.Protocol,
			Port: record.Port, HandshakeHost: record.HandshakeHost,
		})
	}
	sort.Slice(view.Transports, func(left, right int) bool { return view.Transports[left].Kind < view.Transports[right].Kind })
	for _, certificate := range state.Certificates {
		if certificate.Kind == model.CertificateControlNode && certificate.OwnerID == node.ID &&
			certificate.EffectiveCredentialGeneration() == node.CredentialGeneration {
			view.ControlCertificate = NodeCertificateView{
				Fingerprint: certificate.Fingerprint, NotAfter: certificate.NotAfter, Generation: certificate.EffectiveCredentialGeneration(),
			}
			break
		}
	}
	if view.ControlCertificate.Fingerprint == "" {
		return NodeView{}, fmt.Errorf("node %s has no current control certificate metadata", node.ID)
	}
	return view, nil
}
