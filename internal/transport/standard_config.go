package transport

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	StandardInterfaceName        = "vpnctl-wg"
	StandardUDPPort              = 51820
	StandardPersistentKeepalive  = 25
	GatewayStandardCredentialRef = model.SecretRef("wireguard-key:gateway-standard-g1")
	GatewayStandardCredentialGen = uint64(1)
	maximumStandardConfigBytes   = 1 << 20
)

type StandardCredentialStore interface {
	Get(model.SecretRef) ([]byte, error)
	PutIfAbsent(model.SecretRef, []byte) error
}

type GatewayStandardCredential struct {
	Reference  model.SecretRef
	Generation uint64
	PublicKey  string
}

// EnsureGatewayStandardCredential publishes the gateway's provider-owned
// WireGuard identity exactly once. A concurrent winner is adopted only after
// its stored private key has been validated and its public key re-derived.
func EnsureGatewayStandardCredential(ctx context.Context, secrets StandardCredentialStore, runner wireguard.Runner) (GatewayStandardCredential, error) {
	credential, _, err := ensureGatewayStandardCredential(ctx, secrets, runner)
	return credential, err
}

func ensureGatewayStandardCredential(ctx context.Context, secrets StandardCredentialStore, runner wireguard.Runner) (GatewayStandardCredential, bool, error) {
	if ctx == nil {
		return GatewayStandardCredential{}, false, fmt.Errorf("context is required")
	}
	if secrets == nil {
		return GatewayStandardCredential{}, false, fmt.Errorf("standard credential store is required")
	}
	stored, err := secrets.Get(GatewayStandardCredentialRef)
	if err == nil {
		credential, credentialErr := gatewayStandardCredential(ctx, stored, runner)
		return credential, false, credentialErr
	}
	if !errors.Is(err, store.ErrSecretNotFound) && !errors.Is(err, fs.ErrNotExist) {
		return GatewayStandardCredential{}, false, fmt.Errorf("read gateway standard credential: %w", err)
	}
	pair, err := wireguard.GenerateKeyPair(ctx, runner)
	if err != nil {
		return GatewayStandardCredential{}, false, err
	}
	if err := secrets.PutIfAbsent(GatewayStandardCredentialRef, []byte(pair.PrivateKey)); err != nil {
		if !errors.Is(err, store.ErrSecretExists) {
			return GatewayStandardCredential{}, false, fmt.Errorf("publish gateway standard credential: %w", err)
		}
		stored, readErr := secrets.Get(GatewayStandardCredentialRef)
		if readErr != nil {
			return GatewayStandardCredential{}, false, fmt.Errorf("read concurrently published gateway standard credential: %w", readErr)
		}
		credential, credentialErr := gatewayStandardCredential(ctx, stored, runner)
		return credential, false, credentialErr
	}
	return GatewayStandardCredential{
		Reference: GatewayStandardCredentialRef, Generation: GatewayStandardCredentialGen, PublicKey: pair.PublicKey,
	}, true, nil
}

func gatewayStandardCredential(ctx context.Context, privateKey []byte, runner wireguard.Runner) (GatewayStandardCredential, error) {
	publicKey, err := wireguard.PublicKey(ctx, runner, strings.TrimSpace(string(privateKey)))
	if err != nil {
		return GatewayStandardCredential{}, fmt.Errorf("validate gateway standard credential: %w", err)
	}
	return GatewayStandardCredential{
		Reference: GatewayStandardCredentialRef, Generation: GatewayStandardCredentialGen, PublicKey: publicKey,
	}, nil
}

type StandardPeer struct {
	Identity  Identity
	PublicKey string
	AllowedIP string
}

type StandardConfigArtifact struct {
	gatewayPublicKey string
	localAddresses   []string
	peers            []StandardPeer
	content          []byte
}

func (artifact StandardConfigArtifact) ConfigHash() string {
	return standardConfigHash(artifact.content)
}

func (artifact StandardConfigArtifact) Bytes() []byte {
	return append([]byte(nil), artifact.content...)
}

func (artifact StandardConfigArtifact) GatewayPublicKey() string { return artifact.gatewayPublicKey }

func (artifact StandardConfigArtifact) LocalAddresses() []string {
	return append([]string(nil), artifact.localAddresses...)
}

func (artifact StandardConfigArtifact) Peers() []StandardPeer {
	return append([]StandardPeer(nil), artifact.peers...)
}

type StandardNodeCandidate struct {
	StandardConfigArtifact
	descriptor CandidateDescriptor
}

var _ Candidate = StandardNodeCandidate{}

func (candidate StandardNodeCandidate) Descriptor() CandidateDescriptor { return candidate.descriptor }

type GatewayStandardRenderRequest struct {
	State         model.State
	CredentialRef model.SecretRef
	Credentials   interface {
		Get(model.SecretRef) ([]byte, error)
	}
	KeyRunner wireguard.Runner
}

// RenderGatewayStandardConfig creates the one gateway WireGuard interface for
// all currently active client and node identities. It deliberately emits no
// firewall or NAT commands; inet/vpnctl is the sole owner of that policy.
func RenderGatewayStandardConfig(ctx context.Context, request GatewayStandardRenderRequest) (StandardConfigArtifact, error) {
	if ctx == nil {
		return StandardConfigArtifact{}, fmt.Errorf("context is required")
	}
	if request.Credentials == nil {
		return StandardConfigArtifact{}, fmt.Errorf("standard credential reader is required")
	}
	if request.CredentialRef != GatewayStandardCredentialRef {
		return StandardConfigArtifact{}, fmt.Errorf("gateway standard credential reference must be %s", GatewayStandardCredentialRef)
	}
	if err := request.State.Validate(); err != nil {
		return StandardConfigArtifact{}, fmt.Errorf("validate gateway standard state: %w", err)
	}
	if request.State.Host.Role != model.RoleGateway {
		return StandardConfigArtifact{}, fmt.Errorf("gateway standard config requires gateway state")
	}
	privateKeyBytes, err := request.Credentials.Get(request.CredentialRef)
	if err != nil {
		return StandardConfigArtifact{}, fmt.Errorf("read gateway standard credential: %w", err)
	}
	privateKey := strings.TrimSpace(string(privateKeyBytes))
	publicKey, err := wireguard.PublicKey(ctx, request.KeyRunner, privateKey)
	if err != nil {
		return StandardConfigArtifact{}, fmt.Errorf("validate gateway standard credential: %w", err)
	}
	clientGateway, err := standardGatewayAddress(request.State.Host.ClientCIDR)
	if err != nil {
		return StandardConfigArtifact{}, fmt.Errorf("derive client gateway address: %w", err)
	}
	nodeGateway, err := standardGatewayAddress(request.State.Host.NodeCIDR)
	if err != nil {
		return StandardConfigArtifact{}, fmt.Errorf("derive node gateway address: %w", err)
	}
	peers, err := gatewayStandardPeers(request.State)
	if err != nil {
		return StandardConfigArtifact{}, err
	}

	var config strings.Builder
	config.WriteString("[Interface]\n")
	fmt.Fprintf(&config, "Address = %s, %s\n", clientGateway, nodeGateway)
	fmt.Fprintf(&config, "ListenPort = %d\n", StandardUDPPort)
	fmt.Fprintf(&config, "PrivateKey = %s\n", privateKey)
	config.WriteString("Table = off\n")
	config.WriteString("SaveConfig = false\n")
	for _, peer := range peers {
		config.WriteString("\n[Peer]\n")
		fmt.Fprintf(&config, "PublicKey = %s\n", peer.PublicKey)
		fmt.Fprintf(&config, "AllowedIPs = %s\n", peer.AllowedIP)
	}
	content := []byte(config.String())
	if len(content) > maximumStandardConfigBytes {
		return StandardConfigArtifact{}, fmt.Errorf("gateway standard config exceeds %d bytes", maximumStandardConfigBytes)
	}
	return StandardConfigArtifact{
		gatewayPublicKey: publicKey,
		localAddresses:   []string{clientGateway, nodeGateway},
		peers:            peers,
		content:          content,
	}, nil
}

type NodeStandardRenderRequest struct {
	Transport         model.Transport
	Node              model.Node
	NodeCIDR          string
	GatewayPublicIPv4 string
	GatewayPublicKey  string
	PrivateKey        string
	KeyRunner         wireguard.Runner
}

// RenderNodeStandardConfig keeps automatic route creation disabled and adds
// only the stable node-overlay gateway route. The selected default route is a
// separate fail-closed routing concern and is never installed by wg-quick.
func RenderNodeStandardConfig(ctx context.Context, request NodeStandardRenderRequest) (StandardNodeCandidate, error) {
	if ctx == nil {
		return StandardNodeCandidate{}, fmt.Errorf("context is required")
	}
	if err := request.Node.Validate(); err != nil {
		return StandardNodeCandidate{}, fmt.Errorf("validate standard node: %w", err)
	}
	if request.Node.Lifecycle != model.LifecycleActive {
		return StandardNodeCandidate{}, fmt.Errorf("standard node must be active")
	}
	if err := request.Transport.Validate(); err != nil {
		return StandardNodeCandidate{}, fmt.Errorf("validate standard node transport: %w", err)
	}
	if request.Transport.OwnerKind != model.TargetNode || request.Transport.OwnerID != request.Node.ID || request.Transport.Kind != model.TransportStandard {
		return StandardNodeCandidate{}, fmt.Errorf("standard transport does not belong to node %s", request.Node.ID)
	}
	if request.Transport.State == model.TransportDisabled {
		return StandardNodeCandidate{}, fmt.Errorf("disabled standard transport cannot be rendered")
	}
	if request.Transport.CredentialGeneration != request.Node.CredentialGeneration {
		return StandardNodeCandidate{}, fmt.Errorf("standard transport credential generation does not match node")
	}
	privateKey := strings.TrimSpace(request.PrivateKey)
	publicKey, err := wireguard.PublicKey(ctx, request.KeyRunner, privateKey)
	if err != nil {
		return StandardNodeCandidate{}, fmt.Errorf("validate node standard credential: %w", err)
	}
	if publicKey != request.Transport.PublicKey {
		return StandardNodeCandidate{}, fmt.Errorf("node standard private key does not match authoritative public key")
	}
	if err := wireguard.ValidateKey(request.GatewayPublicKey); err != nil {
		return StandardNodeCandidate{}, fmt.Errorf("gateway standard public key is invalid: %w", err)
	}
	publicAddress, err := netip.ParseAddr(request.GatewayPublicIPv4)
	if err != nil || !publicAddress.Is4() || publicAddress.String() != request.GatewayPublicIPv4 || !publicAddress.IsGlobalUnicast() {
		return StandardNodeCandidate{}, fmt.Errorf("gateway standard endpoint must be a canonical global-unicast IPv4 address")
	}
	nodeAddress, err := standardIdentityAddress(request.Node.OverlayIPv4, request.NodeCIDR)
	if err != nil {
		return StandardNodeCandidate{}, fmt.Errorf("derive node standard address: %w", err)
	}
	gatewayAddress, err := standardGatewayAddress(request.NodeCIDR)
	if err != nil {
		return StandardNodeCandidate{}, fmt.Errorf("derive node gateway address: %w", err)
	}
	gatewayPrefix, _ := netip.ParsePrefix(gatewayAddress)
	gatewayHost := gatewayPrefix.Addr().String() + "/32"

	var config strings.Builder
	config.WriteString("[Interface]\n")
	fmt.Fprintf(&config, "Address = %s\n", nodeAddress)
	fmt.Fprintf(&config, "PrivateKey = %s\n", privateKey)
	config.WriteString("Table = off\n")
	config.WriteString("SaveConfig = false\n")
	fmt.Fprintf(&config, "PostUp = ip -4 route add %s dev %%i proto static\n", gatewayHost)
	config.WriteString("\n[Peer]\n")
	fmt.Fprintf(&config, "PublicKey = %s\n", request.GatewayPublicKey)
	fmt.Fprintf(&config, "Endpoint = %s:%d\n", request.GatewayPublicIPv4, StandardUDPPort)
	config.WriteString("AllowedIPs = 0.0.0.0/0\n")
	fmt.Fprintf(&config, "PersistentKeepalive = %d\n", StandardPersistentKeepalive)
	content := []byte(config.String())
	if len(content) > maximumStandardConfigBytes {
		return StandardNodeCandidate{}, fmt.Errorf("node standard config exceeds %d bytes", maximumStandardConfigBytes)
	}
	return StandardNodeCandidate{
		StandardConfigArtifact: StandardConfigArtifact{
			gatewayPublicKey: request.GatewayPublicKey,
			localAddresses:   []string{nodeAddress},
			peers: []StandardPeer{{
				Identity:  Identity{OwnerKind: model.TargetNode, OwnerID: request.Node.ID, CredentialGeneration: request.Node.CredentialGeneration},
				PublicKey: request.GatewayPublicKey, AllowedIP: "0.0.0.0/0",
			}},
			content: content,
		},
		descriptor: CandidateDescriptor{
			OwnerKind: model.TargetNode, OwnerID: request.Node.ID, Kind: model.TransportStandard,
			CredentialGeneration: request.Node.CredentialGeneration, ConfigHash: standardConfigHash(content),
		},
	}, nil
}

func gatewayStandardPeers(state model.State) ([]StandardPeer, error) {
	identities := make(map[string]struct {
		lifecycle  model.Lifecycle
		address    string
		generation uint64
	}, len(state.Clients)+len(state.Nodes))
	for _, client := range state.Clients {
		identities[standardIdentityKey(model.TargetClient, client.ID)] = struct {
			lifecycle  model.Lifecycle
			address    string
			generation uint64
		}{client.Lifecycle, client.OverlayIPv4, client.CredentialGeneration}
	}
	for _, node := range state.Nodes {
		identities[standardIdentityKey(model.TargetNode, node.ID)] = struct {
			lifecycle  model.Lifecycle
			address    string
			generation uint64
		}{node.Lifecycle, node.OverlayIPv4, node.CredentialGeneration}
	}
	peers := make([]StandardPeer, 0, len(identities))
	publicKeys := make(map[string]string, len(identities))
	for _, transport := range state.Transports {
		if transport.Kind != model.TransportStandard || transport.State == model.TransportDisabled {
			continue
		}
		identity, found := identities[standardIdentityKey(transport.OwnerKind, transport.OwnerID)]
		if !found || identity.lifecycle != model.LifecycleActive {
			continue
		}
		if identity.generation != transport.CredentialGeneration {
			return nil, fmt.Errorf("standard transport credential generation does not match %s %s", transport.OwnerKind, transport.OwnerID)
		}
		if err := wireguard.ValidateKey(transport.PublicKey); err != nil {
			return nil, fmt.Errorf("%s %s standard public key is invalid: %w", transport.OwnerKind, transport.OwnerID, err)
		}
		if owner, duplicate := publicKeys[transport.PublicKey]; duplicate {
			return nil, fmt.Errorf("standard public key is shared by %s and %s %s", owner, transport.OwnerKind, transport.OwnerID)
		}
		publicKeys[transport.PublicKey] = string(transport.OwnerKind) + " " + transport.OwnerID
		peers = append(peers, StandardPeer{
			Identity:  Identity{OwnerKind: transport.OwnerKind, OwnerID: transport.OwnerID, CredentialGeneration: transport.CredentialGeneration},
			PublicKey: transport.PublicKey, AllowedIP: identity.address + "/32",
		})
	}
	sort.Slice(peers, func(left, right int) bool {
		if peers[left].Identity.OwnerKind != peers[right].Identity.OwnerKind {
			return peers[left].Identity.OwnerKind < peers[right].Identity.OwnerKind
		}
		return peers[left].Identity.OwnerID < peers[right].Identity.OwnerID
	})
	return peers, nil
}

func standardGatewayAddress(cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() || prefix.String() != cidr || prefix.Masked() != prefix || prefix.Bits() > 30 {
		return "", fmt.Errorf("must be a canonical usable IPv4 prefix")
	}
	return fmt.Sprintf("%s/%d", prefix.Addr().Next(), prefix.Bits()), nil
}

func standardIdentityAddress(addressText, cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() || prefix.String() != cidr || prefix.Masked() != prefix || prefix.Bits() > 30 {
		return "", fmt.Errorf("node CIDR must be a canonical usable IPv4 prefix")
	}
	address, err := netip.ParseAddr(addressText)
	if err != nil || !address.Is4() || address.String() != addressText || !prefix.Contains(address) || address == prefix.Addr() || address == prefix.Addr().Next() || !prefix.Contains(address.Next()) {
		return "", fmt.Errorf("identity address must be a canonical allocatable IPv4 address in %s", cidr)
	}
	return address.String() + "/32", nil
}

func standardIdentityKey(kind model.TargetKind, id string) string {
	return string(kind) + ":" + id
}

func standardConfigHash(content []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(content))
}
