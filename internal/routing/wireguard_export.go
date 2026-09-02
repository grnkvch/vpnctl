package routing

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

var defaultWireGuardClientDNS = []string{"1.1.1.1", "8.8.8.8"}

type ClientCredentialReader interface {
	Get(reference model.SecretRef) ([]byte, error)
}

type WireGuardProfileRequest struct {
	ClientReference  string
	GatewayPublicKey string
	DNSServers       []string
}

type WireGuardProfile struct {
	ClientID              string
	ClientName            string
	SourceStateGeneration uint64
	CredentialGeneration  uint64
	content               []byte
}

func (profile WireGuardProfile) Bytes() []byte {
	return append([]byte(nil), profile.content...)
}

type WireGuardProfileRenderer struct {
	state       ClientStateStore
	credentials ClientCredentialReader
}

func NewWireGuardProfileRenderer(state ClientStateStore, credentials ClientCredentialReader) (*WireGuardProfileRenderer, error) {
	if state == nil || credentials == nil {
		return nil, fmt.Errorf("WireGuard profile renderer state and credential reader are required")
	}
	return &WireGuardProfileRenderer{state: state, credentials: credentials}, nil
}

func (renderer *WireGuardProfileRenderer) Render(request WireGuardProfileRequest) (WireGuardProfile, error) {
	if renderer == nil {
		return WireGuardProfile{}, fmt.Errorf("WireGuard profile renderer is required")
	}
	state, err := renderer.state.Load()
	if err != nil {
		return WireGuardProfile{}, fmt.Errorf("load WireGuard profile state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return WireGuardProfile{}, fmt.Errorf("validate WireGuard profile state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return WireGuardProfile{}, fmt.Errorf("WireGuard client profiles require gateway state")
	}
	client, err := resolveVisibleClient(state.Clients, request.ClientReference)
	if err != nil {
		return WireGuardProfile{}, err
	}
	if client.Lifecycle != model.LifecycleActive {
		return WireGuardProfile{}, fmt.Errorf("client %s is not active", client.Name)
	}
	standard, found := findClientStandardTransport(state.Transports, client.ID)
	if !found || standard.State == model.TransportDisabled {
		return WireGuardProfile{}, fmt.Errorf("client %s has no exportable standard transport", client.Name)
	}
	privateKeyBytes, err := renderer.credentials.Get(standard.CredentialRef)
	if err != nil {
		return WireGuardProfile{}, fmt.Errorf("read client standard credential: %w", err)
	}
	privateKey := strings.TrimSpace(string(privateKeyBytes))
	address, err := wireguard.ClientAddress(client.OverlayIPv4, state.Host.ClientCIDR)
	if err != nil {
		return WireGuardProfile{}, fmt.Errorf("derive client WireGuard address: %w", err)
	}
	dns, err := wireGuardClientDNS(request.DNSServers)
	if err != nil {
		return WireGuardProfile{}, err
	}
	content, err := wireguard.RenderClientConfig(wireguard.ClientConfig{
		PrivateKey: privateKey, Address: address, DNSServers: dns,
		ServerPublicKey: strings.TrimSpace(request.GatewayPublicKey),
		Endpoint:        wireguard.Endpoint(state.Host.PublicIPv4, 51820),
	})
	if err != nil {
		return WireGuardProfile{}, err
	}
	return WireGuardProfile{
		ClientID: client.ID, ClientName: client.Name, SourceStateGeneration: state.Generation,
		CredentialGeneration: client.CredentialGeneration, content: []byte(content),
	}, nil
}

func findClientStandardTransport(transports []model.Transport, clientID string) (model.Transport, bool) {
	for _, transport := range transports {
		if transport.OwnerKind == model.TargetClient && transport.OwnerID == clientID && transport.Kind == model.TransportStandard {
			return transport, true
		}
	}
	return model.Transport{}, false
}

func wireGuardClientDNS(requested []string) ([]string, error) {
	values := requested
	if values == nil {
		values = defaultWireGuardClientDNS
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("WireGuard client DNS must contain at least one IPv4 server")
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || address.String() != value {
			return nil, fmt.Errorf("WireGuard client DNS %q must be a canonical IPv4 address", value)
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, fmt.Errorf("WireGuard client DNS duplicates %s", value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}
