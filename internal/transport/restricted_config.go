package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"go.yaml.in/yaml/v3"
)

const (
	RestrictedProviderName          = restricted.ProviderName
	RestrictedProviderVersion       = "v1.19.30"
	RestrictedProviderAsset         = "mihomo-linux-amd64-v1.19.30.gz"
	RestrictedProviderSHA256        = "cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84"
	RestrictedProviderSizeBytes     = int64(18868732)
	RestrictedCipher                = restricted.Cipher
	RestrictedShadowTLSVersion      = restricted.ShadowTLSVersion
	RestrictedUDPOverTCPVersion     = restricted.UDPOverTCPVersion
	RestrictedTCPPort               = restricted.TCPPort
	RestrictedConfigFileName        = "restricted.yaml"
	RestrictedBinaryRelativePath    = "usr/local/libexec/vpnctl/mihomo"
	RestrictedStateRelativePath     = "restricted"
	RestrictedGatewayCredentialGen  = uint64(1)
	RestrictedGatewayListenerName   = "vpnctl-restricted-in"
	RestrictedNodeProxyName         = "VPNCTL-RESTRICTED"
	RestrictedNodeUDPGroupName      = "VPNCTL-RESTRICTED-UDP"
	RestrictedRejectProxyName       = "REJECT-DROP"
	RestrictedBootstrapUserName     = "vpnctl-bootstrap"
	restrictedSecretSchemaVersion   = restricted.SecretSchemaVersion
	maximumRestrictedConfigBytes    = 1 << 20
	restrictedSymmetricKeyByteCount = restricted.SymmetricKeyByteCount
	GatewayRestrictedCredentialRef  = restricted.GatewayCredentialRef
)

type RestrictedCredentialStore interface {
	Get(model.SecretRef) ([]byte, error)
	PutIfAbsent(model.SecretRef, []byte) error
}

// GatewayRestrictedCredential is deliberately secret-free. Its referenced
// payload contains the shared Shadowsocks server key and an undistributed
// bootstrap ShadowTLS user, both generated from 256 bits of entropy.
type GatewayRestrictedCredential struct {
	Reference  model.SecretRef
	Generation uint64
}

type restrictedGatewaySecret = restricted.GatewaySecret

type restrictedIdentitySecret = restricted.IdentitySecret

// EnsureGatewayRestrictedCredential creates the server-wide material once.
// Concurrent initialization adopts only a fully decoded and validated winner.
func EnsureGatewayRestrictedCredential(ctx context.Context, secrets RestrictedCredentialStore, random io.Reader) (GatewayRestrictedCredential, error) {
	credential, _, err := ensureGatewayRestrictedCredential(ctx, secrets, random)
	return credential, err
}

func ensureGatewayRestrictedCredential(ctx context.Context, secrets RestrictedCredentialStore, random io.Reader) (GatewayRestrictedCredential, bool, error) {
	if ctx == nil {
		return GatewayRestrictedCredential{}, false, fmt.Errorf("context is required")
	}
	if secrets == nil {
		return GatewayRestrictedCredential{}, false, fmt.Errorf("restricted credential store is required")
	}
	if random == nil {
		random = rand.Reader
	}
	stored, err := secrets.Get(GatewayRestrictedCredentialRef)
	if err == nil {
		if _, decodeErr := decodeRestrictedGatewaySecret(stored); decodeErr != nil {
			return GatewayRestrictedCredential{}, false, fmt.Errorf("validate gateway restricted credential: %w", decodeErr)
		}
		return GatewayRestrictedCredential{Reference: GatewayRestrictedCredentialRef, Generation: RestrictedGatewayCredentialGen}, false, nil
	}
	if !errors.Is(err, store.ErrSecretNotFound) && !errors.Is(err, fs.ErrNotExist) {
		return GatewayRestrictedCredential{}, false, fmt.Errorf("read gateway restricted credential: %w", err)
	}
	material, err := newRestrictedGatewaySecret(random)
	if err != nil {
		return GatewayRestrictedCredential{}, false, err
	}
	encoded, err := encodeRestrictedSecret(material)
	if err != nil {
		return GatewayRestrictedCredential{}, false, err
	}
	if err := secrets.PutIfAbsent(GatewayRestrictedCredentialRef, encoded); err != nil {
		if !errors.Is(err, store.ErrSecretExists) {
			return GatewayRestrictedCredential{}, false, fmt.Errorf("publish gateway restricted credential: %w", err)
		}
		stored, readErr := secrets.Get(GatewayRestrictedCredentialRef)
		if readErr != nil {
			return GatewayRestrictedCredential{}, false, fmt.Errorf("read concurrently published gateway restricted credential: %w", readErr)
		}
		if _, decodeErr := decodeRestrictedGatewaySecret(stored); decodeErr != nil {
			return GatewayRestrictedCredential{}, false, fmt.Errorf("validate concurrently published gateway restricted credential: %w", decodeErr)
		}
		return GatewayRestrictedCredential{Reference: GatewayRestrictedCredentialRef, Generation: RestrictedGatewayCredentialGen}, false, nil
	}
	return GatewayRestrictedCredential{Reference: GatewayRestrictedCredentialRef, Generation: RestrictedGatewayCredentialGen}, true, nil
}

// GenerateRestrictedIdentitySecret returns a root-only payload for one
// identity. The payload contains no shared server key and is safe to send to
// the gateway only through an authenticated enrollment or rotation channel.
func GenerateRestrictedIdentitySecret(random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	return restricted.GenerateIdentitySecret(random)
}

func newRestrictedGatewaySecret(random io.Reader) (restrictedGatewaySecret, error) {
	return restricted.NewGatewaySecret(random)
}

func encodeRestrictedSecret(value any) ([]byte, error) {
	return restricted.EncodeSecret(value)
}

func decodeRestrictedGatewaySecret(content []byte) (restrictedGatewaySecret, error) {
	return restricted.DecodeGatewaySecret(content)
}

func decodeRestrictedIdentitySecret(content []byte) (restrictedIdentitySecret, error) {
	return restricted.DecodeIdentitySecret(content)
}

func validateRestrictedServerPassword(password string) error {
	return restricted.ValidateServerPassword(password)
}

func validateRestrictedIdentityPassword(password string) error {
	return restricted.ValidateIdentityPassword(password)
}

type RestrictedUserDescriptor struct {
	Identity Identity
	Name     string
}

type renderedRestrictedUser struct {
	descriptor RestrictedUserDescriptor
	password   string
}

type GatewayRestrictedConfigArtifact struct {
	content []byte
	users   []RestrictedUserDescriptor
}

func (artifact GatewayRestrictedConfigArtifact) Bytes() []byte {
	return append([]byte(nil), artifact.content...)
}

func (artifact GatewayRestrictedConfigArtifact) Users() []RestrictedUserDescriptor {
	return append([]RestrictedUserDescriptor(nil), artifact.users...)
}

func (artifact GatewayRestrictedConfigArtifact) ConfigHash() string {
	digest := sha256.Sum256(artifact.content)
	return hex.EncodeToString(digest[:])
}

type RestrictedNodeCandidate struct {
	content    []byte
	descriptor CandidateDescriptor
}

var _ Candidate = RestrictedNodeCandidate{}

func (candidate RestrictedNodeCandidate) Bytes() []byte {
	return append([]byte(nil), candidate.content...)
}

func (candidate RestrictedNodeCandidate) Descriptor() CandidateDescriptor {
	return candidate.descriptor
}

type GatewayRestrictedRenderRequest struct {
	State         model.State
	CredentialRef model.SecretRef
	Credentials   interface {
		Get(model.SecretRef) ([]byte, error)
	}
}

// RenderGatewayRestrictedConfig emits one shared Shadowsocks listener. The
// server key is shared by protocol necessity; the ShadowTLS v3 user password
// remains unique per active identity and is the revocation boundary.
func RenderGatewayRestrictedConfig(request GatewayRestrictedRenderRequest) (GatewayRestrictedConfigArtifact, error) {
	if request.Credentials == nil {
		return GatewayRestrictedConfigArtifact{}, fmt.Errorf("restricted credential reader is required")
	}
	if request.CredentialRef != GatewayRestrictedCredentialRef {
		return GatewayRestrictedConfigArtifact{}, fmt.Errorf("gateway restricted credential reference must be %s", GatewayRestrictedCredentialRef)
	}
	if err := request.State.Validate(); err != nil {
		return GatewayRestrictedConfigArtifact{}, fmt.Errorf("validate gateway restricted state: %w", err)
	}
	if request.State.Host.Role != model.RoleGateway {
		return GatewayRestrictedConfigArtifact{}, fmt.Errorf("gateway restricted config requires gateway state")
	}
	if err := validateRestrictedComponentManifest(request.State.Components); err != nil {
		return GatewayRestrictedConfigArtifact{}, err
	}
	serverContent, err := request.Credentials.Get(request.CredentialRef)
	if err != nil {
		return GatewayRestrictedConfigArtifact{}, fmt.Errorf("read gateway restricted credential: %w", err)
	}
	serverSecret, err := decodeRestrictedGatewaySecret(serverContent)
	if err != nil {
		return GatewayRestrictedConfigArtifact{}, fmt.Errorf("validate gateway restricted credential: %w", err)
	}
	users := []renderedRestrictedUser{{
		descriptor: RestrictedUserDescriptor{Name: RestrictedBootstrapUserName},
		password:   serverSecret.BootstrapShadowTLSPassword,
	}}
	seenPasswords := map[string]struct{}{serverSecret.BootstrapShadowTLSPassword: {}}
	for _, value := range sortedRestrictedTransports(request.State) {
		identitySecretContent, readErr := request.Credentials.Get(value.CredentialRef)
		if readErr != nil {
			return GatewayRestrictedConfigArtifact{}, fmt.Errorf("read restricted identity credential for %s: %w", value.OwnerID, readErr)
		}
		identitySecret, decodeErr := decodeRestrictedIdentitySecret(identitySecretContent)
		if decodeErr != nil {
			return GatewayRestrictedConfigArtifact{}, fmt.Errorf("validate restricted identity credential for %s: %w", value.OwnerID, decodeErr)
		}
		if _, duplicate := seenPasswords[identitySecret.ShadowTLSPassword]; duplicate {
			return GatewayRestrictedConfigArtifact{}, fmt.Errorf("restricted identities must not share ShadowTLS credentials")
		}
		seenPasswords[identitySecret.ShadowTLSPassword] = struct{}{}
		identity := IdentityFromTransport(value)
		users = append(users, renderedRestrictedUser{
			descriptor: RestrictedUserDescriptor{Identity: identity, Name: restrictedUserName(identity)},
			password:   identitySecret.ShadowTLSPassword,
		})
	}

	handshakeHost, err := authoritativeRestrictedHandshakeHost(request.State)
	if err != nil {
		return GatewayRestrictedConfigArtifact{}, err
	}
	content := renderGatewayRestrictedYAML(serverSecret.ShadowsocksPassword, handshakeHost, users)
	if len(content) > maximumRestrictedConfigBytes {
		return GatewayRestrictedConfigArtifact{}, fmt.Errorf("gateway restricted config exceeds %d bytes", maximumRestrictedConfigBytes)
	}
	if err := ValidateGatewayRestrictedConfig(content); err != nil {
		return GatewayRestrictedConfigArtifact{}, fmt.Errorf("validate rendered gateway restricted config: %w", err)
	}
	descriptors := make([]RestrictedUserDescriptor, 0, len(users)-1)
	for _, user := range users[1:] {
		descriptors = append(descriptors, user.descriptor)
	}
	return GatewayRestrictedConfigArtifact{content: content, users: descriptors}, nil
}

type NodeRestrictedRenderRequest struct {
	Transport         model.Transport
	Node              model.Node
	GatewayPublicIPv4 string
	ServerPassword    string
	IdentitySecret    []byte
	Component         model.ComponentPin
}

// RenderNodeRestrictedConfig renders a strict UoT-capable outbound and an
// explicit selected-UDP reject alternative. It intentionally has no
// listener/TUN/DNS policy; routing composition belongs to task 10.2.
func RenderNodeRestrictedConfig(request NodeRestrictedRenderRequest) (RestrictedNodeCandidate, error) {
	if err := request.Node.Validate(); err != nil {
		return RestrictedNodeCandidate{}, fmt.Errorf("validate restricted node: %w", err)
	}
	if request.Node.Lifecycle != model.LifecycleActive {
		return RestrictedNodeCandidate{}, fmt.Errorf("restricted node must be active")
	}
	if err := request.Transport.Validate(); err != nil {
		return RestrictedNodeCandidate{}, fmt.Errorf("validate restricted transport: %w", err)
	}
	if request.Transport.OwnerKind != model.TargetNode || request.Transport.OwnerID != request.Node.ID || request.Transport.Kind != model.TransportRestricted {
		return RestrictedNodeCandidate{}, fmt.Errorf("restricted transport does not belong to node %s", request.Node.ID)
	}
	if request.Transport.State == model.TransportDisabled {
		return RestrictedNodeCandidate{}, fmt.Errorf("disabled restricted transport cannot be rendered")
	}
	if request.Transport.CredentialGeneration != request.Node.CredentialGeneration {
		return RestrictedNodeCandidate{}, fmt.Errorf("restricted transport credential generation does not match node")
	}
	if err := validateRestrictedComponent(request.Component); err != nil {
		return RestrictedNodeCandidate{}, err
	}
	address, err := netip.ParseAddr(request.GatewayPublicIPv4)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.String() != request.GatewayPublicIPv4 {
		return RestrictedNodeCandidate{}, fmt.Errorf("gateway restricted endpoint must be a canonical global-unicast IPv4 address")
	}
	if err := validateRestrictedServerPassword(request.ServerPassword); err != nil {
		return RestrictedNodeCandidate{}, err
	}
	identitySecret, err := decodeRestrictedIdentitySecret(request.IdentitySecret)
	if err != nil {
		return RestrictedNodeCandidate{}, fmt.Errorf("validate node restricted identity credential: %w", err)
	}
	content := renderNodeRestrictedYAML(request, identitySecret.ShadowTLSPassword)
	if len(content) > maximumRestrictedConfigBytes {
		return RestrictedNodeCandidate{}, fmt.Errorf("node restricted config exceeds %d bytes", maximumRestrictedConfigBytes)
	}
	if err := ValidateNodeRestrictedConfig(content); err != nil {
		return RestrictedNodeCandidate{}, fmt.Errorf("validate rendered node restricted config: %w", err)
	}
	digest := sha256.Sum256(content)
	return RestrictedNodeCandidate{
		content: content,
		descriptor: CandidateDescriptor{
			OwnerKind: request.Transport.OwnerKind, OwnerID: request.Transport.OwnerID, Kind: model.TransportRestricted,
			CredentialGeneration: request.Transport.CredentialGeneration, ConfigHash: hex.EncodeToString(digest[:]),
		},
	}, nil
}

func sortedRestrictedTransports(state model.State) []model.Transport {
	active := make(map[string]bool, len(state.Clients)+len(state.Nodes))
	for _, client := range state.Clients {
		active[string(model.TargetClient)+":"+client.ID] = client.Lifecycle == model.LifecycleActive
	}
	for _, node := range state.Nodes {
		active[string(model.TargetNode)+":"+node.ID] = node.Lifecycle == model.LifecycleActive
	}
	result := make([]model.Transport, 0)
	for _, value := range state.Transports {
		key := string(value.OwnerKind) + ":" + value.OwnerID
		if value.Kind == model.TransportRestricted && value.State != model.TransportDisabled && active[key] {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].OwnerKind != result[right].OwnerKind {
			return result[left].OwnerKind < result[right].OwnerKind
		}
		return result[left].OwnerID < result[right].OwnerID
	})
	return result
}

func authoritativeRestrictedHandshakeHost(state model.State) (string, error) {
	if state.HandshakeHost == nil {
		return "", fmt.Errorf("gateway restricted config requires an authoritative handshake host")
	}
	host := state.HandshakeHost.Hostname
	for _, value := range state.Transports {
		if value.Kind != model.TransportRestricted || value.State == model.TransportDisabled {
			continue
		}
		if value.HandshakeHost != host {
			return "", fmt.Errorf("restricted transports disagree on the authoritative handshake host")
		}
	}
	return host, nil
}

func restrictedUserName(identity Identity) string {
	return string(identity.OwnerKind) + "-" + strings.ReplaceAll(identity.OwnerID, "-", "")
}

func renderGatewayRestrictedYAML(serverPassword, handshakeHost string, users []renderedRestrictedUser) []byte {
	var config strings.Builder
	config.WriteString("mode: rule\n")
	config.WriteString("log-level: silent\n")
	config.WriteString("ipv6: false\n")
	config.WriteString("geodata-loader: memconservative\n")
	config.WriteString("geo-auto-update: false\n\n")
	config.WriteString("listeners:\n")
	fmt.Fprintf(&config, "  - name: %s\n", RestrictedGatewayListenerName)
	config.WriteString("    type: shadowsocks\n")
	config.WriteString("    listen: 0.0.0.0\n")
	fmt.Fprintf(&config, "    port: %d\n", RestrictedTCPPort)
	fmt.Fprintf(&config, "    cipher: %s\n", RestrictedCipher)
	fmt.Fprintf(&config, "    password: %s\n", strconv.Quote(serverPassword))
	config.WriteString("    udp: false\n")
	config.WriteString("    shadow-tls:\n")
	config.WriteString("      enable: true\n")
	fmt.Fprintf(&config, "      version: %d\n", RestrictedShadowTLSVersion)
	config.WriteString("      users:\n")
	for _, user := range users {
		fmt.Fprintf(&config, "        - name: %s\n", strconv.Quote(user.descriptor.Name))
		fmt.Fprintf(&config, "          password: %s\n", strconv.Quote(user.password))
	}
	config.WriteString("      handshake:\n")
	fmt.Fprintf(&config, "        dest: %s\n", strconv.Quote(handshakeHost+":443"))
	config.WriteString("\nrules:\n")
	config.WriteString("  - MATCH,DIRECT\n")
	return []byte(config.String())
}

func renderNodeRestrictedYAML(request NodeRestrictedRenderRequest, identityPassword string) []byte {
	var config strings.Builder
	config.WriteString("mode: rule\n")
	config.WriteString("log-level: silent\n")
	config.WriteString("ipv6: false\n")
	config.WriteString("geodata-loader: memconservative\n")
	config.WriteString("geo-auto-update: false\n\n")
	config.WriteString("proxies:\n")
	fmt.Fprintf(&config, "  - name: %s\n", RestrictedNodeProxyName)
	config.WriteString("    type: ss\n")
	fmt.Fprintf(&config, "    server: %s\n", request.GatewayPublicIPv4)
	fmt.Fprintf(&config, "    port: %d\n", RestrictedTCPPort)
	fmt.Fprintf(&config, "    cipher: %s\n", RestrictedCipher)
	fmt.Fprintf(&config, "    password: %s\n", strconv.Quote(request.ServerPassword))
	config.WriteString("    ip-version: ipv4\n")
	config.WriteString("    udp: true\n")
	config.WriteString("    udp-over-tcp: true\n")
	fmt.Fprintf(&config, "    udp-over-tcp-version: %d\n", RestrictedUDPOverTCPVersion)
	config.WriteString("    plugin: shadow-tls\n")
	config.WriteString("    client-fingerprint: chrome\n")
	config.WriteString("    plugin-opts:\n")
	fmt.Fprintf(&config, "      host: %s\n", strconv.Quote(request.Transport.HandshakeHost))
	fmt.Fprintf(&config, "      password: %s\n", strconv.Quote(identityPassword))
	fmt.Fprintf(&config, "      version: %d\n", RestrictedShadowTLSVersion)
	config.WriteString("      strict-mode: true\n")
	config.WriteString("\nproxy-groups:\n")
	fmt.Fprintf(&config, "  - name: %s\n", RestrictedNodeUDPGroupName)
	config.WriteString("    type: select\n")
	config.WriteString("    proxies:\n")
	fmt.Fprintf(&config, "      - %s\n", RestrictedNodeProxyName)
	fmt.Fprintf(&config, "      - %s\n", RestrictedRejectProxyName)
	config.WriteString("\nrules:\n")
	fmt.Fprintf(&config, "  - NETWORK,UDP,%s\n", RestrictedNodeUDPGroupName)
	fmt.Fprintf(&config, "  - MATCH,%s\n", RestrictedNodeProxyName)
	return []byte(config.String())
}

func validateRestrictedComponentManifest(manifest model.ComponentManifest) error {
	for _, component := range manifest.Components {
		if component.Name == RestrictedProviderName {
			return validateRestrictedComponent(component)
		}
	}
	return fmt.Errorf("pinned Mihomo component is absent from the installed manifest")
}

func validateRestrictedComponent(component model.ComponentPin) error {
	if err := component.Validate(); err != nil {
		return fmt.Errorf("validate pinned Mihomo component: %w", err)
	}
	if component.Name != RestrictedProviderName || component.Version != RestrictedProviderVersion || !component.Bundled || component.SHA256 != RestrictedProviderSHA256 {
		return fmt.Errorf("restricted provider does not match the pinned Mihomo artifact")
	}
	required := map[string]bool{
		"shadowsocks-2022-blake3-aes-256-gcm": false,
		"shadowtls-v3-strict":                 false,
	}
	for _, capability := range component.Capabilities {
		if _, known := required[capability]; known {
			required[capability] = true
		}
	}
	for capability, present := range required {
		if !present {
			return fmt.Errorf("pinned Mihomo component lacks %s capability", capability)
		}
	}
	return nil
}

type restrictedGatewayDocument struct {
	Mode          string                      `yaml:"mode"`
	LogLevel      string                      `yaml:"log-level"`
	IPv6          *bool                       `yaml:"ipv6"`
	GeodataLoader string                      `yaml:"geodata-loader"`
	GeoAutoUpdate *bool                       `yaml:"geo-auto-update"`
	Listeners     []restrictedGatewayListener `yaml:"listeners"`
	Rules         []string                    `yaml:"rules"`
}

type restrictedGatewayListener struct {
	Name      string              `yaml:"name"`
	Type      string              `yaml:"type"`
	Listen    string              `yaml:"listen"`
	Port      *int                `yaml:"port"`
	Cipher    string              `yaml:"cipher"`
	Password  string              `yaml:"password"`
	UDP       *bool               `yaml:"udp"`
	ShadowTLS restrictedShadowTLS `yaml:"shadow-tls"`
}

type restrictedShadowTLS struct {
	Enable    *bool                     `yaml:"enable"`
	Version   *int                      `yaml:"version"`
	Users     []restrictedShadowTLSUser `yaml:"users"`
	Handshake restrictedHandshake       `yaml:"handshake"`
}

type restrictedShadowTLSUser struct {
	Name     string `yaml:"name"`
	Password string `yaml:"password"`
}

type restrictedHandshake struct {
	Destination string `yaml:"dest"`
}

type restrictedNodeDocument struct {
	Mode          string                 `yaml:"mode"`
	LogLevel      string                 `yaml:"log-level"`
	IPv6          *bool                  `yaml:"ipv6"`
	GeodataLoader string                 `yaml:"geodata-loader"`
	GeoAutoUpdate *bool                  `yaml:"geo-auto-update"`
	Proxies       []restrictedNodeProxy  `yaml:"proxies"`
	ProxyGroups   []restrictedProxyGroup `yaml:"proxy-groups"`
	Rules         []string               `yaml:"rules"`
}

type restrictedNodeProxy struct {
	Name              string                      `yaml:"name"`
	Type              string                      `yaml:"type"`
	Server            string                      `yaml:"server"`
	Port              *int                        `yaml:"port"`
	Cipher            string                      `yaml:"cipher"`
	Password          string                      `yaml:"password"`
	IPVersion         string                      `yaml:"ip-version"`
	UDP               *bool                       `yaml:"udp"`
	UDPOverTCP        *bool                       `yaml:"udp-over-tcp"`
	UDPOverTCPVersion *int                        `yaml:"udp-over-tcp-version"`
	Plugin            string                      `yaml:"plugin"`
	ClientFingerprint string                      `yaml:"client-fingerprint"`
	PluginOptions     restrictedNodePluginOptions `yaml:"plugin-opts"`
}

type restrictedProxyGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
}

type restrictedNodePluginOptions struct {
	Host       string `yaml:"host"`
	Password   string `yaml:"password"`
	Version    *int   `yaml:"version"`
	StrictMode *bool  `yaml:"strict-mode"`
}

// ValidateGatewayRestrictedConfig enforces the provider contract before the
// native Mihomo parser is allowed to touch its state directory.
func ValidateGatewayRestrictedConfig(content []byte) error {
	if len(content) == 0 || len(content) > maximumRestrictedConfigBytes {
		return fmt.Errorf("restricted gateway config has invalid size")
	}
	var document restrictedGatewayDocument
	if err := decodeRestrictedYAML(content, &document); err != nil {
		return err
	}
	if document.Mode != "rule" || document.LogLevel != "silent" || !isFalse(document.IPv6) ||
		document.GeodataLoader != "memconservative" || !isFalse(document.GeoAutoUpdate) ||
		len(document.Listeners) != 1 || len(document.Rules) != 1 || document.Rules[0] != "MATCH,DIRECT" {
		return fmt.Errorf("restricted gateway config has unsupported global behavior")
	}
	listener := document.Listeners[0]
	if listener.Name != RestrictedGatewayListenerName || listener.Type != "shadowsocks" || listener.Listen != "0.0.0.0" ||
		listener.Port == nil || *listener.Port != RestrictedTCPPort || listener.Cipher != RestrictedCipher || !isFalse(listener.UDP) {
		return fmt.Errorf("restricted gateway listener does not match the pinned TCP-only contract")
	}
	if err := validateRestrictedServerPassword(listener.Password); err != nil {
		return err
	}
	if !isTrue(listener.ShadowTLS.Enable) || listener.ShadowTLS.Version == nil || *listener.ShadowTLS.Version != RestrictedShadowTLSVersion || len(listener.ShadowTLS.Users) == 0 {
		return fmt.Errorf("restricted gateway listener does not enforce ShadowTLS v3")
	}
	host, port, found := strings.Cut(listener.ShadowTLS.Handshake.Destination, ":")
	if !found || port != "443" || !validRestrictedHostname(host) {
		return fmt.Errorf("restricted gateway handshake destination is invalid")
	}
	seenNames := make(map[string]struct{}, len(listener.ShadowTLS.Users))
	seenPasswords := make(map[string]struct{}, len(listener.ShadowTLS.Users))
	for _, user := range listener.ShadowTLS.Users {
		if !validRestrictedUserName(user.Name) {
			return fmt.Errorf("restricted ShadowTLS user name is invalid")
		}
		if err := validateRestrictedIdentityPassword(user.Password); err != nil {
			return err
		}
		if _, duplicate := seenNames[user.Name]; duplicate {
			return fmt.Errorf("restricted ShadowTLS user names must be unique")
		}
		if _, duplicate := seenPasswords[user.Password]; duplicate {
			return fmt.Errorf("restricted ShadowTLS user credentials must be unique")
		}
		seenNames[user.Name] = struct{}{}
		seenPasswords[user.Password] = struct{}{}
	}
	return nil
}

// ValidateNodeRestrictedConfig enforces strict ShadowTLS, UoT v2, an explicit
// UDP reject alternative, and no direct fallback for traffic handed to this
// provider. The artifact cannot open a local/public listener by itself.
func ValidateNodeRestrictedConfig(content []byte) error {
	if len(content) == 0 || len(content) > maximumRestrictedConfigBytes {
		return fmt.Errorf("restricted node config has invalid size")
	}
	var document restrictedNodeDocument
	if err := decodeRestrictedYAML(content, &document); err != nil {
		return err
	}
	if document.Mode != "rule" || document.LogLevel != "silent" || !isFalse(document.IPv6) ||
		document.GeodataLoader != "memconservative" || !isFalse(document.GeoAutoUpdate) ||
		len(document.Proxies) != 1 || len(document.ProxyGroups) != 1 || len(document.Rules) != 2 ||
		document.Rules[0] != "NETWORK,UDP,"+RestrictedNodeUDPGroupName || document.Rules[1] != "MATCH,"+RestrictedNodeProxyName {
		return fmt.Errorf("restricted node config has unsupported global behavior")
	}
	proxy := document.Proxies[0]
	address, err := netip.ParseAddr(proxy.Server)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.String() != proxy.Server ||
		proxy.Name != RestrictedNodeProxyName || proxy.Type != "ss" || proxy.Port == nil || *proxy.Port != RestrictedTCPPort ||
		proxy.Cipher != RestrictedCipher || proxy.IPVersion != "ipv4" || !isTrue(proxy.UDP) || !isTrue(proxy.UDPOverTCP) ||
		proxy.UDPOverTCPVersion == nil || *proxy.UDPOverTCPVersion != RestrictedUDPOverTCPVersion ||
		proxy.Plugin != "shadow-tls" || proxy.ClientFingerprint != "chrome" {
		return fmt.Errorf("restricted node outbound does not match the pinned UoT contract")
	}
	if err := validateRestrictedServerPassword(proxy.Password); err != nil {
		return err
	}
	options := proxy.PluginOptions
	if !validRestrictedHostname(options.Host) || options.Version == nil || *options.Version != RestrictedShadowTLSVersion || !isTrue(options.StrictMode) {
		return fmt.Errorf("restricted node outbound does not enforce strict ShadowTLS v3")
	}
	if err := validateRestrictedIdentityPassword(options.Password); err != nil {
		return err
	}
	group := document.ProxyGroups[0]
	if group.Name != RestrictedNodeUDPGroupName || group.Type != "select" ||
		len(group.Proxies) != 2 || group.Proxies[0] != RestrictedNodeProxyName || group.Proxies[1] != RestrictedRejectProxyName {
		return fmt.Errorf("restricted node UDP guard must select only UoT or explicit reject")
	}
	for _, rule := range document.Rules {
		if strings.Contains(rule, "DIRECT") {
			return fmt.Errorf("restricted node provider rules must not contain direct fallback")
		}
	}
	return nil
}

func decodeRestrictedYAML(content []byte, destination any) error {
	var root yaml.Node
	nodeDecoder := yaml.NewDecoder(bytes.NewReader(content))
	if err := nodeDecoder.Decode(&root); err != nil {
		return fmt.Errorf("decode restricted config: %w", err)
	}
	if err := rejectRestrictedYAMLIndirection(&root); err != nil {
		return err
	}
	var trailingNode yaml.Node
	if err := nodeDecoder.Decode(&trailingNode); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode restricted config: trailing YAML document")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode restricted config: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode restricted config: trailing YAML document")
	}
	return nil
}

func rejectRestrictedYAMLIndirection(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" || node.Tag == "!!merge" || node.Value == "<<" {
		return fmt.Errorf("restricted config YAML aliases, anchors, and merges are forbidden")
	}
	for _, child := range node.Content {
		if err := rejectRestrictedYAMLIndirection(child); err != nil {
			return err
		}
	}
	return nil
}

func isTrue(value *bool) bool  { return value != nil && *value }
func isFalse(value *bool) bool { return value != nil && !*value }

func validRestrictedHostname(value string) bool {
	if value == "" || value != strings.ToLower(value) || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validRestrictedUserName(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}
