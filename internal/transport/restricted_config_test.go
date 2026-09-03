package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestGatewayRestrictedCredentialIsCreatedOnceAndNeverReturnedSecret(t *testing.T) {
	t.Parallel()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	entropy := bytes.Repeat([]byte{0x31}, restrictedSymmetricKeyByteCount*2)
	first, err := EnsureGatewayRestrictedCredential(context.Background(), secrets, bytes.NewReader(entropy))
	if err != nil {
		t.Fatalf("EnsureGatewayRestrictedCredential(first) error = %v", err)
	}
	second, err := EnsureGatewayRestrictedCredential(context.Background(), secrets, bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("EnsureGatewayRestrictedCredential(second) error = %v", err)
	}
	if first != second || first.Reference != GatewayRestrictedCredentialRef || first.Generation != 1 {
		t.Fatalf("credentials = %#v / %#v", first, second)
	}
	stored, err := secrets.Get(GatewayRestrictedCredentialRef)
	if err != nil {
		t.Fatal(err)
	}
	material, err := decodeRestrictedGatewaySecret(stored)
	if err != nil {
		t.Fatal(err)
	}
	if material.ShadowsocksPassword == material.BootstrapShadowTLSPassword {
		t.Fatal("restricted server and bootstrap credentials are not independent")
	}
	kind, id, _ := GatewayRestrictedCredentialRef.Parts()
	info, err := os.Stat(filepath.Join(paths.SecretsDir, kind, id))
	if err != nil || info.Mode().Perm() != store.SecretFileMode {
		t.Fatalf("restricted credential file = %v, %v", info, err)
	}
	encoded, err := json.Marshal(first)
	if err != nil || bytes.Contains(encoded, []byte(material.ShadowsocksPassword)) || bytes.Contains(encoded, []byte(material.BootstrapShadowTLSPassword)) {
		t.Fatalf("public credential JSON leaked secret material: %s, %v", encoded, err)
	}
}

func TestRenderGatewayRestrictedConfigIncludesUniqueActiveIdentitiesDeterministically(t *testing.T) {
	t.Parallel()
	state, credentials := restrictedGatewayFixture(t)
	request := GatewayRestrictedRenderRequest{State: state, CredentialRef: GatewayRestrictedCredentialRef, Credentials: credentials}
	first, err := RenderGatewayRestrictedConfig(request)
	if err != nil {
		t.Fatalf("RenderGatewayRestrictedConfig() error = %v", err)
	}
	second, err := RenderGatewayRestrictedConfig(request)
	if err != nil || !bytes.Equal(first.Bytes(), second.Bytes()) || first.ConfigHash() != second.ConfigHash() {
		t.Fatalf("second render differs: %v", err)
	}
	users := first.Users()
	if len(users) != 7 {
		t.Fatalf("restricted user count = %d, want seven", len(users))
	}
	for index, user := range users {
		if err := user.Identity.Validate(); err != nil {
			t.Fatalf("user %d identity: %v", index, err)
		}
		if index < 5 && user.Identity.OwnerKind != model.TargetClient {
			t.Fatalf("user order = %#v", users)
		}
		if index >= 5 && user.Identity.OwnerKind != model.TargetNode {
			t.Fatalf("user order = %#v", users)
		}
	}
	config := string(first.Bytes())
	for _, required := range []string{
		"log-level: silent", "type: shadowsocks", "listen: 0.0.0.0", "port: 8443",
		"cipher: 2022-blake3-aes-256-gcm", "udp: false", "version: 3",
		`dest: "www.microsoft.com:443"`, `name: "vpnctl-bootstrap"`, "MATCH,DIRECT",
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("gateway restricted config lacks %q:\n%s", required, config)
		}
	}
	if strings.Contains(config, "strict-mode: false") || strings.Contains(config, "udp-over-tcp") || strings.Count(config, "      users:") != 1 {
		t.Fatalf("gateway restricted config weakens the task-8.3 contract:\n%s", config)
	}
	copyBytes := first.Bytes()
	copyBytes[0] = 'x'
	if first.Bytes()[0] != 'm' {
		t.Fatal("restricted artifact bytes are not defensive copies")
	}
}

func TestRenderGatewayRestrictedConfigRejectsSharedIdentityCredentialAndManifestDrift(t *testing.T) {
	t.Parallel()
	state, credentials := restrictedGatewayFixture(t)
	credentials[state.Transports[len(state.Transports)-1].CredentialRef] = append([]byte(nil), credentials[state.Transports[len(state.Transports)-2].CredentialRef]...)
	_, err := RenderGatewayRestrictedConfig(GatewayRestrictedRenderRequest{
		State: state, CredentialRef: GatewayRestrictedCredentialRef, Credentials: credentials,
	})
	if err == nil || !strings.Contains(err.Error(), "must not share") {
		t.Fatalf("shared restricted credential error = %v", err)
	}

	state, credentials = restrictedGatewayFixture(t)
	for index := range state.Components.Components {
		if state.Components.Components[index].Name == RestrictedProviderName {
			state.Components.Components[index].Version = "v1.19.31"
		}
	}
	_, err = RenderGatewayRestrictedConfig(GatewayRestrictedRenderRequest{
		State: state, CredentialRef: GatewayRestrictedCredentialRef, Credentials: credentials,
	})
	if err == nil || !strings.Contains(err.Error(), "pinned Mihomo") {
		t.Fatalf("manifest drift error = %v", err)
	}
}

func TestRenderNodeRestrictedConfigIsStrictTCPOnlyAndHasNoListener(t *testing.T) {
	t.Parallel()
	node := restrictedNodeFixture()
	transport := restrictedTransportFixture(model.TargetNode, node.ID, model.TransportActive, 4, "www.microsoft.com")
	identitySecret := restrictedIdentitySecretBytes(t, 0x44)
	candidate, err := RenderNodeRestrictedConfig(NodeRestrictedRenderRequest{
		Transport: transport, Node: node, GatewayPublicIPv4: "203.0.113.10",
		ServerPassword: restrictedServerPassword(0x33), IdentitySecret: identitySecret,
		Component: restrictedComponentPin(),
	})
	if err != nil {
		t.Fatalf("RenderNodeRestrictedConfig() error = %v", err)
	}
	if err := candidate.Descriptor().Validate(); err != nil {
		t.Fatalf("restricted candidate descriptor: %v", err)
	}
	config := string(candidate.Bytes())
	for _, required := range []string{
		"log-level: silent", "name: VPNCTL-RESTRICTED", "server: 203.0.113.10", "port: 8443",
		"udp: false", "udp-over-tcp: false", "plugin: shadow-tls", `host: "www.microsoft.com"`,
		"version: 3", "strict-mode: true", "MATCH,DIRECT",
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("node restricted config lacks %q:\n%s", required, config)
		}
	}
	if strings.Contains(config, "listeners:") || strings.Contains(config, "mixed-port:") || strings.Contains(config, "socks-port:") || strings.Contains(config, "udp-over-tcp: true") {
		t.Fatalf("node restricted config owns a listener or premature UoT:\n%s", config)
	}
	weakened := bytes.Replace(candidate.Bytes(), []byte("strict-mode: true"), []byte("strict-mode: false"), 1)
	if err := ValidateNodeRestrictedConfig(weakened); err == nil || !strings.Contains(err.Error(), "strict ShadowTLS") {
		t.Fatalf("weakened strict-mode error = %v", err)
	}
}

func TestRestrictedConfigValidationRejectsUnknownFieldsAndYAMLIndirection(t *testing.T) {
	t.Parallel()
	state, credentials := restrictedGatewayFixture(t)
	artifact, err := RenderGatewayRestrictedConfig(GatewayRestrictedRenderRequest{
		State: state, CredentialRef: GatewayRestrictedCredentialRef, Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(artifact.Bytes(), []byte("external-controller: 0.0.0.0:9090\n")...)
	if err := ValidateGatewayRestrictedConfig(unknown); err == nil || !strings.Contains(err.Error(), "field external-controller not found") {
		t.Fatalf("unknown-field error = %v", err)
	}
	alias := bytes.Replace(artifact.Bytes(), []byte("mode: rule"), []byte("mode: &unsafe rule"), 1)
	if err := ValidateGatewayRestrictedConfig(alias); err == nil || !strings.Contains(err.Error(), "aliases, anchors") {
		t.Fatalf("anchor error = %v", err)
	}
}

func TestRestrictedConstantsMatchPinnedManifests(t *testing.T) {
	t.Parallel()
	var componentManifest struct {
		Components struct {
			Mihomo struct {
				Version string `json:"version"`
				Asset   string `json:"asset"`
				SHA256  string `json:"sha256"`
			} `json:"mihomo"`
		} `json:"components"`
		Limits struct {
			PublicNetwork struct {
				RestrictedTCP     int  `json:"restricted_tcp"`
				RestrictedUDPOpen bool `json:"restricted_udp_open"`
			} `json:"public_network"`
			Restricted struct {
				Cipher           string `json:"cipher"`
				ShadowTLSVersion int    `json:"shadowtls_version"`
				Strict           bool   `json:"strict"`
			} `json:"restricted_transport"`
		} `json:"limits"`
	}
	decodeJSONFixture(t, filepath.Join("..", "..", "docs", "v2", "COMPONENT_LIMITS.v1.json"), &componentManifest)
	if componentManifest.Components.Mihomo.Version != RestrictedProviderVersion ||
		componentManifest.Components.Mihomo.Asset != RestrictedProviderAsset ||
		componentManifest.Components.Mihomo.SHA256 != RestrictedProviderSHA256 ||
		componentManifest.Limits.PublicNetwork.RestrictedTCP != RestrictedTCPPort || componentManifest.Limits.PublicNetwork.RestrictedUDPOpen ||
		componentManifest.Limits.Restricted.Cipher != RestrictedCipher ||
		componentManifest.Limits.Restricted.ShadowTLSVersion != RestrictedShadowTLSVersion || !componentManifest.Limits.Restricted.Strict {
		t.Fatalf("production restricted constants drifted from component manifest: %+v", componentManifest)
	}

	var spikeManifest struct {
		Mihomo struct {
			Version string `json:"version"`
			Asset   string `json:"asset"`
			SHA256  string `json:"sha256"`
		} `json:"mihomo"`
		Transport struct {
			Port              int    `json:"port"`
			Protocol          string `json:"protocol"`
			Cipher            string `json:"cipher"`
			ShadowTLSVersion  int    `json:"shadow_tls_version"`
			StrictMode        bool   `json:"strict_mode"`
			NativeUDPListener bool   `json:"native_udp_listener"`
		} `json:"transport"`
	}
	decodeJSONFixture(t, filepath.Join("..", "..", "test", "v2lab", "restricted", "manifest.json"), &spikeManifest)
	if spikeManifest.Mihomo.Version != RestrictedProviderVersion || spikeManifest.Mihomo.Asset != RestrictedProviderAsset ||
		spikeManifest.Mihomo.SHA256 != RestrictedProviderSHA256 || spikeManifest.Transport.Port != RestrictedTCPPort ||
		spikeManifest.Transport.Protocol != "tcp" || spikeManifest.Transport.Cipher != RestrictedCipher ||
		spikeManifest.Transport.ShadowTLSVersion != RestrictedShadowTLSVersion || !spikeManifest.Transport.StrictMode || spikeManifest.Transport.NativeUDPListener {
		t.Fatalf("production restricted constants drifted from spike manifest: %+v", spikeManifest)
	}
}

func restrictedGatewayFixture(t *testing.T) (model.State, restrictedMemoryCredentials) {
	t.Helper()
	state := standardGatewayState()
	state.Components.Components = append(state.Components.Components, restrictedComponentPin())
	credentials := restrictedMemoryCredentials{
		GatewayRestrictedCredentialRef: restrictedGatewaySecretBytes(t, 0x11, 0x12),
	}
	for index, standard := range append([]model.Transport(nil), state.Transports...) {
		ref, err := model.NewSecretRef("restricted-user", fmt.Sprintf("%s-g%d", standard.OwnerID, standard.CredentialGeneration))
		if err != nil {
			t.Fatal(err)
		}
		state.Transports = append(state.Transports, restrictedTransportFixture(
			standard.OwnerKind, standard.OwnerID, model.TransportStandby, standard.CredentialGeneration, "www.microsoft.com",
		))
		state.Transports[len(state.Transports)-1].CredentialRef = ref
		credentials[ref] = restrictedIdentitySecretBytes(t, byte(index+1))
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("restricted gateway fixture: %v", err)
	}
	return state, credentials
}

func restrictedNodeFixture() model.Node {
	return model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: "20000000-0000-4000-8000-000000000004", Name: "private-4",
		Lifecycle: model.LifecycleActive, OverlayIPv4: "10.67.0.4", CredentialGeneration: 4,
		AssignedPresets: []string{}, ActiveTransport: model.TransportRestricted, IdempotencyRecords: []model.IdempotencyRecord{},
		CreatedAt: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC),
	}
}

func restrictedTransportFixture(kind model.TargetKind, id string, state model.TransportState, generation uint64, handshakeHost string) model.Transport {
	reference, _ := model.NewSecretRef("restricted-user", fmt.Sprintf("%s-g%d", id, generation))
	return model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: kind, OwnerID: id, Kind: model.TransportRestricted,
		State: state, Provider: RestrictedProviderName, Protocol: model.ProtocolTCP, Port: RestrictedTCPPort,
		CredentialGeneration: generation, CredentialRef: reference, HandshakeHost: handshakeHost, ConfigHash: strings.Repeat("b", 64),
	}
}

func restrictedComponentPin() model.ComponentPin {
	return model.ComponentPin{
		Name: RestrictedProviderName, Version: RestrictedProviderVersion, Source: "vpnctl-release-bundle", Bundled: true,
		SHA256: RestrictedProviderSHA256,
		Capabilities: []string{
			"tun-routing", "redir-host-split-dns", "shadowsocks-2022-blake3-aes-256-gcm", "shadowtls-v3-strict", "uot-v2",
		},
	}
}

func restrictedGatewaySecretBytes(t *testing.T, serverByte, bootstrapByte byte) []byte {
	t.Helper()
	encoded, err := encodeRestrictedSecret(restrictedGatewaySecret{
		SchemaVersion: restrictedSecretSchemaVersion, ShadowsocksPassword: restrictedServerPassword(serverByte),
		BootstrapShadowTLSPassword: strings.Repeat(fmt.Sprintf("%02x", bootstrapByte), restrictedSymmetricKeyByteCount),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func restrictedIdentitySecretBytes(t *testing.T, value byte) []byte {
	t.Helper()
	encoded, err := encodeRestrictedSecret(restrictedIdentitySecret{
		SchemaVersion:     restrictedSecretSchemaVersion,
		ShadowTLSPassword: strings.Repeat(fmt.Sprintf("%02x", value), restrictedSymmetricKeyByteCount),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func restrictedServerPassword(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, restrictedSymmetricKeyByteCount))
}

func decodeJSONFixture(t *testing.T, path string, destination any) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, destination); err != nil {
		t.Fatal(err)
	}
}

type restrictedMemoryCredentials map[model.SecretRef][]byte

func (credentials restrictedMemoryCredentials) Get(reference model.SecretRef) ([]byte, error) {
	value, found := credentials[reference]
	if !found {
		return nil, store.ErrSecretNotFound
	}
	return append([]byte(nil), value...), nil
}
