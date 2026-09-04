package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
	"golang.org/x/crypto/curve25519"
)

const (
	fixtureGatewayPrivateKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	fixtureGatewayIPv4       = "192.0.2.1"
	fixtureSelectedTarget    = "198.51.100.10/32"
)

type fixtureManifest struct {
	SchemaVersion    int                       `json:"schema_version"`
	GatewayPublicKey string                    `json:"gateway_public_key"`
	GatewayKeyFile   string                    `json:"gateway_key_file"`
	Profiles         map[string]fixtureProfile `json:"profiles"`
}

type fixtureProfile struct {
	ClientID       string   `json:"client_id"`
	ClientName     string   `json:"client_name"`
	OverlayIPv4    string   `json:"overlay_ipv4"`
	PublicKey      string   `json:"public_key"`
	AssignedPreset []string `json:"assigned_presets"`
	Format         string   `json:"format"`
	Path           string   `json:"path"`
	SHA256         string   `json:"sha256"`
	SCPHint        string   `json:"scp_hint"`
}

type fixtureCredentials struct {
	standardCount   byte
	restrictedCount byte
}

func (credentials *fixtureCredentials) GenerateClientCredential(ctx context.Context) (wireguard.KeyPair, error) {
	if err := ctx.Err(); err != nil {
		return wireguard.KeyPair{}, err
	}
	credentials.standardCount++
	private := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{credentials.standardCount + 1}, 32))
	public, err := wireGuardPublicKey(private)
	if err != nil {
		return wireguard.KeyPair{}, err
	}
	return wireguard.KeyPair{PrivateKey: private, PublicKey: public}, nil
}

func (credentials *fixtureCredentials) GenerateRestrictedClientCredential(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	credentials.restrictedCount++
	return restricted.GenerateIdentitySecret(bytes.NewReader(bytes.Repeat([]byte{credentials.restrictedCount + 0x40}, restricted.SymmetricKeyByteCount)))
}

func main() {
	root := flag.String("root", "", "absolute output root")
	flag.Parse()
	if flag.NArg() != 0 || *root == "" {
		fmt.Fprintln(os.Stderr, "usage: generate --root <absolute-directory>")
		os.Exit(2)
	}
	if err := generateFixture(*root); err != nil {
		fmt.Fprintf(os.Stderr, "generate personal-client fixture: %v\n", err)
		os.Exit(1)
	}
}

func generateFixture(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return fmt.Errorf("root must be an absolute, clean, non-root path")
	}
	paths, err := store.NewPaths(root)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.MkdirAll(paths.PresetsDir, 0o755); err != nil {
		return fmt.Errorf("create preset directory: %w", err)
	}

	now := time.Date(2026, time.September, 4, 20, 0, 0, 0, time.UTC)
	presetSource := []byte("schema_version: 1\nname: selected-e2e\ninclude:\n  - type: ip-cidr\n    value: " + fixtureSelectedTarget + "\nexclude: []\n")
	preset, err := routing.CompilePresetSource(presetSource, now)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(paths.PresetsDir, "selected-e2e.yaml"), presetSource, 0o644); err != nil {
		return fmt.Errorf("write preset source: %w", err)
	}

	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return err
	}
	initial := personalGatewayState(now, preset)
	if err := stateStore.Save(0, initial); err != nil {
		return fmt.Errorf("save initial gateway state: %w", err)
	}
	secretStore, err := store.NewSecretStore(paths)
	if err != nil {
		return err
	}
	gatewaySecret, err := restricted.NewGatewaySecret(bytes.NewReader(bytes.Repeat([]byte{0x31}, restricted.SymmetricKeyByteCount*2)))
	if err != nil {
		return err
	}
	encodedGatewaySecret, err := restricted.EncodeSecret(gatewaySecret)
	if err != nil {
		return err
	}
	if err := secretStore.PutIfAbsent(restricted.GatewayCredentialRef, encodedGatewaySecret); err != nil {
		return fmt.Errorf("store restricted gateway fixture: %w", err)
	}

	credentials := &fixtureCredentials{}
	ids := []string{
		"81000000-0000-4000-8000-000000000101",
		"81000000-0000-4000-8000-000000000102",
	}
	nextID := func() (string, error) {
		if len(ids) == 0 {
			return "", fmt.Errorf("fixture exhausted client identities")
		}
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
	manager, err := routing.NewClientManager(paths, stateStore, secretStore, routing.ClientManagerRuntime{
		Now: func() time.Time { return now }, NewUUID: nextID, Credentials: credentials,
	})
	if err != nil {
		return err
	}
	iphone, err := addFixtureClient(manager, "iphone", []string{"selected-e2e"})
	if err != nil {
		return err
	}
	steamdeck, err := addFixtureClient(manager, "steamdeck", nil)
	if err != nil {
		return err
	}
	if iphone.Client.OverlayIPv4 != "10.66.0.2" || steamdeck.Client.OverlayIPv4 != "10.66.0.3" ||
		!equalStrings(iphone.Client.AssignedPresets, []string{"selected-e2e"}) || len(steamdeck.Client.AssignedPresets) != 0 {
		return fmt.Errorf("client allocation or explicit assignment semantics changed")
	}

	gatewayPublicKey, err := wireGuardPublicKey(fixtureGatewayPrivateKey)
	if err != nil {
		return err
	}
	exporter, err := routing.NewClientExporter(paths, stateStore, secretStore)
	if err != nil {
		return err
	}
	clash, err := exporter.Export(routing.ClientExportRequest{
		ClientReference: iphone.Client.ID, Format: routing.ClientExportClash,
		GatewayPublicKey: gatewayPublicKey, ClashDNSMode: routing.ClashDNSPolicy,
		ClashDirectDNSServers: []string{"192.0.2.254"},
	})
	if err != nil {
		return fmt.Errorf("export selective Clash profile: %w", err)
	}
	fullTunnel, err := exporter.Export(routing.ClientExportRequest{
		ClientReference: steamdeck.Client.ID, Format: routing.ClientExportWireGuard,
		GatewayPublicKey: gatewayPublicKey,
	})
	if err != nil {
		return fmt.Errorf("export full-tunnel WireGuard profile: %w", err)
	}

	state, err := stateStore.Load()
	if err != nil {
		return err
	}
	manifest := fixtureManifest{
		SchemaVersion: 1, GatewayPublicKey: gatewayPublicKey, GatewayKeyFile: "gateway.key",
		Profiles: map[string]fixtureProfile{},
	}
	for key, values := range map[string]struct {
		client model.Client
		result routing.ClientExportResult
	}{
		"clash":     {client: findClient(state, iphone.Client.ID), result: clash},
		"wireguard": {client: findClient(state, steamdeck.Client.ID), result: fullTunnel},
	} {
		profile, err := fixtureProfileFromExport(values.client, state.Transports, values.result)
		if err != nil {
			return err
		}
		manifest.Profiles[key] = profile
	}
	if err := assertGeneratedProfiles(manifest); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, manifest.GatewayKeyFile), []byte(fixtureGatewayPrivateKey+"\n"), 0o600); err != nil {
		return fmt.Errorf("write gateway key fixture: %w", err)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(root, "fixture.json"), encoded, 0o600); err != nil {
		return fmt.Errorf("write fixture manifest: %w", err)
	}
	return nil
}

func personalGatewayState(now time.Time, preset model.Preset) model.State {
	handshake := model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1,
		CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: now,
	}
	dns := model.DNSUpstreamState{
		SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamGateway,
		IPv4: model.DefaultGatewayDNSUpstreams(),
	}
	return model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: "81000000-0000-4000-8000-000000000001",
			Role: model.RoleGateway, OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: now,
			PublicIPv4: fixtureGatewayIPv4, ExternalInterface: "eth0", SSHPort: 22,
			ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
		},
		HandshakeHost: &handshake, DNS: &dns,
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{preset},
		Policies: []model.Policy{}, Transports: []model.Transport{}, Exposes: []model.Expose{},
		Certificates: []model.Certificate{}, Operations: []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0-e2e",
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: model.StateSchemaVersion, StateSchemaMaximum: model.StateSchemaVersion,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1, MigrationReversible: true,
			Components: []model.ComponentPin{{
				Name: "vpnctl", Version: "v2.0.0-e2e", Source: "bundle:vpnctl", Bundled: true,
				SHA256: strings.Repeat("a", 64), Capabilities: []string{"cli", "controller"},
			}},
		},
	}
}

func addFixtureClient(manager *routing.ClientManager, name string, presets []string) (routing.ClientAddResult, error) {
	plan, err := manager.PlanAdd(routing.ClientAddRequest{Name: name, PresetNames: presets})
	if err != nil {
		return routing.ClientAddResult{}, fmt.Errorf("plan client %s: %w", name, err)
	}
	result, err := manager.CommitAdd(context.Background(), plan)
	if err != nil {
		return routing.ClientAddResult{}, fmt.Errorf("commit client %s: %w", name, err)
	}
	return result, nil
}

func fixtureProfileFromExport(client model.Client, transports []model.Transport, result routing.ClientExportResult) (fixtureProfile, error) {
	if client.ID == "" || result.ClientID != client.ID || !result.ManagedPath || result.FileMode != "0600" {
		return fixtureProfile{}, fmt.Errorf("managed export metadata is incomplete")
	}
	content, err := os.ReadFile(result.OutputPath)
	if err != nil {
		return fixtureProfile{}, err
	}
	info, err := os.Stat(result.OutputPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fixtureProfile{}, fmt.Errorf("profile %s is not a regular mode-0600 file", client.Name)
	}
	publicKey := ""
	for _, transport := range transports {
		if transport.OwnerKind == model.TargetClient && transport.OwnerID == client.ID && transport.Kind == model.TransportStandard {
			publicKey = transport.PublicKey
			break
		}
	}
	if publicKey == "" {
		return fixtureProfile{}, fmt.Errorf("profile %s has no standard public identity", client.Name)
	}
	digest := sha256.Sum256(content)
	return fixtureProfile{
		ClientID: client.ID, ClientName: client.Name, OverlayIPv4: client.OverlayIPv4,
		PublicKey: publicKey, AssignedPreset: append([]string(nil), client.AssignedPresets...),
		Format: string(result.Format), Path: result.OutputPath, SHA256: hex.EncodeToString(digest[:]), SCPHint: result.SCPHint,
	}, nil
}

func assertGeneratedProfiles(manifest fixtureManifest) error {
	clash := manifest.Profiles["clash"]
	wireGuard := manifest.Profiles["wireguard"]
	if clash.Format != string(routing.ClientExportClash) || wireGuard.Format != string(routing.ClientExportWireGuard) {
		return fmt.Errorf("fixture profile formats are incomplete")
	}
	for _, profile := range []fixtureProfile{clash, wireGuard} {
		if !strings.HasPrefix(profile.SCPHint, "scp root@"+fixtureGatewayIPv4+":") || strings.ContainsAny(profile.SCPHint, "\r\n") {
			return fmt.Errorf("profile %s has an unsafe or missing scp hint", profile.ClientName)
		}
	}
	clashContent, err := os.ReadFile(clash.Path)
	if err != nil {
		return err
	}
	for _, required := range []string{
		"IP-CIDR," + fixtureSelectedTarget + ",VPNCTL-GATEWAY", "MATCH,DIRECT", "type: select", "VPNCTL-STANDARD", "VPNCTL-RESTRICTED",
	} {
		if !bytes.Contains(clashContent, []byte(required)) {
			return fmt.Errorf("selective Clash profile is missing %q", required)
		}
	}
	wireGuardContent, err := os.ReadFile(wireGuard.Path)
	if err != nil {
		return err
	}
	if !bytes.Contains(wireGuardContent, []byte("AllowedIPs = 0.0.0.0/0")) {
		return fmt.Errorf("WireGuard profile is not full tunnel")
	}
	return nil
}

func findClient(state model.State, id string) model.Client {
	for _, client := range state.Clients {
		if client.ID == id {
			return client
		}
	}
	return model.Client{}
}

func wireGuardPublicKey(privateKey string) (string, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(privateKey)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("invalid WireGuard private key")
	}
	public, err := curve25519.X25519(decoded, curve25519.Basepoint)
	clear(decoded)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(public), nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
