package transport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestGatewayStandardCredentialIsCreatedOnceAndNeverReturnedPrivate(t *testing.T) {
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
	runner := &standardKeyRunner{privateKey: standardTestKey(1), publicKey: standardTestKey(2)}
	first, err := EnsureGatewayStandardCredential(context.Background(), secrets, runner)
	if err != nil {
		t.Fatalf("EnsureGatewayStandardCredential(first) error = %v", err)
	}
	second, err := EnsureGatewayStandardCredential(context.Background(), secrets, runner)
	if err != nil {
		t.Fatalf("EnsureGatewayStandardCredential(second) error = %v", err)
	}
	if first != second || first.Reference != GatewayStandardCredentialRef || first.Generation != 1 || first.PublicKey != runner.publicKey {
		t.Fatalf("credentials = %#v / %#v", first, second)
	}
	if runner.generateCalls != 1 {
		t.Fatalf("wg genkey calls = %d, want one", runner.generateCalls)
	}
	stored, err := secrets.Get(GatewayStandardCredentialRef)
	if err != nil || string(stored) != runner.privateKey {
		t.Fatalf("stored private key = %q, %v", stored, err)
	}
	kind, id, _ := GatewayStandardCredentialRef.Parts()
	info, err := os.Stat(filepath.Join(paths.SecretsDir, kind, id))
	if err != nil || info.Mode().Perm() != store.SecretFileMode {
		t.Fatalf("credential file = %v, %v", info, err)
	}
	encoded, err := json.Marshal(first)
	if err != nil || strings.Contains(string(encoded), runner.privateKey) {
		t.Fatalf("public credential JSON leaked private material: %s, %v", encoded, err)
	}
}

func TestRenderGatewayStandardConfigIncludesFiveClientsAndTwoNodesDeterministically(t *testing.T) {
	t.Parallel()
	state := standardGatewayState()
	credentials := standardMemoryCredentials{GatewayStandardCredentialRef: []byte(standardTestKey(90))}
	runner := &standardKeyRunner{publicKey: standardTestKey(91)}
	request := GatewayStandardRenderRequest{
		State: state, CredentialRef: GatewayStandardCredentialRef, Credentials: credentials, KeyRunner: runner,
	}
	first, err := RenderGatewayStandardConfig(context.Background(), request)
	if err != nil {
		t.Fatalf("RenderGatewayStandardConfig() error = %v", err)
	}
	second, err := RenderGatewayStandardConfig(context.Background(), request)
	if err != nil || string(first.Bytes()) != string(second.Bytes()) {
		t.Fatalf("second render differs: %v", err)
	}
	if first.GatewayPublicKey() != runner.publicKey {
		t.Fatalf("gateway public key = %q", first.GatewayPublicKey())
	}
	if got := first.LocalAddresses(); fmt.Sprint(got) != "[10.66.0.1/24 10.67.0.1/24]" {
		t.Fatalf("local addresses = %v", got)
	}
	peers := first.Peers()
	if len(peers) != 7 {
		t.Fatalf("peer count = %d, want 7", len(peers))
	}
	for index := 0; index < 5; index++ {
		if peers[index].Identity.OwnerKind != model.TargetClient || peers[index].AllowedIP != fmt.Sprintf("10.66.0.%d/32", index+2) {
			t.Fatalf("client peer %d = %#v", index, peers[index])
		}
	}
	for index := 5; index < 7; index++ {
		if peers[index].Identity.OwnerKind != model.TargetNode || peers[index].AllowedIP != fmt.Sprintf("10.67.0.%d/32", index-3) {
			t.Fatalf("node peer %d = %#v", index, peers[index])
		}
	}
	config := string(first.Bytes())
	for _, required := range []string{
		"Address = 10.66.0.1/24, 10.67.0.1/24", "ListenPort = 51820", "Table = off", "SaveConfig = false",
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("config lacks %q:\n%s", required, config)
		}
	}
	if strings.Contains(config, "iptables") || strings.Contains(config, "PostUp") || strings.Count(config, "[Peer]") != 7 {
		t.Fatalf("gateway config contains policy commands or wrong peers:\n%s", config)
	}
	copyBytes := first.Bytes()
	copyBytes[0] = 'x'
	if first.Bytes()[0] != '[' {
		t.Fatal("artifact bytes are not defensive copies")
	}
}

func TestRenderGatewayStandardConfigRejectsSharedPeerCredential(t *testing.T) {
	t.Parallel()
	state := standardGatewayState()
	state.Transports[1].PublicKey = state.Transports[0].PublicKey
	_, err := RenderGatewayStandardConfig(context.Background(), GatewayStandardRenderRequest{
		State: state, CredentialRef: GatewayStandardCredentialRef,
		Credentials: standardMemoryCredentials{GatewayStandardCredentialRef: []byte(standardTestKey(90))},
		KeyRunner:   &standardKeyRunner{publicKey: standardTestKey(91)},
	})
	if err == nil || !strings.Contains(err.Error(), "shared") {
		t.Fatalf("shared public key error = %v", err)
	}
}

func TestRenderNodeStandardConfigUsesPinnedEndpointAndOnlyOverlayBootstrapRoute(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	node := model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: "20000000-0000-4000-8000-000000000001", Name: "private-1",
		Lifecycle: model.LifecycleActive, OverlayIPv4: "10.67.0.2", CredentialGeneration: 4,
		AssignedPresets: []string{}, ActiveTransport: model.TransportStandard, IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: created,
	}
	privateKey := standardTestKey(70)
	publicKey := standardTestKey(71)
	transport := standardTransportFixture(model.TargetNode, node.ID, model.TransportActive, publicKey, 4)
	artifact, err := RenderNodeStandardConfig(context.Background(), NodeStandardRenderRequest{
		Transport: transport, Node: node, NodeCIDR: model.DefaultNodeCIDR,
		GatewayPublicIPv4: "203.0.113.10", GatewayPublicKey: standardTestKey(80), PrivateKey: privateKey,
		KeyRunner: &standardKeyRunner{privateKey: privateKey, publicKey: publicKey},
	})
	if err != nil {
		t.Fatalf("RenderNodeStandardConfig() error = %v", err)
	}
	if err := artifact.Descriptor().Validate(); err != nil {
		t.Fatalf("candidate descriptor: %v", err)
	}
	config := string(artifact.Bytes())
	for _, required := range []string{
		"Address = 10.67.0.2/32", "Table = off", "PostUp = ip -4 route add 10.67.0.1/32 dev %i proto static",
		"Endpoint = 203.0.113.10:51820", "AllowedIPs = 0.0.0.0/0", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(config, required) {
			t.Fatalf("node config lacks %q:\n%s", required, config)
		}
	}
	if strings.Contains(config, "default") || strings.Contains(config, "iptables") || strings.Contains(config, "10.66.0.0/24") {
		t.Fatalf("node config owns selected/default/firewall policy:\n%s", config)
	}
}

type standardMemoryCredentials map[model.SecretRef][]byte

func (credentials standardMemoryCredentials) Get(reference model.SecretRef) ([]byte, error) {
	value, found := credentials[reference]
	if !found {
		return nil, store.ErrSecretNotFound
	}
	return append([]byte(nil), value...), nil
}

type standardKeyRunner struct {
	privateKey    string
	publicKey     string
	generateCalls int
}

func (runner *standardKeyRunner) Run(_ context.Context, name string, arguments []string, stdin string) (string, error) {
	if name != "wg" {
		return "", fmt.Errorf("unexpected command %s", name)
	}
	switch strings.Join(arguments, " ") {
	case "genkey":
		runner.generateCalls++
		return runner.privateKey + "\n", nil
	case "pubkey":
		if strings.TrimSpace(stdin) == "" {
			return "", errors.New("missing private key")
		}
		return runner.publicKey + "\n", nil
	default:
		return "", fmt.Errorf("unexpected wg arguments %v", arguments)
	}
}

func standardGatewayState() model.State {
	created := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	state := model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 8,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: "10000000-0000-4000-8000-000000000001", Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: created,
			PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", SSHPort: 22,
			ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
		},
		Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports: []model.Transport{}, Exposes: []model.Expose{}, Certificates: []model.Certificate{},
		Operations: []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{}, Invites: []model.Invite{},
		Components: standardComponentManifest(),
	}
	for index := 0; index < 5; index++ {
		id := fmt.Sprintf("30000000-0000-4000-8000-%012d", index+1)
		state.Clients = append(state.Clients, model.Client{
			SchemaVersion: model.ResourceSchemaVersion, ID: id, Name: fmt.Sprintf("client-%d", index+1), Platform: "test",
			Lifecycle: model.LifecycleActive, OverlayIPv4: fmt.Sprintf("10.66.0.%d", index+2), CredentialGeneration: 1,
			AssignedPresets: []string{}, ActiveTransport: model.TransportStandard, CreatedAt: created,
		})
		state.Transports = append(state.Transports, standardTransportFixture(model.TargetClient, id, model.TransportActive, standardTestKey(byte(index+10)), 1))
	}
	for index := 0; index < 2; index++ {
		id := fmt.Sprintf("20000000-0000-4000-8000-%012d", index+1)
		state.Nodes = append(state.Nodes, model.Node{
			SchemaVersion: model.ResourceSchemaVersion, ID: id, Name: fmt.Sprintf("node-%d", index+1),
			Lifecycle: model.LifecycleActive, OverlayIPv4: fmt.Sprintf("10.67.0.%d", index+2), CredentialGeneration: 1,
			AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
			IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: created,
		})
		state.Transports = append(state.Transports, standardTransportFixture(model.TargetNode, id, model.TransportActive, standardTestKey(byte(index+30)), 1))
	}
	return state
}

func standardTransportFixture(kind model.TargetKind, id string, state model.TransportState, publicKey string, generation uint64) model.Transport {
	return model.Transport{
		SchemaVersion: model.ResourceSchemaVersion, OwnerKind: kind, OwnerID: id, Kind: model.TransportStandard,
		State: state, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: StandardUDPPort,
		CredentialGeneration: generation, CredentialRef: model.SecretRef("wireguard-key:" + strings.ReplaceAll(id, "-", "") + "-g1"),
		PublicKey: publicKey, ConfigHash: strings.Repeat("a", 64),
	}
}

func standardComponentManifest() model.ComponentManifest {
	return model.ComponentManifest{
		SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0-dev",
		ControlProtocols: []string{"1.0"}, StateSchemaMinimum: 1, StateSchemaMaximum: 1,
		TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1, MigrationReversible: true,
		Components: []model.ComponentPin{{
			Name: "wireguard-tools", Version: "ubuntu-24.04", Source: "ubuntu", Bundled: false, Capabilities: []string{"standard-transport"},
		}},
	}
}

func standardTestKey(value byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{value}), 32)))
}
