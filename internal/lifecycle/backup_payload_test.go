package lifecycle

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	backupAllowlistGatewayID = "94000000-0000-4000-8000-000000000001"
	backupAllowlistNodeID    = "94000000-0000-4000-8000-000000000002"
	backupAllowlistClientID  = "94000000-0000-4000-8000-000000000003"
)

func TestGatewayBackupStructuralAllowlistIncludesPortableMaterialAndExcludesCanaries(t *testing.T) {
	fixture := newBackupAllowlistFixture(t)
	backupper, err := newGatewayBackupper(GatewayBackupRuntime{
		State: fixture.state, Payloads: fixture.source, BackupsDir: fixture.paths.BackupsDir,
		Now:     func() time.Time { return fixture.now.Add(time.Minute) },
		NewUUID: func() (string, error) { return "94000000-0000-4000-8000-000000000020", nil },
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x71}, 256)),
	}, fastBackupArchiveCodec())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := backupper.Plan(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := backupper.Apply(context.Background(), plan, []byte("allowlist-test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := os.ReadFile(result.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, files := decryptGatewayBackupFiles(t, encrypted, []byte("allowlist-test-passphrase"))

	expected := []string{
		"config/presets.d/telegram.yaml",
		"exports/clients/.metadata/" + backupAllowlistClientID + ".clash.json",
		"exports/clients/iphone.clash.yaml",
		"exports/gateway.crt",
		"state/state.json",
	}
	references, err := gatewayBackupSecretReferences(plan.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range references {
		kind, id, _ := reference.Parts()
		expected = append(expected, path.Join("secrets", kind, id))
	}
	sort.Strings(expected)
	got := make([]string, 0, len(files)-1)
	for name := range files {
		if name != "manifest.json" {
			got = append(got, name)
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("backup payload paths\n got: %q\nwant: %q", got, expected)
	}
	if manifest.StateGeneration != plan.ExpectedStateGeneration || len(manifest.Entries) != len(expected) {
		t.Fatalf("backup manifest = %+v", manifest)
	}
	for index, entry := range manifest.Entries {
		if entry.Path != expected[index] {
			t.Fatalf("manifest entry %d path = %q, want %q", index, entry.Path, expected[index])
		}
		content := files[entry.Path]
		digest := sha256.Sum256(content)
		if entry.SizeBytes != int64(len(content)) || entry.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("manifest entry %s does not bind payload content", entry.Path)
		}
	}

	plaintext := bytes.Join(mapBackupFileValues(files), nil)
	for _, canary := range fixture.excludedCanaries {
		if bytes.Contains(plaintext, canary.content) {
			t.Fatalf("decrypted gateway backup contains excluded %s canary bytes", canary.name)
		}
		if _, found := files[canary.archivePath]; found {
			t.Fatalf("decrypted gateway backup contains excluded path %s", canary.archivePath)
		}
	}
	if !bytes.Equal(files["secrets/restricted-user/"+backupAllowlistNodeID+"-g1"], fixture.includedNodeShared) ||
		!bytes.Equal(files["secrets/tunnel-token/"+backupAllowlistNodeID+"-g1"], fixture.includedTunnelShared) {
		t.Fatal("gateway-side node trust material is missing from backup")
	}
}

func TestGatewayBackupStructuralAllowlistRejectsNodePrivateReferenceAndSecretSubstitution(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*model.State)
		want   string
	}{
		{
			name: "node private key reference",
			mutate: func(state *model.State) {
				for index := range state.Certificates {
					if state.Certificates[index].OwnerKind == "node" {
						state.Certificates[index].PrivateKeyRef = model.SecretRef("control-key:" + backupAllowlistNodeID + "-g1")
					}
				}
			},
			want: "refuse node-owned private key",
		},
		{
			name: "application secret substituted for client key",
			mutate: func(state *model.State) {
				for index := range state.Transports {
					if state.Transports[index].OwnerKind == model.TargetClient && state.Transports[index].Kind == model.TransportStandard {
						state.Transports[index].CredentialRef = "application-data:database"
					}
				}
			},
			want: "outside the structural backup contract",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newBackupAllowlistFixture(t)
			state := fixture.state.state
			test.mutate(&state)
			if err := state.Validate(); err != nil {
				t.Fatalf("fixture mutation must remain model-valid to exercise the backup boundary: %v", err)
			}
			if _, err := fixture.source.Prepare(context.Background(), state); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("structural allowlist error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestGatewayBackupStructuralAllowlistRejectsUnsafeOrChangedSelectedFiles(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		fixture := newBackupAllowlistFixture(t)
		profile := filepath.Join(fixture.paths.ClientExportsDir, "iphone.clash.yaml")
		target := filepath.Join(fixture.paths.Root, "foreign-profile")
		if err := os.WriteFile(target, []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(profile); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, profile); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.source.Prepare(context.Background(), fixture.state.state); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("symlinked selected file error = %v", err)
		}
	})

	t.Run("content drift", func(t *testing.T) {
		fixture := newBackupAllowlistFixture(t)
		payload, err := fixture.source.Prepare(context.Background(), fixture.state.state)
		if err != nil {
			t.Fatal(err)
		}
		defer payload.Close()
		preset := filepath.Join(fixture.paths.PresetsDir, "telegram.yaml")
		if err := os.WriteFile(preset, []byte("changed after planning\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := payload.WriteTo(context.Background(), io.Discard); err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("changed selected file error = %v", err)
		}
	})

	t.Run("new managed path", func(t *testing.T) {
		fixture := newBackupAllowlistFixture(t)
		payload, err := fixture.source.Prepare(context.Background(), fixture.state.state)
		if err != nil {
			t.Fatal(err)
		}
		defer payload.Close()
		appeared := filepath.Join(fixture.paths.ClientExportsDir, "iphone.wireguard.conf")
		if err := os.WriteFile(appeared, []byte("appeared"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := payload.WriteTo(context.Background(), io.Discard); err == nil || !strings.Contains(err.Error(), "appeared after planning") {
			t.Fatalf("appeared selected file error = %v", err)
		}
	})
}

func TestGatewayBackupStructuralAllowlistDoesNotRequireRevokedIdentitySecrets(t *testing.T) {
	fixture := newBackupAllowlistFixture(t)
	state := fixture.state.state
	revokedAt := fixture.now.Add(time.Minute)
	var err error
	state.Nodes[0], err = state.Nodes[0].Revoke(revokedAt)
	if err != nil {
		t.Fatal(err)
	}
	state.Clients[0], err = state.Clients[0].Revoke(revokedAt)
	if err != nil {
		t.Fatal(err)
	}
	for index := range state.Transports {
		state.Transports[index].State = model.TransportDisabled
	}
	removed := []model.SecretRef{
		model.SecretRef("control-cert:" + backupAllowlistNodeID + "-g1"),
		model.SecretRef("restricted-user:" + backupAllowlistNodeID + "-g1"),
		model.SecretRef("tunnel-token:" + backupAllowlistNodeID + "-g1"),
		model.SecretRef("wireguard-key:" + backupAllowlistClientID + "-standard-g1"),
		model.SecretRef("restricted-user:" + backupAllowlistClientID + "-g1"),
	}
	for _, reference := range removed {
		deleted, deleteErr := fixture.secrets.Delete(reference)
		if deleteErr != nil || !deleted {
			t.Fatalf("delete revoked identity secret %s: deleted=%t error=%v", reference, deleted, deleteErr)
		}
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("revoked fixture state: %v", err)
	}
	payload, err := fixture.source.Prepare(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer payload.Close()
	var plaintext bytes.Buffer
	if err := payload.WriteTo(context.Background(), &plaintext); err != nil {
		t.Fatal(err)
	}
	_, files := readGatewayBackupTar(t, plaintext.Bytes())
	for _, reference := range removed {
		kind, id, _ := reference.Parts()
		archivePath := path.Join("secrets", kind, id)
		if _, found := files[archivePath]; found {
			t.Fatalf("revoked identity secret remains in backup: %s", archivePath)
		}
	}
}

type backupAllowlistCanary struct {
	name        string
	archivePath string
	content     []byte
}

type backupAllowlistFixture struct {
	paths                store.Paths
	state                *memoryUpdateState
	source               *GatewayBackupPayloadSource
	secrets              *store.SecretStore
	now                  time.Time
	includedNodeShared   []byte
	includedTunnelShared []byte
	excludedCanaries     []backupAllowlistCanary
}

func newBackupAllowlistFixture(t *testing.T) backupAllowlistFixture {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		paths.StateDir, paths.PresetsDir, paths.ExportsDir, paths.ClientExportsDir,
		filepath.Join(paths.ClientExportsDir, ".metadata"), paths.BackupsDir,
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 4, 16, 0, 0, 0, time.UTC)
	state := backupAllowlistState(t, now)
	references, err := gatewayBackupSecretReferences(state)
	if err != nil {
		t.Fatal(err)
	}
	includedNodeShared := []byte("INCLUDED-GATEWAY-NODE-RESTRICTED-SHARED-MATERIAL")
	includedTunnelShared := []byte("INCLUDED-GATEWAY-NODE-TUNNEL-SHARED-MATERIAL")
	for _, reference := range references {
		content := []byte("allowlisted-secret:" + reference.String())
		if reference == model.SecretRef("restricted-user:"+backupAllowlistNodeID+"-g1") {
			content = includedNodeShared
		}
		if reference == model.SecretRef("tunnel-token:"+backupAllowlistNodeID+"-g1") {
			content = includedTunnelShared
		}
		if err := secrets.PutIfAbsent(reference, content); err != nil {
			t.Fatalf("store %s: %v", reference, err)
		}
	}
	excluded := []backupAllowlistCanary{
		{name: "node control private key", archivePath: "secrets/control-key/" + backupAllowlistNodeID + "-g1", content: []byte("EXCLUDED-NODE-CONTROL-PRIVATE-CANARY")},
		{name: "node WireGuard private key", archivePath: "secrets/wireguard-key/" + backupAllowlistNodeID + "-standard-g1", content: []byte("EXCLUDED-NODE-WIREGUARD-PRIVATE-CANARY")},
		{name: "application secret", archivePath: "secrets/application-data/database", content: []byte("EXCLUDED-APPLICATION-SECRET-CANARY")},
		{name: "application export", archivePath: "exports/clients/application.sqlite", content: []byte("EXCLUDED-APPLICATION-EXPORT-CANARY")},
		{name: "non-preset config", archivePath: "config/presets.d/application.notes", content: []byte("EXCLUDED-PRESET-ADJACENT-APPLICATION-CANARY")},
		{name: "application state", archivePath: "state/application/data.db", content: []byte("EXCLUDED-APPLICATION-STATE-CANARY")},
	}
	for _, canary := range excluded[:3] {
		reference := model.SecretRef(strings.TrimPrefix(canary.archivePath, "secrets/"))
		reference = model.SecretRef(strings.Replace(reference.String(), "/", ":", 1))
		if err := secrets.PutIfAbsent(reference, canary.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(paths.PresetsDir, "telegram.yaml"), []byte("schema_version: 1\nname: telegram\ninclude: []\nexclude: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.PresetsDir, "application.notes"), excluded[4].content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.ExportsDir, ingress.PublicCertificateExportName), []byte("public certificate export\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.ClientExportsDir, "iphone.clash.yaml"), []byte("client profile secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.ClientExportsDir, ".metadata", backupAllowlistClientID+".clash.json"), []byte("client export metadata\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.ClientExportsDir, "application.sqlite"), excluded[3].content, 0o600); err != nil {
		t.Fatal(err)
	}
	applicationDirectory := filepath.Join(paths.StateDir, "application")
	if err := os.MkdirAll(applicationDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(applicationDirectory, "data.db"), excluded[5].content, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewGatewayBackupPayloadSource(paths, secrets)
	if err != nil {
		t.Fatal(err)
	}
	return backupAllowlistFixture{
		paths: paths, state: &memoryUpdateState{state: state}, source: source, secrets: secrets, now: now,
		includedNodeShared: append([]byte(nil), includedNodeShared...), includedTunnelShared: append([]byte(nil), includedTunnelShared...),
		excludedCanaries: excluded,
	}
}

func backupAllowlistState(t *testing.T, now time.Time) model.State {
	t.Helper()
	state := initialGatewayState(backupAllowlistGatewayID, now, linuxplatform.GatewayNetworkPlan{
		PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
	}, 22, gatewayTestManifest(), gatewayTestHandshakeHost())
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	state.EnrollmentIdentity = &model.EnrollmentIdentity{
		SchemaVersion: model.ResourceSchemaVersion, Algorithm: "Ed25519", Fingerprint: fingerprint,
		PublicKeyRef: control.EnrollmentPublicKeyRef, PrivateKeyRef: control.EnrollmentPrivateKeyRef, Generation: 1, CreatedAt: now,
	}
	state.Nodes = append(state.Nodes, model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: backupAllowlistNodeID, Name: "private-node", Lifecycle: model.LifecycleActive,
		OverlayIPv4: "10.67.0.2", CredentialGeneration: 1, ControlProtocol: "1.0", AssignedPresets: []string{},
		ActiveTransport: model.TransportRestricted, IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: now,
	})
	state.Clients = append(state.Clients, model.Client{
		SchemaVersion: model.ResourceSchemaVersion, ID: backupAllowlistClientID, Name: "iphone", Platform: "ios",
		Lifecycle: model.LifecycleActive, OverlayIPv4: "10.66.0.2", CredentialGeneration: 1,
		AssignedPresets: []string{}, ActiveTransport: model.TransportStandard, CreatedAt: now,
	})
	hash := strings.Repeat("b", 64)
	hostname := state.HandshakeHost.Hostname
	state.Transports = append(state.Transports,
		model.Transport{SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: backupAllowlistNodeID, Kind: model.TransportStandard, State: model.TransportStandby, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: 51820, CredentialGeneration: 1, CredentialRef: model.SecretRef("wireguard-peer:" + backupAllowlistNodeID + "-g1"), PublicKey: "node-public-key", ConfigHash: hash},
		model.Transport{SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: backupAllowlistNodeID, Kind: model.TransportRestricted, State: model.TransportActive, Provider: "mihomo", Protocol: model.ProtocolTCP, Port: 8443, CredentialGeneration: 1, CredentialRef: model.SecretRef("restricted-user:" + backupAllowlistNodeID + "-g1"), HandshakeHost: hostname, ConfigHash: hash},
		model.Transport{SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetClient, OwnerID: backupAllowlistClientID, Kind: model.TransportStandard, State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: 51820, CredentialGeneration: 1, CredentialRef: model.SecretRef("wireguard-key:" + backupAllowlistClientID + "-standard-g1"), PublicKey: "client-public-key", ConfigHash: hash},
		model.Transport{SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetClient, OwnerID: backupAllowlistClientID, Kind: model.TransportRestricted, State: model.TransportStandby, Provider: "mihomo", Protocol: model.ProtocolTCP, Port: 8443, CredentialGeneration: 1, CredentialRef: model.SecretRef("restricted-user:" + backupAllowlistClientID + "-g1"), HandshakeHost: hostname, ConfigHash: hash},
	)
	state.Certificates = append(state.Certificates,
		backupAllowlistCertificate("94000000-0000-4000-8000-000000000010", model.CertificateControlCA, "host", backupAllowlistGatewayID, control.ControlCACertificateRef, control.ControlCAPrivateKeyRef, now, nil),
		backupAllowlistCertificate("94000000-0000-4000-8000-000000000011", model.CertificateControlServer, "host", backupAllowlistGatewayID, control.GatewayControlCertificateRef, control.GatewayControlPrivateKeyRef, now, []string{"IP:10.67.0.1"}),
		backupAllowlistCertificate("94000000-0000-4000-8000-000000000012", model.CertificatePublicIngress, "host", backupAllowlistGatewayID, ingress.PublicCertificateRef, ingress.PublicCertificatePrivateKeyRef, now, []string{"IP:203.0.113.10"}),
		backupAllowlistCertificate("94000000-0000-4000-8000-000000000013", model.CertificateControlNode, "node", backupAllowlistNodeID, "control-cert:"+backupAllowlistNodeID+"-g1", "", now, []string{"urn:vpnctl:node:" + backupAllowlistNodeID}),
	)
	state.Certificates[len(state.Certificates)-1].CredentialGeneration = 1
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	return state
}

func backupAllowlistCertificate(id string, kind model.CertificateKind, ownerKind, ownerID, certificateRef string, privateKeyRef model.SecretRef, now time.Time, sans []string) model.Certificate {
	return model.Certificate{
		SchemaVersion: model.ResourceSchemaVersion, ID: id, Kind: kind, OwnerKind: ownerKind, OwnerID: ownerID,
		Fingerprint: "sha256:" + strings.Repeat("c", 64), SerialHex: "01", Subject: "vpnctl backup allowlist test",
		SANs: append([]string{}, sans...), NotBefore: now, NotAfter: now.AddDate(5, 0, 0), WarningDays: 180,
		Generation: 1, CertificateRef: certificateRef, PrivateKeyRef: privateKeyRef,
	}
}

func decryptGatewayBackupFiles(t *testing.T, encrypted, passphrase []byte) (backupPayloadManifest, map[string][]byte) {
	t.Helper()
	var plaintext bytes.Buffer
	if err := fastBackupArchiveCodec().decrypt(bytes.NewReader(encrypted), &plaintext, passphrase); err != nil {
		t.Fatal(err)
	}
	return readGatewayBackupTar(t, plaintext.Bytes())
}

func readGatewayBackupTar(t *testing.T, plaintext []byte) (backupPayloadManifest, map[string][]byte) {
	t.Helper()
	tape := tar.NewReader(bytes.NewReader(plaintext))
	files := map[string][]byte{}
	for {
		header, err := tape.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(tape)
		if err != nil {
			t.Fatal(err)
		}
		if _, duplicate := files[header.Name]; duplicate {
			t.Fatalf("duplicate backup payload path %s", header.Name)
		}
		files[header.Name] = content
	}
	var manifest backupPayloadManifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest, files
}

func mapBackupFileValues(files map[string][]byte) [][]byte {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	values := make([][]byte, 0, len(names))
	for _, name := range names {
		values = append(values, files[name])
	}
	return values
}
