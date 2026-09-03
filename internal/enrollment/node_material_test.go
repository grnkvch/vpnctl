package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	testNodeMaterialID  = "20000000-0000-4000-8000-000000000001"
	testNodeMaterialID2 = "20000000-0000-4000-8000-000000000002"
)

func TestNodeCredentialProvisioningKeepsPrivateKeysLocal(t *testing.T) {
	secretStore, paths := newNodeMaterialSecretStore(t)
	runner := &nodeMaterialWireGuardRunner{}
	provisioner, err := NewNodeCredentialProvisioner(secretStore, NodeCredentialRuntime{
		Entropy: bytes.NewReader(nodeMaterialEntropy()), WireGuardRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	installation, err := provisioner.Provision(context.Background(), testNodeMaterialID, 1)
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if installation.NodeID != testNodeMaterialID || installation.CredentialGeneration != 1 ||
		len(installation.OwnedReferences) != 4 || len(runner.calls) != 2 {
		t.Fatalf("installation = %+v, wg calls = %+v", installation, runner.calls)
	}
	if err := installation.PublicExchange.Validate(); err != nil {
		t.Fatalf("public exchange validation error = %v", err)
	}

	controlPrivate := readNodeMaterialSecret(t, secretStore, installation.References.ControlPrivateKey)
	defer clear(controlPrivate)
	wireGuardPrivate := readNodeMaterialSecret(t, secretStore, installation.References.WireGuardPrivateKey)
	defer clear(wireGuardPrivate)
	restrictedCredential := readNodeMaterialSecret(t, secretStore, installation.References.RestrictedCredential)
	defer clear(restrictedCredential)
	tunnelCredential := readNodeMaterialSecret(t, secretStore, installation.References.TunnelCredential)
	defer clear(tunnelCredential)

	assertControlCSRMatchesPrivateKey(t, installation.PublicExchange.ControlCSRPEM, controlPrivate)
	if string(wireGuardPrivate) != testNodeWireGuardPrivate() || installation.PublicExchange.WireGuardPublicKey != testNodeWireGuardPublic() {
		t.Fatal("WireGuard public/private material did not preserve the local key pair")
	}
	if _, err := restricted.DecodeIdentitySecret(restrictedCredential); err != nil {
		t.Fatalf("restricted credential error = %v", err)
	}
	if err := validateNodeTunnelCredential(tunnelCredential); err != nil {
		t.Fatalf("tunnel credential error = %v", err)
	}
	if bytes.Equal(restrictedCredential, tunnelCredential) || bytes.Equal(controlPrivate, wireGuardPrivate) {
		t.Fatal("independent node credential domains reused material")
	}

	encodedPublic, err := EncodeNodePublicExchange(installation.PublicExchange)
	if err != nil {
		t.Fatal(err)
	}
	decodedPublic, err := DecodeNodePublicExchange(encodedPublic)
	if err != nil || !reflect.DeepEqual(decodedPublic, installation.PublicExchange) {
		t.Fatalf("public exchange round trip = %+v, %v", decodedPublic, err)
	}
	gatewayState, err := model.EncodeState(gatewayStateWithNodePublicExchange(t, installation))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.BackupsDir, store.SecretDirectoryMode); err != nil {
		t.Fatal(err)
	}
	plainStateCopies := []string{
		paths.StateFile,
		paths.PreviousStateFile,
		filepath.Join(paths.BackupsDir, "unencrypted-state-copy.json"),
	}
	for _, path := range plainStateCopies {
		if err := os.WriteFile(path, gatewayState, store.StateFileMode); err != nil {
			t.Fatal(err)
		}
	}
	privateNeedles := nodePrivateMaterialNeedles(t, controlPrivate, wireGuardPrivate, restrictedCredential, tunnelCredential)
	defer func() {
		for _, value := range privateNeedles {
			clear(value)
		}
	}()
	for name, privateValue := range privateNeedles {
		if bytes.Contains(encodedPublic, privateValue) {
			t.Fatalf("public exchange contains %s", name)
		}
		if bytes.Contains(gatewayState, privateValue) {
			t.Fatalf("gateway state contains %s", name)
		}
		for _, path := range plainStateCopies {
			plainCopy, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(plainCopy, privateValue) {
				t.Fatalf("plain state copy %s contains %s", filepath.Base(path), name)
			}
		}
	}
	if _, err := json.Marshal(installation); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal(installation) error = %v", err)
	}
	if _, err := json.Marshal(installation.References); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("json.Marshal(references) error = %v", err)
	}

	assertNodeMaterialModes(t, paths, installation.References)
	if err := provisioner.Rollback(context.Background(), installation); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	for _, reference := range installation.References.Values() {
		if _, err := secretStore.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("secret %s remains after rollback: %v", reference, err)
		}
	}
}

func TestNodeCredentialProvisioningCreatesUniqueTunnelCredentialPerNodeGeneration(t *testing.T) {
	secretStore, _ := newNodeMaterialSecretStore(t)
	entropy := make([]byte, 3*len(nodeMaterialEntropy()))
	for index := range entropy {
		entropy[index] = byte(index + 1)
	}
	provisioner, err := NewNodeCredentialProvisioner(secretStore, NodeCredentialRuntime{
		Entropy: bytes.NewReader(entropy), WireGuardRunner: &nodeMaterialWireGuardRunner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	requests := []struct {
		nodeID     string
		generation uint64
	}{
		{nodeID: testNodeMaterialID, generation: 1},
		{nodeID: testNodeMaterialID, generation: 2},
		{nodeID: testNodeMaterialID2, generation: 1},
	}
	credentials := make(map[string]struct{}, len(requests))
	commitments := make(map[string]struct{}, len(requests))
	references := make(map[model.SecretRef]struct{}, len(requests))
	for _, request := range requests {
		installation, err := provisioner.Provision(context.Background(), request.nodeID, request.generation)
		if err != nil {
			t.Fatalf("Provision(%s, %d) error = %v", request.nodeID, request.generation, err)
		}
		credential := readNodeMaterialSecret(t, secretStore, installation.References.TunnelCredential)
		if err := validateNodeTunnelCredential(credential); err != nil {
			clear(credential)
			t.Fatalf("credential validation error = %v", err)
		}
		value := string(credential)
		clear(credential)
		commitment := installation.PublicExchange.MaterialHashes[NodeTunnelCredentialHashName]
		if _, duplicate := credentials[value]; duplicate {
			t.Fatal("two node generations received the same tunnel credential")
		}
		if _, duplicate := commitments[commitment]; duplicate {
			t.Fatal("two node generations received the same tunnel credential commitment")
		}
		if _, duplicate := references[installation.References.TunnelCredential]; duplicate {
			t.Fatal("two node generations received the same tunnel credential reference")
		}
		credentials[value] = struct{}{}
		commitments[commitment] = struct{}{}
		references[installation.References.TunnelCredential] = struct{}{}
	}
}

func TestNodePublicExchangeRejectsPrivateAndTamperedFields(t *testing.T) {
	installation, _, _ := provisionNodeMaterialFixture(t)
	encoded, err := EncodeNodePublicExchange(installation.PublicExchange)
	if err != nil {
		t.Fatal(err)
	}
	withPrivate := bytes.Replace(encoded, []byte(`"node_id":`), []byte(`"control_private_key":"forbidden","node_id":`), 1)
	if _, err := DecodeNodePublicExchange(withPrivate); err == nil {
		t.Fatal("public exchange accepted a private-key field")
	}
	withUnknown := bytes.Replace(encoded, []byte(`"node_id":`), []byte(`"unknown":true,"node_id":`), 1)
	if _, err := DecodeNodePublicExchange(withUnknown); err == nil {
		t.Fatal("public exchange accepted an unknown field")
	}

	for name, mutate := range map[string]func(*NodePublicExchange){
		"CSR identity": func(value *NodePublicExchange) {
			value.NodeID = "30000000-0000-4000-8000-000000000003"
		},
		"WireGuard public key": func(value *NodePublicExchange) {
			value.WireGuardPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
		},
		"CSR hash": func(value *NodePublicExchange) {
			value.MaterialHashes[NodeControlCSRHashName] = strings.Repeat("0", 64)
		},
		"missing commitment": func(value *NodePublicExchange) {
			delete(value.MaterialHashes, NodeTunnelCredentialHashName)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := installation.PublicExchange
			candidate.MaterialHashes = cloneStringMap(candidate.MaterialHashes)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("tampered public exchange passed validation")
			}
		})
	}
}

func TestNodeSharedCredentialPayloadBindsCommitmentsAndExcludesPrivateKeys(t *testing.T) {
	installation, provisioner, secretStore := provisionNodeMaterialFixture(t)
	payload, err := provisioner.SharedCredentialPayload(installation)
	if err != nil {
		t.Fatalf("SharedCredentialPayload() error = %v", err)
	}
	defer payload.Destroy()
	controlPrivate := readNodeMaterialSecret(t, secretStore, installation.References.ControlPrivateKey)
	defer clear(controlPrivate)
	wireGuardPrivate := readNodeMaterialSecret(t, secretStore, installation.References.WireGuardPrivateKey)
	defer clear(wireGuardPrivate)
	if err := payload.Use(func(encoded []byte) error {
		if bytes.Contains(encoded, controlPrivate) || bytes.Contains(encoded, wireGuardPrivate) {
			t.Fatal("shared credential payload contains an asymmetric private key")
		}
		var wire struct {
			SchemaVersion        int    `json:"schema_version"`
			RestrictedCredential string `json:"restricted_credential"`
			TunnelCredential     string `json:"tunnel_credential"`
		}
		if err := json.Unmarshal(encoded, &wire); err != nil {
			return err
		}
		if wire.SchemaVersion != NodeSharedExchangeSchemaVersion ||
			sha256Hex([]byte(wire.RestrictedCredential)) != installation.PublicExchange.MaterialHashes[NodeRestrictedCredentialHashName] ||
			sha256Hex([]byte(wire.TunnelCredential)) != installation.PublicExchange.MaterialHashes[NodeTunnelCredentialHashName] {
			t.Fatal("shared credential payload does not match its public commitments")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	restrictedReference := installation.References.RestrictedCredential
	if err := secretStore.Put(restrictedReference, []byte(`{"schema_version":1,"shadowtls_password":"`+strings.Repeat("ab", 32)+`"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := provisioner.SharedCredentialPayload(installation); err == nil {
		t.Fatal("shared payload accepted a credential that differed from its commitment")
	}
}

func TestNodeCredentialProvisioningRollsBackOnlyNewOwnedSecrets(t *testing.T) {
	secretStore, _ := newNodeMaterialSecretStore(t)
	references, err := NewNodeCredentialReferences(testNodeMaterialID, 1)
	if err != nil {
		t.Fatal(err)
	}
	foreign := []byte("pre-existing-restricted-credential")
	if err := secretStore.PutIfAbsent(references.RestrictedCredential, foreign); err != nil {
		t.Fatal(err)
	}
	provisioner, _ := NewNodeCredentialProvisioner(secretStore, NodeCredentialRuntime{
		Entropy: bytes.NewReader(nodeMaterialEntropy()), WireGuardRunner: &nodeMaterialWireGuardRunner{},
	})
	if _, err := provisioner.Provision(context.Background(), testNodeMaterialID, 1); err == nil {
		t.Fatal("Provision() unexpectedly replaced a pre-existing secret")
	}
	stored, err := secretStore.Get(references.RestrictedCredential)
	if err != nil || !bytes.Equal(stored, foreign) {
		t.Fatalf("pre-existing secret = %q, %v", stored, err)
	}
	for _, reference := range []model.SecretRef{references.ControlPrivateKey, references.WireGuardPrivateKey, references.TunnelCredential} {
		if _, err := secretStore.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("new partial secret %s survived rollback: %v", reference, err)
		}
	}

	installation := NodeCredentialInstallation{
		NodeID: testNodeMaterialID, CredentialGeneration: 1, References: references,
		OwnedReferences: []model.SecretRef{references.RestrictedCredential, "token:foreign"},
	}
	if err := provisioner.Rollback(context.Background(), installation); err == nil {
		t.Fatal("Rollback() accepted a foreign reference")
	}
	stored, err = secretStore.Get(references.RestrictedCredential)
	if err != nil || !bytes.Equal(stored, foreign) {
		t.Fatal("refused rollback changed an owned reference before validating the full set")
	}
}

func TestNodeEnrollmentTLSCaptureContainsNoCredentialPlaintext(t *testing.T) {
	installation, provisioner, secretStore := provisionNodeMaterialFixture(t)
	publicExchange, err := EncodeNodePublicExchange(installation.PublicExchange)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := provisioner.SharedCredentialPayload(installation)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Destroy()
	var plaintext []byte
	if err := shared.Use(func(sharedPayload []byte) error {
		plaintext = append(append(append([]byte(nil), publicExchange...), '\n'), sharedPayload...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	capture, received := captureTLS13ClientWrite(t, plaintext)
	if !bytes.Equal(received, plaintext) {
		t.Fatal("TLS server did not receive the complete enrollment exchange")
	}
	controlPrivate := readNodeMaterialSecret(t, secretStore, installation.References.ControlPrivateKey)
	wireGuardPrivate := readNodeMaterialSecret(t, secretStore, installation.References.WireGuardPrivateKey)
	restrictedCredential := readNodeMaterialSecret(t, secretStore, installation.References.RestrictedCredential)
	tunnelCredential := readNodeMaterialSecret(t, secretStore, installation.References.TunnelCredential)
	privateValues := [][]byte{publicExchange}
	for _, value := range nodePrivateMaterialNeedles(t, controlPrivate, wireGuardPrivate, restrictedCredential, tunnelCredential) {
		privateValues = append(privateValues, value)
	}
	defer func() {
		clear(controlPrivate)
		clear(wireGuardPrivate)
		clear(restrictedCredential)
		clear(tunnelCredential)
		for _, value := range privateValues {
			clear(value)
		}
	}()
	for _, value := range privateValues {
		if bytes.Contains(capture, value) {
			t.Fatal("TLS packet capture contains enrollment material in plaintext")
		}
	}
}

type nodeMaterialWireGuardRunner struct {
	calls []string
}

func (runner *nodeMaterialWireGuardRunner) Run(_ context.Context, name string, arguments []string, stdin string) (string, error) {
	runner.calls = append(runner.calls, name+" "+strings.Join(arguments, " "))
	switch {
	case name == "wg" && reflect.DeepEqual(arguments, []string{"genkey"}) && stdin == "":
		return testNodeWireGuardPrivate() + "\n", nil
	case name == "wg" && reflect.DeepEqual(arguments, []string{"pubkey"}) && stdin == testNodeWireGuardPrivate()+"\n":
		return testNodeWireGuardPublic() + "\n", nil
	default:
		return "", errors.New("unexpected WireGuard command")
	}
}

func provisionNodeMaterialFixture(t *testing.T) (NodeCredentialInstallation, *NodeCredentialProvisioner, *store.SecretStore) {
	t.Helper()
	secretStore, _ := newNodeMaterialSecretStore(t)
	provisioner, err := NewNodeCredentialProvisioner(secretStore, NodeCredentialRuntime{
		Entropy: bytes.NewReader(nodeMaterialEntropy()), WireGuardRunner: &nodeMaterialWireGuardRunner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	installation, err := provisioner.Provision(context.Background(), testNodeMaterialID, 1)
	if err != nil {
		t.Fatal(err)
	}
	return installation, provisioner, secretStore
}

func newNodeMaterialSecretStore(t *testing.T) (*store.SecretStore, store.Paths) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, store.SecretDirectoryMode); err != nil {
		t.Fatal(err)
	}
	secretStore, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	return secretStore, paths
}

func nodeMaterialEntropy() []byte {
	result := make([]byte, 32+restricted.SymmetricKeyByteCount+NodeTunnelCredentialBytes)
	for index := range result {
		result[index] = byte(index + 1)
	}
	return result
}

func testNodeWireGuardPrivate() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
}

func testNodeWireGuardPublic() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
}

func readNodeMaterialSecret(t *testing.T, secretStore *store.SecretStore, reference model.SecretRef) []byte {
	t.Helper()
	value, err := secretStore.Get(reference)
	if err != nil {
		t.Fatalf("Get(%s) error = %v", reference, err)
	}
	return value
}

func assertControlCSRMatchesPrivateKey(t *testing.T, csrPEM string, privatePEM []byte) {
	t.Helper()
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	privateBlock, _ := pem.Decode(privatePEM)
	if csrBlock == nil || privateBlock == nil {
		t.Fatal("control material is not PEM")
	}
	request, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || !request.PublicKey.(ed25519.PublicKey).Equal(privateKey.Public()) {
		t.Fatal("control CSR does not match the stored private key")
	}
}

func nodePrivateMaterialNeedles(t *testing.T, controlPrivate, wireGuardPrivate, restrictedCredential, tunnelCredential []byte) map[string][]byte {
	t.Helper()
	privateBlock, _ := pem.Decode(controlPrivate)
	if privateBlock == nil {
		t.Fatal("control private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	controlKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("control private key is not Ed25519")
	}
	identity, err := restricted.DecodeIdentitySecret(restrictedCredential)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"control private PEM":   controlPrivate,
		"control private seed":  []byte(base64.StdEncoding.EncodeToString(controlKey.Seed())),
		"WireGuard private key": wireGuardPrivate,
		"restricted credential": restrictedCredential,
		"restricted password":   []byte(identity.ShadowTLSPassword),
		"tunnel credential":     tunnelCredential,
	}
}

func assertNodeMaterialModes(t *testing.T, paths store.Paths, references NodeCredentialReferences) {
	t.Helper()
	info, err := os.Stat(paths.SecretsDir)
	if err != nil || info.Mode().Perm() != store.SecretDirectoryMode {
		t.Fatalf("secrets directory mode = %v, %v", info, err)
	}
	for _, reference := range references.Values() {
		kind, id, _ := reference.Parts()
		for _, path := range []string{filepath.Join(paths.SecretsDir, kind), filepath.Join(paths.SecretsDir, kind, id)} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			want := store.SecretDirectoryMode
			if path == filepath.Join(paths.SecretsDir, kind, id) {
				want = store.SecretFileMode
			}
			if info.Mode().Perm() != want {
				t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
			}
		}
	}
}

func gatewayStateWithNodePublicExchange(t *testing.T, installation NodeCredentialInstallation) model.State {
	t.Helper()
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	state := inviteGatewayState(now)
	state.HandshakeHost = &model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1,
		CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: now,
	}
	state.Nodes = []model.Node{{
		SchemaVersion: model.ResourceSchemaVersion, ID: installation.NodeID, Name: "private-node",
		Lifecycle: model.LifecycleActive, OverlayIPv4: "10.67.0.2", CredentialGeneration: installation.CredentialGeneration,
		AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
		IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: now,
	}}
	standardReference, err := model.NewSecretRef("wireguard-peer", installation.NodeID+"-g1")
	if err != nil {
		t.Fatal(err)
	}
	state.Transports = []model.Transport{
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: installation.NodeID,
			Kind: model.TransportStandard, State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: 51820,
			CredentialGeneration: installation.CredentialGeneration, CredentialRef: standardReference,
			PublicKey: installation.PublicExchange.WireGuardPublicKey, ConfigHash: strings.Repeat("1", 64),
		},
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: installation.NodeID,
			Kind: model.TransportRestricted, State: model.TransportStandby, Provider: "mihomo", Protocol: model.ProtocolTCP, Port: 8443,
			CredentialGeneration: installation.CredentialGeneration, CredentialRef: installation.References.RestrictedCredential,
			HandshakeHost: "www.microsoft.com", ConfigHash: strings.Repeat("2", 64),
		},
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("gateway state fixture: %v", err)
	}
	return state
}

type recordingConn struct {
	net.Conn
	mu      sync.Mutex
	written []byte
}

func (connection *recordingConn) Write(data []byte) (int, error) {
	connection.mu.Lock()
	connection.written = append(connection.written, data...)
	connection.mu.Unlock()
	return connection.Conn.Write(data)
}

func (connection *recordingConn) Capture() []byte {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return append([]byte(nil), connection.written...)
}

func captureTLS13ClientWrite(t *testing.T, payload []byte) ([]byte, []byte) {
	t.Helper()
	certificate := nodeMaterialTLSCertificate(t)
	clientRaw, serverRaw := net.Pipe()
	recorder := &recordingConn{Conn: clientRaw}
	client := tls.Client(recorder, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true, // test-only in-memory server
	})
	server := tls.Server(serverRaw, &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
	})
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})
	type serverResult struct {
		data []byte
		err  error
	}
	result := make(chan serverResult, 1)
	go func() {
		if err := server.Handshake(); err != nil {
			result <- serverResult{err: err}
			return
		}
		data := make([]byte, len(payload))
		_, err := io.ReadFull(server, data)
		result <- serverResult{data: data, err: err}
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	serverRead := <-result
	if serverRead.err != nil {
		t.Fatal(serverRead.err)
	}
	capture := recorder.Capture()
	_ = clientRaw.Close()
	_ = serverRaw.Close()
	return capture, serverRead.data
}

func nodeMaterialTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node-material-test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
}

func cloneStringMap(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}
