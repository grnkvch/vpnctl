package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestTunnelCredentialsAreIndependentCanonical256BitValues(t *testing.T) {
	t.Parallel()

	entropy := make([]byte, 2*CredentialBytes)
	for index := range entropy {
		entropy[index] = byte(index + 1)
	}
	first, err := GenerateCredential(bytes.NewReader(entropy))
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateCredential(bytes.NewReader(entropy[CredentialBytes:]))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("independent node entropy produced the same tunnel credential")
	}
	for _, value := range [][]byte{first, second} {
		if err := ValidateCredential(value); err != nil {
			t.Fatalf("ValidateCredential() error = %v", err)
		}
		if len(value) != 43 || bytes.ContainsRune(value, '=') {
			t.Fatalf("credential encoding = %q", value)
		}
	}
	if err := ValidateCredential(append(append([]byte(nil), first...), '=')); err == nil {
		t.Fatal("padded tunnel credential was accepted")
	}
	if _, err := GenerateCredential(bytes.NewReader(entropy[:CredentialBytes-1])); err == nil {
		t.Fatal("short entropy source was accepted")
	}
}

func TestTunnelCredentialReferenceAndCommitmentBindNodeGeneration(t *testing.T) {
	t.Parallel()

	reference, err := CredentialReference(testNodeA, 7)
	if err != nil {
		t.Fatal(err)
	}
	if reference != model.SecretRef("tunnel-token:"+testNodeA+"-g7") {
		t.Fatalf("credential reference = %q", reference)
	}
	commitment, err := NewCredentialCommitment(testNodeA, 7, []byte(testTunnelCredential))
	if err != nil {
		t.Fatal(err)
	}
	if err := commitment.Validate(); err != nil || !commitment.Matches(testNodeA, 7, []byte(testTunnelCredential)) {
		t.Fatalf("commitment validation/match = %v/%t", err, commitment.Matches(testNodeA, 7, []byte(testTunnelCredential)))
	}
	other, err := GenerateCredential(bytes.NewReader(bytes.Repeat([]byte{0x33}, CredentialBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if commitment.Matches(testNodeA, 7, other) {
		t.Fatal("commitment matched another node credential")
	}
	changed := commitment
	changed.Generation++
	if changed.Validate() != nil || changed.NodeID != commitment.NodeID || changed.SHA256 != commitment.SHA256 {
		t.Fatalf("generation-scoped commitment changed unrelated fields: %+v", changed)
	}
	if commitment.Matches(testNodeB, 7, []byte(testTunnelCredential)) || commitment.Matches(testNodeA, 8, []byte(testTunnelCredential)) {
		t.Fatal("commitment matched a cross-node or stale-generation credential")
	}
	for _, invalid := range []CredentialCommitment{
		{NodeID: testNodeA, Generation: 0, SHA256: commitment.SHA256},
		{NodeID: testNodeB, Generation: 7, SHA256: "secret-value"},
	} {
		if invalid.Validate() == nil {
			t.Fatalf("invalid commitment was accepted: %+v", invalid)
		}
	}
}

func TestStoreCredentialSourceUsesRootOnlyGenerationScopedSecret(t *testing.T) {
	t.Parallel()

	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secretStore, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := CredentialReference(testNodeA, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := secretStore.PutIfAbsent(reference, []byte(testTunnelCredential)); err != nil {
		t.Fatal(err)
	}
	source, err := NewStoreCredentialSource(secretStore)
	if err != nil {
		t.Fatal(err)
	}
	value, err := source.TunnelCredential(testNodeA, 3)
	if err != nil || string(value) != testTunnelCredential {
		t.Fatalf("TunnelCredential() = %q, %v", value, err)
	}
	clear(value)
	again, err := source.TunnelCredential(testNodeA, 3)
	if err != nil || string(again) != testTunnelCredential {
		t.Fatalf("credential source did not return an independent copy: %q, %v", again, err)
	}
	clear(again)
	kind, identity, _ := reference.Parts()
	for path, want := range map[string]os.FileMode{
		paths.SecretsDir:                                store.SecretDirectoryMode,
		filepath.Join(paths.SecretsDir, kind):           store.SecretDirectoryMode,
		filepath.Join(paths.SecretsDir, kind, identity): store.SecretFileMode,
	} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != want {
			t.Fatalf("root-only path %s = %v, %v; want mode %o", path, info, err, want)
		}
	}
	if _, err := source.TunnelCredential(testNodeA, 4); err == nil || err.Error() != "read tunnel credential" || strings.Contains(err.Error(), paths.SecretsDir) {
		t.Fatalf("missing generation error was not sanitized: %v", err)
	}
}

func TestFRPProviderReadsOnlyTheExactStoredNodeGenerationCredential(t *testing.T) {
	t.Parallel()

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
	reference, err := CredentialReference(testNodeA, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := secretStore.PutIfAbsent(reference, []byte(testTunnelCredential)); err != nil {
		t.Fatal(err)
	}
	source, err := NewStoreCredentialSource(secretStore)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewFRPProvider(paths.Root, testFRPComponent(), source)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := provider.Render(context.Background(), RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: testNodeHostID, Generation: 1,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{testFRPSession(t)},
	}})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	config := candidate.(FRPCandidate).Bytes()
	defer clear(config)
	if !bytes.Contains(config, []byte(`metadatas.tunnel_token = "`+testTunnelCredential+`"`)) {
		t.Fatal("private frpc candidate did not receive the stored generation credential")
	}
	for _, surface := range [][]byte{
		[]byte(fmt.Sprintf("%+v", candidate.Descriptor())),
		[]byte(fmt.Sprintf("%+v", provider)),
	} {
		if bytes.Contains(surface, []byte(testTunnelCredential)) || bytes.Contains(surface, []byte(reference)) {
			t.Fatalf("public provider surface contains tunnel credential material: %s", surface)
		}
	}

	wrongGeneration := testFRPSession(t)
	wrongGeneration.CredentialGeneration = 2
	_, err = provider.Render(context.Background(), RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: testNodeHostID, Generation: 2,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{wrongGeneration},
	}})
	if err == nil || err.Error() != "read frp node credential" || strings.Contains(err.Error(), string(reference)) {
		t.Fatalf("wrong-generation error was not sanitized: %v", err)
	}
}

func TestTransportSwitchPreservesLogicalTunnelCredentialAndConfiguration(t *testing.T) {
	t.Parallel()

	provider, err := NewFRPProvider("/", testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	session := testFRPSession(t)
	request := RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: testNodeHostID, Generation: 11,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{session},
	}}
	restrictedCandidate, err := provider.Render(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Plan.Generation++
	request.Plan.Nodes[0].ActiveTransport = model.TransportStandard
	standardCandidate, err := provider.Render(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	restrictedConfig := restrictedCandidate.(FRPCandidate).Bytes()
	standardConfig := standardCandidate.(FRPCandidate).Bytes()
	defer clear(restrictedConfig)
	defer clear(standardConfig)
	if !bytes.Equal(restrictedConfig, standardConfig) {
		t.Fatal("manual transport switch changed logical tunnel identity, credential, or mappings")
	}
	if restrictedCandidate.Descriptor().CredentialGeneration != standardCandidate.Descriptor().CredentialGeneration ||
		restrictedCandidate.Descriptor().ConfigHash != standardCandidate.Descriptor().ConfigHash ||
		restrictedCandidate.Descriptor().ActiveTransport == standardCandidate.Descriptor().ActiveTransport {
		t.Fatalf("transport-switch descriptors = %+v / %+v", restrictedCandidate.Descriptor(), standardCandidate.Descriptor())
	}
}

func TestTunnelCredentialPublicAndPlainSurfacesAreRedacted(t *testing.T) {
	t.Parallel()

	commitment, err := NewCredentialCommitment(testNodeA, 1, []byte(testTunnelCredential))
	if err != nil {
		t.Fatal(err)
	}
	descriptor := CandidateDescriptor{
		Provider: FRPProviderName, HostRole: model.RoleNode, HostID: testNodeHostID, Generation: 1,
		NodeID: testNodeA, CredentialGeneration: 1, ActiveTransport: model.TransportRestricted,
		ConfigHash: strings.Repeat("a", 64),
	}
	plainSnapshot, err := json.Marshal(struct {
		Node       model.Node           `json:"node"`
		Commitment CredentialCommitment `json:"tunnel_credential_commitment"`
		Candidate  CandidateDescriptor  `json:"candidate"`
	}{Node: testNode(testNodeA), Commitment: commitment, Candidate: descriptor})
	if err != nil {
		t.Fatal(err)
	}
	publicSurfaces := [][]byte{
		plainSnapshot,
		[]byte(fmt.Sprintf("%+v", commitment)),
		[]byte(fmt.Sprintf("%+v", descriptor)),
	}
	for _, surface := range publicSurfaces {
		if bytes.Contains(surface, []byte(testTunnelCredential)) || bytes.Contains(surface, []byte("tunnel-token:")) {
			t.Fatalf("plain/public surface contains a credential or secret reference: %s", surface)
		}
	}
	result := output.NewResult("tunnel.status", output.StatusOK, output.CategorySuccess, output.SafeObject{
		"node_id": testNodeA, "credential_generation": uint64(1), "tunnel_token": testTunnelCredential,
	})
	if err := result.Validate(); err == nil || !strings.Contains(err.Error(), "key is not allowed") {
		t.Fatalf("result accepted tunnel token: %v", err)
	}
	if rule := output.ClassifyField("tunnel_token"); rule.Classification != output.ClassSecret || rule.AllowedInResult {
		t.Fatalf("tunnel token redaction rule = %+v", rule)
	}
}

type failingCredentialReader struct{}

func (failingCredentialReader) Get(model.SecretRef) ([]byte, error) {
	return nil, errors.New("secret-path-and-token-canary")
}

func TestStoreCredentialSourceSanitizesReaderFailure(t *testing.T) {
	t.Parallel()

	source, err := NewStoreCredentialSource(failingCredentialReader{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.TunnelCredential(testNodeA, 1)
	if err == nil || err.Error() != "read tunnel credential" || strings.Contains(err.Error(), "canary") {
		t.Fatalf("credential read error was not sanitized: %v", err)
	}
}
