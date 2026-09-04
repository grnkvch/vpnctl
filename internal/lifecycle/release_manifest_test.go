package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestSignedReleaseManifestBindsCompleteReleaseContract(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, artifacts := releaseManifestFixture()
	signed, err := EncodeSignedReleaseManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := DecodeAndVerifyReleaseManifest(signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(verified, manifest) {
		t.Fatalf("verified release manifest differs:\nwant=%+v\n got=%+v", manifest, verified)
	}
	component := verified.ComponentManifest
	if component.VPNCTLVersion != "v2.0.0" || !reflect.DeepEqual(component.ControlProtocols, []string{"2.3", "1.9"}) ||
		component.StateSchemaMinimum != 1 || component.StateSchemaMaximum != 2 || component.TargetOS != "ubuntu 24.04" ||
		component.TargetArchitecture != "amd64" || component.HandshakeHostListVersion != 7 || !component.MigrationReversible {
		t.Fatalf("signed compatibility contract = %+v", component)
	}
	if len(verified.Artifacts) != 3 || len(verified.APTPackages) != 3 {
		t.Fatalf("delivery contract artifacts=%d apt=%d", len(verified.Artifacts), len(verified.APTPackages))
	}
	for path, content := range artifacts {
		if err := VerifyReleaseArtifact(verified, path, bytes.NewReader(content)); err != nil {
			t.Fatalf("verify %s: %v", path, err)
		}
	}
	if err := VerifyReleasePlatform(verified, ReleasePlatform{
		OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64",
	}); err != nil {
		t.Fatal(err)
	}

	verified.Artifacts[0].Roles[0] = model.RoleNode
	verified.ComponentManifest.Components[0].Capabilities[0] = "mutated"
	again, err := DecodeAndVerifyReleaseManifest(signed, publicKey)
	if err != nil || again.Artifacts[0].Roles[0] != model.RoleGateway || again.ComponentManifest.Components[0].Capabilities[0] == "mutated" {
		t.Fatalf("caller mutation changed verified envelope: %+v, %v", again, err)
	}
}

func TestV2ReleaseManifestUsesRuntimeProviderPinsAndAptRanges(t *testing.T) {
	t.Parallel()
	vpnctlHash := strings.Repeat("a", 64)
	manifest, err := NewV2ReleaseManifest("v2.0.0", vpnctlHash, true)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ComponentManifest.VPNCTLVersion != "v2.0.0" ||
		manifest.ComponentManifest.HandshakeHostListVersion != 1 || !manifest.ComponentManifest.MigrationReversible ||
		len(manifest.ComponentManifest.Components) != 6 || len(manifest.Artifacts) != 3 || len(manifest.APTPackages) != 3 {
		t.Fatalf("production release manifest = %+v", manifest)
	}
	if manifest.Artifacts[0].Component != "vpnctl" || manifest.Artifacts[0].Path != "bin/vpnctl" || manifest.Artifacts[0].SHA256 != vpnctlHash ||
		manifest.Artifacts[1].Component != "frp" || manifest.Artifacts[2].Component != "mihomo" {
		t.Fatalf("production release artifacts = %+v", manifest.Artifacts)
	}
	if manifest.APTPackages[1].Component != "nginx" || manifest.APTPackages[1].MaximumVersionExclusive != "1.24.1" ||
		manifest.APTPackages[1].MinimumVersion != "1.24.0-2ubuntu7.17" {
		t.Fatalf("production nginx compatibility = %+v", manifest.APTPackages[1])
	}
	if _, err := NewV2ReleaseManifest("v2.0.0", "invalid", true); !errors.Is(err, ErrInvalidReleaseManifest) {
		t.Fatalf("invalid vpnctl checksum error = %v", err)
	}
	if _, err := NewV2ReleaseManifest("", vpnctlHash, true); !errors.Is(err, ErrInvalidReleaseManifest) {
		t.Fatalf("invalid vpnctl version error = %v", err)
	}
}

func TestSignedReleaseManifestRejectsSignatureAndPayloadTampering(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	manifest, _ := releaseManifestFixture()
	signed, err := EncodeSignedReleaseManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	var envelope SignedReleaseManifest
	if err := json.Unmarshal(signed, &envelope); err != nil {
		t.Fatal(err)
	}

	tamperedPayload := envelope
	tamperedPayload.Payload = mutateReleaseBase64(tamperedPayload.Payload)
	tamperedSignature := envelope
	tamperedSignature.Signature = mutateReleaseBase64(tamperedSignature.Signature)
	tamperedKeyID := envelope
	tamperedKeyID.KeyID = "sha256:" + strings.Repeat("0", 64)
	tamperedAlgorithm := envelope
	tamperedAlgorithm.Algorithm = "none"
	for name, candidate := range map[string]SignedReleaseManifest{
		"payload": tamperedPayload, "signature": tamperedSignature, "key-id": tamperedKeyID, "algorithm": tamperedAlgorithm,
	} {
		name, candidate := name, candidate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			encoded, _ := json.Marshal(candidate)
			if _, err := DecodeAndVerifyReleaseManifest(encoded, publicKey); !errors.Is(err, ErrInvalidReleaseManifest) {
				t.Fatalf("tampered envelope error = %v", err)
			}
		})
	}

	wrongPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := DecodeAndVerifyReleaseManifest(signed, wrongPublic); !errors.Is(err, ErrInvalidReleaseManifest) {
		t.Fatalf("wrong release key error = %v", err)
	}
	if _, err := DecodeAndVerifyReleaseManifest(signed, ed25519.PublicKey{1}); !errors.Is(err, ErrInvalidReleaseManifest) {
		t.Fatalf("invalid release key error = %v", err)
	}
	if _, err := EncodeSignedReleaseManifest(manifest, ed25519.PrivateKey{1}); !errors.Is(err, ErrInvalidReleaseManifest) {
		t.Fatalf("invalid signing key error = %v", err)
	}
}

func TestSignedReleaseManifestRejectsAmbiguousOrNonCanonicalJSON(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	manifest, _ := releaseManifestFixture()
	signed, _ := EncodeSignedReleaseManifest(manifest, privateKey)

	unknownEnvelope := append(signed[:len(signed)-1], []byte(`,"unknown":true}`)...)
	duplicateEnvelope := append([]byte(`{"schema_version":1,`), signed[1:]...)
	for name, candidate := range map[string][]byte{
		"unknown-envelope-field":   unknownEnvelope,
		"duplicate-envelope-field": duplicateEnvelope,
		"multiple-envelopes":       append(append([]byte(nil), signed...), signed...),
	} {
		if _, err := DecodeAndVerifyReleaseManifest(candidate, publicKey); !errors.Is(err, ErrInvalidReleaseManifest) {
			t.Fatalf("%s error = %v", name, err)
		}
	}

	payload, _ := json.Marshal(manifest)
	unknownPayload := append(payload[:len(payload)-1], []byte(`,"unknown":true}`)...)
	duplicatePayload := append([]byte(`{"schema_version":1,`), payload[1:]...)
	nonCanonicalPayload := append([]byte(" "), payload...)
	for name, candidate := range map[string][]byte{
		"unknown-payload-field":   unknownPayload,
		"duplicate-payload-field": duplicatePayload,
		"non-canonical-payload":   nonCanonicalPayload,
	} {
		encoded := signRawReleasePayload(t, candidate, privateKey)
		if _, err := DecodeAndVerifyReleaseManifest(encoded, publicKey); !errors.Is(err, ErrInvalidReleaseManifest) {
			t.Fatalf("%s error = %v", name, err)
		}
	}

	oversized := bytes.Repeat([]byte{'x'}, MaximumSignedReleaseManifestBytes+1)
	if _, err := DecodeAndVerifyReleaseManifest(oversized, publicKey); !errors.Is(err, ErrInvalidReleaseManifest) {
		t.Fatalf("oversized envelope error = %v", err)
	}
}

func TestReleaseManifestRejectsIncompleteOrAmbiguousDeliveryMetadata(t *testing.T) {
	t.Parallel()
	base, _ := releaseManifestFixture()
	tests := map[string]func(*ReleaseManifest){
		"manifest-schema": func(value *ReleaseManifest) { value.SchemaVersion++ },
		"control-window":  func(value *ReleaseManifest) { value.ComponentManifest.ControlProtocols = []string{"1.0", "1.1"} },
		"state-range": func(value *ReleaseManifest) {
			value.ComponentManifest.StateSchemaMinimum = 3
			value.ComponentManifest.StateSchemaMaximum = 2
		},
		"target":         func(value *ReleaseManifest) { value.ComponentManifest.TargetArchitecture = "arm64" },
		"handshake-list": func(value *ReleaseManifest) { value.ComponentManifest.HandshakeHostListVersion = 0 },
		"component-order": func(value *ReleaseManifest) {
			value.ComponentManifest.Components[0], value.ComponentManifest.Components[1] = value.ComponentManifest.Components[1], value.ComponentManifest.Components[0]
		},
		"capability-order": func(value *ReleaseManifest) {
			value.ComponentManifest.Components[0].Capabilities = []string{"tls", "auth"}
		},
		"missing-vpnctl":               func(value *ReleaseManifest) { value.Artifacts = value.Artifacts[1:] },
		"vpnctl-one-role":              func(value *ReleaseManifest) { value.Artifacts[0].Roles = []model.Role{model.RoleGateway} },
		"escaping-path":                func(value *ReleaseManifest) { value.Artifacts[0].Path = "../vpnctl" },
		"artifact-checksum":            func(value *ReleaseManifest) { value.Artifacts[0].SHA256 = strings.Repeat("f", 64) },
		"duplicate-artifact-component": func(value *ReleaseManifest) { value.Artifacts[1].Component = value.Artifacts[0].Component },
		"artifact-order": func(value *ReleaseManifest) {
			value.Artifacts[0], value.Artifacts[1] = value.Artifacts[1], value.Artifacts[0]
		},
		"missing-apt": func(value *ReleaseManifest) { value.APTPackages = value.APTPackages[1:] },
		"apt-source":  func(value *ReleaseManifest) { value.APTPackages[0].Source = "foreign" },
		"apt-range": func(value *ReleaseManifest) {
			value.APTPackages[0].MaximumVersionExclusive = value.APTPackages[0].MinimumVersion
		},
		"apt-capability": func(value *ReleaseManifest) { value.APTPackages[0].Capabilities = []string{"different"} },
		"apt-role":       func(value *ReleaseManifest) { value.APTPackages[0].Roles = []model.Role{"client"} },
		"apt-order": func(value *ReleaseManifest) {
			value.APTPackages[0], value.APTPackages[1] = value.APTPackages[1], value.APTPackages[0]
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := cloneReleaseManifest(base)
			mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidReleaseManifest) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}

	irreversible := cloneReleaseManifest(base)
	irreversible.ComponentManifest.MigrationReversible = false
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := EncodeSignedReleaseManifest(irreversible, privateKey)
	if err != nil {
		t.Fatalf("explicit irreversible migration rejected: %v", err)
	}
	var envelope SignedReleaseManifest
	_ = json.Unmarshal(signed, &envelope)
	payload, _ := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if !bytes.Contains(payload, []byte(`"migration_reversible":false`)) {
		t.Fatalf("migration reversibility is absent from signed payload: %s", payload)
	}
}

func TestReleasePlatformRejectsUnsupportedHostWithoutWeakeningManifest(t *testing.T) {
	t.Parallel()
	manifest, _ := releaseManifestFixture()
	for name, platform := range map[string]ReleasePlatform{
		"wrong-os":      {OperatingSystem: "debian", Version: "12", Architecture: "amd64"},
		"wrong-version": {OperatingSystem: "ubuntu", Version: "22.04", Architecture: "amd64"},
		"wrong-arch":    {OperatingSystem: "ubuntu", Version: "24.04", Architecture: "arm64"},
		"missing":       {},
	} {
		if err := VerifyReleasePlatform(manifest, platform); !errors.Is(err, ErrUnsupportedReleasePlatform) {
			t.Fatalf("%s platform error = %v", name, err)
		}
	}
}

func TestReleaseArtifactVerificationRejectsTamperUnknownPathAndReadFailure(t *testing.T) {
	t.Parallel()
	manifest, artifacts := releaseManifestFixture()
	if err := VerifyReleaseArtifact(manifest, "bin/vpnctl", bytes.NewReader(append(artifacts["bin/vpnctl"], 'x'))); !errors.Is(err, ErrReleaseArtifactMismatch) {
		t.Fatalf("tampered artifact error = %v", err)
	}
	if err := VerifyReleaseArtifact(manifest, "components/unknown", bytes.NewReader(nil)); !errors.Is(err, ErrReleaseArtifactMismatch) {
		t.Fatalf("unknown artifact error = %v", err)
	}
	if err := VerifyReleaseArtifact(manifest, "bin/vpnctl", nil); !errors.Is(err, ErrReleaseArtifactMismatch) {
		t.Fatalf("nil artifact error = %v", err)
	}
	if err := VerifyReleaseArtifact(manifest, "bin/vpnctl", errorReleaseReader{}); !errors.Is(err, ErrReleaseArtifactMismatch) {
		t.Fatalf("read artifact error = %v", err)
	}
}

func releaseManifestFixture() (ReleaseManifest, map[string][]byte) {
	artifacts := map[string][]byte{
		"bin/vpnctl":                       []byte("vpnctl-v2-linux-amd64"),
		"components/frp-linux-amd64.tgz":   []byte("frp-0.69.0-linux-amd64"),
		"components/mihomo-linux-amd64.gz": []byte("mihomo-v1.19.30-linux-amd64"),
	}
	manifest := ReleaseManifest{
		SchemaVersion: ReleaseManifestSchemaVersion,
		ComponentManifest: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0",
			ControlProtocols: []string{"2.3", "1.9"}, StateSchemaMinimum: 1, StateSchemaMaximum: 2,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 7, MigrationReversible: true,
			Components: []model.ComponentPin{
				{Name: "frp", Version: "0.69.0", Source: "bundle:frp", Bundled: true, SHA256: releaseDigest(artifacts["components/frp-linux-amd64.tgz"]), Capabilities: []string{"http-plugin-authorization", "tcp-mux", "tls-server-verification"}},
				{Name: "mihomo", Version: "v1.19.30", Source: "bundle:mihomo", Bundled: true, SHA256: releaseDigest(artifacts["components/mihomo-linux-amd64.gz"]), Capabilities: []string{"shadowtls-v3-strict", "tun-routing", "uot-v2"}},
				{Name: "nftables", Version: "1.0.9", Source: "ubuntu:noble", Capabilities: []string{"atomic-ruleset", "inet-family"}},
				{Name: "nginx", Version: "1.24.0-2ubuntu7.17", Source: "ubuntu:noble-updates", Capabilities: []string{"http-1", "http-2", "streaming-proxy"}},
				{Name: "vpnctl", Version: "v2.0.0", Source: "bundle:vpnctl", Bundled: true, SHA256: releaseDigest(artifacts["bin/vpnctl"]), Capabilities: []string{"cli", "controller"}},
				{Name: "wireguard-tools", Version: "1.0.20210914", Source: "ubuntu:noble", Capabilities: []string{"wireguard-userspace-tools"}},
			},
		},
		Artifacts: []ReleaseArtifact{
			{Component: "vpnctl", Path: "bin/vpnctl", SHA256: releaseDigest(artifacts["bin/vpnctl"]), Roles: []model.Role{model.RoleGateway, model.RoleNode}},
			{Component: "frp", Path: "components/frp-linux-amd64.tgz", SHA256: releaseDigest(artifacts["components/frp-linux-amd64.tgz"]), Roles: []model.Role{model.RoleGateway, model.RoleNode}},
			{Component: "mihomo", Path: "components/mihomo-linux-amd64.gz", SHA256: releaseDigest(artifacts["components/mihomo-linux-amd64.gz"]), Roles: []model.Role{model.RoleGateway, model.RoleNode}},
		},
		APTPackages: []APTPackageCompatibility{
			{Component: "nftables", Package: "nftables", Source: "ubuntu:noble", MinimumVersion: "1.0.9-1build1", MaximumVersionExclusive: "1.1", Roles: []model.Role{model.RoleGateway, model.RoleNode}, Capabilities: []string{"atomic-ruleset", "inet-family"}},
			{Component: "nginx", Package: "nginx", Source: "ubuntu:noble-updates", MinimumVersion: "1.24.0-2ubuntu7.17", MaximumVersionExclusive: "1.25", Roles: []model.Role{model.RoleGateway}, Capabilities: []string{"http-1", "http-2", "streaming-proxy"}},
			{Component: "wireguard-tools", Package: "wireguard-tools", Source: "ubuntu:noble", MinimumVersion: "1.0.20210914-1ubuntu4", MaximumVersionExclusive: "1.1", Roles: []model.Role{model.RoleGateway, model.RoleNode}, Capabilities: []string{"wireguard-userspace-tools"}},
		},
	}
	return manifest, artifacts
}

func releaseDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func mutateReleaseBase64(value string) string {
	replacement := byte('A')
	if value[len(value)-1] == replacement {
		replacement = 'B'
	}
	return value[:len(value)-1] + string(replacement)
}

func signRawReleasePayload(t *testing.T, payload []byte, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	envelope := SignedReleaseManifest{
		SchemaVersion: ReleaseSignatureEnvelopeSchemaVersion, Algorithm: ReleaseSignatureAlgorithm,
		KeyID: releaseManifestKeyID(publicKey), Payload: base64.RawURLEncoding.EncodeToString(payload),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, releaseManifestSignedMessage(payload))),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type errorReleaseReader struct{}

func (errorReleaseReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
