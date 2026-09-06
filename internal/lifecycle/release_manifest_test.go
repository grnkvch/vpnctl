package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestCanonicalReleaseManifestBindsCompleteReleaseContract(t *testing.T) {
	t.Parallel()
	manifest, artifacts := releaseManifestFixture()
	encoded, err := EncodeReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := DecodeReleaseManifest(encoded)
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
		t.Fatalf("compatibility contract = %+v", component)
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
	again, err := DecodeReleaseManifest(encoded)
	if err != nil || again.Artifacts[0].Roles[0] != model.RoleGateway || again.ComponentManifest.Components[0].Capabilities[0] == "mutated" {
		t.Fatalf("caller mutation changed decoded manifest: %+v, %v", again, err)
	}
}

func TestV2ReleaseManifestUsesRuntimeProviderPinsAndAptRanges(t *testing.T) {
	t.Parallel()
	vpnctlHash := strings.Repeat("a", 64)
	manifest, err := NewV2ReleaseManifest("v2.0.0", vpnctlHash, 12345, true)
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
	if _, err := NewV2ReleaseManifest("v2.0.0", "invalid", 12345, true); !errors.Is(err, ErrInvalidReleaseManifest) {
		t.Fatalf("invalid vpnctl checksum error = %v", err)
	}
	if _, err := NewV2ReleaseManifest("", vpnctlHash, 12345, true); !errors.Is(err, ErrInvalidReleaseManifest) {
		t.Fatalf("invalid vpnctl version error = %v", err)
	}
}

func TestReleaseManifestRejectsAmbiguousOrNonCanonicalJSON(t *testing.T) {
	t.Parallel()
	manifest, _ := releaseManifestFixture()
	encoded, _ := EncodeReleaseManifest(manifest)
	unknownField := append(encoded[:len(encoded)-1], []byte(`,"unknown":true}`)...)
	duplicateField := append([]byte(`{"schema_version":1,`), encoded[1:]...)
	for name, candidate := range map[string][]byte{
		"unknown-field":   unknownField,
		"duplicate-field": duplicateField,
		"multiple-values": append(append([]byte(nil), encoded...), encoded...),
		"leading-space":   append([]byte(" "), encoded...),
	} {
		if _, err := DecodeReleaseManifest(candidate); !errors.Is(err, ErrInvalidReleaseManifest) {
			t.Fatalf("%s error = %v", name, err)
		}
	}

	oversized := bytes.Repeat([]byte{'x'}, MaximumReleaseManifestBytes+1)
	if _, err := DecodeReleaseManifest(oversized); !errors.Is(err, ErrInvalidReleaseManifest) {
		t.Fatalf("oversized manifest error = %v", err)
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
		"artifact-size":                func(value *ReleaseManifest) { value.Artifacts[0].SizeBytes = 0 },
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
	encoded, err := EncodeReleaseManifest(irreversible)
	if err != nil {
		t.Fatalf("explicit irreversible migration rejected: %v", err)
	}
	if !bytes.Contains(encoded, []byte(`"migration_reversible":false`)) {
		t.Fatalf("migration reversibility is absent from manifest: %s", encoded)
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
			{Component: "vpnctl", Path: "bin/vpnctl", SHA256: releaseDigest(artifacts["bin/vpnctl"]), SizeBytes: int64(len(artifacts["bin/vpnctl"])), Roles: []model.Role{model.RoleGateway, model.RoleNode}},
			{Component: "frp", Path: "components/frp-linux-amd64.tgz", SHA256: releaseDigest(artifacts["components/frp-linux-amd64.tgz"]), SizeBytes: int64(len(artifacts["components/frp-linux-amd64.tgz"])), Roles: []model.Role{model.RoleGateway, model.RoleNode}},
			{Component: "mihomo", Path: "components/mihomo-linux-amd64.gz", SHA256: releaseDigest(artifacts["components/mihomo-linux-amd64.gz"]), SizeBytes: int64(len(artifacts["components/mihomo-linux-amd64.gz"])), Roles: []model.Role{model.RoleGateway, model.RoleNode}},
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

type errorReleaseReader struct{}

func (errorReleaseReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
