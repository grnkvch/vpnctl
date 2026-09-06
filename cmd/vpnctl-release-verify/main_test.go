package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestReleaseVerifierChecksAllAssetsAndBundle(t *testing.T) {
	t.Parallel()
	directory := buildVerificationFixture(t)
	result, err := verifyFixtureReleaseAssets(directory, "v2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "passed" || result.Version != "v2.0.0" || result.Platform != "ubuntu-24.04-amd64" ||
		result.Integrity != "sha256-and-bundle-verified" || result.Bundle != "manifest-and-artifacts-verified" ||
		result.Migration != "backward-reversible" {
		t.Fatalf("release verification result = %+v", result)
	}
}

func TestReleaseVerifierRejectsTamperingVersionModesAndSymlinks(t *testing.T) {
	t.Parallel()
	t.Run("binary tampering", func(t *testing.T) {
		directory := buildVerificationFixture(t)
		path := filepath.Join(directory, lifecycle.ReleaseBinaryAsset)
		if err := os.WriteFile(path, []byte("tampered"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyFixtureReleaseAssets(directory, "v2.0.0"); err == nil {
			t.Fatal("tampered binary passed")
		}
	})
	t.Run("wrong version", func(t *testing.T) {
		directory := buildVerificationFixture(t)
		if _, err := verifyFixtureReleaseAssets(directory, "v2.0.1"); err == nil {
			t.Fatal("wrong release version passed")
		}
	})
	t.Run("unsafe mode", func(t *testing.T) {
		directory := buildVerificationFixture(t)
		if err := os.Chmod(filepath.Join(directory, lifecycle.ReleaseChecksumsAsset), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyFixtureReleaseAssets(directory, "v2.0.0"); err == nil {
			t.Fatal("unexpected checksum metadata mode passed")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		directory := buildVerificationFixture(t)
		path := filepath.Join(directory, lifecycle.ReleaseChecksumsAsset)
		target := filepath.Join(t.TempDir(), "checksums-copy")
		content, err := os.ReadFile(path)
		if err != nil || os.WriteFile(target, content, 0o644) != nil || os.Remove(path) != nil || os.Symlink(target, path) != nil {
			t.Fatal("prepare symlink fixture")
		}
		if _, err := verifyFixtureReleaseAssets(directory, "v2.0.0"); err == nil {
			t.Fatal("symlinked checksum metadata passed")
		}
	})
	t.Run("unexpected signature asset", func(t *testing.T) {
		directory := buildVerificationFixture(t)
		if err := os.WriteFile(filepath.Join(directory, "release-checksums.txt.sig"), []byte("obsolete"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyFixtureReleaseAssets(directory, "v2.0.0"); err == nil {
			t.Fatal("release with detached signature was not rejected as a non-three-asset release")
		}
	})
}

func TestProductionReleaseManifestContractRequiresEveryPinnedComponent(t *testing.T) {
	t.Parallel()
	binary := []byte("vpnctl")
	checksums := lifecycle.ReleaseChecksums{
		Version: "v2.0.0",
		Binary: lifecycle.ReleaseChecksumRecord{
			Name: lifecycle.ReleaseBinaryAsset, SHA256: digest(binary), SizeBytes: int64(len(binary)),
		},
	}
	manifest, err := lifecycle.NewV2ReleaseManifest(
		checksums.Version, checksums.Binary.SHA256, checksums.Binary.SizeBytes, true,
	)
	if err != nil || verifyProductionReleaseManifest(manifest, checksums) != nil {
		t.Fatalf("exact production manifest rejected: %v", err)
	}
	manifest.ComponentManifest.Components[0].Version = "unexpected"
	if err := verifyProductionReleaseManifest(manifest, checksums); err == nil {
		t.Fatal("changed production component pin passed")
	}
}

func TestReleaseVerifierRejectsIncompleteArguments(t *testing.T) {
	t.Parallel()
	if _, err := runReleaseVerification(nil); err == nil {
		t.Fatal("missing verifier arguments passed")
	}
	if _, err := runReleaseVerification([]string{"unexpected"}); err == nil {
		t.Fatal("positional verifier argument passed")
	}
}

func buildVerificationFixture(t *testing.T) string {
	t.Helper()
	binary := []byte("vpnctl release verifier fixture")
	binarySHA256 := digest(binary)
	manifest := lifecycle.ReleaseManifest{
		SchemaVersion: lifecycle.ReleaseManifestSchemaVersion,
		ComponentManifest: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0",
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: 1, StateSchemaMaximum: 1,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1,
			MigrationReversible: true,
			Components: []model.ComponentPin{
				{Name: "nftables", Version: "1.0.9", Source: "ubuntu-24.04-noble", Capabilities: []string{"atomic-ruleset"}},
				{Name: "vpnctl", Version: "v2.0.0", Source: "vpnctl-release-bundle", Bundled: true, SHA256: binarySHA256, Capabilities: []string{"cli"}},
			},
		},
		Artifacts: []lifecycle.ReleaseArtifact{{
			Component: "vpnctl", Path: "bin/vpnctl", SHA256: binarySHA256, SizeBytes: int64(len(binary)),
			Roles: []model.Role{model.RoleGateway, model.RoleNode},
		}},
		APTPackages: []lifecycle.APTPackageCompatibility{{
			Component: "nftables", Package: "nftables", Source: "ubuntu-24.04-noble",
			MinimumVersion: "1.0.9-1build1", MaximumVersionExclusive: "1.1",
			Roles: []model.Role{model.RoleGateway, model.RoleNode}, Capabilities: []string{"atomic-ruleset"},
		}},
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	var bundle bytes.Buffer
	if err := lifecycle.BuildReleaseBundle(&bundle, manifest, map[string][]byte{"bin/vpnctl": binary}); err != nil {
		t.Fatal(err)
	}
	checksums, err := lifecycle.NewReleaseChecksums(
		"v2.0.0", binarySHA256, int64(len(binary)), digest(bundle.Bytes()), int64(bundle.Len()),
	)
	if err != nil {
		t.Fatal(err)
	}
	checksumsEncoded, err := lifecycle.EncodeReleaseChecksums(checksums)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	writeFixtureAsset(t, directory, lifecycle.ReleaseBinaryAsset, binary, 0o755)
	writeFixtureAsset(t, directory, lifecycle.ReleaseBundleAsset, bundle.Bytes(), 0o644)
	writeFixtureAsset(t, directory, lifecycle.ReleaseChecksumsAsset, checksumsEncoded, 0o644)
	return directory
}

func verifyFixtureReleaseAssets(directory, version string) (releaseVerificationResult, error) {
	return verifyReleaseAssetsWithContract(
		directory,
		version,
		func(manifest lifecycle.ReleaseManifest, checksums lifecycle.ReleaseChecksums) error {
			if manifest.ComponentManifest.VPNCTLVersion != checksums.Version {
				return os.ErrInvalid
			}
			return nil
		},
	)
}

func writeFixtureAsset(t *testing.T, directory, name string, content []byte, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func digest(content []byte) string {
	value := sha256.Sum256(content)
	return hex.EncodeToString(value[:])
}
