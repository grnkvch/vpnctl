package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestReleaseVerifierAuthenticatesAllAssetsAndBundle(t *testing.T) {
	t.Parallel()
	directory, publicKey := buildVerificationFixture(t)
	result, err := verifyReleaseAssets(directory, "v2.0.0", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "passed" || result.Version != "v2.0.0" || result.Platform != "ubuntu-24.04-amd64" ||
		result.Signature != "ed25519-verified" || result.Bundle != "manifest-and-artifacts-verified" ||
		result.Migration != "backward-reversible" {
		t.Fatalf("release verification result = %+v", result)
	}
}

func TestReleaseVerifierRejectsTamperingVersionModesAndSymlinks(t *testing.T) {
	t.Parallel()
	t.Run("binary tampering", func(t *testing.T) {
		directory, publicKey := buildVerificationFixture(t)
		path := filepath.Join(directory, lifecycle.ReleaseBinaryAsset)
		if err := os.WriteFile(path, []byte("tampered"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyReleaseAssets(directory, "v2.0.0", publicKey); err == nil {
			t.Fatal("tampered binary passed")
		}
	})
	t.Run("wrong version", func(t *testing.T) {
		directory, publicKey := buildVerificationFixture(t)
		if _, err := verifyReleaseAssets(directory, "v2.0.1", publicKey); err == nil {
			t.Fatal("wrong release version passed")
		}
	})
	t.Run("unsafe mode", func(t *testing.T) {
		directory, publicKey := buildVerificationFixture(t)
		if err := os.Chmod(filepath.Join(directory, lifecycle.ReleaseChecksumsAsset), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyReleaseAssets(directory, "v2.0.0", publicKey); err == nil {
			t.Fatal("unexpected checksum metadata mode passed")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		directory, publicKey := buildVerificationFixture(t)
		path := filepath.Join(directory, lifecycle.ReleaseChecksumsSignatureAsset)
		target := filepath.Join(directory, "signature-copy")
		content, err := os.ReadFile(path)
		if err != nil || os.WriteFile(target, content, 0o644) != nil || os.Remove(path) != nil || os.Symlink(target, path) != nil {
			t.Fatal("prepare symlink fixture")
		}
		if _, err := verifyReleaseAssets(directory, "v2.0.0", publicKey); err == nil {
			t.Fatal("symlinked signature passed")
		}
	})
}

func TestReleaseVerifierRejectsIncompleteArguments(t *testing.T) {
	t.Parallel()
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := runReleaseVerification(nil, publicKey); err == nil {
		t.Fatal("missing verifier arguments passed")
	}
	if _, err := runReleaseVerification([]string{"unexpected"}, publicKey); err == nil {
		t.Fatal("positional verifier argument passed")
	}
}

func buildVerificationFixture(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	if err := lifecycle.BuildReleaseBundle(&bundle, manifest, privateKey, map[string][]byte{"bin/vpnctl": binary}); err != nil {
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
	signature, err := lifecycle.SignReleaseChecksums(checksumsEncoded, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	writeFixtureAsset(t, directory, lifecycle.ReleaseBinaryAsset, binary, 0o755)
	writeFixtureAsset(t, directory, lifecycle.ReleaseBundleAsset, bundle.Bytes(), 0o644)
	writeFixtureAsset(t, directory, lifecycle.ReleaseChecksumsAsset, checksumsEncoded, 0o644)
	writeFixtureAsset(t, directory, lifecycle.ReleaseChecksumsSignatureAsset, signature, 0o644)
	return directory, publicKey
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
