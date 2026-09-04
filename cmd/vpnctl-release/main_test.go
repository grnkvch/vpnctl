package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
)

func TestReleaseBuilderRequiresMatchingPrivateKeyAndLeavesNoPartialOutput(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeReleaseBuilderPrivateKey(t, privateKey, 0o600)
	binaryPath := writeReleaseBuilderInput(t, "vpnctl", []byte("vpnctl"))
	mihomoPath := writeReleaseBuilderInput(t, "mihomo.gz", []byte("not-the-pinned-archive"))
	frpPath := writeReleaseBuilderInput(t, "frp.tar.gz", []byte("not-the-pinned-archive"))
	output := t.TempDir()
	err = buildReleaseAssets(releaseBuildOptions{
		Version: "v2.0.0", VPNCTLPath: binaryPath, MihomoPath: mihomoPath, FRPPath: frpPath,
		SigningKey: keyPath, OutputDir: output, MigrationBack: true,
	}, publicKey)
	if err == nil {
		t.Fatal("release builder accepted unpinned provider archives")
	}
	entries, readErr := os.ReadDir(output)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("failed build left partial outputs=%v err=%v", entries, readErr)
	}

	wrongPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := readReleaseSigningKey(keyPath, wrongPublic); err == nil {
		t.Fatal("release builder accepted a key outside the pinned trust anchor")
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readReleaseSigningKey(keyPath, publicKey); err == nil {
		t.Fatal("release builder accepted a group/world-readable signing key")
	}
}

func TestReleaseBuilderPrivateKeyParserReturnsAnIndependentEd25519Key(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := writeReleaseBuilderPrivateKey(t, privateKey, 0o600)
	parsed, err := readReleaseSigningKey(keyPath, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed, privateKey) {
		t.Fatal("parsed signing key differs")
	}
	parsed[0] ^= 1
	again, err := readReleaseSigningKey(keyPath, publicKey)
	if err != nil || bytes.Equal(parsed, again) {
		t.Fatal("signing key parser returned shared mutable storage")
	}
	symlink := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.Symlink(keyPath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readReleaseSigningKey(symlink, publicKey); err == nil {
		t.Fatal("release builder accepted a signing-key symlink")
	}
}

func TestReleaseBuilderRejectsIncompleteArguments(t *testing.T) {
	t.Parallel()
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := runReleaseBuild(nil, publicKey); err == nil {
		t.Fatal("release builder accepted missing arguments")
	}
	if err := runReleaseBuild([]string{"unexpected"}, publicKey); err == nil {
		t.Fatal("release builder accepted a positional argument")
	}
}

func TestReleaseBuilderWithPinnedProviderArchives(t *testing.T) {
	mihomoPath := os.Getenv("VPNCTL_TEST_MIHOMO_ARCHIVE")
	frpPath := os.Getenv("VPNCTL_TEST_FRP_ARCHIVE")
	if mihomoPath == "" || frpPath == "" {
		t.Skip("set pinned provider archive paths for the native release-builder gate")
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := writeReleaseBuilderPrivateKey(t, privateKey, 0o600)
	binary := []byte("vpnctl-linux-amd64-release-gate")
	binaryPath := writeReleaseBuilderInput(t, "vpnctl", binary)
	output := t.TempDir()
	if err := buildReleaseAssets(releaseBuildOptions{
		Version: "v2.0.0-test", VPNCTLPath: binaryPath, MihomoPath: mihomoPath, FRPPath: frpPath,
		SigningKey: keyPath, OutputDir: output, MigrationBack: true,
	}, publicKey); err != nil {
		t.Fatal(err)
	}
	secondOutput := t.TempDir()
	if err := buildReleaseAssets(releaseBuildOptions{
		Version: "v2.0.0-test", VPNCTLPath: binaryPath, MihomoPath: mihomoPath, FRPPath: frpPath,
		SigningKey: keyPath, OutputDir: secondOutput, MigrationBack: true,
	}, publicKey); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		lifecycle.ReleaseBinaryAsset, lifecycle.ReleaseBundleAsset,
		lifecycle.ReleaseChecksumsAsset, lifecycle.ReleaseChecksumsSignatureAsset,
	} {
		first, firstErr := os.ReadFile(filepath.Join(output, name))
		second, secondErr := os.ReadFile(filepath.Join(secondOutput, name))
		if firstErr != nil || secondErr != nil || !bytes.Equal(first, second) {
			t.Fatalf("repeated release output %s differs: %v/%v", name, firstErr, secondErr)
		}
	}
	checksumsBytes, err := os.ReadFile(filepath.Join(output, lifecycle.ReleaseChecksumsAsset))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile(filepath.Join(output, lifecycle.ReleaseChecksumsSignatureAsset))
	if err != nil {
		t.Fatal(err)
	}
	checksums, err := lifecycle.VerifyReleaseChecksums(checksumsBytes, signature, publicKey)
	if err != nil || checksums.Version != "v2.0.0-test" {
		t.Fatalf("signed output metadata=%+v err=%v", checksums, err)
	}
	for _, record := range []lifecycle.ReleaseChecksumRecord{checksums.Binary, checksums.Bundle} {
		path := filepath.Join(output, record.Name)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		verifyErr := lifecycle.VerifyReleaseChecksumRecord(record, info.Size(), file)
		closeErr := file.Close()
		if verifyErr != nil || closeErr != nil {
			t.Fatalf("verify %s: %v/%v", record.Name, verifyErr, closeErr)
		}
	}
	installRoot := t.TempDir()
	installer, err := lifecycle.NewReleaseBundleInstaller(installRoot, publicKey, lifecycle.ReleasePlatform{
		OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := installer.Inspect(context.Background(), filepath.Join(output, lifecycle.ReleaseBundleAsset))
	if err != nil || manifest.ComponentManifest.VPNCTLVersion != "v2.0.0-test" {
		t.Fatalf("inspect built bundle version=%q err=%v", manifest.ComponentManifest.VPNCTLVersion, err)
	}
}

func writeReleaseBuilderPrivateKey(t *testing.T, key ed25519.PrivateKey, mode os.FileMode) string {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeReleaseBuilderInput(t *testing.T, name string, value []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
