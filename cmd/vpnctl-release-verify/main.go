// vpnctl-release-verify is a maintainer-side release gate. It is not shipped
// to managed hosts and performs no installation or network access.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/releasetrust"
)

const maximumReleaseMetadataBytes = int64(4096)

type releaseVerificationResult struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	BinarySHA256  string `json:"binary_sha256"`
	BinaryBytes   int64  `json:"binary_bytes"`
	BundleSHA256  string `json:"bundle_sha256"`
	BundleBytes   int64  `json:"bundle_bytes"`
	Platform      string `json:"platform"`
	Signature     string `json:"signature"`
	Bundle        string `json:"bundle"`
	Migration     string `json:"migration"`
}

func main() {
	publicKey, err := releasetrust.PublicKey()
	if err == nil {
		var result releaseVerificationResult
		result, err = runReleaseVerification(os.Args[1:], publicKey)
		if err == nil {
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetEscapeHTML(false)
			err = encoder.Encode(result)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnctl release verification failed")
		os.Exit(1)
	}
}

func runReleaseVerification(arguments []string, publicKey ed25519.PublicKey) (releaseVerificationResult, error) {
	flags := flag.NewFlagSet("vpnctl-release-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var assetsDirectory, expectedVersion string
	flags.StringVar(&assetsDirectory, "assets", "", "absolute directory containing signed release assets")
	flags.StringVar(&expectedVersion, "version", "", "expected canonical stable release version")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return releaseVerificationResult{}, errors.New("invalid arguments")
	}
	return verifyReleaseAssets(assetsDirectory, expectedVersion, publicKey)
}

func verifyReleaseAssets(directory, expectedVersion string, publicKey ed25519.PublicKey) (releaseVerificationResult, error) {
	canonicalVersion, err := lifecycle.CanonicalStableReleaseVersion(expectedVersion)
	if err != nil || canonicalVersion != expectedVersion {
		return releaseVerificationResult{}, errors.New("expected version must be canonical")
	}
	if len(publicKey) != ed25519.PublicKeySize || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return releaseVerificationResult{}, errors.New("release verification input is invalid")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return releaseVerificationResult{}, errors.New("release asset directory is invalid")
	}

	checksumsPath := filepath.Join(directory, lifecycle.ReleaseChecksumsAsset)
	signaturePath := filepath.Join(directory, lifecycle.ReleaseChecksumsSignatureAsset)
	checksumsEncoded, err := readBoundedReleaseAsset(checksumsPath, maximumReleaseMetadataBytes, 0o644)
	if err != nil {
		return releaseVerificationResult{}, err
	}
	signature, err := readBoundedReleaseAsset(signaturePath, ed25519.SignatureSize, 0o644)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return releaseVerificationResult{}, errors.New("release checksum signature is invalid")
	}
	checksums, err := lifecycle.VerifyReleaseChecksums(checksumsEncoded, signature, publicKey)
	if err != nil || checksums.Version != expectedVersion {
		return releaseVerificationResult{}, errors.New("release checksums are invalid")
	}
	if err := verifyReleaseRecord(directory, checksums.Binary, 0o755); err != nil {
		return releaseVerificationResult{}, err
	}
	if err := verifyReleaseRecord(directory, checksums.Bundle, 0o644); err != nil {
		return releaseVerificationResult{}, err
	}

	installer, err := lifecycle.NewReleaseBundleInstaller(directory, publicKey, lifecycle.ReleasePlatform{
		OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64",
	})
	if err != nil {
		return releaseVerificationResult{}, errors.New("release bundle verifier is unavailable")
	}
	manifest, err := installer.Inspect(context.Background(), filepath.Join(directory, lifecycle.ReleaseBundleAsset))
	if err != nil || manifest.ComponentManifest.VPNCTLVersion != expectedVersion || !manifest.ComponentManifest.MigrationReversible {
		return releaseVerificationResult{}, errors.New("release bundle manifest is invalid")
	}
	var binaryMatched bool
	for _, artifact := range manifest.Artifacts {
		if artifact.Component == "vpnctl" && artifact.Path == "bin/vpnctl" &&
			artifact.SHA256 == checksums.Binary.SHA256 && artifact.SizeBytes == checksums.Binary.SizeBytes {
			binaryMatched = true
		}
	}
	if !binaryMatched {
		return releaseVerificationResult{}, errors.New("standalone binary differs from signed bundle")
	}
	return releaseVerificationResult{
		SchemaVersion: 1, Status: "passed", Version: expectedVersion,
		BinarySHA256: checksums.Binary.SHA256, BinaryBytes: checksums.Binary.SizeBytes,
		BundleSHA256: checksums.Bundle.SHA256, BundleBytes: checksums.Bundle.SizeBytes,
		Platform: "ubuntu-24.04-amd64", Signature: "ed25519-verified",
		Bundle: "manifest-and-artifacts-verified", Migration: "backward-reversible",
	}, nil
}

func readBoundedReleaseAsset(path string, maximum int64, mode fs.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() <= 0 || info.Size() > maximum || info.Mode().Perm() != mode {
		return nil, errors.New("release asset is invalid")
	}
	content, err := os.ReadFile(path)
	if err != nil || int64(len(content)) != info.Size() {
		return nil, errors.New("release asset could not be read completely")
	}
	return content, nil
}

func verifyReleaseRecord(directory string, record lifecycle.ReleaseChecksumRecord, mode fs.FileMode) error {
	path := filepath.Join(directory, record.Name)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() != record.SizeBytes || info.Mode().Perm() != mode {
		return errors.New("signed release artifact is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("signed release artifact could not be opened")
	}
	verifyErr := lifecycle.VerifyReleaseChecksumRecord(record, info.Size(), file)
	closeErr := file.Close()
	if verifyErr != nil || closeErr != nil {
		return errors.New("signed release artifact checksum is invalid")
	}
	return nil
}
