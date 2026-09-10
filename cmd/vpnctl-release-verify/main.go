// vpnctl-release-verify is a maintainer-side release gate. It is not shipped
// to managed hosts and performs no installation or network access.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
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
	Integrity     string `json:"integrity"`
	Bundle        string `json:"bundle"`
	Migration     string `json:"migration"`
}

func main() {
	result, err := runReleaseVerification(os.Args[1:])
	if err == nil {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		err = encoder.Encode(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnctl release verification failed")
		os.Exit(1)
	}
}

func runReleaseVerification(arguments []string) (releaseVerificationResult, error) {
	flags := flag.NewFlagSet("vpnctl-release-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var assetsDirectory, expectedVersion string
	flags.StringVar(&assetsDirectory, "assets", "", "absolute directory containing checksum-governed release assets")
	flags.StringVar(&expectedVersion, "version", "", "expected canonical stable release version")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return releaseVerificationResult{}, errors.New("invalid arguments")
	}
	return verifyReleaseAssets(assetsDirectory, expectedVersion)
}

func verifyReleaseAssets(directory, expectedVersion string) (releaseVerificationResult, error) {
	return verifyReleaseAssetsWithContract(directory, expectedVersion, verifyProductionReleaseManifest)
}

func verifyReleaseAssetsWithContract(
	directory, expectedVersion string,
	manifestContract func(lifecycle.ReleaseManifest, lifecycle.ReleaseChecksums) error,
) (releaseVerificationResult, error) {
	canonicalVersion, err := lifecycle.CanonicalStableReleaseVersion(expectedVersion)
	if err != nil || canonicalVersion != expectedVersion {
		return releaseVerificationResult{}, errors.New("expected version must be canonical")
	}
	if manifestContract == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return releaseVerificationResult{}, errors.New("release verification input is invalid")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return releaseVerificationResult{}, errors.New("release asset directory is invalid")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 3 {
		return releaseVerificationResult{}, errors.New("release directory must contain exactly three assets")
	}
	expectedAssets := map[string]bool{
		lifecycle.ReleaseBinaryAsset: false, lifecycle.ReleaseBundleAsset: false, lifecycle.ReleaseChecksumsAsset: false,
	}
	for _, entry := range entries {
		if _, found := expectedAssets[entry.Name()]; !found {
			return releaseVerificationResult{}, errors.New("release directory contains an unexpected asset")
		}
		expectedAssets[entry.Name()] = true
	}

	checksumsPath := filepath.Join(directory, lifecycle.ReleaseChecksumsAsset)
	checksumsEncoded, err := readBoundedReleaseAsset(checksumsPath, maximumReleaseMetadataBytes, 0o644)
	if err != nil {
		return releaseVerificationResult{}, err
	}
	checksums, err := lifecycle.DecodeReleaseChecksums(checksumsEncoded)
	if err != nil || checksums.Version != expectedVersion {
		return releaseVerificationResult{}, errors.New("release checksums are invalid")
	}
	if err := verifyReleaseRecord(directory, checksums.Binary, 0o755); err != nil {
		return releaseVerificationResult{}, err
	}
	if err := verifyReleaseRecord(directory, checksums.Bundle, 0o644); err != nil {
		return releaseVerificationResult{}, err
	}

	installer, err := lifecycle.NewReleaseBundleInstaller(directory, lifecycle.ReleasePlatform{
		OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64",
	})
	if err != nil {
		return releaseVerificationResult{}, errors.New("release bundle verifier is unavailable")
	}
	manifest, err := installer.InspectInstallable(context.Background(), filepath.Join(directory, lifecycle.ReleaseBundleAsset))
	if err != nil || manifest.ComponentManifest.VPNCTLVersion != expectedVersion || !manifest.ComponentManifest.MigrationReversible {
		return releaseVerificationResult{}, errors.New("release bundle manifest is invalid")
	}
	if err := manifestContract(manifest, checksums); err != nil {
		return releaseVerificationResult{}, errors.New("release bundle differs from the production manifest")
	}
	var binaryMatched bool
	for _, artifact := range manifest.Artifacts {
		if artifact.Component == "vpnctl" && artifact.Path == "bin/vpnctl" &&
			artifact.SHA256 == checksums.Binary.SHA256 && artifact.SizeBytes == checksums.Binary.SizeBytes {
			binaryMatched = true
		}
	}
	if !binaryMatched {
		return releaseVerificationResult{}, errors.New("standalone binary differs from bundle")
	}
	return releaseVerificationResult{
		SchemaVersion: 1, Status: "passed", Version: expectedVersion,
		BinarySHA256: checksums.Binary.SHA256, BinaryBytes: checksums.Binary.SizeBytes,
		BundleSHA256: checksums.Bundle.SHA256, BundleBytes: checksums.Bundle.SizeBytes,
		Platform: "ubuntu-24.04-amd64", Integrity: "sha256-and-bundle-verified",
		Bundle: "manifest-and-artifacts-verified", Migration: "backward-reversible",
	}, nil
}

func verifyProductionReleaseManifest(manifest lifecycle.ReleaseManifest, checksums lifecycle.ReleaseChecksums) error {
	expected, err := lifecycle.NewV2ReleaseManifest(
		checksums.Version, checksums.Binary.SHA256, checksums.Binary.SizeBytes, true,
	)
	if err != nil || !reflect.DeepEqual(manifest, expected) {
		return errors.New("production release manifest mismatch")
	}
	return nil
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
		return errors.New("release artifact is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("release artifact could not be opened")
	}
	verifyErr := lifecycle.VerifyReleaseChecksumRecord(record, info.Size(), file)
	closeErr := file.Close()
	if verifyErr != nil || closeErr != nil {
		return errors.New("release artifact checksum is invalid")
	}
	return nil
}
