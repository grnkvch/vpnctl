// vpnctl-release is a maintainer-side builder. It is not shipped to managed
// hosts and never discovers or downloads provider artifacts.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

type releaseBuildOptions struct {
	Version       string
	VPNCTLPath    string
	MihomoPath    string
	FRPPath       string
	OutputDir     string
	MigrationBack bool
}

func main() {
	err := runReleaseBuild(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "vpnctl release build failed: %v\n", err)
		os.Exit(1)
	}
}

func runReleaseBuild(arguments []string) error {
	flags := flag.NewFlagSet("vpnctl-release", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	options := releaseBuildOptions{MigrationBack: true}
	flags.StringVar(&options.Version, "version", "", "vpnctl version")
	flags.StringVar(&options.VPNCTLPath, "vpnctl", "", "standalone linux/amd64 vpnctl binary")
	flags.StringVar(&options.MihomoPath, "mihomo", "", "pinned Mihomo gzip archive")
	flags.StringVar(&options.FRPPath, "frp", "", "pinned frp tar.gz archive")
	flags.StringVar(&options.OutputDir, "output-dir", "", "empty output directory")
	flags.BoolVar(&options.MigrationBack, "migration-reversible", true, "mark state migration backward reversible")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	return buildReleaseAssets(options)
}

func buildReleaseAssets(options releaseBuildOptions) error {
	if options.Version == "" || options.VPNCTLPath == "" || options.MihomoPath == "" || options.FRPPath == "" || options.OutputDir == "" {
		return fmt.Errorf("version, vpnctl, mihomo, frp, and output-dir are required")
	}
	outputInfo, err := os.Lstat(options.OutputDir)
	if err != nil || outputInfo.Mode()&os.ModeSymlink != 0 || !outputInfo.IsDir() || !filepath.IsAbs(options.OutputDir) || filepath.Clean(options.OutputDir) != options.OutputDir {
		return fmt.Errorf("output directory must be an existing clean absolute directory")
	}
	entries, err := os.ReadDir(options.OutputDir)
	if err != nil || len(entries) != 0 {
		return fmt.Errorf("output directory must be empty")
	}
	vpnctlBinary, err := readReleaseBuildInput(options.VPNCTLPath, lifecycle.MaximumStandaloneVPNCTLBytes)
	if err != nil {
		return fmt.Errorf("vpnctl input: %w", err)
	}
	mihomoArchive, err := readReleaseBuildInput(options.MihomoPath, transport.RestrictedProviderSizeBytes)
	if err != nil {
		return fmt.Errorf("Mihomo input: %w", err)
	}
	frpArchive, err := readReleaseBuildInput(options.FRPPath, tunnel.FRPProviderSizeBytes)
	if err != nil {
		return fmt.Errorf("frp input: %w", err)
	}
	vpnctlDigest := releaseBuildDigest(vpnctlBinary)
	manifest, err := lifecycle.NewV2ReleaseManifest(options.Version, vpnctlDigest, int64(len(vpnctlBinary)), options.MigrationBack)
	if err != nil {
		return err
	}
	artifacts := map[string][]byte{
		"bin/vpnctl": vpnctlBinary,
		"components/" + transport.RestrictedProviderAsset: mihomoArchive,
		"components/" + tunnel.FRPProviderAsset:           frpArchive,
	}
	var bundle bytes.Buffer
	if err := lifecycle.BuildReleaseBundle(&bundle, manifest, artifacts); err != nil {
		return err
	}
	checksums, err := lifecycle.NewReleaseChecksums(
		options.Version, vpnctlDigest, int64(len(vpnctlBinary)), releaseBuildDigest(bundle.Bytes()), int64(bundle.Len()),
	)
	if err != nil {
		return err
	}
	encodedChecksums, err := lifecycle.EncodeReleaseChecksums(checksums)
	if err != nil {
		return err
	}
	outputs := []struct {
		name string
		mode fs.FileMode
		data []byte
	}{
		{name: lifecycle.ReleaseBinaryAsset, mode: 0o755, data: vpnctlBinary},
		{name: lifecycle.ReleaseBundleAsset, mode: 0o644, data: bundle.Bytes()},
		{name: lifecycle.ReleaseChecksumsAsset, mode: 0o644, data: encodedChecksums},
	}
	written := make([]string, 0, len(outputs))
	defer func() {
		for _, target := range written {
			_ = os.Remove(target)
		}
	}()
	for _, output := range outputs {
		target := filepath.Join(options.OutputDir, output.name)
		if err := writeReleaseBuildOutput(target, output.data, output.mode); err != nil {
			return err
		}
		written = append(written, target)
	}
	directory, err := os.Open(options.OutputDir)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.Join(syncErr, closeErr)
	}
	written = nil
	return nil
}

func readReleaseBuildInput(inputPath string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(inputPath) || filepath.Clean(inputPath) != inputPath {
		return nil, fmt.Errorf("path must be clean and absolute")
	}
	info, err := os.Lstat(inputPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("input must be a bounded regular non-symlink file")
	}
	content, err := os.ReadFile(inputPath)
	if err != nil || int64(len(content)) != info.Size() {
		return nil, fmt.Errorf("read complete input")
	}
	return content, nil
}

func writeReleaseBuildOutput(target string, content []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		_ = os.Remove(target)
		return err
	}
	_, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(target)
		return errors.Join(writeErr, syncErr, closeErr)
	}
	return nil
}

func releaseBuildDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
