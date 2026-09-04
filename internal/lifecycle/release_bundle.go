package lifecycle

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const (
	releaseBundleMagic             = "VPNCTLBUNDLE\x00\x01"
	maximumReleaseBundleBytes      = int64(MaximumSignedReleaseManifestBytes) + maximumReleaseArtifactTotalBytes + 64<<10
	maximumInstalledComponentBytes = int64(128 << 20)
)

var (
	ErrInvalidReleaseBundle   = errors.New("invalid release bundle")
	ErrReleaseInstallConflict = errors.New("release installation conflict")
)

type ReleaseBundleInstallResult struct {
	Manifest            ReleaseManifest
	ChangedFiles        []string
	RequiredAPTPackages []APTPackageCompatibility
}

type ReleaseBundleInstaller struct {
	root      string
	publicKey ed25519.PublicKey
	platform  ReleasePlatform
}

type InitReleaseSource interface {
	Inspect(context.Context) (ReleaseManifest, error)
	Install(context.Context, model.Role) (ReleaseBundleInstallResult, error)
}

type LocalInitReleaseSource struct {
	installer *ReleaseBundleInstaller
	bundle    string
}

type stagedReleaseBundle struct {
	manifest  ReleaseManifest
	root      string
	artifacts map[string]string
}

type releaseInstallCandidate struct {
	target string
	source string
}

// BuildReleaseBundle writes a timestamp-free, owner-free binary stream. The
// signed manifest and its canonical artifact order make equal inputs produce
// equal output without depending on tar metadata or the current filesystem.
func BuildReleaseBundle(writer io.Writer, manifest ReleaseManifest, privateKey ed25519.PrivateKey, artifacts map[string][]byte) error {
	if writer == nil {
		return releaseBundleInvalid("writer is required")
	}
	if err := manifest.Validate(); err != nil {
		return releaseBundleInvalid("manifest: %v", err)
	}
	if len(artifacts) != len(manifest.Artifacts) {
		return releaseBundleInvalid("artifact set does not match signed manifest")
	}
	for _, artifact := range manifest.Artifacts {
		content, found := artifacts[artifact.Path]
		if !found || int64(len(content)) != artifact.SizeBytes {
			return releaseBundleInvalid("artifact %s size does not match manifest", artifact.Path)
		}
		if err := VerifyReleaseArtifact(manifest, artifact.Path, bytesReader(content)); err != nil {
			return releaseBundleInvalid("artifact %s: %v", artifact.Path, err)
		}
	}
	signed, err := EncodeSignedReleaseManifest(manifest, privateKey)
	if err != nil {
		return releaseBundleInvalid("sign manifest: %v", err)
	}
	if err := writeReleaseBundleBytes(writer, []byte(releaseBundleMagic)); err != nil {
		return err
	}
	if err := writeReleaseBundleUint32(writer, uint32(len(signed))); err != nil {
		return err
	}
	if err := writeReleaseBundleBytes(writer, signed); err != nil {
		return err
	}
	for _, artifact := range manifest.Artifacts {
		if err := writeReleaseBundleUint16(writer, uint16(len(artifact.Path))); err != nil {
			return err
		}
		if err := writeReleaseBundleBytes(writer, []byte(artifact.Path)); err != nil {
			return err
		}
		if err := writeReleaseBundleUint64(writer, uint64(artifact.SizeBytes)); err != nil {
			return err
		}
		if err := writeReleaseBundleBytes(writer, artifacts[artifact.Path]); err != nil {
			return err
		}
	}
	return nil
}

func NewReleaseBundleInstaller(root string, publicKey ed25519.PublicKey, platform ReleasePlatform) (*ReleaseBundleInstaller, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fmt.Errorf("release install root must be clean and absolute")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("release verification key must be Ed25519")
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("release install root must be a real directory")
	}
	return &ReleaseBundleInstaller{
		root: root, publicKey: append(ed25519.PublicKey(nil), publicKey...), platform: platform,
	}, nil
}

func NewLocalInitReleaseSource(installer *ReleaseBundleInstaller, bundlePath string) (*LocalInitReleaseSource, error) {
	if installer == nil || !filepath.IsAbs(bundlePath) || filepath.Clean(bundlePath) != bundlePath {
		return nil, fmt.Errorf("local init release source requires an installer and clean absolute bundle path")
	}
	return &LocalInitReleaseSource{installer: installer, bundle: bundlePath}, nil
}

func (source *LocalInitReleaseSource) Inspect(ctx context.Context) (ReleaseManifest, error) {
	if source == nil || source.installer == nil {
		return ReleaseManifest{}, fmt.Errorf("local init release source is incomplete")
	}
	return source.installer.Inspect(ctx, source.bundle)
}

func (source *LocalInitReleaseSource) Install(ctx context.Context, role model.Role) (ReleaseBundleInstallResult, error) {
	if source == nil || source.installer == nil {
		return ReleaseBundleInstallResult{}, fmt.Errorf("local init release source is incomplete")
	}
	return source.installer.Install(ctx, source.bundle, role)
}

func (installer *ReleaseBundleInstaller) Install(ctx context.Context, bundlePath string, role model.Role) (ReleaseBundleInstallResult, error) {
	if ctx == nil {
		return ReleaseBundleInstallResult{}, fmt.Errorf("context is required")
	}
	if installer == nil || len(installer.publicKey) != ed25519.PublicKeySize {
		return ReleaseBundleInstallResult{}, fmt.Errorf("release bundle installer is incomplete")
	}
	if role != model.RoleGateway && role != model.RoleNode {
		return ReleaseBundleInstallResult{}, releaseBundleInvalid("unsupported install role %q", role)
	}
	staged, err := installer.stage(ctx, bundlePath)
	if err != nil {
		return ReleaseBundleInstallResult{}, err
	}
	defer os.RemoveAll(staged.root)

	candidates, err := installer.prepareCandidates(ctx, staged, role)
	if err != nil {
		return ReleaseBundleInstallResult{}, err
	}
	if err := preflightReleaseCandidates(candidates); err != nil {
		return ReleaseBundleInstallResult{}, err
	}
	createdDirectories, err := installer.ensureTargetDirectories(candidates)
	if err != nil {
		return ReleaseBundleInstallResult{}, err
	}
	changed := make([]string, 0, len(candidates))
	rollback := func() {
		for index := len(changed) - 1; index >= 0; index-- {
			_ = os.Remove(changed[index])
		}
		for index := len(createdDirectories) - 1; index >= 0; index-- {
			_ = os.Remove(createdDirectories[index])
		}
	}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			rollback()
			return ReleaseBundleInstallResult{}, err
		}
		updated, err := installReleaseCandidate(candidate)
		if err != nil {
			rollback()
			return ReleaseBundleInstallResult{}, err
		}
		if updated {
			changed = append(changed, candidate.target)
		}
	}
	return ReleaseBundleInstallResult{
		Manifest: cloneReleaseManifest(staged.manifest), ChangedFiles: changed,
		RequiredAPTPackages: releaseAPTPackagesForRole(staged.manifest, role),
	}, nil
}

// Inspect verifies the complete local bundle without creating a staging or
// install file. Init uses it while building a read-only role plan, then Install
// repeats the verification immediately before mutation.
func (installer *ReleaseBundleInstaller) Inspect(ctx context.Context, bundlePath string) (ReleaseManifest, error) {
	if ctx == nil {
		return ReleaseManifest{}, fmt.Errorf("context is required")
	}
	if installer == nil || len(installer.publicKey) != ed25519.PublicKeySize {
		return ReleaseManifest{}, fmt.Errorf("release bundle installer is incomplete")
	}
	input, manifest, err := installer.open(bundlePath)
	if err != nil {
		return ReleaseManifest{}, err
	}
	defer input.Close()
	if _, err := consumeReleaseBundleArtifacts(ctx, input, manifest, ""); err != nil {
		return ReleaseManifest{}, err
	}
	return cloneReleaseManifest(manifest), nil
}

func (installer *ReleaseBundleInstaller) open(bundlePath string) (*os.File, ReleaseManifest, error) {
	if !filepath.IsAbs(bundlePath) || filepath.Clean(bundlePath) != bundlePath {
		return nil, ReleaseManifest{}, releaseBundleInvalid("bundle path must be clean and absolute")
	}
	info, err := os.Lstat(bundlePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumReleaseBundleBytes {
		return nil, ReleaseManifest{}, releaseBundleInvalid("bundle must be a bounded regular file")
	}
	input, err := os.Open(bundlePath)
	if err != nil {
		return nil, ReleaseManifest{}, releaseBundleInvalid("open bundle")
	}
	magic := make([]byte, len(releaseBundleMagic))
	if _, err := io.ReadFull(input, magic); err != nil || string(magic) != releaseBundleMagic {
		_ = input.Close()
		return nil, ReleaseManifest{}, releaseBundleInvalid("bundle magic is invalid")
	}
	manifestLength, err := readReleaseBundleUint32(input)
	if err != nil || manifestLength == 0 || manifestLength > MaximumSignedReleaseManifestBytes {
		_ = input.Close()
		return nil, ReleaseManifest{}, releaseBundleInvalid("signed manifest length is invalid")
	}
	signed := make([]byte, manifestLength)
	if _, err := io.ReadFull(input, signed); err != nil {
		_ = input.Close()
		return nil, ReleaseManifest{}, releaseBundleInvalid("signed manifest is truncated")
	}
	manifest, err := DecodeAndVerifyReleaseManifest(signed, installer.publicKey)
	if err != nil {
		_ = input.Close()
		return nil, ReleaseManifest{}, releaseBundleInvalid("verify signed manifest: %v", err)
	}
	if err := VerifyReleasePlatform(manifest, installer.platform); err != nil {
		_ = input.Close()
		return nil, ReleaseManifest{}, err
	}
	return input, manifest, nil
}

func (installer *ReleaseBundleInstaller) stage(ctx context.Context, bundlePath string) (*stagedReleaseBundle, error) {
	input, manifest, err := installer.open(bundlePath)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	stageRoot, err := os.MkdirTemp("", "vpnctl-release-bundle-")
	if err != nil {
		return nil, releaseBundleInvalid("create bundle stage")
	}
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		_ = os.RemoveAll(stageRoot)
		return nil, releaseBundleInvalid("secure bundle stage")
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(stageRoot)
		}
	}()
	artifacts, err := consumeReleaseBundleArtifacts(ctx, input, manifest, stageRoot)
	if err != nil {
		return nil, err
	}
	keep = true
	return &stagedReleaseBundle{manifest: manifest, root: stageRoot, artifacts: artifacts}, nil
}

func consumeReleaseBundleArtifacts(ctx context.Context, input io.Reader, manifest ReleaseManifest, stageRoot string) (map[string]string, error) {
	artifacts := make(map[string]string, len(manifest.Artifacts))
	for index, artifact := range manifest.Artifacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pathLength, err := readReleaseBundleUint16(input)
		if err != nil || pathLength == 0 || int(pathLength) > 255 {
			return nil, releaseBundleInvalid("artifact %d path framing is invalid", index)
		}
		pathBytes := make([]byte, pathLength)
		if _, err := io.ReadFull(input, pathBytes); err != nil || string(pathBytes) != artifact.Path {
			return nil, releaseBundleInvalid("artifact %d path differs from signed order", index)
		}
		size, err := readReleaseBundleUint64(input)
		if err != nil || size != uint64(artifact.SizeBytes) {
			return nil, releaseBundleInvalid("artifact %s size differs from signed manifest", artifact.Path)
		}
		digest := sha256.New()
		var stagedPath string
		var output *os.File
		writer := io.Writer(digest)
		if stageRoot != "" {
			stagedPath = filepath.Join(stageRoot, fmt.Sprintf("%02d.artifact", index))
			output, err = os.OpenFile(stagedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return nil, releaseBundleInvalid("create artifact stage")
			}
			writer = io.MultiWriter(output, digest)
		}
		_, copyErr := io.CopyN(writer, input, artifact.SizeBytes)
		var syncErr, closeErr error
		if output != nil {
			syncErr = output.Sync()
			closeErr = output.Close()
		}
		if copyErr != nil || syncErr != nil || closeErr != nil {
			return nil, releaseBundleInvalid("artifact %s is truncated", artifact.Path)
		}
		if hex.EncodeToString(digest.Sum(nil)) != artifact.SHA256 {
			return nil, releaseBundleInvalid("artifact %s checksum differs from signed manifest", artifact.Path)
		}
		if stageRoot != "" {
			artifacts[artifact.Component] = stagedPath
		}
	}
	var trailing [1]byte
	if count, err := input.Read(trailing[:]); count != 0 || !errors.Is(err, io.EOF) {
		return nil, releaseBundleInvalid("bundle contains unsigned trailing bytes")
	}
	return artifacts, nil
}

func (installer *ReleaseBundleInstaller) prepareCandidates(ctx context.Context, staged *stagedReleaseBundle, role model.Role) ([]releaseInstallCandidate, error) {
	result := make([]releaseInstallCandidate, 0, len(staged.manifest.Artifacts))
	for _, artifact := range staged.manifest.Artifacts {
		if !releaseRolesContain(artifact.Roles, role) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		source := staged.artifacts[artifact.Component]
		switch artifact.Component {
		case "vpnctl":
			result = append(result, releaseInstallCandidate{target: filepath.Join(installer.root, strings.TrimPrefix(linuxplatform.DefaultVPNCTLBinaryPath, "/")), source: source})
		case transport.RestrictedProviderName:
			extracted := filepath.Join(staged.root, "mihomo")
			if err := extractReleaseGzipBinary(source, extracted); err != nil {
				return nil, err
			}
			result = append(result, releaseInstallCandidate{target: filepath.Join(installer.root, transport.RestrictedBinaryRelativePath), source: extracted})
		case tunnel.FRPProviderName:
			binary := "frpc"
			target := tunnel.FRPClientBinaryRelativePath
			if role == model.RoleGateway {
				binary, target = "frps", tunnel.FRPServerBinaryRelativePath
			}
			extracted := filepath.Join(staged.root, binary)
			if err := extractReleaseFRPBinary(source, extracted, binary); err != nil {
				return nil, err
			}
			result = append(result, releaseInstallCandidate{target: filepath.Join(installer.root, target), source: extracted})
		default:
			return nil, releaseBundleInvalid("bundled component %s has no role installer", artifact.Component)
		}
	}
	if len(result) == 0 {
		return nil, releaseBundleInvalid("bundle contains no components for role %s", role)
	}
	return result, nil
}

func (installer *ReleaseBundleInstaller) ensureTargetDirectories(candidates []releaseInstallCandidate) ([]string, error) {
	created := make([]string, 0)
	seen := make(map[string]struct{})
	for _, candidate := range candidates {
		directory := filepath.Dir(candidate.target)
		if _, found := seen[directory]; found {
			continue
		}
		paths, err := ensureReleaseDirectory(installer.root, directory)
		if err != nil {
			for index := len(created) - 1; index >= 0; index-- {
				_ = os.Remove(created[index])
			}
			return nil, err
		}
		created = append(created, paths...)
		seen[directory] = struct{}{}
	}
	return created, nil
}

func preflightReleaseCandidates(candidates []releaseInstallCandidate) error {
	for _, candidate := range candidates {
		sourceInfo, err := os.Lstat(candidate.source)
		if err != nil || sourceInfo.Mode()&os.ModeSymlink != 0 || !sourceInfo.Mode().IsRegular() || sourceInfo.Size() <= 0 {
			return releaseBundleInvalid("staged component is unavailable")
		}
		info, err := os.Lstat(candidate.target)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: target %s is not an owned regular file", ErrReleaseInstallConflict, candidate.target)
		}
		equal, err := equalReleaseFiles(candidate.target, candidate.source)
		if err != nil || !equal || info.Mode().Perm() != 0o755 {
			return fmt.Errorf("%w: target %s differs from selected bundle", ErrReleaseInstallConflict, candidate.target)
		}
	}
	return nil
}

func installReleaseCandidate(candidate releaseInstallCandidate) (bool, error) {
	if info, err := os.Lstat(candidate.target); err == nil {
		equal, compareErr := equalReleaseFiles(candidate.target, candidate.source)
		if compareErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 || !equal {
			return false, fmt.Errorf("%w: target %s changed after preflight", ErrReleaseInstallConflict, candidate.target)
		}
		return false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	source, err := os.Open(candidate.source)
	if err != nil {
		return false, err
	}
	defer source.Close()
	temporary, err := os.CreateTemp(filepath.Dir(candidate.target), ".vpnctl-release-*.tmp")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o755); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if _, err := io.Copy(temporary, source); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Link(temporaryPath, candidate.target); err != nil {
		return false, err
	}
	directory, err := os.Open(filepath.Dir(candidate.target))
	if err != nil {
		_ = os.Remove(candidate.target)
		return false, err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		_ = os.Remove(candidate.target)
		return false, errors.Join(syncErr, closeErr)
	}
	return true, nil
}

func ensureReleaseDirectory(root, target string) ([]string, error) {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, releaseBundleInvalid("install directory escapes root")
	}
	current := root
	created := make([]string, 0)
	for _, segment := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Mkdir(current, 0o755); err != nil {
				return created, err
			}
			created = append(created, current)
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return created, fmt.Errorf("%w: install directory %s is not a real directory", ErrReleaseInstallConflict, current)
		}
	}
	return created, nil
}

func extractReleaseGzipBinary(archivePath, target string) error {
	archive, err := os.Open(archivePath)
	if err != nil {
		return releaseBundleInvalid("open Mihomo archive")
	}
	defer archive.Close()
	buffered := bufio.NewReader(archive)
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return releaseBundleInvalid("decode Mihomo archive")
	}
	compressed.Multistream(false)
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = compressed.Close()
		return err
	}
	count, copyErr := io.Copy(output, io.LimitReader(compressed, maximumInstalledComponentBytes+1))
	closeCompressedErr := compressed.Close()
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || closeCompressedErr != nil || syncErr != nil || closeErr != nil || count <= 0 || count > maximumInstalledComponentBytes {
		_ = os.Remove(target)
		return releaseBundleInvalid("Mihomo archive payload is invalid")
	}
	if _, err := buffered.Peek(1); !errors.Is(err, io.EOF) {
		_ = os.Remove(target)
		return releaseBundleInvalid("Mihomo archive has trailing data")
	}
	return nil
}

func extractReleaseFRPBinary(archivePath, target, binaryName string) error {
	archive, err := os.Open(archivePath)
	if err != nil {
		return releaseBundleInvalid("open frp archive")
	}
	defer archive.Close()
	buffered := bufio.NewReader(archive)
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return releaseBundleInvalid("decode frp archive")
	}
	compressed.Multistream(false)
	tarReader := tar.NewReader(compressed)
	expected := "frp_" + tunnel.FRPProviderVersion + "_linux_amd64/" + binaryName
	found := false
	var total int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Size < 0 || header.Size > maximumInstalledComponentBytes || total > maximumInstalledComponentBytes-header.Size {
			_ = compressed.Close()
			_ = os.Remove(target)
			return releaseBundleInvalid("frp archive framing is invalid")
		}
		total += header.Size
		if path.Clean(header.Name) != header.Name || strings.HasPrefix(header.Name, "/") || strings.HasPrefix(header.Name, "../") || strings.Contains(header.Name, "\\") {
			_ = compressed.Close()
			_ = os.Remove(target)
			return releaseBundleInvalid("frp archive path is invalid")
		}
		if header.Name != expected {
			if _, err := io.CopyN(io.Discard, tarReader, header.Size); err != nil {
				_ = compressed.Close()
				_ = os.Remove(target)
				return releaseBundleInvalid("frp archive entry is truncated")
			}
			continue
		}
		if found || header.Typeflag != tar.TypeReg || header.Size == 0 {
			_ = compressed.Close()
			_ = os.Remove(target)
			return releaseBundleInvalid("frp binary entry is invalid")
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = compressed.Close()
			return err
		}
		_, copyErr := io.CopyN(output, tarReader, header.Size)
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil {
			_ = compressed.Close()
			_ = os.Remove(target)
			return releaseBundleInvalid("frp binary entry is truncated")
		}
		found = true
	}
	_, drainErr := io.Copy(io.Discard, compressed)
	closeCompressedErr := compressed.Close()
	if !found || drainErr != nil || closeCompressedErr != nil {
		_ = os.Remove(target)
		return releaseBundleInvalid("frp role binary is absent")
	}
	if _, err := buffered.Peek(1); !errors.Is(err, io.EOF) {
		_ = os.Remove(target)
		return releaseBundleInvalid("frp archive has trailing data")
	}
	return nil
}

func releaseAPTPackagesForRole(manifest ReleaseManifest, role model.Role) []APTPackageCompatibility {
	result := make([]APTPackageCompatibility, 0, len(manifest.APTPackages))
	for _, compatibility := range manifest.APTPackages {
		if releaseRolesContain(compatibility.Roles, role) {
			copy := compatibility
			copy.Roles = append([]model.Role(nil), compatibility.Roles...)
			copy.Capabilities = append([]string(nil), compatibility.Capabilities...)
			result = append(result, copy)
		}
	}
	return result
}

func releaseRolesContain(roles []model.Role, role model.Role) bool {
	for _, candidate := range roles {
		if candidate == role {
			return true
		}
	}
	return false
}

func releaseBundleInvalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidReleaseBundle, fmt.Sprintf(format, arguments...))
}

func writeReleaseBundleBytes(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil {
			return releaseBundleInvalid("write bundle")
		}
		if count <= 0 || count > len(value) {
			return releaseBundleInvalid("bundle writer made no progress")
		}
		value = value[count:]
	}
	return nil
}

func writeReleaseBundleUint16(writer io.Writer, value uint16) error {
	var buffer [2]byte
	binary.BigEndian.PutUint16(buffer[:], value)
	return writeReleaseBundleBytes(writer, buffer[:])
}

func writeReleaseBundleUint32(writer io.Writer, value uint32) error {
	var buffer [4]byte
	binary.BigEndian.PutUint32(buffer[:], value)
	return writeReleaseBundleBytes(writer, buffer[:])
}

func writeReleaseBundleUint64(writer io.Writer, value uint64) error {
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], value)
	return writeReleaseBundleBytes(writer, buffer[:])
}

func readReleaseBundleUint16(reader io.Reader) (uint16, error) {
	var buffer [2]byte
	_, err := io.ReadFull(reader, buffer[:])
	return binary.BigEndian.Uint16(buffer[:]), err
}

func readReleaseBundleUint32(reader io.Reader) (uint32, error) {
	var buffer [4]byte
	_, err := io.ReadFull(reader, buffer[:])
	return binary.BigEndian.Uint32(buffer[:]), err
}

func readReleaseBundleUint64(reader io.Reader) (uint64, error) {
	var buffer [8]byte
	_, err := io.ReadFull(reader, buffer[:])
	return binary.BigEndian.Uint64(buffer[:]), err
}

type releaseByteReader struct {
	value []byte
}

func bytesReader(value []byte) *releaseByteReader {
	return &releaseByteReader{value: value}
}

func (reader *releaseByteReader) Read(destination []byte) (int, error) {
	if len(reader.value) == 0 {
		return 0, io.EOF
	}
	count := copy(destination, reader.value)
	reader.value = reader.value[count:]
	return count, nil
}

func equalReleaseFiles(leftPath, rightPath string) (bool, error) {
	left, err := os.Open(leftPath)
	if err != nil {
		return false, err
	}
	defer left.Close()
	right, err := os.Open(rightPath)
	if err != nil {
		return false, err
	}
	defer right.Close()
	leftHash, rightHash := sha256.New(), sha256.New()
	leftSize, err := io.Copy(leftHash, left)
	if err != nil {
		return false, err
	}
	rightSize, err := io.Copy(rightHash, right)
	if err != nil {
		return false, err
	}
	return leftSize == rightSize && hex.EncodeToString(leftHash.Sum(nil)) == hex.EncodeToString(rightHash.Sum(nil)), nil
}
