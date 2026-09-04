package lifecycle

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const DefaultReleaseRepositoryURL = "https://github.com/grnkvch/vpnctl/releases"

type UpdateReleaseSource struct {
	baseURL   *url.URL
	client    *http.Client
	publicKey ed25519.PublicKey
	inspector *ReleaseBundleInstaller
}

type StagedUpdateRelease struct {
	Version       string
	Checksums     ReleaseChecksums
	Manifest      ReleaseManifest
	BinaryPath    string
	BundlePath    string
	ChecksumsPath string
	SignaturePath string

	root      string
	closeOnce sync.Once
	closeErr  error
}

func NewUpdateReleaseSource(baseURL string, client *http.Client, publicKey ed25519.PublicKey, inspector *ReleaseBundleInstaller) (*UpdateReleaseSource, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("release repository URL must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	if client == nil || len(publicKey) != ed25519.PublicKeySize || inspector == nil {
		return nil, fmt.Errorf("update release source dependencies are incomplete")
	}
	return &UpdateReleaseSource{
		baseURL: parsed, client: client, publicKey: append(ed25519.PublicKey(nil), publicKey...), inspector: inspector,
	}, nil
}

// Stage performs the only release-network activity in the update workflow.
// An empty requested version selects the repository's latest stable endpoint;
// an explicit version addresses only that exact release. The complete bundle
// is verified before this method returns a retained local stage.
func (source *UpdateReleaseSource) Stage(ctx context.Context, requestedVersion string) (*StagedUpdateRelease, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if source == nil || source.client == nil || source.baseURL == nil || source.inspector == nil || len(source.publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("update release source is incomplete")
	}
	if requestedVersion != "" {
		canonical, err := CanonicalStableReleaseVersion(requestedVersion)
		if err != nil {
			return nil, err
		}
		requestedVersion = canonical
	}
	root, err := os.MkdirTemp("", "vpnctl-update-release-")
	if err != nil {
		return nil, fmt.Errorf("create update release stage: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("secure update release stage: %w", err)
	}
	staged := &StagedUpdateRelease{
		root:       root,
		BinaryPath: filepath.Join(root, ReleaseBinaryAsset), BundlePath: filepath.Join(root, ReleaseBundleAsset),
		ChecksumsPath: filepath.Join(root, ReleaseChecksumsAsset), SignaturePath: filepath.Join(root, ReleaseChecksumsSignatureAsset),
	}
	keep := false
	defer func() {
		if !keep {
			_ = staged.Close()
		}
	}()

	releasePath := "latest/download"
	if requestedVersion != "" {
		releasePath = "download/" + requestedVersion
	}
	if err := source.download(ctx, releasePath, ReleaseChecksumsAsset, staged.ChecksumsPath, 4096, false); err != nil {
		return nil, err
	}
	if err := source.download(ctx, releasePath, ReleaseChecksumsSignatureAsset, staged.SignaturePath, ed25519.SignatureSize, true); err != nil {
		return nil, err
	}
	encodedChecksums, err := readBoundedReleaseFile(staged.ChecksumsPath, 4096)
	if err != nil {
		return nil, fmt.Errorf("read staged release checksums: %w", err)
	}
	signature, err := readExactReleaseFile(staged.SignaturePath, ed25519.SignatureSize)
	if err != nil {
		return nil, fmt.Errorf("read staged release signature: %w", err)
	}
	checksums, err := VerifyReleaseChecksums(encodedChecksums, signature, source.publicKey)
	if err != nil {
		return nil, fmt.Errorf("verify staged release checksums: %w", err)
	}
	if requestedVersion != "" && checksums.Version != requestedVersion {
		return nil, fmt.Errorf("signed release version %s differs from requested %s", checksums.Version, requestedVersion)
	}
	if canonical, stableErr := CanonicalStableReleaseVersion(checksums.Version); stableErr != nil || canonical != checksums.Version {
		return nil, fmt.Errorf("release metadata does not identify a canonical stable release")
	}
	if err := source.download(ctx, releasePath, ReleaseBinaryAsset, staged.BinaryPath, checksums.Binary.SizeBytes, true); err != nil {
		return nil, err
	}
	if err := source.download(ctx, releasePath, ReleaseBundleAsset, staged.BundlePath, checksums.Bundle.SizeBytes, true); err != nil {
		return nil, err
	}
	if err := verifyStagedReleaseFile(staged.BinaryPath, checksums.Binary); err != nil {
		return nil, err
	}
	if err := verifyStagedReleaseFile(staged.BundlePath, checksums.Bundle); err != nil {
		return nil, err
	}
	manifest, err := source.inspector.Inspect(ctx, staged.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("verify staged release bundle: %w", err)
	}
	if manifest.ComponentManifest.VPNCTLVersion != checksums.Version {
		return nil, fmt.Errorf("bundle version differs from signed release metadata")
	}
	vpnctlArtifact, found := releaseArtifactForComponent(manifest, "vpnctl")
	if !found || vpnctlArtifact.SHA256 != checksums.Binary.SHA256 || vpnctlArtifact.SizeBytes != checksums.Binary.SizeBytes {
		return nil, fmt.Errorf("standalone binary differs from the bundle vpnctl artifact")
	}
	staged.Version, staged.Checksums, staged.Manifest = checksums.Version, checksums, manifest
	keep = true
	return staged, nil
}

func (source *UpdateReleaseSource) download(ctx context.Context, releasePath, asset, target string, byteLimit int64, exact bool) error {
	if byteLimit <= 0 || byteLimit > MaximumReleaseBundleBytes {
		return fmt.Errorf("release asset %s has an invalid download bound", asset)
	}
	assetURL := *source.baseURL
	assetURL.Path = strings.TrimRight(source.baseURL.Path, "/") + "/" + releasePath + "/" + asset
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL.String(), nil)
	if err != nil {
		return fmt.Errorf("build release asset request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	response, err := source.client.Do(request)
	if err != nil {
		return fmt.Errorf("download release asset %s: %w", asset, err)
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL == nil || response.Request.URL.Scheme != "https" {
		return fmt.Errorf("release asset %s resolved outside HTTPS", asset)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download release asset %s: HTTP %d", asset, response.StatusCode)
	}
	if response.ContentLength >= 0 && (response.ContentLength <= 0 || response.ContentLength > byteLimit || exact && response.ContentLength != byteLimit) {
		return fmt.Errorf("release asset %s content length is invalid", asset)
	}
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create staged release asset %s: %w", asset, err)
	}
	read, copyErr := io.Copy(output, io.LimitReader(response.Body, byteLimit+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	sizeErr := error(nil)
	if read <= 0 || read > byteLimit || exact && read != byteLimit {
		sizeErr = sizeMismatchError(read, byteLimit, exact)
	}
	if copyErr != nil || syncErr != nil || closeErr != nil || sizeErr != nil {
		return fmt.Errorf("download release asset %s: %w", asset, errors.Join(copyErr, syncErr, closeErr, sizeErr))
	}
	return nil
}

func (staged *StagedUpdateRelease) Close() error {
	if staged == nil {
		return nil
	}
	staged.closeOnce.Do(func() {
		if staged.root != "" {
			staged.closeErr = os.RemoveAll(staged.root)
			staged.root = ""
		}
	})
	return staged.closeErr
}

func (staged *StagedUpdateRelease) valid() bool {
	return staged != nil && staged.root != "" && staged.Version != "" && staged.BundlePath != "" && staged.ChecksumsPath != "" && staged.SignaturePath != ""
}

func readBoundedReleaseFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("release asset must be a bounded regular file")
	}
	return os.ReadFile(path)
}

func readExactReleaseFile(path string, size int64) ([]byte, error) {
	content, err := readBoundedReleaseFile(path, size)
	if err != nil || int64(len(content)) != size {
		return nil, fmt.Errorf("release asset size differs from expected: %w", err)
	}
	return content, nil
}

func verifyStagedReleaseFile(path string, record ReleaseChecksumRecord) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("staged release asset %s is not a regular file", record.Name)
	}
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := VerifyReleaseChecksumRecord(record, info.Size(), input); err != nil {
		return fmt.Errorf("verify staged release asset %s: %w", record.Name, err)
	}
	return nil
}

func releaseArtifactForComponent(manifest ReleaseManifest, component string) (ReleaseArtifact, bool) {
	for _, artifact := range manifest.Artifacts {
		if artifact.Component == component {
			return artifact, true
		}
	}
	return ReleaseArtifact{}, false
}

func sizeMismatchError(actual, limit int64, exact bool) error {
	if exact {
		return fmt.Errorf("received %d bytes, expected %d", actual, limit)
	}
	return fmt.Errorf("received %d bytes outside 1..%d", actual, limit)
}
