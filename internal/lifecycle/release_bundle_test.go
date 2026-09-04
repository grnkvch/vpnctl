package lifecycle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestReleaseBundleBuildIsReproducibleAndRejectsArtifactDrift(t *testing.T) {
	t.Parallel()
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	manifest, artifacts, _ := releaseBundleFixture(t)
	var first, second bytes.Buffer
	if err := BuildReleaseBundle(&first, manifest, privateKey, artifacts); err != nil {
		t.Fatal(err)
	}
	if err := BuildReleaseBundle(&second, manifest, privateKey, artifacts); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) || len(first.Bytes()) == 0 {
		t.Fatal("equal release inputs did not produce identical bundle bytes")
	}

	missing := cloneReleaseArtifactBytes(artifacts)
	delete(missing, manifest.Artifacts[0].Path)
	extra := cloneReleaseArtifactBytes(artifacts)
	extra["components/extra"] = []byte("extra")
	tampered := cloneReleaseArtifactBytes(artifacts)
	tampered[manifest.Artifacts[0].Path] = append(tampered[manifest.Artifacts[0].Path], 'x')
	for name, candidate := range map[string]map[string][]byte{"missing": missing, "extra": extra, "tampered": tampered} {
		var output bytes.Buffer
		if err := BuildReleaseBundle(&output, manifest, privateKey, candidate); !errors.Is(err, ErrInvalidReleaseBundle) || output.Len() != 0 {
			t.Fatalf("%s artifacts error=%v bytes=%d", name, err, output.Len())
		}
	}
	if err := BuildReleaseBundle(io.Discard, manifest, ed25519.PrivateKey{1}, artifacts); !errors.Is(err, ErrInvalidReleaseBundle) {
		t.Fatalf("invalid signing key error = %v", err)
	}
	if err := BuildReleaseBundle(nil, manifest, privateKey, artifacts); !errors.Is(err, ErrInvalidReleaseBundle) {
		t.Fatalf("nil writer error = %v", err)
	}
	if err := BuildReleaseBundle(errorReleaseWriter{}, manifest, privateKey, artifacts); !errors.Is(err, ErrInvalidReleaseBundle) {
		t.Fatalf("failed writer error = %v", err)
	}
}

func TestSCPTransferredBundleInstallsOnlySelectedRoleFromLocalBytes(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	manifest, artifacts, installed := releaseBundleFixture(t)
	transferRoot := t.TempDir()
	localPath := filepath.Join(transferRoot, "vpnctl-v2-local.bundle")
	remotePath := filepath.Join(transferRoot, "vpnctl-v2-scp.bundle")
	writeReleaseBundleFile(t, localPath, manifest, privateKey, artifacts)
	copyReleaseBundleLikeSCP(t, localPath, remotePath)
	localBytes, _ := os.ReadFile(localPath)
	remoteBytes, _ := os.ReadFile(remotePath)
	if !bytes.Equal(localBytes, remoteBytes) {
		t.Fatal("scp-modeled transfer changed bundle bytes")
	}
	if err := os.Remove(localPath); err != nil {
		t.Fatal(err)
	}

	for _, role := range []model.Role{model.RoleGateway, model.RoleNode} {
		role := role
		t.Run(string(role), func(t *testing.T) {
			root := t.TempDir()
			installer, err := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{
				OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64",
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := installer.Install(context.Background(), remotePath, role)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result.Manifest, manifest) || len(result.ChangedFiles) != 3 {
				t.Fatalf("install result = %+v", result)
			}
			wantAPT := 2
			if role == model.RoleGateway {
				wantAPT = 3
			}
			if len(result.RequiredAPTPackages) != wantAPT {
				t.Fatalf("%s apt packages = %+v", role, result.RequiredAPTPackages)
			}
			assertReleaseInstalledFile(t, root, "usr/local/bin/vpnctl", installed["vpnctl"])
			assertReleaseInstalledFile(t, root, "usr/local/libexec/vpnctl/mihomo", installed["mihomo"])
			presentFRP, absentFRP := "frpc", "frps"
			if role == model.RoleGateway {
				presentFRP, absentFRP = "frps", "frpc"
			}
			assertReleaseInstalledFile(t, root, "usr/local/libexec/vpnctl/"+presentFRP, installed[presentFRP])
			if _, err := os.Lstat(filepath.Join(root, "usr/local/libexec/vpnctl", absentFRP)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s install created opposite-role %s: %v", role, absentFRP, err)
			}
			second, err := installer.Install(context.Background(), remotePath, role)
			if err != nil || len(second.ChangedFiles) != 0 {
				t.Fatalf("idempotent install = %+v, %v", second, err)
			}
		})
	}
}

func TestReleaseBundleVerificationFailsBeforeInstallMutation(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	manifest, artifacts, _ := releaseBundleFixture(t)
	var valid bytes.Buffer
	if err := BuildReleaseBundle(&valid, manifest, privateKey, artifacts); err != nil {
		t.Fatal(err)
	}
	validBytes := valid.Bytes()
	tampered := append([]byte(nil), validBytes...)
	artifactOffset := bytes.LastIndex(tampered, artifacts[manifest.Artifacts[len(manifest.Artifacts)-1].Path])
	if artifactOffset < 0 {
		t.Fatal("artifact bytes absent from bundle fixture")
	}
	tampered[artifactOffset] ^= 0x01
	truncated := append([]byte(nil), validBytes[:len(validBytes)-1]...)
	extra := append(append([]byte(nil), validBytes...), 0x01)
	wrongMagic := append([]byte(nil), validBytes...)
	wrongMagic[0] ^= 0x01
	manifestLength := int(binary.BigEndian.Uint32(validBytes[len(releaseBundleMagic):]))
	firstArtifactOffset := len(releaseBundleMagic) + 4 + manifestLength
	wrongPath := append([]byte(nil), validBytes...)
	wrongPath[firstArtifactOffset+2] ^= 0x01
	firstPathLength := int(binary.BigEndian.Uint16(validBytes[firstArtifactOffset:]))
	wrongSize := append([]byte(nil), validBytes...)
	wrongSize[firstArtifactOffset+2+firstPathLength+7] ^= 0x01
	for name, bundle := range map[string][]byte{
		"artifact-tamper": tampered, "truncated": truncated, "extra": extra, "magic": wrongMagic,
		"path-framing": wrongPath, "size-framing": wrongSize,
	} {
		name, bundle := name, bundle
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			bundlePath := filepath.Join(t.TempDir(), "candidate.bundle")
			if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
				t.Fatal(err)
			}
			installer, _ := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
			if _, err := installer.Install(context.Background(), bundlePath, model.RoleGateway); !errors.Is(err, ErrInvalidReleaseBundle) {
				t.Fatalf("Install() error = %v", err)
			}
			assertReleaseInstallRootUnchanged(t, root)
		})
	}

	root := t.TempDir()
	bundlePath := filepath.Join(t.TempDir(), "candidate.bundle")
	if err := os.WriteFile(bundlePath, validBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	installer, _ := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "22.04", Architecture: "amd64"})
	if _, err := installer.Install(context.Background(), bundlePath, model.RoleGateway); !errors.Is(err, ErrUnsupportedReleasePlatform) {
		t.Fatalf("unsupported platform error = %v", err)
	}
	assertReleaseInstallRootUnchanged(t, root)
	installer, _ = NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	if _, err := installer.Install(context.Background(), bundlePath, model.Role("client")); !errors.Is(err, ErrInvalidReleaseBundle) {
		t.Fatalf("unsupported role error = %v", err)
	}
	assertReleaseInstallRootUnchanged(t, root)

	oversizedPath := filepath.Join(t.TempDir(), "oversized.bundle")
	oversized, err := os.OpenFile(oversizedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := oversized.Truncate(maximumReleaseBundleBytes + 1); err != nil {
		_ = oversized.Close()
		t.Fatal(err)
	}
	if err := oversized.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Install(context.Background(), oversizedPath, model.RoleGateway); !errors.Is(err, ErrInvalidReleaseBundle) {
		t.Fatalf("oversized bundle error = %v", err)
	}
	assertReleaseInstallRootUnchanged(t, root)

	symlinkPath := filepath.Join(t.TempDir(), "candidate.bundle")
	if err := os.Symlink(bundlePath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Install(context.Background(), symlinkPath, model.RoleGateway); !errors.Is(err, ErrInvalidReleaseBundle) {
		t.Fatalf("symlink bundle error = %v", err)
	}
	assertReleaseInstallRootUnchanged(t, root)
}

func TestReleaseBundleExistingConflictPreservesEveryTarget(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	manifest, artifacts, _ := releaseBundleFixture(t)
	bundlePath := filepath.Join(t.TempDir(), "candidate.bundle")
	writeReleaseBundleFile(t, bundlePath, manifest, privateKey, artifacts)
	root := t.TempDir()
	vpnctlPath := filepath.Join(root, "usr/local/bin/vpnctl")
	if err := os.MkdirAll(filepath.Dir(vpnctlPath), 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("foreign-vpnctl")
	if err := os.WriteFile(vpnctlPath, foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	installer, _ := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	if _, err := installer.Install(context.Background(), bundlePath, model.RoleGateway); !errors.Is(err, ErrReleaseInstallConflict) {
		t.Fatalf("conflicting install error = %v", err)
	}
	content, _ := os.ReadFile(vpnctlPath)
	if !bytes.Equal(content, foreign) {
		t.Fatalf("foreign target changed to %q", content)
	}
	for _, relative := range []string{"usr/local/libexec/vpnctl/mihomo", "usr/local/libexec/vpnctl/frps"} {
		if _, err := os.Lstat(filepath.Join(root, relative)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("conflict created %s: %v", relative, err)
		}
	}
}

func TestReleaseBundleRejectsInvalidProviderArchiveBeforeInstall(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	manifest, artifacts, _ := releaseBundleFixture(t)
	frpPath := manifest.Artifacts[1].Path
	artifacts[frpPath] = testReleaseGzip(t, []byte("not-a-tar"))
	manifest.Artifacts[1].SHA256 = releaseDigest(artifacts[frpPath])
	manifest.Artifacts[1].SizeBytes = int64(len(artifacts[frpPath]))
	manifest.ComponentManifest.Components[0].SHA256 = manifest.Artifacts[1].SHA256
	bundlePath := filepath.Join(t.TempDir(), "candidate.bundle")
	writeReleaseBundleFile(t, bundlePath, manifest, privateKey, artifacts)
	root := t.TempDir()
	installer, _ := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	if _, err := installer.Install(context.Background(), bundlePath, model.RoleGateway); !errors.Is(err, ErrInvalidReleaseBundle) {
		t.Fatalf("invalid provider archive error = %v", err)
	}
	assertReleaseInstallRootUnchanged(t, root)
}

func releaseBundleFixture(t *testing.T) (ReleaseManifest, map[string][]byte, map[string][]byte) {
	t.Helper()
	installed := map[string][]byte{
		"vpnctl": []byte("vpnctl-linux-amd64"), "mihomo": []byte("mihomo-linux-amd64"),
		"frpc": []byte("frpc-linux-amd64"), "frps": []byte("frps-linux-amd64"),
	}
	frp := testReleaseFRPArchive(t, installed["frpc"], installed["frps"])
	mihomo := testReleaseGzip(t, installed["mihomo"])
	manifest, _ := releaseManifestFixture()
	artifacts := map[string][]byte{
		"bin/vpnctl": installed["vpnctl"], "components/frp-linux-amd64.tgz": frp,
		"components/mihomo-linux-amd64.gz": mihomo,
	}
	for index := range manifest.Artifacts {
		content := artifacts[manifest.Artifacts[index].Path]
		manifest.Artifacts[index].SHA256 = releaseDigest(content)
		manifest.Artifacts[index].SizeBytes = int64(len(content))
		for componentIndex := range manifest.ComponentManifest.Components {
			if manifest.ComponentManifest.Components[componentIndex].Name == manifest.Artifacts[index].Component {
				manifest.ComponentManifest.Components[componentIndex].SHA256 = manifest.Artifacts[index].SHA256
			}
		}
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	return manifest, artifacts, installed
}

func testReleaseFRPArchive(t *testing.T, frpc, frps []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	root := "frp_0.69.0_linux_amd64/"
	for _, entry := range []struct {
		name    string
		content []byte
	}{{name: "frpc", content: frpc}, {name: "frps", content: frps}} {
		header := &tar.Header{Name: root + entry.name, Mode: 0o755, Size: int64(len(entry.content)), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(entry.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func testReleaseGzip(t *testing.T, content []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	writer.Header.ModTime = time.Unix(0, 0).UTC()
	writer.Header.OS = 255
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func writeReleaseBundleFile(t *testing.T, path string, manifest ReleaseManifest, privateKey ed25519.PrivateKey, artifacts map[string][]byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := BuildReleaseBundle(file, manifest, privateKey, artifacts); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func copyReleaseBundleLikeSCP(t *testing.T, sourcePath, targetPath string) {
	t.Helper()
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertReleaseInstalledFile(t *testing.T, root, relative string, want []byte) {
	t.Helper()
	path := filepath.Join(root, relative)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 {
		t.Fatalf("installed file %s mode=%v error=%v", relative, info, err)
	}
	content, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(content, want) {
		t.Fatalf("installed file %s content=%q error=%v", relative, content, err)
	}
}

func assertReleaseInstallRootUnchanged(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed install changed root: entries=%v error=%v", entries, err)
	}
}

func cloneReleaseArtifactBytes(values map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(values))
	for key, value := range values {
		result[key] = append([]byte(nil), value...)
	}
	return result
}

type errorReleaseWriter struct{}

func (errorReleaseWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}
