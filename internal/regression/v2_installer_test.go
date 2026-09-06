package regression

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
)

func TestV2CurlInstallerVerifiesChecksummedAssetsAndWritesStandardLayout(t *testing.T) {
	t.Parallel()
	requireInstallerCommands(t)
	fixture := newInstallerFixture(t)
	root := t.TempDir()
	result := runInstallerFixture(t, fixture, root, nil)
	if result.err != nil {
		t.Fatalf("installer failed: %v\nstdout:\n%s\nstderr:\n%s", result.err, result.stdout, result.stderr)
	}
	if !strings.Contains(result.stdout, filepath.Join(root, "usr/local/bin/vpnctl")) ||
		!strings.Contains(result.stdout, filepath.Join(root, "usr/local/lib/vpnctl/release/vpnctl.bundle")) ||
		!strings.Contains(result.stdout, "verified release version v2.0.0") || result.stderr != "" {
		t.Fatalf("installer output stdout=%q stderr=%q", result.stdout, result.stderr)
	}
	assertInstalledAsset(t, root, "usr/local/bin/vpnctl", fixture.binary, 0o755)
	assertInstalledAsset(t, root, "usr/local/lib/vpnctl/release/vpnctl.bundle", fixture.bundle, 0o600)
	assertInstalledAsset(t, root, "usr/local/lib/vpnctl/release/checksums.txt", fixture.checksums, 0o600)
	info, err := os.Stat(filepath.Join(root, "usr/local/lib/vpnctl/release"))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("release directory mode=%v err=%v", info.Mode(), err)
	}

	before := snapshotInstallerTree(t, root)
	second := runInstallerFixture(t, fixture, root, nil)
	if second.err != nil {
		t.Fatalf("idempotent installer failed: %v\n%s", second.err, second.stderr)
	}
	after := snapshotInstallerTree(t, root)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("idempotent install changed standard layout\nbefore=%+v\nafter=%+v", before, after)
	}

	offlineRoot := t.TempDir()
	offline := runInstallerFixture(t, fixture, offlineRoot, map[string]string{"VPNCTL_RELEASE_ASSET_DIR": fixture.assetDir})
	if offline.err != nil {
		t.Fatalf("offline copied-asset install failed: %v\n%s", offline.err, offline.stderr)
	}
	assertInstalledAsset(t, offlineRoot, "usr/local/bin/vpnctl", fixture.binary, 0o755)
	assertInstalledAsset(t, offlineRoot, "usr/local/lib/vpnctl/release/vpnctl.bundle", fixture.bundle, 0o600)
}

func TestV2CurlInstallerRejectsCorruptDownloadsBeforeExistingInstallMutation(t *testing.T) {
	t.Parallel()
	requireInstallerCommands(t)
	for name, corrupt := range map[string]func(*testing.T, *installerFixture){
		"binary-checksum": func(t *testing.T, fixture *installerFixture) {
			appendInstallerAsset(t, fixture.assetDir, lifecycle.ReleaseBinaryAsset)
		},
		"bundle-checksum": func(t *testing.T, fixture *installerFixture) {
			appendInstallerAsset(t, fixture.assetDir, lifecycle.ReleaseBundleAsset)
		},
		"metadata": func(t *testing.T, fixture *installerFixture) {
			appendInstallerAsset(t, fixture.assetDir, lifecycle.ReleaseChecksumsAsset)
		},
		"bundle-structure": func(t *testing.T, fixture *installerFixture) {
			appendInstallerAsset(t, fixture.assetDir, lifecycle.ReleaseBundleAsset)
			bundle, err := os.ReadFile(filepath.Join(fixture.assetDir, lifecycle.ReleaseBundleAsset))
			if err != nil {
				t.Fatal(err)
			}
			checksums, err := lifecycle.NewReleaseChecksums(
				"v2.0.0", installerDigest(fixture.binary), int64(len(fixture.binary)), installerDigest(bundle), int64(len(bundle)),
			)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := lifecycle.EncodeReleaseChecksums(checksums)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(fixture.assetDir, lifecycle.ReleaseChecksumsAsset), encoded, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"missing-download": func(t *testing.T, fixture *installerFixture) {
			if err := os.Remove(filepath.Join(fixture.assetDir, lifecycle.ReleaseBundleAsset)); err != nil {
				t.Fatal(err)
			}
		},
	} {
		name, corrupt := name, corrupt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newInstallerFixture(t)
			corrupt(t, fixture)
			root := t.TempDir()
			seedExistingInstallerLayout(t, root)
			before := snapshotInstallerTree(t, root)
			result := runInstallerFixture(t, fixture, root, nil)
			if result.err == nil || result.stderr == "" {
				t.Fatalf("corrupt installer result err=%v stdout=%q stderr=%q", result.err, result.stdout, result.stderr)
			}
			after := snapshotInstallerTree(t, root)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("corrupt download changed install\nbefore=%+v\nafter=%+v", before, after)
			}
		})
	}
}

func TestV2CurlInstallerRollsBackPublishedFilesAndRejectsSymlinks(t *testing.T) {
	t.Parallel()
	requireInstallerCommands(t)
	t.Run("publication rollback", func(t *testing.T) {
		fixture := newInstallerFixture(t)
		root := t.TempDir()
		seedExistingInstallerLayout(t, root)
		before := snapshotInstallerTree(t, root)
		result := runInstallerFixture(t, fixture, root, map[string]string{
			"VPNCTL_TESTING": "1", "VPNCTL_TEST_FAIL_AFTER_INSTALL": "2",
		})
		if result.err == nil || !strings.Contains(result.stderr, "injected installer publication failure") {
			t.Fatalf("injected failure err=%v stderr=%q", result.err, result.stderr)
		}
		after := snapshotInstallerTree(t, root)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("rollback changed previous install\nbefore=%+v\nafter=%+v", before, after)
		}
	})

	t.Run("symlink target", func(t *testing.T) {
		fixture := newInstallerFixture(t)
		root := t.TempDir()
		binaryDir := filepath.Join(root, "usr/local/bin")
		if err := os.MkdirAll(binaryDir, 0o755); err != nil {
			t.Fatal(err)
		}
		foreign := filepath.Join(root, "foreign")
		if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(foreign, filepath.Join(binaryDir, "vpnctl")); err != nil {
			t.Fatal(err)
		}
		before := snapshotInstallerTree(t, root)
		result := runInstallerFixture(t, fixture, root, nil)
		if result.err == nil || !strings.Contains(result.stderr, "install target conflict") {
			t.Fatalf("symlink result err=%v stderr=%q", result.err, result.stderr)
		}
		after := snapshotInstallerTree(t, root)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("symlink conflict changed root\nbefore=%+v\nafter=%+v", before, after)
		}
	})

	t.Run("requested version mismatch", func(t *testing.T) {
		fixture := newInstallerFixture(t)
		root := t.TempDir()
		seedExistingInstallerLayout(t, root)
		before := snapshotInstallerTree(t, root)
		result := runInstallerFixture(t, fixture, root, map[string]string{"VPNCTL_VERSION": "v2.0.1"})
		if result.err == nil || !strings.Contains(result.stderr, "does not match requested") {
			t.Fatalf("version mismatch err=%v stderr=%q", result.err, result.stderr)
		}
		if after := snapshotInstallerTree(t, root); !reflect.DeepEqual(before, after) {
			t.Fatalf("version mismatch changed install\nbefore=%+v\nafter=%+v", before, after)
		}
	})

	t.Run("unsafe requested version", func(t *testing.T) {
		fixture := newInstallerFixture(t)
		root := t.TempDir()
		seedExistingInstallerLayout(t, root)
		before := snapshotInstallerTree(t, root)
		result := runInstallerFixture(t, fixture, root, map[string]string{"VPNCTL_VERSION": "v2.0.0/../candidate"})
		if result.err == nil || !strings.Contains(result.stderr, "VPNCTL_VERSION must be") {
			t.Fatalf("unsafe version err=%v stderr=%q", result.err, result.stderr)
		}
		if after := snapshotInstallerTree(t, root); !reflect.DeepEqual(before, after) {
			t.Fatalf("unsafe version changed install\nbefore=%+v\nafter=%+v", before, after)
		}
	})
}

func TestV2InstallerUsesHTTPSAndChecksumsWithoutReleaseSigning(t *testing.T) {
	t.Parallel()
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(script)
	for _, required := range []string{
		"--proto '=https' --tlsv1.2", "vpnctl-release-checksums-v1", "file_checksum",
		"__release-verify-bundle", "/usr/local/bin", "/usr/local/lib/vpnctl/release", "mutation_started=1", "VPNCTL_RELEASE_ASSET_DIR",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("curl installer omits %q", required)
		}
	}
	for _, forbidden := range []string{"release-checksums.txt.sig", "VPNCTL_RELEASE_PUBLIC_KEY_FILE", "openssl", "pkeyutl"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("checksum-only installer retains release-signing token %q", forbidden)
		}
	}
}

func TestV2ReleaseScriptBuildsOnlyTheThreeChecksumGovernedAssets(t *testing.T) {
	t.Parallel()
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "release.sh"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(script)
	for _, required := range []string{
		"VPNCTL_MIHOMO_ARCHIVE", "VPNCTL_FRP_ARCHIVE",
		"-buildvcs=false", "go run ./cmd/vpnctl-release", lifecycle.ReleaseBinaryAsset,
		lifecycle.ReleaseBundleAsset, lifecycle.ReleaseChecksumsAsset,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("v2 release script omits %q", required)
		}
	}
	for _, forbidden := range []string{"curl ", "wget ", "go install ", "VPNCTL_RELEASE_SIGNING_KEY", "release-checksums.txt.sig", "-signing-key"} {
		if strings.Contains(source, forbidden) {
			t.Errorf("v2 release script unexpectedly fetches with %q", forbidden)
		}
	}
}

type installerFixture struct {
	assetDir  string
	shimDir   string
	binary    []byte
	bundle    []byte
	checksums []byte
}

type installerRun struct {
	stdout string
	stderr string
	err    error
}

func newInstallerFixture(t *testing.T) *installerFixture {
	t.Helper()
	binary := []byte("#!/bin/sh\n[ \"$#\" -eq 5 ] || exit 64\n[ \"$1\" = \"__release-verify-bundle\" ] || exit 64\n[ \"$3\" = \"v2.0.0\" ] || exit 64\n[ \"$(sed -n '1,$p' \"$2\")\" = 'checksummed complete vpnctl v2 release bundle' ]\n")
	bundle := []byte("checksummed complete vpnctl v2 release bundle\n")
	checksums, err := lifecycle.NewReleaseChecksums("v2.0.0", installerDigest(binary), int64(len(binary)), installerDigest(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := lifecycle.EncodeReleaseChecksums(checksums)
	if err != nil {
		t.Fatal(err)
	}
	assetDir := t.TempDir()
	for name, value := range map[string][]byte{
		lifecycle.ReleaseBinaryAsset: binary, lifecycle.ReleaseBundleAsset: bundle,
		lifecycle.ReleaseChecksumsAsset: encoded,
	} {
		if err := os.WriteFile(filepath.Join(assetDir, name), value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	shimDir := t.TempDir()
	writeExecutableFixture(t, filepath.Join(shimDir, "curl"), `#!/bin/sh
output=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift 2 ;;
    https://*) url=$1; shift ;;
    *) shift ;;
  esac
done
[ -n "$output" ] && [ -n "$url" ] || exit 64
cp "$VPNCTL_TEST_ASSET_DIR/${url##*/}" "$output"
`)
	writeExecutableFixture(t, filepath.Join(shimDir, "uname"), `#!/bin/sh
case "${1:-}" in
  -s) echo Linux ;;
  -m) echo x86_64 ;;
  *) exit 64 ;;
esac
`)
	return &installerFixture{
		assetDir: assetDir, shimDir: shimDir,
		binary: binary, bundle: bundle, checksums: encoded,
	}
}

func runInstallerFixture(t *testing.T, fixture *installerFixture, root string, extra map[string]string) installerRun {
	t.Helper()
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", script)
	environment := append([]string(nil), os.Environ()...)
	environment = append(environment,
		"PATH="+fixture.shimDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"VPNCTL_TEST_ASSET_DIR="+fixture.assetDir,
		"VPNCTL_RELEASE_BASE_URL=https://fixtures.invalid/release",
		"VPNCTL_INSTALL_ROOT="+root,
	)
	for name, value := range extra {
		environment = append(environment, name+"="+value)
	}
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	return installerRun{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

func seedExistingInstallerLayout(t *testing.T, root string) {
	t.Helper()
	values := map[string]struct {
		content []byte
		mode    fs.FileMode
	}{
		"usr/local/bin/vpnctl":                       {content: []byte("previous binary"), mode: 0o755},
		"usr/local/lib/vpnctl/release/vpnctl.bundle": {content: []byte("previous bundle"), mode: 0o600},
		"usr/local/lib/vpnctl/release/checksums.txt": {content: []byte("previous checksums"), mode: 0o600},
	}
	for relative, value := range values {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, value.content, value.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, value.mode); err != nil {
			t.Fatal(err)
		}
	}
}

type installerTreeEntry struct {
	Mode    fs.FileMode
	Content string
	Link    string
}

func snapshotInstallerTree(t *testing.T, root string) map[string]installerTreeEntry {
	t.Helper()
	result := make(map[string]installerTreeEntry)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		item := installerTreeEntry{Mode: info.Mode()}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			item.Link, err = os.Readlink(path)
		case info.Mode().IsRegular():
			var content []byte
			content, err = os.ReadFile(path)
			item.Content = string(content)
		}
		if err != nil {
			return err
		}
		result[filepath.ToSlash(relative)] = item
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertInstalledAsset(t *testing.T, root, relative string, expected []byte, mode fs.FileMode) {
	t.Helper()
	path := filepath.Join(root, relative)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("%s stat error=%v", relative, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		t.Fatalf("%s mode=%v", relative, info.Mode())
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatalf("%s content mismatch err=%v", relative, err)
	}
}

func appendInstallerAsset(t *testing.T, root, name string) {
	t.Helper()
	path := filepath.Join(root, name)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("corrupt")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeExecutableFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func installerDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return fmt.Sprintf("%x", digest)
}

func requireInstallerCommands(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX installer test")
	}
	for _, command := range []string{"sh", "cmp"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s unavailable: %v", command, err)
		}
	}
}
