package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestPreparedReleaseBundleUpdateStagesEverythingAndRollsBackExactFiles(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	installer, err := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	currentAssets, _, currentInstalled := updateReleaseAssetsWithInstalled(t, privateKey, "v2.0.0", "old")
	targetAssets, targetManifest, targetInstalled := updateReleaseAssetsWithInstalled(t, privateKey, "v2.1.0", "new")
	current := writeStagedUpdateRelease(t, currentAssets, currentAssetsManifest(t, installer, currentAssets))
	defer current.Close()
	target := writeStagedUpdateRelease(t, targetAssets, targetManifest)
	defer target.Close()
	if _, err := installer.Install(context.Background(), current.BundlePath, model.RoleGateway); err != nil {
		t.Fatal(err)
	}
	installStandardReleaseMetadata(t, root, current)
	before := snapshotReleaseUpdateRoot(t, root)

	prepared, err := installer.PrepareUpdate(context.Background(), standardReleaseBundleInRoot(root), target, model.RoleGateway)
	if err != nil {
		t.Fatal(err)
	}
	wantChanges := []ReleaseBundleComponentChange{
		{Name: "frp", CurrentVersion: "0.69.0-old", TargetVersion: "0.69.0-new", TargetPath: filepath.Join(root, "usr/local/libexec/vpnctl/frps"), FileChanged: true},
		{Name: "mihomo", CurrentVersion: "v1.19.30-old", TargetVersion: "v1.19.30-new", TargetPath: filepath.Join(root, "usr/local/libexec/vpnctl/mihomo"), FileChanged: true},
		{Name: "vpnctl", CurrentVersion: "v2.0.0", TargetVersion: "v2.1.0", TargetPath: filepath.Join(root, "usr/local/bin/vpnctl"), FileChanged: true},
	}
	if changes := prepared.Changes(); !reflect.DeepEqual(changes, wantChanges) {
		t.Fatalf("component changes = %+v, want %+v", changes, wantChanges)
	}
	for _, change := range prepared.Changes() {
		if err := prepared.ActivateComponent(context.Background(), change.Name); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepared.PublishMetadata(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertUpdateInstalledFiles(t, root, targetInstalled, targetAssets)
	if err := prepared.RollbackMetadata(context.Background()); err != nil {
		t.Fatal(err)
	}
	for index := len(wantChanges) - 1; index >= 0; index-- {
		if err := prepared.RollbackComponent(context.Background(), wantChanges[index].Name); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if after := snapshotReleaseUpdateRoot(t, root); !reflect.DeepEqual(before, after) {
		t.Fatalf("release rollback changed root\nbefore=%+v\nafter=%+v", before, after)
	}
	assertUpdateInstalledFiles(t, root, currentInstalled, currentAssets)
}

func TestPreparedReleaseBundleUpdateCommitAndConflictBehavior(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	for _, test := range []struct {
		name   string
		tamper bool
	}{
		{name: "commit"},
		{name: "installed drift", tamper: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			installer, _ := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
			currentAssets, currentManifest, _ := updateReleaseAssetsWithInstalled(t, privateKey, "v2.0.0", "old")
			targetAssets, targetManifest, targetInstalled := updateReleaseAssetsWithInstalled(t, privateKey, "v2.1.0", "new")
			current := writeStagedUpdateRelease(t, currentAssets, currentManifest)
			defer current.Close()
			target := writeStagedUpdateRelease(t, targetAssets, targetManifest)
			defer target.Close()
			if _, err := installer.Install(context.Background(), current.BundlePath, model.RoleNode); err != nil {
				t.Fatal(err)
			}
			installStandardReleaseMetadata(t, root, current)
			before := snapshotReleaseUpdateRoot(t, root)
			if test.tamper {
				if err := os.WriteFile(filepath.Join(root, "usr/local/libexec/vpnctl/frpc"), []byte("foreign"), 0o755); err != nil {
					t.Fatal(err)
				}
				before = snapshotReleaseUpdateRoot(t, root)
			}
			prepared, err := installer.PrepareUpdate(context.Background(), standardReleaseBundleInRoot(root), target, model.RoleNode)
			if test.tamper {
				if err == nil || prepared != nil {
					t.Fatalf("drift prepared = %+v, %v", prepared, err)
				}
				if after := snapshotReleaseUpdateRoot(t, root); !reflect.DeepEqual(before, after) {
					t.Fatal("failed preflight mutated installed release")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, change := range prepared.Changes() {
				if err := prepared.ActivateComponent(context.Background(), change.Name); err != nil {
					t.Fatal(err)
				}
			}
			if err := prepared.PublishMetadata(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := prepared.Commit(); err != nil {
				t.Fatal(err)
			}
			assertUpdateInstalledFiles(t, root, targetInstalled, targetAssets)
		})
	}
}

func updateReleaseAssetsWithInstalled(t *testing.T, privateKey ed25519.PrivateKey, version, marker string) (map[string][]byte, ReleaseManifest, map[string][]byte) {
	t.Helper()
	installed := map[string][]byte{
		"vpnctl": []byte("vpnctl-" + marker), "frpc": []byte("frpc-" + marker),
		"frps": []byte("frps-" + marker), "mihomo": []byte("mihomo-" + marker),
	}
	assets, manifest := updateReleaseAssetsForInstalled(t, privateKey, version, installed, map[string]string{
		"frp": "0.69.0-" + marker, "mihomo": "v1.19.30-" + marker,
	})
	return assets, manifest, installed
}

func updateReleaseAssetsForInstalled(t *testing.T, privateKey ed25519.PrivateKey, version string, installed map[string][]byte, componentVersions map[string]string) (map[string][]byte, ReleaseManifest) {
	t.Helper()
	frpArchive := testReleaseFRPArchive(t, installed["frpc"], installed["frps"])
	mihomoArchive := testReleaseGzip(t, installed["mihomo"])
	manifest, _ := releaseManifestFixture()
	manifest.ComponentManifest.VPNCTLVersion = version
	artifacts := map[string][]byte{
		"bin/vpnctl": installed["vpnctl"], "components/frp-linux-amd64.tgz": frpArchive,
		"components/mihomo-linux-amd64.gz": mihomoArchive,
	}
	for index := range manifest.Artifacts {
		artifact := &manifest.Artifacts[index]
		artifact.SHA256 = releaseDigest(artifacts[artifact.Path])
		artifact.SizeBytes = int64(len(artifacts[artifact.Path]))
		for componentIndex := range manifest.ComponentManifest.Components {
			component := &manifest.ComponentManifest.Components[componentIndex]
			if component.Name != artifact.Component {
				continue
			}
			component.SHA256 = artifact.SHA256
			if component.Name == "vpnctl" {
				component.Version = version
			} else if componentVersion := componentVersions[component.Name]; componentVersion != "" {
				component.Version = componentVersion
			}
		}
	}
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	var bundle bytes.Buffer
	if err := BuildReleaseBundle(&bundle, manifest, privateKey, artifacts); err != nil {
		t.Fatal(err)
	}
	checksums, _ := NewReleaseChecksums(version, releaseDigest(installed["vpnctl"]), int64(len(installed["vpnctl"])), releaseDigest(bundle.Bytes()), int64(bundle.Len()))
	encoded, _ := EncodeReleaseChecksums(checksums)
	signature, _ := SignReleaseChecksums(encoded, privateKey)
	assets := map[string][]byte{
		ReleaseBinaryAsset: installed["vpnctl"], ReleaseBundleAsset: bundle.Bytes(),
		ReleaseChecksumsAsset: encoded, ReleaseChecksumsSignatureAsset: signature,
	}
	return assets, manifest
}

func writeStagedUpdateRelease(t *testing.T, assets map[string][]byte, manifest ReleaseManifest) *StagedUpdateRelease {
	t.Helper()
	root := t.TempDir()
	for name, content := range assets {
		if err := os.WriteFile(filepath.Join(root, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	checksums, err := DecodeReleaseChecksums(assets[ReleaseChecksumsAsset])
	if err != nil {
		t.Fatal(err)
	}
	return &StagedUpdateRelease{
		Version: checksums.Version, Checksums: checksums, Manifest: manifest, root: root,
		BinaryPath: filepath.Join(root, ReleaseBinaryAsset), BundlePath: filepath.Join(root, ReleaseBundleAsset),
		ChecksumsPath: filepath.Join(root, ReleaseChecksumsAsset), SignaturePath: filepath.Join(root, ReleaseChecksumsSignatureAsset),
	}
}

func currentAssetsManifest(t *testing.T, installer *ReleaseBundleInstaller, assets map[string][]byte) ReleaseManifest {
	t.Helper()
	staged := writeStagedUpdateRelease(t, assets, ReleaseManifest{})
	defer staged.Close()
	manifest, err := installer.Inspect(context.Background(), staged.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func installStandardReleaseMetadata(t *testing.T, root string, staged *StagedUpdateRelease) {
	t.Helper()
	directory := filepath.Join(root, stringsTrimReleaseDirectory())
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for source, target := range map[string]string{
		staged.BundlePath: filepath.Join(root, ReleaseInstalledBundlePath[1:]), staged.ChecksumsPath: filepath.Join(root, ReleaseInstalledChecksumsPath[1:]),
		staged.SignaturePath: filepath.Join(root, ReleaseInstalledSignaturePath[1:]),
	} {
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func stringsTrimReleaseDirectory() string { return ReleaseInstallDirectory[1:] }

func standardReleaseBundleInRoot(root string) string {
	return filepath.Join(root, ReleaseInstalledBundlePath[1:])
}

func snapshotReleaseUpdateRoot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		result[relative] = content
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertUpdateInstalledFiles(t *testing.T, root string, installed, assets map[string][]byte) {
	t.Helper()
	for relative, want := range map[string][]byte{
		"usr/local/bin/vpnctl": installed["vpnctl"], "usr/local/libexec/vpnctl/mihomo": installed["mihomo"],
		"usr/local/lib/vpnctl/release/vpnctl.bundle":     assets[ReleaseBundleAsset],
		"usr/local/lib/vpnctl/release/checksums.txt":     assets[ReleaseChecksumsAsset],
		"usr/local/lib/vpnctl/release/checksums.txt.sig": assets[ReleaseChecksumsSignatureAsset],
	} {
		content, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil || !bytes.Equal(content, want) {
			t.Fatalf("installed %s differs: %v", relative, err)
		}
	}
	frpName := "frps"
	if _, err := os.Stat(filepath.Join(root, "usr/local/libexec/vpnctl/frpc")); err == nil {
		frpName = "frpc"
	}
	content, err := os.ReadFile(filepath.Join(root, "usr/local/libexec/vpnctl/"+frpName))
	if err != nil || !bytes.Equal(content, installed[frpName]) {
		t.Fatalf("installed %s differs: %v", frpName, err)
	}
}
