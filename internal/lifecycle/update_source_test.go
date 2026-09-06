package lifecycle

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestUpdateReleaseSourceContactsOnlyRequestedLatestOrExactReleaseAndStagesWholeBundle(t *testing.T) {
	assets := updateReleaseAssets(t, "v2.1.0")
	var mu sync.Mutex
	requests := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests = append(requests, request.URL.Path)
		mu.Unlock()
		name := filepath.Base(request.URL.Path)
		content, found := assets[name]
		if !found {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/octet-stream")
		_, _ = writer.Write(content)
	}))
	defer server.Close()
	inspector, err := NewReleaseBundleInstaller(t.TempDir(), ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewUpdateReleaseSource(server.URL+"/releases", server.Client(), inspector)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 0 {
		t.Fatal("constructing an update source contacted the release server")
	}
	latest, err := source.Stage(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if latest.Version != "v2.1.0" || latest.Manifest.ComponentManifest.VPNCTLVersion != latest.Version || !latest.valid() {
		t.Fatalf("latest stage = %+v", latest)
	}
	for name, path := range map[string]string{
		ReleaseBinaryAsset: latest.BinaryPath, ReleaseBundleAsset: latest.BundlePath,
		ReleaseChecksumsAsset: latest.ChecksumsPath,
	} {
		content, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(content, assets[name]) {
			t.Fatalf("staged %s differs: %v", name, err)
		}
	}
	root := latest.root
	if err := latest.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("closed update stage remains: %v", err)
	}

	exact, err := source.Stage(context.Background(), "2.1.0")
	if err != nil {
		t.Fatal(err)
	}
	defer exact.Close()
	want := []string{}
	for _, prefix := range []string{"/releases/latest/download/", "/releases/download/v2.1.0/"} {
		for _, name := range []string{ReleaseChecksumsAsset, ReleaseBinaryAsset, ReleaseBundleAsset} {
			want = append(want, prefix+name)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("release requests = %q, want %q", requests, want)
	}
}

func TestUpdateReleaseSourceRejectsCorruptionAndVersionMismatchWithoutRetainedStage(t *testing.T) {
	for name, test := range map[string]struct {
		mutate    func(map[string][]byte)
		requested string
	}{
		"checksum metadata":  {mutate: func(assets map[string][]byte) { assets[ReleaseChecksumsAsset][0] ^= 1 }},
		"binary":             {mutate: func(assets map[string][]byte) { assets[ReleaseBinaryAsset] = append(assets[ReleaseBinaryAsset], 'x') }},
		"bundle":             {mutate: func(assets map[string][]byte) { assets[ReleaseBundleAsset][len(assets[ReleaseBundleAsset])-1] ^= 1 }},
		"version mismatch":   {mutate: func(map[string][]byte) {}, requested: "v2.2.0"},
		"prerelease request": {mutate: func(map[string][]byte) {}, requested: "v2.1.0-beta.1"},
	} {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			assets := updateReleaseAssets(t, "v2.1.0")
			test.mutate(assets)
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				content, found := assets[filepath.Base(request.URL.Path)]
				if !found {
					http.NotFound(writer, request)
					return
				}
				_, _ = writer.Write(content)
			}))
			defer server.Close()
			inspector, _ := NewReleaseBundleInstaller(t.TempDir(), ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
			source, _ := NewUpdateReleaseSource(server.URL, server.Client(), inspector)
			if staged, err := source.Stage(context.Background(), test.requested); err == nil || staged != nil {
				t.Fatalf("corrupt release staged: %+v, %v", staged, err)
			}
		})
	}
}

func updateReleaseAssets(t *testing.T, version string) map[string][]byte {
	t.Helper()
	manifest, artifacts, installed := releaseBundleFixture(t)
	manifest.ComponentManifest.VPNCTLVersion = version
	for index := range manifest.ComponentManifest.Components {
		if manifest.ComponentManifest.Components[index].Name == "vpnctl" {
			manifest.ComponentManifest.Components[index].Version = version
		}
	}
	var bundle bytes.Buffer
	if err := BuildReleaseBundle(&bundle, manifest, artifacts); err != nil {
		t.Fatal(err)
	}
	checksums, err := NewReleaseChecksums(version, releaseDigest(installed["vpnctl"]), int64(len(installed["vpnctl"])), releaseDigest(bundle.Bytes()), int64(bundle.Len()))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeReleaseChecksums(checksums)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		ReleaseBinaryAsset: append([]byte(nil), installed["vpnctl"]...), ReleaseBundleAsset: append([]byte(nil), bundle.Bytes()...),
		ReleaseChecksumsAsset: append([]byte(nil), encoded...),
	}
}
