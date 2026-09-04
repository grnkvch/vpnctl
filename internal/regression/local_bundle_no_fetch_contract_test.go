package regression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundledComponentsHaveNoInitApplyRepairUpstreamFetchPath(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	files := []string{
		"internal/lifecycle/release_bundle.go",
		"internal/cli/gateway_init.go",
		"internal/cli/node_init.go",
		"internal/lifecycle/gateway_init.go",
		"internal/lifecycle/node_init.go",
		"internal/operations/apply.go",
		"internal/operations/repair.go",
	}
	for _, relative := range files {
		content, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		source := string(content)
		for _, forbidden := range []string{"\"net/http\"", "\"os/exec\"", "http://", "https://", "curl", "wget"} {
			if strings.Contains(source, forbidden) {
				t.Errorf("%s contains forbidden bundled-component fetch primitive %q", relative, forbidden)
			}
		}
	}
	bundleSource, err := os.ReadFile(filepath.Join(root, "internal/lifecycle/release_bundle.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"BuildReleaseBundle", "NewReleaseBundleInstaller", "os.Lstat(bundlePath)", "DecodeAndVerifyReleaseManifest", "VerifyReleasePlatform"} {
		if !strings.Contains(string(bundleSource), required) {
			t.Errorf("local bundle boundary omits %q", required)
		}
	}
}
