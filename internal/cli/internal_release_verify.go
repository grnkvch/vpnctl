package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strconv"

	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
)

// executeInternalReleaseBundleVerification is a bootstrap-only protocol used
// by scripts/install.sh after it verifies the three downloaded release assets.
// It is intentionally omitted from the public command registry and help.
func executeInternalReleaseBundleVerification(args []string, stderr io.Writer) int {
	if len(args) != 4 {
		fmt.Fprintln(stderr, "release bundle verification failed")
		return ExitValidation
	}
	bundlePath, expectedVersion, binarySHA256 := args[0], args[1], args[2]
	binarySize, err := strconv.ParseInt(args[3], 10, 64)
	if err != nil || strconv.FormatInt(binarySize, 10) != args[3] ||
		!filepath.IsAbs(bundlePath) || filepath.Clean(bundlePath) != bundlePath {
		fmt.Fprintln(stderr, "release bundle verification failed")
		return ExitValidation
	}
	installer, err := lifecycle.NewReleaseBundleInstaller(filepath.Dir(bundlePath), lifecycle.ReleasePlatform{
		OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64",
	})
	if err != nil {
		fmt.Fprintln(stderr, "release bundle verification failed")
		return ExitValidation
	}
	manifest, err := installer.Inspect(context.Background(), bundlePath)
	if err != nil {
		fmt.Fprintln(stderr, "release bundle verification failed")
		return ExitValidation
	}
	expected, err := lifecycle.NewV2ReleaseManifest(expectedVersion, binarySHA256, binarySize, true)
	if err != nil || !reflect.DeepEqual(manifest, expected) {
		fmt.Fprintln(stderr, "release bundle verification failed")
		return ExitValidation
	}
	return ExitSuccess
}
