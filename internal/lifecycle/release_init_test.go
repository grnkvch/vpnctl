package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestGatewayAndNodeInitInspectThenInstallOnlyTheirLocalReleaseRole(t *testing.T) {
	t.Parallel()
	for _, role := range []model.Role{model.RoleGateway, model.RoleNode} {
		role := role
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			manifest, _ := releaseManifestFixture()
			release := &recordingInitReleaseSource{manifest: manifest}
			var planRoot string
			if role == model.RoleGateway {
				harness := newGatewayInitHarnessWithRelease(t, release)
				planRoot = harness.paths.ConfigDir
				plan, err := harness.initializer.Plan(context.Background(), validGatewayInitInput())
				if err != nil {
					t.Fatal(err)
				}
				if release.inspectCalls != 1 || release.installCalls != 0 || plan.releaseManifest.SchemaVersion != ReleaseManifestSchemaVersion {
					t.Fatalf("gateway release plan calls=%d/%d manifest=%+v", release.inspectCalls, release.installCalls, plan.releaseManifest)
				}
				if _, err := harness.initializer.Apply(context.Background(), plan); err != nil {
					t.Fatal(err)
				}
				state, _ := harness.state.Load()
				if !reflect.DeepEqual(state.Components, manifest.ComponentManifest) {
					t.Fatal("gateway state did not persist signed component manifest")
				}
			} else {
				harness := newNodeInitHarnessWithRelease(t, release)
				planRoot = harness.paths.ConfigDir
				plan, err := harness.initializer.Plan(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if release.inspectCalls != 1 || release.installCalls != 0 || plan.releaseManifest.SchemaVersion != ReleaseManifestSchemaVersion {
					t.Fatalf("node release plan calls=%d/%d manifest=%+v", release.inspectCalls, release.installCalls, plan.releaseManifest)
				}
				if _, err := harness.initializer.Apply(context.Background(), plan); err != nil {
					t.Fatal(err)
				}
				state, _ := harness.state.Load()
				if !reflect.DeepEqual(state.Components, manifest.ComponentManifest) {
					t.Fatal("node state did not persist signed component manifest")
				}
			}
			if release.installCalls != 1 || release.installedRole != role {
				t.Fatalf("release installed calls=%d role=%s", release.installCalls, release.installedRole)
			}
			if _, err := os.Lstat(planRoot); err != nil {
				t.Fatalf("successful init did not create layout: %v", err)
			}
		})
	}
}

func TestInitConsumesTheStandardLocalBundleAndInstallsOnlySelectedBinaries(t *testing.T) {
	t.Parallel()
	for _, role := range []model.Role{model.RoleGateway, model.RoleNode} {
		role := role
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			var root string
			var apply func() error
			var setRelease func(InitReleaseSource)
			if role == model.RoleGateway {
				harness := newGatewayInitHarness(t)
				root = harness.paths.Root
				setRelease = func(source InitReleaseSource) { harness.initializer.runtime.Release = source }
				apply = func() error {
					plan, err := harness.initializer.Plan(context.Background(), validGatewayInitInput())
					if err != nil {
						return err
					}
					_, err = harness.initializer.Apply(context.Background(), plan)
					return err
				}
			} else {
				harness := newNodeInitHarness(t)
				root = harness.paths.Root
				setRelease = func(source InitReleaseSource) { harness.initializer.runtime.Release = source }
				apply = func() error {
					plan, err := harness.initializer.Plan(context.Background())
					if err != nil {
						return err
					}
					_, err = harness.initializer.Apply(context.Background(), plan)
					return err
				}
			}

			publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
			manifest, artifacts, installed := releaseBundleFixture(t)
			bundlePath := filepath.Join(root, strings.TrimPrefix(ReleaseInstalledBundlePath, "/"))
			if err := os.MkdirAll(filepath.Dir(bundlePath), 0o700); err != nil {
				t.Fatal(err)
			}
			writeReleaseBundleFile(t, bundlePath, manifest, privateKey, artifacts)
			installer, err := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
			if err != nil {
				t.Fatal(err)
			}
			source, err := NewLocalInitReleaseSource(installer, bundlePath)
			if err != nil {
				t.Fatal(err)
			}
			setRelease(source)
			if err := apply(); err != nil {
				t.Fatal(err)
			}
			assertReleaseInstalledFile(t, root, "usr/local/bin/vpnctl", installed["vpnctl"])
			assertReleaseInstalledFile(t, root, "usr/local/libexec/vpnctl/mihomo", installed["mihomo"])
			present, absent := "frpc", "frps"
			if role == model.RoleGateway {
				present, absent = "frps", "frpc"
			}
			assertReleaseInstalledFile(t, root, "usr/local/libexec/vpnctl/"+present, installed[present])
			if _, err := os.Lstat(filepath.Join(root, "usr/local/libexec/vpnctl", absent)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s init installed opposite binary %s: %v", role, absent, err)
			}
		})
	}
}

func TestInitReleaseFailurePrecedesPersistentLayoutAndState(t *testing.T) {
	t.Parallel()
	manifest, _ := releaseManifestFixture()
	t.Run("inspect", func(t *testing.T) {
		release := &recordingInitReleaseSource{manifest: manifest, inspectErr: errors.New("invalid signed bundle")}
		harness := newNodeInitHarnessWithRelease(t, release)
		if _, err := harness.initializer.Plan(context.Background()); err == nil || release.installCalls != 0 {
			t.Fatalf("inspect failure error=%v installCalls=%d", err, release.installCalls)
		}
		if _, err := os.Lstat(harness.paths.ConfigDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("inspect failure created layout: %v", err)
		}
		if _, err := harness.state.Load(); !errors.Is(err, store.ErrStateNotFound) {
			t.Fatalf("inspect failure created state: %v", err)
		}
	})

	t.Run("changed after plan", func(t *testing.T) {
		release := &recordingInitReleaseSource{manifest: manifest}
		harness := newNodeInitHarnessWithRelease(t, release)
		plan, err := harness.initializer.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		release.installManifest = manifest
		release.installManifest.ComponentManifest.VPNCTLVersion = "v2.0.1"
		if _, err := harness.initializer.Apply(context.Background(), plan); err == nil {
			t.Fatal("changed release was accepted after planning")
		}
		if _, err := os.Lstat(harness.paths.ConfigDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale release created layout: %v", err)
		}
		if _, err := harness.state.Load(); !errors.Is(err, store.ErrStateNotFound) {
			t.Fatalf("stale release created state: %v", err)
		}
	})
}

type recordingInitReleaseSource struct {
	manifest        ReleaseManifest
	installManifest ReleaseManifest
	inspectErr      error
	installErr      error
	inspectCalls    int
	installCalls    int
	installedRole   model.Role
}

func (source *recordingInitReleaseSource) Inspect(context.Context) (ReleaseManifest, error) {
	source.inspectCalls++
	if source.inspectErr != nil {
		return ReleaseManifest{}, source.inspectErr
	}
	return cloneReleaseManifest(source.manifest), nil
}

func (source *recordingInitReleaseSource) Install(_ context.Context, role model.Role) (ReleaseBundleInstallResult, error) {
	source.installCalls++
	source.installedRole = role
	if source.installErr != nil {
		return ReleaseBundleInstallResult{}, source.installErr
	}
	manifest := source.installManifest
	if manifest.SchemaVersion == 0 {
		manifest = source.manifest
	}
	return ReleaseBundleInstallResult{Manifest: cloneReleaseManifest(manifest)}, nil
}
