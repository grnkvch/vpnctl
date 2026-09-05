package operations

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/render"
)

func TestFilesystemOwnedResourceDiscovererMatchesRenderedFileManifest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	logical := "/etc/vpnctl/generated/routing.yaml"
	content := []byte("mode: rule\n")
	writeManagedObservationFile(t, root, logical, content, 0o640)
	manifest := managedFileManifest(t, 5, logical, content, 0o640)
	discoverer, err := NewFilesystemOwnedResourceDiscoverer(root)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := NewConvergencePlanner(
		staticConvergenceSource{snapshot: ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}}},
		discoverer,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 0 || len(plan.Drift) != 0 || plan.Impact != ConvergenceImpactNone {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestFilesystemOwnedResourceDiscovererReportsMissingAndModifiedShapes(t *testing.T) {
	t.Parallel()
	logical := "/etc/vpnctl/generated/transport.yaml"
	expected := []byte("expected\n")
	tests := []struct {
		name    string
		prepare func(*testing.T, string)
		kind    OwnedDriftKind
	}{
		{name: "missing", prepare: func(*testing.T, string) {}, kind: OwnedDriftMissing},
		{name: "content", prepare: func(t *testing.T, root string) {
			writeManagedObservationFile(t, root, logical, []byte("changed\n"), 0o600)
		}, kind: OwnedDriftModified},
		{name: "mode", prepare: func(t *testing.T, root string) { writeManagedObservationFile(t, root, logical, expected, 0o644) }, kind: OwnedDriftModified},
		{name: "symlink", prepare: func(t *testing.T, root string) {
			t.Helper()
			target := filepath.Join(root, "target")
			if err := os.WriteFile(target, []byte("secret-canary"), 0o600); err != nil {
				t.Fatal(err)
			}
			actual := managedObservationPath(root, logical)
			if err := os.MkdirAll(filepath.Dir(actual), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, actual); err != nil {
				t.Fatal(err)
			}
		}, kind: OwnedDriftModified},
		{name: "directory", prepare: func(t *testing.T, root string) {
			t.Helper()
			if err := os.MkdirAll(managedObservationPath(root, logical), 0o700); err != nil {
				t.Fatal(err)
			}
		}, kind: OwnedDriftModified},
		{name: "hardlink", prepare: func(t *testing.T, root string) {
			t.Helper()
			target := filepath.Join(root, "foreign")
			if err := os.WriteFile(target, []byte("hardlink-secret-canary"), 0o600); err != nil {
				t.Fatal(err)
			}
			actual := managedObservationPath(root, logical)
			if err := os.MkdirAll(filepath.Dir(actual), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(target, actual); err != nil {
				t.Fatal(err)
			}
		}, kind: OwnedDriftModified},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.prepare(t, root)
			manifest := managedFileManifest(t, 6, logical, expected, 0o600)
			discoverer, err := NewFilesystemOwnedResourceDiscoverer(root)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := discoverer.DiscoverOwnedResources(context.Background(), manifest)
			if err != nil {
				t.Fatal(err)
			}
			drift := ownedDrift(manifest.Resources, observed)
			if len(drift) != 1 || drift[0].Kind != test.kind || drift[0].Resource.ID != logical {
				t.Fatalf("drift = %+v", drift)
			}
			if encoded := drift[0].ActualSHA256; strings.Contains(encoded, "secret-canary") || strings.Contains(encoded, "changed") {
				t.Fatalf("drift leaked file content: %+v", drift[0])
			}
		})
	}
}

func TestFilesystemOwnedResourceDiscovererRejectsForeignAndUnsupportedResources(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	discoverer, err := NewFilesystemOwnedResourceDiscoverer(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []ManagedResourceKey{
		{Component: "state", Kind: ManagedResourceFile, ID: "/etc/shadow"},
		{Component: "routing", Kind: ManagedResourceUnit, ID: "vpnctl-routing.service"},
	} {
		manifest, err := NewConvergenceManifest(2, []ManagedResource{{
			Key: key, RevisionSHA256: ManagedFingerprint([]byte("revision")), RuntimeSHA256: ManagedFingerprint([]byte("runtime")),
			ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := discoverer.DiscoverOwnedResources(context.Background(), manifest); !errors.Is(err, ErrOwnedResourceDiscoveryUnsupported) {
			t.Fatalf("key=%+v error=%v", key, err)
		}
	}
}

func TestFilesystemOwnedResourceDiscovererRejectsOversizeAndCancellation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	logical := "/etc/vpnctl/generated/large.yaml"
	actual := managedObservationPath(root, logical)
	if err := os.MkdirAll(filepath.Dir(actual), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(actual, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaximumManagedFileObservationBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	manifest := managedFileManifest(t, 7, logical, []byte("expected"), 0o600)
	discoverer, err := NewFilesystemOwnedResourceDiscoverer(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := discoverer.DiscoverOwnedResources(context.Background(), manifest); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := discoverer.DiscoverOwnedResources(ctx, manifest); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
}

func TestNewFilesystemOwnedResourceDiscovererRejectsUnsafeRoots(t *testing.T) {
	t.Parallel()
	for _, root := range []string{"", ".", "relative", "/tmp/../var"} {
		if _, err := NewFilesystemOwnedResourceDiscoverer(root); err == nil {
			t.Fatalf("NewFilesystemOwnedResourceDiscoverer(%q) error = nil", root)
		}
	}
}

func managedFileManifest(t *testing.T, generation uint64, path string, content []byte, mode os.FileMode) ConvergenceManifest {
	t.Helper()
	artifacts, err := render.BuildManifest(generation, []render.ArtifactInput{{Path: path, Mode: mode, Content: content}})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ArtifactConvergenceManifest("routing", artifacts, ConvergenceImpactAvailability, ConvergenceImpactAvailability)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func writeManagedObservationFile(t *testing.T, root, logical string, content []byte, mode os.FileMode) {
	t.Helper()
	actual := managedObservationPath(root, logical)
	if err := os.MkdirAll(filepath.Dir(actual), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(actual, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(actual, mode); err != nil {
		t.Fatal(err)
	}
}

func managedObservationPath(root, logical string) string {
	return filepath.Join(root, strings.TrimPrefix(logical, "/"))
}
