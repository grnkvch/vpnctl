package operations

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFileConvergenceSnapshotSourceReadsCanonicalClosedSnapshot(t *testing.T) {
	t.Parallel()
	path := convergenceSnapshotTestPath(t)
	first := ManagedResource{
		Key:            ManagedResourceKey{Component: "routing", Kind: ManagedResourceUnit, ID: "vpnctl-routing.service"},
		RevisionSHA256: ManagedFingerprint([]byte("routing-revision")), RuntimeSHA256: ManagedFingerprint([]byte("routing-runtime")),
		ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
	}
	second := ManagedResource{
		Key:            ManagedResourceKey{Component: "control", Kind: ManagedResourceState, ID: "fleet"},
		RevisionSHA256: ManagedFingerprint([]byte("control-revision")), RuntimeSHA256: ManagedFingerprint([]byte("control-runtime")),
		ApplyImpact: ConvergenceImpactNone, RemoveImpact: ConvergenceImpactNone,
	}
	desired, err := NewConvergenceManifest(4, []ManagedResource{first, second})
	if err != nil {
		t.Fatal(err)
	}
	applied, err := NewConvergenceManifest(4, []ManagedResource{second, first})
	if err != nil {
		t.Fatal(err)
	}
	written := ConvergenceSnapshot{Desired: desired, Applied: applied, Pending: []PendingOperation{}}
	writeConvergenceSnapshotFixture(t, path, written, 0o600)
	source, err := NewFileConvergenceSnapshotSource(path)
	if err != nil {
		t.Fatal(err)
	}

	read, err := source.ReadConvergenceSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read.Desired, read.Applied) || read.Pending == nil || len(read.Pending) != 0 {
		t.Fatalf("snapshot = %+v", read)
	}
	if read.Desired.Resources[0].Key.Component != "control" || read.Desired.Resources[1].Key.Component != "routing" {
		t.Fatalf("resources are not canonical: %+v", read.Desired.Resources)
	}
}

func TestFileConvergenceSnapshotSourceSeparatesUnavailableFromInvalid(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	missing := filepath.Join(root, "missing", "convergence.json")
	source, err := NewFileConvergenceSnapshotSource(missing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.ReadConvergenceSnapshot(context.Background()); !errors.Is(err, ErrConvergenceSnapshotUnavailable) || errors.Is(err, ErrConvergencePlanInvalid) {
		t.Fatalf("missing error = %v", err)
	}

	invalidPath := filepath.Join(root, "invalid", "convergence.json")
	if err := os.MkdirAll(filepath.Dir(invalidPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalidPath, []byte(`{"desired":{},"applied":{},"pending":[],"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid, err := NewFileConvergenceSnapshotSource(invalidPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invalid.ReadConvergenceSnapshot(context.Background()); !errors.Is(err, ErrConvergencePlanInvalid) {
		t.Fatalf("invalid error = %v", err)
	}
}

func TestFileConvergenceSnapshotSourceRejectsUnsafeFilesAndTrailingJSON(t *testing.T) {
	t.Parallel()
	valid := emptyConvergenceSnapshotFixture(t, 2)
	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		mode os.FileMode
		data []byte
	}{
		{name: "world-readable", mode: 0o644, data: encoded},
		{name: "empty", mode: 0o600, data: []byte{}},
		{name: "trailing-value", mode: 0o600, data: append(append([]byte{}, encoded...), []byte(` {}`)...)},
		{name: "too-large", mode: 0o600, data: []byte(strings.Repeat("x", MaximumConvergenceSnapshotBytes+1))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := convergenceSnapshotTestPath(t)
			writeConvergenceSnapshotFixture(t, path, test.data, test.mode)
			source, err := NewFileConvergenceSnapshotSource(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.ReadConvergenceSnapshot(context.Background()); !errors.Is(err, ErrConvergencePlanInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestFileConvergenceSnapshotSourceRejectsSymlinkAndCancellation(t *testing.T) {
	t.Parallel()
	path := convergenceSnapshotTestPath(t)
	target := filepath.Join(filepath.Dir(path), "target.json")
	writeConvergenceSnapshotFixture(t, target, emptyConvergenceSnapshotFixture(t, 3), 0o600)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	source, err := NewFileConvergenceSnapshotSource(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.ReadConvergenceSnapshot(context.Background()); !errors.Is(err, ErrConvergencePlanInvalid) {
		t.Fatalf("symlink error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.ReadConvergenceSnapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
}

func TestNewFileConvergenceSnapshotSourceRejectsUnsafePaths(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"", "convergence.json", "/var/lib/vpnctl/../convergence.json", "/var/lib/vpnctl/status.json"} {
		if _, err := NewFileConvergenceSnapshotSource(path); err == nil {
			t.Fatalf("NewFileConvergenceSnapshotSource(%q) error = nil", path)
		}
	}
}

func convergenceSnapshotTestPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state", "convergence.json")
}

func emptyConvergenceSnapshotFixture(t *testing.T, generation uint64) ConvergenceSnapshot {
	t.Helper()
	manifest, err := NewConvergenceManifest(generation, []ManagedResource{})
	if err != nil {
		t.Fatal(err)
	}
	return ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}}
}

func writeConvergenceSnapshotFixture(t *testing.T, path string, value any, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, ok := value.([]byte)
	if !ok {
		var err error
		data, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
