package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestUpdateSnapshotRejectsTamperedStateAndSymlinkedRelease(t *testing.T) {
	for _, test := range []struct {
		name   string
		tamper func(*testing.T, string)
	}{
		{
			name: "state checksum",
			tamper: func(t *testing.T, root string) {
				path := filepath.Join(root, updateSnapshotStateFile)
				encoded, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(encoded, ' '), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlinked signature",
			tamper: func(t *testing.T, root string) {
				path := filepath.Join(root, updateSnapshotSignatureFile)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, updateSnapshotChecksumsFile), path); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := updatedFixtureWithSnapshot(t, model.RoleGateway)
			pointer, err := loadUpdateSnapshotPointer(filepath.Join(fixture.snapshots.root, updateSnapshotPreviousFile))
			if err != nil {
				t.Fatal(err)
			}
			test.tamper(t, filepath.Join(fixture.snapshots.root, "update-"+pointer.SnapshotID))
			if _, err := fixture.snapshots.LoadPrevious(context.Background()); !errors.Is(err, ErrUpdateSnapshotInvalid) {
				t.Fatalf("tampered snapshot load = %v", err)
			}
		})
	}
}

func TestUpdateSnapshotPendingBlocksRollbackAndAbortPreservesPrevious(t *testing.T) {
	fixture := updatedFixtureWithSnapshot(t, model.RoleNode)
	previous, err := fixture.snapshots.LoadPrevious(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	previousID := previous.Metadata.SnapshotID
	_ = previous.Close()
	current := fixture.state.state
	candidate, err := fixture.snapshots.Prepare(context.Background(), UpdateSnapshotInput{
		OperationID: "90000000-0000-4000-8000-000000000030", Role: model.RoleNode,
		UpdatedToVersion: "v2.2.0", UpdatedStateSchema: current.SchemaVersion, MigrationReversible: true,
		CreatedAt: fixture.updater.runtime.Now().UTC().Truncate(0), PreviousState: current,
		Release: UpdateSnapshotReleaseFiles{
			BundlePath:    standardReleaseBundleInRoot(fixture.root),
			ChecksumsPath: filepath.Join(fixture.root, "usr/local/lib/vpnctl/release/checksums.txt"),
			SignaturePath: filepath.Join(fixture.root, "usr/local/lib/vpnctl/release/checksums.txt.sig"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.snapshots.LoadPrevious(context.Background()); !errors.Is(err, ErrUpdateSnapshotPending) {
		t.Fatalf("pending snapshot did not block rollback: %v", err)
	}
	if err := candidate.Abort(); err != nil {
		t.Fatal(err)
	}
	retained, err := fixture.snapshots.LoadPrevious(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer retained.Close()
	if retained.Metadata.SnapshotID != previousID {
		t.Fatalf("abort replaced previous snapshot: got %s want %s", retained.Metadata.SnapshotID, previousID)
	}
}
