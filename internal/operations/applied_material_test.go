package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const appliedMaterialTestCanary = "telegram-bot-token-secret-canary"

func TestAppliedMaterialArchiveRoundTripIsCanonicalImmutableAndRedacted(t *testing.T) {
	t.Parallel()

	applied, material, fileKey, unitKey := appliedMaterialFixture(t)
	reversed := applied
	reversed.Resources = append([]ManagedResource(nil), applied.Resources...)
	for left, right := 0, len(reversed.Resources)-1; left < right; left, right = left+1, right-1 {
		reversed.Resources[left], reversed.Resources[right] = reversed.Resources[right], reversed.Resources[left]
	}
	firstID, err := AppliedMaterialIDFor(applied)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := AppliedMaterialIDFor(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if firstID != secondID || len(firstID.String()) != sha256.Size*2 {
		t.Fatalf("canonical IDs = %q and %q", firstID, secondID)
	}

	set, err := NewAppliedMaterialSet(reversed, material)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Destroy()
	if got := fmt.Sprintf("%s %+v %#v", material[0], *set, set); strings.Contains(got, appliedMaterialTestCanary) || !strings.Contains(got, appliedMaterialRedactedMarker) {
		t.Fatalf("formatted material was not redacted: %q", got)
	}
	if _, err := json.Marshal(set); !errors.Is(err, ErrAppliedMaterialSerialization) {
		t.Fatalf("Marshal(set) error = %v", err)
	}
	if _, err := json.Marshal(material[0]); !errors.Is(err, ErrAppliedMaterialSerialization) {
		t.Fatalf("Marshal(material) error = %v", err)
	}
	for index := range material {
		material[index].Destroy()
	}

	archiveRoot := t.TempDir()
	if err := os.Chmod(archiveRoot, AppliedMaterialDirectoryMode); err != nil {
		t.Fatal(err)
	}
	archiveDirectory := filepath.Join(archiveRoot, "applied-material")
	archive, err := NewFileAppliedMaterialArchive(archiveDirectory)
	if err != nil {
		t.Fatal(err)
	}
	publishedID, err := archive.Ensure(context.Background(), reversed, set)
	if err != nil {
		t.Fatal(err)
	}
	if publishedID != firstID {
		t.Fatalf("published ID = %q, want %q", publishedID, firstID)
	}
	if id, err := archive.Ensure(context.Background(), applied, set); err != nil || id != firstID {
		t.Fatalf("idempotent Ensure() = %q, %v", id, err)
	}

	assertAppliedMaterialPath(t, archiveDirectory, os.ModeDir|AppliedMaterialDirectoryMode, 0)
	bundlePath := filepath.Join(archiveDirectory, appliedMaterialBundleName(firstID))
	assertAppliedMaterialPath(t, bundlePath, AppliedMaterialBundleMode, 1)

	loaded, err := archive.Load(context.Background(), applied)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Destroy()
	descriptors := loaded.Descriptors()
	if len(descriptors) != 2 || descriptors[0].Resource != fileKey || descriptors[1].Resource != unitKey {
		t.Fatalf("canonical descriptors = %+v", descriptors)
	}
	if descriptors[0].UnitRuntime != nil || descriptors[1].UnitRuntime == nil || descriptors[1].UnitRuntime.ActiveState != "active" || descriptors[1].UnitRuntime.Enablement != "enabled" {
		t.Fatalf("runtime descriptors = %+v", descriptors)
	}
	if err := loaded.Use(fileKey, func(mode os.FileMode, content []byte, runtime *ManagedUnitRuntime) error {
		if mode != 0o600 || runtime != nil || string(content) != "token="+appliedMaterialTestCanary+"\n" {
			t.Fatalf("file material = mode %04o, content %q, runtime %+v", mode, content, runtime)
		}
		clear(content)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Use(fileKey, func(_ os.FileMode, content []byte, _ *ManagedUnitRuntime) error {
		if string(content) != "token="+appliedMaterialTestCanary+"\n" {
			t.Fatal("Use exposed the archive-owned byte slice")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	loaded.Destroy()
	if loaded.ID() != "" || len(loaded.Descriptors()) != 0 || !errors.Is(loaded.Use(fileKey, func(os.FileMode, []byte, *ManagedUnitRuntime) error { return nil }), ErrAppliedMaterialInvalid) {
		t.Fatal("Destroy did not make loaded material unusable")
	}
	removed, err := archive.Discard(context.Background(), applied)
	if err != nil || !removed {
		t.Fatalf("Discard() = %t, %v", removed, err)
	}
	if removed, err := archive.Discard(context.Background(), applied); err != nil || removed {
		t.Fatalf("idempotent Discard() = %t, %v", removed, err)
	}
	if _, err := archive.Load(context.Background(), applied); !errors.Is(err, ErrAppliedMaterialUnavailable) {
		t.Fatalf("Load() after Discard error = %v", err)
	}
}

func TestAppliedMaterialSetRequiresExactManifestRuntimeAndBounds(t *testing.T) {
	t.Parallel()

	applied, material, _, unitKey := appliedMaterialFixture(t)
	defer func() {
		for index := range material {
			material[index].Destroy()
		}
	}()

	t.Run("missing", func(t *testing.T) {
		if _, err := NewAppliedMaterialSet(applied, material[:1]); !errors.Is(err, ErrAppliedMaterialInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		if _, err := NewAppliedMaterialSet(applied, []AppliedMaterial{material[0], material[0]}); !errors.Is(err, ErrAppliedMaterialInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("manifest-runtime", func(t *testing.T) {
		mismatched := applied
		mismatched.Resources = append([]ManagedResource(nil), applied.Resources...)
		for index := range mismatched.Resources {
			if mismatched.Resources[index].Key.Kind == ManagedResourceFile {
				mismatched.Resources[index].RuntimeSHA256 = strings.Repeat("0", sha256.Size*2)
			}
		}
		if _, err := NewAppliedMaterialSet(mismatched, material); !errors.Is(err, ErrAppliedMaterialInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unit-runtime", func(t *testing.T) {
		content := []byte("[Service]\nExecStart=/usr/bin/vpnctl\n")
		runtime := testAppliedUnitRuntime(content)
		runtime.ActiveState = "inactive"
		candidate, err := NewAppliedUnitMaterial(unitKey, 0o644, content, runtime)
		if err != nil {
			t.Fatal(err)
		}
		defer candidate.Destroy()
		if _, err := NewAppliedMaterialSet(applied, []AppliedMaterial{candidate, material[1]}); !errors.Is(err, ErrAppliedMaterialInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported-kind", func(t *testing.T) {
		_, err := NewAppliedFileMaterial(ManagedResourceKey{Component: "state", Kind: ManagedResourceState, ID: "fleet"}, 0o600, nil)
		if !errors.Is(err, ErrAppliedMaterialInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("content-size", func(t *testing.T) {
		oversized := make([]byte, AppliedMaterialMaximumContentBytes+1)
		_, err := NewAppliedFileMaterial(ManagedResourceKey{Component: "ingress", Kind: ManagedResourceFile, ID: "/etc/vpnctl/large"}, 0o600, oversized)
		clear(oversized)
		if !errors.Is(err, ErrAppliedMaterialInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("entry-count", func(t *testing.T) {
		tooMany := make([]AppliedMaterial, AppliedMaterialMaximumEntries+1)
		if _, err := NewAppliedMaterialSet(applied, tooMany); !errors.Is(err, ErrAppliedMaterialInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("ensure-revalidates-runtime", func(t *testing.T) {
		set, err := NewAppliedMaterialSet(applied, material)
		if err != nil {
			t.Fatal(err)
		}
		defer set.Destroy()
		set.entries[0].content[0] ^= 1
		root := t.TempDir()
		if err := os.Chmod(root, AppliedMaterialDirectoryMode); err != nil {
			t.Fatal(err)
		}
		archive, err := NewFileAppliedMaterialArchive(filepath.Join(root, "archive"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = archive.Ensure(context.Background(), applied, set)
		assertAppliedMaterialError(t, err, ErrAppliedMaterialInvalid)
	})
}

func TestAppliedMaterialArchiveRejectsUnequalUnsafeAndCorruptBundlesWithoutDisclosure(t *testing.T) {
	t.Parallel()

	applied, material, _, _ := appliedMaterialFixture(t)
	set, err := NewAppliedMaterialSet(applied, material)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Destroy()
	for index := range material {
		material[index].Destroy()
	}
	id := set.ID()

	t.Run("unequal", func(t *testing.T) {
		archive, path := newAppliedMaterialTestArchive(t, id)
		if _, err := archive.Ensure(context.Background(), applied, set); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("different "+appliedMaterialTestCanary), AppliedMaterialBundleMode); err != nil {
			t.Fatal(err)
		}
		_, err := archive.Ensure(context.Background(), applied, set)
		assertAppliedMaterialError(t, err, ErrAppliedMaterialConflict)
	})

	t.Run("corrupt-load", func(t *testing.T) {
		archive, path := newAppliedMaterialTestArchive(t, id)
		if _, err := archive.Ensure(context.Background(), applied, set); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{\"content\":\""+appliedMaterialTestCanary+"\"}\n"), AppliedMaterialBundleMode); err != nil {
			t.Fatal(err)
		}
		_, err := archive.Load(context.Background(), applied)
		assertAppliedMaterialError(t, err, ErrAppliedMaterialConflict)
	})

	t.Run("runtime-tamper-load", func(t *testing.T) {
		archive, path := newAppliedMaterialTestArchive(t, id)
		if _, err := archive.Ensure(context.Background(), applied, set); err != nil {
			t.Fatal(err)
		}
		encoded, err := set.encode()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		var bundle appliedMaterialBundle
		if err := json.Unmarshal(encoded, &bundle); err != nil {
			t.Fatal(err)
		}
		defer clearAppliedMaterialBundle(&bundle)
		bundle.Entries[0].Content[0] ^= 1
		tampered, err := json.Marshal(bundle)
		if err != nil {
			t.Fatal(err)
		}
		tampered = append(tampered, '\n')
		defer func() { clear(tampered) }()
		if err := os.WriteFile(path, tampered, AppliedMaterialBundleMode); err != nil {
			t.Fatal(err)
		}
		_, err = archive.Load(context.Background(), applied)
		assertAppliedMaterialError(t, err, ErrAppliedMaterialConflict)
	})

	for _, test := range []struct {
		name  string
		shape func(*testing.T, string, string)
	}{
		{name: "symlink", shape: func(t *testing.T, directory, path string) {
			target := filepath.Join(directory, "target")
			if err := os.WriteFile(target, []byte(appliedMaterialTestCanary), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink", shape: func(t *testing.T, directory, path string) {
			target := filepath.Join(directory, "target")
			if err := os.WriteFile(target, []byte(appliedMaterialTestCanary), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "mode", shape: func(t *testing.T, _, path string) {
			if err := os.WriteFile(path, []byte(appliedMaterialTestCanary), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			archive, path := newAppliedMaterialTestArchive(t, id)
			test.shape(t, filepath.Dir(path), path)
			_, err := archive.Ensure(context.Background(), applied, set)
			assertAppliedMaterialError(t, err, ErrAppliedMaterialUnsafe)
		})
	}

	t.Run("unsafe-parent", func(t *testing.T) {
		parent := t.TempDir()
		if err := os.Chmod(parent, 0o755); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(parent, 0o700)
		archive, err := NewFileAppliedMaterialArchive(filepath.Join(parent, "archive"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = archive.Ensure(context.Background(), applied, set)
		assertAppliedMaterialError(t, err, ErrAppliedMaterialUnsafe)
	})
}

func TestAppliedMaterialArchiveRecoversCrashCandidateAndLoadUsesManifestIdentity(t *testing.T) {
	t.Parallel()

	applied, material, _, _ := appliedMaterialFixture(t)
	set, err := NewAppliedMaterialSet(applied, material)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Destroy()
	for index := range material {
		material[index].Destroy()
	}
	encoded, err := set.encode()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)

	archive, finalPath := newAppliedMaterialTestArchive(t, set.ID())
	directory := filepath.Dir(finalPath)
	candidatePath := filepath.Join(directory, ".candidate-0123456789abcdef01234567")
	if err := os.WriteFile(candidatePath, encoded, AppliedMaterialBundleMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(candidatePath, finalPath); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Ensure(context.Background(), applied, set); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(candidatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crash candidate remains: %v", err)
	}
	assertAppliedMaterialPath(t, finalPath, AppliedMaterialBundleMode, 1)

	other := applied
	other.Generation++
	if _, err := archive.Load(context.Background(), other); !errors.Is(err, ErrAppliedMaterialUnavailable) {
		t.Fatalf("Load(other manifest) error = %v", err)
	}
	loaded, err := archive.Load(context.Background(), applied)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Destroy()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := archive.Ensure(cancelled, applied, set); !errors.Is(err, context.Canceled) {
		t.Fatalf("Ensure(cancelled) error = %v", err)
	}
}

func appliedMaterialFixture(t *testing.T) (ConvergenceManifest, []AppliedMaterial, ManagedResourceKey, ManagedResourceKey) {
	t.Helper()
	fileKey := ManagedResourceKey{Component: "ingress", Kind: ManagedResourceFile, ID: "/etc/vpnctl/generated/gateway.conf"}
	unitKey := ManagedResourceKey{Component: "transport", Kind: ManagedResourceUnit, ID: "vpnctl-standard.service"}
	fileContent := []byte("token=" + appliedMaterialTestCanary + "\n")
	unitContent := []byte("[Service]\nExecStart=/usr/bin/vpnctl serve\n")
	fileMaterial, err := NewAppliedFileMaterial(fileKey, 0o600, fileContent)
	if err != nil {
		t.Fatal(err)
	}
	unitRuntime := testAppliedUnitRuntime(unitContent)
	unitMaterial, err := NewAppliedUnitMaterial(unitKey, 0o644, unitContent, unitRuntime)
	if err != nil {
		fileMaterial.Destroy()
		t.Fatal(err)
	}
	resources := []ManagedResource{
		{
			Key:            ManagedResourceKey{Component: "control", Kind: ManagedResourceState, ID: "fleet"},
			RevisionSHA256: ManagedFingerprint([]byte("state-revision")), RuntimeSHA256: ManagedFingerprint([]byte("state-runtime")),
			ApplyImpact: ConvergenceImpactNone, RemoveImpact: ConvergenceImpactDestructive,
		},
		{
			Key: unitKey, RevisionSHA256: ManagedFingerprint([]byte("unit-revision")), RuntimeSHA256: unitMaterial.entry.runtimeSHA256,
			ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
		},
		{
			Key: fileKey, RevisionSHA256: ManagedFingerprint([]byte("file-revision")), RuntimeSHA256: fileMaterial.entry.runtimeSHA256,
			ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
		},
	}
	applied, err := NewConvergenceManifest(7, resources)
	if err != nil {
		fileMaterial.Destroy()
		unitMaterial.Destroy()
		t.Fatal(err)
	}
	clear(fileContent)
	clear(unitContent)
	return applied, []AppliedMaterial{unitMaterial, fileMaterial}, fileKey, unitKey
}

func testAppliedUnitRuntime(content []byte) ManagedUnitRuntime {
	digest := sha256.Sum256(content)
	return ManagedUnitRuntime{
		FileType: "regular", Mode: "0644", ContentSHA256: hex.EncodeToString(digest[:]),
		LoadState: "loaded", ActiveState: "active", SubState: "running", Enablement: "enabled",
	}
}

func newAppliedMaterialTestArchive(t *testing.T, id AppliedMaterialID) (*FileAppliedMaterialArchive, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, AppliedMaterialDirectoryMode); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "archive")
	if err := os.Mkdir(directory, AppliedMaterialDirectoryMode); err != nil {
		t.Fatal(err)
	}
	archive, err := NewFileAppliedMaterialArchive(directory)
	if err != nil {
		t.Fatal(err)
	}
	return archive, filepath.Join(directory, appliedMaterialBundleName(id))
}

func assertAppliedMaterialPath(t *testing.T, path string, wantMode os.FileMode, wantLinks uint64) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode() != wantMode {
		t.Fatalf("%s mode = %v, want %v", path, info.Mode(), wantMode)
	}
	if wantLinks == 0 {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Nlink) != wantLinks {
		t.Fatalf("%s links = %+v, want %d", path, stat, wantLinks)
	}
}

func assertAppliedMaterialError(t *testing.T, err error, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want %v", err, target)
	}
	if strings.Contains(fmt.Sprint(err), appliedMaterialTestCanary) {
		t.Fatalf("error disclosed material: %v", err)
	}
}
