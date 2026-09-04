package lifecycle

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestGatewayRestoreArchiveLoaderAuthenticatesAndValidatesStructuralPayload(t *testing.T) {
	archivePath, passphrase, sourceState := writeGatewayRestoreArchiveFixture(t)
	scratch := t.TempDir()
	loader, err := newGatewayRestoreArchiveLoader(scratch, fastBackupArchiveCodec())
	if err != nil {
		t.Fatal(err)
	}
	entered := append([]byte(nil), passphrase...)
	payload, err := loader.Load(context.Background(), archivePath, entered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entered, make([]byte, len(entered))) {
		t.Fatal("restore archive loader did not wipe the caller-owned passphrase")
	}
	if !reflect.DeepEqual(payload.State(), sourceState) {
		t.Fatal("restored authoritative state differs from the authenticated archive")
	}
	files := payload.Files()
	if len(files) < 2 || files[len(files)-1].Path != "state/state.json" {
		t.Fatalf("staged restore files = %#v", files)
	}
	stateFile, err := payload.Open("state/state.json")
	if err != nil {
		t.Fatal(err)
	}
	if info, err := stateFile.Stat(); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("staged state mode = %v, %v", info, err)
	}
	_ = stateFile.Close()
	stage := payload.root
	if err := payload.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private restore stage remains after close: %v", err)
	}
}

func TestGatewayRestoreArchiveLoaderRejectsAuthenticationAndSourcePathAttacks(t *testing.T) {
	archivePath, passphrase, _ := writeGatewayRestoreArchiveFixture(t)
	loader, err := newGatewayRestoreArchiveLoader(t.TempDir(), fastBackupArchiveCodec())
	if err != nil {
		t.Fatal(err)
	}

	wrong := []byte("wrong restore passphrase")
	if _, err := loader.Load(context.Background(), archivePath, wrong); !errors.Is(err, ErrBackupAuthentication) {
		t.Fatalf("wrong-passphrase error = %v", err)
	}
	if !bytes.Equal(wrong, make([]byte, len(wrong))) {
		t.Fatal("failed restore did not wipe the passphrase")
	}

	tampered := filepath.Join(t.TempDir(), "tampered.v2b")
	content, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-1] ^= 0x80
	if err := os.WriteFile(tampered, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loader.Load(context.Background(), tampered, append([]byte(nil), passphrase...)); err == nil ||
		(!errors.Is(err, ErrBackupAuthentication) && !errors.Is(err, ErrBackupArchiveInvalid)) {
		t.Fatalf("tampered archive error = %v", err)
	}

	symlink := filepath.Join(t.TempDir(), "backup-link.v2b")
	if err := os.Symlink(archivePath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := loader.Load(context.Background(), symlink, append([]byte(nil), passphrase...)); !errors.Is(err, ErrGatewayRestoreArchiveInvalid) {
		t.Fatalf("symlink archive error = %v", err)
	}
}

func TestGatewayRestoreArchiveLoaderRejectsAuthenticatedExtraAndMissingEntries(t *testing.T) {
	archivePath, passphrase, state := writeGatewayRestoreArchiveFixture(t)
	encrypted, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	_, files := decryptGatewayBackupFiles(t, encrypted, passphrase)
	delete(files, "manifest.json")

	for _, test := range []struct {
		name   string
		mutate func(map[string][]byte)
	}{
		{
			name: "application entry",
			mutate: func(values map[string][]byte) {
				values["state/application/database"] = []byte("authenticated application canary")
			},
		},
		{
			name: "missing required gateway secret",
			mutate: func(values map[string][]byte) {
				delete(values, "secrets/enrollment-key/gateway")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneRestoreTestFiles(files)
			test.mutate(candidate)
			path := writeAuthenticatedRestoreTestFiles(t, state, candidate, passphrase)
			loader, err := newGatewayRestoreArchiveLoader(t.TempDir(), fastBackupArchiveCodec())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := loader.Load(context.Background(), path, append([]byte(nil), passphrase...)); !errors.Is(err, ErrGatewayRestoreArchiveInvalid) {
				t.Fatalf("structurally invalid authenticated archive error = %v", err)
			}
		})
	}
}

func writeGatewayRestoreArchiveFixture(t *testing.T) (string, []byte, model.State) {
	t.Helper()
	fixture := newBackupAllowlistFixture(t)
	backupper, err := newGatewayBackupper(GatewayBackupRuntime{
		State: fixture.state, Payloads: fixture.source, BackupsDir: fixture.paths.BackupsDir,
		Now:     func() time.Time { return fixture.now.Add(time.Minute) },
		NewUUID: func() (string, error) { return "95000000-0000-4000-8000-000000000001", nil },
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x35}, 256)),
	}, fastBackupArchiveCodec())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := backupper.Plan(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	state := plan.state
	passphrase := []byte("restore archive fixture passphrase")
	result, err := backupper.Apply(context.Background(), plan, append([]byte(nil), passphrase...))
	if err != nil {
		t.Fatal(err)
	}
	return result.OutputPath, passphrase, state
}

func writeAuthenticatedRestoreTestFiles(t *testing.T, state model.State, files map[string][]byte, passphrase []byte) string {
	t.Helper()
	var plaintext bytes.Buffer
	if err := writeCanonicalRestoreTestTar(&plaintext, state, files); err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if err := fastBackupArchiveCodec().encrypt(&encrypted, append([]byte(nil), passphrase...), bytes.NewReader(bytes.Repeat([]byte{0x5a}, 256)), func(destination io.Writer) error {
		_, err := destination.Write(plaintext.Bytes())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authenticated-test.v2b")
	if err := os.WriteFile(path, encrypted.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCanonicalRestoreTestTar(destination io.Writer, state model.State, files map[string][]byte) error {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]backupPayloadManifestEntry, 0, len(names))
	for _, name := range names {
		digest := sha256.Sum256(files[name])
		entries = append(entries, backupPayloadManifestEntry{Path: name, SizeBytes: int64(len(files[name])), SHA256: hex.EncodeToString(digest[:])})
	}
	manifest := backupPayloadManifest{SchemaVersion: 1, Format: backupPayloadFormat, StateGeneration: state.Generation, PublicIPv4: state.Host.PublicIPv4, Entries: entries}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	tape := tar.NewWriter(destination)
	all := append([]string{"manifest.json"}, names...)
	for _, name := range all {
		content := files[name]
		if name == "manifest.json" {
			content = encoded
		}
		if err := tape.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return err
		}
		if _, err := tape.Write(content); err != nil {
			return err
		}
	}
	return tape.Close()
}

func cloneRestoreTestFiles(files map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(files))
	for name, content := range files {
		result[name] = append([]byte(nil), content...)
	}
	return result
}
