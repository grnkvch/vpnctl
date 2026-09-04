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
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestGatewayBackupWritesAtomicEncryptedArchiveAndMetadata(t *testing.T) {
	backupper, state, backupDir, now := newGatewayBackupFixture(t, StateBackupPayloadSource{})
	plan, err := backupper.Plan(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(backupDir, "vpnctl-20260904T140506Z.v2b")
	if plan.OutputPath != wantPath || plan.ExpectedStateGeneration != state.state.Generation || !plan.CreatedAt.Equal(now) {
		t.Fatalf("backup plan = %+v", plan)
	}
	if _, err := os.Lstat(wantPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("backup plan created output: %v", err)
	}
	passphrase := []byte("correct horse battery staple")
	result, err := backupper.Apply(context.Background(), plan, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(passphrase, make([]byte, len(passphrase))) {
		t.Fatal("backup manager retained caller passphrase bytes")
	}
	info, err := os.Lstat(result.OutputPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != BackupFileMode || info.Size() != result.SizeBytes {
		t.Fatalf("backup output info=%v result=%+v error=%v", info, result, err)
	}
	content, err := os.ReadFile(result.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if result.SHA256 != hex.EncodeToString(digest[:]) || bytes.Contains(content, []byte("correct horse battery staple")) || bytes.Contains(content, []byte(`"public_ipv4"`)) {
		t.Fatal("backup hash differs or encrypted archive exposed plaintext")
	}
	if state.saves != 1 || state.state.Generation != plan.ExpectedStateGeneration+1 || len(state.state.Backups) != 1 {
		t.Fatalf("backup metadata state=%+v saves=%d", state.state.Backups, state.saves)
	}
	metadata := state.state.Backups[0]
	if metadata.ID != result.BackupID || metadata.Path != result.OutputPath || metadata.SHA256 != result.SHA256 ||
		metadata.SizeBytes != result.SizeBytes || metadata.StateGeneration != plan.ExpectedStateGeneration || metadata.Format != BackupArchiveFormat {
		t.Fatalf("backup metadata = %+v", metadata)
	}
	manifest, archivedState := decryptGatewayBackupPayload(t, content, []byte("correct horse battery staple"))
	if manifest.StateGeneration != plan.ExpectedStateGeneration || manifest.PublicIPv4 != plan.PublicIPv4 || len(manifest.Entries) != 1 {
		t.Fatalf("backup manifest = %+v", manifest)
	}
	decoded, err := model.DecodeState(archivedState)
	if err != nil || !reflect.DeepEqual(decoded, plan.state) {
		t.Fatalf("archived state differs from planned snapshot: %v", err)
	}
	stateDigest := sha256.Sum256(archivedState)
	if manifest.Entries[0].Path != "state/state.json" || manifest.Entries[0].SHA256 != hex.EncodeToString(stateDigest[:]) || manifest.Entries[0].SizeBytes != int64(len(archivedState)) {
		t.Fatalf("archived state manifest entry = %+v", manifest.Entries[0])
	}
}

func TestGatewayBackupRefusesExistingTargetAtPlanAndPublish(t *testing.T) {
	backupper, state, backupDir, _ := newGatewayBackupFixture(t, StateBackupPayloadSource{})
	target := filepath.Join(backupDir, "custom.backup")
	if err := os.WriteFile(target, []byte("foreign"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := backupper.Plan(context.Background(), target); !errors.Is(err, ErrBackupExists) {
		t.Fatalf("existing target plan error = %v", err)
	}
	if content, _ := os.ReadFile(target); string(content) != "foreign" || state.saves != 0 {
		t.Fatal("existing target changed during plan")
	}

	second := filepath.Join(backupDir, "appears-after-plan.backup")
	plan, err := backupper.Plan(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("racing foreign file"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := backupper.Apply(context.Background(), plan, []byte("passphrase")); !errors.Is(err, ErrBackupExists) {
		t.Fatalf("publish race error = %v", err)
	}
	if content, _ := os.ReadFile(second); string(content) != "racing foreign file" || state.saves != 0 {
		t.Fatal("publish race overwrote target or changed state")
	}
	assertNoBackupTemporaries(t, backupDir)
}

func TestGatewayBackupPartialPayloadFailureLeavesNoArchiveOrMetadata(t *testing.T) {
	source := staticBackupPayloadSource{payload: &failingBackupPayload{}}
	backupper, state, backupDir, _ := newGatewayBackupFixture(t, source)
	plan, err := backupper.Plan(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backupper.Apply(context.Background(), plan, []byte("passphrase")); err == nil || !strings.Contains(err.Error(), "injected payload failure") {
		t.Fatalf("partial payload error = %v", err)
	}
	if _, err := os.Lstat(plan.OutputPath); !errors.Is(err, os.ErrNotExist) || state.saves != 0 || len(state.state.Backups) != 0 {
		t.Fatalf("partial failure output=%v saves=%d backups=%d", err, state.saves, len(state.state.Backups))
	}
	assertNoBackupTemporaries(t, backupDir)
}

func TestGatewayBackupRemovesPublishedArchiveWhenMetadataCommitFails(t *testing.T) {
	fixture := newUpdaterFixture(t, model.RoleGateway, "old")
	state := &failingBackupState{state: fixture.state.state, saveErr: errors.New("injected state failure")}
	backupDir := filepath.Join(fixture.root, "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	backupper, err := newGatewayBackupper(GatewayBackupRuntime{
		State: state, Payloads: StateBackupPayloadSource{}, BackupsDir: backupDir,
		Now:     func() time.Time { return time.Date(2026, 9, 4, 14, 5, 6, 0, time.UTC) },
		NewUUID: func() (string, error) { return "92000000-0000-4000-8000-000000000001", nil },
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x41}, 64)),
	}, fastBackupArchiveCodec())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := backupper.Plan(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backupper.Apply(context.Background(), plan, []byte("passphrase")); !errors.Is(err, state.saveErr) {
		t.Fatalf("metadata failure = %v", err)
	}
	if _, err := os.Lstat(plan.OutputPath); !errors.Is(err, os.ErrNotExist) || len(state.state.Backups) != 0 {
		t.Fatalf("metadata failure retained output=%v backups=%d", err, len(state.state.Backups))
	}
	assertNoBackupTemporaries(t, backupDir)
}

func TestGatewayBackupRejectsStateChangeAndNonGatewayBeforeWriting(t *testing.T) {
	backupper, state, backupDir, _ := newGatewayBackupFixture(t, StateBackupPayloadSource{})
	plan, err := backupper.Plan(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	state.state.Generation++
	if _, err := backupper.Apply(context.Background(), plan, []byte("passphrase")); !errors.Is(err, ErrBackupConflict) {
		t.Fatalf("changed state error = %v", err)
	}
	if _, err := os.Lstat(plan.OutputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state conflict created output: %v", err)
	}
	assertNoBackupTemporaries(t, backupDir)

	node := newUpdaterFixture(t, model.RoleNode, "old")
	nodeDir := filepath.Join(node.root, "backups")
	if err := os.Mkdir(nodeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	nodeBackupper, err := newGatewayBackupper(GatewayBackupRuntime{
		State: node.state, Payloads: StateBackupPayloadSource{}, BackupsDir: nodeDir,
	}, fastBackupArchiveCodec())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodeBackupper.Plan(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "initialized gateway") {
		t.Fatalf("node backup plan error = %v", err)
	}
}

func newGatewayBackupFixture(t *testing.T, source BackupPayloadSource) (*GatewayBackupper, *memoryUpdateState, string, time.Time) {
	t.Helper()
	fixture := newUpdaterFixture(t, model.RoleGateway, "old")
	backupDir := filepath.Join(fixture.root, "backups")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 4, 14, 5, 6, 789, time.UTC).Truncate(time.Second)
	backupper, err := newGatewayBackupper(GatewayBackupRuntime{
		State: fixture.state, Payloads: source, BackupsDir: backupDir, Now: func() time.Time { return now },
		NewUUID: func() (string, error) { return "92000000-0000-4000-8000-000000000001", nil },
		Random:  bytes.NewReader(bytes.Repeat([]byte{0x41}, 256)),
	}, fastBackupArchiveCodec())
	if err != nil {
		t.Fatal(err)
	}
	return backupper, fixture.state, backupDir, now
}

func decryptGatewayBackupPayload(t *testing.T, encrypted, passphrase []byte) (backupPayloadManifest, []byte) {
	t.Helper()
	var plaintext bytes.Buffer
	if err := fastBackupArchiveCodec().decrypt(bytes.NewReader(encrypted), &plaintext, passphrase); err != nil {
		t.Fatal(err)
	}
	tape := tar.NewReader(&plaintext)
	files := map[string][]byte{}
	for {
		header, err := tape.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(tape)
		if err != nil {
			t.Fatal(err)
		}
		files[header.Name] = content
	}
	var manifest backupPayloadManifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest, files["state/state.json"]
}

func assertNoBackupTemporaries(t *testing.T, directory string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".vpnctl-backup-*.tmp"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("backup temporary files = %v, %v", matches, err)
	}
}

type staticBackupPayloadSource struct{ payload BackupPayload }

func (source staticBackupPayloadSource) Prepare(context.Context, model.State) (BackupPayload, error) {
	return source.payload, nil
}

type failingBackupPayload struct{ closed bool }

func (payload *failingBackupPayload) WriteTo(_ context.Context, writer io.Writer) error {
	_, _ = writer.Write([]byte("partial plaintext"))
	return errors.New("injected payload failure")
}

func (payload *failingBackupPayload) Close() error {
	payload.closed = true
	return nil
}

type failingBackupState struct {
	state   model.State
	saveErr error
}

func (state *failingBackupState) Load() (model.State, error) { return state.state, nil }

func (state *failingBackupState) Save(uint64, model.State) error { return state.saveErr }
