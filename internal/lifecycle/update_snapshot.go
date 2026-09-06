package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	UpdateSnapshotSchemaVersion = 1

	updateSnapshotMetadataFile  = "snapshot.json"
	updateSnapshotStateFile     = "state.json"
	updateSnapshotBundleFile    = "vpnctl.bundle"
	updateSnapshotChecksumsFile = "checksums.txt"
	updateSnapshotPendingFile   = "update.pending.json"
	updateSnapshotPreviousFile  = "update.previous.json"
	maximumUpdateSnapshotMeta   = 16 << 10
)

var (
	ErrUpdateSnapshotNotFound = errors.New("previous update snapshot not found")
	ErrUpdateSnapshotPending  = errors.New("an incomplete update snapshot requires recovery")
	ErrUpdateSnapshotInvalid  = errors.New("update snapshot is invalid")
	updateSnapshotIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type UpdateSnapshotReleaseFiles struct {
	BundlePath    string
	ChecksumsPath string
}

type UpdateSnapshotMetadata struct {
	SchemaVersion       int        `json:"schema_version"`
	SnapshotID          string     `json:"snapshot_id"`
	OperationID         string     `json:"operation_id"`
	Role                model.Role `json:"role"`
	PreviousVersion     string     `json:"previous_version"`
	UpdatedToVersion    string     `json:"updated_to_version"`
	PreviousStateSchema int        `json:"previous_state_schema"`
	UpdatedStateSchema  int        `json:"updated_state_schema"`
	MigrationReversible bool       `json:"migration_reversible"`
	CreatedAt           time.Time  `json:"created_at"`
	PreviousStateSHA256 string     `json:"previous_state_sha256"`
	AppliedStateSHA256  string     `json:"applied_state_sha256,omitempty"`
	BundleSHA256        string     `json:"bundle_sha256"`
	ChecksumsSHA256     string     `json:"checksums_sha256"`
}

type UpdateSnapshotInput struct {
	OperationID         string
	Role                model.Role
	UpdatedToVersion    string
	UpdatedStateSchema  int
	MigrationReversible bool
	CreatedAt           time.Time
	PreviousState       model.State
	Release             UpdateSnapshotReleaseFiles
}

type LoadedUpdateSnapshot struct {
	Metadata UpdateSnapshotMetadata
	State    model.State
	Release  *StagedUpdateRelease
}

func (snapshot *LoadedUpdateSnapshot) Close() error {
	if snapshot == nil || snapshot.Release == nil {
		return nil
	}
	return snapshot.Release.Close()
}

type FilesystemUpdateSnapshotStore struct {
	root      string
	inspector *ReleaseBundleInstaller
}

type PreparedUpdateSnapshot struct {
	mu       sync.Mutex
	store    *FilesystemUpdateSnapshotStore
	metadata UpdateSnapshotMetadata
	root     string
	closed   bool
	final    bool
}

type updateSnapshotPointer struct {
	SchemaVersion int    `json:"schema_version"`
	SnapshotID    string `json:"snapshot_id"`
}

func NewFilesystemUpdateSnapshotStore(root string, inspector *ReleaseBundleInstaller) (*FilesystemUpdateSnapshotStore, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || inspector == nil {
		return nil, fmt.Errorf("update snapshot store dependencies are incomplete")
	}
	if err := validateUpdateSnapshotDirectory(root); err != nil {
		return nil, err
	}
	return &FilesystemUpdateSnapshotStore{root: root, inspector: inspector}, nil
}

func (snapshotStore *FilesystemUpdateSnapshotStore) Prepare(ctx context.Context, input UpdateSnapshotInput) (*PreparedUpdateSnapshot, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if snapshotStore == nil || snapshotStore.inspector == nil {
		return nil, fmt.Errorf("update snapshot store is incomplete")
	}
	if err := validateUpdateSnapshotDirectory(snapshotStore.root); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(snapshotStore.root, updateSnapshotPendingFile)); err == nil {
		return nil, ErrUpdateSnapshotPending
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inspect pending update snapshot: %w", err)
	}
	if err := input.PreviousState.Validate(); err != nil || input.PreviousState.Host.Role != input.Role {
		return nil, fmt.Errorf("%w: previous state and role are invalid", ErrUpdateSnapshotInvalid)
	}
	if !updateSnapshotIDPattern.MatchString(input.OperationID) || input.CreatedAt.IsZero() || !input.CreatedAt.Equal(input.CreatedAt.UTC().Truncate(time.Second)) ||
		input.UpdatedStateSchema < 1 {
		return nil, fmt.Errorf("%w: snapshot identity is invalid", ErrUpdateSnapshotInvalid)
	}
	updatedVersion, err := CanonicalStableReleaseVersion(input.UpdatedToVersion)
	if err != nil || updatedVersion != input.UpdatedToVersion {
		return nil, fmt.Errorf("%w: target version is invalid", ErrUpdateSnapshotInvalid)
	}
	previousVersion, err := CanonicalStableReleaseVersion(input.PreviousState.Components.VPNCTLVersion)
	if err != nil || previousVersion != input.PreviousState.Components.VPNCTLVersion {
		return nil, fmt.Errorf("%w: previous version is invalid", ErrUpdateSnapshotInvalid)
	}
	stateBytes, err := model.EncodeState(input.PreviousState)
	if err != nil {
		return nil, fmt.Errorf("encode previous update state: %w", err)
	}
	metadata := UpdateSnapshotMetadata{
		SchemaVersion: UpdateSnapshotSchemaVersion, SnapshotID: input.OperationID, OperationID: input.OperationID,
		Role: input.Role, PreviousVersion: previousVersion, UpdatedToVersion: updatedVersion,
		PreviousStateSchema: input.PreviousState.SchemaVersion, UpdatedStateSchema: input.UpdatedStateSchema,
		MigrationReversible: input.MigrationReversible, CreatedAt: input.CreatedAt,
		PreviousStateSHA256: updateSnapshotBytesSHA256(stateBytes),
	}

	temporary, err := os.MkdirTemp(snapshotStore.root, ".update-"+input.OperationID+"-")
	if err != nil {
		return nil, fmt.Errorf("create update snapshot stage: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return nil, fmt.Errorf("secure update snapshot stage: %w", err)
	}
	files := []struct {
		source string
		name   string
		hash   *string
	}{
		{input.Release.BundlePath, updateSnapshotBundleFile, &metadata.BundleSHA256},
		{input.Release.ChecksumsPath, updateSnapshotChecksumsFile, &metadata.ChecksumsSHA256},
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		target := filepath.Join(temporary, file.name)
		if err := copyRegularReleaseFile(file.source, target, 0o600); err != nil {
			return nil, fmt.Errorf("copy update snapshot %s: %w", file.name, err)
		}
		value, err := updateSnapshotFileSHA256(target, MaximumReleaseBundleBytes)
		if err != nil {
			return nil, err
		}
		*file.hash = value
	}
	if err := snapshotStore.verifyRelease(ctx, metadata, UpdateSnapshotReleaseFiles{
		BundlePath: filepath.Join(temporary, updateSnapshotBundleFile), ChecksumsPath: filepath.Join(temporary, updateSnapshotChecksumsFile),
	}); err != nil {
		return nil, fmt.Errorf("verify previous snapshot release: %w", err)
	}
	if err := writeUpdateSnapshotNew(filepath.Join(temporary, updateSnapshotStateFile), stateBytes, 0o600); err != nil {
		return nil, err
	}
	if err := metadata.validate(false); err != nil {
		return nil, err
	}
	metadataBytes, err := encodeUpdateSnapshotJSON(metadata)
	if err != nil {
		return nil, err
	}
	if err := writeUpdateSnapshotNew(filepath.Join(temporary, updateSnapshotMetadataFile), metadataBytes, 0o600); err != nil {
		return nil, err
	}
	if err := syncReleaseDirectory(temporary); err != nil {
		return nil, fmt.Errorf("sync update snapshot stage: %w", err)
	}
	finalRoot := filepath.Join(snapshotStore.root, "update-"+input.OperationID)
	if _, err := os.Lstat(finalRoot); err == nil {
		return nil, fmt.Errorf("%w: snapshot ID already exists", ErrUpdateSnapshotInvalid)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := os.Rename(temporary, finalRoot); err != nil {
		return nil, fmt.Errorf("publish update snapshot directory: %w", err)
	}
	keep = true
	if err := syncReleaseDirectory(snapshotStore.root); err != nil {
		_ = removeOwnedUpdateSnapshot(snapshotStore.root, input.OperationID)
		return nil, err
	}
	pointerBytes, _ := encodeUpdateSnapshotJSON(updateSnapshotPointer{SchemaVersion: UpdateSnapshotSchemaVersion, SnapshotID: input.OperationID})
	if err := replaceUpdateSnapshotFile(filepath.Join(snapshotStore.root, updateSnapshotPendingFile), pointerBytes, false); err != nil {
		_ = removeOwnedUpdateSnapshot(snapshotStore.root, input.OperationID)
		return nil, fmt.Errorf("publish pending update snapshot: %w", err)
	}
	return &PreparedUpdateSnapshot{store: snapshotStore, metadata: metadata, root: finalRoot}, nil
}

func (prepared *PreparedUpdateSnapshot) Finalize(applied model.State) error {
	if prepared == nil {
		return fmt.Errorf("prepared update snapshot is required")
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.closed || prepared.final || prepared.store == nil {
		return fmt.Errorf("prepared update snapshot cannot be finalized")
	}
	if err := applied.Validate(); err != nil || applied.Host.Role != prepared.metadata.Role ||
		applied.Components.VPNCTLVersion != prepared.metadata.UpdatedToVersion || applied.SchemaVersion != prepared.metadata.UpdatedStateSchema {
		return fmt.Errorf("%w: applied state does not match snapshot target", ErrUpdateSnapshotInvalid)
	}
	encoded, err := model.EncodeState(applied)
	if err != nil {
		return err
	}
	prepared.metadata.AppliedStateSHA256 = updateSnapshotBytesSHA256(encoded)
	if err := prepared.metadata.validate(true); err != nil {
		return err
	}
	metadataBytes, err := encodeUpdateSnapshotJSON(prepared.metadata)
	if err != nil {
		return err
	}
	if err := replaceUpdateSnapshotFile(filepath.Join(prepared.root, updateSnapshotMetadataFile), metadataBytes, true); err != nil {
		return fmt.Errorf("finalize update snapshot metadata: %w", err)
	}
	prepared.final = true
	return nil
}

func (prepared *PreparedUpdateSnapshot) Promote() error {
	if prepared == nil {
		return fmt.Errorf("prepared update snapshot is required")
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.closed || !prepared.final || prepared.store == nil {
		return fmt.Errorf("prepared update snapshot cannot be promoted")
	}
	pendingPath := filepath.Join(prepared.store.root, updateSnapshotPendingFile)
	pointer, err := loadUpdateSnapshotPointer(pendingPath)
	if err != nil || pointer.SnapshotID != prepared.metadata.SnapshotID {
		return fmt.Errorf("%w: pending snapshot pointer changed", ErrUpdateSnapshotInvalid)
	}
	previousPath := filepath.Join(prepared.store.root, updateSnapshotPreviousFile)
	oldSnapshotID := ""
	if info, err := os.Lstat(previousPath); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600) {
		return fmt.Errorf("%w: previous snapshot pointer is not an owned file", ErrUpdateSnapshotInvalid)
	} else if err == nil {
		old, loadErr := loadUpdateSnapshotPointer(previousPath)
		if loadErr != nil {
			return loadErr
		}
		oldSnapshotID = old.SnapshotID
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(pendingPath, previousPath); err != nil {
		return fmt.Errorf("promote update snapshot pointer: %w", err)
	}
	if err := syncReleaseDirectory(prepared.store.root); err != nil {
		return fmt.Errorf("sync promoted update snapshot: %w", err)
	}
	prepared.closed = true
	if oldSnapshotID != "" && oldSnapshotID != prepared.metadata.SnapshotID {
		_ = removeOwnedUpdateSnapshot(prepared.store.root, oldSnapshotID)
		_ = syncReleaseDirectory(prepared.store.root)
	}
	return nil
}

func (prepared *PreparedUpdateSnapshot) Abort() error {
	if prepared == nil {
		return nil
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.closed {
		return nil
	}
	prepared.closed = true
	var result []error
	pendingPath := filepath.Join(prepared.store.root, updateSnapshotPendingFile)
	if pointer, err := loadUpdateSnapshotPointer(pendingPath); err == nil {
		if pointer.SnapshotID != prepared.metadata.SnapshotID {
			return fmt.Errorf("%w: pending snapshot pointer belongs to another operation", ErrUpdateSnapshotInvalid)
		}
		result = append(result, os.Remove(pendingPath))
	} else if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, ErrUpdateSnapshotNotFound) {
		result = append(result, err)
	}
	result = append(result, removeOwnedUpdateSnapshot(prepared.store.root, prepared.metadata.SnapshotID))
	result = append(result, syncReleaseDirectory(prepared.store.root))
	return errors.Join(result...)
}

func (snapshotStore *FilesystemUpdateSnapshotStore) LoadPrevious(ctx context.Context) (*LoadedUpdateSnapshot, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if snapshotStore == nil || snapshotStore.inspector == nil {
		return nil, fmt.Errorf("update snapshot store is incomplete")
	}
	if err := validateUpdateSnapshotDirectory(snapshotStore.root); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(snapshotStore.root, updateSnapshotPendingFile)); err == nil {
		return nil, ErrUpdateSnapshotPending
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("inspect pending update snapshot: %w", err)
	}
	pointer, err := loadUpdateSnapshotPointer(filepath.Join(snapshotStore.root, updateSnapshotPreviousFile))
	if err != nil {
		return nil, err
	}
	root := filepath.Join(snapshotStore.root, "update-"+pointer.SnapshotID)
	if err := validateUpdateSnapshotDirectory(root); err != nil {
		return nil, fmt.Errorf("%w: snapshot directory is invalid", ErrUpdateSnapshotInvalid)
	}
	metadataBytes, err := readUpdateSnapshotFile(filepath.Join(root, updateSnapshotMetadataFile), maximumUpdateSnapshotMeta)
	if err != nil {
		return nil, err
	}
	var metadata UpdateSnapshotMetadata
	if err := decodeStrictReleaseJSON(metadataBytes, &metadata); err != nil {
		return nil, fmt.Errorf("%w: decode metadata: %v", ErrUpdateSnapshotInvalid, err)
	}
	if err := metadata.validate(true); err != nil || metadata.SnapshotID != pointer.SnapshotID {
		return nil, fmt.Errorf("%w: metadata does not match pointer", ErrUpdateSnapshotInvalid)
	}
	statePath := filepath.Join(root, updateSnapshotStateFile)
	stateBytes, err := readUpdateSnapshotFile(statePath, store.MaxStateBytes)
	if err != nil || updateSnapshotBytesSHA256(stateBytes) != metadata.PreviousStateSHA256 {
		return nil, fmt.Errorf("%w: previous state checksum differs", ErrUpdateSnapshotInvalid)
	}
	previousState, err := model.DecodeState(stateBytes)
	if err != nil || previousState.Host.Role != metadata.Role || previousState.SchemaVersion != metadata.PreviousStateSchema ||
		previousState.Components.VPNCTLVersion != metadata.PreviousVersion {
		return nil, fmt.Errorf("%w: previous state does not match metadata", ErrUpdateSnapshotInvalid)
	}
	paths := UpdateSnapshotReleaseFiles{
		BundlePath: filepath.Join(root, updateSnapshotBundleFile), ChecksumsPath: filepath.Join(root, updateSnapshotChecksumsFile),
	}
	if err := snapshotStore.verifyRelease(ctx, metadata, paths); err != nil {
		return nil, err
	}
	stageRoot, err := os.MkdirTemp("", "vpnctl-update-rollback-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		_ = os.RemoveAll(stageRoot)
		return nil, err
	}
	stage := &StagedUpdateRelease{
		Version: metadata.PreviousVersion, BundlePath: filepath.Join(stageRoot, ReleaseBundleAsset),
		ChecksumsPath: filepath.Join(stageRoot, ReleaseChecksumsAsset), root: stageRoot,
	}
	for source, target := range map[string]string{paths.BundlePath: stage.BundlePath, paths.ChecksumsPath: stage.ChecksumsPath} {
		if err := copyRegularReleaseFile(source, target, 0o600); err != nil {
			_ = stage.Close()
			return nil, err
		}
	}
	if err := snapshotStore.verifyRelease(ctx, metadata, UpdateSnapshotReleaseFiles{
		BundlePath: stage.BundlePath, ChecksumsPath: stage.ChecksumsPath,
	}); err != nil {
		_ = stage.Close()
		return nil, err
	}
	checksumsBytes, err := readUpdateSnapshotFile(stage.ChecksumsPath, 4096)
	if err != nil {
		_ = stage.Close()
		return nil, err
	}
	checksums, err := DecodeReleaseChecksums(checksumsBytes)
	if err != nil {
		_ = stage.Close()
		return nil, err
	}
	manifest, err := snapshotStore.inspector.Inspect(ctx, stage.BundlePath)
	if err != nil {
		_ = stage.Close()
		return nil, err
	}
	stage.Checksums, stage.Manifest = checksums, manifest
	return &LoadedUpdateSnapshot{Metadata: metadata, State: previousState, Release: stage}, nil
}

func (snapshotStore *FilesystemUpdateSnapshotStore) ConsumePrevious(snapshotID string) error {
	if snapshotStore == nil || !updateSnapshotIDPattern.MatchString(snapshotID) {
		return fmt.Errorf("%w: snapshot consumption identity is invalid", ErrUpdateSnapshotInvalid)
	}
	previousPath := filepath.Join(snapshotStore.root, updateSnapshotPreviousFile)
	pointer, err := loadUpdateSnapshotPointer(previousPath)
	if err != nil || pointer.SnapshotID != snapshotID {
		return fmt.Errorf("%w: previous snapshot pointer changed", ErrUpdateSnapshotInvalid)
	}
	if err := os.Remove(previousPath); err != nil {
		return fmt.Errorf("consume previous update snapshot: %w", err)
	}
	if err := syncReleaseDirectory(snapshotStore.root); err != nil {
		return fmt.Errorf("sync consumed update snapshot: %w", err)
	}
	_ = removeOwnedUpdateSnapshot(snapshotStore.root, snapshotID)
	_ = syncReleaseDirectory(snapshotStore.root)
	return nil
}

func (snapshotStore *FilesystemUpdateSnapshotStore) verifyRelease(ctx context.Context, metadata UpdateSnapshotMetadata, paths UpdateSnapshotReleaseFiles) error {
	for path, expected := range map[string]string{
		paths.BundlePath: metadata.BundleSHA256, paths.ChecksumsPath: metadata.ChecksumsSHA256,
	} {
		actual, err := updateSnapshotFileSHA256(path, MaximumReleaseBundleBytes)
		if err != nil || actual != expected {
			return fmt.Errorf("%w: release snapshot checksum differs", ErrUpdateSnapshotInvalid)
		}
	}
	checksumsBytes, err := readUpdateSnapshotFile(paths.ChecksumsPath, 4096)
	if err != nil {
		return err
	}
	checksums, err := DecodeReleaseChecksums(checksumsBytes)
	if err != nil || checksums.Version != metadata.PreviousVersion {
		return fmt.Errorf("%w: release checksum metadata is invalid", ErrUpdateSnapshotInvalid)
	}
	if err := verifyStagedReleaseFile(paths.BundlePath, checksums.Bundle); err != nil {
		return fmt.Errorf("%w: %v", ErrUpdateSnapshotInvalid, err)
	}
	manifest, err := snapshotStore.inspector.Inspect(ctx, paths.BundlePath)
	if err != nil || manifest.ComponentManifest.VPNCTLVersion != metadata.PreviousVersion {
		return fmt.Errorf("%w: release bundle is invalid", ErrUpdateSnapshotInvalid)
	}
	vpnctl, found := releaseArtifactForComponent(manifest, "vpnctl")
	if !found || vpnctl.SHA256 != checksums.Binary.SHA256 || vpnctl.SizeBytes != checksums.Binary.SizeBytes {
		return fmt.Errorf("%w: bundled vpnctl differs from checksum metadata", ErrUpdateSnapshotInvalid)
	}
	return nil
}

func (metadata UpdateSnapshotMetadata) validate(final bool) error {
	previous, previousErr := CanonicalStableReleaseVersion(metadata.PreviousVersion)
	updated, updatedErr := CanonicalStableReleaseVersion(metadata.UpdatedToVersion)
	if metadata.SchemaVersion != UpdateSnapshotSchemaVersion || !updateSnapshotIDPattern.MatchString(metadata.SnapshotID) ||
		metadata.OperationID != metadata.SnapshotID || metadata.Role != model.RoleGateway && metadata.Role != model.RoleNode ||
		previousErr != nil || previous != metadata.PreviousVersion || updatedErr != nil || updated != metadata.UpdatedToVersion ||
		metadata.PreviousStateSchema < 1 || metadata.UpdatedStateSchema < 1 || metadata.CreatedAt.IsZero() ||
		!metadata.CreatedAt.Equal(metadata.CreatedAt.UTC().Truncate(time.Second)) || !validReleaseSHA256(metadata.PreviousStateSHA256) ||
		!validReleaseSHA256(metadata.BundleSHA256) || !validReleaseSHA256(metadata.ChecksumsSHA256) {
		return fmt.Errorf("%w: metadata fields are invalid", ErrUpdateSnapshotInvalid)
	}
	if final && !validReleaseSHA256(metadata.AppliedStateSHA256) || !final && metadata.AppliedStateSHA256 != "" {
		return fmt.Errorf("%w: applied-state checksum finalization is inconsistent", ErrUpdateSnapshotInvalid)
	}
	return nil
}

func loadUpdateSnapshotPointer(path string) (updateSnapshotPointer, error) {
	encoded, err := readUpdateSnapshotFile(path, maximumUpdateSnapshotMeta)
	if errors.Is(err, fs.ErrNotExist) {
		return updateSnapshotPointer{}, ErrUpdateSnapshotNotFound
	}
	if err != nil {
		return updateSnapshotPointer{}, err
	}
	var pointer updateSnapshotPointer
	if err := decodeStrictReleaseJSON(encoded, &pointer); err != nil || pointer.SchemaVersion != UpdateSnapshotSchemaVersion || !updateSnapshotIDPattern.MatchString(pointer.SnapshotID) {
		return updateSnapshotPointer{}, fmt.Errorf("%w: snapshot pointer is invalid", ErrUpdateSnapshotInvalid)
	}
	return pointer, nil
}

func validateUpdateSnapshotDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("update snapshot root must be a mode-0700 real directory")
	}
	return nil
}

func readUpdateSnapshotFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("%w: %s is not a bounded mode-0600 regular file", ErrUpdateSnapshotInvalid, filepath.Base(path))
	}
	return os.ReadFile(path)
}

func updateSnapshotFileSHA256(path string, maximum int64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maximum {
		return "", fmt.Errorf("%w: %s cannot be hashed", ErrUpdateSnapshotInvalid, filepath.Base(path))
	}
	input, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer input.Close()
	digest := sha256.New()
	read, err := io.Copy(digest, io.LimitReader(input, maximum+1))
	if err != nil || read != info.Size() {
		return "", fmt.Errorf("%w: read %s", ErrUpdateSnapshotInvalid, filepath.Base(path))
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func updateSnapshotBytesSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func encodeUpdateSnapshotJSON(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func writeUpdateSnapshotNew(path string, content []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, writeErr := file.Write(content); writeErr != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return writeErr
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func replaceUpdateSnapshotFile(path string, content []byte, replace bool) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !replace || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return fmt.Errorf("%w: snapshot target conflicts", ErrUpdateSnapshotInvalid)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncReleaseDirectory(directory)
}

func removeOwnedUpdateSnapshot(root, id string) error {
	if !updateSnapshotIDPattern.MatchString(id) {
		return fmt.Errorf("%w: invalid snapshot removal ID", ErrUpdateSnapshotInvalid)
	}
	path := filepath.Join(root, "update-"+id)
	if filepath.Dir(path) != root || filepath.Base(path) != "update-"+id {
		return fmt.Errorf("%w: invalid snapshot removal path", ErrUpdateSnapshotInvalid)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: snapshot removal target is not owned", ErrUpdateSnapshotInvalid)
	}
	return os.RemoveAll(path)
}
