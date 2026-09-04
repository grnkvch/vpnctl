package lifecycle

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	MaximumGatewayRestoreArchiveBytes   = int64(512 << 20)
	maximumGatewayRestorePlaintextBytes = int64(384 << 20)
	maximumGatewayRestoreManifestBytes  = int64(8 << 20)
	maximumGatewayRestoreEntries        = 32768
)

var ErrGatewayRestoreArchiveInvalid = errors.New("invalid gateway restore archive")

type GatewayRestoreFile struct {
	Path      string
	SizeBytes int64
	SHA256    string
}

// GatewayRestorePayload is a fully authenticated, structurally validated
// private staging tree. Callers may inspect only the declared entries; the
// temporary root remains opaque and is recursively removed by Close.
type GatewayRestorePayload struct {
	root     string
	manifest backupPayloadManifest
	state    model.State
	files    []GatewayRestoreFile
	closed   bool
}

func (payload *GatewayRestorePayload) State() model.State {
	if payload == nil || payload.closed {
		return model.State{}
	}
	return payload.state
}

func (payload *GatewayRestorePayload) Files() []GatewayRestoreFile {
	if payload == nil || payload.closed {
		return nil
	}
	return append([]GatewayRestoreFile(nil), payload.files...)
}

func (payload *GatewayRestorePayload) Open(archivePath string) (*os.File, error) {
	if payload == nil || payload.closed {
		return nil, fmt.Errorf("gateway restore payload is unavailable")
	}
	if err := validateBackupPayloadPath(archivePath); err != nil {
		return nil, err
	}
	index := sort.Search(len(payload.files), func(index int) bool { return payload.files[index].Path >= archivePath })
	if index == len(payload.files) || payload.files[index].Path != archivePath {
		return nil, fs.ErrNotExist
	}
	target := filepath.Join(payload.root, filepath.FromSlash(archivePath))
	file, err := openBackupPathNoFollow(target, false)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != payload.files[index].SizeBytes {
		_ = file.Close()
		return nil, fmt.Errorf("staged gateway restore entry changed: %s", archivePath)
	}
	return file, nil
}

func (payload *GatewayRestorePayload) Close() error {
	if payload == nil || payload.closed {
		return nil
	}
	payload.closed = true
	payload.files = nil
	payload.state = model.State{}
	payload.manifest = backupPayloadManifest{}
	root := payload.root
	payload.root = ""
	if root == "" {
		return nil
	}
	return os.RemoveAll(root)
}

// rewriteEndpoint changes only the authenticated payload's private staging
// tree. The live host remains untouched until the already-preflighted restore
// transaction activates the complete candidate.
func (payload *GatewayRestorePayload) rewriteEndpoint(
	candidate model.State,
	currentCertificate model.Certificate,
	renewedCertificate model.Certificate,
	certificatePEM, privateKeyPEM []byte,
) error {
	if payload == nil || payload.closed || payload.root == "" || len(certificatePEM) == 0 || len(privateKeyPEM) == 0 {
		return fmt.Errorf("gateway restore endpoint rewrite is incomplete")
	}
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("validate gateway restore endpoint payload: %w", err)
	}
	if currentCertificate.Kind != model.CertificatePublicIngress || renewedCertificate.Kind != model.CertificatePublicIngress ||
		currentCertificate.ID != renewedCertificate.ID || currentCertificate.OwnerID != renewedCertificate.OwnerID ||
		currentCertificate.CertificateRef == renewedCertificate.CertificateRef || currentCertificate.PrivateKeyRef == renewedCertificate.PrivateKeyRef {
		return fmt.Errorf("gateway restore endpoint certificate transition is invalid")
	}
	oldCertificatePath, err := gatewayRestoreSecretPath(model.SecretRef(currentCertificate.CertificateRef))
	if err != nil {
		return err
	}
	oldPrivateKeyPath, err := gatewayRestoreSecretPath(currentCertificate.PrivateKeyRef)
	if err != nil {
		return err
	}
	newCertificatePath, err := gatewayRestoreSecretPath(model.SecretRef(renewedCertificate.CertificateRef))
	if err != nil {
		return err
	}
	newPrivateKeyPath, err := gatewayRestoreSecretPath(renewedCertificate.PrivateKeyRef)
	if err != nil {
		return err
	}
	declared := make(map[string]GatewayRestoreFile, len(payload.files))
	for _, file := range payload.files {
		declared[file.Path] = file
	}
	for _, required := range []string{oldCertificatePath, oldPrivateKeyPath, "state/state.json"} {
		if _, ok := declared[required]; !ok {
			return restoreArchiveInvalid("endpoint rewrite is missing %s", required)
		}
	}
	for _, absent := range []string{newCertificatePath, newPrivateKeyPath} {
		if _, ok := declared[absent]; ok {
			return restoreArchiveInvalid("endpoint rewrite target is already declared: %s", absent)
		}
	}
	stateBytes, err := model.EncodeState(candidate)
	if err != nil {
		return err
	}
	updates := map[string][]byte{
		"state/state.json": stateBytes,
		newCertificatePath: append([]byte(nil), certificatePEM...),
		newPrivateKeyPath:  append([]byte(nil), privateKeyPEM...),
		path.Join("exports", ingress.PublicCertificateExportName): append([]byte(nil), certificatePEM...),
	}
	defer wipeBackupBytes(updates[newPrivateKeyPath])
	for _, archivePath := range []string{"state/state.json", newCertificatePath, newPrivateKeyPath, path.Join("exports", ingress.PublicCertificateExportName)} {
		_, replace := declared[archivePath]
		if err := writeGatewayRestorePayloadEntry(payload.root, archivePath, updates[archivePath], replace); err != nil {
			return err
		}
	}
	removed := map[string]struct{}{oldCertificatePath: {}, oldPrivateKeyPath: {}}
	for archivePath := range declared {
		if strings.HasPrefix(archivePath, "exports/clients/.metadata/") {
			removed[archivePath] = struct{}{}
		}
	}
	for archivePath := range removed {
		if err := removeGatewayRestorePayloadEntry(payload.root, archivePath); err != nil {
			return err
		}
	}
	for archivePath, content := range updates {
		digest := sha256.Sum256(content)
		declared[archivePath] = GatewayRestoreFile{
			Path: archivePath, SizeBytes: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
		}
	}
	for archivePath := range removed {
		delete(declared, archivePath)
	}
	paths := make([]string, 0, len(declared))
	for archivePath := range declared {
		paths = append(paths, archivePath)
	}
	sort.Strings(paths)
	files := make([]GatewayRestoreFile, 0, len(paths))
	entries := make([]backupPayloadManifestEntry, 0, len(paths))
	for _, archivePath := range paths {
		file := declared[archivePath]
		files = append(files, file)
		entries = append(entries, backupPayloadManifestEntry{Path: file.Path, SizeBytes: file.SizeBytes, SHA256: file.SHA256})
	}
	if err := validateGatewayRestoreAllowlist(candidate, entries); err != nil {
		return err
	}
	payload.state = candidate
	payload.files = files
	payload.manifest.StateGeneration = candidate.Generation
	payload.manifest.PublicIPv4 = candidate.Host.PublicIPv4
	payload.manifest.Entries = entries
	return nil
}

func gatewayRestoreSecretPath(reference model.SecretRef) (string, error) {
	kind, id, err := reference.Parts()
	if err != nil {
		return "", err
	}
	return path.Join("secrets", kind, id), nil
}

func writeGatewayRestorePayloadEntry(root, archivePath string, content []byte, replace bool) (returnErr error) {
	maximum, err := gatewayRestoreEntryMaximum(archivePath)
	if err != nil {
		return err
	}
	if len(content) == 0 || int64(len(content)) > maximum {
		return restoreArchiveInvalid("rewritten entry %s has invalid size", archivePath)
	}
	target := filepath.Join(root, filepath.FromSlash(archivePath))
	info, statErr := os.Lstat(target)
	if replace {
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return restoreArchiveInvalid("rewritten entry %s is unsafe", archivePath)
		}
	} else if statErr == nil {
		return restoreArchiveInvalid("rewritten entry %s already exists", archivePath)
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return statErr
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".vpnctl-restore-rewrite-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, temporary.Close())
		}
		if removeErr := os.Remove(temporaryPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			returnErr = errors.Join(returnErr, removeErr)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(temporaryPath, target); err != nil {
		return err
	}
	return syncGatewayRestorePayloadDirectory(parent)
}

func removeGatewayRestorePayloadEntry(root, archivePath string) error {
	target := filepath.Join(root, filepath.FromSlash(archivePath))
	info, err := os.Lstat(target)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return restoreArchiveInvalid("removed endpoint entry %s is unsafe or absent", archivePath)
	}
	if err := os.Remove(target); err != nil {
		return err
	}
	return syncGatewayRestorePayloadDirectory(filepath.Dir(target))
}

func syncGatewayRestorePayloadDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

type GatewayRestoreArchiveLoader struct {
	scratch string
	codec   backupArchiveCodec
}

func NewGatewayRestoreArchiveLoader(scratch string) (*GatewayRestoreArchiveLoader, error) {
	return newGatewayRestoreArchiveLoader(scratch, productionBackupArchiveCodec())
}

func newGatewayRestoreArchiveLoader(scratch string, codec backupArchiveCodec) (*GatewayRestoreArchiveLoader, error) {
	if !filepath.IsAbs(scratch) || filepath.Clean(scratch) != scratch || codec.deriveKey == nil {
		return nil, fmt.Errorf("gateway restore archive loader dependencies are incomplete")
	}
	info, err := os.Lstat(scratch)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("gateway restore scratch path must be a real directory")
	}
	return &GatewayRestoreArchiveLoader{scratch: scratch, codec: codec}, nil
}

func (loader *GatewayRestoreArchiveLoader) Load(ctx context.Context, archivePath string, passphrase []byte) (_ *GatewayRestorePayload, returnErr error) {
	if ctx == nil || loader == nil || loader.codec.deriveKey == nil {
		wipeBackupBytes(passphrase)
		return nil, fmt.Errorf("gateway restore archive loader is incomplete")
	}
	defer wipeBackupBytes(passphrase)
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("gateway restore passphrase is required")
	}
	if !filepath.IsAbs(archivePath) || filepath.Clean(archivePath) != archivePath || strings.ContainsAny(archivePath, "\x00\r\n") {
		return nil, restoreArchiveInvalid("archive path must be clean, absolute, and single-line")
	}
	before, err := os.Lstat(archivePath)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < int64(backupFixedHeaderBytes+backupRecordHeaderBytes) || before.Size() > MaximumGatewayRestoreArchiveBytes {
		return nil, restoreArchiveInvalid("archive must be a bounded regular file")
	}
	archive, err := openBackupPathNoFollow(archivePath, false)
	if err != nil {
		return nil, restoreArchiveInvalid("open archive: %v", err)
	}
	defer archive.Close()
	opened, err := archive.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() != before.Size() {
		return nil, restoreArchiveInvalid("archive changed while opening")
	}

	plaintext, err := os.CreateTemp(loader.scratch, ".vpnctl-restore-plaintext-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create gateway restore plaintext staging file: %w", err)
	}
	plaintextPath := plaintext.Name()
	plaintextClosed := false
	defer func() {
		if !plaintextClosed {
			returnErr = errors.Join(returnErr, plaintext.Close())
		}
		if removeErr := os.Remove(plaintextPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			returnErr = errors.Join(returnErr, removeErr)
		}
	}()
	if err := plaintext.Chmod(0o600); err != nil {
		return nil, fmt.Errorf("secure gateway restore plaintext staging file: %w", err)
	}
	bounded := &gatewayRestoreBoundedWriter{destination: plaintext, maximum: maximumGatewayRestorePlaintextBytes}
	if err := loader.codec.decrypt(archive, bounded, passphrase); err != nil {
		return nil, err
	}
	if err := plaintext.Sync(); err != nil {
		return nil, fmt.Errorf("sync authenticated gateway restore payload: %w", err)
	}
	if _, err := plaintext.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind authenticated gateway restore payload: %w", err)
	}
	payload, err := loader.extract(ctx, plaintext, bounded.written)
	if err != nil {
		return nil, err
	}
	if err := plaintext.Close(); err != nil {
		_ = payload.Close()
		return nil, fmt.Errorf("close authenticated gateway restore payload: %w", err)
	}
	plaintextClosed = true
	return payload, nil
}

func (loader *GatewayRestoreArchiveLoader) extract(ctx context.Context, plaintext *os.File, plaintextBytes int64) (_ *GatewayRestorePayload, returnErr error) {
	stage, err := os.MkdirTemp(loader.scratch, "vpnctl-restore-payload-")
	if err != nil {
		return nil, fmt.Errorf("create gateway restore payload stage: %w", err)
	}
	if err := os.Chmod(stage, 0o700); err != nil {
		_ = os.RemoveAll(stage)
		return nil, fmt.Errorf("secure gateway restore payload stage: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			returnErr = errors.Join(returnErr, os.RemoveAll(stage))
		}
	}()

	tape := tar.NewReader(plaintext)
	header, err := tape.Next()
	if err != nil {
		return nil, restoreArchiveInvalid("read manifest entry: %v", err)
	}
	if err := validateRestoreTarHeader(header, "manifest.json", maximumGatewayRestoreManifestBytes); err != nil {
		return nil, err
	}
	manifestBytes, err := io.ReadAll(io.LimitReader(tape, maximumGatewayRestoreManifestBytes+1))
	if err != nil || int64(len(manifestBytes)) != header.Size {
		return nil, restoreArchiveInvalid("manifest entry is truncated")
	}
	manifest, err := decodeGatewayRestoreManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	files := make([]GatewayRestoreFile, 0, len(manifest.Entries))
	for index, entry := range manifest.Entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := tape.Next()
		if err != nil {
			return nil, restoreArchiveInvalid("read entry %d: %v", index, err)
		}
		maximum, err := gatewayRestoreEntryMaximum(entry.Path)
		if err != nil {
			return nil, err
		}
		if entry.SizeBytes > maximum {
			return nil, restoreArchiveInvalid("entry %s exceeds its structural size limit", entry.Path)
		}
		if err := validateRestoreTarHeader(header, entry.Path, maximum); err != nil {
			return nil, err
		}
		if header.Size != entry.SizeBytes {
			return nil, restoreArchiveInvalid("entry %s size differs from manifest", entry.Path)
		}
		if err := stageGatewayRestoreEntry(stage, tape, entry); err != nil {
			return nil, err
		}
		files = append(files, GatewayRestoreFile{Path: entry.Path, SizeBytes: entry.SizeBytes, SHA256: entry.SHA256})
	}
	if _, err := tape.Next(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, restoreArchiveInvalid("archive contains an entry absent from the manifest")
		}
		return nil, restoreArchiveInvalid("read archive terminator: %v", err)
	}
	if err := validateGatewayRestoreTarTail(plaintext, plaintextBytes); err != nil {
		return nil, err
	}
	stateBytes, err := os.ReadFile(filepath.Join(stage, "state", "state.json"))
	if err != nil {
		return nil, restoreArchiveInvalid("read authoritative state: %v", err)
	}
	state, err := model.DecodeState(stateBytes)
	if err != nil || state.Host.Role != model.RoleGateway {
		return nil, restoreArchiveInvalid("authoritative state is not a valid gateway state")
	}
	if manifest.StateGeneration != state.Generation || manifest.PublicIPv4 != state.Host.PublicIPv4 {
		return nil, restoreArchiveInvalid("manifest identity differs from authoritative state")
	}
	if err := validateGatewayRestoreAllowlist(state, manifest.Entries); err != nil {
		return nil, err
	}
	payload := &GatewayRestorePayload{root: stage, manifest: manifest, state: state, files: files}
	keep = true
	return payload, nil
}

type gatewayRestoreBoundedWriter struct {
	destination io.Writer
	maximum     int64
	written     int64
}

func (writer *gatewayRestoreBoundedWriter) Write(value []byte) (int, error) {
	if writer == nil || writer.destination == nil || writer.maximum < 1 {
		return 0, fmt.Errorf("gateway restore plaintext writer is incomplete")
	}
	remaining := writer.maximum - writer.written
	if remaining <= 0 || int64(len(value)) > remaining {
		return 0, restoreArchiveInvalid("decrypted payload exceeds %d bytes", writer.maximum)
	}
	written, err := writer.destination.Write(value)
	writer.written += int64(written)
	return written, err
}

func decodeGatewayRestoreManifest(data []byte) (backupPayloadManifest, error) {
	if len(data) == 0 || int64(len(data)) > maximumGatewayRestoreManifestBytes {
		return backupPayloadManifest{}, restoreArchiveInvalid("manifest size is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var manifest backupPayloadManifest
	if err := decoder.Decode(&manifest); err != nil {
		return backupPayloadManifest{}, restoreArchiveInvalid("decode manifest: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return backupPayloadManifest{}, restoreArchiveInvalid("manifest must contain exactly one JSON value")
	}
	if manifest.SchemaVersion != 1 || manifest.Format != backupPayloadFormat || manifest.StateGeneration == 0 || manifest.PublicIPv4 == "" ||
		len(manifest.Entries) == 0 || len(manifest.Entries) > maximumGatewayRestoreEntries {
		return backupPayloadManifest{}, restoreArchiveInvalid("manifest contract is invalid")
	}
	previous := ""
	var total int64
	for index, entry := range manifest.Entries {
		if err := validateBackupPayloadPath(entry.Path); err != nil || entry.Path == "manifest.json" || entry.SizeBytes <= 0 || !validReleaseSHA256(entry.SHA256) {
			return backupPayloadManifest{}, restoreArchiveInvalid("manifest entry %d is invalid", index)
		}
		if index > 0 && entry.Path <= previous {
			return backupPayloadManifest{}, restoreArchiveInvalid("manifest entries must be sorted by unique path")
		}
		if total > maximumGatewayRestorePlaintextBytes-entry.SizeBytes {
			return backupPayloadManifest{}, restoreArchiveInvalid("manifest payload exceeds restore bounds")
		}
		total += entry.SizeBytes
		previous = entry.Path
	}
	return manifest, nil
}

func validateRestoreTarHeader(header *tar.Header, expectedPath string, maximum int64) error {
	if header == nil || header.Name != expectedPath || header.Typeflag != tar.TypeReg || header.Mode != 0o600 || header.Size <= 0 || header.Size > maximum ||
		header.Linkname != "" || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" ||
		!header.ModTime.Equal(time.Unix(0, 0).UTC()) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() || header.Devmajor != 0 || header.Devminor != 0 {
		return restoreArchiveInvalid("entry %s has non-canonical tar metadata (name=%q type=%d mode=%04o size=%d uid=%d gid=%d uname=%q gname=%q mtime=%s atime=%s ctime=%s)",
			expectedPath, header.Name, header.Typeflag, header.Mode, header.Size, header.Uid, header.Gid, header.Uname, header.Gname,
			header.ModTime.UTC().Format(time.RFC3339Nano), header.AccessTime.UTC().Format(time.RFC3339Nano), header.ChangeTime.UTC().Format(time.RFC3339Nano))
	}
	return nil
}

func stageGatewayRestoreEntry(stage string, source io.Reader, entry backupPayloadManifestEntry) (returnErr error) {
	target := filepath.Join(stage, filepath.FromSlash(entry.Path))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("create gateway restore entry parent: %w", err)
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return restoreArchiveInvalid("create staged entry %s: %v", entry.Path, err)
	}
	closed := false
	keep := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, file.Close())
		}
		if !keep {
			returnErr = errors.Join(returnErr, os.Remove(target))
		}
	}()
	hash := sha256.New()
	written, err := io.CopyN(io.MultiWriter(file, hash), source, entry.SizeBytes)
	if err != nil || written != entry.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
		return restoreArchiveInvalid("entry %s content differs from manifest", entry.Path)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync staged gateway restore entry %s: %w", entry.Path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close staged gateway restore entry %s: %w", entry.Path, err)
	}
	closed = true
	keep = true
	return nil
}

func validateGatewayRestoreTarTail(plaintext *os.File, plaintextBytes int64) error {
	position, err := plaintext.Seek(0, io.SeekCurrent)
	if err != nil || position > plaintextBytes || plaintextBytes-position > 1024 {
		return restoreArchiveInvalid("archive has a non-canonical tar terminator")
	}
	remaining := make([]byte, plaintextBytes-position)
	if _, err := io.ReadFull(plaintext, remaining); err != nil {
		return restoreArchiveInvalid("read archive terminator")
	}
	for _, value := range remaining {
		if value != 0 {
			return restoreArchiveInvalid("archive has data after its tar terminator")
		}
	}
	return nil
}

func gatewayRestoreEntryMaximum(archivePath string) (int64, error) {
	switch {
	case archivePath == "state/state.json":
		return store.MaxStateBytes, nil
	case strings.HasPrefix(archivePath, "secrets/"):
		return store.MaxSecretBytes, nil
	case strings.HasPrefix(archivePath, "config/presets.d/"):
		return routing.PresetMaximumDocumentBytes, nil
	case archivePath == path.Join("exports", ingress.PublicCertificateExportName):
		return backupPublicExportMaximumBytes, nil
	case strings.HasPrefix(archivePath, "exports/clients/"):
		return backupManagedExportMaximumBytes, nil
	default:
		return 0, restoreArchiveInvalid("entry path is outside the gateway restore contract: %s", archivePath)
	}
}

func validateGatewayRestoreAllowlist(state model.State, entries []backupPayloadManifestEntry) error {
	required := map[string]struct{}{"state/state.json": {}}
	allowed := map[string]struct{}{"state/state.json": {}, path.Join("exports", ingress.PublicCertificateExportName): {}}
	references, err := gatewayBackupSecretReferences(state)
	if err != nil {
		return restoreArchiveInvalid("derive structural secret allowlist: %v", err)
	}
	for _, reference := range references {
		kind, id, _ := reference.Parts()
		archivePath := path.Join("secrets", kind, id)
		required[archivePath] = struct{}{}
		allowed[archivePath] = struct{}{}
	}
	for _, client := range state.Clients {
		for _, item := range []struct {
			format    string
			extension string
		}{{"clash", ".clash.yaml"}, {"wireguard", ".wireguard.conf"}} {
			allowed[path.Join("exports/clients", client.Name+item.extension)] = struct{}{}
			allowed[path.Join("exports/clients/.metadata", client.ID+"."+item.format+".json")] = struct{}{}
		}
	}
	presetCount := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Path, "config/presets.d/") {
			name := strings.TrimPrefix(entry.Path, "config/presets.d/")
			if name == "" || strings.Contains(name, "/") || path.Ext(name) != ".yaml" {
				return restoreArchiveInvalid("preset entry path is invalid: %s", entry.Path)
			}
			presetCount++
			if presetCount > routing.PresetMaximumDocuments {
				return restoreArchiveInvalid("preset entry count exceeds %d", routing.PresetMaximumDocuments)
			}
			allowed[entry.Path] = struct{}{}
		}
		if _, ok := allowed[entry.Path]; !ok {
			return restoreArchiveInvalid("entry is outside the structural allowlist: %s", entry.Path)
		}
		delete(required, entry.Path)
	}
	if len(required) != 0 {
		missing := make([]string, 0, len(required))
		for name := range required {
			missing = append(missing, name)
		}
		sort.Strings(missing)
		return restoreArchiveInvalid("required structural entries are missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

func restoreArchiveInvalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrGatewayRestoreArchiveInvalid, fmt.Sprintf(format, arguments...))
}
