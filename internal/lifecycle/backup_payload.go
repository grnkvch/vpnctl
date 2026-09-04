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
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
	"golang.org/x/sys/unix"
)

const (
	backupPayloadFormat             = "vpnctl-gateway-payload-v1"
	backupManagedExportMaximumBytes = 16 << 20
	backupPublicExportMaximumBytes  = 64 << 10
)

type BackupPayload interface {
	WriteTo(context.Context, io.Writer) error
	Close() error
}

type BackupPayloadSource interface {
	Prepare(context.Context, model.State) (BackupPayload, error)
}

type backupPayloadManifest struct {
	SchemaVersion   int                          `json:"schema_version"`
	Format          string                       `json:"format"`
	StateGeneration uint64                       `json:"state_generation"`
	PublicIPv4      string                       `json:"public_ipv4"`
	Entries         []backupPayloadManifestEntry `json:"entries"`
}

type backupPayloadManifestEntry struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

type preparedBackupPayloadEntry struct {
	path       string
	data       []byte
	sourcePath string
	sourceInfo os.FileInfo
	size       int64
	sha256     string
}

type preparedGatewayBackupPayload struct {
	entries           []preparedBackupPayloadEntry
	absentSourcePaths []string
	directories       []preparedBackupDirectory
	closed            bool
}

type preparedBackupDirectory struct {
	path   string
	info   os.FileInfo
	suffix string
	names  []string
	limit  int
}

type GatewayBackupSecretReader interface {
	Get(model.SecretRef) ([]byte, error)
}

// GatewayBackupPayloadSource snapshots only structurally owned gateway data.
// It never walks the state, secret, or export trees recursively: every secret
// reference is derived from validated resource ownership, and every export is
// one exact managed path derived from authoritative client identity.
type GatewayBackupPayloadSource struct {
	paths   store.Paths
	secrets GatewayBackupSecretReader
}

func NewGatewayBackupPayloadSource(paths store.Paths, secrets GatewayBackupSecretReader) (*GatewayBackupPayloadSource, error) {
	if secrets == nil {
		return nil, fmt.Errorf("gateway backup secret reader is required")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths {
		return nil, fmt.Errorf("gateway backup paths do not match the system root")
	}
	return &GatewayBackupPayloadSource{paths: paths, secrets: secrets}, nil
}

// stateBackupPayloadSource keeps the state-only task-14.7 envelope fixtures
// focused. Production construction always uses GatewayBackupPayloadSource.
type stateBackupPayloadSource struct{}

func (stateBackupPayloadSource) Prepare(ctx context.Context, state model.State) (BackupPayload, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if state.Host.Role != model.RoleGateway {
		return nil, fmt.Errorf("gateway backup payload requires gateway state")
	}
	encodedState, err := model.EncodeState(state)
	if err != nil {
		return nil, fmt.Errorf("encode gateway backup state: %w", err)
	}
	return prepareGatewayBackupPayload(state, []preparedBackupPayloadEntry{newBackupDataEntry("state/state.json", encodedState)}, nil, nil)
}

func (source *GatewayBackupPayloadSource) Prepare(ctx context.Context, state model.State) (BackupPayload, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if source == nil || source.secrets == nil {
		return nil, fmt.Errorf("gateway backup payload source is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return nil, fmt.Errorf("gateway backup payload requires valid gateway state")
	}
	encodedState, err := model.EncodeState(state)
	if err != nil {
		return nil, fmt.Errorf("encode gateway backup state: %w", err)
	}
	entries := []preparedBackupPayloadEntry{newBackupDataEntry("state/state.json", encodedState)}
	absent := []string{}
	directories := []preparedBackupDirectory{}
	cleanup := func(cause error) (BackupPayload, error) {
		_ = (&preparedGatewayBackupPayload{entries: entries}).Close()
		return nil, cause
	}

	references, err := gatewayBackupSecretReferences(state)
	if err != nil {
		return cleanup(err)
	}
	for _, reference := range references {
		if err := ctx.Err(); err != nil {
			return cleanup(err)
		}
		content, readErr := source.secrets.Get(reference)
		if readErr != nil {
			return cleanup(fmt.Errorf("read allowlisted gateway backup secret %s: %w", reference, readErr))
		}
		kind, id, _ := reference.Parts()
		entries = append(entries, newBackupDataEntry(path.Join("secrets", kind, id), content))
	}

	presets, err := inspectBackupDirectory(ctx, source.paths.PresetsDir, ".yaml", routing.PresetMaximumDirectoryItems)
	if err != nil {
		return cleanup(fmt.Errorf("inspect gateway backup presets: %w", err))
	}
	directories = append(directories, presets)
	for _, name := range presets.names {
		entry, err := inspectBackupFile(ctx, filepath.Join(source.paths.PresetsDir, name), path.Join("config/presets.d", name), routing.PresetMaximumDocumentBytes, 0)
		if err != nil {
			return cleanup(fmt.Errorf("snapshot gateway backup preset %s: %w", name, err))
		}
		entries = append(entries, entry)
	}

	publicExport := filepath.Join(source.paths.ExportsDir, ingress.PublicCertificateExportName)
	entries, absent, err = appendOptionalBackupFile(ctx, entries, absent, publicExport, path.Join("exports", ingress.PublicCertificateExportName), backupPublicExportMaximumBytes, 0o644)
	if err != nil {
		return cleanup(err)
	}
	for _, client := range state.Clients {
		for _, format := range []string{"clash", "wireguard"} {
			extension := ".clash.yaml"
			if format == "wireguard" {
				extension = ".wireguard.conf"
			}
			profileName := client.Name + extension
			profilePath := filepath.Join(source.paths.ClientExportsDir, profileName)
			entries, absent, err = appendOptionalBackupFile(ctx, entries, absent, profilePath, path.Join("exports/clients", profileName), backupManagedExportMaximumBytes, 0o600)
			if err != nil {
				return cleanup(err)
			}
			metadataName := client.ID + "." + format + ".json"
			metadataPath := filepath.Join(source.paths.ClientExportsDir, ".metadata", metadataName)
			entries, absent, err = appendOptionalBackupFile(ctx, entries, absent, metadataPath, path.Join("exports/clients/.metadata", metadataName), backupManagedExportMaximumBytes, 0o600)
			if err != nil {
				return cleanup(err)
			}
		}
	}
	return prepareGatewayBackupPayload(state, entries, absent, directories)
}

func prepareGatewayBackupPayload(state model.State, entries []preparedBackupPayloadEntry, absent []string, directories []preparedBackupDirectory) (BackupPayload, error) {
	seen := make(map[string]struct{}, len(entries)+1)
	seen["manifest.json"] = struct{}{}
	for index := range entries {
		entry := &entries[index]
		if err := validateBackupPayloadPath(entry.path); err != nil {
			_ = (&preparedGatewayBackupPayload{entries: entries}).Close()
			return nil, err
		}
		if _, duplicate := seen[entry.path]; duplicate {
			_ = (&preparedGatewayBackupPayload{entries: entries}).Close()
			return nil, fmt.Errorf("duplicate gateway backup payload path %s", entry.path)
		}
		seen[entry.path] = struct{}{}
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].path < entries[right].path })
	manifestEntries := make([]backupPayloadManifestEntry, len(entries))
	for index, entry := range entries {
		manifestEntries[index] = backupPayloadManifestEntry{
			Path: entry.path, SizeBytes: entry.size, SHA256: entry.sha256,
		}
	}
	manifest := backupPayloadManifest{
		SchemaVersion: 1, Format: backupPayloadFormat, StateGeneration: state.Generation,
		PublicIPv4: state.Host.PublicIPv4, Entries: manifestEntries,
	}
	encodedManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		_ = (&preparedGatewayBackupPayload{entries: entries}).Close()
		return nil, fmt.Errorf("encode gateway backup manifest: %w", err)
	}
	encodedManifest = append(encodedManifest, '\n')
	entries = append([]preparedBackupPayloadEntry{newBackupDataEntry("manifest.json", encodedManifest)}, entries...)
	return &preparedGatewayBackupPayload{
		entries: entries, absentSourcePaths: append([]string(nil), absent...), directories: append([]preparedBackupDirectory(nil), directories...),
	}, nil
}

func (payload *preparedGatewayBackupPayload) WriteTo(ctx context.Context, destination io.Writer) error {
	if ctx == nil || destination == nil || payload == nil || payload.closed {
		return fmt.Errorf("prepared gateway backup payload is unavailable")
	}
	for _, directory := range payload.directories {
		current, err := inspectBackupDirectory(ctx, directory.path, directory.suffix, directory.limit)
		if err != nil || !os.SameFile(directory.info, current.info) || !reflect.DeepEqual(directory.names, current.names) {
			return fmt.Errorf("gateway backup source directory changed after planning: %s", directory.path)
		}
	}
	for _, sourcePath := range payload.absentSourcePaths {
		if _, err := os.Lstat(sourcePath); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("gateway backup source appeared after planning: %s", sourcePath)
		}
	}
	tape := tar.NewWriter(destination)
	for _, entry := range payload.entries {
		if err := ctx.Err(); err != nil {
			_ = tape.Close()
			return err
		}
		header := &tar.Header{
			Name: entry.path, Mode: 0o600, Size: entry.size, Typeflag: tar.TypeReg,
			Format: tar.FormatPAX,
		}
		if err := tape.WriteHeader(header); err != nil {
			_ = tape.Close()
			return fmt.Errorf("write backup payload header %s: %w", entry.path, err)
		}
		if entry.sourcePath == "" {
			if _, err := tape.Write(entry.data); err != nil {
				_ = tape.Close()
				return fmt.Errorf("write backup payload entry %s: %w", entry.path, err)
			}
		} else if err := writeBackupFileEntry(ctx, tape, entry); err != nil {
			_ = tape.Close()
			return err
		}
	}
	if err := tape.Close(); err != nil {
		return fmt.Errorf("finalize backup payload: %w", err)
	}
	return nil
}

func (payload *preparedGatewayBackupPayload) Close() error {
	if payload == nil || payload.closed {
		return nil
	}
	payload.closed = true
	for index := range payload.entries {
		wipeBackupBytes(payload.entries[index].data)
		payload.entries[index].data = nil
		payload.entries[index].sourcePath = ""
		payload.entries[index].sourceInfo = nil
	}
	payload.entries = nil
	payload.absentSourcePaths = nil
	payload.directories = nil
	return nil
}

func newBackupDataEntry(archivePath string, data []byte) preparedBackupPayloadEntry {
	digest := sha256.Sum256(data)
	return preparedBackupPayloadEntry{
		path: archivePath, data: data, size: int64(len(data)), sha256: hex.EncodeToString(digest[:]),
	}
}

func validateBackupPayloadPath(value string) error {
	if value == "" || value == "." || strings.HasPrefix(value, "/") || path.Clean(value) != value || strings.HasPrefix(value, "../") || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("invalid gateway backup payload path %q", value)
	}
	return nil
}

func appendOptionalBackupFile(ctx context.Context, entries []preparedBackupPayloadEntry, absent []string, sourcePath, archivePath string, maximum int64, mode os.FileMode) ([]preparedBackupPayloadEntry, []string, error) {
	entry, err := inspectOptionalBackupFile(ctx, sourcePath, archivePath, maximum, mode)
	if err != nil {
		return entries, absent, err
	}
	if entry == nil {
		return entries, append(absent, sourcePath), nil
	}
	return append(entries, *entry), absent, nil
}

func inspectOptionalBackupFile(ctx context.Context, sourcePath, archivePath string, maximum int64, mode os.FileMode) (*preparedBackupPayloadEntry, error) {
	if _, err := os.Lstat(sourcePath); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("inspect optional gateway backup file %s: %w", sourcePath, err)
	}
	entry, err := inspectBackupFile(ctx, sourcePath, archivePath, maximum, mode)
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func inspectBackupFile(ctx context.Context, sourcePath, archivePath string, maximum int64, mode os.FileMode) (preparedBackupPayloadEntry, error) {
	if ctx == nil || maximum < 1 {
		return preparedBackupPayloadEntry{}, fmt.Errorf("invalid gateway backup file inspection")
	}
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return preparedBackupPayloadEntry{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return preparedBackupPayloadEntry{}, fmt.Errorf("selected gateway backup file must be a regular file no larger than %d bytes: %s", maximum, sourcePath)
	}
	if mode != 0 && info.Mode().Perm() != mode {
		return preparedBackupPayloadEntry{}, fmt.Errorf("selected gateway backup file %s must use mode %04o", sourcePath, mode)
	}
	file, err := openBackupPathNoFollow(sourcePath, false)
	if err != nil {
		return preparedBackupPayloadEntry{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return preparedBackupPayloadEntry{}, fmt.Errorf("selected gateway backup file changed while opening: %s", sourcePath)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(contextBackupReader{ctx: ctx, reader: file}, maximum+1))
	if err != nil {
		return preparedBackupPayloadEntry{}, fmt.Errorf("hash selected gateway backup file %s: %w", sourcePath, err)
	}
	if written != opened.Size() || written > maximum {
		return preparedBackupPayloadEntry{}, fmt.Errorf("selected gateway backup file changed while hashing: %s", sourcePath)
	}
	return preparedBackupPayloadEntry{
		path: archivePath, sourcePath: sourcePath, sourceInfo: opened, size: written, sha256: hex.EncodeToString(hash.Sum(nil)),
	}, nil
}

func writeBackupFileEntry(ctx context.Context, destination io.Writer, entry preparedBackupPayloadEntry) error {
	file, err := openBackupPathNoFollow(entry.sourcePath, false)
	if err != nil {
		return fmt.Errorf("open gateway backup payload entry %s: %w", entry.path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(entry.sourceInfo, info) || info.Size() != entry.size || info.Mode().Perm() != entry.sourceInfo.Mode().Perm() {
		return fmt.Errorf("gateway backup source changed after planning: %s", entry.sourcePath)
	}
	hash := sha256.New()
	written, err := io.CopyN(io.MultiWriter(destination, hash), contextBackupReader{ctx: ctx, reader: file}, entry.size)
	if err != nil || written != entry.size {
		return fmt.Errorf("write gateway backup payload entry %s: source changed or became unreadable", entry.path)
	}
	var trailing [1]byte
	if count, readErr := file.Read(trailing[:]); count != 0 || !errors.Is(readErr, io.EOF) || hex.EncodeToString(hash.Sum(nil)) != entry.sha256 {
		return fmt.Errorf("gateway backup source content changed after planning: %s", entry.sourcePath)
	}
	return nil
}

func inspectBackupDirectory(ctx context.Context, directoryPath, suffix string, limit int) (preparedBackupDirectory, error) {
	if ctx == nil || limit < 1 || suffix == "" {
		return preparedBackupDirectory{}, fmt.Errorf("invalid gateway backup directory inspection")
	}
	before, err := os.Lstat(directoryPath)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return preparedBackupDirectory{}, fmt.Errorf("gateway backup source must be a real directory: %s", directoryPath)
	}
	directory, err := openBackupPathNoFollow(directoryPath, true)
	if err != nil {
		return preparedBackupDirectory{}, err
	}
	defer directory.Close()
	opened, err := directory.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(before, opened) {
		return preparedBackupDirectory{}, fmt.Errorf("gateway backup source directory changed while opening: %s", directoryPath)
	}
	items, err := directory.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return preparedBackupDirectory{}, fmt.Errorf("read gateway backup source directory %s: %w", directoryPath, err)
	}
	if len(items) > limit {
		return preparedBackupDirectory{}, fmt.Errorf("gateway backup source directory exceeds %d entries: %s", limit, directoryPath)
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return preparedBackupDirectory{}, err
		}
		if strings.HasSuffix(item.Name(), suffix) {
			names = append(names, item.Name())
		}
	}
	sort.Strings(names)
	return preparedBackupDirectory{path: directoryPath, info: opened, suffix: suffix, names: names, limit: limit}, nil
}

func openBackupPathNoFollow(value string, directory bool) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(value, flags, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "vpnctl-backup-source")
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open gateway backup source file descriptor")
	}
	return file, nil
}

type contextBackupReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextBackupReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func gatewayBackupSecretReferences(state model.State) ([]model.SecretRef, error) {
	references := map[model.SecretRef]struct{}{
		transport.GatewayStandardCredentialRef:   {},
		transport.GatewayRestrictedCredentialRef: {},
	}
	if state.EnrollmentIdentity == nil {
		return nil, fmt.Errorf("authoritative gateway enrollment identity is missing")
	}
	if err := addBackupSecretReference(references, model.SecretRef(state.EnrollmentIdentity.PublicKeyRef), "enrollment-public"); err != nil {
		return nil, err
	}
	if err := addBackupSecretReference(references, state.EnrollmentIdentity.PrivateKeyRef, "enrollment-key"); err != nil {
		return nil, err
	}
	activeNodes := make(map[string]model.Node)
	for _, node := range state.Nodes {
		if node.Lifecycle == model.LifecycleActive {
			activeNodes[node.ID] = node
			reference, err := tunnel.CredentialReference(node.ID, node.CredentialGeneration)
			if err != nil {
				return nil, err
			}
			references[reference] = struct{}{}
		}
	}
	activeClients := make(map[string]struct{})
	for _, client := range state.Clients {
		if client.Lifecycle == model.LifecycleActive {
			activeClients[client.ID] = struct{}{}
		}
	}
	for _, certificate := range state.Certificates {
		certificateKind, privateKind, err := backupCertificateReferenceKinds(certificate.Kind)
		if err != nil {
			return nil, err
		}
		if err := addBackupSecretReference(references, model.SecretRef(certificate.CertificateRef), certificateKind); err != nil {
			return nil, fmt.Errorf("certificate %s: %w", certificate.ID, err)
		}
		if certificate.OwnerKind == "node" {
			if certificate.PrivateKeyRef != "" {
				return nil, fmt.Errorf("refuse node-owned private key in gateway backup: certificate %s", certificate.ID)
			}
			if _, active := activeNodes[certificate.OwnerID]; !active {
				delete(references, model.SecretRef(certificate.CertificateRef))
			}
			continue
		}
		if certificate.PrivateKeyRef == "" {
			return nil, fmt.Errorf("host certificate %s has no private key reference", certificate.ID)
		}
		if err := addBackupSecretReference(references, certificate.PrivateKeyRef, privateKind); err != nil {
			return nil, fmt.Errorf("certificate %s: %w", certificate.ID, err)
		}
	}
	for _, record := range state.Transports {
		expected, include, err := backupTransportSecretReference(record, activeNodes, activeClients)
		if err != nil {
			return nil, err
		}
		if record.CredentialRef != expected {
			return nil, fmt.Errorf("transport %s/%s %s credential reference is outside the structural backup contract", record.OwnerKind, record.OwnerID, record.Kind)
		}
		if include {
			references[record.CredentialRef] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(references))
	for reference := range references {
		ordered = append(ordered, reference.String())
	}
	sort.Strings(ordered)
	result := make([]model.SecretRef, len(ordered))
	for index, value := range ordered {
		result[index] = model.SecretRef(value)
	}
	return result, nil
}

func backupCertificateReferenceKinds(kind model.CertificateKind) (string, string, error) {
	switch kind {
	case model.CertificateControlCA, model.CertificateControlServer, model.CertificateControlNode:
		return "control-cert", "control-key", nil
	case model.CertificatePublicIngress:
		return "ingress-cert", "ingress-key", nil
	case model.CertificateTunnelServer:
		return "tunnel-cert", "tunnel-key", nil
	default:
		return "", "", fmt.Errorf("unsupported gateway backup certificate kind %q", kind)
	}
}

func addBackupSecretReference(set map[model.SecretRef]struct{}, reference model.SecretRef, kind string) error {
	actual, _, err := reference.Parts()
	if err != nil || actual != kind {
		return fmt.Errorf("secret reference %q must use kind %s", reference, kind)
	}
	set[reference] = struct{}{}
	return nil
}

func backupTransportSecretReference(record model.Transport, activeNodes map[string]model.Node, activeClients map[string]struct{}) (model.SecretRef, bool, error) {
	var kind, id string
	switch record.OwnerKind {
	case model.TargetNode:
		switch record.Kind {
		case model.TransportStandard:
			kind, id = "wireguard-peer", fmt.Sprintf("%s-g%d", record.OwnerID, record.CredentialGeneration)
		case model.TransportRestricted:
			kind, id = "restricted-user", fmt.Sprintf("%s-g%d", record.OwnerID, record.CredentialGeneration)
		default:
			return "", false, fmt.Errorf("unsupported node transport kind %q", record.Kind)
		}
		reference, err := model.NewSecretRef(kind, id)
		_, active := activeNodes[record.OwnerID]
		return reference, active && record.Kind == model.TransportRestricted, err
	case model.TargetClient:
		switch record.Kind {
		case model.TransportStandard:
			kind, id = "wireguard-key", fmt.Sprintf("%s-standard-g%d", record.OwnerID, record.CredentialGeneration)
		case model.TransportRestricted:
			kind, id = "restricted-user", fmt.Sprintf("%s-g%d", record.OwnerID, record.CredentialGeneration)
		default:
			return "", false, fmt.Errorf("unsupported client transport kind %q", record.Kind)
		}
		reference, err := model.NewSecretRef(kind, id)
		_, active := activeClients[record.OwnerID]
		return reference, active, err
	default:
		return "", false, fmt.Errorf("unsupported gateway backup transport owner %q", record.OwnerKind)
	}
}

var _ BackupPayloadSource = stateBackupPayloadSource{}
var _ BackupPayloadSource = (*GatewayBackupPayloadSource)(nil)
var _ BackupPayload = (*preparedGatewayBackupPayload)(nil)
