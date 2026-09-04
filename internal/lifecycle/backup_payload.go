package lifecycle

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const backupPayloadFormat = "vpnctl-gateway-payload-v1"

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
	path string
	data []byte
}

type preparedGatewayBackupPayload struct {
	entries []preparedBackupPayloadEntry
	closed  bool
}

// StateBackupPayloadSource is the task-14.7 baseline payload. The encrypted
// envelope and manifest are production contracts; task 14.8 extends this
// source with the explicit gateway file allowlist without changing framing.
type StateBackupPayloadSource struct{}

func (StateBackupPayloadSource) Prepare(ctx context.Context, state model.State) (BackupPayload, error) {
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
	entries := []preparedBackupPayloadEntry{{path: "state/state.json", data: encodedState}}
	manifestEntries := make([]backupPayloadManifestEntry, len(entries))
	for index, entry := range entries {
		digest := sha256.Sum256(entry.data)
		manifestEntries[index] = backupPayloadManifestEntry{
			Path: entry.path, SizeBytes: int64(len(entry.data)), SHA256: hex.EncodeToString(digest[:]),
		}
	}
	sort.Slice(manifestEntries, func(left, right int) bool { return manifestEntries[left].Path < manifestEntries[right].Path })
	manifest := backupPayloadManifest{
		SchemaVersion: 1, Format: backupPayloadFormat, StateGeneration: state.Generation,
		PublicIPv4: state.Host.PublicIPv4, Entries: manifestEntries,
	}
	encodedManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode gateway backup manifest: %w", err)
	}
	encodedManifest = append(encodedManifest, '\n')
	entries = append([]preparedBackupPayloadEntry{{path: "manifest.json", data: encodedManifest}}, entries...)
	return &preparedGatewayBackupPayload{entries: entries}, nil
}

func (payload *preparedGatewayBackupPayload) WriteTo(ctx context.Context, destination io.Writer) error {
	if ctx == nil || destination == nil || payload == nil || payload.closed {
		return fmt.Errorf("prepared gateway backup payload is unavailable")
	}
	tape := tar.NewWriter(destination)
	for _, entry := range payload.entries {
		if err := ctx.Err(); err != nil {
			_ = tape.Close()
			return err
		}
		header := &tar.Header{
			Name: entry.path, Mode: 0o600, Size: int64(len(entry.data)), Typeflag: tar.TypeReg,
			Format: tar.FormatPAX,
		}
		if err := tape.WriteHeader(header); err != nil {
			_ = tape.Close()
			return fmt.Errorf("write backup payload header %s: %w", entry.path, err)
		}
		if _, err := tape.Write(entry.data); err != nil {
			_ = tape.Close()
			return fmt.Errorf("write backup payload entry %s: %w", entry.path, err)
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
	}
	payload.entries = nil
	return nil
}

var _ BackupPayloadSource = StateBackupPayloadSource{}
var _ BackupPayload = (*preparedGatewayBackupPayload)(nil)
