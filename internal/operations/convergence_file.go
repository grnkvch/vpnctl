package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const MaximumConvergenceSnapshotBytes = 16 << 20

var ErrConvergenceSnapshotUnavailable = errors.New("convergence snapshot is unavailable")

type FileConvergenceSnapshotSource struct {
	path string
}

func NewFileConvergenceSnapshotSource(path string) (*FileConvergenceSnapshotSource, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "convergence.json" {
		return nil, fmt.Errorf("convergence snapshot path must be an absolute clean convergence.json path")
	}
	return &FileConvergenceSnapshotSource{path: path}, nil
}

func (source *FileConvergenceSnapshotSource) ReadConvergenceSnapshot(ctx context.Context) (ConvergenceSnapshot, error) {
	if ctx == nil {
		return ConvergenceSnapshot{}, fmt.Errorf("context is required")
	}
	if source == nil || source.path == "" {
		return ConvergenceSnapshot{}, fmt.Errorf("convergence snapshot source is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return ConvergenceSnapshot{}, err
	}

	fd, err := unix.Open(source.path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ConvergenceSnapshot{}, fmt.Errorf("%w: %s", ErrConvergenceSnapshotUnavailable, source.path)
		}
		if errors.Is(err, unix.ELOOP) {
			return ConvergenceSnapshot{}, fmt.Errorf("%w: snapshot must not be a symbolic link", ErrConvergencePlanInvalid)
		}
		return ConvergenceSnapshot{}, fmt.Errorf("%w: open snapshot: %v", ErrConvergenceSnapshotUnavailable, err)
	}
	file := os.NewFile(uintptr(fd), source.path)
	if file == nil {
		_ = unix.Close(fd)
		return ConvergenceSnapshot{}, fmt.Errorf("%w: wrap snapshot file", ErrConvergenceSnapshotUnavailable)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return ConvergenceSnapshot{}, fmt.Errorf("%w: inspect snapshot: %v", ErrConvergenceSnapshotUnavailable, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > MaximumConvergenceSnapshotBytes {
		return ConvergenceSnapshot{}, fmt.Errorf("%w: snapshot must be a non-empty 0600 regular file within %d bytes", ErrConvergencePlanInvalid, MaximumConvergenceSnapshotBytes)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return ConvergenceSnapshot{}, fmt.Errorf("%w: snapshot must have exactly one filesystem link", ErrConvergencePlanInvalid)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaximumConvergenceSnapshotBytes+1))
	if err != nil {
		return ConvergenceSnapshot{}, fmt.Errorf("%w: read snapshot: %v", ErrConvergenceSnapshotUnavailable, err)
	}
	if len(data) < 1 || len(data) > MaximumConvergenceSnapshotBytes || int64(len(data)) != info.Size() {
		return ConvergenceSnapshot{}, fmt.Errorf("%w: snapshot size changed during read", ErrConvergencePlanInvalid)
	}
	if err := ctx.Err(); err != nil {
		return ConvergenceSnapshot{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snapshot ConvergenceSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return ConvergenceSnapshot{}, fmt.Errorf("%w: decode snapshot: %v", ErrConvergencePlanInvalid, err)
	}
	if err := requireConvergenceJSONEOF(decoder); err != nil {
		return ConvergenceSnapshot{}, fmt.Errorf("%w: %v", ErrConvergencePlanInvalid, err)
	}
	canonical, err := canonicalSnapshot(snapshot)
	if err != nil {
		return ConvergenceSnapshot{}, err
	}
	return canonical, nil
}

func requireConvergenceJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode trailing snapshot data: %w", err)
	}
	return fmt.Errorf("snapshot contains trailing JSON value")
}
