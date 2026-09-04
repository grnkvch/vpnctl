package operations

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

const MaximumLoggingRecordBytes = 64 << 10

var ErrUnsafeLoggingFile = errors.New("unsafe logging file")

// BoundedLoggingFile is the only supported non-journald destination. The
// containing directory is expected to be vpnctl-owned; every opened current or
// archive file must still be a non-symlink regular file with mode 0600.
type BoundedLoggingFile struct {
	mu   sync.Mutex
	path string
	file *os.File
	size int64
}

func OpenBoundedLoggingFile(path string) (*BoundedLoggingFile, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%w: path must be clean and absolute", ErrUnsafeLoggingFile)
	}
	if err := validateLoggingDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, size, err := openLoggingFile(path)
	if err != nil {
		return nil, err
	}
	return &BoundedLoggingFile{path: path, file: file, size: size}, nil
}

func (destination *BoundedLoggingFile) Write(record []byte) (int, error) {
	if destination == nil {
		return 0, fmt.Errorf("logging file is required")
	}
	if len(record) == 0 {
		return 0, nil
	}
	if len(record) > MaximumLoggingRecordBytes || int64(len(record)) > LoggingFileMaxBytes {
		return 0, fmt.Errorf("logging record exceeds %d bytes", MaximumLoggingRecordBytes)
	}
	destination.mu.Lock()
	defer destination.mu.Unlock()
	if destination.file == nil {
		return 0, os.ErrClosed
	}
	if destination.size+int64(len(record)) > LoggingFileMaxBytes {
		if err := destination.rotate(); err != nil {
			return 0, err
		}
	}
	written, err := destination.file.Write(record)
	destination.size += int64(written)
	if err != nil {
		return written, fmt.Errorf("append bounded logging file: %w", err)
	}
	if written != len(record) {
		return written, fmt.Errorf("append bounded logging file: short write")
	}
	return written, nil
}

func (destination *BoundedLoggingFile) Close() error {
	if destination == nil {
		return nil
	}
	destination.mu.Lock()
	defer destination.mu.Unlock()
	if destination.file == nil {
		return nil
	}
	err := destination.file.Close()
	destination.file = nil
	return err
}

func (destination *BoundedLoggingFile) rotate() error {
	if err := destination.file.Sync(); err != nil {
		return fmt.Errorf("sync logging file before rotation: %w", err)
	}
	if err := destination.file.Close(); err != nil {
		return fmt.Errorf("close logging file before rotation: %w", err)
	}
	destination.file = nil

	oldest := loggingArchivePath(destination.path, LoggingFileMaxArchives)
	if err := removeSafeLoggingArchive(oldest); err != nil {
		return err
	}
	for index := LoggingFileMaxArchives - 1; index >= 1; index-- {
		from := loggingArchivePath(destination.path, index)
		if err := moveSafeLoggingArchive(from, loggingArchivePath(destination.path, index+1)); err != nil {
			return err
		}
	}
	if err := moveSafeLoggingArchive(destination.path, loggingArchivePath(destination.path, 1)); err != nil {
		return err
	}
	file, size, err := openLoggingFile(destination.path)
	if err != nil {
		return err
	}
	destination.file, destination.size = file, size
	return nil
}

func validateLoggingDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(path)
		parentInfo, parentErr := os.Lstat(parent)
		if parentErr != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
			return fmt.Errorf("%w: logging directory parent must be a real directory", ErrUnsafeLoggingFile)
		}
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create logging directory: %w", err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("%w: inspect logging directory: %v", ErrUnsafeLoggingFile, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: logging parent must be a mode-0700 real directory", ErrUnsafeLoggingFile)
	}
	return nil
}

func openLoggingFile(path string) (*os.File, int64, error) {
	flags := unix.O_WRONLY | unix.O_APPEND | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	fd, err := unix.Open(path, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Open(path, flags, 0)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("%w: open logging file: %v", ErrUnsafeLoggingFile, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if created {
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return nil, 0, fmt.Errorf("set logging file mode: %w", err)
		}
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, fmt.Errorf("inspect logging file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, 0, fmt.Errorf("%w: logging file must be regular with mode 0600", ErrUnsafeLoggingFile)
	}
	if info.Size() > LoggingFileMaxBytes {
		_ = file.Close()
		return nil, 0, fmt.Errorf("%w: current logging file exceeds its size bound", ErrUnsafeLoggingFile)
	}
	return file, info.Size(), nil
}

func removeSafeLoggingArchive(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect oldest logging archive: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > LoggingFileMaxBytes {
		return fmt.Errorf("%w: archive %s is not a mode-0600 regular file", ErrUnsafeLoggingFile, filepath.Base(path))
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove oldest logging archive: %w", err)
	}
	return nil
}

func moveSafeLoggingArchive(from, to string) error {
	info, err := os.Lstat(from)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect logging archive: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > LoggingFileMaxBytes {
		return fmt.Errorf("%w: archive %s is not a mode-0600 regular file", ErrUnsafeLoggingFile, filepath.Base(from))
	}
	if _, err := os.Lstat(to); err == nil {
		return fmt.Errorf("%w: archive target %s already exists", ErrUnsafeLoggingFile, filepath.Base(to))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect logging archive target: %w", err)
	}
	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("rotate logging archive: %w", err)
	}
	return nil
}

func loggingArchivePath(path string, index int) string {
	return path + "." + strconv.Itoa(index)
}
