package operations

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBoundedLoggingFileCreates0600AndRotatesWithinFixedBounds(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "routing.log")
	for cycle := 0; cycle < LoggingFileMaxArchives+2; cycle++ {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
		if err := os.Truncate(path, LoggingFileMaxBytes-1); err != nil {
			t.Fatal(err)
		}
		destination, err := OpenBoundedLoggingFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := destination.Write([]byte("ab")); err != nil {
			t.Fatal(err)
		}
		if err := destination.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index <= LoggingFileMaxArchives; index++ {
		candidate := path
		if index != 0 {
			candidate = loggingArchivePath(path, index)
		}
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > LoggingFileMaxBytes {
			t.Fatalf("bounded file %s info=%+v err=%v", candidate, info, err)
		}
	}
	if _, err := os.Lstat(loggingArchivePath(path, LoggingFileMaxArchives+1)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected unbounded archive: %v", err)
	}
}

func TestBoundedLoggingFileCreatesOnlyItsPrivateDirectParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "vpnctl")
	path := filepath.Join(directory, "control.log")
	destination, err := OpenBoundedLoggingFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct {
		path string
		mode os.FileMode
	}{{directory, 0o700}, {path, 0o600}} {
		info, err := os.Lstat(candidate.path)
		if err != nil {
			t.Fatalf("inspect created %s: %v", candidate.path, err)
		}
		if info.Mode().Perm() != candidate.mode {
			t.Fatalf("created %s mode=%v", candidate.path, info.Mode().Perm())
		}
	}
}

func TestBoundedLoggingFileRejectsUnsafeTargetsAndOversizedRecords(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBoundedLoggingFile(link); !errors.Is(err, ErrUnsafeLoggingFile) {
		t.Fatalf("symlink error = %v", err)
	}

	unsafeMode := filepath.Join(directory, "unsafe.log")
	if err := os.WriteFile(unsafeMode, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeMode, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBoundedLoggingFile(unsafeMode); !errors.Is(err, ErrUnsafeLoggingFile) {
		t.Fatalf("unsafe mode error = %v", err)
	}

	safePath := filepath.Join(directory, "safe.log")
	destination, err := OpenBoundedLoggingFile(safePath)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	if _, err := destination.Write(make([]byte, MaximumLoggingRecordBytes+1)); err == nil {
		t.Fatal("oversized logging record was accepted")
	}
	info, err := os.Stat(safePath)
	if err != nil || info.Size() != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("safe file after refusal = %+v, %v", info, err)
	}
}

func TestBoundedLoggingFileRefusesSymlinkArchiveDuringRotation(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "dns.log")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, LoggingFileMaxBytes); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "foreign")
	if err := os.WriteFile(target, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, loggingArchivePath(path, LoggingFileMaxArchives)); err != nil {
		t.Fatal(err)
	}
	destination, err := OpenBoundedLoggingFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	if _, err := destination.Write([]byte("x")); !errors.Is(err, ErrUnsafeLoggingFile) {
		t.Fatalf("symlink archive rotation error = %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "foreign" {
		t.Fatalf("foreign target changed: %q, %v", data, err)
	}
}
