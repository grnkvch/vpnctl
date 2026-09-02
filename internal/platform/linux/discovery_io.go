package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

type FileKind string

const (
	FileRegular   FileKind = "regular"
	FileDirectory FileKind = "directory"
	FileCharacter FileKind = "character_device"
)

type HostFileSystem interface {
	ReadFile(string) ([]byte, error)
	Kind(string) (FileKind, error)
	Writable(string) (bool, error)
}

type ProbeCommand struct {
	Name  string
	Args  []string
	Stdin []byte
}

type ProbeResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type ProbeRunner interface {
	Run(context.Context, ProbeCommand) (ProbeResult, error)
}

type DiskUsage struct {
	TotalBytes uint64
	FreeBytes  uint64
}

type DiskInspector interface {
	Usage(string) (DiskUsage, error)
}

type RuntimeFacts struct {
	GOOS   string
	GOARCH string
	EUID   int
}

type Discoverer struct {
	files   HostFileSystem
	runner  ProbeRunner
	disk    DiskInspector
	runtime RuntimeFacts
}

func NewDiscoverer(root string) (*Discoverer, error) {
	files, err := newRootFileSystem(root)
	if err != nil {
		return nil, err
	}
	return &Discoverer{
		files:   files,
		runner:  OSProbeRunner{},
		disk:    rootDiskInspector{root: files.root},
		runtime: RuntimeFacts{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, EUID: os.Geteuid()},
	}, nil
}

type rootFileSystem struct {
	root string
}

func newRootFileSystem(root string) (*rootFileSystem, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("discovery root must be absolute")
	}
	return &rootFileSystem{root: filepath.Clean(root)}, nil
}

func (files *rootFileSystem) ReadFile(path string) ([]byte, error) {
	resolved, err := files.resolve(path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolved)
}

func (files *rootFileSystem) Kind(path string) (FileKind, error) {
	resolved, err := files.resolve(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is a symbolic link", path)
	}
	switch {
	case info.Mode().IsRegular():
		return FileRegular, nil
	case info.IsDir():
		return FileDirectory, nil
	case info.Mode()&os.ModeCharDevice != 0:
		return FileCharacter, nil
	default:
		return "", fmt.Errorf("%s has unsupported file type %s", path, info.Mode().Type())
	}
}

func (files *rootFileSystem) Writable(path string) (bool, error) {
	resolved, err := files.resolve(path)
	if err != nil {
		return false, err
	}
	if err := unix.Access(resolved, unix.W_OK); err != nil {
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EROFS) {
			return false, nil
		}
		return false, err
	}
	file, err := os.OpenFile(resolved, os.O_WRONLY, 0)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) || errors.Is(err, unix.EROFS) {
			return false, nil
		}
		return false, err
	}
	if err := file.Close(); err != nil {
		return false, err
	}
	return true, nil
}

func (files *rootFileSystem) resolve(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("probe path must be clean and absolute: %q", path)
	}
	if files.root == string(filepath.Separator) {
		return path, nil
	}
	return filepath.Join(files.root, strings.TrimPrefix(path, string(filepath.Separator))), nil
}

type OSProbeRunner struct{}

func (OSProbeRunner) Run(ctx context.Context, probe ProbeCommand) (ProbeResult, error) {
	if probe.Name == "" {
		return ProbeResult{}, fmt.Errorf("probe command name is required")
	}
	command := exec.CommandContext(ctx, probe.Name, probe.Args...)
	command.Stdin = bytes.NewReader(probe.Stdin)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := ProbeResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	return ProbeResult{}, err
}

type rootDiskInspector struct {
	root string
}

func (inspector rootDiskInspector) Usage(path string) (DiskUsage, error) {
	files := &rootFileSystem{root: inspector.root}
	resolved, err := files.resolve(path)
	if err != nil {
		return DiskUsage{}, err
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(resolved, &stat); err != nil {
		return DiskUsage{}, err
	}
	blockSize := uint64(stat.Bsize)
	return DiskUsage{
		TotalBytes: stat.Blocks * blockSize,
		FreeBytes:  stat.Bavail * blockSize,
	}, nil
}

func fileExists(files HostFileSystem, path string, want FileKind) (bool, error) {
	kind, err := files.Kind(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return kind == want, nil
}
