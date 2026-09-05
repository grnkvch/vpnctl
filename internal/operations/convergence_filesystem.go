package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const MaximumManagedFileObservationBytes = 16 << 20

var ErrOwnedResourceDiscoveryUnsupported = errors.New("owned-resource discovery is unsupported")

type FilesystemOwnedResourceDiscoverer struct {
	root string
}

func NewFilesystemOwnedResourceDiscoverer(root string) (*FilesystemOwnedResourceDiscoverer, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fmt.Errorf("owned-resource discovery root must be clean and absolute")
	}
	return &FilesystemOwnedResourceDiscoverer{root: root}, nil
}

func (discoverer *FilesystemOwnedResourceDiscoverer) DiscoverOwnedResources(ctx context.Context, applied ConvergenceManifest) ([]OwnedResourceObservation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if discoverer == nil || discoverer.root == "" {
		return nil, fmt.Errorf("filesystem owned-resource discoverer is incomplete")
	}
	if err := applied.Validate(); err != nil {
		return nil, fmt.Errorf("validate applied convergence manifest: %w", err)
	}
	observations := make([]OwnedResourceObservation, 0, len(applied.Resources))
	for _, resource := range applied.Resources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if resource.Key.Kind != ManagedResourceFile {
			return nil, fmt.Errorf("%w: %s resource %s", ErrOwnedResourceDiscoveryUnsupported, resource.Key.Kind, resourceOrder(resource.Key))
		}
		observation, present, err := discoverer.observeFile(ctx, resource)
		if err != nil {
			return nil, err
		}
		if present {
			observations = append(observations, observation)
		}
	}
	return observations, nil
}

func (discoverer *FilesystemOwnedResourceDiscoverer) observeFile(ctx context.Context, resource ManagedResource) (OwnedResourceObservation, bool, error) {
	actualPath, err := discoverer.resolveManagedFile(resource.Key.ID)
	if err != nil {
		return OwnedResourceObservation{}, false, err
	}
	info, err := os.Lstat(actualPath)
	if errors.Is(err, fs.ErrNotExist) {
		return OwnedResourceObservation{}, false, nil
	}
	if err != nil {
		return OwnedResourceObservation{}, false, fmt.Errorf("observe owned file %s: %w", resource.Key.ID, err)
	}
	fileType := managedObservedFileType(info.Mode())
	mode := fmt.Sprintf("%04o", info.Mode().Perm())
	contentSHA256 := ""
	if fileType == "regular" {
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
			fileType = "hardlink"
		}
	}
	if fileType == "regular" {
		contentSHA256, err = readManagedFileSHA256(ctx, actualPath, info)
		if errors.Is(err, fs.ErrNotExist) {
			return OwnedResourceObservation{}, false, nil
		}
		if err != nil {
			return OwnedResourceObservation{}, false, fmt.Errorf("observe owned file %s: %w", resource.Key.ID, err)
		}
	}
	runtimeSHA256, err := managedFileRuntimeFingerprint(fileType, mode, contentSHA256)
	if err != nil {
		return OwnedResourceObservation{}, false, fmt.Errorf("fingerprint owned file %s: %w", resource.Key.ID, err)
	}
	return OwnedResourceObservation{Key: resource.Key, RuntimeSHA256: runtimeSHA256, RemoveImpact: resource.RemoveImpact}, true, nil
}

func (discoverer *FilesystemOwnedResourceDiscoverer) resolveManagedFile(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/etc/vpnctl" || !strings.HasPrefix(path, "/etc/vpnctl/") {
		return "", fmt.Errorf("%w: file %q is outside /etc/vpnctl", ErrOwnedResourceDiscoveryUnsupported, path)
	}
	if discoverer.root == "/" {
		return path, nil
	}
	return filepath.Join(discoverer.root, strings.TrimPrefix(path, "/")), nil
}

func readManagedFileSHA256(ctx context.Context, path string, before os.FileInfo) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return "", fmt.Errorf("wrap owned file")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return "", fmt.Errorf("owned file changed identity during observation")
	}
	if after.Size() < 0 || after.Size() > MaximumManagedFileObservationBytes {
		return "", fmt.Errorf("owned file exceeds %d bytes", MaximumManagedFileObservationBytes)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, MaximumManagedFileObservationBytes+1))
	if err != nil {
		return "", err
	}
	if written != after.Size() || written > MaximumManagedFileObservationBytes {
		return "", fmt.Errorf("owned file size changed during observation")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func managedObservedFileType(mode fs.FileMode) string {
	switch {
	case mode.IsRegular():
		return "regular"
	case mode&fs.ModeSymlink != 0:
		return "symlink"
	case mode.IsDir():
		return "directory"
	default:
		return "other"
	}
}
