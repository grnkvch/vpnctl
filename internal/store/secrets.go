package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"golang.org/x/sys/unix"
)

const (
	SecretDirectoryMode os.FileMode = 0o700
	SecretFileMode      os.FileMode = 0o600
	MaxSecretBytes                  = 1 << 20
	secretTempAttempts              = 32
)

var (
	ErrSecretNotFound    = errors.New("vpnctl secret not found")
	ErrSecretPermissions = errors.New("vpnctl secret permissions are unsafe")
	ErrUnsafeSecretPath  = errors.New("vpnctl secret path has an unsafe type")
)

type PermissionIssue struct {
	RelativePath string
	ObjectType   string
	ExpectedMode os.FileMode
	ActualMode   os.FileMode
	ExpectedUID  uint32
	ActualUID    uint32
	ExpectedGID  uint32
	ActualGID    uint32
	Repairable   bool
}

type SecretStore struct {
	paths Paths
}

func NewSecretStore(paths Paths) (*SecretStore, error) {
	if !filepath.IsAbs(paths.StateDir) || !filepath.IsAbs(paths.SecretsDir) {
		return nil, fmt.Errorf("secret store paths must be absolute")
	}
	if filepath.Clean(paths.StateDir) != paths.StateDir || filepath.Clean(paths.SecretsDir) != paths.SecretsDir {
		return nil, fmt.Errorf("secret store paths must be clean")
	}
	if filepath.Dir(paths.SecretsDir) != paths.StateDir {
		return nil, fmt.Errorf("secrets directory must be a direct child of state directory")
	}
	return &SecretStore{paths: paths}, nil
}

func (store *SecretStore) Put(reference model.SecretRef, secret []byte) error {
	if len(secret) == 0 {
		return fmt.Errorf("secret value must not be empty")
	}
	if len(secret) > MaxSecretBytes {
		return fmt.Errorf("secret value exceeds %d bytes", MaxSecretBytes)
	}
	kind, id, err := reference.Parts()
	if err != nil {
		return err
	}
	rootFD, err := store.openRoot(true)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	kindFD, err := openKindDirectory(rootFD, kind, true)
	if err != nil {
		return err
	}
	defer unix.Close(kindFD)
	if err := validateSecretEntry(kindFD, id); err != nil && !errors.Is(err, ErrSecretNotFound) {
		return err
	}

	temporary, file, err := createSecretTemporary(kindFD)
	if err != nil {
		return err
	}
	keepTemporary := true
	defer func() {
		_ = file.Close()
		if keepTemporary {
			_ = unix.Unlinkat(kindFD, temporary, 0)
		}
	}()
	if err := writeAll(file, secret); err != nil {
		return fmt.Errorf("write secret temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync secret temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close secret temporary file: %w", err)
	}
	if err := unix.Renameat(kindFD, temporary, kindFD, id); err != nil {
		return fmt.Errorf("activate secret: %w", err)
	}
	keepTemporary = false
	if err := unix.Fsync(kindFD); err != nil {
		return fmt.Errorf("sync secret directory: %w", err)
	}
	return nil
}

func (store *SecretStore) Get(reference model.SecretRef) ([]byte, error) {
	kind, id, err := reference.Parts()
	if err != nil {
		return nil, err
	}
	rootFD, err := store.openRoot(false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	kindFD, err := openKindDirectory(rootFD, kind, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(kindFD)
	if err := validateSecretEntry(kindFD, id); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(kindFD, id, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, reference)
		}
		return nil, fmt.Errorf("open secret: %w", err)
	}
	file := os.NewFile(uintptr(fd), "vpnctl-secret")
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open secret file descriptor")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxSecretBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read secret: %w", err)
	}
	if len(data) > MaxSecretBytes {
		return nil, fmt.Errorf("secret exceeds %d bytes", MaxSecretBytes)
	}
	return data, nil
}

func (store *SecretStore) Delete(reference model.SecretRef) (bool, error) {
	kind, id, err := reference.Parts()
	if err != nil {
		return false, err
	}
	rootFD, err := store.openRoot(false)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return false, nil
		}
		return false, err
	}
	defer unix.Close(rootFD)
	kindFD, err := openKindDirectory(rootFD, kind, false)
	if err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return false, nil
		}
		return false, err
	}
	defer unix.Close(kindFD)
	if err := validateSecretEntry(kindFD, id); err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return false, nil
		}
		return false, err
	}
	if err := unix.Unlinkat(kindFD, id, 0); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, fmt.Errorf("delete secret: %w", err)
	}
	if err := unix.Fsync(kindFD); err != nil {
		return false, fmt.Errorf("sync secret directory: %w", err)
	}
	return true, nil
}

func (store *SecretStore) DiagnosePermissions() ([]PermissionIssue, error) {
	expectedUID, expectedGID, err := stateDirectoryOwner(store.paths.StateDir)
	if err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(store.paths.SecretsDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: secrets directory", ErrSecretNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("inspect secrets directory: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return []PermissionIssue{{RelativePath: ".", ObjectType: fileType(rootInfo.Mode()), ExpectedMode: SecretDirectoryMode, ActualMode: rootInfo.Mode().Perm(), ExpectedUID: expectedUID, ExpectedGID: expectedGID}}, nil
	}
	rootFD, err := openDirectoryNoFollow(store.paths.SecretsDir)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	issues := make([]PermissionIssue, 0)
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return nil, fmt.Errorf("inspect secrets directory owner: %w", err)
	}
	if actual := rootInfo.Mode().Perm(); actual != SecretDirectoryMode || rootStat.Uid != expectedUID || rootStat.Gid != expectedGID {
		issues = append(issues, PermissionIssue{RelativePath: ".", ObjectType: "directory", ExpectedMode: SecretDirectoryMode, ActualMode: actual, ExpectedUID: expectedUID, ActualUID: rootStat.Uid, ExpectedGID: expectedGID, ActualGID: rootStat.Gid, Repairable: true})
	}
	kindEntries, err := readDirectoryEntries(rootFD)
	if err != nil {
		return nil, fmt.Errorf("read secrets directory: %w", err)
	}
	for _, kindEntry := range kindEntries {
		kind := kindEntry.Name()
		var stat unix.Stat_t
		if err := unix.Fstatat(rootFD, kind, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, fmt.Errorf("inspect secret kind %s: %w", kind, err)
		}
		mode := statMode(stat)
		if mode&os.ModeSymlink != 0 || !mode.IsDir() || !validSecretKind(kind) {
			issues = append(issues, PermissionIssue{RelativePath: kind, ObjectType: fileType(mode), ExpectedMode: SecretDirectoryMode, ActualMode: mode.Perm(), ExpectedUID: expectedUID, ActualUID: stat.Uid, ExpectedGID: expectedGID, ActualGID: stat.Gid})
			continue
		}
		if actual := mode.Perm(); actual != SecretDirectoryMode || stat.Uid != expectedUID || stat.Gid != expectedGID {
			issues = append(issues, PermissionIssue{RelativePath: kind, ObjectType: "directory", ExpectedMode: SecretDirectoryMode, ActualMode: actual, ExpectedUID: expectedUID, ActualUID: stat.Uid, ExpectedGID: expectedGID, ActualGID: stat.Gid, Repairable: true})
		}
		kindFD, err := unix.Openat(rootFD, kind, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, fmt.Errorf("open secret kind %s: %w", kind, err)
		}
		secretEntries, readErr := readDirectoryEntries(kindFD)
		if readErr != nil {
			_ = unix.Close(kindFD)
			return nil, fmt.Errorf("read secret kind %s: %w", kind, readErr)
		}
		for _, secretEntry := range secretEntries {
			id := secretEntry.Name()
			relative := kind + "/" + id
			var secretStat unix.Stat_t
			if err := unix.Fstatat(kindFD, id, &secretStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				_ = unix.Close(kindFD)
				return nil, fmt.Errorf("inspect secret %s: %w", relative, err)
			}
			secretMode := statMode(secretStat)
			_, referenceErr := model.NewSecretRef(kind, id)
			if secretMode&os.ModeSymlink != 0 || !secretMode.IsRegular() || referenceErr != nil {
				issues = append(issues, PermissionIssue{RelativePath: relative, ObjectType: fileType(secretMode), ExpectedMode: SecretFileMode, ActualMode: secretMode.Perm(), ExpectedUID: expectedUID, ActualUID: secretStat.Uid, ExpectedGID: expectedGID, ActualGID: secretStat.Gid})
				continue
			}
			if actual := secretMode.Perm(); actual != SecretFileMode || secretStat.Uid != expectedUID || secretStat.Gid != expectedGID {
				issues = append(issues, PermissionIssue{RelativePath: relative, ObjectType: "file", ExpectedMode: SecretFileMode, ActualMode: actual, ExpectedUID: expectedUID, ActualUID: secretStat.Uid, ExpectedGID: expectedGID, ActualGID: secretStat.Gid, Repairable: true})
			}
		}
		_ = unix.Close(kindFD)
	}
	sort.Slice(issues, func(left, right int) bool { return issues[left].RelativePath < issues[right].RelativePath })
	return issues, nil
}

func (store *SecretStore) RepairPermissions() ([]PermissionIssue, error) {
	issues, err := store.DiagnosePermissions()
	if err != nil {
		return nil, err
	}
	for _, issue := range issues {
		if !issue.Repairable {
			return issues, fmt.Errorf("%w: %s is %s", ErrUnsafeSecretPath, issue.RelativePath, issue.ObjectType)
		}
	}
	for _, issue := range issues {
		if err := store.repairMode(issue); err != nil {
			return issues, err
		}
	}
	return issues, nil
}

func (store *SecretStore) openRoot(create bool) (int, error) {
	expectedUID, expectedGID, err := stateDirectoryOwner(store.paths.StateDir)
	if err != nil {
		return -1, err
	}
	if create {
		if err := validateStateDirectory(store.paths.StateDir); err != nil {
			return -1, err
		}
		created := false
		if err := os.Mkdir(store.paths.SecretsDir, SecretDirectoryMode); err != nil {
			if !errors.Is(err, os.ErrExist) {
				return -1, fmt.Errorf("create secrets directory: %w", err)
			}
		} else {
			created = true
		}
		if created {
			if err := syncDirectory(store.paths.StateDir); err != nil {
				return -1, err
			}
		}
	}
	info, err := os.Lstat(store.paths.SecretsDir)
	if errors.Is(err, os.ErrNotExist) {
		return -1, fmt.Errorf("%w: secrets directory", ErrSecretNotFound)
	}
	if err != nil {
		return -1, fmt.Errorf("inspect secrets directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return -1, fmt.Errorf("%w: secrets directory is %s", ErrUnsafeSecretPath, fileType(info.Mode()))
	}
	fd, err := openDirectoryNoFollow(store.paths.SecretsDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
			return -1, fmt.Errorf("%w: secrets directory", ErrSecretNotFound)
		}
		return -1, err
	}
	if err := requireFDMode(fd, "secrets directory", unix.S_IFDIR, SecretDirectoryMode, expectedUID, expectedGID); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openKindDirectory(rootFD int, kind string, create bool) (int, error) {
	if !validSecretKind(kind) {
		return -1, fmt.Errorf("invalid secret kind %q", kind)
	}
	if create {
		created := false
		if err := unix.Mkdirat(rootFD, kind, uint32(SecretDirectoryMode)); err != nil {
			if !errors.Is(err, unix.EEXIST) {
				return -1, fmt.Errorf("create secret kind directory: %w", err)
			}
		} else {
			created = true
		}
		if created {
			if err := unix.Fsync(rootFD); err != nil {
				return -1, fmt.Errorf("sync secrets directory: %w", err)
			}
		}
	}
	fd, err := unix.Openat(rootFD, kind, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return -1, fmt.Errorf("%w: secret kind %s", ErrSecretNotFound, kind)
		}
		return -1, fmt.Errorf("%w: open secret kind %s: %v", ErrUnsafeSecretPath, kind, err)
	}
	expectedUID, expectedGID, err := fdOwner(rootFD)
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if err := requireFDMode(fd, "secret kind "+kind, unix.S_IFDIR, SecretDirectoryMode, expectedUID, expectedGID); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func validateSecretEntry(kindFD int, id string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(kindFD, id, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("%w: secret", ErrSecretNotFound)
	}
	if err != nil {
		return fmt.Errorf("inspect secret: %w", err)
	}
	mode := statMode(stat)
	if mode&os.ModeSymlink != 0 || !mode.IsRegular() {
		return fmt.Errorf("%w: secret is %s", ErrUnsafeSecretPath, fileType(mode))
	}
	if mode.Perm() != SecretFileMode {
		return fmt.Errorf("%w: secret mode is %o, want %o", ErrSecretPermissions, mode.Perm(), SecretFileMode)
	}
	expectedUID, expectedGID, err := fdOwner(kindFD)
	if err != nil {
		return err
	}
	if stat.Uid != expectedUID || stat.Gid != expectedGID {
		return fmt.Errorf("%w: secret owner is %d:%d, want %d:%d", ErrSecretPermissions, stat.Uid, stat.Gid, expectedUID, expectedGID)
	}
	return nil
}

func createSecretTemporary(kindFD int) (string, *os.File, error) {
	var entropy [16]byte
	for attempt := 0; attempt < secretTempAttempts; attempt++ {
		if _, err := io.ReadFull(rand.Reader, entropy[:]); err != nil {
			return "", nil, fmt.Errorf("read secret temporary entropy: %w", err)
		}
		name := ".secret-" + hex.EncodeToString(entropy[:]) + ".tmp"
		fd, err := unix.Openat(kindFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(SecretFileMode))
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, fmt.Errorf("create secret temporary file: %w", err)
		}
		if err := unix.Fchmod(fd, uint32(SecretFileMode)); err != nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(kindFD, name, 0)
			return "", nil, fmt.Errorf("set secret temporary mode: %w", err)
		}
		file := os.NewFile(uintptr(fd), "vpnctl-secret-temporary")
		if file == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(kindFD, name, 0)
			return "", nil, fmt.Errorf("open secret temporary file descriptor")
		}
		return name, file, nil
	}
	return "", nil, fmt.Errorf("allocate secret temporary file after %d attempts", secretTempAttempts)
}

func requireFDMode(fd int, label string, expectedType uint32, expectedMode os.FileMode, expectedUID, expectedGID uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if uint32(stat.Mode)&unix.S_IFMT != expectedType {
		return fmt.Errorf("%w: %s has unexpected type", ErrUnsafeSecretPath, label)
	}
	if actual := os.FileMode(stat.Mode).Perm(); actual != expectedMode {
		return fmt.Errorf("%w: %s mode is %o, want %o", ErrSecretPermissions, label, actual, expectedMode)
	}
	if stat.Uid != expectedUID || stat.Gid != expectedGID {
		return fmt.Errorf("%w: %s owner is %d:%d, want %d:%d", ErrSecretPermissions, label, stat.Uid, stat.Gid, expectedUID, expectedGID)
	}
	return nil
}

func openDirectoryNoFollow(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return -1, fmt.Errorf("%w: directory is a symlink", ErrUnsafeSecretPath)
		}
		return -1, err
	}
	return fd, nil
}

func readDirectoryEntries(fd int) ([]os.DirEntry, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "vpnctl-secret-directory")
	if file == nil {
		_ = unix.Close(duplicate)
		return nil, fmt.Errorf("open directory file descriptor")
	}
	defer file.Close()
	return file.ReadDir(-1)
}

func (store *SecretStore) repairMode(issue PermissionIssue) error {
	components := []string{}
	if issue.RelativePath != "." {
		components = strings.Split(issue.RelativePath, "/")
	}
	rootFD, err := openDirectoryNoFollow(store.paths.SecretsDir)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	fd := rootFD
	closeFD := false
	switch len(components) {
	case 0:
	case 1:
		fd, err = unix.Openat(rootFD, components[0], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		closeFD = true
	case 2:
		kindFD, openErr := unix.Openat(rootFD, components[0], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return fmt.Errorf("open permission repair directory: %w", openErr)
		}
		defer unix.Close(kindFD)
		fd, err = unix.Openat(kindFD, components[1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		closeFD = true
	default:
		return fmt.Errorf("%w: invalid repair path", ErrUnsafeSecretPath)
	}
	if err != nil {
		return fmt.Errorf("open permission repair target: %w", err)
	}
	if closeFD {
		defer unix.Close(fd)
	}
	if err := unix.Fchmod(fd, uint32(issue.ExpectedMode)); err != nil {
		return fmt.Errorf("repair permissions for %s: %w", issue.RelativePath, err)
	}
	if err := unix.Fchown(fd, int(issue.ExpectedUID), int(issue.ExpectedGID)); err != nil {
		return fmt.Errorf("repair owner for %s: %w", issue.RelativePath, err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("sync permission repair for %s: %w", issue.RelativePath, err)
	}
	return nil
}

func writeAll(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func validSecretKind(kind string) bool {
	_, err := model.NewSecretRef(kind, "value")
	return err == nil
}

func stateDirectoryOwner(path string) (uint32, uint32, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, 0, fmt.Errorf("inspect state directory owner: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return 0, 0, fmt.Errorf("state directory must be a real directory")
	}
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return 0, 0, fmt.Errorf("inspect state directory owner: %w", err)
	}
	return stat.Uid, stat.Gid, nil
}

func fdOwner(fd int) (uint32, uint32, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return 0, 0, fmt.Errorf("inspect directory owner: %w", err)
	}
	return stat.Uid, stat.Gid, nil
}

func statMode(stat unix.Stat_t) os.FileMode {
	mode := os.FileMode(stat.Mode & 0o777)
	switch uint32(stat.Mode) & unix.S_IFMT {
	case unix.S_IFDIR:
		mode |= os.ModeDir
	case unix.S_IFLNK:
		mode |= os.ModeSymlink
	case unix.S_IFREG:
	default:
		mode |= os.ModeDevice
	}
	return mode
}

func fileType(mode os.FileMode) string {
	switch {
	case mode&os.ModeSymlink != 0:
		return "symlink"
	case mode.IsDir():
		return "directory"
	case mode.IsRegular():
		return "file"
	default:
		return "non-regular"
	}
}
