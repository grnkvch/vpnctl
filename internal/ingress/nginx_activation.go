package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/observability"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"golang.org/x/sys/unix"
)

const (
	NginxActivationLockName     = "ingress-activation.lock"
	NginxGeneratedDirectoryName = "ingress"
	NginxGenerationsDirectory   = "generations"
	NginxCurrentLinkName        = "current"
	NginxBinaryRelativePath     = "usr/sbin/nginx"
	NginxRuntimeRelativePath    = "run/vpnctl-ingress"

	nginxRollbackTimeout = 15 * time.Second
)

var (
	ErrNginxTreeConflict = errors.New("nginx configuration tree conflict")
	ErrNginxTreeDrift    = errors.New("nginx configuration tree drift")
	ErrNginxValidation   = errors.New("nginx configuration validation failed")
	ErrNginxActivation   = errors.New("nginx configuration activation failed")
	ErrNginxReload       = errors.New("nginx graceful reload failed")
	ErrNginxRollback     = errors.New("nginx configuration rollback failed")

	nginxGenerationNamePattern = regexp.MustCompile(`^g([1-9][0-9]*)-([0-9a-f]{64})$`)
)

type NginxReloadRunner interface {
	Reload(context.Context, string, string) error
}

type OSNginxReloadRunner struct{}

func (OSNginxReloadRunner) Reload(ctx context.Context, binaryPath, activeRoot string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath ||
		!filepath.IsAbs(activeRoot) || filepath.Clean(activeRoot) != activeRoot {
		return fmt.Errorf("nginx reload paths must be clean and absolute")
	}
	command := exec.CommandContext(ctx, binaryPath, "-p", activeRoot+string(filepath.Separator), "-c", NginxMainConfigPath, "-s", "reload")
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

type NginxActivationResult struct {
	Changed            bool
	Initial            bool
	Reloaded           bool
	PreviousGeneration uint64
	StateGeneration    uint64
	ConfigHash         string
	ActiveExposeCount  int
}

type NginxActivationManager struct {
	paths    store.Paths
	probe    linuxplatform.ProbeRunner
	reloader NginxReloadRunner
}

func NewNginxActivationManager(paths store.Paths, probe linuxplatform.ProbeRunner, reloader NginxReloadRunner) (*NginxActivationManager, error) {
	if probe == nil || reloader == nil {
		return nil, fmt.Errorf("nginx activation dependencies are incomplete")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil || paths != want {
		return nil, fmt.Errorf("nginx activation paths are invalid")
	}
	return &NginxActivationManager{paths: paths, probe: probe, reloader: reloader}, nil
}

func NginxGeneratedRoot(paths store.Paths) string {
	return filepath.Join(paths.ConfigDir, "generated", "gateway", NginxGeneratedDirectoryName)
}

func NginxActiveRoot(paths store.Paths) string {
	return filepath.Join(NginxGeneratedRoot(paths), NginxCurrentLinkName)
}

func NginxRuntimeDirectory(paths store.Paths) string {
	return filepath.Join(paths.Root, NginxRuntimeRelativePath)
}

func NginxBinaryPath(paths store.Paths) string {
	return filepath.Join(paths.Root, NginxBinaryRelativePath)
}

func (manager *NginxActivationManager) Apply(ctx context.Context, candidate NginxCandidate) (NginxActivationResult, error) {
	result := NginxActivationResult{
		StateGeneration: candidate.StateGeneration(), ConfigHash: candidate.ConfigHash(), ActiveExposeCount: candidate.ActiveExposeCount(),
	}
	if ctx == nil {
		return NginxActivationResult{}, fmt.Errorf("context is required")
	}
	if manager == nil || manager.probe == nil || manager.reloader == nil {
		return NginxActivationResult{}, fmt.Errorf("nginx activation manager is incomplete")
	}
	if err := candidate.Validate(); err != nil {
		return NginxActivationResult{}, fmt.Errorf("validate nginx activation candidate: %w", err)
	}
	if candidate.runtimeDirectory != NginxRuntimeDirectory(manager.paths) {
		return NginxActivationResult{}, fmt.Errorf("nginx candidate runtime directory differs from the owned path")
	}
	if err := ctx.Err(); err != nil {
		return NginxActivationResult{}, err
	}
	if err := ensureNginxActivationDirectories(manager.paths); err != nil {
		return NginxActivationResult{}, err
	}
	lock, err := acquireNginxActivationLock(ctx, manager.paths)
	if err != nil {
		return NginxActivationResult{}, err
	}
	defer releaseNginxActivationLock(lock)

	if err := validateNginxActivationBase(manager.paths); err != nil {
		return NginxActivationResult{}, err
	}
	current, present, err := inspectCurrentNginxTree(manager.paths)
	if err != nil {
		return NginxActivationResult{}, err
	}
	generations, err := inspectNginxGenerationNamespace(manager.paths)
	if err != nil {
		return NginxActivationResult{}, err
	}
	inactive := make([]nginxGeneration, 0, len(generations))
	foundCurrent := !present
	for _, generation := range generations {
		if present && generation == current {
			foundCurrent = true
			continue
		}
		inactive = append(inactive, generation)
	}
	if !foundCurrent {
		return NginxActivationResult{}, fmt.Errorf("%w: active generation is absent from the owned namespace", ErrNginxTreeDrift)
	}
	if len(inactive) != 0 {
		matchesRecovery := len(inactive) == 1 && inactive[0].generation == candidate.StateGeneration() && inactive[0].hash == candidate.ConfigHash() &&
			(!present || candidate.StateGeneration() > current.generation)
		if !matchesRecovery {
			return NginxActivationResult{}, fmt.Errorf("%w: an inactive generation requires explicit reconciliation", ErrNginxTreeConflict)
		}
	}
	if present {
		result.PreviousGeneration = current.generation
		if candidate.StateGeneration() < current.generation ||
			(candidate.StateGeneration() == current.generation && candidate.ConfigHash() != current.hash) {
			return NginxActivationResult{}, fmt.Errorf("%w: candidate generation does not advance the active tree", ErrNginxTreeConflict)
		}
		if candidate.StateGeneration() == current.generation && candidate.ConfigHash() == current.hash {
			return result, nil
		}
	}

	stageRoot, err := stageNginxCandidate(manager.paths, candidate)
	if err != nil {
		return NginxActivationResult{}, err
	}
	defer func() {
		if stageRoot != "" {
			_ = cleanupStagedNginxTree(stageRoot)
		}
	}()
	if err := validateNginxTree(stageRoot, candidate.ConfigHash()); err != nil {
		return NginxActivationResult{}, err
	}
	if err := ValidatePinnedNginxConfig(ctx, manager.probe, NginxBinaryPath(manager.paths), stageRoot); err != nil {
		return NginxActivationResult{}, errors.Join(ErrNginxValidation, err)
	}
	if err := validateNginxTree(stageRoot, candidate.ConfigHash()); err != nil {
		return NginxActivationResult{}, fmt.Errorf("%w: staged tree changed during parser validation", ErrNginxTreeDrift)
	}

	next, reused, err := publishNginxGeneration(manager.paths, stageRoot, candidate.StateGeneration(), candidate.ConfigHash())
	if err != nil {
		return NginxActivationResult{}, err
	}
	stageRoot = ""
	cleanupNext := !reused
	defer func() {
		if cleanupNext {
			_ = removeNginxGeneration(manager.paths, next)
		}
	}()

	oldLink := ""
	if present {
		oldLink = current.link
	}
	if err := replaceNginxCurrentLink(manager.paths, oldLink, next.link); err != nil {
		return NginxActivationResult{}, errors.Join(ErrNginxActivation, err)
	}
	observed, active, inspectErr := inspectCurrentNginxTree(manager.paths)
	if inspectErr != nil || !active || observed != next {
		rollbackErr := replaceNginxCurrentLink(manager.paths, next.link, oldLink)
		if rollbackErr != nil {
			return NginxActivationResult{}, errors.Join(ErrNginxActivation, ErrNginxRollback)
		}
		if inspectErr == nil {
			inspectErr = fmt.Errorf("active nginx generation differs from the published candidate")
		}
		return NginxActivationResult{}, errors.Join(ErrNginxActivation, inspectErr)
	}

	if !present {
		cleanupNext = false
		result.Changed = true
		result.Initial = true
		return result, nil
	}
	if current.hash == next.hash {
		cleanupNext = false
		if err := removeNginxGeneration(manager.paths, current); err != nil {
			return NginxActivationResult{}, fmt.Errorf("finalize nginx provenance activation: %w", err)
		}
		result.Changed = true
		return result, nil
	}

	_ = observability.EmitGenerationSHA256(ctx, observability.IngressReloadStarted, candidate.StateGeneration(), candidate.ConfigHash())
	if err := manager.reloader.Reload(ctx, NginxBinaryPath(manager.paths), NginxActiveRoot(manager.paths)); err != nil {
		rollbackErr := manager.rollback(current, next)
		_ = observability.EmitGenerationSHA256(context.WithoutCancel(ctx), observability.IngressReloadFailed, candidate.StateGeneration(), candidate.ConfigHash())
		if rollbackErr != nil {
			cleanupNext = false
			return NginxActivationResult{}, errors.Join(ErrNginxReload, ErrNginxRollback)
		}
		cleanupNext = false
		return NginxActivationResult{}, ErrNginxReload
	}
	cleanupNext = false
	if err := removeNginxGeneration(manager.paths, current); err != nil {
		_ = observability.EmitGenerationSHA256(context.WithoutCancel(ctx), observability.IngressReloadFailed, candidate.StateGeneration(), candidate.ConfigHash())
		return NginxActivationResult{}, fmt.Errorf("finalize nginx reload: %w", err)
	}
	result.Changed = true
	result.Reloaded = true
	_ = observability.EmitGenerationSHA256(context.WithoutCancel(ctx), observability.IngressReloadCompleted, candidate.StateGeneration(), candidate.ConfigHash())
	return result, nil
}

func (manager *NginxActivationManager) rollback(previous, failed nginxGeneration) error {
	rollbackContext, cancel := context.WithTimeout(context.Background(), nginxRollbackTimeout)
	defer cancel()
	if err := replaceNginxCurrentLink(manager.paths, failed.link, previous.link); err != nil {
		return err
	}
	if err := manager.reloader.Reload(rollbackContext, NginxBinaryPath(manager.paths), NginxActiveRoot(manager.paths)); err != nil {
		return err
	}
	return removeNginxGeneration(manager.paths, failed)
}

type nginxGeneration struct {
	generation uint64
	hash       string
	name       string
	link       string
	root       string
}

func newNginxGeneration(paths store.Paths, generation uint64, hash string) (nginxGeneration, error) {
	name := fmt.Sprintf("g%d-%s", generation, hash)
	parsedGeneration, parsedHash, err := parseNginxGenerationName(name)
	if err != nil || parsedGeneration != generation || parsedHash != hash {
		return nginxGeneration{}, fmt.Errorf("invalid nginx generation identity")
	}
	link := filepath.Join(NginxGenerationsDirectory, name)
	return nginxGeneration{
		generation: generation, hash: hash, name: name, link: link,
		root: filepath.Join(NginxGeneratedRoot(paths), link),
	}, nil
}

func parseNginxGenerationName(name string) (uint64, string, error) {
	match := nginxGenerationNamePattern.FindStringSubmatch(name)
	if match == nil {
		return 0, "", fmt.Errorf("%w: invalid generation directory name", ErrNginxTreeDrift)
	}
	generation, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != match[1] {
		return 0, "", fmt.Errorf("%w: invalid generation number", ErrNginxTreeDrift)
	}
	return generation, match[2], nil
}

func inspectCurrentNginxTree(paths store.Paths) (nginxGeneration, bool, error) {
	currentPath := NginxActiveRoot(paths)
	info, err := os.Lstat(currentPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nginxGeneration{}, false, nil
	}
	if err != nil {
		return nginxGeneration{}, false, fmt.Errorf("inspect active nginx link: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return nginxGeneration{}, false, fmt.Errorf("%w: active path is not a symlink", ErrNginxTreeDrift)
	}
	link, err := os.Readlink(currentPath)
	if err != nil {
		return nginxGeneration{}, false, fmt.Errorf("read active nginx link: %w", err)
	}
	name := filepath.Base(link)
	if filepath.IsAbs(link) || link != filepath.Join(NginxGenerationsDirectory, name) {
		return nginxGeneration{}, false, fmt.Errorf("%w: active link escapes the generations directory", ErrNginxTreeDrift)
	}
	generation, hash, err := parseNginxGenerationName(name)
	if err != nil {
		return nginxGeneration{}, false, err
	}
	value, err := newNginxGeneration(paths, generation, hash)
	if err != nil || value.link != link {
		return nginxGeneration{}, false, fmt.Errorf("%w: active generation identity is invalid", ErrNginxTreeDrift)
	}
	if err := validateNginxTree(value.root, value.hash); err != nil {
		return nginxGeneration{}, false, err
	}
	return value, true, nil
}

func validateNginxActivationBase(paths store.Paths) error {
	entries, err := os.ReadDir(NginxGeneratedRoot(paths))
	if err != nil {
		return fmt.Errorf("inspect nginx activation root: %w", err)
	}
	for _, entry := range entries {
		if entry.Name() != NginxGenerationsDirectory && entry.Name() != NginxCurrentLinkName {
			return fmt.Errorf("%w: unexpected activation-root entry", ErrNginxTreeConflict)
		}
	}
	return nil
}

func inspectNginxGenerationNamespace(paths store.Paths) ([]nginxGeneration, error) {
	directory := filepath.Join(NginxGeneratedRoot(paths), NginxGenerationsDirectory)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect nginx generation namespace: %w", err)
	}
	result := make([]nginxGeneration, 0, len(entries))
	for _, entry := range entries {
		generation, hash, parseErr := parseNginxGenerationName(entry.Name())
		if parseErr != nil {
			return nil, fmt.Errorf("%w: unexpected generation namespace entry", ErrNginxTreeConflict)
		}
		value, identityErr := newNginxGeneration(paths, generation, hash)
		if identityErr != nil {
			return nil, identityErr
		}
		info, statErr := os.Lstat(value.root)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("%w: generation namespace entry is unsafe", ErrNginxTreeDrift)
		}
		if treeErr := validateNginxTree(value.root, value.hash); treeErr != nil {
			return nil, treeErr
		}
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].generation != result[right].generation {
			return result[left].generation < result[right].generation
		}
		return result[left].hash < result[right].hash
	})
	return result, nil
}

func ensureNginxActivationDirectories(paths store.Paths) error {
	if err := validateNginxDirectory(paths.ConfigDir, false, 0); err != nil {
		return fmt.Errorf("validate vpnctl config directory: %w", err)
	}
	if err := validateNginxDirectory(paths.RuntimeDir, true, 0o700); err != nil {
		return fmt.Errorf("validate vpnctl runtime directory: %w", err)
	}
	for _, directory := range []string{
		filepath.Join(paths.ConfigDir, "generated"),
		filepath.Join(paths.ConfigDir, "generated", "gateway"),
		NginxGeneratedRoot(paths),
		filepath.Join(NginxGeneratedRoot(paths), NginxGenerationsDirectory),
	} {
		if err := ensureNginxDirectory(directory, 0o700); err != nil {
			return err
		}
	}
	if err := ensureNginxDirectory(NginxRuntimeDirectory(paths), 0o750); err != nil {
		return err
	}
	return nil
}

func ensureNginxDirectory(path string, mode fs.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create nginx directory %s: %w", path, err)
	}
	return validateNginxDirectory(path, true, mode)
}

func validateNginxDirectory(path string, private bool, exactMode fs.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("nginx path %s must be a real directory", path)
	}
	if private && (info.Mode().Perm()&0o007 != 0 || exactMode != 0 && info.Mode().Perm() != exactMode) {
		return fmt.Errorf("nginx directory %s has unsafe mode %o", path, info.Mode().Perm())
	}
	return nil
}

func acquireNginxActivationLock(ctx context.Context, paths store.Paths) (*os.File, error) {
	lockPath := filepath.Join(paths.RuntimeDir, NginxActivationLockName)
	descriptor, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open nginx activation lock: %w", err)
	}
	lock := os.NewFile(uintptr(descriptor), lockPath)
	if lock == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("open nginx activation lock")
	}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 0 {
		_ = lock.Close()
		return nil, fmt.Errorf("nginx activation lock is unsafe")
	}
	for {
		err = unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return lock, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = lock.Close()
			return nil, fmt.Errorf("lock nginx activation: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = lock.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func releaseNginxActivationLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}

func stageNginxCandidate(paths store.Paths, candidate NginxCandidate) (string, error) {
	generations := filepath.Join(NginxGeneratedRoot(paths), NginxGenerationsDirectory)
	stageRoot, err := os.MkdirTemp(generations, ".stage-")
	if err != nil {
		return "", fmt.Errorf("create staged nginx tree: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = cleanupStagedNginxTree(stageRoot)
		}
	}()
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		return "", err
	}
	confDirectory := filepath.Join(stageRoot, "conf.d")
	if err := os.Mkdir(confDirectory, 0o700); err != nil {
		return "", err
	}
	for _, artifact := range candidate.Artifacts() {
		target := filepath.Join(stageRoot, filepath.FromSlash(artifact.RelativePath()))
		if target != filepath.Join(stageRoot, artifact.RelativePath()) ||
			filepath.Dir(target) != stageRoot && filepath.Dir(target) != confDirectory {
			return "", fmt.Errorf("nginx candidate artifact escapes staged tree")
		}
		if err := writeSyncedNginxArtifact(target, artifact); err != nil {
			return "", err
		}
	}
	for _, directory := range []string{confDirectory, stageRoot, generations} {
		if err := syncNginxDirectory(directory); err != nil {
			return "", err
		}
	}
	keep = true
	return stageRoot, nil
}

func writeSyncedNginxArtifact(path string, artifact NginxArtifact) error {
	descriptor, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(artifact.Mode().Perm()))
	if err != nil {
		return fmt.Errorf("create staged nginx artifact: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return fmt.Errorf("create staged nginx artifact")
	}
	content := artifact.Bytes()
	defer clear(content)
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return nil
}

func validateNginxTree(root, expectedHash string) error {
	artifacts, err := readNginxTree(root)
	if err != nil {
		return err
	}
	if hashNginxArtifacts(artifacts) != expectedHash {
		return fmt.Errorf("%w: generated files differ from the bound hash", ErrNginxTreeDrift)
	}
	return nil
}

func readNginxTree(root string) ([]NginxArtifact, error) {
	if err := validateNginxDirectory(root, true, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNginxTreeDrift, err)
	}
	confDirectory := filepath.Join(root, "conf.d")
	if err := validateNginxDirectory(confDirectory, true, 0o700); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNginxTreeDrift, err)
	}
	if err := validateNginxDirectoryEntries(root, []string{"conf.d", NginxMainConfigPath}); err != nil {
		return nil, err
	}
	if err := validateNginxDirectoryEntries(confDirectory, []string{"proxy-common.conf", "routes.conf"}); err != nil {
		return nil, err
	}
	paths := []string{NginxProxyCommonPath, NginxRoutesConfigPath, NginxMainConfigPath}
	artifacts := make([]NginxArtifact, 0, len(paths))
	total := 0
	for _, relative := range paths {
		path := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 {
			return nil, fmt.Errorf("%w: artifact %s is missing or unsafe", ErrNginxTreeDrift, relative)
		}
		if info.Size() > nginxMaximumTreeBytes || total+int(info.Size()) > nginxMaximumTreeBytes {
			return nil, fmt.Errorf("%w: generated tree exceeds its size bound", ErrNginxTreeDrift)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read nginx artifact %s: %w", relative, err)
		}
		total += len(content)
		artifacts = append(artifacts, NginxArtifact{path: relative, mode: 0o600, content: content})
	}
	return artifacts, nil
}

func validateNginxDirectoryEntries(path string, expected []string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("inspect nginx directory: %w", err)
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	sort.Strings(names)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if strings.Join(names, "\x00") != strings.Join(want, "\x00") {
		return fmt.Errorf("%w: generated tree contains missing or unexpected entries", ErrNginxTreeDrift)
	}
	return nil
}

func publishNginxGeneration(paths store.Paths, stageRoot string, generation uint64, hash string) (nginxGeneration, bool, error) {
	next, err := newNginxGeneration(paths, generation, hash)
	if err != nil {
		return nginxGeneration{}, false, err
	}
	if info, statErr := os.Lstat(next.root); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nginxGeneration{}, false, fmt.Errorf("%w: generation target is unsafe", ErrNginxTreeConflict)
		}
		if err := validateNginxTree(next.root, next.hash); err != nil {
			return nginxGeneration{}, false, err
		}
		if err := cleanupStagedNginxTree(stageRoot); err != nil {
			return nginxGeneration{}, false, err
		}
		return next, true, nil
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return nginxGeneration{}, false, statErr
	}
	if filepath.Dir(stageRoot) != filepath.Dir(next.root) {
		return nginxGeneration{}, false, fmt.Errorf("staged and final nginx trees are on different filesystems")
	}
	if err := os.Rename(stageRoot, next.root); err != nil {
		return nginxGeneration{}, false, fmt.Errorf("publish nginx generation: %w", err)
	}
	if err := syncNginxDirectory(filepath.Dir(next.root)); err != nil {
		cleanupErr := removeNginxGeneration(paths, next)
		return nginxGeneration{}, false, errors.Join(err, cleanupErr)
	}
	return next, false, nil
}

func replaceNginxCurrentLink(paths store.Paths, expected, replacement string) error {
	base := NginxGeneratedRoot(paths)
	currentPath := NginxActiveRoot(paths)
	info, err := os.Lstat(currentPath)
	if expected == "" {
		if err == nil || !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: active link changed during activation", ErrNginxTreeConflict)
		}
	} else {
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%w: active link changed during activation", ErrNginxTreeConflict)
		}
		link, readErr := os.Readlink(currentPath)
		if readErr != nil || link != expected {
			return fmt.Errorf("%w: active link changed during activation", ErrNginxTreeConflict)
		}
	}
	if replacement == "" {
		if err := os.Remove(currentPath); err != nil {
			return err
		}
		return syncNginxDirectory(base)
	}
	name := filepath.Base(replacement)
	if replacement != filepath.Join(NginxGenerationsDirectory, name) {
		return fmt.Errorf("replacement nginx link is unsafe")
	}
	temporary, err := os.CreateTemp(base, ".current-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return err
	}
	defer os.Remove(temporaryPath)
	if err := os.Symlink(replacement, temporaryPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, currentPath); err != nil {
		return err
	}
	return syncNginxDirectory(base)
}

func cleanupStagedNginxTree(root string) error {
	for _, relative := range []string{NginxProxyCommonPath, NginxRoutesConfigPath, NginxMainConfigPath} {
		if err := os.Remove(filepath.Join(root, filepath.FromSlash(relative))); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := os.Remove(filepath.Join(root, "conf.d")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Remove(root); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncNginxDirectory(filepath.Dir(root))
}

func removeNginxGeneration(paths store.Paths, generation nginxGeneration) error {
	want, err := newNginxGeneration(paths, generation.generation, generation.hash)
	if err != nil || want != generation {
		return fmt.Errorf("refuse to remove unbound nginx generation")
	}
	if err := validateNginxTree(generation.root, generation.hash); err != nil {
		return err
	}
	return cleanupStagedNginxTree(generation.root)
}

func syncNginxDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

var _ NginxReloadRunner = OSNginxReloadRunner{}
