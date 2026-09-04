package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

var ErrReleaseUpdateConflict = errors.New("release update conflicts with the installed release")

type ReleaseBundleComponentChange struct {
	Name           string
	CurrentVersion string
	TargetVersion  string
	TargetPath     string
	FileChanged    bool
}

type PreparedReleaseBundleUpdate struct {
	mu sync.Mutex

	installer      *ReleaseBundleInstaller
	role           model.Role
	current        *stagedReleaseBundle
	target         *stagedReleaseBundle
	targetRelease  *StagedUpdateRelease
	changes        []ReleaseBundleComponentChange
	currentByName  map[string]releaseInstallCandidate
	targetByName   map[string]releaseInstallCandidate
	activated      map[string]bool
	metadataActive bool
	closed         bool

	currentBundleBackup    string
	currentChecksumsBackup string
	currentSignatureBackup string
}

func (installer *ReleaseBundleInstaller) PrepareUpdate(ctx context.Context, currentBundlePath string, targetRelease *StagedUpdateRelease, role model.Role) (*PreparedReleaseBundleUpdate, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if installer == nil || !targetRelease.valid() || role != model.RoleGateway && role != model.RoleNode {
		return nil, fmt.Errorf("release update preparation is incomplete")
	}
	current, err := installer.stage(ctx, currentBundlePath)
	if err != nil {
		return nil, fmt.Errorf("stage installed release bundle: %w", err)
	}
	keepCurrent := false
	defer func() {
		if !keepCurrent {
			_ = os.RemoveAll(current.root)
		}
	}()
	target, err := installer.stage(ctx, targetRelease.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("stage target release bundle: %w", err)
	}
	keepTarget := false
	defer func() {
		if !keepTarget {
			_ = os.RemoveAll(target.root)
		}
	}()
	if !reflect.DeepEqual(target.manifest, targetRelease.Manifest) {
		return nil, fmt.Errorf("%w: retained target manifest changed after download", ErrReleaseUpdateConflict)
	}
	currentCandidates, err := installer.prepareCandidates(ctx, current, role)
	if err != nil {
		return nil, fmt.Errorf("prepare installed release components: %w", err)
	}
	targetCandidates, err := installer.prepareCandidates(ctx, target, role)
	if err != nil {
		return nil, fmt.Errorf("prepare target release components: %w", err)
	}
	currentByName, err := releaseCandidatesByComponent(current.manifest, currentCandidates, role)
	if err != nil {
		return nil, err
	}
	targetByName, err := releaseCandidatesByComponent(target.manifest, targetCandidates, role)
	if err != nil {
		return nil, err
	}
	if err := preflightInstalledReleaseCandidates(currentByName, targetByName); err != nil {
		return nil, err
	}
	changes, err := releaseBundleChanges(current.manifest, target.manifest, currentByName, targetByName)
	if err != nil {
		return nil, err
	}
	prepared := &PreparedReleaseBundleUpdate{
		installer: installer, role: role, current: current, target: target, targetRelease: targetRelease,
		changes: changes, currentByName: currentByName, targetByName: targetByName, activated: map[string]bool{},
	}
	if err := prepared.backupInstalledMetadata(currentBundlePath); err != nil {
		return nil, err
	}
	keepCurrent, keepTarget = true, true
	return prepared, nil
}

func (prepared *PreparedReleaseBundleUpdate) CurrentManifest() ReleaseManifest {
	if prepared == nil || prepared.current == nil {
		return ReleaseManifest{}
	}
	return cloneReleaseManifest(prepared.current.manifest)
}

func (prepared *PreparedReleaseBundleUpdate) TargetManifest() ReleaseManifest {
	if prepared == nil || prepared.target == nil {
		return ReleaseManifest{}
	}
	return cloneReleaseManifest(prepared.target.manifest)
}

func (prepared *PreparedReleaseBundleUpdate) Changes() []ReleaseBundleComponentChange {
	if prepared == nil {
		return nil
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	return append([]ReleaseBundleComponentChange(nil), prepared.changes...)
}

func (prepared *PreparedReleaseBundleUpdate) ActivateComponent(ctx context.Context, component string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if err := prepared.usableLocked(); err != nil {
		return err
	}
	change, found := prepared.changeLocked(component)
	if !found {
		return fmt.Errorf("%w: component %s is not part of the role update", ErrReleaseUpdateConflict, component)
	}
	if prepared.activated[component] || !change.FileChanged {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := replaceReleaseFile(change.TargetPath, prepared.targetByName[component].source, 0o755); err != nil {
		return fmt.Errorf("activate release component %s: %w", component, err)
	}
	prepared.activated[component] = true
	return nil
}

func (prepared *PreparedReleaseBundleUpdate) RollbackComponent(ctx context.Context, component string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if err := prepared.usableLocked(); err != nil {
		return err
	}
	if !prepared.activated[component] {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, found := prepared.currentByName[component]
	if !found {
		return fmt.Errorf("%w: installed component %s is unavailable", ErrReleaseUpdateConflict, component)
	}
	if err := replaceReleaseFile(current.target, current.source, 0o755); err != nil {
		return fmt.Errorf("rollback release component %s: %w", component, err)
	}
	delete(prepared.activated, component)
	return nil
}

func (prepared *PreparedReleaseBundleUpdate) PublishMetadata(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if err := prepared.usableLocked(); err != nil {
		return err
	}
	if prepared.metadataActive {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	targets := prepared.installedMetadataPaths()
	sources := []string{prepared.targetRelease.BundlePath, prepared.targetRelease.ChecksumsPath, prepared.targetRelease.SignaturePath}
	for index := range targets {
		if err := replaceReleaseFile(targets[index], sources[index], 0o600); err != nil {
			for rollbackIndex := index - 1; rollbackIndex >= 0; rollbackIndex-- {
				_ = replaceReleaseFile(targets[rollbackIndex], prepared.metadataBackups()[rollbackIndex], 0o600)
			}
			return fmt.Errorf("publish release metadata: %w", err)
		}
	}
	prepared.metadataActive = true
	return nil
}

func (prepared *PreparedReleaseBundleUpdate) RollbackMetadata(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if err := prepared.usableLocked(); err != nil {
		return err
	}
	if !prepared.metadataActive {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var rollbackErrors []error
	for index, target := range prepared.installedMetadataPaths() {
		if err := replaceReleaseFile(target, prepared.metadataBackups()[index], 0o600); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if len(rollbackErrors) == 0 {
		prepared.metadataActive = false
	}
	return errors.Join(rollbackErrors...)
}

func (prepared *PreparedReleaseBundleUpdate) Close() error {
	if prepared == nil {
		return nil
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if prepared.closed {
		return nil
	}
	if prepared.metadataActive || len(prepared.activated) != 0 {
		return fmt.Errorf("%w: active update must be committed or rolled back before close", ErrReleaseUpdateConflict)
	}
	prepared.closed = true
	var cleanupErrors []error
	if prepared.current != nil {
		cleanupErrors = append(cleanupErrors, os.RemoveAll(prepared.current.root))
	}
	if prepared.target != nil {
		cleanupErrors = append(cleanupErrors, os.RemoveAll(prepared.target.root))
	}
	return errors.Join(cleanupErrors...)
}

// Commit releases temporary rollback material after the caller has durably
// committed authoritative state and completed every local health check.
func (prepared *PreparedReleaseBundleUpdate) Commit() error {
	if prepared == nil {
		return fmt.Errorf("prepared release update is required")
	}
	prepared.mu.Lock()
	defer prepared.mu.Unlock()
	if err := prepared.usableLocked(); err != nil {
		return err
	}
	prepared.metadataActive = false
	prepared.activated = map[string]bool{}
	prepared.closed = true
	return errors.Join(os.RemoveAll(prepared.current.root), os.RemoveAll(prepared.target.root))
}

func (prepared *PreparedReleaseBundleUpdate) backupInstalledMetadata(currentBundlePath string) error {
	paths := prepared.installedMetadataPaths()
	if currentBundlePath != paths[0] {
		return fmt.Errorf("%w: installed bundle path is not the standard release path", ErrReleaseUpdateConflict)
	}
	backups := []string{
		filepath.Join(prepared.current.root, "installed.bundle"),
		filepath.Join(prepared.current.root, "installed.checksums"),
		filepath.Join(prepared.current.root, "installed.signature"),
	}
	for index, source := range paths {
		if err := copyRegularReleaseFile(source, backups[index], 0o600); err != nil {
			return fmt.Errorf("%w: installed release metadata %s: %v", ErrReleaseUpdateConflict, filepath.Base(source), err)
		}
	}
	prepared.currentBundleBackup, prepared.currentChecksumsBackup, prepared.currentSignatureBackup = backups[0], backups[1], backups[2]
	return nil
}

func (prepared *PreparedReleaseBundleUpdate) installedMetadataPaths() []string {
	return []string{
		filepath.Join(prepared.installer.root, strings.TrimPrefix(ReleaseInstalledBundlePath, "/")),
		filepath.Join(prepared.installer.root, strings.TrimPrefix(ReleaseInstalledChecksumsPath, "/")),
		filepath.Join(prepared.installer.root, strings.TrimPrefix(ReleaseInstalledSignaturePath, "/")),
	}
}

func (prepared *PreparedReleaseBundleUpdate) metadataBackups() []string {
	return []string{prepared.currentBundleBackup, prepared.currentChecksumsBackup, prepared.currentSignatureBackup}
}

func (prepared *PreparedReleaseBundleUpdate) usableLocked() error {
	if prepared.closed || prepared.installer == nil || prepared.current == nil || prepared.target == nil || !prepared.targetRelease.valid() {
		return fmt.Errorf("prepared release update is closed or incomplete")
	}
	return nil
}

func (prepared *PreparedReleaseBundleUpdate) changeLocked(component string) (ReleaseBundleComponentChange, bool) {
	for _, change := range prepared.changes {
		if change.Name == component {
			return change, true
		}
	}
	return ReleaseBundleComponentChange{}, false
}

func releaseCandidatesByComponent(manifest ReleaseManifest, candidates []releaseInstallCandidate, role model.Role) (map[string]releaseInstallCandidate, error) {
	components := make([]string, 0)
	for _, artifact := range manifest.Artifacts {
		if releaseRolesContain(artifact.Roles, role) {
			components = append(components, artifact.Component)
		}
	}
	if len(components) != len(candidates) {
		return nil, fmt.Errorf("%w: role candidate count differs from signed artifacts", ErrReleaseUpdateConflict)
	}
	result := make(map[string]releaseInstallCandidate, len(candidates))
	for index, component := range components {
		if _, duplicate := result[component]; duplicate {
			return nil, fmt.Errorf("%w: duplicate role component %s", ErrReleaseUpdateConflict, component)
		}
		result[component] = candidates[index]
	}
	return result, nil
}

func preflightInstalledReleaseCandidates(current, target map[string]releaseInstallCandidate) error {
	if len(current) != len(target) {
		return fmt.Errorf("%w: target role component set differs from installed release", ErrReleaseUpdateConflict)
	}
	for name, installed := range current {
		candidate, found := target[name]
		if !found || candidate.target != installed.target {
			return fmt.Errorf("%w: target role component set differs at %s", ErrReleaseUpdateConflict, name)
		}
		info, err := os.Lstat(installed.target)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 {
			return fmt.Errorf("%w: installed component %s is not an owned executable", ErrReleaseUpdateConflict, name)
		}
		equal, err := equalReleaseFiles(installed.target, installed.source)
		if err != nil || !equal {
			return fmt.Errorf("%w: installed component %s differs from the installed signed bundle", ErrReleaseUpdateConflict, name)
		}
	}
	return nil
}

func releaseBundleChanges(current, target ReleaseManifest, currentFiles, targetFiles map[string]releaseInstallCandidate) ([]ReleaseBundleComponentChange, error) {
	currentPins := make(map[string]model.ComponentPin, len(current.ComponentManifest.Components))
	for _, component := range current.ComponentManifest.Components {
		currentPins[component.Name] = component
	}
	changes := make([]ReleaseBundleComponentChange, 0, len(targetFiles))
	for name, targetFile := range targetFiles {
		currentPin, found := currentPins[name]
		targetPin, targetFound := componentPinByName(target.ComponentManifest, name)
		currentFile, currentFound := currentFiles[name]
		if !found || !targetFound || !currentFound {
			return nil, fmt.Errorf("%w: role component %s has incomplete manifest metadata", ErrReleaseUpdateConflict, name)
		}
		equal, err := equalReleaseFiles(currentFile.source, targetFile.source)
		if err != nil {
			return nil, err
		}
		changes = append(changes, ReleaseBundleComponentChange{
			Name: name, CurrentVersion: currentPin.Version, TargetVersion: targetPin.Version,
			TargetPath: targetFile.target, FileChanged: !equal,
		})
	}
	sort.Slice(changes, func(left, right int) bool {
		// Data-plane providers are activated before the management binary.
		if changes[left].Name == "vpnctl" {
			return false
		}
		if changes[right].Name == "vpnctl" {
			return true
		}
		return changes[left].Name < changes[right].Name
	})
	return changes, nil
}

func componentPinByName(manifest model.ComponentManifest, name string) (model.ComponentPin, bool) {
	for _, component := range manifest.Components {
		if component.Name == name {
			return component, true
		}
	}
	return model.ComponentPin{}, false
}

func replaceReleaseFile(target, source string, mode fs.FileMode) error {
	info, err := os.Lstat(target)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("target must remain a regular non-symlink file")
	}
	inputInfo, err := os.Lstat(source)
	if err != nil || inputInfo.Mode()&os.ModeSymlink != 0 || !inputInfo.Mode().IsRegular() || inputInfo.Size() <= 0 {
		return fmt.Errorf("source must be a non-empty regular non-symlink file")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".update-*.tmp")
	if err != nil {
		return err
	}
	temporary := output.Name()
	defer os.Remove(temporary)
	if err := output.Chmod(mode); err != nil {
		_ = output.Close()
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	return syncReleaseDirectory(filepath.Dir(target))
}

func copyRegularReleaseFile(source, target string, mode fs.FileMode) error {
	info, err := os.Lstat(source)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 {
		return fmt.Errorf("source must be a non-empty regular non-symlink file")
	}
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("target staging path already exists")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = output.Close()
		if !keep {
			_ = os.Remove(target)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Chmod(mode); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}

func syncReleaseDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
