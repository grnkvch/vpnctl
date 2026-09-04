package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	v1MigrationSnapshotManifestName = "snapshot.json"
	v1MigrationSnapshotOwnerName    = ".vpnctl-v1-migration-snapshot"
	v1MigrationNetworkMarkerName    = "network-activation.json"
	v1MigrationRecoveryBundleName   = "v2-release.bundle"
	v1MigrationMaximumSnapshotFiles = 4096
	v1MigrationMaximumSnapshotBytes = int64(256 << 20)
)

var v1MigrationWatchdogIDPattern = regexp.MustCompile(`^fw-[0-9A-HJKMNP-TV-Z]{6}$`)

type v1MigrationHandshakeSelector interface {
	Select(context.Context, int, time.Time) (model.HandshakeHost, error)
}

type v1MigrationBundleInstaller interface {
	Inspect(context.Context, string) (ReleaseManifest, error)
	InstallV1Migration(context.Context, string, model.Role, string, string) (ReleaseBundleInstallResult, error)
	PreflightV1MigrationRemoval(context.Context, string, model.Role, string, string) (ReleaseManifest, error)
	RemoveV1MigrationComponents(context.Context, string, model.Role, string, string) (ReleaseManifest, error)
}

type V1MigrationWatchdogTransaction struct {
	ID                   string
	PriorNFTablesPresent bool
}

type V1MigrationWatchdogStatus string

const (
	V1MigrationWatchdogArmed      V1MigrationWatchdogStatus = "armed"
	V1MigrationWatchdogActive     V1MigrationWatchdogStatus = "active"
	V1MigrationWatchdogCommitted  V1MigrationWatchdogStatus = "committed"
	V1MigrationWatchdogRolledBack V1MigrationWatchdogStatus = "rolled_back"
)

// V1MigrationNetworkWatchdog is composed by the standalone migration
// entrypoint so lifecycle does not depend on the sibling operations package.
type V1MigrationNetworkWatchdog interface {
	ArmPrepared(context.Context, int, *linuxplatform.SSHConnection, func(V1MigrationWatchdogTransaction) error) (V1MigrationWatchdogTransaction, error)
	EnsureTimer(context.Context, string) error
	MarkActivated(context.Context, string) error
	Status(context.Context, string) (V1MigrationWatchdogStatus, error)
	Restore(context.Context, string) error
}

// SystemV1MigrationDriver composes the production host adapters used only by
// the standalone one-time migrator. It is intentionally not reachable from
// the permanent vpnctl command registry.
type SystemV1MigrationDriver struct {
	root         string
	paths        store.Paths
	bundles      v1MigrationBundleInstaller
	bundlePath   string
	handshake    v1MigrationHandshakeSelector
	runner       linuxplatform.ProbeRunner
	network      *linuxplatform.NetworkManager
	binaryPath   string
	keyRunner    wireguard.Runner
	entropy      io.Reader
	watchdog     V1MigrationNetworkWatchdog
	recoveryHook func(V1MigrationRecoveryPhase) error
}

func NewSystemV1MigrationDriver(root string, publicKey ed25519.PublicKey, platform ReleasePlatform, binaryPath string, watchdog V1MigrationNetworkWatchdog) (*SystemV1MigrationDriver, error) {
	if watchdog == nil {
		return nil, fmt.Errorf("migration network watchdog is required")
	}
	if binaryPath == "" {
		binaryPath = linuxplatform.DefaultVPNCTLBinaryPath
	}
	paths, err := store.NewPaths(root)
	if err != nil {
		return nil, err
	}
	bundles, err := NewReleaseBundleInstaller(root, publicKey, platform)
	if err != nil {
		return nil, err
	}
	handshake, err := transport.NewBundledHandshakeHostSelector()
	if err != nil {
		return nil, err
	}
	runner := linuxplatform.OSProbeRunner{}
	return &SystemV1MigrationDriver{
		root: root, paths: paths, bundles: bundles, handshake: handshake,
		runner: runner, network: linuxplatform.NewOSNetworkManager(),
		binaryPath: binaryPath, keyRunner: wireguard.ExecRunner{}, entropy: rand.Reader,
		watchdog: watchdog,
	}, nil
}

func (driver *SystemV1MigrationDriver) VerifyBundle(ctx context.Context, bundlePath string) (ReleaseManifest, error) {
	if driver == nil || driver.bundles == nil {
		return ReleaseManifest{}, fmt.Errorf("system v1 migration driver is incomplete")
	}
	manifest, err := driver.bundles.Inspect(ctx, bundlePath)
	if err != nil {
		return ReleaseManifest{}, err
	}
	driver.bundlePath = bundlePath
	return manifest, nil
}

// InstallV1Migration is deliberately narrower than the normal release
// installer: after a verified maintenance snapshot exists it may atomically
// replace only the captured v1 vpnctl binary. New role components and the
// retained signed bundle still use the ordinary no-overwrite ownership rules,
// and the binary is replaced last.
func (installer *ReleaseBundleInstaller) InstallV1Migration(ctx context.Context, bundlePath string, role model.Role, snapshotRoot, binaryPath string) (ReleaseBundleInstallResult, error) {
	if ctx == nil || installer == nil || len(installer.publicKey) != ed25519.PublicKeySize {
		return ReleaseBundleInstallResult{}, fmt.Errorf("v1 migration release installer is incomplete")
	}
	if role != model.RoleGateway {
		return ReleaseBundleInstallResult{}, fmt.Errorf("v1 migration installs only the gateway role")
	}
	if binaryPath == "" {
		binaryPath = linuxplatform.DefaultVPNCTLBinaryPath
	}
	if !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath {
		return ReleaseBundleInstallResult{}, fmt.Errorf("v1 migration binary path must be clean and absolute")
	}
	previousBinary, previousMode, err := loadV1MaintenanceSnapshotFile(snapshotRoot, filepath.ToSlash(filepath.Join("v1-system", strings.TrimPrefix(binaryPath, "/"))))
	if err != nil {
		return ReleaseBundleInstallResult{}, fmt.Errorf("verify captured v1 binary: %w", err)
	}
	if previousMode != 0o755 {
		return ReleaseBundleInstallResult{}, fmt.Errorf("captured v1 binary mode must be 0755")
	}
	defer clear(previousBinary)
	staged, err := installer.stage(ctx, bundlePath)
	if err != nil {
		return ReleaseBundleInstallResult{}, err
	}
	defer os.RemoveAll(staged.root)
	candidates, err := installer.prepareCandidates(ctx, staged, role)
	if err != nil {
		return ReleaseBundleInstallResult{}, err
	}
	physicalBinary := filepath.Join(installer.root, strings.TrimPrefix(binaryPath, "/"))
	var binaryCandidate *releaseInstallCandidate
	nonBinary := make([]releaseInstallCandidate, 0, len(candidates)-1)
	for index := range candidates {
		candidate := candidates[index]
		if candidate.target == physicalBinary {
			copy := candidate
			binaryCandidate = &copy
			continue
		}
		nonBinary = append(nonBinary, candidate)
	}
	if binaryCandidate == nil {
		return ReleaseBundleInstallResult{}, fmt.Errorf("verified release has no vpnctl migration binary")
	}
	if err := preflightReleaseCandidates(nonBinary); err != nil {
		return ReleaseBundleInstallResult{}, err
	}
	if err := preflightV1MigrationBinary(*binaryCandidate, previousBinary, previousMode); err != nil {
		return ReleaseBundleInstallResult{}, err
	}
	retainedBundle := filepath.Join(installer.root, strings.TrimPrefix(ReleaseInstalledBundlePath, "/"))
	bundlePresent, err := preflightV1MigrationRetainedBundle(bundlePath, retainedBundle)
	if err != nil {
		return ReleaseBundleInstallResult{}, err
	}
	createdDirectories, err := installer.ensureTargetDirectories(candidates)
	if err != nil {
		return ReleaseBundleInstallResult{}, err
	}
	releaseDirectories, err := ensureReleaseDirectory(installer.root, filepath.Dir(retainedBundle))
	if err != nil {
		for index := len(createdDirectories) - 1; index >= 0; index-- {
			_ = os.Remove(createdDirectories[index])
		}
		return ReleaseBundleInstallResult{}, err
	}
	createdDirectories = append(createdDirectories, releaseDirectories...)
	changed := make([]string, 0, len(candidates)+1)
	rollbackNew := func() {
		for index := len(changed) - 1; index >= 0; index-- {
			if changed[index] != physicalBinary {
				_ = os.Remove(changed[index])
			}
		}
		for index := len(createdDirectories) - 1; index >= 0; index-- {
			_ = os.Remove(createdDirectories[index])
		}
	}
	for _, candidate := range nonBinary {
		updated, err := installReleaseCandidate(candidate)
		if err != nil {
			rollbackNew()
			return ReleaseBundleInstallResult{}, err
		}
		if updated {
			changed = append(changed, candidate.target)
		}
	}
	if !bundlePresent {
		if err := copyRegularReleaseFile(bundlePath, retainedBundle, 0o600); err != nil {
			rollbackNew()
			return ReleaseBundleInstallResult{}, fmt.Errorf("retain signed migration bundle: %w", err)
		}
		changed = append(changed, retainedBundle)
	}
	updated, err := replaceV1MigrationBinary(*binaryCandidate, previousBinary, previousMode)
	if err != nil {
		rollbackNew()
		return ReleaseBundleInstallResult{}, err
	}
	if updated {
		changed = append(changed, physicalBinary)
	}
	return ReleaseBundleInstallResult{
		Manifest: cloneReleaseManifest(staged.manifest), ChangedFiles: changed,
		RequiredAPTPackages: releaseAPTPackagesForRole(staged.manifest, role),
	}, nil
}

func (installer *ReleaseBundleInstaller) RemoveV1MigrationComponents(ctx context.Context, bundlePath string, role model.Role, snapshotRoot, binaryPath string) (ReleaseManifest, error) {
	manifest, nonBinary, cleanup, err := installer.prepareV1MigrationRemoval(ctx, bundlePath, role, snapshotRoot, binaryPath)
	if err != nil {
		return ReleaseManifest{}, err
	}
	defer cleanup()
	for _, candidate := range nonBinary {
		if _, err := os.Lstat(candidate.target); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return ReleaseManifest{}, err
		}
		equal, err := equalReleaseFiles(candidate.target, candidate.source)
		if err != nil || !equal {
			return ReleaseManifest{}, fmt.Errorf("%w: migration component changed during removal", ErrReleaseInstallConflict)
		}
		if err := os.Remove(candidate.target); err != nil {
			return ReleaseManifest{}, err
		}
		if err := syncLifecycleDirectory(filepath.Dir(candidate.target)); err != nil {
			return ReleaseManifest{}, err
		}
	}
	return manifest, nil
}

// PreflightV1MigrationRemoval verifies the complete signed component set and
// every present target before rollback mutates a service or filesystem path.
func (installer *ReleaseBundleInstaller) PreflightV1MigrationRemoval(ctx context.Context, bundlePath string, role model.Role, snapshotRoot, binaryPath string) (ReleaseManifest, error) {
	manifest, _, cleanup, err := installer.prepareV1MigrationRemoval(ctx, bundlePath, role, snapshotRoot, binaryPath)
	if cleanup != nil {
		defer cleanup()
	}
	return manifest, err
}

func (installer *ReleaseBundleInstaller) prepareV1MigrationRemoval(ctx context.Context, bundlePath string, role model.Role, snapshotRoot, binaryPath string) (ReleaseManifest, []releaseInstallCandidate, func(), error) {
	if ctx == nil || installer == nil || role != model.RoleGateway {
		return ReleaseManifest{}, nil, nil, fmt.Errorf("v1 migration release removal is incomplete")
	}
	if binaryPath == "" {
		binaryPath = linuxplatform.DefaultVPNCTLBinaryPath
	}
	previous, previousMode, err := loadV1MaintenanceSnapshotFile(snapshotRoot, filepath.ToSlash(filepath.Join("v1-system", strings.TrimPrefix(binaryPath, "/"))))
	if err != nil {
		return ReleaseManifest{}, nil, nil, err
	}
	cleanup := func() { clear(previous) }
	staged, err := installer.stage(ctx, bundlePath)
	if err != nil {
		cleanup()
		return ReleaseManifest{}, nil, nil, err
	}
	cleanup = func() {
		clear(previous)
		_ = os.RemoveAll(staged.root)
	}
	candidates, err := installer.prepareCandidates(ctx, staged, role)
	if err != nil {
		cleanup()
		return ReleaseManifest{}, nil, nil, err
	}
	physicalBinary := filepath.Join(installer.root, strings.TrimPrefix(binaryPath, "/"))
	nonBinary := make([]releaseInstallCandidate, 0, len(candidates)-1)
	binaryFound := false
	for _, candidate := range candidates {
		if candidate.target == physicalBinary {
			binaryFound = true
			if err := preflightV1MigrationBinary(candidate, previous, previousMode); err != nil {
				cleanup()
				return ReleaseManifest{}, nil, nil, err
			}
			continue
		}
		nonBinary = append(nonBinary, candidate)
	}
	if !binaryFound {
		cleanup()
		return ReleaseManifest{}, nil, nil, fmt.Errorf("verified release has no vpnctl migration binary")
	}
	if err := preflightReleaseCandidates(nonBinary); err != nil {
		cleanup()
		return ReleaseManifest{}, nil, nil, err
	}
	return cloneReleaseManifest(staged.manifest), nonBinary, cleanup, nil
}

func preflightV1MigrationBinary(candidate releaseInstallCandidate, previous []byte, previousMode os.FileMode) error {
	info, err := os.Lstat(candidate.target)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 {
		return fmt.Errorf("%w: installed vpnctl is not the captured v1 or selected v2 binary", ErrReleaseInstallConflict)
	}
	current, err := os.ReadFile(candidate.target)
	if err != nil {
		return err
	}
	selected, err := os.ReadFile(candidate.source)
	if err != nil {
		return err
	}
	if bytes.Equal(current, selected) || info.Mode().Perm() == previousMode && bytes.Equal(current, previous) {
		return nil
	}
	return fmt.Errorf("%w: installed vpnctl differs from the captured v1 and selected v2 binaries", ErrReleaseInstallConflict)
}

func replaceV1MigrationBinary(candidate releaseInstallCandidate, previous []byte, previousMode os.FileMode) (bool, error) {
	if err := preflightV1MigrationBinary(candidate, previous, previousMode); err != nil {
		return false, err
	}
	equal, err := equalReleaseFiles(candidate.target, candidate.source)
	if err != nil {
		return false, err
	}
	if equal {
		return false, nil
	}
	input, err := os.Open(candidate.source)
	if err != nil {
		return false, err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(filepath.Dir(candidate.target), ".vpnctl-v1-migration-*.tmp")
	if err != nil {
		return false, err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o755); err != nil {
		return false, err
	}
	if _, err := io.Copy(temporary, input); err != nil {
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, candidate.target); err != nil {
		return false, err
	}
	keep = true
	if err := syncLifecycleDirectory(filepath.Dir(candidate.target)); err != nil {
		return false, err
	}
	return true, nil
}

func preflightV1MigrationRetainedBundle(source, target string) (bool, error) {
	info, err := os.Lstat(target)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false, fmt.Errorf("%w: retained migration bundle target is unsafe", ErrReleaseInstallConflict)
	}
	equal, compareErr := equalReleaseFiles(source, target)
	if compareErr != nil || !equal {
		return false, fmt.Errorf("%w: retained migration bundle differs", ErrReleaseInstallConflict)
	}
	return true, nil
}

func loadV1MaintenanceSnapshotFile(root, logicalPath string) ([]byte, os.FileMode, error) {
	if _, err := loadAndVerifyV1MaintenanceSnapshot(root); err != nil {
		return nil, 0, err
	}
	manifestData, _, err := readV1RegularFile(context.Background(), filepath.Join(root, v1MigrationSnapshotManifestName), 64<<10)
	if err != nil {
		return nil, 0, err
	}
	var manifest v1MaintenanceSnapshotManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, 0, err
	}
	for _, entry := range manifest.Entries {
		if entry.Path != logicalPath {
			continue
		}
		data, _, err := readV1RegularFile(context.Background(), filepath.Join(root, filepath.FromSlash(logicalPath)), v1MigrationMaximumSnapshotBytes)
		return data, os.FileMode(entry.Mode), err
	}
	return nil, 0, fmt.Errorf("%w: maintenance snapshot omits %s", ErrV1MigrationConflict, logicalPath)
}

func (driver *SystemV1MigrationDriver) SelectHandshakeHost(ctx context.Context, manifest ReleaseManifest, selectedAt time.Time) (model.HandshakeHost, error) {
	if driver == nil || driver.handshake == nil {
		return model.HandshakeHost{}, fmt.Errorf("system v1 migration driver is incomplete")
	}
	return driver.handshake.Select(ctx, manifest.ComponentManifest.HandshakeHostListVersion, selectedAt)
}

func (driver *SystemV1MigrationDriver) CreateMaintenanceSnapshot(ctx context.Context, root string, inspection *V1Inspection) (V1MaintenanceSnapshot, error) {
	if ctx == nil || driver == nil || driver.runner == nil || inspection == nil || inspection.destroyed || inspection.state.Server == nil {
		return V1MaintenanceSnapshot{}, fmt.Errorf("maintenance snapshot input is incomplete")
	}
	if existing, err := loadAndVerifyV1MaintenanceSnapshot(root); err == nil {
		if err := driver.retainVerifiedV1MigrationBundle(root); err != nil {
			return V1MaintenanceSnapshot{}, err
		}
		return existing, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return V1MaintenanceSnapshot{}, err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
		return V1MaintenanceSnapshot{}, fmt.Errorf("maintenance snapshot root must be a clean absolute non-root path")
	}
	temporary := root + ".incomplete"
	if err := removeIncompleteV1MigrationDirectory(temporary); err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	if err := os.Mkdir(temporary, 0o700); err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := writeV1StageFile(filepath.Join(temporary, v1MigrationSnapshotOwnerName), []byte("vpnctl-v1-maintenance-snapshot-v1\n"), 0o600); err != nil {
		return V1MaintenanceSnapshot{}, err
	}

	unit, err := inspectV1MigrationWireGuardUnit(ctx, driver.runner, inspection.state.Server.WireGuardInterface)
	if err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	entries, err := collectV1MaintenanceFiles(ctx, inspection, driver.binaryPath)
	if err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	digest := sha256.New()
	var bytesTotal int64
	snapshotEntries := make([]v1MaintenanceSnapshotEntry, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return V1MaintenanceSnapshot{}, err
		}
		target := filepath.Join(temporary, filepath.FromSlash(entry.relative))
		if err := ensureV1MigrationPrivateDirectory(temporary, filepath.Dir(target)); err != nil {
			return V1MaintenanceSnapshot{}, err
		}
		if err := writeV1StageFile(target, entry.content, 0o600); err != nil {
			return V1MaintenanceSnapshot{}, err
		}
		_, _ = fmt.Fprintf(digest, "%d:%s:%d:%o:", len(entry.relative), entry.relative, len(entry.content), entry.mode)
		_, _ = digest.Write(entry.content)
		bytesTotal += int64(len(entry.content))
		contentHash := sha256.Sum256(entry.content)
		snapshotEntries = append(snapshotEntries, v1MaintenanceSnapshotEntry{
			Path: entry.relative, Mode: uint32(entry.mode.Perm()), Bytes: int64(len(entry.content)),
			SHA256: hex.EncodeToString(contentHash[:]),
		})
	}
	writeV1MigrationUnitDigest(digest, unit)
	result := V1MaintenanceSnapshot{
		SchemaVersion: V1MigrationSchemaVersion, Files: len(entries), Bytes: bytesTotal,
		LogicalRoots: []string{"v1-system", "v1-workspace"}, SHA256: hex.EncodeToString(digest.Sum(nil)),
		WireGuardUnit: unit,
	}
	manifest, err := json.MarshalIndent(v1MaintenanceSnapshotManifest{Summary: result, Entries: snapshotEntries}, "", "  ")
	if err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	if err := writeV1StageFile(filepath.Join(temporary, v1MigrationSnapshotManifestName), append(manifest, '\n'), 0o600); err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	if err := syncLifecycleDirectory(temporary); err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	if err := os.Rename(temporary, root); err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	keep = true
	if err := syncLifecycleDirectory(filepath.Dir(root)); err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	verified, err := loadAndVerifyV1MaintenanceSnapshot(root)
	if err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	if err := driver.retainVerifiedV1MigrationBundle(root); err != nil {
		return V1MaintenanceSnapshot{}, err
	}
	return verified, nil
}

func (driver *SystemV1MigrationDriver) retainVerifiedV1MigrationBundle(snapshotRoot string) error {
	if driver == nil || driver.bundlePath == "" {
		return nil
	}
	target := filepath.Join(filepath.Dir(snapshotRoot), v1MigrationRecoveryBundleName)
	return retainV1MigrationBundleForRecovery(driver.bundlePath, target)
}

func (driver *SystemV1MigrationDriver) EnsureConvertedStage(ctx context.Context, input V1ConversionInput) (V1ConversionResult, error) {
	if driver != nil && driver.bundlePath != "" {
		if err := retainV1MigrationBundleForRecovery(driver.bundlePath, filepath.Join(filepath.Dir(input.StageRoot), v1MigrationRecoveryBundleName)); err != nil {
			return V1ConversionResult{}, err
		}
	}
	if _, err := os.Lstat(input.StageRoot); errors.Is(err, fs.ErrNotExist) {
		return ConvertV1ToV2Stage(ctx, input)
	} else if err != nil {
		return V1ConversionResult{}, err
	}
	plan, err := buildV1ConversionPlan(input)
	if err != nil {
		return V1ConversionResult{}, err
	}
	paths, err := store.NewPaths(input.StageRoot)
	if err != nil {
		return V1ConversionResult{}, err
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return V1ConversionResult{}, err
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return V1ConversionResult{}, err
	}
	if err := verifyV1ConversionStage(ctx, paths, stateStore, secrets, plan); err != nil {
		return V1ConversionResult{}, fmt.Errorf("%w: existing conversion stage is incomplete or changed: %v", ErrV1MigrationConflict, err)
	}
	return plan.result, nil
}

func retainV1MigrationBundleForRecovery(source, target string) error {
	if present, err := preflightV1MigrationRetainedBundle(source, target); err != nil {
		return err
	} else if present {
		return nil
	}
	if err := copyRegularReleaseFile(source, target, 0o600); err != nil {
		return fmt.Errorf("retain verified recovery bundle: %w", err)
	}
	return syncLifecycleDirectory(filepath.Dir(target))
}

func (driver *SystemV1MigrationDriver) SetupGatewayRole(ctx context.Context, stageRoot string, manifest ReleaseManifest, inspection *V1Inspection) error {
	if ctx == nil || driver == nil || driver.bundles == nil || driver.runner == nil || driver.network == nil || driver.keyRunner == nil || driver.entropy == nil || driver.bundlePath == "" || inspection == nil || inspection.destroyed || inspection.state.Server == nil {
		return fmt.Errorf("system v1 migration driver is incomplete")
	}
	if err := driver.quiesceV1WireGuard(ctx, inspection.state.Server.WireGuardInterface); err != nil {
		return err
	}
	roleRequest, err := driver.prepareGatewayStage(ctx, stageRoot, manifest)
	if err != nil {
		return err
	}
	installed, err := driver.bundles.InstallV1Migration(
		ctx, driver.bundlePath, model.RoleGateway,
		filepath.Join(filepath.Dir(stageRoot), v1MigrationSnapshotName), driver.binaryPath,
	)
	if err != nil {
		return fmt.Errorf("install verified gateway bundle: %w", err)
	}
	if !reflect.DeepEqual(installed.Manifest, manifest) {
		return fmt.Errorf("installed bundle differs from the verified migration plan")
	}
	if err := publishV1MigrationStage(stageRoot, driver.paths); err != nil {
		return err
	}
	watchdogUnits, err := linuxplatform.NewWatchdogUnitInstaller(driver.root, driver.runner)
	if err != nil {
		return err
	}
	unitPlan, err := watchdogUnits.Plan(driver.binaryPath)
	if err != nil {
		return err
	}
	if _, err := watchdogUnits.Apply(ctx, unitPlan); err != nil {
		return fmt.Errorf("install migration watchdog units: %w", err)
	}
	roles, err := linuxplatform.NewRoleSystemdInstaller(driver.root, driver.paths.ConfigDir, driver.runner)
	if err != nil {
		return err
	}
	if _, err := roles.Apply(ctx, roleRequest); err != nil {
		return fmt.Errorf("install migrated gateway units: %w", err)
	}
	return nil
}

func (driver *SystemV1MigrationDriver) quiesceV1WireGuard(ctx context.Context, interfaceName string) error {
	if !v1InterfacePattern.MatchString(interfaceName) {
		return fmt.Errorf("%w: v1 WireGuard interface is invalid", ErrV1MigrationConflict)
	}
	unit := "wg-quick@" + interfaceName + ".service"
	for _, action := range []string{"stop", "disable"} {
		result, err := driver.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{action, unit}})
		if err != nil {
			return err
		}
		if result.ExitCode != 0 {
			return fmt.Errorf("systemctl %s %s failed with exit code %d", action, unit, result.ExitCode)
		}
	}
	return nil
}

func inspectV1MigrationWireGuardUnit(ctx context.Context, runner linuxplatform.ProbeRunner, interfaceName string) (V1MigrationUnitSnapshot, error) {
	if ctx == nil || runner == nil || !v1InterfacePattern.MatchString(interfaceName) {
		return V1MigrationUnitSnapshot{}, fmt.Errorf("inspect v1 WireGuard unit input is incomplete")
	}
	unit := "wg-quick@" + interfaceName + ".service"
	enabledResult, err := runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"is-enabled", unit}})
	if err != nil {
		return V1MigrationUnitSnapshot{}, err
	}
	enabledText := strings.TrimSpace(string(enabledResult.Stdout))
	enabled := enabledResult.ExitCode == 0 && enabledText == "enabled"
	if !enabled && !(enabledResult.ExitCode != 0 && enabledText == "disabled") {
		return V1MigrationUnitSnapshot{}, fmt.Errorf("v1 WireGuard unit enabled state is not recognizable")
	}
	activeResult, err := runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"is-active", unit}})
	if err != nil {
		return V1MigrationUnitSnapshot{}, err
	}
	activeText := strings.TrimSpace(string(activeResult.Stdout))
	active := activeResult.ExitCode == 0 && activeText == "active"
	if !active && !(activeResult.ExitCode != 0 && activeText == "inactive") {
		return V1MigrationUnitSnapshot{}, fmt.Errorf("v1 WireGuard unit active state is not recognizable")
	}
	return V1MigrationUnitSnapshot{Name: unit, Enabled: enabled, Active: active}, nil
}

func writeV1MigrationUnitDigest(writer io.Writer, unit V1MigrationUnitSnapshot) {
	_, _ = fmt.Fprintf(writer, "unit:%d:%s:%t:%t", len(unit.Name), unit.Name, unit.Enabled, unit.Active)
}

func (driver *SystemV1MigrationDriver) prepareGatewayStage(ctx context.Context, stageRoot string, manifest ReleaseManifest) (linuxplatform.RoleInstallationRequest, error) {
	paths, err := store.NewPaths(stageRoot)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	state, err := stateStore.Load()
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	if state.Host.Role != model.RoleGateway || !reflect.DeepEqual(state.Components, manifest.ComponentManifest) {
		return linuxplatform.RoleInstallationRequest{}, fmt.Errorf("%w: converted stage does not match verified gateway release", ErrV1MigrationConflict)
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	if len(state.Certificates) == 0 && state.EnrollmentIdentity == nil {
		if state.Generation != 1 {
			return linuxplatform.RoleInstallationRequest{}, fmt.Errorf("%w: unprovisioned conversion stage has unexpected generation", ErrV1MigrationConflict)
		}
		if err := clearIncompleteV1MigrationIdentity(secrets); err != nil {
			return linuxplatform.RoleInstallationRequest{}, err
		}
		identityProvisioner, err := control.NewGatewayIdentityProvisioner(secrets, control.GatewayIdentityRuntime{Entropy: driver.entropy})
		if err != nil {
			return linuxplatform.RoleInstallationRequest{}, err
		}
		identity, err := identityProvisioner.Provision(ctx, control.GatewayIdentityRequest{
			GatewayID: state.Host.ID, NodeCIDR: state.Host.NodeCIDR, Initialized: state.Host.InitializedAt,
		})
		if err != nil {
			return linuxplatform.RoleInstallationRequest{}, err
		}
		certificateProvisioner, err := ingress.NewPublicCertificateProvisioner(secrets, ingress.PublicCertificateRuntime{Entropy: driver.entropy})
		if err != nil {
			_ = identityProvisioner.Rollback(context.Background(), identity)
			return linuxplatform.RoleInstallationRequest{}, err
		}
		publicCertificate, err := certificateProvisioner.Provision(ctx, ingress.PublicCertificateRequest{
			GatewayID: state.Host.ID, PublicIPv4: state.Host.PublicIPv4, IssuedAt: state.Host.InitializedAt,
		})
		if err != nil {
			return linuxplatform.RoleInstallationRequest{}, errors.Join(err, identityProvisioner.Rollback(context.Background(), identity))
		}
		candidate := state
		candidate.Generation++
		candidate.Certificates = append([]model.Certificate(nil), identity.Certificates...)
		candidate.Certificates = append(candidate.Certificates, publicCertificate.Certificate)
		enrollment := identity.EnrollmentIdentity
		candidate.EnrollmentIdentity = &enrollment
		if err := candidate.Validate(); err != nil {
			return linuxplatform.RoleInstallationRequest{}, errors.Join(
				err,
				certificateProvisioner.Rollback(context.Background(), publicCertificate),
				identityProvisioner.Rollback(context.Background(), identity),
			)
		}
		if saveErr := stateStore.Save(state.Generation, candidate); saveErr != nil {
			loaded, loadErr := stateStore.Load()
			if loadErr != nil || !reflect.DeepEqual(loaded, candidate) {
				return linuxplatform.RoleInstallationRequest{}, errors.Join(
					saveErr, loadErr,
					certificateProvisioner.Rollback(context.Background(), publicCertificate),
					identityProvisioner.Rollback(context.Background(), identity),
				)
			}
		}
		state = candidate
	} else if state.Generation != 2 || len(state.Certificates) != 3 || state.EnrollmentIdentity == nil {
		return linuxplatform.RoleInstallationRequest{}, fmt.Errorf("%w: converted stage identity publication is partial", ErrV1MigrationConflict)
	}
	if err := ensureV1MigrationStageLayout(paths); err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	listeners, err := transport.NewGatewayListenerProvisioner(secrets, driver.keyRunner, driver.entropy)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	listenerFiles, err := listeners.Provision(ctx, state)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	dns, err := routing.RenderGatewayDNSConfig(state)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	request, err := linuxplatform.RenderGatewayRoleInstallation(driver.binaryPath)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	request.Configs = append(request.Configs,
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSConfigFileName, Content: dns.Bytes()},
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSReadyFileName, Content: []byte("schema_version=1\n")},
	)
	for _, file := range listenerFiles.ConfigFiles() {
		request.Configs = append(request.Configs, linuxplatform.RoleConfigFile{Name: file.Name, Content: file.Content})
	}
	generated := filepath.Join(paths.ConfigDir, "generated", string(model.RoleGateway))
	for _, config := range request.Configs {
		if err := writeV1MigrationExactFile(filepath.Join(generated, config.Name), config.Content, 0o600); err != nil {
			return linuxplatform.RoleInstallationRequest{}, err
		}
	}
	return request, nil
}

func clearIncompleteV1MigrationIdentity(secrets *store.SecretStore) error {
	references := []model.SecretRef{
		model.SecretRef(control.ControlCACertificateRef), control.ControlCAPrivateKeyRef,
		model.SecretRef(control.GatewayControlCertificateRef), control.GatewayControlPrivateKeyRef,
		model.SecretRef(control.EnrollmentPublicKeyRef), control.EnrollmentPrivateKeyRef,
		model.SecretRef(ingress.PublicCertificateRef), ingress.PublicCertificatePrivateKeyRef,
	}
	var result error
	for _, reference := range references {
		_, err := secrets.Delete(reference)
		result = errors.Join(result, err)
	}
	return result
}

func ensureV1MigrationStageLayout(paths store.Paths) error {
	directories := []struct {
		path string
		mode os.FileMode
	}{
		{paths.SecretsDir, 0o700}, {paths.BackupsDir, 0o700}, {paths.SnapshotsDir, 0o700},
		{paths.OperationsDir, 0o700}, {paths.WatchdogDir, 0o700},
		{filepath.Join(paths.ConfigDir, "generated"), 0o700},
		{filepath.Join(paths.ConfigDir, "generated", string(model.RoleGateway)), 0o700},
		{filepath.Join(paths.Root, "run"), 0o755}, {paths.RuntimeDir, 0o700},
	}
	for _, directory := range directories {
		if err := ensureV1MigrationOwnedDirectory(paths.Root, directory.path, directory.mode); err != nil {
			return err
		}
	}
	return nil
}

func ensureV1MigrationOwnedDirectory(root, path string, mode os.FileMode) error {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("migration-owned directory escapes its root")
	}
	current := root
	parts := strings.Split(relative, string(filepath.Separator))
	for index, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		wanted := os.FileMode(0o755)
		if index == len(parts)-1 {
			wanted = mode
		}
		if err := os.Mkdir(current, wanted); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("migration-owned directory %s is unsafe", current)
		}
		if current == path && info.Mode().Perm() != wanted {
			return fmt.Errorf("migration-owned directory %s has unexpected mode", current)
		}
	}
	return nil
}

func writeV1MigrationExactFile(path string, content []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
			return fmt.Errorf("%w: migration file %s is unsafe", ErrV1MigrationConflict, path)
		}
		existing, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(existing, content) {
			return fmt.Errorf("%w: migration file %s differs", ErrV1MigrationConflict, path)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".migration-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	keep = true
	return syncLifecycleDirectory(filepath.Dir(path))
}

func publishV1MigrationStage(stageRoot string, paths store.Paths) error {
	for _, parent := range []string{
		filepath.Join(paths.Root, "etc"), filepath.Join(paths.Root, "var"),
		filepath.Join(paths.Root, "var", "lib"), filepath.Join(paths.Root, "run"),
	} {
		if err := ensureV1MigrationOwnedDirectory(paths.Root, parent, 0o755); err != nil {
			return err
		}
	}
	for _, tree := range []struct{ source, target string }{
		{filepath.Join(stageRoot, "etc", "vpnctl"), paths.ConfigDir},
		{filepath.Join(stageRoot, "var", "lib", "vpnctl"), paths.StateDir},
	} {
		if err := publishV1MigrationTree(tree.source, tree.target); err != nil {
			return err
		}
	}
	if err := ensureV1MigrationOwnedDirectory(paths.Root, paths.RuntimeDir, 0o700); err != nil {
		return err
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return err
	}
	state, err := stateStore.Load()
	if err != nil || state.Host.Role != model.RoleGateway || state.Generation != 2 {
		return fmt.Errorf("published migrated gateway state did not validate")
	}
	return nil
}

func publishV1MigrationTree(sourceRoot, targetRoot string) error {
	sourceInfo, err := os.Lstat(sourceRoot)
	if err != nil || sourceInfo.Mode()&os.ModeSymlink != 0 || !sourceInfo.IsDir() {
		return fmt.Errorf("migration stage tree is unsafe")
	}
	return filepath.WalkDir(sourceRoot, func(source string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("migration stage contains an unsafe entry")
		}
		relative, err := filepath.Rel(sourceRoot, source)
		if err != nil {
			return err
		}
		target := filepath.Join(targetRoot, relative)
		if info.IsDir() {
			if err := os.Mkdir(target, info.Mode().Perm()); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
			targetInfo, err := os.Lstat(target)
			if err != nil || targetInfo.Mode()&os.ModeSymlink != 0 || !targetInfo.IsDir() || targetInfo.Mode().Perm() != info.Mode().Perm() {
				return fmt.Errorf("%w: migration publish directory %s conflicts", ErrV1MigrationConflict, target)
			}
			return nil
		}
		content, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		return writeV1MigrationExactFile(target, content, info.Mode().Perm())
	})
}

type v1MigrationNetworkMarker struct {
	SchemaVersion int    `json:"schema_version"`
	TransactionID string `json:"transaction_id"`
}

func loadV1MigrationNetworkMarker(path string) (v1MigrationNetworkMarker, error) {
	data, metadata, err := readV1RegularFile(context.Background(), path, 4096)
	if err != nil {
		return v1MigrationNetworkMarker{}, err
	}
	if metadata.Mode.Perm() != 0o600 {
		return v1MigrationNetworkMarker{}, fmt.Errorf("%w: network activation marker has unsafe mode", ErrV1MigrationConflict)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var marker v1MigrationNetworkMarker
	if err := decoder.Decode(&marker); err != nil || marker.SchemaVersion != 1 || !v1MigrationWatchdogIDPattern.MatchString(marker.TransactionID) {
		return v1MigrationNetworkMarker{}, fmt.Errorf("%w: network activation marker is invalid", ErrV1MigrationConflict)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return v1MigrationNetworkMarker{}, fmt.Errorf("%w: network activation marker has trailing data", ErrV1MigrationConflict)
	}
	return marker, nil
}

func writeV1MigrationNetworkMarker(path string, marker v1MigrationNetworkMarker) error {
	if marker.SchemaVersion != 1 || !v1MigrationWatchdogIDPattern.MatchString(marker.TransactionID) {
		return fmt.Errorf("invalid network activation marker")
	}
	encoded, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	return writeV1MigrationExactFile(path, append(encoded, '\n'), 0o600)
}

func (driver *SystemV1MigrationDriver) ActivateGatewayNetwork(ctx context.Context, stageRoot string, sshPort int, rawSSHConnection string) (string, error) {
	if ctx == nil || driver == nil || driver.network == nil || driver.watchdog == nil {
		return "", fmt.Errorf("system v1 migration driver is incomplete")
	}
	markerPath := filepath.Join(filepath.Dir(stageRoot), v1MigrationNetworkMarkerName)
	marker, err := loadV1MigrationNetworkMarker(markerPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if marker.TransactionID == "" {
		var origin *linuxplatform.SSHConnection
		if strings.TrimSpace(rawSSHConnection) != "" {
			parsed, err := linuxplatform.ParseSSHConnection(rawSSHConnection)
			if err != nil {
				return "", fmt.Errorf("parse migration SSH connection: %w", err)
			}
			origin = &parsed
		}
		transaction, err := driver.watchdog.ArmPrepared(ctx, sshPort, origin, func(transaction V1MigrationWatchdogTransaction) error {
			if transaction.PriorNFTablesPresent {
				return fmt.Errorf("%w: inet/vpnctl existed before migration activation", ErrV1MigrationConflict)
			}
			marker = v1MigrationNetworkMarker{SchemaVersion: 1, TransactionID: transaction.ID}
			return writeV1MigrationNetworkMarker(markerPath, marker)
		})
		if err != nil {
			return "", err
		}
		marker.TransactionID = transaction.ID
	}
	status, err := driver.watchdog.Status(ctx, marker.TransactionID)
	if err != nil {
		return "", err
	}
	switch status {
	case V1MigrationWatchdogCommitted, V1MigrationWatchdogActive:
		return marker.TransactionID, nil
	case V1MigrationWatchdogRolledBack:
		return "", ErrV1MigrationRolledBack
	case V1MigrationWatchdogArmed:
		// Starting an already-active systemd timer is idempotent. Repeating it
		// closes the crash window after the migration marker was persisted but
		// before ArmWithPreparedHook returned from its first systemctl call.
		if err := driver.watchdog.EnsureTimer(ctx, marker.TransactionID); err != nil {
			return "", err
		}
		stateStore, err := store.NewStateStore(driver.paths)
		if err != nil {
			return "", err
		}
		state, err := stateStore.Load()
		if err != nil {
			return "", err
		}
		firewall, err := RenderGatewayIdentityFirewall(state, GatewayIdentityFirewallServices{
			ClientTCPPorts: []int{routing.GatewayDNSPort}, ClientUDPPorts: []int{routing.GatewayDNSPort},
			NodeTCPPorts: []int{routing.GatewayDNSPort, control.RPCControlTCPPort, tunnel.FRPServerPort},
			NodeUDPPorts: []int{routing.GatewayDNSPort},
		})
		if err != nil {
			return "", err
		}
		if err := driver.network.ActivateGatewayReplacingOwned(ctx, firewall); err != nil {
			return "", err
		}
		if err := driver.watchdog.MarkActivated(ctx, marker.TransactionID); err != nil {
			return "", err
		}
		return marker.TransactionID, nil
	default:
		return "", fmt.Errorf("unknown watchdog state %q", status)
	}
}

func (driver *SystemV1MigrationDriver) GatewayNetworkStatus(ctx context.Context, transactionID string) (V1MigrationNetworkStatus, error) {
	if driver == nil || driver.watchdog == nil {
		return "", fmt.Errorf("system v1 migration driver is incomplete")
	}
	status, err := driver.watchdog.Status(ctx, transactionID)
	if err != nil {
		return "", err
	}
	switch status {
	case V1MigrationWatchdogArmed, V1MigrationWatchdogActive:
		return V1MigrationNetworkPending, nil
	case V1MigrationWatchdogCommitted:
		return V1MigrationNetworkCommitted, nil
	case V1MigrationWatchdogRolledBack:
		return V1MigrationNetworkRolledBack, nil
	default:
		return "", fmt.Errorf("unknown watchdog state %q", status)
	}
}

func (driver *SystemV1MigrationDriver) TranslateKnownUFW(ctx context.Context, inspection *V1Inspection) error {
	if ctx == nil || driver == nil || driver.runner == nil || inspection == nil || inspection.destroyed {
		return fmt.Errorf("UFW migration input is incomplete")
	}
	if inspection.Report.UFW.Enabled == nil {
		return fmt.Errorf("%w: original UFW enabled state is unknown", ErrV1MigrationConflict)
	}
	freshInspector, err := NewV1InstallationInspector(inspection.workspaceRoot, driver.root)
	if err != nil {
		return err
	}
	fresh, err := freshInspector.Inspect(ctx)
	if err != nil {
		return err
	}
	defer fresh.Destroy()
	if fresh.Report.UFW.ConfigPresent != inspection.Report.UFW.ConfigPresent || !reflect.DeepEqual(fresh.Report.UFW.Rules, inspection.Report.UFW.Rules) {
		return fmt.Errorf("%w: UFW rules changed after migration preflight", ErrV1MigrationConflict)
	}
	if fresh.Report.UFW.Enabled == nil {
		return fmt.Errorf("%w: current UFW enabled state is unknown", ErrV1MigrationConflict)
	}
	if !*inspection.Report.UFW.Enabled || !*fresh.Report.UFW.Enabled {
		return nil
	}
	result, err := driver.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "ufw", Args: []string{"--force", "disable"}})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("ufw --force disable failed with exit code %d", result.ExitCode)
	}
	verified, err := freshInspector.Inspect(ctx)
	if err != nil {
		return fmt.Errorf("verify UFW disable: %w", err)
	}
	defer verified.Destroy()
	if verified.Report.UFW.Enabled == nil || *verified.Report.UFW.Enabled {
		return fmt.Errorf("%w: UFW remained enabled after disable", ErrV1MigrationConflict)
	}
	if verified.Report.UFW.ConfigPresent != inspection.Report.UFW.ConfigPresent || !reflect.DeepEqual(verified.Report.UFW.Rules, inspection.Report.UFW.Rules) {
		return fmt.Errorf("%w: UFW rules changed while disabling v1 UFW", ErrV1MigrationConflict)
	}
	return nil
}

func (driver *SystemV1MigrationDriver) ValidateMigratedClients(ctx context.Context, _ string, conversion V1ConversionResult) ([]V1MigrationClientValidation, error) {
	if ctx == nil || driver == nil || driver.keyRunner == nil {
		return nil, fmt.Errorf("client validation driver is incomplete")
	}
	stateStore, err := store.NewStateStore(driver.paths)
	if err != nil {
		return nil, err
	}
	state, err := stateStore.Load()
	if err != nil {
		return nil, err
	}
	secrets, err := store.NewSecretStore(driver.paths)
	if err != nil {
		return nil, err
	}
	clients := make(map[string]model.Client, len(state.Clients))
	for _, client := range state.Clients {
		clients[client.ID] = client
	}
	transports := make(map[string]model.Transport)
	for _, record := range state.Transports {
		if record.OwnerKind == model.TargetClient && record.Kind == model.TransportStandard {
			transports[record.OwnerID] = record
		}
	}
	preserved := make(map[string]bool)
	for _, artifact := range conversion.PreservedArtifacts {
		preserved[artifact.TargetClientID] = true
	}
	result := make([]V1MigrationClientValidation, 0, len(conversion.Clients))
	for _, converted := range conversion.Clients {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		client, ok := clients[converted.TargetID]
		if !ok || client.OverlayIPv4 != converted.OverlayIPv4 || client.Lifecycle != converted.Lifecycle {
			return nil, fmt.Errorf("migrated client %s identity/address validation failed", converted.TargetID)
		}
		keyPairKept := converted.Lifecycle == model.LifecycleDeleted
		if converted.Lifecycle != model.LifecycleDeleted {
			record, ok := transports[converted.TargetID]
			if !ok {
				return nil, fmt.Errorf("migrated client %s standard transport is absent", converted.TargetID)
			}
			privateKey, err := secrets.Get(record.CredentialRef)
			if err != nil {
				return nil, err
			}
			publicKey, deriveErr := wireguard.PublicKey(ctx, driver.keyRunner, strings.TrimSpace(string(privateKey)))
			clear(privateKey)
			if deriveErr != nil || publicKey != record.PublicKey {
				return nil, fmt.Errorf("migrated client %s key-pair validation failed", converted.TargetID)
			}
			keyPairKept = true
		}
		profileStatus := "not_present"
		if preserved[converted.TargetID] {
			profileStatus = "preserved"
		}
		result = append(result, V1MigrationClientValidation{
			TargetClientID: converted.TargetID, Status: "valid",
			AddressKept: true, KeyPairKept: keyPairKept, ProfileStatus: profileStatus,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].TargetClientID < result[j].TargetClientID })
	return result, nil
}

type v1MaintenanceFile struct {
	relative string
	mode     os.FileMode
	content  []byte
}

type v1MaintenanceSnapshotEntry struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type v1MaintenanceSnapshotManifest struct {
	Summary V1MaintenanceSnapshot        `json:"summary"`
	Entries []v1MaintenanceSnapshotEntry `json:"entries"`
}

func collectV1MaintenanceFiles(ctx context.Context, inspection *V1Inspection, binaryPath string) ([]v1MaintenanceFile, error) {
	entries := []v1MaintenanceFile{}
	var total int64
	stateRoot := filepath.Join(inspection.workspaceRoot, v1StateDirectoryName)
	err := filepath.WalkDir(stateRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("v1 snapshot source contains an unsafe entry")
		}
		if info.IsDir() {
			return nil
		}
		if len(entries) >= v1MigrationMaximumSnapshotFiles || info.Size() < 0 || info.Size() > v1MigrationMaximumSnapshotBytes-total {
			return fmt.Errorf("v1 maintenance snapshot exceeds bounded file or byte limits")
		}
		data, metadata, err := readV1RegularFile(ctx, path, v1MigrationMaximumSnapshotBytes-total)
		if err != nil {
			return err
		}
		if metadata.Mode.Perm() != info.Mode().Perm() {
			return fmt.Errorf("v1 snapshot source changed while reading")
		}
		relative, err := filepath.Rel(stateRoot, path)
		if err != nil {
			return err
		}
		entries = append(entries, v1MaintenanceFile{
			relative: filepath.ToSlash(filepath.Join("v1-workspace", ".vpnctl", relative)),
			mode:     info.Mode().Perm(), content: data,
		})
		total += int64(len(data))
		return nil
	})
	if err != nil {
		return nil, err
	}
	logical := []string{}
	for _, artifact := range []V1SystemArtifact{inspection.Report.WireGuardConfig, inspection.Report.ForwardingConfig} {
		if artifact.Present {
			logical = append(logical, artifact.Path)
		}
	}
	if inspection.Report.UFW.ConfigPresent {
		logical = append(logical, "/etc/ufw/ufw.conf")
	}
	if len(inspection.Report.UFW.Rules) != 0 {
		logical = append(logical, "/etc/ufw/user.rules", "/etc/ufw/user6.rules")
	}
	if binaryPath == "" {
		binaryPath = linuxplatform.DefaultVPNCTLBinaryPath
	}
	logical = append(logical, binaryPath)
	sort.Strings(logical)
	logical = compactStrings(logical)
	for _, source := range logical {
		path := filepath.Join(inspection.systemRoot, strings.TrimPrefix(source, "/"))
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			if source == binaryPath {
				return nil, fmt.Errorf("v1 binary is required for the maintenance rollback package")
			}
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("v1 snapshot system source %s is unsafe", source)
		}
		if len(entries) >= v1MigrationMaximumSnapshotFiles || info.Size() < 0 || info.Size() > v1MigrationMaximumSnapshotBytes-total {
			return nil, fmt.Errorf("v1 maintenance snapshot exceeds bounded file or byte limits")
		}
		data, metadata, err := readV1SystemRegularFile(ctx, inspection.systemRoot, source, v1MigrationMaximumSnapshotBytes-total)
		if err != nil {
			return nil, err
		}
		if metadata.Mode.Perm() != info.Mode().Perm() {
			return nil, fmt.Errorf("v1 snapshot system source %s changed while reading", source)
		}
		entries = append(entries, v1MaintenanceFile{
			relative: filepath.ToSlash(filepath.Join("v1-system", strings.TrimPrefix(source, "/"))),
			mode:     info.Mode().Perm(), content: data,
		})
		total += int64(len(data))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].relative < entries[j].relative })
	if len(entries) == 0 || len(entries) > v1MigrationMaximumSnapshotFiles || total > v1MigrationMaximumSnapshotBytes {
		return nil, fmt.Errorf("v1 maintenance snapshot exceeds bounded file or byte limits")
	}
	return entries, nil
}

func loadAndVerifyV1MaintenanceSnapshot(root string) (V1MaintenanceSnapshot, error) {
	info, err := os.Lstat(root)
	if errors.Is(err, fs.ErrNotExist) {
		return V1MaintenanceSnapshot{}, fs.ErrNotExist
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return V1MaintenanceSnapshot{}, fmt.Errorf("%w: maintenance snapshot root is unsafe", ErrV1MigrationConflict)
	}
	manifestPath := filepath.Join(root, v1MigrationSnapshotManifestName)
	ownerData, ownerMetadata, ownerErr := readV1RegularFile(context.Background(), filepath.Join(root, v1MigrationSnapshotOwnerName), 128)
	if ownerErr != nil || ownerMetadata.Mode.Perm() != 0o600 || string(ownerData) != "vpnctl-v1-maintenance-snapshot-v1\n" {
		return V1MaintenanceSnapshot{}, fmt.Errorf("%w: maintenance snapshot owner marker is invalid", ErrV1MigrationConflict)
	}
	data, metadata, err := readV1RegularFile(context.Background(), manifestPath, 64<<10)
	if err != nil || metadata.Mode.Perm() != 0o600 {
		return V1MaintenanceSnapshot{}, fmt.Errorf("%w: maintenance snapshot manifest is unsafe", ErrV1MigrationConflict)
	}
	var manifest v1MaintenanceSnapshotManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return V1MaintenanceSnapshot{}, fmt.Errorf("%w: maintenance snapshot manifest is invalid", ErrV1MigrationConflict)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return V1MaintenanceSnapshot{}, fmt.Errorf("%w: maintenance snapshot manifest has trailing data", ErrV1MigrationConflict)
	}
	result := manifest.Summary
	if err := validateV1MaintenanceSnapshot(result); err != nil {
		return V1MaintenanceSnapshot{}, fmt.Errorf("%w: maintenance snapshot metadata is invalid", ErrV1MigrationConflict)
	}
	if len(manifest.Entries) != result.Files {
		return V1MaintenanceSnapshot{}, fmt.Errorf("%w: maintenance snapshot entry count is invalid", ErrV1MigrationConflict)
	}
	entryByPath := make(map[string]v1MaintenanceSnapshotEntry, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.Path)))
		if clean != entry.Path || strings.HasPrefix(clean, "../") || clean == "." || entry.Mode == 0 || entry.Mode > 0o777 || entry.Bytes < 0 || entry.Bytes > v1MigrationMaximumSnapshotBytes || len(entry.SHA256) != sha256.Size*2 {
			return V1MaintenanceSnapshot{}, fmt.Errorf("%w: maintenance snapshot entry is invalid", ErrV1MigrationConflict)
		}
		if _, duplicate := entryByPath[entry.Path]; duplicate {
			return V1MaintenanceSnapshot{}, fmt.Errorf("%w: maintenance snapshot entry is duplicated", ErrV1MigrationConflict)
		}
		entryByPath[entry.Path] = entry
	}
	digest := sha256.New()
	files := 0
	var bytesTotal int64
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || path == manifestPath || path == filepath.Join(root, v1MigrationSnapshotOwnerName) {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("snapshot contains an unsafe entry")
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0o700 {
				return fmt.Errorf("snapshot directory is not root-only")
			}
			return nil
		}
		if info.Mode().Perm() != 0o600 {
			return fmt.Errorf("snapshot file is not root-only")
		}
		relative, _ := filepath.Rel(root, path)
		relative = filepath.ToSlash(relative)
		source, found := entryByPath[relative]
		if !found || info.Size() != source.Bytes || bytesTotal > v1MigrationMaximumSnapshotBytes-source.Bytes {
			return fmt.Errorf("snapshot file differs from its manifest")
		}
		content, _, err := readV1RegularFile(context.Background(), path, source.Bytes)
		if err != nil {
			return err
		}
		contentHash := sha256.Sum256(content)
		if source.Bytes != int64(len(content)) || source.SHA256 != hex.EncodeToString(contentHash[:]) {
			return fmt.Errorf("snapshot file differs from its manifest")
		}
		delete(entryByPath, relative)
		_, _ = fmt.Fprintf(digest, "%d:%s:%d:%o:", len(relative), relative, len(content), os.FileMode(source.Mode))
		_, _ = digest.Write(content)
		files++
		bytesTotal += int64(len(content))
		return nil
	})
	writeV1MigrationUnitDigest(digest, result.WireGuardUnit)
	if err != nil || files != result.Files || bytesTotal != result.Bytes || len(entryByPath) != 0 || hex.EncodeToString(digest.Sum(nil)) != result.SHA256 {
		return V1MaintenanceSnapshot{}, fmt.Errorf("%w: maintenance snapshot contents differ from manifest", ErrV1MigrationConflict)
	}
	return result, nil
}

func removeIncompleteV1MigrationDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: incomplete migration directory is unsafe", ErrV1MigrationConflict)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		data, metadata, readErr := readV1RegularFile(context.Background(), filepath.Join(path, v1MigrationSnapshotOwnerName), 128)
		if readErr != nil || metadata.Mode.Perm() != 0o600 || string(data) != "vpnctl-v1-maintenance-snapshot-v1\n" {
			return fmt.Errorf("%w: incomplete migration directory is not owned by vpnctl", ErrV1MigrationConflict)
		}
	}
	return os.RemoveAll(path)
}

func ensureV1MigrationPrivateDirectory(root, path string) error {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("migration directory escapes its root")
	}
	current := root
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
			return fmt.Errorf("migration directory %s is unsafe", current)
		}
	}
	return nil
}

func compactStrings(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
