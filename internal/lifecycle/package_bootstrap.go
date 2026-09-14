package lifecycle

import (
	"bytes"
	"context"
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
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"golang.org/x/sys/unix"
)

const (
	RolePackagePlanSchemaVersion = 1
	packageBootstrapOwner        = "vpnctl-v2-package-bootstrap-v1\n"
	packageBootstrapLockTimeout  = "30"
)

var (
	ErrRolePackageBootstrap   = errors.New("role package bootstrap failed")
	ErrRolePackageConflict    = errors.New("role package bootstrap conflicts with host state")
	ErrRolePackageUnavailable = errors.New("role package manager is unavailable")
	ErrRolePackageResidue     = errors.New("role package rollback left uncertain residue")
)

type RolePackageAction string

const (
	RolePackagePresent RolePackageAction = "present"
	RolePackageInstall RolePackageAction = "install"
)

type RolePackagePlanItem struct {
	Component               string            `json:"component"`
	Package                 string            `json:"package"`
	Source                  string            `json:"source"`
	MinimumVersion          string            `json:"minimum_version"`
	MaximumVersionExclusive string            `json:"maximum_version_exclusive"`
	InstalledVersion        string            `json:"installed_version,omitempty"`
	CandidateVersion        string            `json:"candidate_version,omitempty"`
	Action                  RolePackageAction `json:"action"`
}

type RolePackagePlan struct {
	SchemaVersion  int                   `json:"schema_version"`
	Role           model.Role            `json:"role"`
	ManifestSHA256 string                `json:"manifest_sha256"`
	Packages       []RolePackagePlanItem `json:"packages"`
}

type RolePackageInstallation struct {
	Changed         bool     `json:"changed"`
	TransactionID   string   `json:"transaction_id,omitempty"`
	Installed       []string `json:"installed"`
	MaskedServices  []string `json:"masked_services"`
	journalPath     string
	approvedPlan    RolePackagePlan
	serviceBaseline []packageServiceBaseline
}

type RolePackageManager interface {
	Plan(context.Context, ReleaseManifest, model.Role) (RolePackagePlan, error)
	Apply(context.Context, ReleaseManifest, RolePackagePlan) (RolePackageInstallation, error)
	Commit(context.Context, RolePackageInstallation) error
	Rollback(context.Context, RolePackageInstallation) error
}

type InitHostDiscoverer interface {
	Discover(context.Context) (linuxplatform.HostSnapshot, error)
}

type SystemRolePackageManager struct {
	root       string
	runner     linuxplatform.ProbeRunner
	now        func() time.Time
	random     io.Reader
	journalDir string
	lockPath   string
}

type packageServiceBaseline struct {
	Name       string `json:"name"`
	Enablement string `json:"enablement"`
	Active     string `json:"active"`
	MaskedByUs bool   `json:"masked_by_vpnctl"`
}

type packageTransactionJournal struct {
	SchemaVersion  int                      `json:"schema_version"`
	TransactionID  string                   `json:"transaction_id"`
	Status         string                   `json:"status"`
	Role           model.Role               `json:"role"`
	ManifestSHA256 string                   `json:"manifest_sha256"`
	Packages       []RolePackagePlanItem    `json:"packages"`
	Services       []packageServiceBaseline `json:"services"`
	StartedAt      time.Time                `json:"started_at"`
	FinishedAt     *time.Time               `json:"finished_at,omitempty"`
	Residue        []string                 `json:"residue"`
}

func NewSystemRolePackageManager(root string, runner linuxplatform.ProbeRunner) (*SystemRolePackageManager, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || runner == nil {
		return nil, fmt.Errorf("role package manager requires a clean absolute root and command runner")
	}
	return &SystemRolePackageManager{
		root: root, runner: runner, now: time.Now, random: rand.Reader,
		journalDir: filepath.Join(root, "var", "lib", "vpnctl-package-bootstrap"),
		lockPath:   filepath.Join(root, "run", "vpnctl-package-bootstrap.lock"),
	}, nil
}

func (manager *SystemRolePackageManager) Plan(ctx context.Context, manifest ReleaseManifest, role model.Role) (RolePackagePlan, error) {
	if ctx == nil || manager == nil || manager.runner == nil {
		return RolePackagePlan{}, fmt.Errorf("%w: planner is incomplete", ErrRolePackageBootstrap)
	}
	if role != model.RoleGateway && role != model.RoleNode {
		return RolePackagePlan{}, fmt.Errorf("%w: unsupported role %q", ErrRolePackageBootstrap, role)
	}
	if err := manifest.Validate(); err != nil {
		return RolePackagePlan{}, fmt.Errorf("%w: release manifest: %v", ErrRolePackageBootstrap, err)
	}
	manifestSHA256, err := releaseManifestSHA256(manifest)
	if err != nil {
		return RolePackagePlan{}, err
	}
	plan := RolePackagePlan{
		SchemaVersion: RolePackagePlanSchemaVersion, Role: role, ManifestSHA256: manifestSHA256,
		Packages: []RolePackagePlanItem{},
	}
	for _, compatibility := range releaseAPTPackagesForRole(manifest, role) {
		item := RolePackagePlanItem{
			Component: compatibility.Component, Package: compatibility.Package, Source: compatibility.Source,
			MinimumVersion: compatibility.MinimumVersion, MaximumVersionExclusive: compatibility.MaximumVersionExclusive,
		}
		installed, present, err := manager.installedVersion(ctx, compatibility.Package)
		if err != nil {
			return RolePackagePlan{}, err
		}
		if present {
			compatible, err := manager.versionCompatible(ctx, installed, compatibility)
			if err != nil {
				return RolePackagePlan{}, err
			}
			if !compatible {
				return RolePackagePlan{}, fmt.Errorf("%w: installed package %s version is outside the release interval", ErrRolePackageConflict, compatibility.Package)
			}
			item.InstalledVersion = installed
			item.Action = RolePackagePresent
			plan.Packages = append(plan.Packages, item)
			continue
		}
		candidate, err := manager.candidateVersion(ctx, compatibility.Package)
		if err != nil {
			return RolePackagePlan{}, err
		}
		compatible, err := manager.versionCompatible(ctx, candidate, compatibility)
		if err != nil {
			return RolePackagePlan{}, err
		}
		if !compatible {
			return RolePackagePlan{}, fmt.Errorf("%w: repository candidate for %s is outside the release interval", ErrRolePackageConflict, compatibility.Package)
		}
		item.CandidateVersion = candidate
		item.Action = RolePackageInstall
		plan.Packages = append(plan.Packages, item)
	}
	sort.Slice(plan.Packages, func(left, right int) bool {
		return plan.Packages[left].Package < plan.Packages[right].Package
	})
	if err := plan.Validate(); err != nil {
		return RolePackagePlan{}, fmt.Errorf("%w: compiled plan: %v", ErrRolePackageBootstrap, err)
	}
	return plan, nil
}

func (manager *SystemRolePackageManager) Apply(ctx context.Context, manifest ReleaseManifest, approved RolePackagePlan) (RolePackageInstallation, error) {
	if ctx == nil || manager == nil || manager.runner == nil {
		return RolePackageInstallation{}, fmt.Errorf("%w: manager is incomplete", ErrRolePackageBootstrap)
	}
	if err := approved.Validate(); err != nil {
		return RolePackageInstallation{}, fmt.Errorf("%w: approved plan: %v", ErrRolePackageBootstrap, err)
	}
	lock, err := manager.acquireLock()
	if err != nil {
		return RolePackageInstallation{}, err
	}
	defer releasePackageBootstrapLock(lock)

	fresh, err := manager.Plan(ctx, manifest, approved.Role)
	if err != nil {
		return RolePackageInstallation{}, err
	}
	if !reflect.DeepEqual(fresh, approved) {
		return RolePackageInstallation{}, fmt.Errorf("%w: package plan changed; preview again", ErrRolePackageConflict)
	}
	installation := RolePackageInstallation{
		Installed: []string{}, MaskedServices: []string{}, approvedPlan: cloneRolePackagePlan(approved),
		serviceBaseline: []packageServiceBaseline{},
	}
	installItems := rolePackageInstallItems(approved)
	if len(installItems) == 0 {
		return installation, nil
	}
	transactionID, err := manager.transactionID()
	if err != nil {
		return RolePackageInstallation{}, fmt.Errorf("%w: allocate transaction identity", ErrRolePackageBootstrap)
	}
	installation.TransactionID = transactionID
	journal := packageTransactionJournal{
		SchemaVersion: RolePackagePlanSchemaVersion, TransactionID: transactionID, Status: "prepared",
		Role: approved.Role, ManifestSHA256: approved.ManifestSHA256, Packages: cloneRolePackageItems(approved.Packages),
		Services: []packageServiceBaseline{}, StartedAt: manager.now().UTC(), Residue: []string{},
	}
	journalPath, err := manager.createJournal(journal)
	if err != nil {
		return RolePackageInstallation{}, err
	}
	installation.journalPath = journalPath

	for _, item := range installItems {
		service := packageServiceName(item.Package)
		if service == "" {
			continue
		}
		baseline, err := manager.captureAndMaskService(ctx, service)
		if err != nil {
			return RolePackageInstallation{}, manager.failApply(ctx, installation, journal, err)
		}
		installation.serviceBaseline = append(installation.serviceBaseline, baseline)
		installation.MaskedServices = append(installation.MaskedServices, service)
		journal.Services = append(journal.Services, baseline)
		journal.Status = "services-masked"
		if err := manager.writeJournal(journalPath, journal); err != nil {
			return RolePackageInstallation{}, manager.failApply(ctx, installation, journal, err)
		}
	}
	if err := manager.apt(ctx, "update"); err != nil {
		return RolePackageInstallation{}, manager.failApply(ctx, installation, journal, err)
	}
	arguments := []string{"install", "--yes", "--no-install-recommends"}
	for _, item := range installItems {
		candidate, err := manager.candidateVersion(ctx, item.Package)
		if err != nil || candidate != item.CandidateVersion {
			if err == nil {
				err = fmt.Errorf("%w: repository candidate for %s changed after preview", ErrRolePackageConflict, item.Package)
			}
			return RolePackageInstallation{}, manager.failApply(ctx, installation, journal, err)
		}
		arguments = append(arguments, item.Package+"="+item.CandidateVersion)
	}
	if err := manager.apt(ctx, arguments...); err != nil {
		return RolePackageInstallation{}, manager.failApply(ctx, installation, journal, err)
	}
	for _, item := range installItems {
		installed, present, err := manager.installedVersion(ctx, item.Package)
		if err != nil || !present || installed != item.CandidateVersion {
			if err == nil {
				err = fmt.Errorf("installed package %s does not equal the approved version", item.Package)
			}
			return RolePackageInstallation{}, manager.failApply(ctx, installation, journal, err)
		}
		installation.Installed = append(installation.Installed, item.Package)
	}
	installation.Changed = true
	journal.Status = "installed"
	if err := manager.writeJournal(journalPath, journal); err != nil {
		return RolePackageInstallation{}, manager.failApply(ctx, installation, journal, err)
	}
	return installation, nil
}

func (manager *SystemRolePackageManager) Commit(ctx context.Context, installation RolePackageInstallation) error {
	if ctx == nil || manager == nil {
		return fmt.Errorf("%w: manager is incomplete", ErrRolePackageBootstrap)
	}
	if !installation.Changed {
		return nil
	}
	if err := manager.validateInstallation(installation); err != nil {
		return err
	}
	for _, baseline := range installation.serviceBaseline {
		if baseline.MaskedByUs && baseline.Enablement != "masked" {
			if err := manager.systemctl(ctx, "unmask", baseline.Name); err != nil {
				return fmt.Errorf("%w: unmask installed service %s", ErrRolePackageBootstrap, baseline.Name)
			}
		}
	}
	return manager.finishJournal(installation.journalPath, "committed", nil)
}

func (manager *SystemRolePackageManager) Rollback(ctx context.Context, installation RolePackageInstallation) error {
	if ctx == nil || manager == nil {
		return fmt.Errorf("%w: manager is incomplete", ErrRolePackageBootstrap)
	}
	if !installation.Changed && installation.TransactionID == "" {
		return nil
	}
	if err := manager.validateInstallation(installation); err != nil {
		return err
	}
	residue := manager.rollbackInstalled(ctx, installation)
	status := "rolled-back"
	if len(residue) != 0 {
		status = "rollback-incomplete"
	}
	journalErr := manager.finishJournal(installation.journalPath, status, residue)
	if len(residue) != 0 {
		return errors.Join(ErrRolePackageResidue, journalErr)
	}
	return journalErr
}

func (plan RolePackagePlan) Validate() error {
	if plan.SchemaVersion != RolePackagePlanSchemaVersion {
		return fmt.Errorf("schema_version must be %d", RolePackagePlanSchemaVersion)
	}
	if plan.Role != model.RoleGateway && plan.Role != model.RoleNode {
		return fmt.Errorf("role is invalid")
	}
	if !validReleaseSHA256(plan.ManifestSHA256) || plan.Packages == nil {
		return fmt.Errorf("manifest binding or package list is invalid")
	}
	previous := ""
	for index, item := range plan.Packages {
		if !releasePackagePattern.MatchString(item.Package) || item.Component == "" || item.Source == "" ||
			item.MinimumVersion == "" || item.MaximumVersionExclusive == "" || item.Package <= previous {
			return fmt.Errorf("package %d is invalid or not sorted", index)
		}
		switch item.Action {
		case RolePackagePresent:
			if item.InstalledVersion == "" || item.CandidateVersion != "" {
				return fmt.Errorf("present package %s has invalid versions", item.Package)
			}
		case RolePackageInstall:
			if item.CandidateVersion == "" || item.InstalledVersion != "" {
				return fmt.Errorf("install package %s has invalid versions", item.Package)
			}
		default:
			return fmt.Errorf("package %s action is invalid", item.Package)
		}
		previous = item.Package
	}
	return nil
}

func validatePrePackageCapabilities(snapshot linuxplatform.HostSnapshot, plan RolePackagePlan) error {
	err := snapshot.ValidateMandatoryCapabilities()
	if err == nil {
		return nil
	}
	var unsupported *linuxplatform.UnsupportedHostError
	if !errors.As(err, &unsupported) {
		return err
	}
	allowed := map[string]bool{}
	for _, item := range plan.Packages {
		if item.Action == RolePackageInstall && item.Component == "nftables" {
			allowed["nftables"] = true
			allowed["conntrack_marks"] = true
		}
	}
	failures := make([]linuxplatform.CapabilityFailure, 0, len(unsupported.Failures))
	for _, failure := range unsupported.Failures {
		if !allowed[failure.Name] {
			failures = append(failures, failure)
		}
	}
	if len(failures) == 0 {
		return nil
	}
	return &linuxplatform.UnsupportedHostError{Failures: failures}
}

func (manager *SystemRolePackageManager) installedVersion(ctx context.Context, name string) (string, bool, error) {
	result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{
		Name: "dpkg-query", Args: []string{"--show", "--showformat=${Status}\t${Version}\n", name},
	})
	if err != nil {
		return "", false, fmt.Errorf("%w: query installed package %s", ErrRolePackageUnavailable, name)
	}
	if result.ExitCode == 1 && len(bytes.TrimSpace(result.Stdout)) == 0 {
		return "", false, nil
	}
	const prefix = "install ok installed\t"
	output := string(result.Stdout)
	// dpkg-query retains an explicit database record after apt removes a
	// package. On Ubuntu 24.04 that known-absent state is returned with exit 0,
	// unlike a package that has never appeared in the database (exit 1). Both
	// are equally absent for planning purposes. Keep every other dpkg state
	// fail-closed: config-files, half-installed and malformed records must not
	// be mistaken for a clean package boundary.
	if result.ExitCode == 0 && output == "unknown ok not-installed\t\n" {
		return "", false, nil
	}
	if result.ExitCode != 0 || !strings.HasPrefix(output, prefix) || !strings.HasSuffix(output, "\n") || strings.Count(output, "\n") != 1 {
		return "", false, fmt.Errorf("%w: installed package query for %s returned an invalid result", ErrRolePackageUnavailable, name)
	}
	version := strings.TrimSuffix(strings.TrimPrefix(output, prefix), "\n")
	if version == "" || strings.ContainsAny(version, "\t\r\n\x00") {
		return "", false, fmt.Errorf("%w: installed package version for %s is invalid", ErrRolePackageUnavailable, name)
	}
	return version, true, nil
}

func (manager *SystemRolePackageManager) candidateVersion(ctx context.Context, name string) (string, error) {
	result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{
		Name: "apt-cache", Args: []string{"policy", name}, Env: []string{"LC_ALL=C"},
	})
	if err != nil || result.ExitCode != 0 {
		return "", fmt.Errorf("%w: query repository candidate for %s", ErrRolePackageUnavailable, name)
	}
	for _, raw := range strings.Split(string(result.Stdout), "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "Candidate:") {
			continue
		}
		version := strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
		if version == "" || version == "(none)" || strings.ContainsAny(version, "\t\r\n\x00 ") {
			break
		}
		return version, nil
	}
	return "", fmt.Errorf("%w: no repository candidate for %s", ErrRolePackageUnavailable, name)
}

func (manager *SystemRolePackageManager) versionCompatible(ctx context.Context, version string, compatibility APTPackageCompatibility) (bool, error) {
	for _, comparison := range []struct {
		op       string
		boundary string
	}{{op: "ge", boundary: compatibility.MinimumVersion}, {op: "lt", boundary: compatibility.MaximumVersionExclusive}} {
		result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{
			Name: "dpkg", Args: []string{"--compare-versions", version, comparison.op, comparison.boundary},
		})
		if err != nil {
			return false, fmt.Errorf("%w: compare package %s version", ErrRolePackageUnavailable, compatibility.Package)
		}
		switch result.ExitCode {
		case 0:
		case 1:
			return false, nil
		default:
			return false, fmt.Errorf("%w: package %s version comparison failed", ErrRolePackageUnavailable, compatibility.Package)
		}
	}
	return true, nil
}

func (manager *SystemRolePackageManager) captureAndMaskService(ctx context.Context, name string) (packageServiceBaseline, error) {
	baseline := packageServiceBaseline{Name: name}
	var err error
	baseline.Enablement, err = manager.systemctlState(ctx, "is-enabled", name)
	if err != nil {
		return packageServiceBaseline{}, err
	}
	baseline.Active, err = manager.systemctlState(ctx, "is-active", name)
	if err != nil {
		return packageServiceBaseline{}, err
	}
	if baseline.Enablement == "masked" {
		return baseline, nil
	}
	if err := manager.systemctl(ctx, "mask", name); err != nil {
		return packageServiceBaseline{}, err
	}
	baseline.MaskedByUs = true
	return baseline, nil
}

func (manager *SystemRolePackageManager) systemctlState(ctx context.Context, verb, name string) (string, error) {
	result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{verb, name}})
	if err != nil {
		return "", fmt.Errorf("%w: inspect service %s", ErrRolePackageUnavailable, name)
	}
	value := strings.TrimSpace(string(result.Stdout))
	if result.ExitCode == 0 && value != "" && !strings.ContainsAny(value, "\t\r\n\x00 ") {
		return value, nil
	}
	if result.ExitCode == 1 || result.ExitCode == 3 || result.ExitCode == 4 {
		if value == "" {
			value = "not-found"
		}
		if !strings.ContainsAny(value, "\t\r\n\x00 ") {
			return value, nil
		}
	}
	return "", fmt.Errorf("%w: service state for %s is invalid", ErrRolePackageUnavailable, name)
}

func (manager *SystemRolePackageManager) systemctl(ctx context.Context, arguments ...string) error {
	result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: arguments})
	if err != nil || result.ExitCode != 0 {
		return fmt.Errorf("%w: systemctl action failed", ErrRolePackageUnavailable)
	}
	return nil
}

func (manager *SystemRolePackageManager) apt(ctx context.Context, arguments ...string) error {
	args := []string{"-o", "DPkg::Lock::Timeout=" + packageBootstrapLockTimeout}
	args = append(args, arguments...)
	result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{
		Name: "apt-get", Args: args, Env: []string{"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"},
	})
	if err != nil || result.ExitCode != 0 {
		return fmt.Errorf("%w: apt action %s failed", ErrRolePackageUnavailable, arguments[0])
	}
	return nil
}

func (manager *SystemRolePackageManager) failApply(ctx context.Context, installation RolePackageInstallation, journal packageTransactionJournal, cause error) error {
	residue := manager.rollbackInstalled(context.WithoutCancel(ctx), installation)
	status := "rolled-back"
	if len(residue) != 0 {
		status = "rollback-incomplete"
	}
	journal.Status = status
	finished := manager.now().UTC()
	journal.FinishedAt = &finished
	journal.Services = append([]packageServiceBaseline(nil), installation.serviceBaseline...)
	journal.Residue = append([]string(nil), residue...)
	journalErr := manager.writeJournal(installation.journalPath, journal)
	if len(residue) != 0 {
		return errors.Join(cause, ErrRolePackageResidue, journalErr)
	}
	return errors.Join(cause, journalErr)
}

func (manager *SystemRolePackageManager) rollbackInstalled(ctx context.Context, installation RolePackageInstallation) []string {
	residue := []string{}
	items := rolePackageInstallItems(installation.approvedPlan)
	for index := len(items) - 1; index >= 0; index-- {
		item := items[index]
		_, present, err := manager.installedVersion(ctx, item.Package)
		if err != nil {
			residue = append(residue, "package-state:"+item.Package)
			continue
		}
		if !present {
			continue
		}
		if err := manager.apt(ctx, "remove", "--yes", item.Package); err != nil {
			residue = append(residue, "package:"+item.Package)
		}
	}
	for index := len(installation.serviceBaseline) - 1; index >= 0; index-- {
		baseline := installation.serviceBaseline[index]
		if baseline.MaskedByUs && baseline.Enablement != "masked" {
			if err := manager.systemctl(ctx, "unmask", baseline.Name); err != nil {
				residue = append(residue, "service-mask:"+baseline.Name)
			}
		}
	}
	sort.Strings(residue)
	return residue
}

func (manager *SystemRolePackageManager) acquireLock() (*os.File, error) {
	parent := filepath.Dir(manager.lockPath)
	info, err := os.Lstat(parent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%w: runtime directory is unavailable", ErrRolePackageUnavailable)
	}
	fd, err := unix.Open(manager.lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: create package transaction lock", ErrRolePackageUnavailable)
	}
	file := os.NewFile(uintptr(fd), manager.lockPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: open package transaction lock", ErrRolePackageUnavailable)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: another package transaction holds the lock", ErrRolePackageUnavailable)
	}
	return file, nil
}

func releasePackageBootstrapLock(file *os.File) {
	if file == nil {
		return
	}
	_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
	_ = file.Close()
}

func (manager *SystemRolePackageManager) createJournal(journal packageTransactionJournal) (string, error) {
	if err := manager.ensureJournalDirectory(); err != nil {
		return "", err
	}
	path := filepath.Join(manager.journalDir, "transaction-"+journal.TransactionID+".json")
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%w: package transaction journal already exists", ErrRolePackageConflict)
	}
	if err := manager.writeJournal(path, journal); err != nil {
		return "", err
	}
	return path, nil
}

func (manager *SystemRolePackageManager) ensureJournalDirectory() error {
	parent := filepath.Dir(manager.journalDir)
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return fmt.Errorf("%w: package journal parent is unavailable", ErrRolePackageUnavailable)
	}
	info, err := os.Lstat(manager.journalDir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(manager.journalDir, 0o700); err != nil {
			return fmt.Errorf("%w: create package journal directory", ErrRolePackageUnavailable)
		}
		if err := os.WriteFile(filepath.Join(manager.journalDir, ".owner"), []byte(packageBootstrapOwner), 0o600); err != nil {
			return fmt.Errorf("%w: create package journal owner", ErrRolePackageUnavailable)
		}
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("%w: package journal directory is not owned", ErrRolePackageConflict)
	}
	owner, err := os.ReadFile(filepath.Join(manager.journalDir, ".owner"))
	if err != nil || string(owner) != packageBootstrapOwner {
		return fmt.Errorf("%w: package journal owner does not match", ErrRolePackageConflict)
	}
	return nil
}

func (manager *SystemRolePackageManager) writeJournal(path string, journal packageTransactionJournal) error {
	encoded, err := json.Marshal(journal)
	if err != nil {
		return fmt.Errorf("%w: encode package transaction journal", ErrRolePackageBootstrap)
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".package-transaction-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: create package transaction journal", ErrRolePackageUnavailable)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("%w: publish package transaction journal", ErrRolePackageUnavailable)
	}
	return syncLifecycleDirectory(filepath.Dir(path))
}

func (manager *SystemRolePackageManager) finishJournal(path, status string, residue []string) error {
	journal, err := readPackageTransactionJournal(path)
	if err != nil {
		return err
	}
	journal.Status = status
	finished := manager.now().UTC()
	journal.FinishedAt = &finished
	journal.Residue = append([]string(nil), residue...)
	return manager.writeJournal(path, journal)
}

func readPackageTransactionJournal(path string) (packageTransactionJournal, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return packageTransactionJournal{}, fmt.Errorf("%w: read package transaction journal", ErrRolePackageUnavailable)
	}
	var journal packageTransactionJournal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil || journal.SchemaVersion != RolePackagePlanSchemaVersion {
		return packageTransactionJournal{}, fmt.Errorf("%w: package transaction journal is invalid", ErrRolePackageConflict)
	}
	return journal, nil
}

func (manager *SystemRolePackageManager) validateInstallation(installation RolePackageInstallation) error {
	if installation.TransactionID == "" || installation.journalPath == "" ||
		filepath.Dir(installation.journalPath) != manager.journalDir || installation.approvedPlan.Validate() != nil {
		return fmt.Errorf("%w: package installation receipt is invalid", ErrRolePackageConflict)
	}
	journal, err := readPackageTransactionJournal(installation.journalPath)
	if err != nil {
		return err
	}
	if journal.TransactionID != installation.TransactionID || journal.ManifestSHA256 != installation.approvedPlan.ManifestSHA256 ||
		journal.Role != installation.approvedPlan.Role {
		return fmt.Errorf("%w: package installation receipt differs from journal", ErrRolePackageConflict)
	}
	return nil
}

func (manager *SystemRolePackageManager) transactionID() (string, error) {
	var value [8]byte
	if _, err := io.ReadFull(manager.random, value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func releaseManifestSHA256(manifest ReleaseManifest) (string, error) {
	encoded, err := EncodeReleaseManifest(manifest)
	if err != nil {
		return "", fmt.Errorf("%w: encode release manifest", ErrRolePackageBootstrap)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func packageServiceName(name string) string {
	if name == "nginx" {
		return "nginx.service"
	}
	return ""
}

func rolePackageInstallItems(plan RolePackagePlan) []RolePackagePlanItem {
	items := make([]RolePackagePlanItem, 0, len(plan.Packages))
	for _, item := range plan.Packages {
		if item.Action == RolePackageInstall {
			items = append(items, item)
		}
	}
	return items
}

func cloneRolePackagePlan(plan RolePackagePlan) RolePackagePlan {
	plan.Packages = cloneRolePackageItems(plan.Packages)
	return plan
}

func cloneRolePackageItems(items []RolePackagePlanItem) []RolePackagePlanItem {
	if items == nil {
		return nil
	}
	result := make([]RolePackagePlanItem, len(items))
	copy(result, items)
	return result
}

var _ RolePackageManager = (*SystemRolePackageManager)(nil)
