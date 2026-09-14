package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestRolePackagePlannerFiltersRolesAndUsesOnlyManifestCandidates(t *testing.T) {
	t.Parallel()

	manifest, _ := releaseManifestFixture()
	for _, role := range []model.Role{model.RoleGateway, model.RoleNode} {
		role := role
		t.Run(string(role), func(t *testing.T) {
			t.Parallel()
			runner := newPackageBootstrapRunner(manifest)
			manager := newPackageBootstrapManager(t, runner)
			plan, err := manager.Plan(context.Background(), manifest, role)
			if err != nil {
				t.Fatal(err)
			}
			wantCount := 2
			if role == model.RoleGateway {
				wantCount = 3
			}
			if plan.Role != role || plan.ManifestSHA256 == "" || len(plan.Packages) != wantCount {
				t.Fatalf("%s plan = %+v", role, plan)
			}
			for _, item := range plan.Packages {
				if item.Action != RolePackageInstall || item.CandidateVersion == "" || item.InstalledVersion != "" {
					t.Fatalf("%s package plan = %+v", role, item)
				}
				if role == model.RoleNode && item.Package == "nginx" {
					t.Fatal("node package plan contains Gateway-only nginx")
				}
				compatibility := packageCompatibilityByName(t, manifest, item.Package)
				if item.CandidateVersion != runner.candidates[item.Package] || item.Component != compatibility.Component ||
					item.Source != compatibility.Source || item.MinimumVersion != compatibility.MinimumVersion ||
					item.MaximumVersionExclusive != compatibility.MaximumVersionExclusive {
					t.Fatalf("package plan escaped manifest contract: %+v", item)
				}
			}
			if containsPackageBootstrapCall(runner.calls, "apt-get") {
				t.Fatalf("read-only plan invoked apt-get: %q", runner.calls)
			}
		})
	}
}

func TestRolePackagePlannerAcceptsCompatibleInstalledAndRejectsIncompatibleOrUnavailable(t *testing.T) {
	t.Parallel()

	manifest, _ := releaseManifestFixture()
	runner := newPackageBootstrapRunner(manifest)
	for name, version := range runner.candidates {
		runner.versions[name] = version
	}
	manager := newPackageBootstrapManager(t, runner)
	plan, err := manager.Plan(context.Background(), manifest, model.RoleGateway)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range plan.Packages {
		if item.Action != RolePackagePresent || item.InstalledVersion == "" || item.CandidateVersion != "" {
			t.Fatalf("installed package plan = %+v", item)
		}
	}
	if containsPackageBootstrapCall(runner.calls, "apt-cache") {
		t.Fatalf("installed package plan queried repository candidates: %q", runner.calls)
	}

	runner.versions["nginx"] = "0.0-incompatible"
	if _, err := manager.Plan(context.Background(), manifest, model.RoleGateway); !errors.Is(err, ErrRolePackageConflict) {
		t.Fatalf("incompatible package error = %v", err)
	}
	delete(runner.versions, "nginx")
	delete(runner.candidates, "nginx")
	if _, err := manager.Plan(context.Background(), manifest, model.RoleGateway); !errors.Is(err, ErrRolePackageUnavailable) {
		t.Fatalf("unavailable package error = %v", err)
	}
}

func TestRolePackagePlannerTreatsDpkgRemovedRecordAsAbsent(t *testing.T) {
	t.Parallel()

	manifest, _ := releaseManifestFixture()
	runner := newPackageBootstrapRunner(manifest)
	runner.notInstalledRecords["nginx"] = true
	manager := newPackageBootstrapManager(t, runner)
	plan, err := manager.Plan(context.Background(), manifest, model.RoleGateway)
	if err != nil {
		t.Fatal(err)
	}
	item := packagePlanItemByName(t, plan, "nginx")
	if item.Action != RolePackageInstall || item.InstalledVersion != "" || item.CandidateVersion != runner.candidates["nginx"] {
		t.Fatalf("removed-package plan = %+v", item)
	}

	// A residual configuration or interrupted dpkg state is not the same as
	// clean absence and must remain unavailable until the operator repairs it.
	runner.notInstalledRecords["nginx"] = false
	runner.dpkgOverrides["nginx"] = "deinstall ok config-files\t" + runner.candidates["nginx"] + "\n"
	if _, err := manager.Plan(context.Background(), manifest, model.RoleGateway); !errors.Is(err, ErrRolePackageUnavailable) {
		t.Fatalf("residual dpkg state error = %v", err)
	}
}

func TestPrePackageCapabilitiesDeferOnlyMissingDeclaredPackageCapabilities(t *testing.T) {
	t.Parallel()

	manifest, _ := releaseManifestFixture()
	runner := newPackageBootstrapRunner(manifest)
	manager := newPackageBootstrapManager(t, runner)
	plan, err := manager.Plan(context.Background(), manifest, model.RoleGateway)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := validGatewaySnapshot()
	snapshot.Capabilities.NFTables = linuxplatform.Capability{Available: false, Detail: "nft command absent"}
	snapshot.Capabilities.ConntrackMarks = linuxplatform.Capability{Available: false, Detail: "nft command absent"}
	if err := validatePrePackageCapabilities(snapshot, plan); err != nil {
		t.Fatalf("declared nftables installation did not defer package capabilities: %v", err)
	}
	snapshot.Capabilities.Linux = linuxplatform.Capability{Available: false, Detail: "darwin"}
	if err := validatePrePackageCapabilities(snapshot, plan); !errors.Is(err, linuxplatform.ErrUnsupportedHost) || strings.Contains(err.Error(), "nftables") {
		t.Fatalf("immutable preflight filtering error = %v", err)
	}
	snapshot.Capabilities.Linux = linuxplatform.Capability{Available: true, Detail: "linux"}
	for index := range plan.Packages {
		if plan.Packages[index].Component == "nftables" {
			plan.Packages[index].Action = RolePackagePresent
			plan.Packages[index].InstalledVersion = plan.Packages[index].CandidateVersion
			plan.Packages[index].CandidateVersion = ""
		}
	}
	if err := validatePrePackageCapabilities(snapshot, plan); !errors.Is(err, linuxplatform.ErrUnsupportedHost) {
		t.Fatalf("missing capability from an already-present package was deferred: %v", err)
	}
}

func TestRolePackageApplyPinsVersionsMasksNginxAndIsIdempotent(t *testing.T) {
	t.Parallel()

	manifest, _ := releaseManifestFixture()
	runner := newPackageBootstrapRunner(manifest)
	manager := newPackageBootstrapManager(t, runner)
	manager.random = bytes.NewReader(bytes.Repeat([]byte{0x42}, 8))
	manager.now = func() time.Time { return time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC) }
	plan, err := manager.Plan(context.Background(), manifest, model.RoleGateway)
	if err != nil {
		t.Fatal(err)
	}
	runner.calls = nil
	runner.environments = nil
	installation, err := manager.Apply(context.Background(), manifest, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !installation.Changed || installation.TransactionID != "4242424242424242" ||
		!reflect.DeepEqual(installation.MaskedServices, []string{"nginx.service"}) || len(installation.Installed) != 3 {
		t.Fatalf("package installation = %+v", installation)
	}
	for _, item := range plan.Packages {
		if runner.versions[item.Package] != item.CandidateVersion {
			t.Fatalf("installed %s = %q, want %q", item.Package, runner.versions[item.Package], item.CandidateVersion)
		}
	}
	joined := strings.Join(runner.calls, "\n")
	for _, required := range []string{
		"systemctl mask nginx.service",
		"apt-get -o DPkg::Lock::Timeout=30 update",
		"apt-get -o DPkg::Lock::Timeout=30 install --yes --no-install-recommends",
		"nginx=" + runner.candidates["nginx"],
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("package apply omitted %q from:\n%s", required, joined)
		}
	}
	for _, forbidden := range []string{" upgrade", "dist-upgrade", "autoremove"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("package apply contains forbidden action %q:\n%s", forbidden, joined)
		}
	}
	for index, call := range runner.calls {
		if !strings.HasPrefix(call, "apt-get ") {
			continue
		}
		if !reflect.DeepEqual(runner.environments[index], []string{"DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"}) {
			t.Fatalf("apt environment = %q", runner.environments[index])
		}
	}
	info, err := os.Stat(installation.journalPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("package journal = %v, %v", info, err)
	}
	journal, err := readPackageTransactionJournal(installation.journalPath)
	if err != nil || journal.Status != "installed" || journal.ManifestSHA256 != plan.ManifestSHA256 {
		t.Fatalf("package journal = %+v, %v", journal, err)
	}
	if err := manager.Commit(context.Background(), installation); err != nil {
		t.Fatal(err)
	}
	if runner.serviceEnablement["nginx.service"] == "masked" {
		t.Fatal("committed package transaction left nginx masked")
	}
	journal, _ = readPackageTransactionJournal(installation.journalPath)
	if journal.Status != "committed" || journal.FinishedAt == nil {
		t.Fatalf("committed package journal = %+v", journal)
	}
	runner.calls = nil
	second, err := manager.Plan(context.Background(), manifest, model.RoleGateway)
	if err != nil {
		t.Fatal(err)
	}
	secondResult, err := manager.Apply(context.Background(), manifest, second)
	if err != nil || secondResult.Changed || secondResult.TransactionID != "" {
		t.Fatalf("idempotent package apply = %+v, %v", secondResult, err)
	}
	if containsPackageBootstrapCall(runner.calls, "apt-get") || containsPackageBootstrapCall(runner.calls, "systemctl mask") {
		t.Fatalf("idempotent apply mutated host: %q", runner.calls)
	}
}

func TestRolePackageApplyRejectsStaleOrFabricatedPlanBeforeMutation(t *testing.T) {
	t.Parallel()

	manifest, _ := releaseManifestFixture()
	runner := newPackageBootstrapRunner(manifest)
	manager := newPackageBootstrapManager(t, runner)
	plan, err := manager.Plan(context.Background(), manifest, model.RoleGateway)
	if err != nil {
		t.Fatal(err)
	}
	plan.Packages[0].CandidateVersion = "fabricated-version"
	runner.calls = nil
	if _, err := manager.Apply(context.Background(), manifest, plan); !errors.Is(err, ErrRolePackageConflict) {
		t.Fatalf("fabricated plan error = %v", err)
	}
	if containsPackageBootstrapCall(runner.calls, "apt-get") || containsPackageBootstrapCall(runner.calls, "systemctl mask") {
		t.Fatalf("fabricated plan mutated host: %q", runner.calls)
	}
}

func TestRolePackageApplyFailsClosedWhileTransactionLockIsHeld(t *testing.T) {
	t.Parallel()

	manifest, _ := releaseManifestFixture()
	runner := newPackageBootstrapRunner(manifest)
	manager := newPackageBootstrapManager(t, runner)
	plan, err := manager.Plan(context.Background(), manifest, model.RoleGateway)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := manager.acquireLock()
	if err != nil {
		t.Fatal(err)
	}
	defer releasePackageBootstrapLock(lock)
	runner.calls = nil
	if _, err := manager.Apply(context.Background(), manifest, plan); !errors.Is(err, ErrRolePackageUnavailable) {
		t.Fatalf("contended package lock error = %v", err)
	}
	if containsPackageBootstrapCall(runner.calls, "apt-get") || containsPackageBootstrapCall(runner.calls, "systemctl mask") {
		t.Fatalf("contended package lock mutated host: %q", runner.calls)
	}
}

func TestRolePackageApplyFailureRollsBackOnlyNewPackagesAndReportsResidue(t *testing.T) {
	t.Parallel()

	manifest, _ := releaseManifestFixture()
	for _, removeFails := range []bool{false, true} {
		removeFails := removeFails
		t.Run(fmt.Sprintf("remove-fails-%t", removeFails), func(t *testing.T) {
			t.Parallel()
			runner := newPackageBootstrapRunner(manifest)
			runner.failInstallAfter = 1
			runner.failRemove = removeFails
			manager := newPackageBootstrapManager(t, runner)
			manager.random = bytes.NewReader(bytes.Repeat([]byte{byte(1 + boolIndex(removeFails))}, 8))
			plan, err := manager.Plan(context.Background(), manifest, model.RoleGateway)
			if err != nil {
				t.Fatal(err)
			}
			_, err = manager.Apply(context.Background(), manifest, plan)
			if !errors.Is(err, ErrRolePackageUnavailable) {
				t.Fatalf("failed install error = %v", err)
			}
			if removeFails {
				if !errors.Is(err, ErrRolePackageResidue) || len(runner.versions) == 0 {
					t.Fatalf("rollback residue error/state = %v / %+v", err, runner.versions)
				}
			} else if len(runner.versions) != 0 || runner.serviceEnablement["nginx.service"] == "masked" {
				t.Fatalf("known rollback left state = packages:%+v services:%+v", runner.versions, runner.serviceEnablement)
			}
			entries, readErr := os.ReadDir(manager.journalDir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			var journal packageTransactionJournal
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "transaction-") {
					journal, readErr = readPackageTransactionJournal(filepath.Join(manager.journalDir, entry.Name()))
					if readErr != nil {
						t.Fatal(readErr)
					}
				}
			}
			wantStatus := "rolled-back"
			if removeFails {
				wantStatus = "rollback-incomplete"
			}
			if journal.Status != wantStatus || journal.FinishedAt == nil || (removeFails && len(journal.Residue) == 0) {
				t.Fatalf("failed package journal = %+v", journal)
			}
		})
	}
}

func newPackageBootstrapManager(t *testing.T, runner *packageBootstrapRunner) *SystemRolePackageManager {
	t.Helper()
	root := newGatewaySystemRoot(t)
	manager, err := NewSystemRolePackageManager(root, runner)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

type packageBootstrapRunner struct {
	versions            map[string]string
	candidates          map[string]string
	notInstalledRecords map[string]bool
	dpkgOverrides       map[string]string
	serviceEnablement   map[string]string
	serviceActive       map[string]string
	calls               []string
	environments        [][]string
	failInstallAfter    int
	failRemove          bool
}

func newPackageBootstrapRunner(manifest ReleaseManifest) *packageBootstrapRunner {
	candidates := make(map[string]string, len(manifest.APTPackages))
	for _, compatibility := range manifest.APTPackages {
		candidates[compatibility.Package] = compatibility.MinimumVersion
	}
	return &packageBootstrapRunner{
		versions: candidatesEmptyCopy(candidates), candidates: candidates,
		notInstalledRecords: map[string]bool{}, dpkgOverrides: map[string]string{},
		serviceEnablement: map[string]string{"nginx.service": "not-found"},
		serviceActive:     map[string]string{"nginx.service": "inactive"},
	}
}

func (runner *packageBootstrapRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	call := strings.TrimSpace(command.Name + " " + strings.Join(command.Args, " "))
	runner.calls = append(runner.calls, call)
	runner.environments = append(runner.environments, append([]string(nil), command.Env...))
	switch command.Name {
	case "dpkg-query":
		name := command.Args[len(command.Args)-1]
		if output, ok := runner.dpkgOverrides[name]; ok {
			return linuxplatform.ProbeResult{Stdout: []byte(output)}, nil
		}
		version, present := runner.versions[name]
		if !present {
			if runner.notInstalledRecords[name] {
				return linuxplatform.ProbeResult{Stdout: []byte("unknown ok not-installed\t\n")}, nil
			}
			return linuxplatform.ProbeResult{ExitCode: 1}, nil
		}
		return linuxplatform.ProbeResult{Stdout: []byte("install ok installed\t" + version + "\n")}, nil
	case "apt-cache":
		name := command.Args[len(command.Args)-1]
		candidate, present := runner.candidates[name]
		if !present {
			return linuxplatform.ProbeResult{Stdout: []byte(name + ":\n  Installed: (none)\n  Candidate: (none)\n")}, nil
		}
		return linuxplatform.ProbeResult{Stdout: []byte(name + ":\n  Installed: (none)\n  Candidate: " + candidate + "\n")}, nil
	case "dpkg":
		version, operation := command.Args[1], command.Args[2]
		if version == "0.0-incompatible" && operation == "ge" || version == "9999-incompatible" && operation == "lt" {
			return linuxplatform.ProbeResult{ExitCode: 1}, nil
		}
		return linuxplatform.ProbeResult{}, nil
	case "systemctl":
		verb, name := command.Args[0], command.Args[len(command.Args)-1]
		switch verb {
		case "is-enabled":
			value := runner.serviceEnablement[name]
			if value == "" {
				value = "not-found"
			}
			exit := 0
			if value != "enabled" && value != "masked" {
				exit = 1
			}
			return linuxplatform.ProbeResult{ExitCode: exit, Stdout: []byte(value + "\n")}, nil
		case "is-active":
			value := runner.serviceActive[name]
			if value == "" {
				value = "inactive"
			}
			exit := 0
			if value != "active" {
				exit = 3
			}
			return linuxplatform.ProbeResult{ExitCode: exit, Stdout: []byte(value + "\n")}, nil
		case "mask":
			runner.serviceEnablement[name] = "masked"
			return linuxplatform.ProbeResult{}, nil
		case "unmask":
			runner.serviceEnablement[name] = "disabled"
			return linuxplatform.ProbeResult{}, nil
		}
	case "apt-get":
		if containsString(command.Args, "update") {
			return linuxplatform.ProbeResult{}, nil
		}
		if containsString(command.Args, "install") {
			installed := 0
			for _, argument := range command.Args {
				name, version, found := strings.Cut(argument, "=")
				if !found || name == "DPkg::Lock::Timeout" {
					continue
				}
				runner.versions[name] = version
				installed++
				if runner.failInstallAfter > 0 && installed >= runner.failInstallAfter {
					return linuxplatform.ProbeResult{ExitCode: 100}, nil
				}
			}
			return linuxplatform.ProbeResult{}, nil
		}
		if containsString(command.Args, "remove") {
			name := command.Args[len(command.Args)-1]
			if runner.failRemove {
				return linuxplatform.ProbeResult{ExitCode: 100}, nil
			}
			delete(runner.versions, name)
			return linuxplatform.ProbeResult{}, nil
		}
	}
	return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected package command %q", call)
}

func packageCompatibilityByName(t *testing.T, manifest ReleaseManifest, name string) APTPackageCompatibility {
	t.Helper()
	for _, compatibility := range manifest.APTPackages {
		if compatibility.Package == name {
			return compatibility
		}
	}
	t.Fatalf("package %s is absent from manifest", name)
	return APTPackageCompatibility{}
}

func packagePlanItemByName(t *testing.T, plan RolePackagePlan, name string) RolePackagePlanItem {
	t.Helper()
	for _, item := range plan.Packages {
		if item.Package == name {
			return item
		}
	}
	t.Fatalf("package %s is absent from plan", name)
	return RolePackagePlanItem{}
}

func candidatesEmptyCopy(values map[string]string) map[string]string {
	return make(map[string]string, len(values))
}

func containsPackageBootstrapCall(calls []string, value string) bool {
	for _, call := range calls {
		if strings.Contains(call, value) {
			return true
		}
	}
	return false
}

func boolIndex(value bool) int {
	if value {
		return 1
	}
	return 0
}
