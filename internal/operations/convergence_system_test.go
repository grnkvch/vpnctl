package operations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestSystemOwnedResourceDiscovererMatchesMixedFileAndUnitManifest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := "/etc/vpnctl/generated/routing.yaml"
	configContent := []byte("mode: rule\n")
	writeManagedObservationFile(t, root, configPath, configContent, 0o640)
	fileManifest := managedFileManifest(t, 8, configPath, configContent, 0o640)

	unitName := "vpnctl-routing.service"
	unitContent := []byte("[Service]\nExecStart=/usr/local/bin/vpnctl __service node-routing\n")
	writeManagedObservationFile(t, root, "/etc/systemd/system/"+unitName, unitContent, 0o644)
	unit := managedUnitResource(t, unitName, unitContent, 0o644, "active", "running", "enabled")
	manifest, err := NewConvergenceManifest(8, append(fileManifest.Resources, unit))
	if err != nil {
		t.Fatal(err)
	}
	runner := &unitDiscoveryRunner{activeState: "active", subState: "running", enablement: "enabled"}
	discoverer, err := NewSystemOwnedResourceDiscoverer(root, runner)
	if err != nil {
		t.Fatal(err)
	}
	planner, err := NewConvergencePlanner(
		staticConvergenceSource{snapshot: ConvergenceSnapshot{Desired: manifest, Applied: manifest, Pending: []PendingOperation{}}},
		discoverer,
	)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := planner.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 0 || len(plan.Drift) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
	wantCommands := []linuxplatform.ProbeCommand{
		{Name: "systemctl", Args: []string{"show", "--no-pager", "--property=LoadState", "--property=ActiveState", "--property=SubState", unitName}},
		{Name: "systemctl", Args: []string{"is-enabled", unitName}},
	}
	if !reflect.DeepEqual(runner.commands, wantCommands) {
		t.Fatalf("commands = %+v", runner.commands)
	}
}

func TestSystemOwnedResourceDiscovererReportsStoppedAndMissingUnits(t *testing.T) {
	t.Parallel()
	unitName := "vpnctl-tunnel-client.service"
	unitContent := []byte("[Service]\nExecStart=/usr/local/bin/frpc\n")
	unit := managedUnitResource(t, unitName, unitContent, 0o644, "active", "running", "enabled")
	manifest, err := NewConvergenceManifest(3, []ManagedResource{unit})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		writeUnit bool
		active    string
		sub       string
		kind      OwnedDriftKind
		calls     int
	}{
		{name: "stopped", writeUnit: true, active: "inactive", sub: "dead", kind: OwnedDriftModified, calls: 2},
		{name: "missing", kind: OwnedDriftMissing, calls: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if test.writeUnit {
				writeManagedObservationFile(t, root, "/etc/systemd/system/"+unitName, unitContent, 0o644)
			}
			runner := &unitDiscoveryRunner{activeState: test.active, subState: test.sub, enablement: "enabled"}
			discoverer, err := NewSystemOwnedResourceDiscoverer(root, runner)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := discoverer.DiscoverOwnedResources(context.Background(), manifest)
			if err != nil {
				t.Fatal(err)
			}
			drift := ownedDrift(manifest.Resources, observed)
			if len(drift) != 1 || drift[0].Kind != test.kind || len(runner.commands) != test.calls {
				t.Fatalf("drift=%+v commands=%+v", drift, runner.commands)
			}
		})
	}
}

func TestSystemOwnedResourceDiscovererDoesNotProbeUnsafeUnitFileShapes(t *testing.T) {
	t.Parallel()
	unitName := "vpnctl-standard.service"
	unit := managedUnitResource(t, unitName, []byte("expected"), 0o644, "active", "running", "enabled")
	manifest, err := NewConvergenceManifest(4, []ManagedResource{unit})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"symlink", "hardlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			actual := managedObservationPath(root, "/etc/systemd/system/"+unitName)
			if err := os.MkdirAll(filepath.Dir(actual), 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "foreign-unit")
			if err := os.WriteFile(target, []byte("unit-secret-canary"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(target, actual); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, actual); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(actual, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			runner := &unitDiscoveryRunner{}
			discoverer, err := NewSystemOwnedResourceDiscoverer(root, runner)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := discoverer.DiscoverOwnedResources(context.Background(), manifest)
			if err != nil {
				t.Fatal(err)
			}
			drift := ownedDrift(manifest.Resources, observed)
			if len(drift) != 1 || drift[0].Kind != OwnedDriftModified || len(runner.commands) != 0 {
				t.Fatalf("drift=%+v commands=%+v", drift, runner.commands)
			}
		})
	}
}

func TestSystemOwnedResourceDiscovererRejectsUnknownUnitAndProbeFailure(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	unknown := ManagedResource{
		Key:            ManagedResourceKey{Component: "runtime", Kind: ManagedResourceUnit, ID: "ssh.service"},
		RevisionSHA256: ManagedFingerprint([]byte("revision")), RuntimeSHA256: ManagedFingerprint([]byte("runtime")),
		ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
	}
	manifest, err := NewConvergenceManifest(2, []ManagedResource{unknown})
	if err != nil {
		t.Fatal(err)
	}
	discoverer, err := NewSystemOwnedResourceDiscoverer(root, &unitDiscoveryRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := discoverer.DiscoverOwnedResources(context.Background(), manifest); !errors.Is(err, ErrOwnedResourceDiscoveryUnsupported) {
		t.Fatalf("unknown unit error = %v", err)
	}

	unitName := "vpnctl-dns.service"
	content := []byte("[Service]\nExecStart=/usr/local/bin/mihomo\n")
	writeManagedObservationFile(t, root, "/etc/systemd/system/"+unitName, content, 0o644)
	manifest, err = NewConvergenceManifest(2, []ManagedResource{managedUnitResource(t, unitName, content, 0o644, "active", "running", "enabled")})
	if err != nil {
		t.Fatal(err)
	}
	discoverer, err = NewSystemOwnedResourceDiscoverer(root, &unitDiscoveryRunner{err: errors.New("systemd-secret-canary")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := discoverer.DiscoverOwnedResources(context.Background(), manifest); err == nil || strings.Contains(err.Error(), "systemd-secret-canary") {
		t.Fatalf("probe error = %v", err)
	}
}

func TestManagedUnitRuntimeFingerprintRejectsUnsafeValues(t *testing.T) {
	t.Parallel()
	if _, err := ManagedUnitRuntimeFingerprint(ManagedUnitRuntime{LoadState: "active\nsecret"}); err == nil {
		t.Fatal("unsafe unit runtime value accepted")
	}
	if names := managedUnitNames(); len(names) < 2 || !sortStringsAreStrict(names) {
		t.Fatalf("managed unit names = %v", names)
	}
}

type unitDiscoveryRunner struct {
	commands    []linuxplatform.ProbeCommand
	activeState string
	subState    string
	enablement  string
	err         error
}

func (runner *unitDiscoveryRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	runner.commands = append(runner.commands, command)
	if runner.err != nil {
		return linuxplatform.ProbeResult{}, runner.err
	}
	if len(command.Args) > 0 && command.Args[0] == "show" {
		return linuxplatform.ProbeResult{Stdout: []byte(
			"LoadState=loaded\nActiveState=" + runner.activeState + "\nSubState=" + runner.subState + "\n",
		)}, nil
	}
	if len(command.Args) > 0 && command.Args[0] == "is-enabled" {
		return linuxplatform.ProbeResult{Stdout: []byte(runner.enablement + "\n")}, nil
	}
	return linuxplatform.ProbeResult{}, errors.New("unexpected command")
}

func managedUnitResource(t *testing.T, name string, content []byte, mode os.FileMode, activeState, subState, enablement string) ManagedResource {
	t.Helper()
	contentHash := sha256.Sum256(content)
	runtimeSHA256, err := ManagedUnitRuntimeFingerprint(ManagedUnitRuntime{
		FileType: "regular", Mode: fileModeText(mode), ContentSHA256: hex.EncodeToString(contentHash[:]),
		LoadState: "loaded", ActiveState: activeState, SubState: subState, Enablement: enablement,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ManagedResource{
		Key:            ManagedResourceKey{Component: statusUnitTestComponent(name), Kind: ManagedResourceUnit, ID: name},
		RevisionSHA256: ManagedFingerprint([]byte("revision:" + name)), RuntimeSHA256: runtimeSHA256,
		ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
	}
}

func fileModeText(mode os.FileMode) string { return fmt.Sprintf("%04o", mode.Perm()) }

func statusUnitTestComponent(name string) string {
	switch {
	case strings.Contains(name, "routing"):
		return "routing"
	case strings.Contains(name, "tunnel"):
		return "tunnel"
	case strings.Contains(name, "dns"):
		return "dns"
	default:
		return "transport"
	}
}

func sortStringsAreStrict(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] >= values[index] {
			return false
		}
	}
	return true
}
