package ingress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestNginxActivationInitialInstallAndIdempotenceUseCompleteAtomicTree(t *testing.T) {
	t.Parallel()
	manager, paths, probe, reloader := nginxActivationFixture(t)
	candidate := nginxActivationCandidate(t, paths, 1, 1)
	result, err := manager.Apply(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !result.Initial || result.Reloaded || result.PreviousGeneration != 0 ||
		result.StateGeneration != 1 || result.ConfigHash != candidate.ConfigHash() || result.ActiveExposeCount != 1 {
		t.Fatalf("initial result = %+v", result)
	}
	active, present, err := inspectCurrentNginxTree(paths)
	if err != nil || !present || active.generation != 1 || active.hash != candidate.ConfigHash() {
		t.Fatalf("active generation = %+v, present=%t, err=%v", active, present, err)
	}
	link, err := os.Readlink(NginxActiveRoot(paths))
	if err != nil || link != active.link || filepath.IsAbs(link) {
		t.Fatalf("active link = %q, err=%v", link, err)
	}
	assertNginxTreeEqualsCandidate(t, active.root, candidate)
	if len(probe.commands) != 2 || len(reloader.calls) != 0 {
		t.Fatalf("initial commands = probe:%v reload:%v", probe.commands, reloader.calls)
	}
	if info, err := os.Stat(NginxRuntimeDirectory(paths)); err != nil {
		t.Fatalf("inspect runtime directory: %v", err)
	} else if info.Mode().Perm() != 0o750 {
		t.Fatalf("runtime directory mode = %v", info.Mode().Perm())
	}
	assertNoStagedNginxTrees(t, paths)

	probeCount := len(probe.commands)
	result, err = manager.Apply(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Initial || result.Reloaded || result.PreviousGeneration != 1 ||
		len(probe.commands) != probeCount || len(reloader.calls) != 0 {
		t.Fatalf("idempotent apply = result:%+v probe:%v reload:%v", result, probe.commands, reloader.calls)
	}
}

func TestNginxActivationChangedTreeSwitchesBeforeGracefulReloadAndPrunesPrior(t *testing.T) {
	t.Parallel()
	manager, paths, _, reloader := nginxActivationFixture(t)
	before := nginxActivationCandidate(t, paths, 1, 1)
	if _, err := manager.Apply(context.Background(), before); err != nil {
		t.Fatal(err)
	}
	old, _, _ := inspectCurrentNginxTree(paths)
	after := nginxActivationCandidate(t, paths, 2, 2)
	reloader.inspect = func() {
		active, present, err := inspectCurrentNginxTree(paths)
		if err != nil || !present {
			t.Errorf("reload observed no valid active tree: %+v %t %v", active, present, err)
			return
		}
		reloader.activeHashes = append(reloader.activeHashes, active.hash)
	}
	result, err := manager.Apply(context.Background(), after)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Initial || !result.Reloaded || result.PreviousGeneration != 1 || result.StateGeneration != 2 {
		t.Fatalf("update result = %+v", result)
	}
	wantCall := NginxBinaryPath(paths) + " reload " + NginxActiveRoot(paths)
	if !reflect.DeepEqual(reloader.calls, []string{wantCall}) || !reflect.DeepEqual(reloader.activeHashes, []string{after.ConfigHash()}) {
		t.Fatalf("reload observations = calls:%v active:%v", reloader.calls, reloader.activeHashes)
	}
	active, present, err := inspectCurrentNginxTree(paths)
	if err != nil || !present || active.generation != 2 || active.hash != after.ConfigHash() {
		t.Fatalf("updated active tree = %+v %t %v", active, present, err)
	}
	if _, err := os.Lstat(old.root); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("prior generation remains after successful reload: %v", err)
	}
	assertNoStagedNginxTrees(t, paths)
}

func TestNginxActivationSameContentAdvancesGenerationWithoutReload(t *testing.T) {
	t.Parallel()
	manager, paths, probe, reloader := nginxActivationFixture(t)
	before := nginxActivationCandidate(t, paths, 1, 1)
	if _, err := manager.Apply(context.Background(), before); err != nil {
		t.Fatal(err)
	}
	old, _, _ := inspectCurrentNginxTree(paths)
	after := nginxActivationCandidate(t, paths, 2, 1)
	if before.ConfigHash() != after.ConfigHash() {
		t.Fatal("generation-only fixture changed rendered content")
	}
	result, err := manager.Apply(context.Background(), after)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Initial || result.Reloaded || result.PreviousGeneration != 1 || len(reloader.calls) != 0 || len(probe.commands) != 4 {
		t.Fatalf("generation-only activation = result:%+v probes:%d reload:%v", result, len(probe.commands), reloader.calls)
	}
	active, present, err := inspectCurrentNginxTree(paths)
	if err != nil || !present || active.generation != 2 || active.hash != before.ConfigHash() {
		t.Fatalf("generation-only active = %+v %t %v", active, present, err)
	}
	if _, err := os.Lstat(old.root); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("old provenance tree remains: %v", err)
	}
}

func TestNginxActivationInvalidParserAndValidationMutationPreserveCurrent(t *testing.T) {
	t.Parallel()
	for name, configure := range map[string]func(*nginxActivationProbe){
		"parser rejection": func(probe *nginxActivationProbe) { probe.validationCode = 1 },
		"validator mutation": func(probe *nginxActivationProbe) {
			probe.afterValidation = func(root string) error {
				path := filepath.Join(root, filepath.FromSlash(NginxRoutesConfigPath))
				file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					return err
				}
				if _, err := file.WriteString("# drift\n"); err != nil {
					_ = file.Close()
					return err
				}
				return file.Close()
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			manager, paths, probe, reloader := nginxActivationFixture(t)
			before := nginxActivationCandidate(t, paths, 1, 1)
			if _, err := manager.Apply(context.Background(), before); err != nil {
				t.Fatal(err)
			}
			activeBefore, _, _ := inspectCurrentNginxTree(paths)
			probe.commands = nil
			configure(probe)
			after := nginxActivationCandidate(t, paths, 2, 2)
			_, err := manager.Apply(context.Background(), after)
			if name == "parser rejection" && !errors.Is(err, ErrNginxValidation) {
				t.Fatalf("parser error = %v", err)
			}
			if name == "validator mutation" && !errors.Is(err, ErrNginxTreeDrift) {
				t.Fatalf("mutation error = %v", err)
			}
			activeAfter, present, inspectErr := inspectCurrentNginxTree(paths)
			if inspectErr != nil || !present || activeAfter != activeBefore || len(reloader.calls) != 0 {
				t.Fatalf("invalid candidate changed current: before=%+v after=%+v present=%t err=%v reload=%v", activeBefore, activeAfter, present, inspectErr, reloader.calls)
			}
			if len(probe.commands) != 2 {
				t.Fatalf("validation calls = %v", probe.commands)
			}
			assertOnlyNginxGeneration(t, paths, activeBefore.name)
			assertNoStagedNginxTrees(t, paths)
		})
	}
}

func TestNginxActivationReloadFailureRestoresPriorServingGeneration(t *testing.T) {
	t.Parallel()
	manager, paths, _, reloader := nginxActivationFixture(t)
	before := nginxActivationCandidate(t, paths, 1, 1)
	if _, err := manager.Apply(context.Background(), before); err != nil {
		t.Fatal(err)
	}
	old, _, _ := inspectCurrentNginxTree(paths)
	after := nginxActivationCandidate(t, paths, 2, 2)
	reloader.failures = []error{errors.New("new-secret-canary"), nil}
	reloader.inspect = func() {
		active, present, err := inspectCurrentNginxTree(paths)
		if err != nil || !present {
			t.Errorf("reload inspection = %+v %t %v", active, present, err)
			return
		}
		reloader.activeHashes = append(reloader.activeHashes, active.hash)
	}
	_, err := manager.Apply(context.Background(), after)
	if !errors.Is(err, ErrNginxReload) || errors.Is(err, ErrNginxRollback) || strings.Contains(err.Error(), "canary") {
		t.Fatalf("reload failure = %v", err)
	}
	active, present, inspectErr := inspectCurrentNginxTree(paths)
	if inspectErr != nil || !present || active != old {
		t.Fatalf("rollback active = %+v, want %+v, present=%t err=%v", active, old, present, inspectErr)
	}
	if !reflect.DeepEqual(reloader.activeHashes, []string{after.ConfigHash(), before.ConfigHash()}) || len(reloader.calls) != 2 {
		t.Fatalf("rollback reload observations = hashes:%v calls:%v", reloader.activeHashes, reloader.calls)
	}
	assertOnlyNginxGeneration(t, paths, old.name)
	assertNoStagedNginxTrees(t, paths)
}

func TestNginxActivationFailedRuntimeRollbackRetainsExactRecoveryTrees(t *testing.T) {
	t.Parallel()
	manager, paths, _, reloader := nginxActivationFixture(t)
	before := nginxActivationCandidate(t, paths, 1, 1)
	if _, err := manager.Apply(context.Background(), before); err != nil {
		t.Fatal(err)
	}
	after := nginxActivationCandidate(t, paths, 2, 2)
	reloader.failures = []error{errors.New("new reload"), errors.New("old reload")}
	_, err := manager.Apply(context.Background(), after)
	if !errors.Is(err, ErrNginxReload) || !errors.Is(err, ErrNginxRollback) {
		t.Fatalf("failed rollback error = %v", err)
	}
	active, present, inspectErr := inspectCurrentNginxTree(paths)
	if inspectErr != nil || !present || active.generation != 1 || active.hash != before.ConfigHash() {
		t.Fatalf("failed rollback pointer = %+v %t %v", active, present, inspectErr)
	}
	wantNext, err := newNginxGeneration(paths, 2, after.ConfigHash())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateNginxTree(wantNext.root, wantNext.hash); err != nil {
		t.Fatalf("failed generation snapshot is unavailable: %v", err)
	}
	assertOnlyNginxGeneration(t, paths, active.name, wantNext.name)
	if _, err := manager.Apply(context.Background(), before); !errors.Is(err, ErrNginxTreeConflict) {
		t.Fatalf("uncertain runtime was treated as idempotent: %v", err)
	}

	reloader.failures = nil
	result, err := manager.Apply(context.Background(), after)
	if err != nil || !result.Changed || !result.Reloaded {
		t.Fatalf("reconcile retained candidate = %+v, %v", result, err)
	}
	recovered, present, err := inspectCurrentNginxTree(paths)
	if err != nil || !present || recovered.generation != 2 || recovered.hash != after.ConfigHash() {
		t.Fatalf("recovered active = %+v %t %v", recovered, present, err)
	}
	assertOnlyNginxGeneration(t, paths, recovered.name)
}

func TestNginxActivationDetectsCurrentDriftBeforeParserOrReload(t *testing.T) {
	t.Parallel()
	manager, paths, probe, reloader := nginxActivationFixture(t)
	before := nginxActivationCandidate(t, paths, 1, 1)
	if _, err := manager.Apply(context.Background(), before); err != nil {
		t.Fatal(err)
	}
	active, _, _ := inspectCurrentNginxTree(paths)
	path := filepath.Join(active.root, filepath.FromSlash(NginxRoutesConfigPath))
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(content, []byte("# operator drift\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	probeCount := len(probe.commands)
	_, err = manager.Apply(context.Background(), nginxActivationCandidate(t, paths, 2, 2))
	if !errors.Is(err, ErrNginxTreeDrift) {
		t.Fatalf("drift error = %v", err)
	}
	if len(probe.commands) != probeCount || len(reloader.calls) != 0 {
		t.Fatalf("drift reached parser/reload: probe=%v reload=%v", probe.commands, reloader.calls)
	}
	link, readErr := os.Readlink(NginxActiveRoot(paths))
	if readErr != nil || link != active.link {
		t.Fatalf("drift changed current link = %q, %v", link, readErr)
	}
}

func TestNginxActivationRejectsUnsafeLinkGenerationAndLockState(t *testing.T) {
	t.Parallel()
	manager, paths, _, reloader := nginxActivationFixture(t)
	first := nginxActivationCandidate(t, paths, 2, 1)
	if _, err := manager.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), nginxActivationCandidate(t, paths, 1, 1)); !errors.Is(err, ErrNginxTreeConflict) {
		t.Fatalf("stale generation error = %v", err)
	}
	equalGenerationDifferentTree := nginxActivationCandidate(t, paths, 2, 2)
	if _, err := manager.Apply(context.Background(), equalGenerationDifferentTree); !errors.Is(err, ErrNginxTreeConflict) {
		t.Fatalf("equal-generation conflict error = %v", err)
	}
	if len(reloader.calls) != 0 {
		t.Fatalf("generation conflicts invoked reload: %v", reloader.calls)
	}
	staleLinkCandidate := filepath.Join(NginxGeneratedRoot(paths), ".current-orphan")
	if err := os.WriteFile(staleLinkCandidate, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), nginxActivationCandidate(t, paths, 3, 2)); !errors.Is(err, ErrNginxTreeConflict) {
		t.Fatalf("stale link candidate error = %v", err)
	}
	if err := os.Remove(staleLinkCandidate); err != nil {
		t.Fatal(err)
	}
	staleStage := filepath.Join(NginxGeneratedRoot(paths), NginxGenerationsDirectory, ".stage-orphan")
	if err := os.Mkdir(staleStage, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), nginxActivationCandidate(t, paths, 3, 2)); !errors.Is(err, ErrNginxTreeConflict) {
		t.Fatalf("stale stage error = %v", err)
	}
	if err := os.Remove(staleStage); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(NginxActiveRoot(paths)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/foreign-nginx", NginxActiveRoot(paths)); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), nginxActivationCandidate(t, paths, 3, 2)); !errors.Is(err, ErrNginxTreeDrift) {
		t.Fatalf("escaping active link error = %v", err)
	}
	if err := os.Remove(NginxActiveRoot(paths)); err != nil {
		t.Fatal(err)
	}
	active, _ := newNginxGeneration(paths, 2, first.ConfigHash())
	if err := os.Symlink(active.link, NginxActiveRoot(paths)); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(paths.RuntimeDir, NginxActivationLockName)
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), first); err == nil || !strings.Contains(err.Error(), "lock is unsafe") {
		t.Fatalf("unsafe lock error = %v", err)
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireNginxActivationLock(context.Background(), paths)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseNginxActivationLock(lock)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := manager.Apply(ctx, first); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled lock wait error = %v", err)
	}
}

func TestNginxActivationValidatesCandidateAndConstructorBeforeFilesystemMutation(t *testing.T) {
	t.Parallel()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	probe := &nginxActivationProbe{}
	reloader := &recordingNginxReloader{}
	if _, err := NewNginxActivationManager(paths, nil, reloader); err == nil {
		t.Fatal("constructor accepted nil probe")
	}
	if _, err := NewNginxActivationManager(paths, probe, nil); err == nil {
		t.Fatal("constructor accepted nil reloader")
	}
	dirty := paths
	dirty.ConfigDir += "-other"
	if _, err := NewNginxActivationManager(dirty, probe, reloader); err == nil {
		t.Fatal("constructor accepted inconsistent paths")
	}
	if err := os.MkdirAll(paths.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.RuntimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := NewNginxActivationManager(paths, probe, reloader)
	if err != nil {
		t.Fatal(err)
	}
	candidate := nginxActivationCandidate(t, paths, 1, 1)
	candidate.runtimeDirectory = filepath.Join(paths.RuntimeDir, "wrong")
	if _, err := manager.Apply(context.Background(), candidate); err == nil {
		t.Fatal("manager accepted a candidate for another runtime directory")
	}
	for _, path := range []string{NginxGeneratedRoot(paths), NginxRuntimeDirectory(paths)} {
		if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("invalid candidate created %s: %v", path, err)
		}
	}
	if err := (OSNginxReloadRunner{}).Reload(nil, "/usr/sbin/nginx", "/candidate"); err == nil {
		t.Fatal("OS reloader accepted nil context")
	}
	if err := (OSNginxReloadRunner{}).Reload(context.Background(), "nginx", "/candidate"); err == nil {
		t.Fatal("OS reloader accepted relative binary")
	}
}

func nginxActivationFixture(t *testing.T) (*NginxActivationManager, store.Paths, *nginxActivationProbe, *recordingNginxReloader) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.RuntimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	probe := &nginxActivationProbe{}
	reloader := &recordingNginxReloader{}
	manager, err := NewNginxActivationManager(paths, probe, reloader)
	if err != nil {
		t.Fatal(err)
	}
	return manager, paths, probe, reloader
}

func nginxActivationCandidate(t *testing.T, paths store.Paths, generation uint64, exposeCount int) NginxCandidate {
	t.Helper()
	exposes := make([]model.Expose, 0, exposeCount)
	fixtures := []struct {
		id   string
		path string
		port int
	}{
		{nginxTestExposeA, "/first", 20000},
		{nginxTestExposeB, "/second", 20001},
		{nginxTestExposeC, "/third", 20002},
	}
	if exposeCount > len(fixtures) {
		t.Fatalf("unsupported activation expose count %d", exposeCount)
	}
	for _, fixture := range fixtures[:exposeCount] {
		exposes = append(exposes, nginxExposeFixture(fixture.id, fixture.path, model.RouteExact, fixture.port, model.ExposeReady))
	}
	request := nginxRenderFixture()
	request.StateGeneration = generation
	request.RuntimeDirectory = NginxRuntimeDirectory(paths)
	request.CertificatePath = filepath.Join(paths.StateDir, "secrets", "ingress.crt")
	request.PrivateKeyPath = filepath.Join(paths.StateDir, "secrets", "ingress.key")
	request.Exposes = exposes
	candidate, err := RenderNginxConfig(request)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func assertNginxTreeEqualsCandidate(t *testing.T, root string, candidate NginxCandidate) {
	t.Helper()
	for _, artifact := range candidate.Artifacts() {
		path := filepath.Join(root, filepath.FromSlash(artifact.RelativePath()))
		content, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(content, artifact.Bytes()) {
			t.Fatalf("artifact %s differs: %v", artifact.RelativePath(), err)
		}
		if info, err := os.Stat(path); err != nil {
			t.Fatalf("inspect artifact %s: %v", artifact.RelativePath(), err)
		} else if info.Mode().Perm() != artifact.Mode().Perm() {
			t.Fatalf("artifact %s mode differs: %v", artifact.RelativePath(), info.Mode().Perm())
		}
	}
}

func assertNoStagedNginxTrees(t *testing.T, paths store.Paths) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(NginxGeneratedRoot(paths), NginxGenerationsDirectory, ".stage-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("staged nginx trees remain: %v, %v", matches, err)
	}
}

func assertOnlyNginxGeneration(t *testing.T, paths store.Paths, names ...string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(NginxGeneratedRoot(paths), NginxGenerationsDirectory))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	sortStrings(got)
	want := append([]string(nil), names...)
	sortStrings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("generation directories = %v, want %v", got, want)
	}
}

func sortStrings(values []string) {
	for left := 0; left < len(values); left++ {
		for right := left + 1; right < len(values); right++ {
			if values[right] < values[left] {
				values[left], values[right] = values[right], values[left]
			}
		}
	}
}

type nginxActivationProbe struct {
	mu              sync.Mutex
	commands        []linuxplatform.ProbeCommand
	validationCode  int
	afterValidation func(string) error
}

func (probe *nginxActivationProbe) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	probe.commands = append(probe.commands, command)
	if reflect.DeepEqual(command.Args, []string{"-v"}) {
		return linuxplatform.ProbeResult{Stderr: []byte("nginx version: nginx/1.24.0\n")}, nil
	}
	if len(command.Args) != 5 || command.Args[0] != "-t" || command.Args[1] != "-p" || command.Args[3] != "-c" || command.Args[4] != NginxMainConfigPath {
		return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected nginx validation command")
	}
	root := strings.TrimSuffix(command.Args[2], string(filepath.Separator))
	if probe.afterValidation != nil {
		if err := probe.afterValidation(root); err != nil {
			return linuxplatform.ProbeResult{}, err
		}
	}
	return linuxplatform.ProbeResult{ExitCode: probe.validationCode}, nil
}

type recordingNginxReloader struct {
	mu           sync.Mutex
	calls        []string
	activeHashes []string
	failures     []error
	inspect      func()
}

func (reloader *recordingNginxReloader) Reload(_ context.Context, binaryPath, activeRoot string) error {
	reloader.mu.Lock()
	defer reloader.mu.Unlock()
	reloader.calls = append(reloader.calls, binaryPath+" reload "+activeRoot)
	if reloader.inspect != nil {
		reloader.inspect()
	}
	if len(reloader.failures) == 0 {
		return nil
	}
	err := reloader.failures[0]
	reloader.failures = reloader.failures[1:]
	return err
}
