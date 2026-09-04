package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestFRPClientConfigurationInitialInstallAndIdempotenceAreAtomic(t *testing.T) {
	t.Parallel()

	manager, paths, probe, reloader := frpClientConfigurationFixture(t)
	request := frpClientConfigurationRequest(t, 1)
	result, err := manager.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || !result.Initial || result.Reloaded || result.PreviousMappingCount != 0 || result.MappingCount != 1 || len(result.ConfigHash) != 64 {
		t.Fatalf("initial result = %+v", result)
	}
	configPath, binaryPath := frpServicePaths(paths, model.RoleNode)
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(content)
	if _, err := parseFRPClientConfig(content); err != nil {
		t.Fatalf("installed config is invalid: %v", err)
	}
	info, err := os.Stat(configPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("installed config mode = %v err=%v", info.Mode().Perm(), err)
	}
	if len(probe.calls) != 2 || probe.calls[0] != binaryPath+" --version" || !strings.HasPrefix(probe.calls[1], binaryPath+" verify -c ") {
		t.Fatalf("initial native validation calls = %v", probe.calls)
	}
	if len(reloader.calls) != 0 {
		t.Fatalf("initial install invoked reload: %v", reloader.calls)
	}
	assertNoFRPClientTransactionFiles(t, configPath)

	probeCalls := len(probe.calls)
	result, err = manager.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || result.Initial || result.Reloaded || result.PreviousMappingCount != 1 || result.MappingCount != 1 {
		t.Fatalf("idempotent result = %+v", result)
	}
	if len(probe.calls) != probeCalls || len(reloader.calls) != 0 {
		t.Fatalf("idempotent apply invoked external commands: probe=%v reload=%v", probe.calls, reloader.calls)
	}
}

func TestFRPClientConfigurationAddsAndRemovesMappingsThroughLoopbackReload(t *testing.T) {
	t.Parallel()

	manager, paths, _, reloader := frpClientConfigurationFixture(t)
	if _, err := manager.Apply(context.Background(), frpClientConfigurationRequest(t, 1)); err != nil {
		t.Fatal(err)
	}
	configPath, binaryPath := frpServicePaths(paths, model.RoleNode)
	reloader.inspect = func(path string) {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			return
		}
		defer clear(content)
		document, err := parseFRPClientConfig(content)
		if err != nil {
			t.Error(err)
			return
		}
		reloader.mappingCounts = append(reloader.mappingCounts, len(document.Mappings))
	}

	result, err := manager.Apply(context.Background(), frpClientConfigurationRequest(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Initial || !result.Reloaded || result.PreviousMappingCount != 1 || result.MappingCount != 2 {
		t.Fatalf("add result = %+v", result)
	}
	result, err = manager.Apply(context.Background(), frpClientConfigurationRequest(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Initial || !result.Reloaded || result.PreviousMappingCount != 2 || result.MappingCount != 1 {
		t.Fatalf("remove result = %+v", result)
	}
	wantCall := binaryPath + " reload -c " + configPath
	if fmt.Sprint(reloader.calls) != fmt.Sprint([]string{wantCall, wantCall}) || fmt.Sprint(reloader.mappingCounts) != fmt.Sprint([]int{2, 1}) {
		t.Fatalf("reload observations = calls:%v mappings:%v", reloader.calls, reloader.mappingCounts)
	}
	assertNoFRPClientTransactionFiles(t, configPath)
}

func TestFRPClientConfigurationRejectsCommonSettingChangeBeforeMutation(t *testing.T) {
	t.Parallel()

	manager, paths, probe, reloader := frpClientConfigurationFixture(t)
	if _, err := manager.Apply(context.Background(), frpClientConfigurationRequest(t, 1)); err != nil {
		t.Fatal(err)
	}
	configPath, _ := frpServicePaths(paths, model.RoleNode)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	request := frpClientConfigurationRequest(t, 2)
	request.Plan.ServerEndpoint = netip.MustParseAddrPort("10.67.0.2:17000")
	probeCalls := len(probe.calls)
	_, err = manager.Apply(context.Background(), request)
	if !errors.Is(err, ErrFRPClientConfigurationConflict) {
		t.Fatalf("common-setting error = %v", err)
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	defer clear(after)
	if !bytes.Equal(before, after) || len(probe.calls) != probeCalls || len(reloader.calls) != 0 {
		t.Fatalf("rejected common change mutated config or invoked commands: probe=%v reload=%v", probe.calls, reloader.calls)
	}
	assertNoFRPClientTransactionFiles(t, configPath)
}

func TestFRPClientConfigurationRejectsPinnedValidationBeforeActivation(t *testing.T) {
	t.Parallel()

	manager, paths, probe, reloader := frpClientConfigurationFixture(t)
	probe.validationCode = 1
	configPath, _ := frpServicePaths(paths, model.RoleNode)
	_, err := manager.Apply(context.Background(), frpClientConfigurationRequest(t, 1))
	if err == nil || err.Error() != "validate staged tunnel client configuration" {
		t.Fatalf("pinned validation error = %v", err)
	}
	if _, statErr := os.Lstat(configPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("invalid candidate reached active path: %v", statErr)
	}
	if len(reloader.calls) != 0 {
		t.Fatal("invalid candidate invoked reload")
	}
	assertNoFRPClientTransactionFiles(t, configPath)
}

func TestFRPClientConfigurationValidatesRequestBeforeCreatingTransactionResources(t *testing.T) {
	t.Parallel()

	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.ConfigDir, 0o700); err != nil {
		t.Fatal(err)
	}
	provider, err := NewFRPProvider(paths.Root, testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewFRPClientConfigurationManager(paths, provider, &frpServiceProbe{}, &recordingFRPClientReloader{})
	if err != nil {
		t.Fatal(err)
	}
	request := frpClientConfigurationRequest(t, 1)
	request.Plan.HostRole = model.RoleGateway
	if _, err := manager.Apply(context.Background(), request); err == nil {
		t.Fatal("manager accepted a gateway candidate")
	}
	for _, path := range []string{filepath.Join(paths.ConfigDir, "generated"), paths.RuntimeDir} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("invalid request created %s: %v", path, statErr)
		}
	}
}

func TestFRPClientConfigurationReloadFailureRestoresFileAndRuntime(t *testing.T) {
	t.Parallel()

	manager, paths, _, reloader := frpClientConfigurationFixture(t)
	if _, err := manager.Apply(context.Background(), frpClientConfigurationRequest(t, 1)); err != nil {
		t.Fatal(err)
	}
	configPath, binaryPath := frpServicePaths(paths, model.RoleNode)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	reloader.failures = []error{errors.New("reload-secret-canary"), nil}
	_, err = manager.Apply(context.Background(), frpClientConfigurationRequest(t, 2))
	if !errors.Is(err, ErrFRPClientReload) || errors.Is(err, ErrFRPClientRollback) || strings.Contains(err.Error(), "canary") {
		t.Fatalf("reload failure = %v", err)
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	defer clear(after)
	wantCall := binaryPath + " reload -c " + configPath
	if !bytes.Equal(before, after) || fmt.Sprint(reloader.calls) != fmt.Sprint([]string{wantCall, wantCall}) {
		t.Fatalf("rollback = content_equal:%t calls:%v", bytes.Equal(before, after), reloader.calls)
	}
	assertNoFRPClientTransactionFiles(t, configPath)
}

func TestFRPClientConfigurationReportsFailedRuntimeRollbackAndRetainsSnapshot(t *testing.T) {
	t.Parallel()

	manager, paths, _, reloader := frpClientConfigurationFixture(t)
	if _, err := manager.Apply(context.Background(), frpClientConfigurationRequest(t, 1)); err != nil {
		t.Fatal(err)
	}
	configPath, _ := frpServicePaths(paths, model.RoleNode)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	reloader.failures = []error{errors.New("new reload"), errors.New("old reload")}
	_, err = manager.Apply(context.Background(), frpClientConfigurationRequest(t, 2))
	if !errors.Is(err, ErrFRPClientReload) || !errors.Is(err, ErrFRPClientRollback) {
		t.Fatalf("rollback failure = %v", err)
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("failed runtime rollback did not restore the authoritative file")
	}
	if info, statErr := os.Stat(configPath + ".previous"); statErr != nil {
		t.Fatalf("failed rollback did not retain recovery snapshot: %v", statErr)
	} else if info.Mode().Perm() != 0o600 {
		t.Fatalf("recovery snapshot mode = %v", info.Mode().Perm())
	}
	if _, repeatErr := manager.Apply(context.Background(), frpClientConfigurationRequest(t, 1)); !errors.Is(repeatErr, ErrFRPClientConfigurationConflict) {
		t.Fatalf("unreconciled snapshot repeat error = %v", repeatErr)
	}
}

func TestFRPClientConfigurationRejectsUnsafeFilesAndCanceledLockWait(t *testing.T) {
	t.Parallel()

	manager, paths, _, reloader := frpClientConfigurationFixture(t)
	configPath, _ := frpServicePaths(paths, model.RoleNode)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(paths.Root, "foreign-config")
	if err := os.WriteFile(target, []byte("secret-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, configPath); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), frpClientConfigurationRequest(t, 1)); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink current config error = %v", err)
	}
	if len(reloader.calls) != 0 {
		t.Fatal("unsafe current config invoked reload")
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(paths.RuntimeDir, FRPClientConfigurationLockName)
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), frpClientConfigurationRequest(t, 1)); err == nil || !strings.Contains(err.Error(), "lock is unsafe") {
		t.Fatalf("unsafe lock error = %v", err)
	}
	if err := os.Chmod(lockPath, 0o600); err != nil {
		t.Fatal(err)
	}

	lock, err := acquireFRPClientConfigurationLock(context.Background(), paths)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseFRPClientConfigurationLock(lock)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := manager.Apply(ctx, frpClientConfigurationRequest(t, 1)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled lock wait error = %v", err)
	}
}

func TestFRPClientConfigurationConstructorRejectsIncompleteDependencies(t *testing.T) {
	t.Parallel()

	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewFRPProvider(paths.Root, testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	probe := &frpServiceProbe{}
	reloader := &recordingFRPClientReloader{}
	if _, err := NewFRPClientConfigurationManager(paths, nil, probe, reloader); err == nil {
		t.Fatal("constructor accepted nil provider")
	}
	if _, err := NewFRPClientConfigurationManager(paths, provider, nil, reloader); err == nil {
		t.Fatal("constructor accepted nil probe")
	}
	if _, err := NewFRPClientConfigurationManager(paths, provider, probe, nil); err == nil {
		t.Fatal("constructor accepted nil reloader")
	}
}

func frpClientConfigurationFixture(t *testing.T) (*FRPClientConfigurationManager, store.Paths, *frpServiceProbe, *recordingFRPClientReloader) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{paths.ConfigDir, paths.RuntimeDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	provider, err := NewFRPProvider(paths.Root, testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	probe := &frpServiceProbe{}
	reloader := &recordingFRPClientReloader{}
	manager, err := NewFRPClientConfigurationManager(paths, provider, probe, reloader)
	if err != nil {
		t.Fatal(err)
	}
	return manager, paths, probe, reloader
}

func frpClientConfigurationRequest(t *testing.T, mappings int) RenderRequest {
	t.Helper()
	session := testFRPSession(t)
	if mappings < 0 || mappings > len(session.Mappings) {
		t.Fatalf("invalid mapping fixture count %d", mappings)
	}
	session.Mappings = session.Mappings[:mappings]
	return RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: testNodeHostID, Generation: uint64(mappings + 1),
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{session},
	}}
}

func assertNoFRPClientTransactionFiles(t *testing.T, configPath string) {
	t.Helper()
	if _, err := os.Lstat(configPath + ".previous"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback snapshot remains: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(configPath), ".vpnctl-tunnel-client-*.next"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("staged tunnel configs remain: %v err=%v", matches, err)
	}
}

type recordingFRPClientReloader struct {
	mu            sync.Mutex
	calls         []string
	mappingCounts []int
	failures      []error
	inspect       func(string)
}

func (runner *recordingFRPClientReloader) Reload(_ context.Context, binaryPath, configPath string) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.calls = append(runner.calls, binaryPath+" reload -c "+configPath)
	if runner.inspect != nil {
		runner.inspect(configPath)
	}
	if len(runner.failures) == 0 {
		return nil
	}
	err := runner.failures[0]
	runner.failures = runner.failures[1:]
	return err
}
