package controller

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestSystemGatewayHandshakeHostRuntimeCommitsAndRollsBackExactListenerGenerations(t *testing.T) {
	fixture := newSystemHandshakeHostFixture(t)
	manager := fixture.manager(t)

	prepare, err := manager.PlanPrepare(context.Background(), "www.apple.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Prepare(prepare); err != nil {
		t.Fatal(err)
	}
	commit, err := manager.PlanCommit()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Commit(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	assertSystemHandshakeHostLive(t, fixture.paths, "www.apple.com")
	assertNoSystemHandshakeHostStages(t, fixture.paths)
	state, err := fixture.state.Load()
	if err != nil || state.HandshakeHost.Hostname != "www.apple.com" || state.HandshakeHostChange == nil || state.HandshakeHostChange.State != model.HandshakeHostCommitted {
		t.Fatalf("committed state = %+v, %v", state.HandshakeHostChange, err)
	}

	fixture.now = fixture.now.Add(time.Hour)
	rollback, err := manager.PlanRollback()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Rollback(context.Background(), rollback); err != nil {
		t.Fatal(err)
	}
	assertSystemHandshakeHostLive(t, fixture.paths, "www.microsoft.com")
	assertNoSystemHandshakeHostStages(t, fixture.paths)
	state, err = fixture.state.Load()
	if err != nil || state.HandshakeHost.Hostname != "www.microsoft.com" || state.HandshakeHostChange != nil {
		t.Fatalf("rolled-back state = %+v, %v", state.HandshakeHostChange, err)
	}
	if want := []string{"www.apple.com", "www.microsoft.com"}; !reflect.DeepEqual(fixture.runner.restartHosts, want) {
		t.Fatalf("restart generations = %v, want %v", fixture.runner.restartHosts, want)
	}
}

func TestSystemGatewayHandshakeHostRuntimeFailedRestartRestoresBeforeStateWrite(t *testing.T) {
	fixture := newSystemHandshakeHostFixture(t)
	fixture.runner.restartExitCodes = []int{1, 0}
	manager := fixture.manager(t)
	prepare, _ := manager.PlanPrepare(context.Background(), "www.apple.com")
	_, _ = manager.Prepare(prepare)
	commit, _ := manager.PlanCommit()

	if _, err := manager.Commit(context.Background(), commit); err == nil || errors.Is(err, transport.ErrHandshakeHostCommitUncertain) {
		t.Fatalf("recoverable listener restart error = %v", err)
	}
	assertSystemHandshakeHostLive(t, fixture.paths, "www.microsoft.com")
	assertNoSystemHandshakeHostStages(t, fixture.paths)
	state, err := fixture.state.Load()
	if err != nil || state.HandshakeHost.Hostname != "www.microsoft.com" || state.HandshakeHostChange == nil || state.HandshakeHostChange.State != model.HandshakeHostPrepared {
		t.Fatalf("failed commit state = %+v, %v", state.HandshakeHostChange, err)
	}
	if want := []string{"www.apple.com", "www.microsoft.com"}; !reflect.DeepEqual(fixture.runner.restartHosts, want) {
		t.Fatalf("failed restart generations = %v, want %v", fixture.runner.restartHosts, want)
	}
}

func TestSystemGatewayHandshakeHostRuntimeRejectsLiveDriftBeforeStaging(t *testing.T) {
	fixture := newSystemHandshakeHostFixture(t)
	manager := fixture.manager(t)
	prepare, _ := manager.PlanPrepare(context.Background(), "www.apple.com")
	_, _ = manager.Prepare(prepare)
	commit, _ := manager.PlanCommit()
	path := restrictedRuntimeLivePath(fixture.paths, transport.RestrictedConfigFileName)
	if err := os.WriteFile(path, []byte("drift\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := manager.Commit(context.Background(), commit); !errors.Is(err, ErrHandshakeHostRuntimeDrift) {
		t.Fatalf("live drift error = %v", err)
	}
	assertNoSystemHandshakeHostStages(t, fixture.paths)
	if len(fixture.runner.restartHosts) != 0 {
		t.Fatalf("drift restarted listener: %v", fixture.runner.restartHosts)
	}
}

func TestSystemGatewayHandshakeHostRuntimeParserFailureLeavesLiveGeneration(t *testing.T) {
	fixture := newSystemHandshakeHostFixture(t)
	fixture.runner.validationExitCode = 1
	manager := fixture.manager(t)
	prepare, _ := manager.PlanPrepare(context.Background(), "www.apple.com")
	_, _ = manager.Prepare(prepare)
	commit, _ := manager.PlanCommit()

	if _, err := manager.Commit(context.Background(), commit); err == nil || !strings.Contains(err.Error(), "pinned Mihomo rejected") {
		t.Fatalf("parser validation error = %v", err)
	}
	assertSystemHandshakeHostLive(t, fixture.paths, "www.microsoft.com")
	assertNoSystemHandshakeHostStages(t, fixture.paths)
	if len(fixture.runner.restartHosts) != 0 {
		t.Fatalf("invalid candidate restarted listener: %v", fixture.runner.restartHosts)
	}
}

type systemHandshakeHostFixture struct {
	paths   store.Paths
	state   *store.StateStore
	secrets *store.SecretStore
	runner  *systemHandshakeHostRunner
	runtime *SystemGatewayHandshakeHostRuntime
	now     time.Time
}

func newSystemHandshakeHostFixture(t *testing.T) *systemHandshakeHostFixture {
	t.Helper()
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	state.HandshakeHost = &model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1,
		CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: now,
	}
	state.Components.Components = append(state.Components.Components, model.ComponentPin{
		Name: transport.RestrictedProviderName, Version: transport.RestrictedProviderVersion,
		Source: "vpnctl-release-bundle", Bundled: true, SHA256: transport.RestrictedProviderSHA256,
		Capabilities: []string{"tun-routing", "redir-host-split-dns", "shadowsocks-2022-blake3-aes-256-gcm", "shadowtls-v3-strict", "uot-v2"},
	})
	encoded, err := model.EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.StateFile, encoded, store.StateFileMode); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		restrictedRuntimeRoot(paths),
		filepath.Join(paths.StateDir, transport.RestrictedStateRelativePath),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.EnsureGatewayRestrictedCredential(context.Background(), secrets, bytes.NewReader(bytes.Repeat([]byte{0x61}, 64))); err != nil {
		t.Fatal(err)
	}
	publication, err := renderRestrictedRuntimePublication(state, secrets)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range publication {
		if err := os.WriteFile(restrictedRuntimeLivePath(paths, file.name), file.content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &systemHandshakeHostRunner{paths: paths}
	runtime, err := newSystemGatewayHandshakeHostRuntime(paths, stateStore, secrets, runner)
	if err != nil {
		t.Fatal(err)
	}
	return &systemHandshakeHostFixture{paths: paths, state: stateStore, secrets: secrets, runner: runner, runtime: runtime, now: now}
}

func (fixture *systemHandshakeHostFixture) manager(t *testing.T) *transport.HandshakeHostManager {
	t.Helper()
	manager, err := transport.NewHandshakeHostManager(
		fixture.state,
		systemHandshakeHostProber{now: func() time.Time { return fixture.now }},
		fixture.runtime,
		func() time.Time { return fixture.now },
		func() (string, error) { return "40000000-0000-4000-8000-000000000001", nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

type systemHandshakeHostProber struct {
	now func() time.Time
}

func (prober systemHandshakeHostProber) Probe(_ context.Context, candidate transport.HandshakeHostCandidate) transport.HandshakeHostProbeResult {
	return transport.HandshakeHostProbeResult{
		CandidateID: candidate.ID, Hostname: candidate.Hostname, ObservedAt: prober.now(),
		Reachable: true, TLS13: true, CertificateValid: true, Latency: 10 * time.Millisecond, Code: "passed",
	}
}

type systemHandshakeHostRunner struct {
	paths              store.Paths
	validationExitCode int
	restartExitCodes   []int
	restartHosts       []string
}

func (runner *systemHandshakeHostRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	switch {
	case command.Name == filepath.Join(runner.paths.Root, transport.RestrictedBinaryRelativePath) && reflect.DeepEqual(command.Args, []string{"-v"}):
		return linuxplatform.ProbeResult{Stdout: []byte("Mihomo Meta " + transport.RestrictedProviderVersion + " linux amd64\n")}, nil
	case command.Name == filepath.Join(runner.paths.Root, transport.RestrictedBinaryRelativePath) && len(command.Args) == 5 && command.Args[0] == "-t" && command.Args[3] == "-f":
		content, err := os.ReadFile(command.Args[4])
		validHost := strings.Contains(string(content), `dest: "www.apple.com:443"`) || strings.Contains(string(content), `dest: "www.microsoft.com:443"`)
		if err != nil || !validHost {
			return linuxplatform.ProbeResult{}, errors.New("candidate config was not staged for Mihomo validation")
		}
		return linuxplatform.ProbeResult{ExitCode: runner.validationExitCode}, nil
	case command.Name == "systemctl" && reflect.DeepEqual(command.Args, []string{"restart", "vpnctl-restricted.service"}):
		content, err := os.ReadFile(restrictedRuntimeLivePath(runner.paths, transport.RestrictedConfigFileName))
		if err != nil {
			return linuxplatform.ProbeResult{}, err
		}
		host := "www.microsoft.com"
		if strings.Contains(string(content), `dest: "www.apple.com:443"`) {
			host = "www.apple.com"
		}
		runner.restartHosts = append(runner.restartHosts, host)
		if len(runner.restartExitCodes) != 0 {
			exit := runner.restartExitCodes[0]
			runner.restartExitCodes = runner.restartExitCodes[1:]
			return linuxplatform.ProbeResult{ExitCode: exit}, nil
		}
		return linuxplatform.ProbeResult{}, nil
	case command.Name == "systemctl" && reflect.DeepEqual(command.Args, []string{"is-active", "--quiet", "vpnctl-restricted.service"}):
		return linuxplatform.ProbeResult{}, nil
	case command.Name == "ss" && reflect.DeepEqual(command.Args, []string{"-H", "-lunp", "sport = :8443"}):
		return linuxplatform.ProbeResult{}, nil
	case command.Name == "ss" && reflect.DeepEqual(command.Args, []string{"-H", "-ltnp", "sport = :8443"}):
		return linuxplatform.ProbeResult{Stdout: []byte(`LISTEN 0 4096 *:8443 *:* users:(("mihomo",pid=41,fd=7))` + "\n")}, nil
	default:
		return linuxplatform.ProbeResult{}, errors.New("unexpected handshake-host runtime command")
	}
}

func assertSystemHandshakeHostLive(t *testing.T, paths store.Paths, hostname string) {
	t.Helper()
	content, err := os.ReadFile(restrictedRuntimeLivePath(paths, transport.RestrictedConfigFileName))
	if err != nil || !strings.Contains(string(content), `dest: "`+hostname+`:443"`) {
		t.Fatalf("live restricted host = %s, %v", content, err)
	}
}

func assertNoSystemHandshakeHostStages(t *testing.T, paths store.Paths) {
	t.Helper()
	entries, err := os.ReadDir(restrictedRuntimeRoot(paths))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), handshakeHostStagePrefix) {
			t.Fatalf("retained handshake-host stage = %s", entry.Name())
		}
	}
}

var _ transport.HandshakeHostProber = systemHandshakeHostProber{}
var _ linuxplatform.ProbeRunner = (*systemHandshakeHostRunner)(nil)
