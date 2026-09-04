package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestSystemGatewayUninstallRestoresOriginalNetworkAndPreservesRecoveryState(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		paths.ConfigDir, paths.PresetsDir, paths.StateDir, paths.SecretsDir, paths.ExportsDir,
		paths.BackupsDir, paths.RuntimeDir, filepath.Join(root, "etc", "systemd", "system"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string][]byte{
		filepath.Join(paths.PresetsDir, "telegram.yaml"): []byte("schema_version: 1\n"),
		filepath.Join(paths.SecretsDir, "sentinel"):      []byte("secret\n"),
		filepath.Join(paths.ExportsDir, "sentinel"):      []byte("export\n"),
		filepath.Join(paths.BackupsDir, "sentinel"):      []byte("backup\n"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, artifacts, _ := releaseBundleFixture(t)
	bundle := filepath.Join(root, strings.TrimPrefix(ReleaseInstalledBundlePath, "/"))
	if err := os.MkdirAll(filepath.Dir(bundle), 0o700); err != nil {
		t.Fatal(err)
	}
	writeReleaseBundleFile(t, bundle, manifest, privateKey, artifacts)
	releaseInstaller, _ := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	if _, err := releaseInstaller.Install(context.Background(), bundle, model.RoleGateway); err != nil {
		t.Fatal(err)
	}

	state := uninstallGatewayState(t)
	state.Components = manifest.ComponentManifest
	state.HandshakeHost.ListVersion = manifest.ComponentManifest.HandshakeHostListVersion
	stateStore, _ := store.NewStateStore(paths)
	if err := stateStore.Save(0, state); err != nil {
		t.Fatal(err)
	}
	runner := &uninstallSystemProbeRunner{}
	roles, _ := linuxplatform.NewRoleSystemdInstaller(root, paths.ConfigDir, runner)
	request, _ := linuxplatform.RenderGatewayRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	if _, err := roles.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	nginxRoot := ingress.NginxGeneratedRoot(paths)
	if err := os.MkdirAll(nginxRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nginxRoot, "sentinel.conf"), []byte("managed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	watchdog, _ := linuxplatform.NewWatchdogUnitInstaller(root, runner)
	watchdogInstall, _ := watchdog.Plan(linuxplatform.DefaultVPNCTLBinaryPath)
	if _, err := watchdog.Apply(context.Background(), watchdogInstall); err != nil {
		t.Fatal(err)
	}
	network, _ := linuxplatform.NewNetworkManager(runner)
	snapshot := linuxplatform.NetworkSnapshot{
		SchemaVersion: linuxplatform.NetworkSnapshotSchemaVersion,
		Routes:        []linuxplatform.Route{}, PolicyRules: []linuxplatform.PolicyRule{}, Sysctls: []linuxplatform.SysctlSnapshot{},
	}
	runtime := &SystemUninstallRuntime{
		paths: paths, state: stateStore, runner: runner, roles: roles, watchdog: watchdog,
		watchdogDB: &uninstallWatchdogStoreFixture{ids: []string{"fw-ABC123"}, snapshot: snapshot},
		network:    network, binaryPath: linuxplatform.DefaultVPNCTLBinaryPath, releaseKey: publicKey,
	}
	uninstaller, _ := NewUninstaller(stateStore, runtime)
	plan, err := uninstaller.Plan(context.Background(), UninstallOptions{Force: true})
	if err != nil || plan.Blocked || len(plan.ActiveNodeIDs) != 1 {
		t.Fatalf("gateway uninstall plan = %+v, %v", plan, err)
	}
	callStart := len(runner.calls)
	result, err := uninstaller.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.BinaryRemoved || !result.NetworkRestored || result.DNSRestored || result.InstallerBinaryRetained {
		t.Fatalf("gateway uninstall result = %+v", result)
	}
	for _, relative := range []string{"usr/local/bin/vpnctl", "usr/local/libexec/vpnctl/mihomo", "usr/local/libexec/vpnctl/frps"} {
		if _, err := os.Lstat(filepath.Join(root, relative)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("gateway runtime component remains %s: %v", relative, err)
		}
	}
	for _, path := range []string{
		paths.StateFile, bundle, filepath.Join(paths.PresetsDir, "telegram.yaml"), filepath.Join(paths.SecretsDir, "sentinel"),
		filepath.Join(paths.ExportsDir, "sentinel"), filepath.Join(paths.BackupsDir, "sentinel"),
	} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("gateway recoverable uninstall removed %s: %v", path, err)
		}
	}
	joined := strings.Join(runner.calls[callStart:], "\n")
	for _, required := range []string{
		"systemctl stop vpnctl-watchdog@fw-ABC123.timer",
		"systemctl stop vpnctl-controller.service", "systemctl stop nginx.service",
		"ip -4 route flush table 20001", "systemctl daemon-reload",
	} {
		if !strings.Contains(joined, required) {
			t.Errorf("gateway uninstall calls missing %q:\n%s", required, joined)
		}
	}
	if controllerStop, standardStop := strings.Index(joined, "systemctl stop vpnctl-controller.service"), strings.Index(joined, "systemctl stop vpnctl-standard.service"); controllerStop < 0 || standardStop < 0 || controllerStop > standardStop {
		t.Fatalf("gateway controller was not stopped first:\n%s", joined)
	}
}

func TestSystemNodeUninstallRemovesVerifiedRuntimeAndPreservesRecoveryState(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		paths.ConfigDir, paths.PresetsDir, paths.StateDir, paths.SecretsDir, paths.ExportsDir,
		paths.BackupsDir, paths.RuntimeDir, filepath.Join(root, "etc", "systemd", "system"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string][]byte{
		filepath.Join(paths.PresetsDir, "telegram.yaml"): []byte("schema_version: 1\n"),
		filepath.Join(paths.SecretsDir, "sentinel"):      []byte("secret\n"),
		filepath.Join(paths.ExportsDir, "sentinel"):      []byte("export\n"),
		filepath.Join(paths.BackupsDir, "sentinel"):      []byte("backup\n"),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, artifacts, _ := releaseBundleFixture(t)
	bundle := filepath.Join(root, strings.TrimPrefix(ReleaseInstalledBundlePath, "/"))
	if err := os.MkdirAll(filepath.Dir(bundle), 0o700); err != nil {
		t.Fatal(err)
	}
	writeReleaseBundleFile(t, bundle, manifest, privateKey, artifacts)
	releaseInstaller, err := NewReleaseBundleInstaller(root, publicKey, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := releaseInstaller.Install(context.Background(), bundle, model.RoleNode); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	state := initialNodeState("94000000-0000-4000-8000-000000000001", now, manifest.ComponentManifest, []string{"192.0.2.53"})
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := stateStore.Save(0, state); err != nil {
		t.Fatal(err)
	}
	runner := &uninstallSystemProbeRunner{}
	roles, _ := linuxplatform.NewRoleSystemdInstaller(root, paths.ConfigDir, runner)
	request, _ := linuxplatform.RenderNodeRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	if _, err := roles.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	dns, _ := routing.NewNodeDNSIntegrationManager(paths, runner)
	guard, _ := routing.NewPersistentNodeRoutingGuardManager(paths, runner)
	runtime := &SystemUninstallRuntime{
		paths: paths, state: stateStore, runner: runner, roles: roles, dns: dns, guard: guard,
		binaryPath: linuxplatform.DefaultVPNCTLBinaryPath, releaseKey: publicKey,
	}
	uninstaller, _ := NewUninstaller(stateStore, runtime)
	plan, err := uninstaller.Plan(context.Background(), UninstallOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := uninstaller.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.BinaryRemoved || result.DNSRestored || result.NetworkRestored || result.InstallerBinaryRetained {
		t.Fatalf("uninstall result = %+v", result)
	}
	for _, relative := range []string{"usr/local/bin/vpnctl", "usr/local/libexec/vpnctl/mihomo", "usr/local/libexec/vpnctl/frpc"} {
		if _, err := os.Lstat(filepath.Join(root, relative)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("runtime component remains %s: %v", relative, err)
		}
	}
	for _, path := range []string{
		paths.StateFile, bundle, filepath.Join(paths.PresetsDir, "telegram.yaml"), filepath.Join(paths.SecretsDir, "sentinel"),
		filepath.Join(paths.ExportsDir, "sentinel"), filepath.Join(paths.BackupsDir, "sentinel"),
	} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("recoverable uninstall removed %s: %v", path, err)
		}
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "systemctl stop vpnctl-routing-guard.service") || !strings.Contains(joined, "systemctl daemon-reload") {
		t.Fatalf("uninstall service sequence is incomplete:\n%s", joined)
	}
}

type uninstallSystemProbeRunner struct{ calls []string }

type uninstallWatchdogStoreFixture struct {
	ids      []string
	snapshot linuxplatform.NetworkSnapshot
}

func (fixture *uninstallWatchdogStoreFixture) TransactionIDs() ([]string, error) {
	return append([]string(nil), fixture.ids...), nil
}

func (fixture *uninstallWatchdogStoreFixture) InitialNetworkSnapshot() (linuxplatform.NetworkSnapshot, error) {
	return fixture.snapshot, nil
}

func (runner *uninstallSystemProbeRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	key := strings.Join(append([]string{command.Name}, command.Args...), " ")
	runner.calls = append(runner.calls, key)
	switch {
	case key == "nft --json list tables":
		return linuxplatform.ProbeResult{Stdout: []byte(`{"nftables":[]}`)}, nil
	case strings.HasPrefix(key, "nft --stateless -nn list table "):
		return linuxplatform.ProbeResult{ExitCode: 1, Stderr: []byte("No such file or directory")}, nil
	case strings.HasPrefix(key, "ip -json -4 route show table "), strings.HasPrefix(key, "ip -json -6 route show table "),
		key == "ip -json -4 rule show", key == "ip -json -6 rule show":
		return linuxplatform.ProbeResult{Stdout: []byte(`[]`)}, nil
	default:
		return linuxplatform.ProbeResult{}, nil
	}
}
