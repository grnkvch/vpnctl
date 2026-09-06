package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestSystemNodePurgeDeletesStateBeforeVerifiedBinaryLast(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	paths, _ := store.NewPaths(root)
	for _, directory := range []string{
		paths.ConfigDir, paths.PresetsDir, paths.StateDir, paths.SecretsDir, paths.ExportsDir,
		paths.BackupsDir, paths.RuntimeDir, filepath.Join(root, "etc", "systemd", "system"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(paths.PresetsDir, "telegram.yaml"), []byte("schema_version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(paths.BackupsDir, "portable.backup")
	if err := os.WriteFile(backup, []byte("archive\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	manifest, artifacts, _ := releaseBundleFixture(t)
	bundle := filepath.Join(root, strings.TrimPrefix(ReleaseInstalledBundlePath, "/"))
	if err := os.MkdirAll(filepath.Dir(bundle), 0o700); err != nil {
		t.Fatal(err)
	}
	writeReleaseBundleFile(t, bundle, manifest, artifacts)
	installer, _ := NewReleaseBundleInstaller(root, ReleasePlatform{OperatingSystem: "ubuntu", Version: "24.04", Architecture: "amd64"})
	if _, err := installer.Install(context.Background(), bundle, model.RoleNode); err != nil {
		t.Fatal(err)
	}
	state := initialNodeState("95000000-0000-4000-8000-000000000099", time.Now().UTC().Truncate(time.Second), manifest.ComponentManifest, []string{"192.0.2.53"})
	stateStore, _ := store.NewStateStore(paths)
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
		binaryPath: linuxplatform.DefaultVPNCTLBinaryPath,
	}
	purger, _ := NewPurger(stateStore, runtime)
	plan, err := purger.Plan(context.Background(), PurgeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := purger.Apply(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !result.DataPurged || result.BackupsRemoved || !result.BinaryRemoved || result.InstallerBinaryRetained {
		t.Fatalf("system purge result = %+v", result)
	}
	for _, path := range []string{
		paths.StateFile, paths.PreviousStateFile, paths.ConfigDir,
		filepath.Join(root, "usr", "local", "bin", "vpnctl"), filepath.Join(root, "usr", "local", "libexec", "vpnctl", "mihomo"),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("purged path remains %s: %v", path, err)
		}
	}
	if content, err := os.ReadFile(backup); err != nil || string(content) != "archive\n" {
		t.Fatalf("default purge removed portable backup: %q, %v", content, err)
	}
	entries, err := os.ReadDir(paths.StateDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(paths.BackupsDir) {
		t.Fatalf("purge retained hidden managed data: %v, %v", entries, err)
	}
	if _, err := os.Lstat(bundle); err != nil {
		t.Fatalf("purge removed non-state release archive: %v", err)
	}
}

func TestSystemPurgeRemovesAllManagedDataAndPreservesArchivesOnlyByDefault(t *testing.T) {
	for _, includeBackups := range []bool{false, true} {
		includeBackups := includeBackups
		t.Run(map[bool]string{false: "preserve-backups", true: "include-backups"}[includeBackups], func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			paths, err := store.NewPaths(root)
			if err != nil {
				t.Fatal(err)
			}
			for _, directory := range []string{paths.ConfigDir, paths.PresetsDir, paths.StateDir, paths.SecretsDir, paths.ExportsDir, paths.BackupsDir, paths.SnapshotsDir, paths.OperationsDir} {
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for path, content := range map[string][]byte{
				filepath.Join(paths.PresetsDir, "telegram.yaml"):   []byte("schema_version: 1\n"),
				filepath.Join(paths.SecretsDir, "identity"):        []byte("secret\n"),
				filepath.Join(paths.ExportsDir, "client.conf"):     []byte("profile\n"),
				filepath.Join(paths.SnapshotsDir, "update.json"):   []byte("snapshot\n"),
				filepath.Join(paths.OperationsDir, "record.json"):  []byte("operation\n"),
				filepath.Join(paths.BackupsDir, "portable.backup"): []byte("archive\n"),
			} {
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			state := initialNodeState("95000000-0000-4000-8000-000000000001", time.Now().UTC().Truncate(time.Second), gatewayTestManifest(), []string{"192.0.2.53"})
			stateStore, _ := store.NewStateStore(paths)
			if err := stateStore.Save(0, state); err != nil {
				t.Fatal(err)
			}
			runtime := &SystemUninstallRuntime{paths: paths, state: stateStore}
			plan, err := runtime.InspectPurge(context.Background(), state, includeBackups)
			if err != nil || plan.BackupArchives != 1 {
				t.Fatalf("InspectPurge() = %+v, %v", plan, err)
			}
			dataPurged, backupsRemoved, err := runtime.RemovePurgedData(context.Background(), plan)
			if err != nil || !dataPurged || backupsRemoved != includeBackups {
				t.Fatalf("RemovePurgedData() = %t/%t, %v", dataPurged, backupsRemoved, err)
			}
			if _, err := os.Lstat(paths.ConfigDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("config survived purge: %v", err)
			}
			if _, err := os.Lstat(paths.StateFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("authoritative state survived purge: %v", err)
			}
			backup := filepath.Join(paths.BackupsDir, "portable.backup")
			if _, err := os.Lstat(backup); includeBackups && !errors.Is(err, os.ErrNotExist) || !includeBackups && err != nil {
				t.Fatalf("backup retention include=%t error=%v", includeBackups, err)
			}
			if includeBackups {
				if _, err := os.Lstat(paths.StateDir); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("state directory survived full purge: %v", err)
				}
			} else {
				entries, err := os.ReadDir(paths.StateDir)
				if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(paths.BackupsDir) {
					t.Fatalf("default purge retained hidden state: %v, %v", entries, err)
				}
			}
		})
	}
}

func TestSystemPurgeRejectsUnsafeManagedBackupEntryBeforeDeletion(t *testing.T) {
	root := t.TempDir()
	paths, _ := store.NewPaths(root)
	for _, directory := range []string{paths.ConfigDir, paths.StateDir, paths.BackupsDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := initialNodeState("95000000-0000-4000-8000-000000000002", time.Now().UTC().Truncate(time.Second), gatewayTestManifest(), []string{"192.0.2.53"})
	stateStore, _ := store.NewStateStore(paths)
	if err := stateStore.Save(0, state); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../state.json", filepath.Join(paths.BackupsDir, "unsafe.backup")); err != nil {
		t.Fatal(err)
	}
	runtime := &SystemUninstallRuntime{paths: paths, state: stateStore}
	if _, err := runtime.InspectPurge(context.Background(), state, true); err == nil {
		t.Fatal("unsafe backup symlink was accepted")
	}
	if _, err := os.Lstat(paths.StateFile); err != nil {
		t.Fatalf("failed preflight changed state: %v", err)
	}
}
