package store

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestDefaultPaths(t *testing.T) {
	paths := DefaultPaths()
	want := Paths{
		Root: "/",

		ConfigDir:  "/etc/vpnctl",
		PresetsDir: "/etc/vpnctl/presets.d",

		StateDir:          "/var/lib/vpnctl",
		StateFile:         "/var/lib/vpnctl/state.json",
		PreviousStateFile: "/var/lib/vpnctl/state.previous.json",
		SecretsDir:        "/var/lib/vpnctl/secrets",
		ExportsDir:        "/var/lib/vpnctl/exports",
		ClientExportsDir:  "/var/lib/vpnctl/exports/clients",
		BackupsDir:        "/var/lib/vpnctl/backups",
		SnapshotsDir:      "/var/lib/vpnctl/snapshots",
		OperationsDir:     "/var/lib/vpnctl/operations",

		RuntimeDir:    "/run/vpnctl",
		ControlSocket: "/run/vpnctl/control.sock",
		StateLock:     "/run/vpnctl/state.lock",
	}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("DefaultPaths()\nwant: %#v\n got: %#v", want, paths)
	}
}

func TestPathsAreIndependentOfWorkingDirectory(t *testing.T) {
	firstDirectory := t.TempDir()
	secondDirectory := t.TempDir()

	t.Chdir(firstDirectory)
	first := DefaultPaths()
	t.Chdir(secondDirectory)
	second := DefaultPaths()

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("paths changed with cwd\nfirst:  %#v\nsecond: %#v", first, second)
	}
	if first.StateFile != "/var/lib/vpnctl/state.json" || first.ConfigDir != "/etc/vpnctl" || first.RuntimeDir != "/run/vpnctl" {
		t.Fatalf("unexpected system paths: %#v", first)
	}
}

func TestNewPathsUsesExplicitTestRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixture-root")
	paths, err := NewPaths(root)
	if err != nil {
		t.Fatalf("NewPaths() error = %v", err)
	}
	if paths.Root != root {
		t.Fatalf("Root = %q, want %q", paths.Root, root)
	}
	want := map[string]string{
		"config":  filepath.Join(root, "etc", "vpnctl"),
		"presets": filepath.Join(root, "etc", "vpnctl", "presets.d"),
		"state":   filepath.Join(root, "var", "lib", "vpnctl", "state.json"),
		"secrets": filepath.Join(root, "var", "lib", "vpnctl", "secrets"),
		"exports": filepath.Join(root, "var", "lib", "vpnctl", "exports"),
		"backups": filepath.Join(root, "var", "lib", "vpnctl", "backups"),
		"runtime": filepath.Join(root, "run", "vpnctl"),
		"socket":  filepath.Join(root, "run", "vpnctl", "control.sock"),
	}
	got := map[string]string{
		"config":  paths.ConfigDir,
		"presets": paths.PresetsDir,
		"state":   paths.StateFile,
		"secrets": paths.SecretsDir,
		"exports": paths.ExportsDir,
		"backups": paths.BackupsDir,
		"runtime": paths.RuntimeDir,
		"socket":  paths.ControlSocket,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NewPaths()\nwant: %#v\n got: %#v", want, got)
	}
}

func TestNewPathsRejectsImplicitOrRelativeRoots(t *testing.T) {
	tests := []string{"", ".", "fixture", filepath.Join("fixture", "root")}
	for _, root := range tests {
		root := root
		t.Run(root, func(t *testing.T) {
			if _, err := NewPaths(root); err == nil {
				t.Fatalf("NewPaths(%q) error = nil", root)
			}
		})
	}
}

func TestNewPathsCleansExplicitRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "parent", "..", "fixture")
	paths, err := NewPaths(root)
	if err != nil {
		t.Fatalf("NewPaths() error = %v", err)
	}
	if paths.Root != filepath.Clean(root) {
		t.Fatalf("Root = %q, want clean %q", paths.Root, filepath.Clean(root))
	}
	if !filepath.IsAbs(paths.StateFile) {
		t.Fatalf("StateFile is relative: %q", paths.StateFile)
	}
}
