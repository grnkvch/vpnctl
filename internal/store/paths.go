package store

import (
	"fmt"
	"path/filepath"
)

type Paths struct {
	Root string

	ConfigDir  string
	PresetsDir string

	StateDir          string
	StateFile         string
	PreviousStateFile string
	SecretsDir        string
	ExportsDir        string
	ClientExportsDir  string
	BackupsDir        string
	SnapshotsDir      string
	OperationsDir     string

	RuntimeDir    string
	ControlSocket string
	StateLock     string
}

func DefaultPaths() Paths {
	paths, err := NewPaths("/")
	if err != nil {
		panic(err)
	}
	return paths
}

func NewPaths(root string) (Paths, error) {
	if root == "" {
		return Paths{}, fmt.Errorf("system path root is required")
	}
	if !filepath.IsAbs(root) {
		return Paths{}, fmt.Errorf("system path root must be absolute")
	}
	root = filepath.Clean(root)
	configDir := filepath.Join(root, "etc", "vpnctl")
	stateDir := filepath.Join(root, "var", "lib", "vpnctl")
	runtimeDir := filepath.Join(root, "run", "vpnctl")
	return Paths{
		Root: root,

		ConfigDir:  configDir,
		PresetsDir: filepath.Join(configDir, "presets.d"),

		StateDir:          stateDir,
		StateFile:         filepath.Join(stateDir, "state.json"),
		PreviousStateFile: filepath.Join(stateDir, "state.previous.json"),
		SecretsDir:        filepath.Join(stateDir, "secrets"),
		ExportsDir:        filepath.Join(stateDir, "exports"),
		ClientExportsDir:  filepath.Join(stateDir, "exports", "clients"),
		BackupsDir:        filepath.Join(stateDir, "backups"),
		SnapshotsDir:      filepath.Join(stateDir, "snapshots"),
		OperationsDir:     filepath.Join(stateDir, "operations"),

		RuntimeDir:    runtimeDir,
		ControlSocket: filepath.Join(runtimeDir, "control.sock"),
		StateLock:     filepath.Join(runtimeDir, "state.lock"),
	}, nil
}
