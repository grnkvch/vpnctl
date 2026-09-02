package lifecycle

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/vgrinkevich/vpnctl/internal/store"
)

var ErrNodeLayoutConflict = errors.New("node initialization paths already exist without authoritative state")

type NodeLayoutDirectory struct {
	Path string
	Mode os.FileMode
}

type NodeLayoutPlan struct {
	Directories      []NodeLayoutDirectory
	AuthoritativeDir string
}

type NodeLayoutInstaller struct {
	paths store.Paths
}

func NewNodeLayoutInstaller(paths store.Paths) (*NodeLayoutInstaller, error) {
	if !filepath.IsAbs(paths.Root) || filepath.Clean(paths.Root) != paths.Root {
		return nil, fmt.Errorf("node layout root must be clean and absolute")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil {
		return nil, err
	}
	if paths != want {
		return nil, fmt.Errorf("node layout paths do not match the system root")
	}
	return &NodeLayoutInstaller{paths: paths}, nil
}

// PlanFresh claims only vpnctl-owned roots. Unlike the dedicated gateway
// layout, a private node does not create preset, export, backup, PKI, or
// watchdog trees during role-only initialization.
func (installer *NodeLayoutInstaller) PlanFresh() (NodeLayoutPlan, error) {
	if installer == nil {
		return NodeLayoutPlan{}, fmt.Errorf("node layout installer is required")
	}
	for _, root := range []string{installer.paths.ConfigDir, installer.paths.StateDir, installer.paths.RuntimeDir} {
		if _, err := os.Lstat(root); err == nil {
			return NodeLayoutPlan{}, fmt.Errorf("%w: %s", ErrNodeLayoutConflict, root)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return NodeLayoutPlan{}, fmt.Errorf("inspect node layout root %s: %w", root, err)
		}
	}
	return NodeLayoutPlan{
		Directories: []NodeLayoutDirectory{
			{Path: installer.paths.ConfigDir, Mode: 0o755},
			{Path: installer.paths.StateDir, Mode: 0o700},
			{Path: installer.paths.SecretsDir, Mode: 0o700},
			{Path: installer.paths.SnapshotsDir, Mode: 0o700},
			{Path: installer.paths.OperationsDir, Mode: 0o700},
			{Path: installer.paths.RuntimeDir, Mode: 0o700},
		},
		AuthoritativeDir: installer.paths.StateDir,
	}, nil
}

func (installer *NodeLayoutInstaller) Apply(plan NodeLayoutPlan) ([]string, error) {
	want, err := installer.PlanFresh()
	if err != nil {
		return nil, err
	}
	if !equalNodeLayoutPlans(plan, want) {
		return nil, fmt.Errorf("node layout plan does not match the selected system root")
	}
	for _, parent := range []string{
		filepath.Dir(installer.paths.ConfigDir), filepath.Dir(installer.paths.StateDir), filepath.Dir(installer.paths.RuntimeDir),
	} {
		info, err := os.Lstat(parent)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("node layout parent %s must be a real existing directory", parent)
		}
	}
	changed := make([]string, 0, len(plan.Directories))
	for _, directory := range plan.Directories {
		if err := os.Mkdir(directory.Path, directory.Mode); err != nil {
			return changed, fmt.Errorf("create node directory %s: %w", directory.Path, err)
		}
		changed = append(changed, directory.Path)
		if err := syncLifecycleDirectory(filepath.Dir(directory.Path)); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

func equalNodeLayoutPlans(left, right NodeLayoutPlan) bool {
	if left.AuthoritativeDir != right.AuthoritativeDir || len(left.Directories) != len(right.Directories) {
		return false
	}
	for index := range left.Directories {
		if left.Directories[index] != right.Directories[index] {
			return false
		}
	}
	return true
}
