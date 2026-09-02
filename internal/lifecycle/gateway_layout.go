package lifecycle

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/vgrinkevich/vpnctl/internal/store"
)

var ErrGatewayLayoutConflict = errors.New("gateway initialization paths already exist without authoritative state")

type GatewayLayoutDirectory struct {
	Path string
	Mode os.FileMode
}

type GatewayLayoutPlan struct {
	Directories      []GatewayLayoutDirectory
	PresetDirectory  string
	PKIPlaceholders  []string
	AuthoritativeDir string
}

type GatewayLayoutInstaller struct {
	paths store.Paths
}

func NewGatewayLayoutInstaller(paths store.Paths) (*GatewayLayoutInstaller, error) {
	if !filepath.IsAbs(paths.Root) || filepath.Clean(paths.Root) != paths.Root {
		return nil, fmt.Errorf("gateway layout root must be clean and absolute")
	}
	want, err := store.NewPaths(paths.Root)
	if err != nil {
		return nil, err
	}
	if paths != want {
		return nil, fmt.Errorf("gateway layout paths do not match the system root")
	}
	return &GatewayLayoutInstaller{paths: paths}, nil
}

// PlanFresh refuses to adopt pre-existing vpnctl roots when no authoritative
// state exists. This keeps similarly named foreign files outside ownership.
func (installer *GatewayLayoutInstaller) PlanFresh() (GatewayLayoutPlan, error) {
	if installer == nil {
		return GatewayLayoutPlan{}, fmt.Errorf("gateway layout installer is required")
	}
	for _, root := range []string{installer.paths.ConfigDir, installer.paths.StateDir, installer.paths.RuntimeDir} {
		if _, err := os.Lstat(root); err == nil {
			return GatewayLayoutPlan{}, fmt.Errorf("%w: %s", ErrGatewayLayoutConflict, root)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return GatewayLayoutPlan{}, fmt.Errorf("inspect gateway layout root %s: %w", root, err)
		}
	}
	directories := []GatewayLayoutDirectory{
		{Path: installer.paths.ConfigDir, Mode: 0o755},
		{Path: installer.paths.PresetsDir, Mode: 0o755},
		{Path: installer.paths.StateDir, Mode: 0o700},
		{Path: installer.paths.SecretsDir, Mode: 0o700},
		{Path: filepath.Join(installer.paths.SecretsDir, "pki"), Mode: 0o700},
		{Path: filepath.Join(installer.paths.SecretsDir, "enrollment"), Mode: 0o700},
		{Path: installer.paths.ExportsDir, Mode: 0o700},
		{Path: installer.paths.ClientExportsDir, Mode: 0o700},
		{Path: installer.paths.BackupsDir, Mode: 0o700},
		{Path: installer.paths.SnapshotsDir, Mode: 0o700},
		{Path: installer.paths.OperationsDir, Mode: 0o700},
		{Path: installer.paths.WatchdogDir, Mode: 0o700},
		{Path: installer.paths.RuntimeDir, Mode: 0o700},
	}
	return GatewayLayoutPlan{
		Directories: directories, PresetDirectory: installer.paths.PresetsDir,
		PKIPlaceholders: []string{
			filepath.Join(installer.paths.SecretsDir, "enrollment"),
			filepath.Join(installer.paths.SecretsDir, "pki"),
		},
		AuthoritativeDir: installer.paths.StateDir,
	}, nil
}

func (installer *GatewayLayoutInstaller) Apply(plan GatewayLayoutPlan) ([]string, error) {
	want, err := installer.PlanFresh()
	if err != nil {
		return nil, err
	}
	if !equalGatewayLayoutPlans(plan, want) {
		return nil, fmt.Errorf("gateway layout plan does not match the selected system root")
	}
	for _, parent := range []string{
		filepath.Dir(installer.paths.ConfigDir), filepath.Dir(installer.paths.StateDir), filepath.Dir(installer.paths.RuntimeDir),
	} {
		info, err := os.Lstat(parent)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("gateway layout parent %s must be a real existing directory", parent)
		}
	}
	changed := make([]string, 0, len(plan.Directories))
	for _, directory := range plan.Directories {
		if err := os.Mkdir(directory.Path, directory.Mode); err != nil {
			return changed, fmt.Errorf("create gateway directory %s: %w", directory.Path, err)
		}
		changed = append(changed, directory.Path)
		if err := syncGatewayDirectory(filepath.Dir(directory.Path)); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

func equalGatewayLayoutPlans(left, right GatewayLayoutPlan) bool {
	if left.PresetDirectory != right.PresetDirectory || left.AuthoritativeDir != right.AuthoritativeDir || len(left.Directories) != len(right.Directories) || len(left.PKIPlaceholders) != len(right.PKIPlaceholders) {
		return false
	}
	for index := range left.Directories {
		if left.Directories[index] != right.Directories[index] {
			return false
		}
	}
	leftPKI := append([]string(nil), left.PKIPlaceholders...)
	rightPKI := append([]string(nil), right.PKIPlaceholders...)
	sort.Strings(leftPKI)
	sort.Strings(rightPKI)
	for index := range leftPKI {
		if leftPKI[index] != rightPKI[index] {
			return false
		}
	}
	return true
}

func syncGatewayDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open gateway directory %s: %w", path, err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync gateway directory %s: %w", path, err)
	}
	return nil
}
