package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const nodeInitConvergenceComponent = "role.node"

var ErrNodeServiceConvergencePending = errors.New("node services are active but convergence baseline is pending")

type NodeInitializationConvergenceStore interface {
	EnsureInitialized(context.Context, ConvergenceSnapshot) (bool, error)
}

type NodeServiceConvergenceStore interface {
	Read(context.Context) (ConvergenceSnapshot, error)
	EnsureInitialized(context.Context, ConvergenceSnapshot) (bool, error)
	CompareAndSwap(context.Context, ConvergenceSnapshot, ConvergenceSnapshot) (bool, error)
}

// NodeInitializationConvergencePublisher materializes the exact staged role
// request committed by init --node into the first durable desired/applied
// baseline. It is intentionally post-state-commit and idempotent so retrying a
// partially reported initialization can finish metadata publication safely.
type NodeInitializationConvergencePublisher struct {
	store NodeInitializationConvergenceStore
}

type NodeServiceConvergencePublisher struct {
	store      NodeServiceConvergenceStore
	binaryPath string
}

func NewNodeInitializationConvergencePublisher(store NodeInitializationConvergenceStore) (*NodeInitializationConvergencePublisher, error) {
	if store == nil {
		return nil, fmt.Errorf("node initialization convergence store is required")
	}
	return &NodeInitializationConvergencePublisher{store: store}, nil
}

func NewNodeServiceConvergencePublisher(store NodeServiceConvergenceStore, binaryPath string) (*NodeServiceConvergencePublisher, error) {
	if store == nil || !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath {
		return nil, fmt.Errorf("node service convergence dependencies are invalid")
	}
	return &NodeServiceConvergencePublisher{store: store, binaryPath: binaryPath}, nil
}

func (publisher *NodeInitializationConvergencePublisher) PublishNodeInitialization(
	ctx context.Context,
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
) error {
	if ctx == nil || publisher == nil || publisher.store == nil {
		return fmt.Errorf("node initialization convergence publisher is incomplete")
	}
	snapshot, err := StagedNodeRoleConvergenceSnapshot(generation, request)
	if err != nil {
		return err
	}
	if _, err := publisher.store.EnsureInitialized(ctx, snapshot); err != nil {
		return fmt.Errorf("publish initial node convergence snapshot: %w", err)
	}
	return nil
}

// StagedNodeRoleConvergenceSnapshot records only resources actually installed
// by unjoined node initialization: four inactive/disabled unit files and the
// root-only bootstrap config. Joined generation artifacts are added by the
// later join transaction rather than guessed here.
func StagedNodeRoleConvergenceSnapshot(
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
) (ConvergenceSnapshot, error) {
	return nodeRoleConvergenceSnapshot(generation, request, false)
}

func ActiveNodeRoleConvergenceSnapshot(
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
) (ConvergenceSnapshot, error) {
	return nodeRoleConvergenceSnapshot(generation, request, true)
}

func nodeRoleConvergenceSnapshot(
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
	active bool,
) (ConvergenceSnapshot, error) {
	if generation == 0 || request.Role != model.RoleNode || request.Units == nil || request.Configs == nil || len(request.Units) == 0 {
		return ConvergenceSnapshot{}, fmt.Errorf("staged node convergence request is invalid")
	}
	wantUnits := linuxplatform.RoleUnitNames(model.RoleNode)
	sort.Strings(wantUnits)
	gotUnits := make([]string, len(request.Units))
	for index, unit := range request.Units {
		gotUnits[index] = unit.Name
	}
	sort.Strings(gotUnits)
	if !reflect.DeepEqual(gotUnits, wantUnits) {
		return ConvergenceSnapshot{}, fmt.Errorf("node convergence unit set is incomplete")
	}
	resources := make([]ManagedResource, 0, len(request.Units)+len(request.Configs))
	for _, unit := range request.Units {
		if unit.Name == "" || filepath.Base(unit.Name) != unit.Name || len(unit.Content) == 0 || unit.Enable != active || unit.Start {
			return ConvergenceSnapshot{}, fmt.Errorf("staged node unit %q is invalid", unit.Name)
		}
		content := append([]byte(nil), unit.Content...)
		if content[len(content)-1] != '\n' {
			content = append(content, '\n')
		}
		contentSHA256 := ManagedFingerprint(content)
		activeState, subState, enablement := "inactive", "dead", "disabled"
		if active {
			activeState, subState, enablement = "active", "running", "enabled"
			if unit.Name == "vpnctl-routing-guard.service" {
				subState = "exited"
			}
		}
		runtimeSHA256, err := ManagedUnitRuntimeFingerprint(ManagedUnitRuntime{
			FileType: "regular", Mode: "0644", ContentSHA256: contentSHA256,
			LoadState: "loaded", ActiveState: activeState, SubState: subState, Enablement: enablement,
		})
		if err != nil {
			return ConvergenceSnapshot{}, err
		}
		revisionSHA256, err := roleConvergenceResourceRevision(generation, "unit", unit.Name, "0644", contentSHA256, activeState+"/"+subState+"/"+enablement)
		if err != nil {
			return ConvergenceSnapshot{}, err
		}
		resources = append(resources, ManagedResource{
			Key:            ManagedResourceKey{Component: nodeInitConvergenceComponent, Kind: ManagedResourceUnit, ID: unit.Name},
			RevisionSHA256: revisionSHA256, RuntimeSHA256: runtimeSHA256,
			ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
		})
	}
	for _, config := range request.Configs {
		if config.Name == "" || filepath.Base(config.Name) != config.Name || len(config.Content) == 0 {
			return ConvergenceSnapshot{}, fmt.Errorf("staged node config %q is invalid", config.Name)
		}
		contentSHA256 := ManagedFingerprint(config.Content)
		runtimeSHA256, err := managedFileRuntimeFingerprint("regular", "0600", contentSHA256)
		if err != nil {
			return ConvergenceSnapshot{}, err
		}
		revisionSHA256, err := roleConvergenceResourceRevision(generation, "config", config.Name, "0600", contentSHA256, "present")
		if err != nil {
			return ConvergenceSnapshot{}, err
		}
		resources = append(resources, ManagedResource{
			Key: ManagedResourceKey{
				Component: nodeInitConvergenceComponent, Kind: ManagedResourceFile,
				ID: filepath.Join("/etc/vpnctl/generated/node", config.Name),
			},
			RevisionSHA256: revisionSHA256, RuntimeSHA256: runtimeSHA256,
			ApplyImpact: ConvergenceImpactAvailability, RemoveImpact: ConvergenceImpactAvailability,
		})
	}
	manifest, err := NewConvergenceManifest(generation, resources)
	if err != nil {
		return ConvergenceSnapshot{}, err
	}
	return ConvergenceSnapshot{
		Desired: cloneManifest(manifest), Applied: cloneManifest(manifest), Pending: []PendingOperation{},
	}, nil
}

// PublishActiveNodeGeneration moves a clean prior node baseline to the exact
// fully active service generation. Missing metadata is recoverable because the
// complete candidate is reconstructed from committed state and secrets; any
// different existing current-or-newer baseline remains a conflict.
func (publisher *NodeServiceConvergencePublisher) PublishActiveNodeGeneration(
	ctx context.Context,
	generation uint64,
	configs []linuxplatform.RoleConfigFile,
) error {
	if ctx == nil || publisher == nil || publisher.store == nil {
		return fmt.Errorf("node service convergence publisher is incomplete")
	}
	request, err := linuxplatform.RenderNodeRoleInstallation(publisher.binaryPath)
	if err != nil {
		return err
	}
	for index := range request.Units {
		request.Units[index].Enable = true
		request.Units[index].Start = false
	}
	request.Configs = append(request.Configs, cloneRoleConfigs(configs)...)
	candidate, err := ActiveNodeRoleConvergenceSnapshot(generation, request)
	if err != nil {
		return err
	}
	current, err := publisher.store.Read(ctx)
	if errors.Is(err, ErrConvergenceSnapshotUnavailable) {
		_, err = publisher.store.EnsureInitialized(ctx, candidate)
		return err
	}
	if err != nil {
		return err
	}
	if reflect.DeepEqual(current, candidate) {
		return nil
	}
	if generation <= 1 || current.Desired.Generation != generation-1 || current.Applied.Generation != generation-1 ||
		!reflect.DeepEqual(current.Desired, current.Applied) || len(current.Pending) != 0 {
		return fmt.Errorf("%w: prior node convergence baseline is not clean generation %d", ErrConvergenceSnapshotConflict, generation-1)
	}
	_, err = publisher.store.CompareAndSwap(ctx, current, candidate)
	return err
}

func roleConvergenceResourceRevision(generation uint64, kind, name, mode, contentSHA256, expectedRuntime string) (string, error) {
	encoded, err := json.Marshal(struct {
		Generation    uint64 `json:"generation"`
		Kind          string `json:"kind"`
		Name          string `json:"name"`
		Mode          string `json:"mode"`
		ContentSHA256 string `json:"content_sha256"`
		Expected      string `json:"expected_runtime"`
	}{Generation: generation, Kind: kind, Name: name, Mode: mode, ContentSHA256: contentSHA256, Expected: expectedRuntime})
	if err != nil {
		return "", err
	}
	return ManagedFingerprint(encoded), nil
}

func cloneRoleConfigs(configs []linuxplatform.RoleConfigFile) []linuxplatform.RoleConfigFile {
	result := make([]linuxplatform.RoleConfigFile, len(configs))
	for index, config := range configs {
		result[index] = linuxplatform.RoleConfigFile{Name: config.Name, Content: append([]byte(nil), config.Content...)}
	}
	return result
}

var _ interface {
	PublishNodeInitialization(context.Context, uint64, linuxplatform.RoleInstallationRequest) error
} = (*NodeInitializationConvergencePublisher)(nil)

var _ interface {
	PublishActiveNodeGeneration(context.Context, uint64, []linuxplatform.RoleConfigFile) error
} = (*NodeServiceConvergencePublisher)(nil)
