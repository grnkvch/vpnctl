package operations

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const nodeInitConvergenceComponent = "role.node"

type NodeInitializationConvergenceStore interface {
	EnsureInitialized(context.Context, ConvergenceSnapshot) (bool, error)
}

// NodeInitializationConvergencePublisher materializes the exact staged role
// request committed by init --node into the first durable desired/applied
// baseline. It is intentionally post-state-commit and idempotent so retrying a
// partially reported initialization can finish metadata publication safely.
type NodeInitializationConvergencePublisher struct {
	store NodeInitializationConvergenceStore
}

func NewNodeInitializationConvergencePublisher(store NodeInitializationConvergenceStore) (*NodeInitializationConvergencePublisher, error) {
	if store == nil {
		return nil, fmt.Errorf("node initialization convergence store is required")
	}
	return &NodeInitializationConvergencePublisher{store: store}, nil
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
	if generation == 0 || request.Role != model.RoleNode || request.Units == nil || request.Configs == nil || len(request.Units) == 0 {
		return ConvergenceSnapshot{}, fmt.Errorf("staged node convergence request is invalid")
	}
	resources := make([]ManagedResource, 0, len(request.Units)+len(request.Configs))
	for _, unit := range request.Units {
		if unit.Name == "" || filepath.Base(unit.Name) != unit.Name || len(unit.Content) == 0 || unit.Enable || unit.Start {
			return ConvergenceSnapshot{}, fmt.Errorf("staged node unit %q is invalid", unit.Name)
		}
		content := append([]byte(nil), unit.Content...)
		if content[len(content)-1] != '\n' {
			content = append(content, '\n')
		}
		contentSHA256 := ManagedFingerprint(content)
		runtimeSHA256, err := ManagedUnitRuntimeFingerprint(ManagedUnitRuntime{
			FileType: "regular", Mode: "0644", ContentSHA256: contentSHA256,
			LoadState: "loaded", ActiveState: "inactive", SubState: "dead", Enablement: "disabled",
		})
		if err != nil {
			return ConvergenceSnapshot{}, err
		}
		revisionSHA256, err := nodeInitResourceRevision(generation, "unit", unit.Name, "0644", contentSHA256)
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
		revisionSHA256, err := nodeInitResourceRevision(generation, "config", config.Name, "0600", contentSHA256)
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

func nodeInitResourceRevision(generation uint64, kind, name, mode, contentSHA256 string) (string, error) {
	encoded, err := json.Marshal(struct {
		Generation    uint64 `json:"generation"`
		Kind          string `json:"kind"`
		Name          string `json:"name"`
		Mode          string `json:"mode"`
		ContentSHA256 string `json:"content_sha256"`
	}{Generation: generation, Kind: kind, Name: name, Mode: mode, ContentSHA256: contentSHA256})
	if err != nil {
		return "", err
	}
	return ManagedFingerprint(encoded), nil
}

var _ interface {
	PublishNodeInitialization(context.Context, uint64, linuxplatform.RoleInstallationRequest) error
} = (*NodeInitializationConvergencePublisher)(nil)
