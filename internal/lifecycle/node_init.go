package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var ErrNodeRoleConflict = errors.New("host is already initialized with another role")

type NodeInitPlan struct {
	Changed            bool
	AlreadyInitialized bool
	HostID             string
	Directories        []string
	Units              []string
	Enrolled           bool
	ActiveTunnel       bool

	desiredState model.State
	layout       NodeLayoutPlan
	roleRequest  linuxplatform.RoleInstallationRequest
}

type NodeInitResult struct {
	Changed bool
	HostID  string
	Units   []string
}

type NodeInitStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

type NodeInitRoleInstaller interface {
	Plan(linuxplatform.RoleInstallationRequest) (linuxplatform.RoleInstallationPlan, error)
	Apply(context.Context, linuxplatform.RoleInstallationRequest) (linuxplatform.RoleInstallationResult, error)
}

type NodeInitRuntime struct {
	Paths      store.Paths
	Snapshot   linuxplatform.HostSnapshot
	Manifest   model.ComponentManifest
	BinaryPath string
	State      NodeInitStateStore
	Layout     *NodeLayoutInstaller
	Roles      NodeInitRoleInstaller
	Now        func() time.Time
	NewHostID  model.UUIDGenerator
}

type NodeInitializer struct {
	runtime NodeInitRuntime
}

func NewNodeInitializer(runtime NodeInitRuntime) (*NodeInitializer, error) {
	if runtime.State == nil || runtime.Layout == nil || runtime.Roles == nil {
		return nil, fmt.Errorf("node initializer dependencies are incomplete")
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	if runtime.NewHostID == nil {
		runtime.NewHostID = model.NewUUID
	}
	if runtime.BinaryPath == "" {
		runtime.BinaryPath = linuxplatform.DefaultVPNCTLBinaryPath
	}
	if err := runtime.Manifest.Validate(); err != nil {
		return nil, fmt.Errorf("node component manifest: %w", err)
	}
	wantPaths, err := store.NewPaths(runtime.Paths.Root)
	if err != nil || runtime.Paths != wantPaths {
		return nil, fmt.Errorf("node initializer paths do not match the system root")
	}
	return &NodeInitializer{runtime: runtime}, nil
}

// Plan is read-only. A fresh node plan contains no gateway identity, trust,
// policy, transport, certificate, or active service configuration.
func (initializer *NodeInitializer) Plan(ctx context.Context) (NodeInitPlan, error) {
	if ctx == nil {
		return NodeInitPlan{}, fmt.Errorf("context is required")
	}
	if initializer == nil {
		return NodeInitPlan{}, fmt.Errorf("node initializer is required")
	}
	snapshot := initializer.runtime.Snapshot
	if snapshot.SchemaVersion != linuxplatform.HostSnapshotSchemaVersion {
		return NodeInitPlan{}, fmt.Errorf("host snapshot schema must be %d", linuxplatform.HostSnapshotSchemaVersion)
	}
	if err := snapshot.ValidateMandatoryCapabilities(); err != nil {
		return NodeInitPlan{}, err
	}

	existing, loadErr := initializer.runtime.State.Load()
	if loadErr == nil {
		if existing.Host.Role != model.RoleNode {
			return NodeInitPlan{}, fmt.Errorf("%w: current role is %s", ErrNodeRoleConflict, existing.Host.Role)
		}
		return NodeInitPlan{
			AlreadyInitialized: true, HostID: existing.Host.ID, desiredState: existing, Units: []string{},
			Enrolled: len(existing.Nodes) == 1, ActiveTunnel: nodeHasActiveTunnel(existing),
		}, nil
	}
	if !errors.Is(loadErr, store.ErrStateNotFound) {
		return NodeInitPlan{}, fmt.Errorf("load authoritative state: %w", loadErr)
	}

	layout, err := initializer.runtime.Layout.PlanFresh()
	if err != nil {
		return NodeInitPlan{}, err
	}
	roleRequest, err := linuxplatform.RenderNodeRoleInstallation(initializer.runtime.BinaryPath)
	if err != nil {
		return NodeInitPlan{}, err
	}
	if _, err := initializer.runtime.Roles.Plan(roleRequest); err != nil {
		return NodeInitPlan{}, fmt.Errorf("plan node services: %w", err)
	}
	hostID, err := model.AllocateUUID(nil, initializer.runtime.NewHostID)
	if err != nil {
		return NodeInitPlan{}, fmt.Errorf("allocate node host identity: %w", err)
	}
	desired := initialNodeState(hostID, initializer.runtime.Now().UTC(), initializer.runtime.Manifest)
	if err := desired.Validate(); err != nil {
		return NodeInitPlan{}, fmt.Errorf("build initial node state: %w", err)
	}
	directories := make([]string, len(layout.Directories))
	for index, directory := range layout.Directories {
		directories[index] = directory.Path
	}
	units := make([]string, len(roleRequest.Units))
	for index, unit := range roleRequest.Units {
		units[index] = unit.Name
	}
	sort.Strings(units)
	return NodeInitPlan{
		Changed: true, HostID: hostID, Directories: directories, Units: units,
		desiredState: desired, layout: layout, roleRequest: roleRequest,
	}, nil
}

func (initializer *NodeInitializer) Apply(ctx context.Context, plan NodeInitPlan) (NodeInitResult, error) {
	if ctx == nil {
		return NodeInitResult{}, fmt.Errorf("context is required")
	}
	if initializer == nil {
		return NodeInitResult{}, fmt.Errorf("node initializer is required")
	}
	if plan.AlreadyInitialized && !plan.Changed {
		state, err := initializer.runtime.State.Load()
		if err != nil || state.Host.ID != plan.HostID || state.Host.Role != model.RoleNode {
			return NodeInitResult{}, fmt.Errorf("idempotent node plan is stale")
		}
		return NodeInitResult{HostID: plan.HostID, Units: []string{}}, nil
	}
	if !plan.Changed || plan.AlreadyInitialized || plan.HostID == "" || plan.desiredState.Host.ID != plan.HostID {
		return NodeInitResult{}, fmt.Errorf("invalid node initialization plan")
	}
	if _, err := initializer.runtime.State.Load(); !errors.Is(err, store.ErrStateNotFound) {
		if err == nil {
			return NodeInitResult{}, fmt.Errorf("node initialization plan is stale: state now exists")
		}
		return NodeInitResult{}, fmt.Errorf("recheck authoritative state: %w", err)
	}
	if _, err := initializer.runtime.Layout.Apply(plan.layout); err != nil {
		return NodeInitResult{}, fmt.Errorf("apply node layout: %w", err)
	}
	// Node units are deliberately staged before the role becomes authoritative;
	// their readiness conditions and disabled state make this non-activating.
	if _, err := initializer.runtime.Roles.Apply(ctx, plan.roleRequest); err != nil {
		return NodeInitResult{}, fmt.Errorf("install staged node services: %w", err)
	}
	if err := initializer.runtime.State.Save(0, plan.desiredState); err != nil {
		return NodeInitResult{}, fmt.Errorf("persist initial node state: %w", err)
	}
	return NodeInitResult{Changed: true, HostID: plan.HostID, Units: append([]string(nil), plan.Units...)}, nil
}

func initialNodeState(hostID string, initializedAt time.Time, manifest model.ComponentManifest) model.State {
	return model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: hostID, Role: model.RoleNode,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: initializedAt,
		},
		Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports: []model.Transport{}, Exposes: []model.Expose{}, Certificates: []model.Certificate{},
		Operations: []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{}, Components: manifest,
	}
}

func nodeHasActiveTunnel(state model.State) bool {
	if len(state.Nodes) != 1 {
		return false
	}
	local := state.Nodes[0]
	for _, transport := range state.Transports {
		if transport.OwnerKind == model.TargetNode && transport.OwnerID == local.ID &&
			transport.Kind == local.ActiveTransport && transport.State == model.TransportActive {
			return true
		}
	}
	return false
}
