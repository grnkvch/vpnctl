package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	ErrGatewayRoleConflict = errors.New("host is already initialized with another role")
	ErrGatewayInitConflict = errors.New("gateway is already initialized with different inputs")
)

type GatewayInitInput struct {
	PublicIPv4        string
	ClientCIDR        string
	NodeCIDR          string
	ExternalInterface string
	ExplicitSSHPort   *int
	SSHConnection     string
}

type GatewayInitPlan struct {
	Changed            bool
	AlreadyInitialized bool
	HostID             string
	Network            linuxplatform.GatewayNetworkPlan
	SSH                linuxplatform.SSHPortPlan
	Preflight          linuxplatform.GatewayPreflightPlan
	FixedListeners     []string
	Directories        []string
	PresetDirectory    string
	PKIPlaceholders    []string
	Units              []string
	WatchdogUnitFiles  []string

	desiredState  model.State
	layout        GatewayLayoutPlan
	roleRequest   linuxplatform.RoleInstallationRequest
	watchdogUnits linuxplatform.WatchdogUnitInstallationPlan
	firewall      linuxplatform.GatewayFirewallArtifact
}

type GatewayInitResult struct {
	Changed       bool
	HostID        string
	TransactionID string
	Network       linuxplatform.GatewayNetworkPlan
	Units         []string
}

type GatewayInitStateStore interface {
	Load() (model.State, error)
	Save(expectedGeneration uint64, candidate model.State) error
}

type GatewayInitRoleInstaller interface {
	Plan(linuxplatform.RoleInstallationRequest) (linuxplatform.RoleInstallationPlan, error)
	Apply(context.Context, linuxplatform.RoleInstallationRequest) (linuxplatform.RoleInstallationResult, error)
}

type GatewayInitWatchdog interface {
	Arm(context.Context, GatewayInitWatchdogArm) (GatewayInitWatchdogTransaction, error)
	MarkActivated(context.Context, string) error
	RollbackNow(context.Context, string) error
}

type GatewayInitWatchdogUnitInstaller interface {
	Plan(string) (linuxplatform.WatchdogUnitInstallationPlan, error)
	Apply(context.Context, linuxplatform.WatchdogUnitInstallationPlan) ([]string, error)
}

type GatewayInitWatchdogArm struct {
	AllowedSSHPort int
	Origin         *linuxplatform.SSHConnection
	NetworkScope   linuxplatform.OwnedNetworkScope
}

type GatewayInitWatchdogTransaction struct {
	ID string
}

type GatewayInitNetworkActivator interface {
	ActivateGateway(context.Context, linuxplatform.GatewayFirewallArtifact) error
}

type GatewayInitRuntime struct {
	Paths         store.Paths
	Snapshot      linuxplatform.HostSnapshot
	Manifest      model.ComponentManifest
	BinaryPath    string
	State         GatewayInitStateStore
	Layout        *GatewayLayoutInstaller
	Roles         GatewayInitRoleInstaller
	WatchdogUnits GatewayInitWatchdogUnitInstaller
	Watchdog      GatewayInitWatchdog
	Network       GatewayInitNetworkActivator
	Now           func() time.Time
	NewHostID     model.UUIDGenerator
}

type GatewayInitializer struct {
	runtime GatewayInitRuntime
}

func NewGatewayInitializer(runtime GatewayInitRuntime) (*GatewayInitializer, error) {
	if runtime.State == nil || runtime.Layout == nil || runtime.Roles == nil || runtime.WatchdogUnits == nil || runtime.Watchdog == nil || runtime.Network == nil {
		return nil, fmt.Errorf("gateway initializer dependencies are incomplete")
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
		return nil, fmt.Errorf("gateway component manifest: %w", err)
	}
	wantPaths, err := store.NewPaths(runtime.Paths.Root)
	if err != nil || runtime.Paths != wantPaths {
		return nil, fmt.Errorf("gateway initializer paths do not match the system root")
	}
	return &GatewayInitializer{runtime: runtime}, nil
}

// Plan is read-only. It rejects a dirty clean-host boundary before allocating
// a host identity, and treats only an exact same-role/same-network init as a
// no-op.
func (initializer *GatewayInitializer) Plan(ctx context.Context, input GatewayInitInput) (GatewayInitPlan, error) {
	if ctx == nil {
		return GatewayInitPlan{}, fmt.Errorf("context is required")
	}
	if initializer == nil {
		return GatewayInitPlan{}, fmt.Errorf("gateway initializer is required")
	}
	snapshot := initializer.runtime.Snapshot
	if snapshot.SchemaVersion != linuxplatform.HostSnapshotSchemaVersion {
		return GatewayInitPlan{}, fmt.Errorf("host snapshot schema must be %d", linuxplatform.HostSnapshotSchemaVersion)
	}
	if err := snapshot.ValidateMandatoryCapabilities(); err != nil {
		return GatewayInitPlan{}, err
	}

	existing, loadErr := initializer.runtime.State.Load()
	if loadErr == nil {
		if existing.Host.Role != model.RoleGateway {
			return GatewayInitPlan{}, fmt.Errorf("%w: current role is %s", ErrGatewayRoleConflict, existing.Host.Role)
		}
		snapshot = withoutOwnedGatewayNetwork(snapshot)
		return initializer.planExisting(input, snapshot, existing)
	}
	if !errors.Is(loadErr, store.ErrStateNotFound) {
		return GatewayInitPlan{}, fmt.Errorf("load authoritative state: %w", loadErr)
	}

	network, ssh, err := planGatewayInputs(input, snapshot)
	if err != nil {
		return GatewayInitPlan{}, err
	}
	preflight, err := linuxplatform.AnalyzeGatewayPreflight(linuxplatform.GatewayPreflightInput{Network: network, SSH: ssh}, snapshot)
	if err != nil {
		return GatewayInitPlan{}, err
	}
	layout, err := initializer.runtime.Layout.PlanFresh()
	if err != nil {
		return GatewayInitPlan{}, err
	}
	roleRequest, err := linuxplatform.RenderGatewayRoleInstallation(initializer.runtime.BinaryPath)
	if err != nil {
		return GatewayInitPlan{}, err
	}
	rolePlan, err := initializer.runtime.Roles.Plan(roleRequest)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("plan gateway services: %w", err)
	}
	watchdogUnits, err := initializer.runtime.WatchdogUnits.Plan(initializer.runtime.BinaryPath)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("plan watchdog units: %w", err)
	}
	firewall, err := linuxplatform.RenderGatewayFirewall(linuxplatform.GatewayFirewallInput{
		ExternalInterface: network.ExternalInterface, SSHPort: ssh.Port,
		ClientCIDR: network.ClientCIDR, NodeCIDR: network.NodeCIDR,
	})
	if err != nil {
		return GatewayInitPlan{}, err
	}
	hostID, err := model.AllocateUUID(nil, initializer.runtime.NewHostID)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("allocate gateway host identity: %w", err)
	}
	initializedAt := initializer.runtime.Now().UTC()
	desired := initialGatewayState(hostID, initializedAt, network, ssh.Port, initializer.runtime.Manifest)
	if err := desired.Validate(); err != nil {
		return GatewayInitPlan{}, fmt.Errorf("build initial gateway state: %w", err)
	}
	directories := make([]string, len(layout.Directories))
	for index, directory := range layout.Directories {
		directories[index] = directory.Path
	}
	return GatewayInitPlan{
		Changed: true, HostID: hostID, Network: network, SSH: ssh, Preflight: preflight,
		FixedListeners: []string{"443/tcp", "8443/tcp", "51820/udp"},
		Directories:    directories, PresetDirectory: layout.PresetDirectory,
		PKIPlaceholders: append([]string(nil), layout.PKIPlaceholders...), Units: append([]string(nil), rolePlan.UnitsToStart...),
		WatchdogUnitFiles: append([]string(nil), watchdogUnits.UnitFiles...),
		desiredState:      desired, layout: layout, roleRequest: roleRequest, watchdogUnits: watchdogUnits, firewall: firewall,
	}, nil
}

func (initializer *GatewayInitializer) planExisting(input GatewayInitInput, snapshot linuxplatform.HostSnapshot, existing model.State) (GatewayInitPlan, error) {
	network, ssh, err := planGatewayInputs(input, snapshot)
	if err != nil {
		return GatewayInitPlan{}, err
	}
	if existing.Host.PublicIPv4 != network.PublicIPv4 || existing.Host.ClientCIDR != network.ClientCIDR ||
		existing.Host.NodeCIDR != network.NodeCIDR || existing.Host.ExternalInterface != network.ExternalInterface || existing.Host.SSHPort != ssh.Port {
		return GatewayInitPlan{}, fmt.Errorf("%w: use a planned migration instead of init", ErrGatewayInitConflict)
	}
	return GatewayInitPlan{
		AlreadyInitialized: true, HostID: existing.Host.ID, Network: network, SSH: ssh,
		FixedListeners: []string{"443/tcp", "8443/tcp", "51820/udp"}, desiredState: existing,
	}, nil
}

func (initializer *GatewayInitializer) Apply(ctx context.Context, plan GatewayInitPlan) (GatewayInitResult, error) {
	if ctx == nil {
		return GatewayInitResult{}, fmt.Errorf("context is required")
	}
	if initializer == nil {
		return GatewayInitResult{}, fmt.Errorf("gateway initializer is required")
	}
	if plan.AlreadyInitialized && !plan.Changed {
		state, err := initializer.runtime.State.Load()
		if err != nil || state.Host.ID != plan.HostID || state.Host.Role != model.RoleGateway {
			return GatewayInitResult{}, fmt.Errorf("idempotent gateway plan is stale")
		}
		return GatewayInitResult{HostID: plan.HostID, Network: plan.Network, Units: []string{}}, nil
	}
	if !plan.Changed || plan.AlreadyInitialized || plan.HostID == "" || plan.desiredState.Host.ID != plan.HostID {
		return GatewayInitResult{}, fmt.Errorf("invalid gateway initialization plan")
	}
	if _, err := initializer.runtime.State.Load(); !errors.Is(err, store.ErrStateNotFound) {
		if err == nil {
			return GatewayInitResult{}, fmt.Errorf("gateway initialization plan is stale: state now exists")
		}
		return GatewayInitResult{}, fmt.Errorf("recheck authoritative state: %w", err)
	}
	if _, err := initializer.runtime.Layout.Apply(plan.layout); err != nil {
		return GatewayInitResult{}, fmt.Errorf("apply gateway layout: %w", err)
	}
	if _, err := initializer.runtime.WatchdogUnits.Apply(ctx, plan.watchdogUnits); err != nil {
		return GatewayInitResult{}, fmt.Errorf("install gateway watchdog units: %w", err)
	}
	transaction, err := initializer.runtime.Watchdog.Arm(ctx, GatewayInitWatchdogArm{
		AllowedSSHPort: plan.SSH.Port, Origin: plan.SSH.Connection,
		NetworkScope: linuxplatform.GatewayInitNetworkScope(),
	})
	if err != nil {
		return GatewayInitResult{}, fmt.Errorf("arm gateway lockout watchdog: %w", err)
	}
	fail := func(applyErr error) (GatewayInitResult, error) {
		rollbackErr := initializer.runtime.Watchdog.RollbackNow(ctx, transaction.ID)
		return GatewayInitResult{}, errors.Join(applyErr, rollbackErr)
	}
	if err := initializer.runtime.State.Save(0, plan.desiredState); err != nil {
		return fail(fmt.Errorf("persist initial gateway state: %w", err))
	}
	if _, err := initializer.runtime.Roles.Apply(ctx, plan.roleRequest); err != nil {
		return fail(fmt.Errorf("install gateway services: %w", err))
	}
	if err := initializer.runtime.Network.ActivateGateway(ctx, plan.firewall); err != nil {
		return fail(fmt.Errorf("activate gateway network: %w", err))
	}
	if err := initializer.runtime.Watchdog.MarkActivated(ctx, transaction.ID); err != nil {
		return fail(fmt.Errorf("mark gateway network active: %w", err))
	}
	return GatewayInitResult{
		Changed: true, HostID: plan.HostID, TransactionID: transaction.ID,
		Network: plan.Network, Units: append([]string(nil), plan.Units...),
	}, nil
}

func planGatewayInputs(input GatewayInitInput, snapshot linuxplatform.HostSnapshot) (linuxplatform.GatewayNetworkPlan, linuxplatform.SSHPortPlan, error) {
	network, err := linuxplatform.ValidateGatewayNetwork(linuxplatform.GatewayNetworkInput{
		PublicIPv4: input.PublicIPv4, ClientCIDR: input.ClientCIDR, NodeCIDR: input.NodeCIDR,
		ExternalInterface: input.ExternalInterface,
	}, snapshot)
	if err != nil {
		return linuxplatform.GatewayNetworkPlan{}, linuxplatform.SSHPortPlan{}, err
	}
	ssh, err := linuxplatform.ResolveSSHPort(linuxplatform.SSHPortInput{ExplicitPort: input.ExplicitSSHPort, SSHConnection: input.SSHConnection}, snapshot)
	if err != nil {
		return linuxplatform.GatewayNetworkPlan{}, linuxplatform.SSHPortPlan{}, err
	}
	return network, ssh, nil
}

func initialGatewayState(hostID string, initializedAt time.Time, network linuxplatform.GatewayNetworkPlan, sshPort int, manifest model.ComponentManifest) model.State {
	return model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: hostID, Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: initializedAt,
			PublicIPv4: network.PublicIPv4, ExternalInterface: network.ExternalInterface, SSHPort: sshPort,
			ClientCIDR: network.ClientCIDR, NodeCIDR: network.NodeCIDR,
		},
		Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports: []model.Transport{}, Exposes: []model.Expose{}, Certificates: []model.Certificate{},
		Operations: []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{}, Components: manifest,
	}
}

func withoutOwnedGatewayNetwork(snapshot linuxplatform.HostSnapshot) linuxplatform.HostSnapshot {
	result := snapshot
	result.Interfaces = filterValues(snapshot.Interfaces, func(value linuxplatform.NetworkInterface) bool {
		return value.Name != linuxplatform.GatewayOverlayInterface
	})
	result.ContainerNetworks = filterValues(snapshot.ContainerNetworks, func(value linuxplatform.ContainerNetwork) bool {
		return value.Interface != linuxplatform.GatewayOverlayInterface
	})
	result.Routes = filterValues(snapshot.Routes, func(value linuxplatform.Route) bool {
		return value.Device != linuxplatform.GatewayOverlayInterface && value.Table != linuxplatform.VPNCTLSelectedRouteTable && value.Table != linuxplatform.VPNCTLGatewayRouteTable
	})
	result.PolicyRules = filterValues(snapshot.PolicyRules, func(value linuxplatform.PolicyRule) bool {
		return value.Priority != 10000 && value.Priority != 10010 && value.Priority != 10020
	})
	return result
}

func filterValues[T any](values []T, keep func(T) bool) []T {
	result := make([]T, 0, len(values))
	for _, value := range values {
		if keep(value) {
			result = append(result, value)
		}
	}
	return result
}
