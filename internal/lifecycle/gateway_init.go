package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
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
	Changed              bool
	AlreadyInitialized   bool
	HostID               string
	Network              linuxplatform.GatewayNetworkPlan
	SSH                  linuxplatform.SSHPortPlan
	Preflight            linuxplatform.GatewayPreflightPlan
	FixedListeners       []string
	Directories          []string
	PresetDirectory      string
	PresetFiles          []string
	PKIPlaceholders      []string
	Units                []string
	TransportConfigFiles []string
	WatchdogUnitFiles    []string
	ManagedSwap          linuxplatform.ManagedSwapPlan
	ManagedSwapSelected  bool
	HandshakeHost        model.HandshakeHost

	desiredState     model.State
	layout           GatewayLayoutPlan
	roleRequest      linuxplatform.RoleInstallationRequest
	watchdogUnits    linuxplatform.WatchdogUnitInstallationPlan
	firewall         linuxplatform.GatewayFirewallArtifact
	swapDecisionMade bool
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

type GatewayInitSwapManager interface {
	Plan(linuxplatform.HostResources) (linuxplatform.ManagedSwapPlan, error)
	Apply(context.Context, linuxplatform.ManagedSwapPlan) (model.ManagedSwap, error)
	Deactivate(context.Context, model.ManagedSwap, bool) error
}

type GatewayInitIdentityProvisioner interface {
	Provision(context.Context, control.GatewayIdentityRequest) (control.GatewayIdentityInstallation, error)
	Rollback(context.Context, control.GatewayIdentityInstallation) error
}

type GatewayInitHandshakeHostSelector interface {
	Select(context.Context, int, time.Time) (model.HandshakeHost, error)
}

type GatewayInitTransportProvisioner interface {
	Provision(context.Context, model.State) (transport.GatewayListenerInstallation, error)
	Rollback(context.Context, transport.GatewayListenerInstallation) error
}

type GatewayInitRuntime struct {
	Paths          store.Paths
	Snapshot       linuxplatform.HostSnapshot
	Manifest       model.ComponentManifest
	BinaryPath     string
	State          GatewayInitStateStore
	Layout         *GatewayLayoutInstaller
	Roles          GatewayInitRoleInstaller
	WatchdogUnits  GatewayInitWatchdogUnitInstaller
	Watchdog       GatewayInitWatchdog
	Network        GatewayInitNetworkActivator
	Swap           GatewayInitSwapManager
	Identity       GatewayInitIdentityProvisioner
	HandshakeHosts GatewayInitHandshakeHostSelector
	Transports     GatewayInitTransportProvisioner
	Now            func() time.Time
	NewHostID      model.UUIDGenerator
}

type GatewayInitializer struct {
	runtime GatewayInitRuntime
}

func NewGatewayInitializer(runtime GatewayInitRuntime) (*GatewayInitializer, error) {
	if runtime.State == nil || runtime.Layout == nil || runtime.Roles == nil || runtime.WatchdogUnits == nil || runtime.Watchdog == nil || runtime.Network == nil || runtime.Swap == nil || runtime.Identity == nil || runtime.HandshakeHosts == nil || runtime.Transports == nil {
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
	managedSwap, err := initializer.runtime.Swap.Plan(snapshot.Resources)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("plan managed swap: %w", err)
	}
	initializedAt := initializer.runtime.Now().UTC()
	handshakeHost, err := initializer.runtime.HandshakeHosts.Select(ctx, initializer.runtime.Manifest.HandshakeHostListVersion, initializedAt)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("select restricted handshake host: %w", err)
	}
	hostID, err := model.AllocateUUID(nil, initializer.runtime.NewHostID)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("allocate gateway host identity: %w", err)
	}
	desired := initialGatewayState(hostID, initializedAt, network, ssh.Port, initializer.runtime.Manifest, handshakeHost)
	if err := desired.Validate(); err != nil {
		return GatewayInitPlan{}, fmt.Errorf("build initial gateway state: %w", err)
	}
	firewall, err := RenderGatewayIdentityFirewall(desired, GatewayIdentityFirewallServices{
		NodeTCPPorts: []int{control.RPCControlTCPPort},
	})
	if err != nil {
		return GatewayInitPlan{}, err
	}
	directories := make([]string, len(layout.Directories))
	for index, directory := range layout.Directories {
		directories[index] = directory.Path
	}
	presetFiles := make([]string, len(layout.PresetFiles))
	for index, preset := range layout.PresetFiles {
		presetFiles[index] = preset.Path
	}
	transportConfigFiles := make([]string, 0, len(transport.GatewayListenerFileNames()))
	for _, name := range transport.GatewayListenerFileNames() {
		transportConfigFiles = append(transportConfigFiles, filepath.Join(initializer.runtime.Paths.ConfigDir, "generated", "gateway", name))
	}
	return GatewayInitPlan{
		Changed: true, HostID: hostID, Network: network, SSH: ssh, Preflight: preflight,
		FixedListeners: []string{"443/tcp", "8443/tcp", "51820/udp"},
		Directories:    directories, PresetDirectory: layout.PresetDirectory, PresetFiles: presetFiles,
		PKIPlaceholders: append([]string(nil), layout.PKIPlaceholders...), Units: append([]string(nil), rolePlan.UnitsToStart...),
		TransportConfigFiles: transportConfigFiles,
		WatchdogUnitFiles:    append([]string(nil), watchdogUnits.UnitFiles...),
		ManagedSwap:          managedSwap,
		HandshakeHost:        handshakeHost,
		desiredState:         desired, layout: layout, roleRequest: roleRequest, watchdogUnits: watchdogUnits, firewall: firewall,
		swapDecisionMade: !managedSwap.Offered,
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
	if existing.HandshakeHost == nil {
		return GatewayInitPlan{}, fmt.Errorf("%w: existing state has no pinned handshake host", ErrGatewayInitConflict)
	}
	managedSwap := linuxplatform.ManagedSwapPlan{
		Path: linuxplatform.ManagedSwapLogicalPath, SizeBytes: linuxplatform.ManagedSwapSizeBytes,
		MemoryBytes: snapshot.Resources.MemoryTotalBytes, ExistingBytes: snapshot.Resources.SwapTotalBytes,
		DiskFreeBytes: snapshot.Resources.DiskFreeBytes, DiskReserve: linuxplatform.ManagedSwapDiskReserve,
	}
	if existing.Host.ManagedSwap != nil && existing.Host.ManagedSwap.Enabled {
		managedSwap.Disposition = linuxplatform.ManagedSwapAlreadyOwnedEnabled
	} else if existing.Host.ManagedSwap != nil {
		managedSwap.Disposition = linuxplatform.ManagedSwapAlreadyOwnedStopped
	} else if snapshot.Resources.SwapTotalBytes >= linuxplatform.ManagedSwapSizeBytes {
		managedSwap.Disposition = linuxplatform.ManagedSwapExistingAdequate
	} else {
		managedSwap.Disposition = linuxplatform.ManagedSwapUnknownResources
	}
	return GatewayInitPlan{
		AlreadyInitialized: true, HostID: existing.Host.ID, Network: network, SSH: ssh,
		FixedListeners: []string{"443/tcp", "8443/tcp", "51820/udp"}, ManagedSwap: managedSwap,
		HandshakeHost: *existing.HandshakeHost,
		desiredState:  existing, swapDecisionMade: true,
	}, nil
}

// SelectManagedSwap records the operator's explicit optional choice without
// mutating the host. It is required before Apply whenever the plan offers swap.
func (plan GatewayInitPlan) SelectManagedSwap(create bool) (GatewayInitPlan, error) {
	if plan.AlreadyInitialized || !plan.Changed {
		if create {
			return GatewayInitPlan{}, fmt.Errorf("%w: managed swap cannot be selected for a no-op init", linuxplatform.ErrManagedSwapPlan)
		}
		plan.swapDecisionMade = true
		return plan, nil
	}
	if create && !plan.ManagedSwap.Offered {
		return GatewayInitPlan{}, fmt.Errorf("%w: managed swap is not available in this plan", linuxplatform.ErrManagedSwapPlan)
	}
	plan.ManagedSwapSelected = create
	plan.swapDecisionMade = true
	if plan.desiredState.SchemaVersion != 0 {
		plan.desiredState.Host.ManagedSwap = nil
		if create {
			plan.desiredState.Host.ManagedSwap = &model.ManagedSwap{
				Path: linuxplatform.ManagedSwapLogicalPath, SizeBytes: int64(linuxplatform.ManagedSwapSizeBytes), Enabled: true,
			}
		}
		if err := plan.desiredState.Validate(); err != nil {
			return GatewayInitPlan{}, fmt.Errorf("select managed swap: %w", err)
		}
	}
	return plan, nil
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
	if !plan.Changed || plan.AlreadyInitialized || plan.HostID == "" || plan.desiredState.Host.ID != plan.HostID || !plan.swapDecisionMade ||
		len(plan.desiredState.Certificates) != 0 || plan.desiredState.EnrollmentIdentity != nil {
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
	identity, err := initializer.runtime.Identity.Provision(ctx, control.GatewayIdentityRequest{
		GatewayID: plan.HostID, NodeCIDR: plan.Network.NodeCIDR, Initialized: plan.desiredState.Host.InitializedAt,
	})
	if err != nil {
		return GatewayInitResult{}, fmt.Errorf("provision gateway control identity: %w", err)
	}
	rollbackIdentity := func(applyErr error) (GatewayInitResult, error) {
		return GatewayInitResult{}, errors.Join(applyErr, initializer.runtime.Identity.Rollback(context.Background(), identity))
	}
	candidate := plan.desiredState
	candidate.Certificates = append([]model.Certificate(nil), identity.Certificates...)
	enrollmentIdentity := identity.EnrollmentIdentity
	candidate.EnrollmentIdentity = &enrollmentIdentity
	if err := candidate.Validate(); err != nil {
		return rollbackIdentity(fmt.Errorf("validate provisioned gateway identity: %w", err))
	}
	if _, err := initializer.runtime.WatchdogUnits.Apply(ctx, plan.watchdogUnits); err != nil {
		return rollbackIdentity(fmt.Errorf("install gateway watchdog units: %w", err))
	}
	transaction, err := initializer.runtime.Watchdog.Arm(ctx, GatewayInitWatchdogArm{
		AllowedSSHPort: plan.SSH.Port, Origin: plan.SSH.Connection,
		NetworkScope: linuxplatform.GatewayInitNetworkScope(),
	})
	if err != nil {
		return rollbackIdentity(fmt.Errorf("arm gateway lockout watchdog: %w", err))
	}
	var createdSwap *model.ManagedSwap
	var transportInstallation *transport.GatewayListenerInstallation
	statePersisted := false
	fail := func(applyErr error) (GatewayInitResult, error) {
		rollbackErr := initializer.runtime.Watchdog.RollbackNow(ctx, transaction.ID)
		var swapErr error
		var transportErr error
		var identityErr error
		if transportInstallation != nil && !statePersisted {
			transportErr = initializer.runtime.Transports.Rollback(context.Background(), *transportInstallation)
		}
		if createdSwap != nil && !statePersisted {
			swapErr = initializer.runtime.Swap.Deactivate(ctx, *createdSwap, true)
		}
		if !statePersisted {
			identityErr = initializer.runtime.Identity.Rollback(context.Background(), identity)
		}
		return GatewayInitResult{}, errors.Join(applyErr, rollbackErr, transportErr, swapErr, identityErr)
	}
	if plan.ManagedSwapSelected {
		owned, err := initializer.runtime.Swap.Apply(ctx, plan.ManagedSwap)
		if err != nil {
			return fail(fmt.Errorf("create managed swap: %w", err))
		}
		if plan.desiredState.Host.ManagedSwap == nil || owned != *plan.desiredState.Host.ManagedSwap {
			createdSwap = &owned
			return fail(fmt.Errorf("managed swap result differs from the authoritative plan"))
		}
		createdSwap = &owned
	}
	listeners, err := initializer.runtime.Transports.Provision(ctx, candidate)
	if err != nil {
		return fail(fmt.Errorf("provision gateway transport listeners: %w", err))
	}
	transportInstallation = &listeners
	roleRequest := plan.roleRequest
	roleRequest.Configs = append([]linuxplatform.RoleConfigFile(nil), roleRequest.Configs...)
	for _, file := range listeners.ConfigFiles() {
		roleRequest.Configs = append(roleRequest.Configs, linuxplatform.RoleConfigFile{Name: file.Name, Content: file.Content})
	}
	if err := initializer.runtime.State.Save(0, candidate); err != nil {
		return fail(fmt.Errorf("persist initial gateway state: %w", err))
	}
	statePersisted = true
	if _, err := initializer.runtime.Roles.Apply(ctx, roleRequest); err != nil {
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

func initialGatewayState(hostID string, initializedAt time.Time, network linuxplatform.GatewayNetworkPlan, sshPort int, manifest model.ComponentManifest, selected model.HandshakeHost) model.State {
	selection := selected
	return model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: hostID, Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: initializedAt,
			PublicIPv4: network.PublicIPv4, ExternalInterface: network.ExternalInterface, SSHPort: sshPort,
			ClientCIDR: network.ClientCIDR, NodeCIDR: network.NodeCIDR,
		},
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports: []model.Transport{}, Exposes: []model.Expose{}, Certificates: []model.Certificate{},
		Operations: []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{}, Components: manifest,
		HandshakeHost: &selection,
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
