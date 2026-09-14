package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

var (
	ErrGatewayRoleConflict           = errors.New("host is already initialized with another role")
	ErrGatewayInitConflict           = errors.New("gateway is already initialized with different inputs")
	ErrGatewayInitConvergencePending = errors.New("gateway initialization committed but convergence baseline is pending")
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
	DNSConfigFile        string
	WatchdogUnitFiles    []string
	ManagedSwap          linuxplatform.ManagedSwapPlan
	ManagedSwapSelected  bool
	HandshakeHost        model.HandshakeHost
	Packages             RolePackagePlan
	Ingress              ingress.NginxBaselinePlan
	Readiness            GatewayBootstrapReadinessReport

	desiredState     model.State
	releaseManifest  ReleaseManifest
	layout           GatewayLayoutPlan
	roleRequest      linuxplatform.RoleInstallationRequest
	watchdogUnits    linuxplatform.WatchdogUnitInstallationPlan
	firewall         linuxplatform.GatewayFirewallArtifact
	swapDecisionMade bool
	input            GatewayInitInput
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

type GatewayInitPublicCertificateProvisioner interface {
	Provision(context.Context, ingress.PublicCertificateRequest) (ingress.PublicCertificateInstallation, error)
	Rollback(context.Context, ingress.PublicCertificateInstallation) error
}

type GatewayInitHandshakeHostSelector interface {
	Select(context.Context, int, time.Time) (model.HandshakeHost, error)
}

type GatewayInitTransportProvisioner interface {
	Provision(context.Context, model.State) (transport.GatewayListenerInstallation, error)
	Rollback(context.Context, transport.GatewayListenerInstallation) error
}

type GatewayInitConvergencePublisher interface {
	PublishGatewayInitialization(context.Context, uint64, linuxplatform.RoleInstallationRequest) error
}

type GatewayInitIngressManager interface {
	Plan() (ingress.NginxBaselinePlan, error)
	Apply(context.Context, ingress.NginxBaselinePlan, ingress.NginxBaselineRequest) (ingress.NginxBaselineResult, *ingress.NginxBaselineInstallation, error)
	Commit(context.Context, *ingress.NginxBaselineInstallation) error
	Rollback(context.Context, *ingress.NginxBaselineInstallation) error
}

type GatewayInitReadinessInspector interface {
	Inspect(context.Context, model.State, ReleaseManifest) (GatewayBootstrapReadinessReport, error)
}

type GatewayInitRuntime struct {
	Paths             store.Paths
	Snapshot          linuxplatform.HostSnapshot
	Manifest          model.ComponentManifest
	Release           InitReleaseSource
	Packages          RolePackageManager
	Rediscover        InitHostDiscoverer
	BinaryPath        string
	State             GatewayInitStateStore
	Layout            *GatewayLayoutInstaller
	Roles             GatewayInitRoleInstaller
	WatchdogUnits     GatewayInitWatchdogUnitInstaller
	Watchdog          GatewayInitWatchdog
	Network           GatewayInitNetworkActivator
	Swap              GatewayInitSwapManager
	Identity          GatewayInitIdentityProvisioner
	PublicCertificate GatewayInitPublicCertificateProvisioner
	HandshakeHosts    GatewayInitHandshakeHostSelector
	Transports        GatewayInitTransportProvisioner
	Ingress           GatewayInitIngressManager
	Readiness         GatewayInitReadinessInspector
	Convergence       GatewayInitConvergencePublisher
	Now               func() time.Time
	NewHostID         model.UUIDGenerator
}

type GatewayInitializer struct {
	runtime GatewayInitRuntime
}

func NewGatewayInitializer(runtime GatewayInitRuntime) (*GatewayInitializer, error) {
	if runtime.State == nil || runtime.Layout == nil || runtime.Roles == nil || runtime.WatchdogUnits == nil || runtime.Watchdog == nil || runtime.Network == nil || runtime.Swap == nil || runtime.Identity == nil || runtime.PublicCertificate == nil || runtime.HandshakeHosts == nil || runtime.Transports == nil || runtime.Ingress == nil || runtime.Convergence == nil ||
		(runtime.Release != nil && (runtime.Packages == nil || runtime.Rediscover == nil || runtime.Readiness == nil)) {
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
	if err := runtime.Manifest.Validate(); err != nil && runtime.Release == nil {
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
	manifest := initializer.runtime.Manifest
	var releaseManifest ReleaseManifest
	var packagePlan RolePackagePlan
	if initializer.runtime.Release != nil {
		verified, err := initializer.runtime.Release.Inspect(ctx)
		if err != nil {
			return GatewayInitPlan{}, fmt.Errorf("verify local gateway release bundle: %w", err)
		}
		if err := verified.Validate(); err != nil {
			return GatewayInitPlan{}, fmt.Errorf("validate local gateway release bundle: %w", err)
		}
		releaseManifest = verified
		manifest = verified.ComponentManifest
		packagePlan, err = initializer.runtime.Packages.Plan(ctx, verified, model.RoleGateway)
		if err != nil {
			return GatewayInitPlan{}, fmt.Errorf("plan gateway packages: %w", err)
		}
	}
	if err := validatePrePackageCapabilities(snapshot, packagePlan); err != nil {
		return GatewayInitPlan{}, err
	}

	existing, loadErr := initializer.runtime.State.Load()
	if loadErr == nil {
		if existing.Host.Role != model.RoleGateway {
			return GatewayInitPlan{}, fmt.Errorf("%w: current role is %s", ErrGatewayRoleConflict, existing.Host.Role)
		}
		if !reflect.DeepEqual(existing.Components, manifest) {
			return GatewayInitPlan{}, fmt.Errorf("%w: installed release differs from authoritative state; use vpnctl update", ErrGatewayInitConflict)
		}
		snapshot = withoutOwnedGatewayNetwork(snapshot)
		plan, err := initializer.planExisting(ctx, input, snapshot, existing, releaseManifest, packagePlan)
		plan.releaseManifest = releaseManifest
		plan.Packages = packagePlan
		plan.input = input
		return plan, err
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
	watchdogUnits, err := initializer.runtime.WatchdogUnits.Plan(initializer.runtime.BinaryPath)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("plan watchdog units: %w", err)
	}
	ingressPlan, err := initializer.runtime.Ingress.Plan()
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("plan gateway ingress: %w", err)
	}
	managedSwap, err := initializer.runtime.Swap.Plan(snapshot.Resources)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("plan managed swap: %w", err)
	}
	initializedAt := initializer.runtime.Now().UTC()
	handshakeHost, err := initializer.runtime.HandshakeHosts.Select(ctx, manifest.HandshakeHostListVersion, initializedAt)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("select restricted handshake host: %w", err)
	}
	hostID, err := model.AllocateUUID(nil, initializer.runtime.NewHostID)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("allocate gateway host identity: %w", err)
	}
	desired, err := buildInitialGatewayState(hostID, initializedAt, network, ssh.Port, manifest, handshakeHost)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("build initial gateway state: %w", err)
	}
	if err := desired.Validate(); err != nil {
		return GatewayInitPlan{}, fmt.Errorf("build initial gateway state: %w", err)
	}
	dns, err := routing.RenderGatewayDNSConfig(desired)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("render shared gateway DNS: %w", err)
	}
	roleRequest.Configs = append(roleRequest.Configs,
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSConfigFileName, Content: dns.Bytes()},
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSReadyFileName, Content: []byte("schema_version=1\n")},
	)
	rolePlan, err := initializer.runtime.Roles.Plan(roleRequest)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("plan gateway services: %w", err)
	}
	firewall, err := RenderGatewayIdentityFirewall(desired, GatewayIdentityFirewallServices{
		ClientTCPPorts: []int{routing.GatewayDNSPort}, ClientUDPPorts: []int{routing.GatewayDNSPort},
		NodeTCPPorts: []int{routing.GatewayDNSPort, control.RPCControlTCPPort, tunnel.FRPServerPort}, NodeUDPPorts: []int{routing.GatewayDNSPort},
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
		DNSConfigFile:        filepath.Join(initializer.runtime.Paths.ConfigDir, "generated", "gateway", routing.GatewayDNSConfigFileName),
		WatchdogUnitFiles:    append([]string(nil), watchdogUnits.UnitFiles...),
		ManagedSwap:          managedSwap,
		HandshakeHost:        handshakeHost,
		Packages:             packagePlan,
		Ingress:              ingressPlan,
		desiredState:         desired, releaseManifest: releaseManifest, layout: layout, roleRequest: roleRequest, watchdogUnits: watchdogUnits, firewall: firewall,
		swapDecisionMade: !managedSwap.Offered, input: input,
	}, nil
}

func (initializer *GatewayInitializer) planExisting(ctx context.Context, input GatewayInitInput, snapshot linuxplatform.HostSnapshot, existing model.State, release ReleaseManifest, packages RolePackagePlan) (GatewayInitPlan, error) {
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
	plan := GatewayInitPlan{
		AlreadyInitialized: true, HostID: existing.Host.ID, Network: network, SSH: ssh,
		FixedListeners: []string{"443/tcp", "8443/tcp", "51820/udp"}, ManagedSwap: managedSwap,
		HandshakeHost: *existing.HandshakeHost,
		desiredState:  existing, swapDecisionMade: true, input: input,
	}
	if release.SchemaVersion == 0 {
		return plan, nil
	}
	readiness, err := initializer.runtime.Readiness.Inspect(ctx, existing, release)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("inspect existing gateway bootstrap: %w", err)
	}
	if err := readiness.Validate(); err != nil || readiness.Generation != existing.Generation {
		return GatewayInitPlan{}, errors.Join(fmt.Errorf("inspect existing gateway bootstrap returned invalid metadata"), err)
	}
	plan.Readiness = readiness
	if readiness.Ready {
		return plan, nil
	}
	for _, check := range readiness.Checks {
		if check.Condition == GatewayReadinessConflict {
			return GatewayInitPlan{}, fmt.Errorf("%w: existing gateway readiness conflict %s/%s", ErrGatewayInitConflict, check.Kind, check.ID)
		}
	}
	roleRequest, err := linuxplatform.RenderGatewayRoleInstallation(initializer.runtime.BinaryPath)
	if err != nil {
		return GatewayInitPlan{}, err
	}
	dns, err := routing.RenderGatewayDNSConfig(existing)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("render existing gateway DNS: %w", err)
	}
	roleRequest.Configs = append(roleRequest.Configs,
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSConfigFileName, Content: dns.Bytes()},
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSReadyFileName, Content: []byte("schema_version=1\n")},
	)
	rolePlan, err := initializer.runtime.Roles.Plan(roleRequest)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("plan existing gateway services: %w", err)
	}
	watchdogUnits, err := initializer.runtime.WatchdogUnits.Plan(initializer.runtime.BinaryPath)
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("plan existing gateway watchdog units: %w", err)
	}
	ingressPlan, err := initializer.runtime.Ingress.Plan()
	if err != nil {
		return GatewayInitPlan{}, fmt.Errorf("plan existing gateway ingress: %w", err)
	}
	firewall, err := RenderGatewayIdentityFirewall(existing, GatewayIdentityFirewallServices{
		ClientTCPPorts: []int{routing.GatewayDNSPort}, ClientUDPPorts: []int{routing.GatewayDNSPort},
		NodeTCPPorts: []int{routing.GatewayDNSPort, control.RPCControlTCPPort, tunnel.FRPServerPort}, NodeUDPPorts: []int{routing.GatewayDNSPort},
	})
	if err != nil {
		return GatewayInitPlan{}, err
	}
	plan.Changed = true
	plan.Packages = packages
	plan.Ingress = ingressPlan
	plan.Units = append([]string(nil), rolePlan.UnitsToStart...)
	plan.WatchdogUnitFiles = append([]string(nil), watchdogUnits.UnitFiles...)
	plan.roleRequest = roleRequest
	plan.watchdogUnits = watchdogUnits
	plan.firewall = firewall
	return plan, nil
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
	if plan.AlreadyInitialized && plan.Changed {
		return initializer.applyExisting(ctx, plan)
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
	var packageInstallation RolePackageInstallation
	if plan.releaseManifest.SchemaVersion != 0 {
		if initializer.runtime.Release == nil {
			return GatewayInitResult{}, fmt.Errorf("invalid gateway initialization release plan")
		}
		installed, err := initializer.runtime.Release.Install(ctx, model.RoleGateway)
		if err != nil {
			return GatewayInitResult{}, fmt.Errorf("install gateway release components: %w", err)
		}
		if !reflect.DeepEqual(installed.Manifest, plan.releaseManifest) {
			return GatewayInitResult{}, fmt.Errorf("installed gateway release differs from the verified plan")
		}
		if !reflect.DeepEqual(installed.RequiredAPTPackages, releaseAPTPackagesForRole(plan.releaseManifest, model.RoleGateway)) {
			return GatewayInitResult{}, fmt.Errorf("installed gateway package contract differs from the verified plan")
		}
		packageInstallation, err = initializer.runtime.Packages.Apply(ctx, plan.releaseManifest, plan.Packages)
		if err != nil {
			return GatewayInitResult{}, fmt.Errorf("install gateway packages: %w", err)
		}
		postPackage, err := initializer.runtime.Rediscover.Discover(ctx)
		if err != nil {
			return GatewayInitResult{}, errors.Join(fmt.Errorf("rediscover gateway after package installation: %w", err), initializer.runtime.Packages.Rollback(context.Background(), packageInstallation))
		}
		if err := postPackage.ValidateMandatoryCapabilities(); err != nil {
			return GatewayInitResult{}, errors.Join(err, initializer.runtime.Packages.Rollback(context.Background(), packageInstallation))
		}
		network, ssh, err := planGatewayInputs(plan.input, postPackage)
		if err == nil {
			_, err = linuxplatform.AnalyzeGatewayPreflight(linuxplatform.GatewayPreflightInput{Network: network, SSH: ssh}, postPackage)
		}
		if err != nil || !reflect.DeepEqual(network, plan.Network) || !reflect.DeepEqual(ssh, plan.SSH) {
			if err == nil {
				err = fmt.Errorf("post-package gateway host inputs differ from the approved plan")
			}
			return GatewayInitResult{}, errors.Join(err, initializer.runtime.Packages.Rollback(context.Background(), packageInstallation))
		}
	}
	rollbackPackages := func(applyErr error) (GatewayInitResult, error) {
		if packageInstallation.TransactionID == "" {
			return GatewayInitResult{}, applyErr
		}
		return GatewayInitResult{}, errors.Join(applyErr, initializer.runtime.Packages.Rollback(context.Background(), packageInstallation))
	}
	if _, err := initializer.runtime.Layout.Apply(plan.layout); err != nil {
		return rollbackPackages(fmt.Errorf("apply gateway layout: %w", err))
	}
	identity, err := initializer.runtime.Identity.Provision(ctx, control.GatewayIdentityRequest{
		GatewayID: plan.HostID, NodeCIDR: plan.Network.NodeCIDR, Initialized: plan.desiredState.Host.InitializedAt,
	})
	if err != nil {
		return rollbackPackages(fmt.Errorf("provision gateway control identity: %w", err))
	}
	rollbackIdentity := func(applyErr error) (GatewayInitResult, error) {
		return rollbackPackages(errors.Join(applyErr, initializer.runtime.Identity.Rollback(context.Background(), identity)))
	}
	publicCertificate, err := initializer.runtime.PublicCertificate.Provision(ctx, ingress.PublicCertificateRequest{
		GatewayID: plan.HostID, PublicIPv4: plan.Network.PublicIPv4, IssuedAt: plan.desiredState.Host.InitializedAt,
	})
	if err != nil {
		return rollbackIdentity(fmt.Errorf("provision public ingress certificate: %w", err))
	}
	rollbackIdentities := func(applyErr error) (GatewayInitResult, error) {
		return rollbackPackages(errors.Join(
			applyErr,
			initializer.runtime.PublicCertificate.Rollback(context.Background(), publicCertificate),
			initializer.runtime.Identity.Rollback(context.Background(), identity),
		))
	}
	candidate := plan.desiredState
	candidate.Certificates = append([]model.Certificate(nil), identity.Certificates...)
	candidate.Certificates = append(candidate.Certificates, publicCertificate.Certificate)
	enrollmentIdentity := identity.EnrollmentIdentity
	candidate.EnrollmentIdentity = &enrollmentIdentity
	if err := candidate.Validate(); err != nil {
		return rollbackIdentities(fmt.Errorf("validate provisioned gateway identity: %w", err))
	}
	if _, err := initializer.runtime.WatchdogUnits.Apply(ctx, plan.watchdogUnits); err != nil {
		return rollbackIdentities(fmt.Errorf("install gateway watchdog units: %w", err))
	}
	transaction, err := initializer.runtime.Watchdog.Arm(ctx, GatewayInitWatchdogArm{
		AllowedSSHPort: plan.SSH.Port, Origin: plan.SSH.Connection,
		NetworkScope: linuxplatform.GatewayInitNetworkScope(),
	})
	if err != nil {
		return rollbackIdentities(fmt.Errorf("arm gateway lockout watchdog: %w", err))
	}
	var createdSwap *model.ManagedSwap
	var transportInstallation *transport.GatewayListenerInstallation
	var ingressInstallation *ingress.NginxBaselineInstallation
	statePersisted := false
	fail := func(applyErr error) (GatewayInitResult, error) {
		rollbackErr := initializer.runtime.Watchdog.RollbackNow(ctx, transaction.ID)
		var swapErr error
		var transportErr error
		var ingressErr error
		var identityErr error
		if transportInstallation != nil && !statePersisted {
			transportErr = initializer.runtime.Transports.Rollback(context.Background(), *transportInstallation)
		}
		if ingressInstallation != nil {
			ingressErr = initializer.runtime.Ingress.Rollback(context.Background(), ingressInstallation)
		}
		if createdSwap != nil && !statePersisted {
			swapErr = initializer.runtime.Swap.Deactivate(ctx, *createdSwap, true)
		}
		if !statePersisted {
			identityErr = errors.Join(
				initializer.runtime.PublicCertificate.Rollback(context.Background(), publicCertificate),
				initializer.runtime.Identity.Rollback(context.Background(), identity),
			)
		}
		if packageInstallation.TransactionID != "" {
			identityErr = errors.Join(identityErr, initializer.runtime.Packages.Rollback(context.Background(), packageInstallation))
		}
		return GatewayInitResult{}, errors.Join(applyErr, rollbackErr, ingressErr, transportErr, swapErr, identityErr)
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
	certificatePath, err := gatewayInitSecretPath(initializer.runtime.Paths, model.SecretRef(publicCertificate.Certificate.CertificateRef))
	if err != nil {
		return fail(fmt.Errorf("resolve public ingress certificate path: %w", err))
	}
	privateKeyPath, err := gatewayInitSecretPath(initializer.runtime.Paths, publicCertificate.Certificate.PrivateKeyRef)
	if err != nil {
		return fail(fmt.Errorf("resolve public ingress private-key path: %w", err))
	}
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
	_, activatedIngress, err := initializer.runtime.Ingress.Apply(ctx, plan.Ingress, ingress.NginxBaselineRequest{
		StateGeneration: candidate.Generation, PublicIPv4: candidate.Host.PublicIPv4,
		CertificatePath: certificatePath, PrivateKeyPath: privateKeyPath,
		Exposes: candidate.Exposes,
	})
	if err != nil {
		return fail(errors.Join(ErrGatewayInitConvergencePending, fmt.Errorf("activate baseline gateway ingress: %w", err)))
	}
	ingressInstallation = activatedIngress
	if err := initializer.runtime.Network.ActivateGateway(ctx, plan.firewall); err != nil {
		return fail(fmt.Errorf("activate gateway network: %w", err))
	}
	if plan.releaseManifest.SchemaVersion != 0 {
		readiness, err := initializer.runtime.Readiness.Inspect(ctx, candidate, plan.releaseManifest)
		if err != nil || !readiness.Ready {
			if err == nil {
				err = fmt.Errorf("gateway bootstrap readiness is incomplete")
			}
			return fail(errors.Join(ErrGatewayInitConvergencePending, fmt.Errorf("verify gateway bootstrap readiness: %w", err)))
		}
	}
	if err := initializer.runtime.Convergence.PublishGatewayInitialization(ctx, candidate.Generation, roleRequest); err != nil {
		return fail(errors.Join(ErrGatewayInitConvergencePending, err))
	}
	// Keep package and ingress receipts reversible until the watchdog has
	// accepted responsibility for the live network. Otherwise a failed status
	// transition could roll back networking while leaving readiness healthy,
	// causing an idempotent init retry to miss the absent firewall.
	if err := initializer.runtime.Watchdog.MarkActivated(ctx, transaction.ID); err != nil {
		return fail(fmt.Errorf("mark gateway network active: %w", err))
	}
	if packageInstallation.TransactionID != "" {
		if err := initializer.runtime.Packages.Commit(ctx, packageInstallation); err != nil {
			return fail(errors.Join(ErrGatewayInitConvergencePending, fmt.Errorf("commit gateway package installation: %w", err)))
		}
	}
	if err := initializer.runtime.Ingress.Commit(ctx, ingressInstallation); err != nil {
		return fail(errors.Join(ErrGatewayInitConvergencePending, fmt.Errorf("commit baseline gateway ingress: %w", err)))
	}
	packageInstallation = RolePackageInstallation{}
	ingressInstallation = nil
	return GatewayInitResult{
		Changed: true, HostID: plan.HostID, TransactionID: transaction.ID,
		Network: plan.Network, Units: append([]string(nil), plan.Units...),
	}, nil
}

// applyExisting is the narrow retry path for authoritative state that was
// persisted by init before mandatory package/ingress convergence completed.
// It never recreates identity or client material and never advances state.
func (initializer *GatewayInitializer) applyExisting(ctx context.Context, plan GatewayInitPlan) (GatewayInitResult, error) {
	if plan.HostID == "" || plan.desiredState.Host.ID != plan.HostID || plan.releaseManifest.SchemaVersion == 0 || plan.Readiness.Ready {
		return GatewayInitResult{}, fmt.Errorf("invalid incomplete gateway initialization plan")
	}
	state, err := initializer.runtime.State.Load()
	if err != nil || !reflect.DeepEqual(state, plan.desiredState) {
		return GatewayInitResult{}, errors.Join(fmt.Errorf("incomplete gateway initialization plan is stale"), err)
	}
	freshReadiness, err := initializer.runtime.Readiness.Inspect(ctx, state, plan.releaseManifest)
	if err != nil || !reflect.DeepEqual(freshReadiness, plan.Readiness) {
		return GatewayInitResult{}, errors.Join(fmt.Errorf("incomplete gateway readiness changed after preview"), err)
	}
	installed, err := initializer.runtime.Release.Install(ctx, model.RoleGateway)
	if err != nil {
		return GatewayInitResult{}, fmt.Errorf("install existing gateway release components: %w", err)
	}
	if !reflect.DeepEqual(installed.Manifest, plan.releaseManifest) ||
		!reflect.DeepEqual(installed.RequiredAPTPackages, releaseAPTPackagesForRole(plan.releaseManifest, model.RoleGateway)) {
		return GatewayInitResult{}, fmt.Errorf("installed existing gateway release differs from the verified plan")
	}
	packageInstallation, err := initializer.runtime.Packages.Apply(ctx, plan.releaseManifest, plan.Packages)
	if err != nil {
		return GatewayInitResult{}, fmt.Errorf("repair existing gateway packages: %w", err)
	}
	rollbackPackages := func(cause error) (GatewayInitResult, error) {
		if packageInstallation.TransactionID == "" {
			return GatewayInitResult{}, cause
		}
		return GatewayInitResult{}, errors.Join(cause, initializer.runtime.Packages.Rollback(context.Background(), packageInstallation))
	}
	postPackage, err := initializer.runtime.Rediscover.Discover(ctx)
	if err != nil {
		return rollbackPackages(fmt.Errorf("rediscover incomplete gateway after package repair: %w", err))
	}
	if err := postPackage.ValidateMandatoryCapabilities(); err != nil {
		return rollbackPackages(err)
	}
	listeners, err := initializer.runtime.Transports.Provision(ctx, state)
	if err != nil {
		return rollbackPackages(fmt.Errorf("render incomplete gateway transport listeners: %w", err))
	}
	roleRequest := plan.roleRequest
	roleRequest.Configs = append([]linuxplatform.RoleConfigFile(nil), roleRequest.Configs...)
	for _, file := range listeners.ConfigFiles() {
		roleRequest.Configs = append(roleRequest.Configs, linuxplatform.RoleConfigFile{Name: file.Name, Content: file.Content})
	}
	if _, err := initializer.runtime.WatchdogUnits.Apply(ctx, plan.watchdogUnits); err != nil {
		return rollbackPackages(fmt.Errorf("repair incomplete gateway watchdog units: %w", err))
	}
	transaction, err := initializer.runtime.Watchdog.Arm(ctx, GatewayInitWatchdogArm{
		AllowedSSHPort: plan.SSH.Port, Origin: plan.SSH.Connection, NetworkScope: linuxplatform.GatewayInitNetworkScope(),
	})
	if err != nil {
		return rollbackPackages(fmt.Errorf("arm incomplete gateway lockout watchdog: %w", err))
	}
	var ingressInstallation *ingress.NginxBaselineInstallation
	fail := func(cause error) (GatewayInitResult, error) {
		var ingressErr error
		if ingressInstallation != nil {
			ingressErr = initializer.runtime.Ingress.Rollback(context.Background(), ingressInstallation)
		}
		packageErr := error(nil)
		if packageInstallation.TransactionID != "" {
			packageErr = initializer.runtime.Packages.Rollback(context.Background(), packageInstallation)
		}
		return GatewayInitResult{}, errors.Join(cause, initializer.runtime.Watchdog.RollbackNow(context.Background(), transaction.ID), ingressErr, packageErr)
	}
	if _, err := initializer.runtime.Roles.Apply(ctx, roleRequest); err != nil {
		return fail(fmt.Errorf("repair incomplete gateway services: %w", err))
	}
	certificatePath, privateKeyPath, err := gatewayInitPublicCertificatePaths(initializer.runtime.Paths, state)
	if err != nil {
		return fail(err)
	}
	_, activatedIngress, err := initializer.runtime.Ingress.Apply(ctx, plan.Ingress, ingress.NginxBaselineRequest{
		StateGeneration: state.Generation, PublicIPv4: state.Host.PublicIPv4,
		CertificatePath: certificatePath, PrivateKeyPath: privateKeyPath, Exposes: state.Exposes,
	})
	if err != nil {
		return fail(errors.Join(ErrGatewayInitConvergencePending, fmt.Errorf("repair incomplete gateway ingress: %w", err)))
	}
	ingressInstallation = activatedIngress
	if err := initializer.runtime.Network.ActivateGateway(ctx, plan.firewall); err != nil {
		return fail(fmt.Errorf("activate incomplete gateway network: %w", err))
	}
	readiness, err := initializer.runtime.Readiness.Inspect(ctx, state, plan.releaseManifest)
	if err != nil || !readiness.Ready {
		if err == nil {
			err = fmt.Errorf("gateway bootstrap readiness is incomplete")
		}
		return fail(errors.Join(ErrGatewayInitConvergencePending, fmt.Errorf("verify repaired gateway bootstrap readiness: %w", err)))
	}
	if err := initializer.runtime.Convergence.PublishGatewayInitialization(ctx, state.Generation, roleRequest); err != nil {
		return fail(errors.Join(ErrGatewayInitConvergencePending, err))
	}
	if err := initializer.runtime.Watchdog.MarkActivated(ctx, transaction.ID); err != nil {
		return fail(fmt.Errorf("mark incomplete gateway network active: %w", err))
	}
	if packageInstallation.TransactionID != "" {
		if err := initializer.runtime.Packages.Commit(ctx, packageInstallation); err != nil {
			return fail(errors.Join(ErrGatewayInitConvergencePending, fmt.Errorf("commit repaired gateway packages: %w", err)))
		}
	}
	if err := initializer.runtime.Ingress.Commit(ctx, ingressInstallation); err != nil {
		return fail(errors.Join(ErrGatewayInitConvergencePending, fmt.Errorf("commit repaired gateway ingress: %w", err)))
	}
	packageInstallation = RolePackageInstallation{}
	ingressInstallation = nil
	return GatewayInitResult{
		Changed: true, HostID: state.Host.ID, TransactionID: transaction.ID,
		Network: plan.Network, Units: append([]string(nil), plan.Units...),
	}, nil
}

func gatewayInitPublicCertificatePaths(paths store.Paths, state model.State) (string, string, error) {
	var certificate model.Certificate
	found := false
	for _, item := range state.Certificates {
		if item.Kind != model.CertificatePublicIngress {
			continue
		}
		if found {
			return "", "", fmt.Errorf("multiple public ingress certificates are active")
		}
		certificate, found = item, true
	}
	if !found {
		return "", "", ingress.ErrPublicCertificateNotFound
	}
	certificatePath, err := gatewayInitSecretPath(paths, model.SecretRef(certificate.CertificateRef))
	if err != nil {
		return "", "", fmt.Errorf("resolve public ingress certificate path: %w", err)
	}
	privateKeyPath, err := gatewayInitSecretPath(paths, certificate.PrivateKeyRef)
	if err != nil {
		return "", "", fmt.Errorf("resolve public ingress private-key path: %w", err)
	}
	return certificatePath, privateKeyPath, nil
}

func gatewayInitSecretPath(paths store.Paths, reference model.SecretRef) (string, error) {
	kind, id, err := reference.Parts()
	if err != nil || strings.ContainsAny(kind+id, `/\\`) {
		return "", fmt.Errorf("invalid secret reference")
	}
	return filepath.Join(paths.SecretsDir, kind, id), nil
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

func buildInitialGatewayState(hostID string, initializedAt time.Time, network linuxplatform.GatewayNetworkPlan, sshPort int, manifest model.ComponentManifest, selected model.HandshakeHost) (model.State, error) {
	selection := selected
	dns := model.DNSUpstreamState{
		SchemaVersion: model.ResourceSchemaVersion,
		Scope:         model.DNSUpstreamGateway,
		IPv4:          model.DefaultGatewayDNSUpstreams(),
	}
	templates, err := routing.BuiltinPresetTemplates()
	if err != nil {
		return model.State{}, fmt.Errorf("load built-in presets: %w", err)
	}
	presets := make([]model.Preset, 0, len(templates))
	for _, template := range templates {
		preset, compileErr := routing.CompilePresetSource(template.Source, initializedAt)
		if compileErr != nil {
			return model.State{}, fmt.Errorf("compile built-in preset %s: %w", template.Name, compileErr)
		}
		presets = append(presets, preset)
	}
	return model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: hostID, Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: initializedAt,
			PublicIPv4: network.PublicIPv4, ExternalInterface: network.ExternalInterface, SSHPort: sshPort,
			ClientCIDR: network.ClientCIDR, NodeCIDR: network.NodeCIDR,
		},
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{}, Presets: presets, Policies: []model.Policy{},
		Transports: []model.Transport{}, Exposes: []model.Expose{}, Certificates: []model.Certificate{},
		Operations: []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{}, Components: manifest,
		HandshakeHost: &selection, DNS: &dns,
	}, nil
}

func withoutOwnedGatewayNetwork(snapshot linuxplatform.HostSnapshot) linuxplatform.HostSnapshot {
	result := snapshot
	result.Listeners = filterValues(snapshot.Listeners, func(value linuxplatform.Listener) bool {
		return !(value.Protocol == "tcp" && (value.Port == linuxplatform.GatewayHTTPSTCPPort || value.Port == linuxplatform.GatewayRestrictedTCPPort) ||
			value.Protocol == "udp" && value.Port == linuxplatform.GatewayWireGuardUDPPort)
	})
	result.NFTablesTables = filterValues(snapshot.NFTablesTables, func(value linuxplatform.NFTablesTable) bool {
		return value.Family != linuxplatform.GatewayFirewallFamily || value.Name != linuxplatform.GatewayFirewallTable
	})
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
