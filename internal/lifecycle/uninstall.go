package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const uninstallPlanMarker = "<redacted-uninstall-plan>"

var (
	ErrUninstallForceRequired      = errors.New("gateway uninstall requires force while active resources exist")
	ErrUninstallGatewayUnavailable = errors.New("gateway did not confirm node revocation")
	ErrUninstallPlanStale          = errors.New("uninstall plan is stale")
	ErrUninstallRoleFlag           = errors.New("uninstall flag is invalid for the current role")
	ErrUninstallRuntimePlan        = errors.New("invalid uninstall runtime plan")
)

type UninstallOptions struct {
	Force     bool
	LocalOnly bool
}

// UninstallHostPlan is the fully preflighted, non-secret ownership boundary
// supplied by the host adapter. BinaryPath is populated only when the current
// vpnctl executable is proven to be installer-managed.
type UninstallHostPlan struct {
	StateGeneration        uint64
	Units                  []string
	AuxiliaryUnits         []string
	GeneratedPaths         []string
	RuntimePaths           []string
	ComponentPaths         []string
	BinaryPath             string
	BinarySHA256           string
	WatchdogTransactionIDs []string
	WatchdogUnitFiles      []string
	DNSRestorationRequired bool
	NetworkRestoreRequired bool
	ManagedSwapOwned       bool
}

func (plan UninstallHostPlan) Validate(role model.Role) error {
	if role != model.RoleGateway && role != model.RoleNode {
		return fmt.Errorf("%w: unsupported role %q", ErrUninstallRuntimePlan, role)
	}
	if plan.StateGeneration == 0 {
		return fmt.Errorf("%w: state generation must be positive", ErrUninstallRuntimePlan)
	}
	for label, values := range map[string][]string{
		"units": plan.Units, "auxiliary units": plan.AuxiliaryUnits, "generated paths": plan.GeneratedPaths,
		"runtime paths": plan.RuntimePaths, "component paths": plan.ComponentPaths,
		"watchdog transactions": plan.WatchdogTransactionIDs, "watchdog unit files": plan.WatchdogUnitFiles,
	} {
		if values == nil {
			return fmt.Errorf("%w: %s must be present", ErrUninstallRuntimePlan, label)
		}
		if !sortedUniqueNonempty(values) {
			return fmt.Errorf("%w: %s must be sorted, unique, and non-empty", ErrUninstallRuntimePlan, label)
		}
	}
	if role == model.RoleGateway && plan.DNSRestorationRequired {
		return fmt.Errorf("%w: gateway cannot request node DNS restoration", ErrUninstallRuntimePlan)
	}
	if (plan.BinaryPath == "") != (plan.BinarySHA256 == "") || plan.BinarySHA256 != "" && !validReleaseSHA256(plan.BinarySHA256) {
		return fmt.Errorf("%w: binary path and SHA-256 must form a valid pair", ErrUninstallRuntimePlan)
	}
	return nil
}

type UninstallNodeRevocation struct {
	Confirmed         bool
	GatewayGeneration uint64
}

type UninstallRuntime interface {
	Inspect(context.Context, model.State) (UninstallHostPlan, error)
	RevokeNode(context.Context, model.State) (UninstallNodeRevocation, error)
	StopServices(context.Context, UninstallHostPlan) error
	RestoreDNS(context.Context, UninstallHostPlan) (bool, error)
	RestoreNetwork(context.Context, UninstallHostPlan) (bool, error)
	DisableManagedSwap(context.Context, UninstallHostPlan) (bool, uint64, error)
	RemoveManagedRuntime(context.Context, UninstallHostPlan) error
	RemoveBinary(context.Context, UninstallHostPlan) (bool, error)
}

type UninstallStateStore interface {
	Load() (model.State, error)
}

// UninstallPlan is deliberately unserializable: it retains the exact state
// and ownership plan used to reject drift before the first external or local
// mutation.
type UninstallPlan struct {
	Role                    model.Role
	NodeID                  string
	Changed                 bool
	Blocked                 bool
	ForceRequired           bool
	Force                   bool
	LocalOnly               bool
	NodeRevokeRequired      bool
	ExpectedStateGeneration uint64
	ActiveNodeIDs           []string
	ActiveClientIDs         []string
	ActiveExposeIDs         []string
	AffectedServices        []string
	Preserved               []string

	state model.State
	host  UninstallHostPlan
}

func (UninstallPlan) String() string   { return uninstallPlanMarker }
func (UninstallPlan) GoString() string { return uninstallPlanMarker }
func (UninstallPlan) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type UninstallResult struct {
	Role                    model.Role
	NodeID                  string
	Changed                 bool
	LocalOnly               bool
	NodeRevoked             bool
	GatewayGeneration       uint64
	StateGeneration         uint64
	DNSRestored             bool
	NetworkRestored         bool
	ManagedSwapDisabled     bool
	BinaryRemoved           bool
	InstallerBinaryRetained bool
	ActiveNodeIDs           []string
	ActiveClientIDs         []string
	ActiveExposeIDs         []string
	AffectedServices        []string
	Preserved               []string
}

type Uninstaller struct {
	state   UninstallStateStore
	runtime UninstallRuntime
}

func NewUninstaller(state UninstallStateStore, runtime UninstallRuntime) (*Uninstaller, error) {
	if state == nil || runtime == nil {
		return nil, fmt.Errorf("uninstall state and runtime are required")
	}
	return &Uninstaller{state: state, runtime: runtime}, nil
}

func (uninstaller *Uninstaller) Plan(ctx context.Context, options UninstallOptions) (UninstallPlan, error) {
	if ctx == nil {
		return UninstallPlan{}, fmt.Errorf("context is required")
	}
	if uninstaller == nil || uninstaller.state == nil || uninstaller.runtime == nil {
		return UninstallPlan{}, fmt.Errorf("uninstaller is incomplete")
	}
	state, err := uninstaller.state.Load()
	if err != nil {
		return UninstallPlan{}, fmt.Errorf("load authoritative uninstall state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return UninstallPlan{}, fmt.Errorf("validate authoritative uninstall state: %w", err)
	}
	if state.Host.Role != model.RoleGateway && state.Host.Role != model.RoleNode {
		return UninstallPlan{}, fmt.Errorf("uninstall requires an initialized gateway or node")
	}
	if options.Force && state.Host.Role != model.RoleGateway {
		return UninstallPlan{}, fmt.Errorf("%w: --force is gateway-only", ErrUninstallRoleFlag)
	}
	if options.LocalOnly && state.Host.Role != model.RoleNode {
		return UninstallPlan{}, fmt.Errorf("%w: --local-only is node-only", ErrUninstallRoleFlag)
	}
	host, err := uninstaller.runtime.Inspect(ctx, state)
	if err != nil {
		return UninstallPlan{}, fmt.Errorf("inspect uninstall ownership: %w", err)
	}
	if err := host.Validate(state.Host.Role); err != nil {
		return UninstallPlan{}, err
	}
	if host.StateGeneration != state.Generation {
		return UninstallPlan{}, ErrUninstallPlanStale
	}
	plan := UninstallPlan{
		Role: state.Host.Role, Changed: true, Force: options.Force, LocalOnly: options.LocalOnly,
		ExpectedStateGeneration: state.Generation, AffectedServices: uninstallAffectedServices(host),
		Preserved: uninstallPreservedPaths(), state: state, host: host,
	}
	if state.Host.Role == model.RoleGateway {
		plan.ActiveNodeIDs, plan.ActiveClientIDs, plan.ActiveExposeIDs = activeUninstallResources(state)
		plan.ForceRequired = len(plan.ActiveNodeIDs)+len(plan.ActiveClientIDs)+len(plan.ActiveExposeIDs) != 0
		plan.Blocked = plan.ForceRequired && !options.Force
	} else if len(state.Nodes) == 1 {
		plan.NodeID = state.Nodes[0].ID
		if state.Nodes[0].Lifecycle == model.LifecycleActive && state.Nodes[0].Gateway != nil {
			plan.NodeRevokeRequired = true
		}
	}
	return plan, nil
}

func uninstallAffectedServices(host UninstallHostPlan) []string {
	result := append(append([]string(nil), host.Units...), host.AuxiliaryUnits...)
	if host.ManagedSwapOwned {
		result = append(result, "vpnctl-managed-swap.service")
	}
	sort.Strings(result)
	return result
}

func (uninstaller *Uninstaller) Apply(ctx context.Context, plan UninstallPlan) (UninstallResult, error) {
	if ctx == nil {
		return UninstallResult{}, fmt.Errorf("context is required")
	}
	if uninstaller == nil || uninstaller.state == nil || uninstaller.runtime == nil {
		return UninstallResult{}, fmt.Errorf("uninstaller is incomplete")
	}
	if plan.Blocked {
		return UninstallResult{}, ErrUninstallForceRequired
	}
	fresh, err := uninstaller.state.Load()
	if err != nil {
		return UninstallResult{}, fmt.Errorf("reload authoritative uninstall state: %w", err)
	}
	if fresh.Generation != plan.ExpectedStateGeneration || !reflect.DeepEqual(fresh, plan.state) {
		return UninstallResult{}, ErrUninstallPlanStale
	}
	host, err := uninstaller.runtime.Inspect(ctx, fresh)
	if err != nil {
		return UninstallResult{}, fmt.Errorf("reinspect uninstall ownership: %w", err)
	}
	if !reflect.DeepEqual(host, plan.host) {
		return UninstallResult{}, ErrUninstallPlanStale
	}
	result := UninstallResult{
		Role: plan.Role, NodeID: plan.NodeID, Changed: true, LocalOnly: plan.LocalOnly, StateGeneration: fresh.Generation,
		ActiveNodeIDs: append([]string(nil), plan.ActiveNodeIDs...), ActiveClientIDs: append([]string(nil), plan.ActiveClientIDs...),
		ActiveExposeIDs: append([]string(nil), plan.ActiveExposeIDs...), AffectedServices: append([]string(nil), plan.AffectedServices...),
		Preserved: append([]string(nil), plan.Preserved...), InstallerBinaryRetained: plan.host.BinaryPath == "",
	}
	if plan.Role == model.RoleNode && plan.NodeRevokeRequired && !plan.LocalOnly {
		revocation, err := uninstaller.runtime.RevokeNode(ctx, fresh)
		if err != nil || !revocation.Confirmed || revocation.GatewayGeneration == 0 {
			if err == nil {
				err = ErrUninstallGatewayUnavailable
			}
			return UninstallResult{}, fmt.Errorf("%w: %v", ErrUninstallGatewayUnavailable, err)
		}
		result.NodeRevoked = true
		result.GatewayGeneration = revocation.GatewayGeneration
	}
	if err := uninstaller.runtime.StopServices(ctx, plan.host); err != nil {
		return result, fmt.Errorf("stop uninstall services: %w", err)
	}
	if result.DNSRestored, err = uninstaller.runtime.RestoreDNS(ctx, plan.host); err != nil {
		return result, fmt.Errorf("restore uninstall DNS: %w", err)
	}
	if result.NetworkRestored, err = uninstaller.runtime.RestoreNetwork(ctx, plan.host); err != nil {
		return result, fmt.Errorf("restore uninstall network: %w", err)
	}
	if result.ManagedSwapDisabled, result.StateGeneration, err = uninstaller.runtime.DisableManagedSwap(ctx, plan.host); err != nil {
		return result, fmt.Errorf("disable uninstall managed swap: %w", err)
	}
	if err := uninstaller.runtime.RemoveManagedRuntime(ctx, plan.host); err != nil {
		return result, fmt.Errorf("remove managed uninstall runtime: %w", err)
	}
	if result.BinaryRemoved, err = uninstaller.runtime.RemoveBinary(ctx, plan.host); err != nil {
		return result, fmt.Errorf("remove installer-managed vpnctl binary last: %w", err)
	}
	return result, nil
}

func activeUninstallResources(state model.State) ([]string, []string, []string) {
	nodes := make([]string, 0)
	for _, node := range state.Nodes {
		if node.Lifecycle == model.LifecycleActive {
			nodes = append(nodes, node.ID)
		}
	}
	clients := make([]string, 0)
	for _, client := range state.Clients {
		if client.Lifecycle == model.LifecycleActive {
			clients = append(clients, client.ID)
		}
	}
	exposes := make([]string, 0)
	for _, expose := range state.Exposes {
		if expose.State != model.ExposeDisabled {
			exposes = append(exposes, expose.ID)
		}
	}
	for _, values := range [][]string{nodes, clients, exposes} {
		sort.Strings(values)
	}
	return nodes, clients, exposes
}

func uninstallPreservedPaths() []string {
	return []string{
		"/etc/vpnctl/presets.d", "/var/lib/vpnctl/backups", "/var/lib/vpnctl/exports",
		"/var/lib/vpnctl/secrets", "/var/lib/vpnctl/state.json",
	}
}

func sortedUniqueNonempty(values []string) bool {
	for index, value := range values {
		if value == "" || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}
