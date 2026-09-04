package lifecycle

import (
	"context"
	"fmt"
	"reflect"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const purgePlanMarker = "<redacted-purge-plan>"

type PurgeOptions struct {
	Force          bool
	LocalOnly      bool
	IncludeBackups bool
}

type PurgeHostPlan struct {
	StateGeneration uint64
	ConfigDir       string
	StateDir        string
	BackupsDir      string
	IncludeBackups  bool
	BackupArchives  int
}

func (plan PurgeHostPlan) Validate() error {
	if plan.StateGeneration == 0 || plan.ConfigDir == "" || plan.StateDir == "" || plan.BackupsDir == "" {
		return fmt.Errorf("%w: purge paths and state generation are required", ErrUninstallRuntimePlan)
	}
	if plan.BackupArchives < 0 {
		return fmt.Errorf("%w: purge backup count is invalid", ErrUninstallRuntimePlan)
	}
	return nil
}

type PurgeRuntime interface {
	UninstallRuntime
	InspectPurge(context.Context, model.State, bool) (PurgeHostPlan, error)
	PurgeManagedSwap(context.Context, UninstallHostPlan) (bool, error)
	RemovePurgedData(context.Context, PurgeHostPlan) (bool, bool, error)
}

type PurgePlan struct {
	Role                    model.Role
	NodeID                  string
	Changed                 bool
	Blocked                 bool
	ForceRequired           bool
	Force                   bool
	LocalOnly               bool
	NodeRevokeRequired      bool
	IncludeBackups          bool
	BackupArchives          int
	ExpectedStateGeneration uint64
	ActiveNodeIDs           []string
	ActiveClientIDs         []string
	ActiveExposeIDs         []string
	AffectedServices        []string
	Removed                 []string
	Preserved               []string

	uninstall UninstallPlan
	host      PurgeHostPlan
}

func (PurgePlan) String() string   { return purgePlanMarker }
func (PurgePlan) GoString() string { return purgePlanMarker }
func (PurgePlan) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type PurgeResult struct {
	Role                    model.Role
	NodeID                  string
	SourceStateGeneration   uint64
	Changed                 bool
	LocalOnly               bool
	IncludeBackups          bool
	BackupArchives          int
	NodeRevoked             bool
	GatewayGeneration       uint64
	DNSRestored             bool
	NetworkRestored         bool
	ManagedSwapPurged       bool
	DataPurged              bool
	BackupsRemoved          bool
	BinaryRemoved           bool
	InstallerBinaryRetained bool
	ActiveNodeIDs           []string
	ActiveClientIDs         []string
	ActiveExposeIDs         []string
	AffectedServices        []string
	Removed                 []string
	Preserved               []string
}

type Purger struct {
	state   UninstallStateStore
	runtime PurgeRuntime
}

func NewPurger(state UninstallStateStore, runtime PurgeRuntime) (*Purger, error) {
	if state == nil || runtime == nil {
		return nil, fmt.Errorf("purge state and runtime are required")
	}
	return &Purger{state: state, runtime: runtime}, nil
}

func (purger *Purger) Plan(ctx context.Context, options PurgeOptions) (PurgePlan, error) {
	if ctx == nil {
		return PurgePlan{}, fmt.Errorf("context is required")
	}
	if purger == nil || purger.state == nil || purger.runtime == nil {
		return PurgePlan{}, fmt.Errorf("purger is incomplete")
	}
	uninstaller, _ := NewUninstaller(purger.state, purger.runtime)
	uninstall, err := uninstaller.Plan(ctx, UninstallOptions{Force: options.Force, LocalOnly: options.LocalOnly})
	if err != nil {
		return PurgePlan{}, err
	}
	if options.IncludeBackups && uninstall.Role != model.RoleGateway {
		return PurgePlan{}, fmt.Errorf("%w: --include-backups is gateway-only", ErrUninstallRoleFlag)
	}
	host, err := purger.runtime.InspectPurge(ctx, uninstall.state, options.IncludeBackups)
	if err != nil {
		return PurgePlan{}, fmt.Errorf("inspect purge ownership: %w", err)
	}
	if err := host.Validate(); err != nil {
		return PurgePlan{}, err
	}
	if host.StateGeneration != uninstall.ExpectedStateGeneration || host.IncludeBackups != options.IncludeBackups {
		return PurgePlan{}, ErrUninstallPlanStale
	}
	removed := []string{"/etc/vpnctl", "/var/lib/vpnctl managed state, identities, secrets, certificates, operations, snapshots, and exports"}
	if uninstall.host.ManagedSwapOwned {
		removed = append(removed, "vpnctl managed swap allocation")
	}
	preserved := []string{}
	if options.IncludeBackups {
		if host.BackupArchives > 0 {
			removed = append(removed, "/var/lib/vpnctl/backups")
		}
	} else if host.BackupArchives > 0 {
		preserved = append(preserved, "/var/lib/vpnctl/backups")
	}
	return PurgePlan{
		Role: uninstall.Role, NodeID: uninstall.NodeID, Changed: true, Blocked: uninstall.Blocked,
		ForceRequired: uninstall.ForceRequired, Force: uninstall.Force, LocalOnly: uninstall.LocalOnly,
		NodeRevokeRequired: uninstall.NodeRevokeRequired, IncludeBackups: options.IncludeBackups,
		BackupArchives: host.BackupArchives, ExpectedStateGeneration: uninstall.ExpectedStateGeneration,
		ActiveNodeIDs: append([]string(nil), uninstall.ActiveNodeIDs...), ActiveClientIDs: append([]string(nil), uninstall.ActiveClientIDs...),
		ActiveExposeIDs: append([]string(nil), uninstall.ActiveExposeIDs...), AffectedServices: append([]string(nil), uninstall.AffectedServices...),
		Removed: removed, Preserved: preserved, uninstall: uninstall, host: host,
	}, nil
}

func (purger *Purger) Apply(ctx context.Context, plan PurgePlan) (PurgeResult, error) {
	if ctx == nil {
		return PurgeResult{}, fmt.Errorf("context is required")
	}
	if purger == nil || purger.state == nil || purger.runtime == nil {
		return PurgeResult{}, fmt.Errorf("purger is incomplete")
	}
	if plan.Blocked {
		return PurgeResult{}, ErrUninstallForceRequired
	}
	fresh, err := purger.state.Load()
	if err != nil {
		return PurgeResult{}, fmt.Errorf("reload authoritative purge state: %w", err)
	}
	if fresh.Generation != plan.ExpectedStateGeneration || !reflect.DeepEqual(fresh, plan.uninstall.state) {
		return PurgeResult{}, ErrUninstallPlanStale
	}
	host, err := purger.runtime.Inspect(ctx, fresh)
	if err != nil || !reflect.DeepEqual(host, plan.uninstall.host) {
		return PurgeResult{}, ErrUninstallPlanStale
	}
	purgeHost, err := purger.runtime.InspectPurge(ctx, fresh, plan.IncludeBackups)
	if err != nil || !reflect.DeepEqual(purgeHost, plan.host) {
		return PurgeResult{}, ErrUninstallPlanStale
	}
	result := PurgeResult{
		Role: plan.Role, NodeID: plan.NodeID, SourceStateGeneration: plan.ExpectedStateGeneration,
		Changed: true, LocalOnly: plan.LocalOnly, IncludeBackups: plan.IncludeBackups,
		BackupArchives: plan.BackupArchives, InstallerBinaryRetained: plan.uninstall.host.BinaryPath == "",
		ActiveNodeIDs: append([]string(nil), plan.ActiveNodeIDs...), ActiveClientIDs: append([]string(nil), plan.ActiveClientIDs...),
		ActiveExposeIDs: append([]string(nil), plan.ActiveExposeIDs...), AffectedServices: append([]string(nil), plan.AffectedServices...),
		Removed: append([]string(nil), plan.Removed...), Preserved: append([]string(nil), plan.Preserved...),
	}
	if plan.Role == model.RoleNode && plan.NodeRevokeRequired && !plan.LocalOnly {
		revocation, revokeErr := purger.runtime.RevokeNode(ctx, fresh)
		if revokeErr != nil || !revocation.Confirmed || revocation.GatewayGeneration == 0 {
			if revokeErr == nil {
				revokeErr = ErrUninstallGatewayUnavailable
			}
			return PurgeResult{}, fmt.Errorf("%w: %v", ErrUninstallGatewayUnavailable, revokeErr)
		}
		result.NodeRevoked, result.GatewayGeneration = true, revocation.GatewayGeneration
	}
	if err := purger.runtime.StopServices(ctx, plan.uninstall.host); err != nil {
		return result, fmt.Errorf("stop purge services: %w", err)
	}
	if result.DNSRestored, err = purger.runtime.RestoreDNS(ctx, plan.uninstall.host); err != nil {
		return result, fmt.Errorf("restore purge DNS: %w", err)
	}
	if result.NetworkRestored, err = purger.runtime.RestoreNetwork(ctx, plan.uninstall.host); err != nil {
		return result, fmt.Errorf("restore purge network: %w", err)
	}
	if result.ManagedSwapPurged, err = purger.runtime.PurgeManagedSwap(ctx, plan.uninstall.host); err != nil {
		return result, fmt.Errorf("purge managed swap: %w", err)
	}
	if err := purger.runtime.RemoveManagedRuntime(ctx, plan.uninstall.host); err != nil {
		return result, fmt.Errorf("remove managed purge runtime: %w", err)
	}
	if result.DataPurged, result.BackupsRemoved, err = purger.runtime.RemovePurgedData(ctx, plan.host); err != nil {
		return result, fmt.Errorf("remove irreversible vpnctl data: %w", err)
	}
	if result.BinaryRemoved, err = purger.runtime.RemoveBinary(ctx, plan.uninstall.host); err != nil {
		return result, fmt.Errorf("remove installer-managed vpnctl binary last: %w", err)
	}
	return result, nil
}
