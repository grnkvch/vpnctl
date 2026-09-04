package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

var (
	ErrGatewayRestoreConflict      = errors.New("gateway restore conflict")
	ErrGatewayRestoreReplaceNeeded = errors.New("initialized gateway restore requires --replace")
	ErrGatewayRestoreIncompatible  = errors.New("gateway restore is incompatible with the installed release")
	ErrGatewayRestoreEndpointMove  = errors.New("gateway restore to a different public IP requires endpoint migration planning")
)

type GatewayRestoreInput struct {
	ArchivePath string
	PublicIPv4  string
	Replace     bool
}

type GatewayRestoreHostState struct {
	Initialized      bool
	Role             model.Role
	StateGeneration  uint64
	OwnershipSHA256  string
	CurrentGatewayID string
}

func (state GatewayRestoreHostState) Validate() error {
	if !state.Initialized {
		if state.Role != "" || state.StateGeneration != 0 || state.CurrentGatewayID != "" {
			return fmt.Errorf("clean restore host cannot contain initialized identity")
		}
		return validateOptionalRestoreHash(state.OwnershipSHA256)
	}
	if state.Role != model.RoleGateway && state.Role != model.RoleNode {
		return fmt.Errorf("initialized restore host role is invalid")
	}
	if state.StateGeneration == 0 || model.ValidateResourceID(state.CurrentGatewayID) != nil || !validReleaseSHA256(state.OwnershipSHA256) {
		return fmt.Errorf("initialized restore host identity is incomplete")
	}
	return nil
}

type GatewayRestorePreflight struct {
	Candidate             model.State
	Network               linuxplatform.GatewayNetworkPlan
	SSH                   linuxplatform.SSHPortPlan
	PortRemaps            []tunnel.PortRemap
	AffectedServices      []string
	ExpectedInterruptions []string
}

type GatewayRestoreEmergencySnapshot struct {
	ID        string
	Path      string
	CreatedAt time.Time
}

func (snapshot GatewayRestoreEmergencySnapshot) Validate() error {
	if model.ValidateResourceID(snapshot.ID) != nil || !filepath.IsAbs(snapshot.Path) || filepath.Clean(snapshot.Path) != snapshot.Path ||
		strings.ContainsAny(snapshot.Path, "\x00\r\n") || snapshot.CreatedAt.IsZero() || !snapshot.CreatedAt.Equal(snapshot.CreatedAt.UTC().Truncate(time.Second)) {
		return fmt.Errorf("gateway restore emergency snapshot is invalid")
	}
	return nil
}

type GatewayRestoreActivation struct {
	ID      string
	Started bool
}

type GatewayRestoreReleaseSource interface {
	Inspect(context.Context) (ReleaseManifest, error)
	Install(context.Context, model.Role) (ReleaseBundleInstallResult, error)
}

// GatewayRestoreHost owns the mutation boundary. Inspect and Preflight are
// read-only. Activate must either leave the prior host intact or return a
// Started handle that Rollback can use to restore it exactly.
type GatewayRestoreHost interface {
	Inspect(context.Context) (GatewayRestoreHostState, error)
	Preflight(context.Context, *GatewayRestorePayload, model.State, GatewayRestoreHostState) (GatewayRestorePreflight, error)
	EmergencySnapshot(context.Context, GatewayRestoreHostState) (GatewayRestoreEmergencySnapshot, error)
	Activate(context.Context, *GatewayRestorePayload, GatewayRestorePreflight, GatewayRestoreEmergencySnapshot) (GatewayRestoreActivation, error)
	Health(context.Context, GatewayRestoreActivation, model.State) error
	Commit(context.Context, GatewayRestoreActivation) error
	Rollback(context.Context, GatewayRestoreActivation, GatewayRestoreEmergencySnapshot) error
}

type GatewayRestoreRuntime struct {
	Archives *GatewayRestoreArchiveLoader
	Release  GatewayRestoreReleaseSource
	Host     GatewayRestoreHost
}

type GatewayRestorePlan struct {
	ArchivePath             string
	PublicIPv4              string
	OriginalPublicIPv4      string
	Replace                 bool
	ReplacingInitialized    bool
	SameEndpoint            bool
	TrustPreserved          bool
	GatewayID               string
	SourceGeneration        uint64
	TargetGeneration        uint64
	NodeCount               int
	ClientCount             int
	PortRemaps              []tunnel.PortRemap
	AffectedServices        []string
	ExpectedInterruptions   []string
	EmergencySnapshotNeeded bool

	hostState GatewayRestoreHostState
	preflight GatewayRestorePreflight
	payload   *GatewayRestorePayload
}

type GatewayRestoreResult struct {
	Changed               bool
	GatewayID             string
	PublicIPv4            string
	Generation            uint64
	SameEndpoint          bool
	TrustPreserved        bool
	NodeCount             int
	ClientCount           int
	EmergencySnapshot     *GatewayRestoreEmergencySnapshot
	AffectedServices      []string
	ExpectedInterruptions []string
}

type GatewayRestorer struct {
	runtime GatewayRestoreRuntime
	mu      sync.Mutex
}

func NewGatewayRestorer(runtime GatewayRestoreRuntime) (*GatewayRestorer, error) {
	if runtime.Archives == nil || runtime.Release == nil || runtime.Host == nil {
		return nil, fmt.Errorf("gateway restore dependencies are incomplete")
	}
	return &GatewayRestorer{runtime: runtime}, nil
}

func (restorer *GatewayRestorer) Plan(ctx context.Context, input GatewayRestoreInput, passphrase []byte) (GatewayRestorePlan, error) {
	if ctx == nil || restorer == nil {
		wipeBackupBytes(passphrase)
		return GatewayRestorePlan{}, fmt.Errorf("gateway restore planner is incomplete")
	}
	restorer.mu.Lock()
	defer restorer.mu.Unlock()
	if err := validateGatewayRestoreInput(input); err != nil {
		wipeBackupBytes(passphrase)
		return GatewayRestorePlan{}, err
	}
	hostState, err := restorer.runtime.Host.Inspect(ctx)
	if err != nil {
		wipeBackupBytes(passphrase)
		return GatewayRestorePlan{}, fmt.Errorf("inspect gateway restore host: %w", err)
	}
	if err := hostState.Validate(); err != nil {
		wipeBackupBytes(passphrase)
		return GatewayRestorePlan{}, fmt.Errorf("validate gateway restore host: %w", err)
	}
	if hostState.Initialized {
		if hostState.Role != model.RoleGateway {
			wipeBackupBytes(passphrase)
			return GatewayRestorePlan{}, fmt.Errorf("%w: initialized role is %s", ErrGatewayRestoreConflict, hostState.Role)
		}
		if !input.Replace {
			wipeBackupBytes(passphrase)
			return GatewayRestorePlan{}, ErrGatewayRestoreReplaceNeeded
		}
	} else if input.Replace {
		wipeBackupBytes(passphrase)
		return GatewayRestorePlan{}, fmt.Errorf("%w: --replace requires an initialized gateway", ErrGatewayRestoreConflict)
	}
	payload, err := restorer.runtime.Archives.Load(ctx, input.ArchivePath, passphrase)
	if err != nil {
		return GatewayRestorePlan{}, fmt.Errorf("load gateway restore archive: %w", err)
	}
	closePayload := true
	defer func() {
		if closePayload {
			_ = payload.Close()
		}
	}()
	restored := payload.State()
	if restored.Host.PublicIPv4 != input.PublicIPv4 {
		return GatewayRestorePlan{}, fmt.Errorf("%w: archive uses %s and requested endpoint is %s", ErrGatewayRestoreEndpointMove, restored.Host.PublicIPv4, input.PublicIPv4)
	}
	release, err := restorer.runtime.Release.Inspect(ctx)
	if err != nil {
		return GatewayRestorePlan{}, fmt.Errorf("inspect installed restore release: %w", err)
	}
	if err := release.Validate(); err != nil {
		return GatewayRestorePlan{}, fmt.Errorf("%w: installed release manifest: %v", ErrGatewayRestoreIncompatible, err)
	}
	candidate, err := prepareGatewayRestoreReleaseState(restored, release.ComponentManifest)
	if err != nil {
		return GatewayRestorePlan{}, err
	}
	preflight, err := restorer.runtime.Host.Preflight(ctx, payload, candidate, hostState)
	if err != nil {
		return GatewayRestorePlan{}, fmt.Errorf("preflight gateway restore host: %w", err)
	}
	if err := validateGatewayRestorePreflight(candidate, restored, input.PublicIPv4, preflight); err != nil {
		return GatewayRestorePlan{}, err
	}
	plan := GatewayRestorePlan{
		ArchivePath: input.ArchivePath, PublicIPv4: input.PublicIPv4, OriginalPublicIPv4: restored.Host.PublicIPv4,
		Replace: input.Replace, ReplacingInitialized: hostState.Initialized, SameEndpoint: true, TrustPreserved: true,
		GatewayID: restored.Host.ID, SourceGeneration: restored.Generation, TargetGeneration: preflight.Candidate.Generation,
		NodeCount: len(restored.Nodes), ClientCount: len(restored.Clients), PortRemaps: append([]tunnel.PortRemap{}, preflight.PortRemaps...),
		AffectedServices: append([]string{}, preflight.AffectedServices...), ExpectedInterruptions: append([]string{}, preflight.ExpectedInterruptions...),
		EmergencySnapshotNeeded: hostState.Initialized, hostState: hostState, preflight: preflight, payload: payload,
	}
	if err := plan.Validate(); err != nil {
		return GatewayRestorePlan{}, err
	}
	closePayload = false
	return plan, nil
}

func (plan GatewayRestorePlan) Validate() error {
	if err := validateGatewayRestoreInput(GatewayRestoreInput{ArchivePath: plan.ArchivePath, PublicIPv4: plan.PublicIPv4, Replace: plan.Replace}); err != nil {
		return err
	}
	if !plan.SameEndpoint || !plan.TrustPreserved || plan.OriginalPublicIPv4 != plan.PublicIPv4 || model.ValidateResourceID(plan.GatewayID) != nil ||
		plan.SourceGeneration == 0 || plan.TargetGeneration < plan.SourceGeneration || plan.NodeCount < 0 || plan.ClientCount < 0 ||
		plan.ReplacingInitialized != plan.Replace || plan.EmergencySnapshotNeeded != plan.Replace {
		return fmt.Errorf("gateway restore plan identity is invalid")
	}
	if plan.payload == nil || plan.preflight.Candidate.Generation != plan.TargetGeneration || plan.preflight.Candidate.Host.ID != plan.GatewayID ||
		plan.preflight.Candidate.Host.PublicIPv4 != plan.PublicIPv4 || !reflect.DeepEqual(plan.PortRemaps, plan.preflight.PortRemaps) ||
		!reflect.DeepEqual(plan.AffectedServices, plan.preflight.AffectedServices) || !reflect.DeepEqual(plan.ExpectedInterruptions, plan.preflight.ExpectedInterruptions) {
		return fmt.Errorf("gateway restore plan does not match retained preflight")
	}
	if err := plan.hostState.Validate(); err != nil {
		return err
	}
	return nil
}

func (restorer *GatewayRestorer) Apply(ctx context.Context, plan GatewayRestorePlan) (result GatewayRestoreResult, returnErr error) {
	if ctx == nil || restorer == nil {
		return GatewayRestoreResult{}, fmt.Errorf("gateway restore apply is incomplete")
	}
	if err := plan.Validate(); err != nil {
		return GatewayRestoreResult{}, err
	}
	restorer.mu.Lock()
	defer restorer.mu.Unlock()
	defer plan.payload.Close()
	current, err := restorer.runtime.Host.Inspect(ctx)
	if err != nil || !reflect.DeepEqual(current, plan.hostState) {
		return GatewayRestoreResult{}, fmt.Errorf("%w: host changed after restore planning", ErrGatewayRestoreConflict)
	}
	var snapshot GatewayRestoreEmergencySnapshot
	if plan.EmergencySnapshotNeeded {
		snapshot, err = restorer.runtime.Host.EmergencySnapshot(ctx, current)
		if err != nil {
			return GatewayRestoreResult{}, fmt.Errorf("create gateway restore emergency snapshot: %w", err)
		}
		if err := snapshot.Validate(); err != nil {
			return GatewayRestoreResult{}, err
		}
	}
	installed, err := restorer.runtime.Release.Install(ctx, model.RoleGateway)
	if err != nil {
		return GatewayRestoreResult{}, fmt.Errorf("install gateway restore release: %w", err)
	}
	if err := installed.Manifest.Validate(); err != nil {
		return GatewayRestoreResult{}, fmt.Errorf("%w: installed release manifest is invalid", ErrGatewayRestoreIncompatible)
	}
	if !reflect.DeepEqual(installed.Manifest.ComponentManifest, plan.preflight.Candidate.Components) {
		return GatewayRestoreResult{}, fmt.Errorf("%w: installed release differs from the prevalidated restore plan", ErrGatewayRestoreIncompatible)
	}
	activation, err := restorer.runtime.Host.Activate(ctx, plan.payload, plan.preflight, snapshot)
	if err != nil {
		if activation.Started {
			err = errors.Join(err, restorer.runtime.Host.Rollback(context.Background(), activation, snapshot))
		}
		return GatewayRestoreResult{}, fmt.Errorf("activate gateway restore: %w", err)
	}
	if !activation.Started || model.ValidateResourceID(activation.ID) != nil {
		return GatewayRestoreResult{}, fmt.Errorf("activate gateway restore returned an invalid transaction")
	}
	rollback := func(cause error) (GatewayRestoreResult, error) {
		return GatewayRestoreResult{}, errors.Join(cause, restorer.runtime.Host.Rollback(context.Background(), activation, snapshot))
	}
	if err := restorer.runtime.Host.Health(ctx, activation, plan.preflight.Candidate); err != nil {
		return rollback(fmt.Errorf("restored gateway health check: %w", err))
	}
	if err := restorer.runtime.Host.Commit(ctx, activation); err != nil {
		return rollback(fmt.Errorf("commit gateway restore: %w", err))
	}
	result = GatewayRestoreResult{
		Changed: true, GatewayID: plan.GatewayID, PublicIPv4: plan.PublicIPv4, Generation: plan.TargetGeneration,
		SameEndpoint: true, TrustPreserved: true, NodeCount: plan.NodeCount, ClientCount: plan.ClientCount,
		AffectedServices: append([]string{}, plan.AffectedServices...), ExpectedInterruptions: append([]string{}, plan.ExpectedInterruptions...),
	}
	if plan.EmergencySnapshotNeeded {
		copy := snapshot
		result.EmergencySnapshot = &copy
	}
	return result, nil
}

func (restorer *GatewayRestorer) Discard(plan GatewayRestorePlan) error {
	if plan.payload == nil {
		return nil
	}
	return plan.payload.Close()
}

func prepareGatewayRestoreReleaseState(restored model.State, installed model.ComponentManifest) (model.State, error) {
	if err := installed.Validate(); err != nil {
		return model.State{}, fmt.Errorf("%w: installed component manifest is invalid", ErrGatewayRestoreIncompatible)
	}
	if restored.SchemaVersion < installed.StateSchemaMinimum || restored.SchemaVersion > installed.StateSchemaMaximum {
		return model.State{}, fmt.Errorf("%w: state schema %d is outside installed range", ErrGatewayRestoreIncompatible, restored.SchemaVersion)
	}
	for _, node := range restored.Nodes {
		if node.Lifecycle == model.LifecycleActive && node.ControlProtocol != "" && !restoreStringContains(installed.ControlProtocols, node.ControlProtocol) {
			return model.State{}, fmt.Errorf("%w: active node %s uses unsupported control protocol %s", ErrGatewayRestoreIncompatible, node.ID, node.ControlProtocol)
		}
	}
	candidate := restored
	if !reflect.DeepEqual(candidate.Components, installed) {
		next, err := model.NextGeneration(candidate.Generation)
		if err != nil {
			return model.State{}, err
		}
		candidate.Generation = next
		candidate.Components = installed
	}
	if err := candidate.Validate(); err != nil {
		return model.State{}, fmt.Errorf("%w: migrated restore state: %v", ErrGatewayRestoreIncompatible, err)
	}
	return candidate, nil
}

func validateGatewayRestorePreflight(base, restored model.State, publicIPv4 string, preflight GatewayRestorePreflight) error {
	if err := preflight.Candidate.Validate(); err != nil || preflight.Candidate.Host.Role != model.RoleGateway {
		return fmt.Errorf("invalid gateway restore preflight candidate")
	}
	if preflight.Candidate.Host.ID != restored.Host.ID || preflight.Candidate.Host.PublicIPv4 != publicIPv4 ||
		!reflect.DeepEqual(preflight.Candidate.EnrollmentIdentity, restored.EnrollmentIdentity) ||
		!reflect.DeepEqual(preflight.Candidate.Nodes, restored.Nodes) || !reflect.DeepEqual(preflight.Candidate.Clients, restored.Clients) ||
		!reflect.DeepEqual(preflight.Candidate.Certificates, restored.Certificates) || !reflect.DeepEqual(preflight.Candidate.Transports, restored.Transports) {
		return fmt.Errorf("gateway restore preflight changed trust or identity material")
	}
	if preflight.Network.PublicIPv4 != publicIPv4 || preflight.Network.ClientCIDR != preflight.Candidate.Host.ClientCIDR ||
		preflight.Network.NodeCIDR != preflight.Candidate.Host.NodeCIDR || preflight.Network.ExternalInterface != preflight.Candidate.Host.ExternalInterface ||
		preflight.SSH.Port != preflight.Candidate.Host.SSHPort {
		return fmt.Errorf("gateway restore preflight network differs from candidate state")
	}
	remapped := base
	remapped.Host = preflight.Candidate.Host
	remapped.Exposes = append([]model.Expose{}, base.Exposes...)
	for _, remap := range preflight.PortRemaps {
		found := false
		for index := range remapped.Exposes {
			if remapped.Exposes[index].ID == remap.ExposeID {
				if remapped.Exposes[index].TunnelPort != remap.PreviousPort {
					return fmt.Errorf("gateway restore preflight port remap has a stale source")
				}
				remapped.Exposes[index].TunnelPort = remap.Port
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("gateway restore preflight remaps an unknown expose")
		}
	}
	changed := !reflect.DeepEqual(restoreStateWithoutGeneration(remapped), restoreStateWithoutGeneration(base))
	wantGeneration := base.Generation
	if changed {
		var err error
		wantGeneration, err = model.NextGeneration(base.Generation)
		if err != nil {
			return err
		}
	}
	remapped.Generation = wantGeneration
	if !reflect.DeepEqual(remapped, preflight.Candidate) {
		return fmt.Errorf("gateway restore preflight candidate contains changes outside the permitted network/remap scope")
	}
	if preflight.PortRemaps == nil || preflight.AffectedServices == nil || preflight.ExpectedInterruptions == nil ||
		!sort.StringsAreSorted(preflight.AffectedServices) || !restoreSortedUnique(preflight.AffectedServices) {
		return fmt.Errorf("gateway restore preflight impact is invalid")
	}
	return nil
}

func restoreStateWithoutGeneration(state model.State) model.State {
	state.Generation = 0
	return state
}

func validateGatewayRestoreInput(input GatewayRestoreInput) error {
	if !filepath.IsAbs(input.ArchivePath) || filepath.Clean(input.ArchivePath) != input.ArchivePath || strings.ContainsAny(input.ArchivePath, "\x00\r\n") {
		return fmt.Errorf("gateway restore archive path must be clean and absolute")
	}
	address, err := netip.ParseAddr(input.PublicIPv4)
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	benchmark := netip.MustParsePrefix("198.18.0.0/15")
	if err != nil || !address.Is4() || address.String() != input.PublicIPv4 || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || cgnat.Contains(address) || benchmark.Contains(address) {
		return fmt.Errorf("gateway restore public IP must be an explicit canonical public IPv4 address")
	}
	return nil
}

func validateOptionalRestoreHash(value string) error {
	if value != "" && !validReleaseSHA256(value) {
		return fmt.Errorf("gateway restore ownership hash is invalid")
	}
	return nil
}

func restoreStringContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func restoreSortedUnique(values []string) bool {
	for index, value := range values {
		if value == "" || strings.ContainsAny(value, "\x00\r\n") || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}
