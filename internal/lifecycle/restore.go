package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

var (
	ErrGatewayRestoreConflict      = errors.New("gateway restore conflict")
	ErrGatewayRestoreReplaceNeeded = errors.New("initialized gateway restore requires --replace")
	ErrGatewayRestoreIncompatible  = errors.New("gateway restore is incompatible with the installed release")
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
	Archives                    *GatewayRestoreArchiveLoader
	Release                     GatewayRestoreReleaseSource
	Host                        GatewayRestoreHost
	Entropy                     io.Reader
	Now                         func() time.Time
	PublicCertificateExportPath string
}

type GatewayRestoreAffectedNode struct {
	ID   string
	Name string
}

type GatewayRestoreAffectedClientExport struct {
	ClientID   string
	ClientName string
	Format     string
}

type GatewayRestoreAffectedExpose struct {
	ID     string
	NodeID string
	Name   string
	State  model.ExposeState
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
	PublicCertificate       *model.Certificate
	PublicCertificateExport string
	AffectedNodes           []GatewayRestoreAffectedNode
	StaleClientExports      []GatewayRestoreAffectedClientExport
	AffectedExposes         []GatewayRestoreAffectedExpose

	hostState              GatewayRestoreHostState
	preflight              GatewayRestorePreflight
	payload                *GatewayRestorePayload
	wantAffectedNodes      []GatewayRestoreAffectedNode
	wantStaleClientExports []GatewayRestoreAffectedClientExport
	wantAffectedExposes    []GatewayRestoreAffectedExpose
}

func (GatewayRestorePlan) String() string   { return "<redacted-gateway-restore-plan>" }
func (GatewayRestorePlan) GoString() string { return "<redacted-gateway-restore-plan>" }

type GatewayRestoreResult struct {
	Changed                 bool
	GatewayID               string
	PublicIPv4              string
	Generation              uint64
	SameEndpoint            bool
	TrustPreserved          bool
	NodeCount               int
	ClientCount             int
	EmergencySnapshot       *GatewayRestoreEmergencySnapshot
	AffectedServices        []string
	ExpectedInterruptions   []string
	PublicCertificate       *model.Certificate
	PublicCertificateExport string
	AffectedNodes           []GatewayRestoreAffectedNode
	StaleClientExports      []GatewayRestoreAffectedClientExport
	AffectedExposes         []GatewayRestoreAffectedExpose
}

type GatewayRestorer struct {
	runtime GatewayRestoreRuntime
	mu      sync.Mutex
}

func NewGatewayRestorer(runtime GatewayRestoreRuntime) (*GatewayRestorer, error) {
	if runtime.Archives == nil || runtime.Release == nil || runtime.Host == nil {
		return nil, fmt.Errorf("gateway restore dependencies are incomplete")
	}
	if runtime.Entropy == nil {
		runtime.Entropy = rand.Reader
	}
	if runtime.Now == nil {
		runtime.Now = time.Now
	}
	if runtime.PublicCertificateExportPath == "" {
		runtime.PublicCertificateExportPath = "/var/lib/vpnctl/exports/gateway.crt"
	}
	if !filepath.IsAbs(runtime.PublicCertificateExportPath) || filepath.Clean(runtime.PublicCertificateExportPath) != runtime.PublicCertificateExportPath ||
		strings.ContainsAny(runtime.PublicCertificateExportPath, "\x00\r\n") {
		return nil, fmt.Errorf("gateway restore public certificate export path is invalid")
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
	sameEndpoint := restored.Host.PublicIPv4 == input.PublicIPv4
	var publicCertificate *model.Certificate
	var affectedNodes []GatewayRestoreAffectedNode
	var staleClientExports []GatewayRestoreAffectedClientExport
	var affectedExposes []GatewayRestoreAffectedExpose
	if !sameEndpoint {
		affectedNodes, staleClientExports, affectedExposes = gatewayRestoreEndpointImpact(restored, payload)
		candidate, publicCertificate, err = restorer.prepareEndpointMove(payload, candidate, input.PublicIPv4)
		if err != nil {
			return GatewayRestorePlan{}, err
		}
	}
	preflight, err := restorer.runtime.Host.Preflight(ctx, payload, candidate, hostState)
	if err != nil {
		return GatewayRestorePlan{}, fmt.Errorf("preflight gateway restore host: %w", err)
	}
	if !sameEndpoint {
		preflight.ExpectedInterruptions = append(preflight.ExpectedInterruptions,
			"private nodes, client profiles, and external webhook registrations remain unavailable until the listed endpoint actions are completed")
	}
	if err := validateGatewayRestorePreflight(candidate, input.PublicIPv4, preflight); err != nil {
		return GatewayRestorePlan{}, err
	}
	plan := GatewayRestorePlan{
		ArchivePath: input.ArchivePath, PublicIPv4: input.PublicIPv4, OriginalPublicIPv4: restored.Host.PublicIPv4,
		Replace: input.Replace, ReplacingInitialized: hostState.Initialized, SameEndpoint: sameEndpoint, TrustPreserved: true,
		GatewayID: restored.Host.ID, SourceGeneration: restored.Generation, TargetGeneration: preflight.Candidate.Generation,
		NodeCount: len(restored.Nodes), ClientCount: len(restored.Clients), PortRemaps: append([]tunnel.PortRemap{}, preflight.PortRemaps...),
		AffectedServices: append([]string{}, preflight.AffectedServices...), ExpectedInterruptions: append([]string{}, preflight.ExpectedInterruptions...),
		PublicCertificate: cloneGatewayRestoreCertificate(publicCertificate), PublicCertificateExport: restoreOptionalString(!sameEndpoint, restorer.runtime.PublicCertificateExportPath),
		AffectedNodes: append([]GatewayRestoreAffectedNode{}, affectedNodes...), StaleClientExports: append([]GatewayRestoreAffectedClientExport{}, staleClientExports...),
		AffectedExposes:         append([]GatewayRestoreAffectedExpose{}, affectedExposes...),
		EmergencySnapshotNeeded: hostState.Initialized, hostState: hostState, preflight: preflight, payload: payload,
		wantAffectedNodes: append([]GatewayRestoreAffectedNode{}, affectedNodes...), wantStaleClientExports: append([]GatewayRestoreAffectedClientExport{}, staleClientExports...),
		wantAffectedExposes: append([]GatewayRestoreAffectedExpose{}, affectedExposes...),
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
	if plan.SameEndpoint != (plan.OriginalPublicIPv4 == plan.PublicIPv4) || !plan.TrustPreserved || model.ValidateResourceID(plan.GatewayID) != nil ||
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
	if err := validateGatewayRestoreEndpointImpact(plan.SameEndpoint, plan.GatewayID, plan.PublicIPv4, plan.PublicCertificateExport,
		plan.PublicCertificate, plan.AffectedNodes, plan.StaleClientExports, plan.AffectedExposes); err != nil {
		return err
	}
	if !reflect.DeepEqual(plan.AffectedNodes, plan.wantAffectedNodes) || !reflect.DeepEqual(plan.StaleClientExports, plan.wantStaleClientExports) ||
		!reflect.DeepEqual(plan.AffectedExposes, plan.wantAffectedExposes) {
		return fmt.Errorf("gateway restore endpoint impact differs from retained plan")
	}
	if !plan.SameEndpoint {
		candidateCertificate, found := gatewayRestorePublicCertificate(plan.preflight.Candidate)
		if !found || !reflect.DeepEqual(candidateCertificate, *plan.PublicCertificate) {
			return fmt.Errorf("gateway restore public certificate differs from retained preflight")
		}
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
		SameEndpoint: plan.SameEndpoint, TrustPreserved: plan.TrustPreserved, NodeCount: plan.NodeCount, ClientCount: plan.ClientCount,
		AffectedServices: append([]string{}, plan.AffectedServices...), ExpectedInterruptions: append([]string{}, plan.ExpectedInterruptions...),
		PublicCertificate: cloneGatewayRestoreCertificate(plan.PublicCertificate), PublicCertificateExport: plan.PublicCertificateExport,
		AffectedNodes: append([]GatewayRestoreAffectedNode{}, plan.AffectedNodes...), StaleClientExports: append([]GatewayRestoreAffectedClientExport{}, plan.StaleClientExports...),
		AffectedExposes: append([]GatewayRestoreAffectedExpose{}, plan.AffectedExposes...),
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

func (restorer *GatewayRestorer) prepareEndpointMove(
	payload *GatewayRestorePayload,
	base model.State,
	publicIPv4 string,
) (model.State, *model.Certificate, error) {
	encoded, err := model.EncodeState(base)
	if err != nil {
		return model.State{}, nil, err
	}
	candidate, err := model.DecodeState(encoded)
	if err != nil {
		return model.State{}, nil, err
	}
	certificateIndex := -1
	for index, certificate := range candidate.Certificates {
		if certificate.Kind != model.CertificatePublicIngress {
			continue
		}
		if certificateIndex >= 0 {
			return model.State{}, nil, fmt.Errorf("gateway restore has multiple public ingress certificates")
		}
		certificateIndex = index
	}
	if certificateIndex < 0 {
		return model.State{}, nil, ingress.ErrPublicCertificateNotFound
	}
	current := candidate.Certificates[certificateIndex]
	nextCertificateGeneration, err := model.NextGeneration(current.Generation)
	if err != nil {
		return model.State{}, nil, err
	}
	nextStateGeneration, err := model.NextGeneration(candidate.Generation)
	if err != nil {
		return model.State{}, nil, err
	}
	material, err := ingress.GeneratePublicCertificate(restorer.runtime.Entropy, publicIPv4, restorer.runtime.Now().UTC().Truncate(time.Second))
	if err != nil {
		return model.State{}, nil, fmt.Errorf("issue public ingress certificate for restored endpoint: %w", err)
	}
	defer wipeBackupBytes(material.PrivateKeyPEM)
	certificateRef, privateKeyRef, err := ingress.PublicCertificateReferences(nextCertificateGeneration)
	if err != nil {
		return model.State{}, nil, err
	}
	fingerprint := sha256.Sum256(material.Certificate.Raw)
	renewed := current
	renewed.Fingerprint = "sha256:" + hex.EncodeToString(fingerprint[:])
	renewed.SerialHex = material.Certificate.SerialNumber.Text(16)
	renewed.Subject = material.Certificate.Subject.String()
	renewed.SANs = []string{"IP:" + publicIPv4}
	renewed.NotBefore = material.Certificate.NotBefore.UTC()
	renewed.NotAfter = material.Certificate.NotAfter.UTC()
	renewed.WarningDays = ingress.PublicCertificateWarningDays
	renewed.Generation = nextCertificateGeneration
	renewed.CertificateRef = certificateRef
	renewed.PrivateKeyRef = privateKeyRef
	if err := renewed.Validate(); err != nil {
		return model.State{}, nil, fmt.Errorf("build restored public ingress certificate metadata: %w", err)
	}
	if _, err := ingress.ValidatePublicCertificatePEM(material.CertificatePEM, renewed, publicIPv4); err != nil {
		return model.State{}, nil, err
	}
	candidate.Host.PublicIPv4 = publicIPv4
	candidate.Certificates[certificateIndex] = renewed
	candidate.Generation = nextStateGeneration
	if err := candidate.Validate(); err != nil {
		return model.State{}, nil, fmt.Errorf("validate restored endpoint migration: %w", err)
	}
	if err := payload.rewriteEndpoint(candidate, current, renewed, material.CertificatePEM, material.PrivateKeyPEM); err != nil {
		return model.State{}, nil, err
	}
	return candidate, cloneGatewayRestoreCertificate(&renewed), nil
}

func gatewayRestoreEndpointImpact(
	state model.State,
	payload *GatewayRestorePayload,
) ([]GatewayRestoreAffectedNode, []GatewayRestoreAffectedClientExport, []GatewayRestoreAffectedExpose) {
	nodes := make([]GatewayRestoreAffectedNode, 0)
	for _, node := range state.Nodes {
		if node.Lifecycle == model.LifecycleActive {
			nodes = append(nodes, GatewayRestoreAffectedNode{ID: node.ID, Name: node.Name})
		}
	}
	sort.Slice(nodes, func(left, right int) bool {
		leftName, rightName := strings.ToLower(nodes[left].Name), strings.ToLower(nodes[right].Name)
		return leftName < rightName || (leftName == rightName && nodes[left].ID < nodes[right].ID)
	})

	files := make(map[string]struct{})
	for _, file := range payload.Files() {
		files[file.Path] = struct{}{}
	}
	clientExports := make([]GatewayRestoreAffectedClientExport, 0)
	for _, client := range state.Clients {
		if client.Lifecycle != model.LifecycleActive {
			continue
		}
		for _, item := range []struct {
			format    string
			extension string
		}{{"clash", ".clash.yaml"}, {"wireguard", ".wireguard.conf"}} {
			profile := path.Join("exports/clients", client.Name+item.extension)
			metadata := path.Join("exports/clients/.metadata", client.ID+"."+item.format+".json")
			_, hasProfile := files[profile]
			_, hasMetadata := files[metadata]
			if hasProfile || hasMetadata {
				clientExports = append(clientExports, GatewayRestoreAffectedClientExport{
					ClientID: client.ID, ClientName: client.Name, Format: item.format,
				})
			}
		}
	}
	sort.Slice(clientExports, func(left, right int) bool {
		leftName, rightName := strings.ToLower(clientExports[left].ClientName), strings.ToLower(clientExports[right].ClientName)
		if leftName != rightName {
			return leftName < rightName
		}
		if clientExports[left].ClientID != clientExports[right].ClientID {
			return clientExports[left].ClientID < clientExports[right].ClientID
		}
		return clientExports[left].Format < clientExports[right].Format
	})

	exposes := make([]GatewayRestoreAffectedExpose, 0)
	for _, expose := range state.Exposes {
		if expose.State != model.ExposeReady && expose.State != model.ExposeDegraded {
			continue
		}
		exposes = append(exposes, GatewayRestoreAffectedExpose{
			ID: expose.ID, NodeID: expose.NodeID, Name: expose.Name, State: expose.State,
		})
	}
	sort.Slice(exposes, func(left, right int) bool {
		leftName, rightName := strings.ToLower(exposes[left].Name), strings.ToLower(exposes[right].Name)
		return leftName < rightName || (leftName == rightName && exposes[left].ID < exposes[right].ID)
	})
	return nodes, clientExports, exposes
}

func validateGatewayRestoreEndpointImpact(
	sameEndpoint bool,
	gatewayID, publicIPv4, exportPath string,
	certificate *model.Certificate,
	nodes []GatewayRestoreAffectedNode,
	clientExports []GatewayRestoreAffectedClientExport,
	exposes []GatewayRestoreAffectedExpose,
) error {
	if sameEndpoint {
		if certificate != nil || exportPath != "" || len(nodes) != 0 || len(clientExports) != 0 || len(exposes) != 0 {
			return fmt.Errorf("same-endpoint gateway restore contains stale endpoint actions")
		}
		return nil
	}
	if certificate == nil || certificate.Validate() != nil || certificate.Kind != model.CertificatePublicIngress || certificate.OwnerKind != "host" ||
		certificate.OwnerID != gatewayID || !reflect.DeepEqual(certificate.SANs, []string{"IP:" + publicIPv4}) || certificate.Generation < 2 ||
		!filepath.IsAbs(exportPath) || filepath.Clean(exportPath) != exportPath || strings.ContainsAny(exportPath, "\x00\r\n") {
		return fmt.Errorf("changed-endpoint gateway restore certificate is invalid")
	}
	previousNode := ""
	activeNodeIDs := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		key := strings.ToLower(node.Name) + "\x00" + node.ID
		if model.ValidateResourceID(node.ID) != nil || node.Name == "" || key <= previousNode {
			return fmt.Errorf("changed-endpoint gateway restore node impact is invalid")
		}
		previousNode = key
		activeNodeIDs[node.ID] = struct{}{}
	}
	previousClient := ""
	for _, client := range clientExports {
		key := strings.ToLower(client.ClientName) + "\x00" + client.ClientID + "\x00" + client.Format
		if model.ValidateResourceID(client.ClientID) != nil || client.ClientName == "" || (client.Format != "clash" && client.Format != "wireguard") || key <= previousClient {
			return fmt.Errorf("changed-endpoint gateway restore client impact is invalid")
		}
		previousClient = key
	}
	previousExpose := ""
	for _, expose := range exposes {
		key := strings.ToLower(expose.Name) + "\x00" + expose.ID
		_, activeNode := activeNodeIDs[expose.NodeID]
		if model.ValidateResourceID(expose.ID) != nil || model.ValidateResourceID(expose.NodeID) != nil || !activeNode ||
			(expose.State != model.ExposeReady && expose.State != model.ExposeDegraded) || key <= previousExpose {
			return fmt.Errorf("changed-endpoint gateway restore expose impact is invalid")
		}
		previousExpose = key
	}
	return nil
}

func cloneGatewayRestoreCertificate(certificate *model.Certificate) *model.Certificate {
	if certificate == nil {
		return nil
	}
	copy := *certificate
	copy.SANs = append([]string{}, certificate.SANs...)
	return &copy
}

func gatewayRestorePublicCertificate(state model.State) (model.Certificate, bool) {
	var result model.Certificate
	found := false
	for _, certificate := range state.Certificates {
		if certificate.Kind != model.CertificatePublicIngress {
			continue
		}
		if found {
			return model.Certificate{}, false
		}
		result = certificate
		found = true
	}
	return result, found
}

func restoreOptionalString(include bool, value string) string {
	if include {
		return value
	}
	return ""
}

func validateGatewayRestorePreflight(base model.State, publicIPv4 string, preflight GatewayRestorePreflight) error {
	if err := preflight.Candidate.Validate(); err != nil || preflight.Candidate.Host.Role != model.RoleGateway {
		return fmt.Errorf("invalid gateway restore preflight candidate")
	}
	if preflight.Candidate.Host.ID != base.Host.ID || preflight.Candidate.Host.PublicIPv4 != publicIPv4 ||
		!reflect.DeepEqual(preflight.Candidate.EnrollmentIdentity, base.EnrollmentIdentity) ||
		!reflect.DeepEqual(preflight.Candidate.Nodes, base.Nodes) || !reflect.DeepEqual(preflight.Candidate.Clients, base.Clients) ||
		!reflect.DeepEqual(preflight.Candidate.Certificates, base.Certificates) || !reflect.DeepEqual(preflight.Candidate.Transports, base.Transports) {
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
