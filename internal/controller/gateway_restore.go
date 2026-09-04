package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	maximumRestoreTreeFiles = 65536
	maximumRestoreTreeBytes = int64(768 << 20)
)

type gatewayRestoreNetwork interface {
	Snapshot(context.Context, linuxplatform.OwnedNetworkScope) (linuxplatform.NetworkSnapshot, error)
	ActivateGateway(context.Context, linuxplatform.GatewayFirewallArtifact) error
	Restore(context.Context, linuxplatform.NetworkSnapshot) error
}

type gatewayRestoreRoleInstaller interface {
	Plan(linuxplatform.RoleInstallationRequest) (linuxplatform.RoleInstallationPlan, error)
	Apply(context.Context, linuxplatform.RoleInstallationRequest) (linuxplatform.RoleInstallationResult, error)
}

type gatewayRestoreWatchdogInstaller interface {
	Plan(string) (linuxplatform.WatchdogUnitInstallationPlan, error)
	Apply(context.Context, linuxplatform.WatchdogUnitInstallationPlan) ([]string, error)
}

type gatewayRestoreRendered struct {
	roleRequest   linuxplatform.RoleInstallationRequest
	watchdogUnits linuxplatform.WatchdogUnitInstallationPlan
	files         map[string]restoreRenderedFile
	nginx         ingress.NginxCandidate
}

type restoreRenderedFile struct {
	content []byte
	mode    fs.FileMode
}

type restoreUnitSnapshot struct {
	path    string
	present bool
	content []byte
	mode    fs.FileMode
}

type systemGatewayRestoreTransaction struct {
	id                  string
	oldConfig           string
	oldState            string
	configWasPresent    bool
	stateWasPresent     bool
	runtimeWasPresent   bool
	configMoved         bool
	configActivated     bool
	stateMoved          bool
	stateActivated      bool
	units               []restoreUnitSnapshot
	network             linuxplatform.NetworkSnapshot
	previousInitialized bool
	started             bool
}

type systemGatewayRestoreHost struct {
	paths         store.Paths
	snapshot      linuxplatform.HostSnapshot
	sshConnection string
	binaryPath    string
	runner        linuxplatform.ProbeRunner
	network       gatewayRestoreNetwork
	roles         gatewayRestoreRoleInstaller
	watchdogUnits gatewayRestoreWatchdogInstaller
	now           func() time.Time
	newUUID       model.UUIDGenerator
	wgRunner      wireguard.Runner

	mu           sync.Mutex
	transactions map[string]*systemGatewayRestoreTransaction
}

// NewSystemGatewayRestorer composes the authenticated archive loader and the
// dedicated-host Linux transaction. Discovery is supplied by the CLI so plan
// and apply use one frozen, read-only host view.
func NewSystemGatewayRestorer(
	paths store.Paths,
	snapshot linuxplatform.HostSnapshot,
	release lifecycle.GatewayRestoreReleaseSource,
	binaryPath string,
	sshConnection string,
) (*lifecycle.GatewayRestorer, error) {
	if release == nil {
		return nil, fmt.Errorf("create gateway restorer: installed release is required")
	}
	runner := linuxplatform.OSProbeRunner{}
	network := linuxplatform.NewOSNetworkManager()
	roles, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, runner)
	if err != nil {
		return nil, err
	}
	watchdogUnits, err := linuxplatform.NewWatchdogUnitInstaller(paths.Root, runner)
	if err != nil {
		return nil, err
	}
	host, err := newSystemGatewayRestoreHost(paths, snapshot, sshConnection, binaryPath, runner, network, roles, watchdogUnits, wireguard.ExecRunner{})
	if err != nil {
		return nil, err
	}
	scratch := filepath.Join(paths.Root, "tmp")
	archives, err := lifecycle.NewGatewayRestoreArchiveLoader(scratch)
	if err != nil {
		return nil, err
	}
	return lifecycle.NewGatewayRestorer(lifecycle.GatewayRestoreRuntime{Archives: archives, Release: release, Host: host})
}

func newSystemGatewayRestoreHost(
	paths store.Paths,
	snapshot linuxplatform.HostSnapshot,
	sshConnection, binaryPath string,
	runner linuxplatform.ProbeRunner,
	network gatewayRestoreNetwork,
	roles gatewayRestoreRoleInstaller,
	watchdogUnits gatewayRestoreWatchdogInstaller,
	wgRunner wireguard.Runner,
) (*systemGatewayRestoreHost, error) {
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths || snapshot.SchemaVersion != linuxplatform.HostSnapshotSchemaVersion ||
		runner == nil || network == nil || roles == nil || watchdogUnits == nil || wgRunner == nil {
		return nil, fmt.Errorf("gateway restore system dependencies are incomplete")
	}
	if binaryPath == "" {
		binaryPath = linuxplatform.DefaultVPNCTLBinaryPath
	}
	if !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath {
		return nil, fmt.Errorf("gateway restore binary path must be clean and absolute")
	}
	return &systemGatewayRestoreHost{
		paths: paths, snapshot: snapshot, sshConnection: sshConnection, binaryPath: binaryPath,
		runner: runner, network: network, roles: roles, watchdogUnits: watchdogUnits,
		now: time.Now, newUUID: model.NewUUID, wgRunner: wgRunner,
		transactions: make(map[string]*systemGatewayRestoreTransaction),
	}, nil
}

func (host *systemGatewayRestoreHost) Inspect(ctx context.Context) (lifecycle.GatewayRestoreHostState, error) {
	if ctx == nil || host == nil {
		return lifecycle.GatewayRestoreHostState{}, fmt.Errorf("gateway restore host inspection is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return lifecycle.GatewayRestoreHostState{}, err
	}
	stateStore, err := store.NewStateStore(host.paths)
	if err != nil {
		return lifecycle.GatewayRestoreHostState{}, err
	}
	state, err := stateStore.Load()
	if errors.Is(err, store.ErrStateNotFound) {
		for _, root := range []string{host.paths.ConfigDir, host.paths.StateDir, host.paths.RuntimeDir} {
			if _, statErr := os.Lstat(root); statErr == nil {
				return lifecycle.GatewayRestoreHostState{}, fmt.Errorf("%w: clean restore host contains %s", lifecycle.ErrGatewayRestoreConflict, root)
			} else if !errors.Is(statErr, fs.ErrNotExist) {
				return lifecycle.GatewayRestoreHostState{}, statErr
			}
		}
		return lifecycle.GatewayRestoreHostState{}, nil
	}
	if err != nil {
		return lifecycle.GatewayRestoreHostState{}, err
	}
	if err := state.Validate(); err != nil {
		return lifecycle.GatewayRestoreHostState{}, fmt.Errorf("%w: authoritative state is invalid", lifecycle.ErrGatewayRestoreConflict)
	}
	if info, statErr := os.Lstat(host.paths.RuntimeDir); statErr == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
		return lifecycle.GatewayRestoreHostState{}, fmt.Errorf("%w: runtime root is unsafe", lifecycle.ErrGatewayRestoreConflict)
	} else if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return lifecycle.GatewayRestoreHostState{}, statErr
	}
	digest, err := restoreOwnershipDigest(host.paths, state)
	if err != nil {
		return lifecycle.GatewayRestoreHostState{}, err
	}
	return lifecycle.GatewayRestoreHostState{
		Initialized: true, Role: state.Host.Role, StateGeneration: state.Generation,
		OwnershipSHA256: digest, CurrentGatewayID: state.Host.ID,
	}, nil
}

func (host *systemGatewayRestoreHost) Preflight(
	ctx context.Context,
	payload *lifecycle.GatewayRestorePayload,
	candidate model.State,
	current lifecycle.GatewayRestoreHostState,
) (lifecycle.GatewayRestorePreflight, error) {
	if ctx == nil || host == nil || payload == nil {
		return lifecycle.GatewayRestorePreflight{}, fmt.Errorf("gateway restore preflight is incomplete")
	}
	if err := host.snapshot.ValidateMandatoryCapabilities(); err != nil {
		return lifecycle.GatewayRestorePreflight{}, err
	}
	observed, err := host.Inspect(ctx)
	if err != nil || !reflect.DeepEqual(observed, current) {
		return lifecycle.GatewayRestorePreflight{}, fmt.Errorf("%w: gateway changed during restore preflight", lifecycle.ErrGatewayRestoreConflict)
	}
	ownedTunnelPorts, err := host.currentRestoreTunnelPorts(current)
	if err != nil {
		return lifecycle.GatewayRestorePreflight{}, err
	}
	snapshot := gatewayRestorePreflightSnapshot(host.snapshot, current.Initialized, ownedTunnelPorts)
	network, err := linuxplatform.ValidateGatewayNetwork(linuxplatform.GatewayNetworkInput{
		PublicIPv4: candidate.Host.PublicIPv4, ClientCIDR: candidate.Host.ClientCIDR,
		NodeCIDR: candidate.Host.NodeCIDR, ExternalInterface: candidate.Host.ExternalInterface,
	}, snapshot)
	if err != nil {
		return lifecycle.GatewayRestorePreflight{}, err
	}
	ssh, err := linuxplatform.ResolveSSHPort(linuxplatform.SSHPortInput{SSHConnection: host.sshConnection}, snapshot)
	if err != nil {
		return lifecycle.GatewayRestorePreflight{}, err
	}
	if _, err := linuxplatform.AnalyzeGatewayPreflight(linuxplatform.GatewayPreflightInput{Network: network, SSH: ssh}, snapshot); err != nil {
		return lifecycle.GatewayRestorePreflight{}, err
	}
	unavailable := restoreUnavailableLoopbackPorts(host.snapshot, ownedTunnelPorts)
	_, remaps, err := tunnel.DefaultLoopbackAllocatorFromExposes(candidate.Exposes, unavailable)
	if err != nil {
		return lifecycle.GatewayRestorePreflight{}, err
	}
	updated := candidate
	updated.Host.ExternalInterface = network.ExternalInterface
	updated.Host.SSHPort = ssh.Port
	updated.Exposes = append([]model.Expose(nil), candidate.Exposes...)
	for _, remap := range remaps {
		for index := range updated.Exposes {
			if updated.Exposes[index].ID == remap.ExposeID {
				updated.Exposes[index].TunnelPort = remap.Port
				break
			}
		}
	}
	if !reflect.DeepEqual(restoreStateWithoutGeneration(updated), restoreStateWithoutGeneration(candidate)) {
		updated.Generation, err = model.NextGeneration(candidate.Generation)
		if err != nil {
			return lifecycle.GatewayRestorePreflight{}, err
		}
	}
	if err := updated.Validate(); err != nil {
		return lifecycle.GatewayRestorePreflight{}, fmt.Errorf("validate system restore candidate: %w", err)
	}
	if _, err := host.renderAndValidate(ctx, payload, updated); err != nil {
		return lifecycle.GatewayRestorePreflight{}, fmt.Errorf("validate restored gateway material: %w", err)
	}
	affected := []string{
		"nginx.service", "vpnctl-controller.service", "vpnctl-dns.service", "vpnctl-restricted.service",
		"vpnctl-standard.service", "vpnctl-tunnel-server.service",
	}
	sort.Strings(affected)
	return lifecycle.GatewayRestorePreflight{
		Candidate: updated, Network: network, SSH: ssh, PortRemaps: remaps,
		AffectedServices:      affected,
		ExpectedInterruptions: []string{"gateway transports, private-node tunnels, and HTTPS ingress restart during restore convergence"},
	}, nil
}

func restoreStateWithoutGeneration(state model.State) model.State {
	state.Generation = 0
	return state
}

func (host *systemGatewayRestoreHost) currentRestoreTunnelPorts(current lifecycle.GatewayRestoreHostState) ([]int, error) {
	if !current.Initialized {
		return nil, nil
	}
	stateStore, err := store.NewStateStore(host.paths)
	if err != nil {
		return nil, err
	}
	state, err := stateStore.Load()
	if err != nil {
		return nil, err
	}
	if state.Host.Role != model.RoleGateway || state.Host.ID != current.CurrentGatewayID || state.Generation != current.StateGeneration {
		return nil, fmt.Errorf("%w: current gateway identity changed during restore preflight", lifecycle.ErrGatewayRestoreConflict)
	}
	digest, err := restoreOwnershipDigest(host.paths, state)
	if err != nil {
		return nil, err
	}
	if digest != current.OwnershipSHA256 {
		return nil, fmt.Errorf("%w: current gateway ownership changed during restore preflight", lifecycle.ErrGatewayRestoreConflict)
	}
	ports := make([]int, 0, len(state.Exposes))
	for _, expose := range state.Exposes {
		ports = append(ports, expose.TunnelPort)
	}
	sort.Ints(ports)
	return ports, nil
}

func gatewayRestorePreflightSnapshot(snapshot linuxplatform.HostSnapshot, initialized bool, ownedTunnelPorts []int) linuxplatform.HostSnapshot {
	result := snapshot
	if !initialized {
		return result
	}
	result.Interfaces = filterRestoreValues(snapshot.Interfaces, func(value linuxplatform.NetworkInterface) bool {
		return value.Name != linuxplatform.GatewayOverlayInterface
	})
	result.ContainerNetworks = filterRestoreValues(snapshot.ContainerNetworks, func(value linuxplatform.ContainerNetwork) bool {
		return value.Interface != linuxplatform.GatewayOverlayInterface
	})
	result.Routes = filterRestoreValues(snapshot.Routes, func(value linuxplatform.Route) bool {
		return value.Device != linuxplatform.GatewayOverlayInterface && value.Table != linuxplatform.VPNCTLSelectedRouteTable && value.Table != linuxplatform.VPNCTLGatewayRouteTable
	})
	result.PolicyRules = filterRestoreValues(snapshot.PolicyRules, func(value linuxplatform.PolicyRule) bool {
		return value.Priority != linuxplatform.VPNCTLRecoveryRulePriority && value.Priority != linuxplatform.VPNCTLIngressRulePriority && value.Priority != linuxplatform.VPNCTLSelectedRulePriority
	})
	result.NFTablesTables = filterRestoreValues(snapshot.NFTablesTables, func(value linuxplatform.NFTablesTable) bool {
		return value.Family != linuxplatform.VPNCTLNFTablesFamily || value.Name != linuxplatform.VPNCTLNFTablesTable
	})
	ownedPorts := map[string]struct{}{
		"tcp:443": {}, "tcp:8443": {}, "udp:51820": {},
	}
	for _, port := range ownedTunnelPorts {
		ownedPorts[fmt.Sprintf("tcp:%d", port)] = struct{}{}
	}
	result.Listeners = filterRestoreValues(snapshot.Listeners, func(value linuxplatform.Listener) bool {
		_, owned := ownedPorts[fmt.Sprintf("%s:%d", value.Protocol, value.Port)]
		return !owned
	})
	return result
}

func filterRestoreValues[T any](values []T, keep func(T) bool) []T {
	result := make([]T, 0, len(values))
	for _, value := range values {
		if keep(value) {
			result = append(result, value)
		}
	}
	return result
}

func restoreUnavailableLoopbackPorts(snapshot linuxplatform.HostSnapshot, ownedTunnelPorts []int) []int {
	owned := make(map[int]struct{}, len(ownedTunnelPorts))
	for _, port := range ownedTunnelPorts {
		owned[port] = struct{}{}
	}
	unavailable := make(map[int]struct{})
	for _, listener := range snapshot.Listeners {
		if listener.Protocol != "tcp" || listener.Port < tunnel.DefaultLoopbackPortFirst || listener.Port > tunnel.DefaultLoopbackPortLast {
			continue
		}
		if listener.Address != "127.0.0.1" && listener.Address != "0.0.0.0" && listener.Address != "*" {
			continue
		}
		if _, currentOwnership := owned[listener.Port]; currentOwnership {
			continue
		}
		unavailable[listener.Port] = struct{}{}
	}
	result := make([]int, 0, len(unavailable))
	for port := range unavailable {
		result = append(result, port)
	}
	sort.Ints(result)
	return result
}

func (host *systemGatewayRestoreHost) renderAndValidate(ctx context.Context, payload *lifecycle.GatewayRestorePayload, candidate model.State) (_ gatewayRestoreRendered, returnErr error) {
	stage, err := os.MkdirTemp(filepath.Join(host.paths.Root, "tmp"), "vpnctl-restore-preflight-")
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	defer func() { returnErr = errors.Join(returnErr, os.RemoveAll(stage)) }()
	stagePaths, err := store.NewPaths(stage)
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	for _, directory := range []string{stagePaths.StateDir, stagePaths.SecretsDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return gatewayRestoreRendered{}, err
		}
	}
	for _, file := range payload.Files() {
		if !strings.HasPrefix(file.Path, "secrets/") {
			continue
		}
		target := filepath.Join(stagePaths.StateDir, filepath.FromSlash(file.Path))
		if err := copyGatewayRestorePayloadFile(payload, file.Path, target, 0o600); err != nil {
			return gatewayRestoreRendered{}, err
		}
	}
	secrets, err := store.NewSecretStore(stagePaths)
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	if err := validateRestoredCertificates(candidate, secrets); err != nil {
		return gatewayRestoreRendered{}, err
	}
	if err := validateRestoredEnrollmentIdentity(candidate, secrets); err != nil {
		return gatewayRestoreRendered{}, err
	}
	for _, file := range payload.Files() {
		if !strings.HasPrefix(file.Path, "config/presets.d/") {
			continue
		}
		content, err := readGatewayRestorePayloadFile(payload, file.Path, routing.PresetMaximumDocumentBytes)
		if err != nil {
			return gatewayRestoreRendered{}, err
		}
		ast, err := routing.DecodePresetDocument(content)
		if err != nil {
			return gatewayRestoreRendered{}, fmt.Errorf("preset %s: %w", filepath.Base(file.Path), err)
		}
		if filepath.Base(file.Path) != ast.Name+".yaml" {
			return gatewayRestoreRendered{}, fmt.Errorf("preset source name differs from filename")
		}
	}

	roleRequest, err := linuxplatform.RenderGatewayRoleInstallation(host.binaryPath)
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	dns, err := routing.RenderGatewayDNSConfig(candidate)
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	roleRequest.Configs = append(roleRequest.Configs,
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSConfigFileName, Content: dns.Bytes()},
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSReadyFileName, Content: []byte("schema_version=1\n")},
	)
	listeners, err := transport.NewGatewayListenerProvisioner(secrets, host.wgRunner, nil)
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	listenerFiles, err := listeners.Provision(ctx, candidate)
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	for _, file := range listenerFiles.ConfigFiles() {
		roleRequest.Configs = append(roleRequest.Configs, linuxplatform.RoleConfigFile{Name: file.Name, Content: file.Content})
	}

	files := make(map[string]restoreRenderedFile)
	tunnelRecord, tunnelPresent, err := findRestoreCertificate(candidate, model.CertificateTunnelServer)
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	if !tunnelPresent && (restoreHasActiveNodes(candidate) || len(candidate.Exposes) != 0) {
		return gatewayRestoreRendered{}, fmt.Errorf("restored private-node topology has no tunnel server identity")
	}
	if tunnelPresent {
		plan, err := tunnel.PlanFromState(candidate)
		if err != nil {
			return gatewayRestoreRendered{}, err
		}
		frpComponent, err := restoreComponent(candidate.Components, tunnel.FRPProviderName)
		if err != nil {
			return gatewayRestoreRendered{}, err
		}
		frpProvider, err := tunnel.NewFRPProvider(host.paths.Root, frpComponent, nil)
		if err != nil {
			return gatewayRestoreRendered{}, err
		}
		frpCandidate, err := frpProvider.Render(ctx, tunnel.RenderRequest{Plan: plan})
		if err != nil {
			return gatewayRestoreRendered{}, err
		}
		frpBytes, ok := frpCandidate.(interface{ Bytes() []byte })
		if !ok {
			return gatewayRestoreRendered{}, fmt.Errorf("frp restore candidate is opaque")
		}
		files[tunnel.FRPServerConfigFileName] = restoreRenderedFile{content: frpBytes.Bytes(), mode: 0o600}
		files[tunnel.FRPServerReadyFileName] = restoreRenderedFile{content: []byte(fmt.Sprintf("schema_version=1\nstate_generation=%d\nconfig_sha256=%s\n", candidate.Generation, frpCandidate.Descriptor().ConfigHash)), mode: 0o600}
		tunnelCertificate, err := secrets.Get(model.SecretRef(tunnelRecord.CertificateRef))
		if err != nil {
			return gatewayRestoreRendered{}, err
		}
		tunnelKey, err := secrets.Get(tunnelRecord.PrivateKeyRef)
		if err != nil {
			return gatewayRestoreRendered{}, err
		}
		files[tunnel.FRPServerCertificateName] = restoreRenderedFile{content: tunnelCertificate, mode: 0o644}
		files[tunnel.FRPServerPrivateKeyName] = restoreRenderedFile{content: tunnelKey, mode: 0o600}
	}

	publicRecord, err := restoreCertificate(candidate, model.CertificatePublicIngress)
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	publicCertificate, err := secrets.Get(model.SecretRef(publicRecord.CertificateRef))
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	if _, err := ingress.ValidatePublicCertificatePEM(publicCertificate, publicRecord, candidate.Host.PublicIPv4); err != nil {
		return gatewayRestoreRendered{}, err
	}
	nginx, err := ingress.RenderNginxConfig(ingress.NginxRenderRequest{
		StateGeneration: candidate.Generation, PublicIPv4: candidate.Host.PublicIPv4,
		CertificatePath:  restoreSecretPath(host.paths, model.SecretRef(publicRecord.CertificateRef)),
		PrivateKeyPath:   restoreSecretPath(host.paths, publicRecord.PrivateKeyRef),
		RuntimeDirectory: ingress.NginxRuntimeDirectory(host.paths), Limits: ingress.DefaultGatewayHardLimits(),
		Exposes: append([]model.Expose(nil), candidate.Exposes...),
	})
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	if _, err := host.roles.Plan(roleRequest); err != nil {
		return gatewayRestoreRendered{}, err
	}
	watchdogUnits, err := host.watchdogUnits.Plan(host.binaryPath)
	if err != nil {
		return gatewayRestoreRendered{}, err
	}
	return gatewayRestoreRendered{roleRequest: roleRequest, watchdogUnits: watchdogUnits, files: files, nginx: nginx}, nil
}

func restoreComponent(manifest model.ComponentManifest, name string) (model.ComponentPin, error) {
	for _, component := range manifest.Components {
		if component.Name == name {
			return component, nil
		}
	}
	return model.ComponentPin{}, fmt.Errorf("restored release has no %s component", name)
}

func restoreCertificate(state model.State, kind model.CertificateKind) (model.Certificate, error) {
	record, found, err := findRestoreCertificate(state, kind)
	if err != nil {
		return model.Certificate{}, err
	}
	if !found {
		return model.Certificate{}, fmt.Errorf("restored state has no %s certificate", kind)
	}
	return record, nil
}

func findRestoreCertificate(state model.State, kind model.CertificateKind) (model.Certificate, bool, error) {
	var found *model.Certificate
	for index := range state.Certificates {
		if state.Certificates[index].Kind != kind {
			continue
		}
		if found != nil {
			return model.Certificate{}, false, fmt.Errorf("restored state has multiple %s certificates", kind)
		}
		copy := state.Certificates[index]
		found = &copy
	}
	if found == nil {
		return model.Certificate{}, false, nil
	}
	return *found, true, nil
}

func restoreHasActiveNodes(state model.State) bool {
	for _, node := range state.Nodes {
		if node.Lifecycle == model.LifecycleActive {
			return true
		}
	}
	return false
}

func validateRestoredCertificates(state model.State, secrets *store.SecretStore) error {
	activeNodes := make(map[string]struct{}, len(state.Nodes))
	for _, node := range state.Nodes {
		if node.Lifecycle == model.LifecycleActive {
			activeNodes[node.ID] = struct{}{}
		}
	}
	for _, record := range state.Certificates {
		if record.Kind == model.CertificateControlNode {
			if _, active := activeNodes[record.OwnerID]; !active {
				continue
			}
		}
		certificatePEM, err := secrets.Get(model.SecretRef(record.CertificateRef))
		if err != nil {
			return fmt.Errorf("read restored certificate %s: %w", record.ID, err)
		}
		block, rest := pem.Decode(certificatePEM)
		if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
			return fmt.Errorf("restored certificate %s PEM is invalid", record.ID)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse restored certificate %s: %w", record.ID, err)
		}
		digest := sha256.Sum256(certificate.Raw)
		if record.Fingerprint != "sha256:"+hex.EncodeToString(digest[:]) || record.SerialHex != certificate.SerialNumber.Text(16) || record.Subject != certificate.Subject.String() ||
			!record.NotBefore.Equal(certificate.NotBefore) || !record.NotAfter.Equal(certificate.NotAfter) {
			return fmt.Errorf("restored certificate %s differs from authoritative metadata", record.ID)
		}
		if record.PrivateKeyRef != "" {
			privateKey, err := secrets.Get(record.PrivateKeyRef)
			if err != nil {
				return fmt.Errorf("read restored certificate key %s: %w", record.ID, err)
			}
			if _, err := tls.X509KeyPair(certificatePEM, privateKey); err != nil {
				return fmt.Errorf("restored certificate key %s does not match", record.ID)
			}
		}
	}
	return nil
}

func validateRestoredEnrollmentIdentity(state model.State, secrets *store.SecretStore) error {
	if state.EnrollmentIdentity == nil {
		return fmt.Errorf("restored gateway enrollment identity is missing")
	}
	identity := *state.EnrollmentIdentity
	publicPEM, err := secrets.Get(model.SecretRef(identity.PublicKeyRef))
	if err != nil {
		return fmt.Errorf("read restored enrollment public key: %w", err)
	}
	publicBlock, rest := pem.Decode(publicPEM)
	if publicBlock == nil || publicBlock.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return fmt.Errorf("restored enrollment public key PEM is invalid")
	}
	parsedPublic, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse restored enrollment public key: %w", err)
	}
	publicKey, ok := parsedPublic.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("restored enrollment public key must use Ed25519")
	}
	privatePEM, err := secrets.Get(identity.PrivateKeyRef)
	if err != nil {
		return fmt.Errorf("read restored enrollment private key: %w", err)
	}
	privateBlock, rest := pem.Decode(privatePEM)
	if privateBlock == nil || privateBlock.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return fmt.Errorf("restored enrollment private key PEM is invalid")
	}
	parsedPrivate, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse restored enrollment private key: %w", err)
	}
	privateKey, ok := parsedPrivate.(ed25519.PrivateKey)
	if !ok || !publicKey.Equal(privateKey.Public()) {
		return fmt.Errorf("restored enrollment private key does not match its public key")
	}
	digest := sha256.Sum256(publicBlock.Bytes)
	if identity.Fingerprint != "sha256:"+hex.EncodeToString(digest[:]) {
		return fmt.Errorf("restored enrollment public key differs from authoritative metadata")
	}
	return nil
}

func restoreSecretPath(paths store.Paths, reference model.SecretRef) string {
	kind, id, _ := reference.Parts()
	return filepath.Join(paths.SecretsDir, kind, id)
}

func copyGatewayRestorePayloadFile(payload *lifecycle.GatewayRestorePayload, archivePath, target string, mode fs.FileMode) (returnErr error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	source, err := payload.Open(archivePath)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, destination.Close())
		}
	}()
	if _, err := io.Copy(destination, source); err != nil {
		return err
	}
	if err := destination.Sync(); err != nil {
		return err
	}
	if err := destination.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

func readGatewayRestorePayloadFile(payload *lifecycle.GatewayRestorePayload, archivePath string, maximum int64) ([]byte, error) {
	file, err := payload.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return nil, fmt.Errorf("restore payload file exceeds %d bytes", maximum)
	}
	return content, nil
}

type gatewayRestoreSnapshotMetadata struct {
	SchemaVersion    int       `json:"schema_version"`
	SnapshotID       string    `json:"snapshot_id"`
	CreatedAt        time.Time `json:"created_at"`
	StateGeneration  uint64    `json:"state_generation"`
	OwnershipSHA256  string    `json:"ownership_sha256"`
	CurrentGatewayID string    `json:"current_gateway_id"`
}

func (host *systemGatewayRestoreHost) EmergencySnapshot(ctx context.Context, current lifecycle.GatewayRestoreHostState) (_ lifecycle.GatewayRestoreEmergencySnapshot, returnErr error) {
	if ctx == nil || host == nil || !current.Initialized || current.Role != model.RoleGateway {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, fmt.Errorf("initialized gateway is required for an emergency restore snapshot")
	}
	observed, err := host.Inspect(ctx)
	if err != nil || !reflect.DeepEqual(observed, current) {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, fmt.Errorf("%w: gateway changed before emergency snapshot", lifecycle.ErrGatewayRestoreConflict)
	}
	id, err := model.AllocateUUID(nil, host.newUUID)
	if err != nil {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, err
	}
	createdAt := host.now().UTC().Truncate(time.Second)
	parent := filepath.Join(filepath.Dir(host.paths.StateDir), "vpnctl-restore-snapshots")
	if err := ensureRestoreDirectory(parent, 0o700); err != nil {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, err
	}
	temporary, err := os.MkdirTemp(parent, ".restore-"+id+"-")
	if err != nil {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, err
	}
	keep := false
	defer func() {
		if !keep {
			returnErr = errors.Join(returnErr, os.RemoveAll(temporary))
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, err
	}
	if err := copyRestoreTree(ctx, host.paths.ConfigDir, filepath.Join(temporary, "config")); err != nil {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, fmt.Errorf("snapshot gateway config: %w", err)
	}
	if err := copyRestoreTree(ctx, host.paths.StateDir, filepath.Join(temporary, "state")); err != nil {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, fmt.Errorf("snapshot gateway state: %w", err)
	}
	metadata, err := json.MarshalIndent(gatewayRestoreSnapshotMetadata{
		SchemaVersion: 1, SnapshotID: id, CreatedAt: createdAt, StateGeneration: current.StateGeneration,
		OwnershipSHA256: current.OwnershipSHA256, CurrentGatewayID: current.CurrentGatewayID,
	}, "", "  ")
	if err != nil {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, err
	}
	metadata = append(metadata, '\n')
	if err := writeRestoreFile(filepath.Join(temporary, "snapshot.json"), metadata, 0o600); err != nil {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, err
	}
	final := filepath.Join(parent, "restore-"+id)
	if _, err := os.Lstat(final); err == nil {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, fmt.Errorf("restore snapshot ID collision")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, err
	}
	if err := os.Rename(temporary, final); err != nil {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, err
	}
	keep = true
	if err := syncRestoreDirectory(parent); err != nil {
		return lifecycle.GatewayRestoreEmergencySnapshot{}, err
	}
	return lifecycle.GatewayRestoreEmergencySnapshot{ID: id, Path: final, CreatedAt: createdAt}, nil
}

func (host *systemGatewayRestoreHost) Activate(
	ctx context.Context,
	payload *lifecycle.GatewayRestorePayload,
	preflight lifecycle.GatewayRestorePreflight,
	snapshot lifecycle.GatewayRestoreEmergencySnapshot,
) (lifecycle.GatewayRestoreActivation, error) {
	if ctx == nil || host == nil || payload == nil {
		return lifecycle.GatewayRestoreActivation{}, fmt.Errorf("gateway restore activation is incomplete")
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	if len(host.transactions) != 0 {
		return lifecycle.GatewayRestoreActivation{}, fmt.Errorf("%w: another gateway restore transaction is active", lifecycle.ErrGatewayRestoreConflict)
	}
	rendered, err := host.renderAndValidate(ctx, payload, preflight.Candidate)
	if err != nil {
		return lifecycle.GatewayRestoreActivation{}, err
	}
	configStage, stateStage, err := host.stageRestoreTrees(ctx, payload, preflight.Candidate, rendered)
	if err != nil {
		return lifecycle.GatewayRestoreActivation{}, err
	}
	keepStages := true
	defer func() {
		if keepStages {
			_ = os.RemoveAll(configStage)
			_ = os.RemoveAll(stateStage)
		}
	}()
	firewall, err := lifecycle.RenderGatewayIdentityFirewall(preflight.Candidate, lifecycle.GatewayIdentityFirewallServices{
		ClientTCPPorts: []int{routing.GatewayDNSPort}, ClientUDPPorts: []int{routing.GatewayDNSPort},
		NodeTCPPorts: []int{routing.GatewayDNSPort, control.RPCControlTCPPort, tunnel.FRPServerPort}, NodeUDPPorts: []int{routing.GatewayDNSPort},
	})
	if err != nil {
		return lifecycle.GatewayRestoreActivation{}, err
	}
	networkSnapshot, err := host.network.Snapshot(ctx, linuxplatform.GatewayInitNetworkScope())
	if err != nil {
		return lifecycle.GatewayRestoreActivation{}, fmt.Errorf("snapshot gateway network before restore: %w", err)
	}
	unitSnapshots, err := host.snapshotRestoreUnits(rendered)
	if err != nil {
		return lifecycle.GatewayRestoreActivation{}, err
	}
	id, err := model.AllocateUUID(nil, host.newUUID)
	if err != nil {
		return lifecycle.GatewayRestoreActivation{}, err
	}
	transaction := &systemGatewayRestoreTransaction{
		id: id, oldConfig: filepath.Join(filepath.Dir(host.paths.ConfigDir), ".vpnctl-restore-old-config-"+id),
		oldState: filepath.Join(filepath.Dir(host.paths.StateDir), ".vpnctl-restore-old-state-"+id),
		units:    unitSnapshots, network: networkSnapshot, previousInitialized: snapshot.ID != "",
	}
	if _, err := os.Lstat(host.paths.ConfigDir); err == nil {
		transaction.configWasPresent = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return lifecycle.GatewayRestoreActivation{}, err
	}
	if _, err := os.Lstat(host.paths.StateDir); err == nil {
		transaction.stateWasPresent = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return lifecycle.GatewayRestoreActivation{}, err
	}
	if _, err := os.Lstat(host.paths.RuntimeDir); err == nil {
		transaction.runtimeWasPresent = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return lifecycle.GatewayRestoreActivation{}, err
	}
	if transaction.previousInitialized != transaction.configWasPresent || transaction.previousInitialized != transaction.stateWasPresent {
		return lifecycle.GatewayRestoreActivation{}, fmt.Errorf("%w: live restore roots differ from the planned host", lifecycle.ErrGatewayRestoreConflict)
	}
	for _, oldRoot := range []string{transaction.oldConfig, transaction.oldState} {
		if _, err := os.Lstat(oldRoot); err == nil {
			return lifecycle.GatewayRestoreActivation{}, fmt.Errorf("%w: restore transaction path already exists", lifecycle.ErrGatewayRestoreConflict)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return lifecycle.GatewayRestoreActivation{}, err
		}
	}
	host.transactions[id] = transaction
	activation := lifecycle.GatewayRestoreActivation{ID: id, Started: true}
	transaction.started = true

	if transaction.previousInitialized {
		if err := host.stopGatewayUnits(ctx); err != nil {
			return activation, err
		}
	}
	if transaction.configWasPresent {
		if err := os.Rename(host.paths.ConfigDir, transaction.oldConfig); err != nil {
			return activation, err
		}
		transaction.configMoved = true
	}
	if err := os.Rename(configStage, host.paths.ConfigDir); err != nil {
		return activation, err
	}
	transaction.configActivated = true
	configStage = ""
	if transaction.stateWasPresent {
		if err := os.Rename(host.paths.StateDir, transaction.oldState); err != nil {
			return activation, err
		}
		transaction.stateMoved = true
	}
	if err := os.Rename(stateStage, host.paths.StateDir); err != nil {
		return activation, err
	}
	transaction.stateActivated = true
	stateStage = ""
	keepStages = false
	if !transaction.runtimeWasPresent {
		if err := os.Mkdir(host.paths.RuntimeDir, 0o700); err != nil {
			return activation, err
		}
	}
	if _, err := host.watchdogUnits.Apply(ctx, rendered.watchdogUnits); err != nil {
		return activation, fmt.Errorf("install restore watchdog units: %w", err)
	}
	if _, err := host.roles.Apply(ctx, rendered.roleRequest); err != nil {
		return activation, fmt.Errorf("activate restored gateway services: %w", err)
	}
	if err := host.network.ActivateGateway(ctx, firewall); err != nil {
		return activation, fmt.Errorf("activate restored gateway network: %w", err)
	}
	return activation, nil
}

func (host *systemGatewayRestoreHost) Health(ctx context.Context, activation lifecycle.GatewayRestoreActivation, candidate model.State) error {
	if ctx == nil || host == nil || !activation.Started {
		return fmt.Errorf("gateway restore health check is incomplete")
	}
	host.mu.Lock()
	transaction := host.transactions[activation.ID]
	host.mu.Unlock()
	if transaction == nil || !transaction.started {
		return fmt.Errorf("gateway restore transaction is unavailable")
	}
	stateStore, err := store.NewStateStore(host.paths)
	if err != nil {
		return err
	}
	observed, err := stateStore.Load()
	if err != nil || !reflect.DeepEqual(observed, candidate) {
		return fmt.Errorf("restored authoritative state differs from the prevalidated candidate")
	}
	for _, unit := range linuxplatform.RoleUnitNames(model.RoleGateway) {
		readyName := map[string]string{
			"vpnctl-controller.service":    "gateway-controller.ready",
			"vpnctl-dns.service":           routing.GatewayDNSReadyFileName,
			"vpnctl-restricted.service":    transport.GatewayRestrictedReadyFileName,
			"vpnctl-standard.service":      transport.GatewayStandardReadyFileName,
			"vpnctl-tunnel-server.service": tunnel.FRPServerReadyFileName,
		}[unit]
		if _, err := os.Lstat(filepath.Join(host.paths.ConfigDir, "generated", "gateway", readyName)); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		result, err := host.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"is-active", "--quiet", unit}})
		if err != nil || result.ExitCode != 0 {
			return fmt.Errorf("restored gateway service %s is not active", unit)
		}
	}
	secrets, err := store.NewSecretStore(host.paths)
	if err != nil {
		return err
	}
	if err := validateRestoredCertificates(candidate, secrets); err != nil {
		return err
	}
	if err := validateRestoredEnrollmentIdentity(candidate, secrets); err != nil {
		return err
	}
	return nil
}

func (host *systemGatewayRestoreHost) Commit(ctx context.Context, activation lifecycle.GatewayRestoreActivation) error {
	if ctx == nil || host == nil || !activation.Started {
		return fmt.Errorf("gateway restore commit is incomplete")
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	transaction := host.transactions[activation.ID]
	if transaction == nil {
		return fmt.Errorf("gateway restore transaction is unavailable")
	}
	var result error
	for _, path := range []string{transaction.oldConfig, transaction.oldState} {
		if err := removeRestoreOwnedTree(path); err != nil {
			result = errors.Join(result, err)
		}
	}
	if result != nil {
		return result
	}
	delete(host.transactions, activation.ID)
	return nil
}

func (host *systemGatewayRestoreHost) Rollback(ctx context.Context, activation lifecycle.GatewayRestoreActivation, snapshot lifecycle.GatewayRestoreEmergencySnapshot) error {
	if ctx == nil || host == nil || !activation.Started {
		return fmt.Errorf("gateway restore rollback is incomplete")
	}
	host.mu.Lock()
	defer host.mu.Unlock()
	transaction := host.transactions[activation.ID]
	if transaction == nil {
		return nil
	}
	var result error
	for _, unit := range linuxplatform.RoleUnitNames(model.RoleGateway) {
		result = errors.Join(result, host.runSystemctl(ctx, "stop", unit))
	}
	result = errors.Join(result, host.network.Restore(ctx, transaction.network))
	result = errors.Join(result, restoreSwappedRoot(host.paths.ConfigDir, transaction.oldConfig, transaction.configWasPresent, transaction.configMoved, transaction.configActivated, snapshot.Path, "config"))
	result = errors.Join(result, restoreSwappedRoot(host.paths.StateDir, transaction.oldState, transaction.stateWasPresent, transaction.stateMoved, transaction.stateActivated, snapshot.Path, "state"))
	if !transaction.runtimeWasPresent {
		result = errors.Join(result, removeRestoreOwnedTree(host.paths.RuntimeDir))
	}
	for _, unit := range transaction.units {
		result = errors.Join(result, restoreUnitFile(unit))
	}
	result = errors.Join(result, host.runSystemctl(ctx, "daemon-reload"))
	if transaction.previousInitialized {
		for _, unit := range linuxplatform.RoleUnitNames(model.RoleGateway) {
			result = errors.Join(result, host.runSystemctl(ctx, "enable", unit), host.runSystemctl(ctx, "start", unit))
		}
	}
	delete(host.transactions, activation.ID)
	return result
}

func (host *systemGatewayRestoreHost) stageRestoreTrees(
	ctx context.Context,
	payload *lifecycle.GatewayRestorePayload,
	candidate model.State,
	rendered gatewayRestoreRendered,
) (configStage, stateStage string, returnErr error) {
	if err := validateRestoreParent(filepath.Dir(host.paths.ConfigDir)); err != nil {
		return "", "", err
	}
	if err := validateRestoreParent(filepath.Dir(host.paths.StateDir)); err != nil {
		return "", "", err
	}
	configStage, err := os.MkdirTemp(filepath.Dir(host.paths.ConfigDir), ".vpnctl-restore-config-")
	if err != nil {
		return "", "", err
	}
	stateStage, err = os.MkdirTemp(filepath.Dir(host.paths.StateDir), ".vpnctl-restore-state-")
	if err != nil {
		_ = os.RemoveAll(configStage)
		return "", "", err
	}
	keep := false
	defer func() {
		if !keep {
			returnErr = errors.Join(returnErr, os.RemoveAll(configStage), os.RemoveAll(stateStage))
		}
	}()
	if err := os.Chmod(configStage, 0o755); err != nil {
		return "", "", err
	}
	if err := os.Chmod(stateStage, 0o700); err != nil {
		return "", "", err
	}
	for _, directory := range []string{
		filepath.Join(configStage, "presets.d"), filepath.Join(configStage, "generated", "gateway"),
		filepath.Join(stateStage, "secrets"), filepath.Join(stateStage, "secrets", "pki"), filepath.Join(stateStage, "secrets", "enrollment"),
		filepath.Join(stateStage, "exports"), filepath.Join(stateStage, "exports", "clients"),
		filepath.Join(stateStage, "backups"), filepath.Join(stateStage, "snapshots"),
		filepath.Join(stateStage, "operations"), filepath.Join(stateStage, "operations", "watchdog"),
	} {
		mode := fs.FileMode(0o700)
		if strings.HasPrefix(directory, configStage) {
			mode = 0o755
		}
		if err := os.MkdirAll(directory, mode); err != nil {
			return "", "", err
		}
	}
	for _, file := range payload.Files() {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		var target string
		mode := fs.FileMode(0o600)
		switch {
		case strings.HasPrefix(file.Path, "secrets/"):
			target = filepath.Join(stateStage, filepath.FromSlash(file.Path))
		case strings.HasPrefix(file.Path, "exports/"):
			target = filepath.Join(stateStage, filepath.FromSlash(file.Path))
			if file.Path == "exports/"+ingress.PublicCertificateExportName {
				mode = 0o644
			}
		case strings.HasPrefix(file.Path, "config/presets.d/"):
			target = filepath.Join(configStage, strings.TrimPrefix(filepath.FromSlash(file.Path), "config"+string(filepath.Separator)))
			mode = 0o644
		default:
			continue
		}
		if err := copyGatewayRestorePayloadFile(payload, file.Path, target, mode); err != nil {
			return "", "", err
		}
	}
	encoded, err := model.EncodeState(candidate)
	if err != nil {
		return "", "", err
	}
	if err := writeRestoreFile(filepath.Join(stateStage, "state.json"), encoded, 0o600); err != nil {
		return "", "", err
	}
	generated := filepath.Join(configStage, "generated", "gateway")
	for _, file := range rendered.roleRequest.Configs {
		if err := writeRestoreFile(filepath.Join(generated, file.Name), file.Content, 0o600); err != nil {
			return "", "", err
		}
	}
	for name, file := range rendered.files {
		if err := writeRestoreFile(filepath.Join(generated, name), file.content, file.mode); err != nil {
			return "", "", err
		}
	}
	nginxRoot := filepath.Join(generated, ingress.NginxGeneratedDirectoryName)
	generationName := fmt.Sprintf("g%d-%s", rendered.nginx.StateGeneration(), rendered.nginx.ConfigHash())
	generationRoot := filepath.Join(nginxRoot, ingress.NginxGenerationsDirectory, generationName)
	if err := os.MkdirAll(generationRoot, 0o700); err != nil {
		return "", "", err
	}
	for _, artifact := range rendered.nginx.Artifacts() {
		if err := writeRestoreFile(filepath.Join(generationRoot, filepath.FromSlash(artifact.RelativePath())), artifact.Bytes(), artifact.Mode()); err != nil {
			return "", "", err
		}
	}
	if err := os.Symlink(filepath.Join(ingress.NginxGenerationsDirectory, generationName), filepath.Join(nginxRoot, ingress.NginxCurrentLinkName)); err != nil {
		return "", "", err
	}
	keep = true
	return configStage, stateStage, nil
}

func (host *systemGatewayRestoreHost) snapshotRestoreUnits(rendered gatewayRestoreRendered) ([]restoreUnitSnapshot, error) {
	names := linuxplatform.RoleUnitNames(model.RoleGateway)
	for _, unit := range rendered.watchdogUnits.Units {
		names = append(names, unit.Name)
	}
	sort.Strings(names)
	result := make([]restoreUnitSnapshot, 0, len(names))
	unitRoot := filepath.Join(host.paths.Root, "etc", "systemd", "system")
	if err := validateRestoreParent(unitRoot); err != nil {
		return nil, err
	}
	for index, name := range names {
		if index > 0 && name == names[index-1] {
			continue
		}
		path := filepath.Join(unitRoot, name)
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			result = append(result, restoreUnitSnapshot{path: path})
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > 256<<10 {
			return nil, fmt.Errorf("systemd unit target is unsafe: %s", path)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		result = append(result, restoreUnitSnapshot{path: path, present: true, content: content, mode: info.Mode().Perm()})
	}
	return result, nil
}

func (host *systemGatewayRestoreHost) stopGatewayUnits(ctx context.Context) error {
	units := linuxplatform.RoleUnitNames(model.RoleGateway)
	sort.Sort(sort.Reverse(sort.StringSlice(units)))
	for _, unit := range units {
		if err := host.runSystemctl(ctx, "stop", unit); err != nil {
			return err
		}
	}
	return nil
}

func (host *systemGatewayRestoreHost) runSystemctl(ctx context.Context, arguments ...string) error {
	result, err := host.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: arguments})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("systemctl %s failed with exit code %d", strings.Join(arguments, " "), result.ExitCode)
	}
	return nil
}

func restoreUnitFile(snapshot restoreUnitSnapshot) error {
	if snapshot.present {
		return replaceRestoreFile(snapshot.path, snapshot.content, snapshot.mode)
	}
	info, err := os.Lstat(snapshot.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refuse unsafe restore unit rollback target %s", snapshot.path)
	}
	return os.Remove(snapshot.path)
}

func restoreSwappedRoot(live, old string, wasPresent, moved, activated bool, snapshotPath, snapshotName string) error {
	if !moved && !activated {
		return nil
	}
	if activated {
		if err := removeRestoreOwnedTree(live); err != nil {
			return err
		}
	}
	if !wasPresent {
		return nil
	}
	if _, err := os.Lstat(old); err == nil {
		return os.Rename(old, live)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if snapshotPath == "" {
		return fmt.Errorf("previous restore root is unavailable")
	}
	return copyRestoreTree(context.Background(), filepath.Join(snapshotPath, snapshotName), live)
}

func removeRestoreOwnedTree(path string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("refuse unsafe restore cleanup path")
	}
	name := filepath.Base(path)
	if name != "vpnctl" && !strings.HasPrefix(name, ".vpnctl-restore-old-") {
		return fmt.Errorf("refuse non-owned restore cleanup path %s", path)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refuse unsafe restore cleanup target %s", path)
	}
	return os.RemoveAll(path)
}

func restoreOwnershipDigest(paths store.Paths, state model.State) (string, error) {
	encoded, err := model.EncodeState(state)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("vpnctl-restore-ownership-v1\x00state\x00"))
	_, _ = hash.Write(encoded)
	if err := hashRestoreTree(hash, paths.ConfigDir); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func hashRestoreTree(hash io.Writer, root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("restore ownership root must be a real directory")
	}
	count := 0
	var total int64
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		count++
		if count > maximumRestoreTreeFiles {
			return fmt.Errorf("restore ownership tree exceeds file bound")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		_, _ = io.WriteString(hash, filepath.ToSlash(relative)+"\x00"+info.Mode().String()+"\x00")
		switch {
		case info.IsDir():
			return nil
		case info.Mode().IsRegular():
			total += info.Size()
			if total > maximumRestoreTreeBytes {
				return fmt.Errorf("restore ownership tree exceeds byte bound")
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(hash, io.LimitReader(file, info.Size()+1))
			closeErr := file.Close()
			return errors.Join(copyErr, closeErr)
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil || !safeRestoreSymlink(target) {
				return fmt.Errorf("restore ownership tree has unsafe symlink")
			}
			_, _ = io.WriteString(hash, target)
			return nil
		default:
			return fmt.Errorf("restore ownership tree has unsupported file type")
		}
	})
}

func copyRestoreTree(ctx context.Context, source, destination string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("restore tree source must be a real directory")
	}
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("restore tree destination already exists")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	count := 0
	var total int64
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if count > maximumRestoreTreeFiles {
			return fmt.Errorf("restore snapshot tree exceeds file bound")
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := destination
		if relative != "." {
			target = filepath.Join(destination, relative)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			return os.Mkdir(target, info.Mode().Perm())
		case info.Mode().IsRegular():
			total += info.Size()
			if total > maximumRestoreTreeBytes {
				return fmt.Errorf("restore snapshot tree exceeds byte bound")
			}
			return copyRestoreRegularFile(path, target, info.Mode().Perm(), info.Size())
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil || !safeRestoreSymlink(link) {
				return fmt.Errorf("restore snapshot tree has unsafe symlink")
			}
			return os.Symlink(link, target)
		default:
			return fmt.Errorf("restore snapshot tree has unsupported file type")
		}
	})
}

func copyRestoreRegularFile(source, destination string, mode fs.FileMode, expectedSize int64) (returnErr error) {
	inputInfo, err := os.Lstat(source)
	if err != nil || inputInfo.Mode()&os.ModeSymlink != 0 || !inputInfo.Mode().IsRegular() || inputInfo.Size() != expectedSize {
		return fmt.Errorf("restore snapshot source changed")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, output.Close())
		}
	}()
	written, err := io.Copy(output, io.LimitReader(input, expectedSize+1))
	if err != nil || written != expectedSize {
		return fmt.Errorf("copy restore snapshot file: %w", err)
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

func safeRestoreSymlink(target string) bool {
	if target == "" || filepath.IsAbs(target) || filepath.Clean(target) != target {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(target), "/") {
		if part == ".." {
			return false
		}
	}
	return !strings.ContainsAny(target, "\x00\r\n")
}

func validateRestoreParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("restore parent must be a real existing directory: %s", path)
	}
	return nil
}

func ensureRestoreDirectory(path string, mode fs.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("restore directory is unsafe: %s", path)
	}
	return nil
}

func writeRestoreFile(path string, content []byte, mode fs.FileMode) (returnErr error) {
	if len(content) == 0 {
		return fmt.Errorf("refuse empty restore file %s", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, file.Close())
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

func replaceRestoreFile(path string, content []byte, mode fs.FileMode) error {
	parent := filepath.Dir(path)
	if err := validateRestoreParent(parent); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".vpnctl-restore-unit-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncRestoreDirectory(parent)
}

func syncRestoreDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

var _ lifecycle.GatewayRestoreHost = (*systemGatewayRestoreHost)(nil)
