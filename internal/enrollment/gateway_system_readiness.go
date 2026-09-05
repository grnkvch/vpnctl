package enrollment

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const maximumGatewayJoinSnapshotBytes = 8 << 20

// SystemGatewayJoinReadiness publishes one complete gateway-side join
// candidate before the authoritative invite/node transition. The returned
// preparation owns an exact file snapshot and the serialization lock until
// the caller either commits or rolls back the candidate.
type SystemGatewayJoinReadiness struct {
	paths      store.Paths
	secrets    NodeCredentialSecretStore
	roles      *linuxplatform.RoleSystemdInstaller
	runner     linuxplatform.ProbeRunner
	keyRunner  wireguard.Runner
	mutationMu *sync.Mutex
	binaryPath string
}

func NewSystemGatewayJoinReadiness(
	paths store.Paths,
	secrets NodeCredentialSecretStore,
	mutationMu *sync.Mutex,
) (*SystemGatewayJoinReadiness, error) {
	return newSystemGatewayJoinReadiness(
		paths, secrets, mutationMu, linuxplatform.OSProbeRunner{}, wireguard.ExecRunner{}, linuxplatform.DefaultVPNCTLBinaryPath,
	)
}

func newSystemGatewayJoinReadiness(
	paths store.Paths,
	secrets NodeCredentialSecretStore,
	mutationMu *sync.Mutex,
	runner linuxplatform.ProbeRunner,
	keyRunner wireguard.Runner,
	binaryPath string,
) (*SystemGatewayJoinReadiness, error) {
	if secrets == nil || mutationMu == nil || runner == nil || keyRunner == nil {
		return nil, fmt.Errorf("system gateway join readiness dependencies are incomplete")
	}
	roles, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, runner)
	if err != nil {
		return nil, err
	}
	if _, err := linuxplatform.RenderGatewayRoleInstallation(binaryPath); err != nil {
		return nil, err
	}
	return &SystemGatewayJoinReadiness{
		paths: paths, secrets: secrets, roles: roles, runner: runner, keyRunner: keyRunner,
		mutationMu: mutationMu, binaryPath: binaryPath,
	}, nil
}

func (readiness *SystemGatewayJoinReadiness) Check(ctx context.Context, candidate GatewayJoinCandidate) (JoinReadinessReport, error) {
	preparation, err := readiness.Prepare(ctx, candidate)
	if err != nil {
		return JoinReadinessReport{}, err
	}
	report := preparation.Report()
	return report, preparation.Rollback(context.Background())
}

func (readiness *SystemGatewayJoinReadiness) Prepare(
	ctx context.Context,
	candidate GatewayJoinCandidate,
) (GatewayJoinReadinessPreparation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if readiness == nil || readiness.secrets == nil || readiness.roles == nil || readiness.runner == nil ||
		readiness.keyRunner == nil || readiness.mutationMu == nil {
		return nil, fmt.Errorf("system gateway join readiness is incomplete")
	}
	readiness.mutationMu.Lock()
	locked := true
	defer func() {
		if locked {
			readiness.mutationMu.Unlock()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateSystemGatewayJoinCandidate(candidate); err != nil {
		return nil, err
	}

	references, err := NewNodeCredentialReferences(candidate.Node.ID, candidate.Node.CredentialGeneration)
	if err != nil {
		return nil, err
	}
	overlay := &gatewayJoinCredentialOverlay{base: readiness.secrets, values: make(map[model.SecretRef][]byte, 1)}
	err = candidate.UseNodeSharedCredentials(func(restrictedCredential, tunnelCredential []byte) error {
		if _, err := restricted.DecodeIdentitySecret(restrictedCredential); err != nil {
			return fmt.Errorf("validate candidate restricted credential: %w", err)
		}
		if err := tunnel.ValidateCredential(tunnelCredential); err != nil {
			return fmt.Errorf("validate candidate tunnel credential: %w", err)
		}
		overlay.values[references.RestrictedCredential] = append([]byte(nil), restrictedCredential...)
		return nil
	})
	if err != nil {
		overlay.Destroy()
		return nil, err
	}
	defer overlay.Destroy()

	request, err := readiness.renderCandidate(ctx, candidate, overlay)
	if err != nil {
		return nil, err
	}
	defer clearGatewayJoinRoleRequest(&request)
	snapshots, err := snapshotGatewayJoinConfigs(readiness.paths, request.Configs)
	if err != nil {
		return nil, err
	}
	preparation := &systemGatewayJoinPreparation{runtime: readiness, snapshots: snapshots}
	rollback := func(cause error) (GatewayJoinReadinessPreparation, error) {
		rollbackErr := preparation.rollbackLocked(context.Background())
		locked = false
		return nil, errors.Join(cause, rollbackErr)
	}
	if _, err := readiness.roles.Apply(ctx, request); err != nil {
		return rollback(fmt.Errorf("publish gateway join candidate: %w", err))
	}
	if err := readiness.restartCandidateServices(ctx); err != nil {
		return rollback(err)
	}
	report, err := readiness.checkCandidate(ctx, candidate)
	if err != nil {
		return rollback(err)
	}
	if err := report.Validate(); err != nil {
		return rollback(err)
	}
	preparation.report = report
	locked = false
	return preparation, nil
}

func (readiness *SystemGatewayJoinReadiness) renderCandidate(
	ctx context.Context,
	candidate GatewayJoinCandidate,
	credentials *gatewayJoinCredentialOverlay,
) (linuxplatform.RoleInstallationRequest, error) {
	return renderSystemGatewayCandidate(
		ctx, readiness.paths, credentials, readiness.keyRunner, readiness.binaryPath,
		candidate.State, candidate.TunnelServerCertificatePEM,
	)
}

func renderSystemGatewayCandidate(
	ctx context.Context,
	paths store.Paths,
	credentials NodeCredentialSecretStore,
	keyRunner wireguard.Runner,
	binaryPath string,
	state model.State,
	tunnelCertificatePEM []byte,
) (linuxplatform.RoleInstallationRequest, error) {
	request, err := linuxplatform.RenderGatewayRoleInstallation(binaryPath)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	listeners, err := transport.NewGatewayListenerProvisioner(credentials, keyRunner, nil)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	listenerFiles, err := listeners.Provision(ctx, state)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, fmt.Errorf("render candidate gateway listeners: %w", err)
	}
	for _, file := range listenerFiles.ConfigFiles() {
		request.Configs = append(request.Configs, linuxplatform.RoleConfigFile{Name: file.Name, Content: file.Content})
	}
	tunnelFiles, err := renderSystemGatewayTunnelCandidate(ctx, paths, credentials, state, tunnelCertificatePEM)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, err
	}
	request.Configs = append(request.Configs, tunnelFiles...)
	return request, nil
}

func renderSystemGatewayTunnelCandidate(
	ctx context.Context,
	paths store.Paths,
	secrets NodeCredentialSecretStore,
	state model.State,
	tunnelCertificatePEM []byte,
) ([]linuxplatform.RoleConfigFile, error) {
	plan, err := tunnel.PlanFromState(state)
	if err != nil {
		return nil, err
	}
	component, err := systemGatewayJoinComponent(state.Components, tunnel.FRPProviderName)
	if err != nil {
		return nil, err
	}
	provider, err := tunnel.NewFRPProvider(paths.Root, component, nil)
	if err != nil {
		return nil, err
	}
	value, err := provider.Render(ctx, tunnel.RenderRequest{Plan: plan})
	if err != nil {
		return nil, fmt.Errorf("render candidate gateway tunnel: %w", err)
	}
	frpCandidate, ok := value.(tunnel.FRPCandidate)
	if !ok || frpCandidate.Descriptor().HostRole != model.RoleGateway {
		return nil, fmt.Errorf("gateway tunnel provider returned an invalid candidate")
	}
	record, err := systemGatewayJoinTunnelCertificate(state)
	if err != nil {
		return nil, err
	}
	privateKey, err := secrets.Get(record.PrivateKeyRef)
	if err != nil {
		return nil, fmt.Errorf("read candidate tunnel private key: %w", err)
	}
	defer clear(privateKey)
	if _, err := tls.X509KeyPair(tunnelCertificatePEM, privateKey); err != nil {
		return nil, fmt.Errorf("candidate tunnel certificate and private key do not match")
	}
	return []linuxplatform.RoleConfigFile{
		{Name: tunnel.FRPServerConfigFileName, Content: frpCandidate.Bytes()},
		{Name: tunnel.FRPServerReadyFileName, Content: []byte(fmt.Sprintf(
			"schema_version=1\nstate_generation=%d\nconfig_sha256=%s\n", state.Generation, frpCandidate.Descriptor().ConfigHash,
		))},
		{Name: tunnel.FRPServerCertificateName, Content: append([]byte(nil), tunnelCertificatePEM...)},
		{Name: tunnel.FRPServerPrivateKeyName, Content: append([]byte(nil), privateKey...)},
	}, nil
}

func (readiness *SystemGatewayJoinReadiness) restartCandidateServices(ctx context.Context) error {
	for _, unit := range gatewayJoinCandidateUnits() {
		result, err := readiness.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"restart", unit}})
		if err != nil || result.ExitCode != 0 {
			return fmt.Errorf("restart gateway join candidate service %s", unit)
		}
	}
	return nil
}

func (readiness *SystemGatewayJoinReadiness) checkCandidate(
	ctx context.Context,
	candidate GatewayJoinCandidate,
) (JoinReadinessReport, error) {
	standardTransport, err := systemGatewayJoinTransport(candidate.State, candidate.Node.ID, model.TransportStandard)
	if err != nil {
		return JoinReadinessReport{}, err
	}
	observer, err := transport.NewStandardHealthObserver(readiness.runner, nil)
	if err != nil {
		return JoinReadinessReport{}, err
	}
	clientGatewayAddress, err := gatewayJoinPoolAddress(candidate.State.Host.ClientCIDR)
	if err != nil {
		return JoinReadinessReport{}, err
	}
	nodeGatewayAddress, err := gatewayJoinPoolAddress(candidate.State.Host.NodeCIDR)
	if err != nil {
		return JoinReadinessReport{}, err
	}
	standardHealth, err := observer.Observe(ctx, transport.StandardHealthExpectation{
		Identity: transport.IdentityFromTransport(standardTransport), RuntimeRole: systemGatewayJoinRuntimeRole(standardTransport.State),
		HostRole: model.RoleGateway, InterfacePublicKey: candidate.GatewayWireGuardPublicKey,
		LocalAddresses: []string{clientGatewayAddress, nodeGatewayAddress}, PeerPublicKey: standardTransport.PublicKey,
		PeerAllowedIPs: []string{candidate.Node.OverlayIPv4 + "/32"}, RequireHandshake: false,
	})
	if err != nil || standardHealth.Condition != transport.HealthHealthy {
		return JoinReadinessReport{}, errors.Join(fmt.Errorf("candidate gateway standard transport is not healthy"), err)
	}
	restrictedObserver, err := transport.NewRestrictedGatewayHealthObserver(readiness.runner)
	if err != nil {
		return JoinReadinessReport{}, err
	}
	restrictedCondition, _, err := restrictedObserver.ObserveListener(ctx)
	if err != nil || restrictedCondition != transport.HealthHealthy {
		return JoinReadinessReport{}, errors.Join(fmt.Errorf("candidate gateway restricted transport is not healthy"), err)
	}
	if err := readiness.checkTunnelListener(ctx, candidate.State.Host.NodeCIDR); err != nil {
		return JoinReadinessReport{}, err
	}
	return JoinReadinessReport{Gateway: true, Control: true, Standard: true, Restricted: true, Tunnel: true}, nil
}

func (readiness *SystemGatewayJoinReadiness) checkTunnelListener(ctx context.Context, nodeCIDR string) error {
	active, err := readiness.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"is-active", "--quiet", "vpnctl-tunnel-server.service"}})
	if err != nil || active.ExitCode != 0 {
		return errors.Join(fmt.Errorf("candidate gateway tunnel service is not active"), err)
	}
	address, err := gatewayJoinPoolHost(nodeCIDR)
	if err != nil {
		return err
	}
	result, err := readiness.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "ss", Args: []string{"-H", "-ltnp", "sport = :17000"}})
	if err != nil || result.ExitCode != 0 {
		return errors.Join(fmt.Errorf("candidate gateway tunnel listener is unavailable"), err)
	}
	line := strings.TrimSpace(string(result.Stdout))
	if strings.Count(line, "\n") != 0 || !strings.Contains(line, address+":17000") || !strings.Contains(line, `(("frps",pid=`) {
		return fmt.Errorf("candidate gateway tunnel listener does not match the managed endpoint")
	}
	return nil
}

func validateSystemGatewayJoinCandidate(candidate GatewayJoinCandidate) error {
	if err := candidate.State.Validate(); err != nil || candidate.State.Host.Role != model.RoleGateway {
		return errors.Join(fmt.Errorf("system join readiness requires valid gateway state"), err)
	}
	if candidate.Node.ID == "" || candidate.Node.Lifecycle != model.LifecycleActive || candidate.Node.CredentialGeneration == 0 ||
		len(candidate.TunnelServerCertificatePEM) == 0 || candidate.GatewayWireGuardPublicKey == "" {
		return fmt.Errorf("system gateway join candidate is incomplete")
	}
	found := false
	for _, node := range candidate.State.Nodes {
		if node.ID == candidate.Node.ID && node.Name == candidate.Node.Name && node.CredentialGeneration == candidate.Node.CredentialGeneration {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("system gateway join candidate node differs from candidate state")
	}
	ca, err := parseSingleJoinCertificate(candidate.ControlCACertificatePEM)
	if err != nil || !ca.IsCA {
		return errors.Join(fmt.Errorf("candidate control CA is invalid"), err)
	}
	leaf, err := parseSingleJoinCertificate(candidate.ControlCertificatePEM)
	if err != nil || leaf.CheckSignatureFrom(ca) != nil {
		return errors.Join(fmt.Errorf("candidate node control certificate is invalid"), err)
	}
	certificate, err := parseSingleJoinCertificate(candidate.TunnelServerCertificatePEM)
	record, recordErr := systemGatewayJoinTunnelCertificate(candidate.State)
	if err != nil || recordErr != nil || joinCertificateFingerprint(certificate) != record.Fingerprint {
		return errors.Join(fmt.Errorf("candidate tunnel certificate is invalid"), err, recordErr)
	}
	return nil
}

type gatewayJoinCredentialOverlay struct {
	base   NodeCredentialSecretStore
	values map[model.SecretRef][]byte
}

func (overlay *gatewayJoinCredentialOverlay) Get(reference model.SecretRef) ([]byte, error) {
	if value, ok := overlay.values[reference]; ok {
		return append([]byte(nil), value...), nil
	}
	return overlay.base.Get(reference)
}

func (overlay *gatewayJoinCredentialOverlay) PutIfAbsent(reference model.SecretRef, value []byte) error {
	return overlay.base.PutIfAbsent(reference, value)
}

func (overlay *gatewayJoinCredentialOverlay) Delete(reference model.SecretRef) (bool, error) {
	return overlay.base.Delete(reference)
}

func (overlay *gatewayJoinCredentialOverlay) Destroy() {
	for reference, value := range overlay.values {
		clear(value)
		delete(overlay.values, reference)
	}
}

type gatewayJoinConfigSnapshot struct {
	path    string
	content []byte
	mode    fs.FileMode
	present bool
}

type systemGatewayJoinPreparation struct {
	mu        sync.Mutex
	runtime   *SystemGatewayJoinReadiness
	snapshots []gatewayJoinConfigSnapshot
	report    JoinReadinessReport
	finished  bool
}

func (preparation *systemGatewayJoinPreparation) Report() JoinReadinessReport {
	if preparation == nil {
		return JoinReadinessReport{}
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	return preparation.report
}

func (preparation *systemGatewayJoinPreparation) Commit() {
	if preparation == nil {
		return
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	if preparation.finished {
		return
	}
	preparation.finished = true
	clearGatewayJoinSnapshots(preparation.snapshots)
	preparation.snapshots = nil
	preparation.runtime.mutationMu.Unlock()
}

func (preparation *systemGatewayJoinPreparation) Rollback(ctx context.Context) error {
	if preparation == nil || ctx == nil {
		return fmt.Errorf("gateway join readiness rollback is incomplete")
	}
	preparation.mu.Lock()
	defer preparation.mu.Unlock()
	return preparation.rollbackLocked(ctx)
}

func (preparation *systemGatewayJoinPreparation) rollbackLocked(ctx context.Context) error {
	if preparation.finished {
		return nil
	}
	preparation.finished = true
	defer preparation.runtime.mutationMu.Unlock()
	defer func() {
		clearGatewayJoinSnapshots(preparation.snapshots)
		preparation.snapshots = nil
	}()
	var result error
	for _, snapshot := range preparation.snapshots {
		if err := restoreGatewayJoinConfig(snapshot); err != nil {
			result = errors.Join(result, err)
		}
	}
	for _, unit := range gatewayJoinCandidateUnits() {
		probe, err := preparation.runtime.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"restart", unit}})
		if err != nil || probe.ExitCode != 0 {
			result = errors.Join(result, fmt.Errorf("restart restored gateway service %s", unit), err)
		}
	}
	return result
}

func snapshotGatewayJoinConfigs(paths store.Paths, configs []linuxplatform.RoleConfigFile) ([]gatewayJoinConfigSnapshot, error) {
	directory := filepath.Join(paths.ConfigDir, "generated", "gateway")
	snapshots := make([]gatewayJoinConfigSnapshot, 0, len(configs))
	seen := make(map[string]struct{}, len(configs))
	for _, config := range configs {
		if _, duplicate := seen[config.Name]; duplicate {
			clearGatewayJoinSnapshots(snapshots)
			return nil, fmt.Errorf("duplicate gateway join config %s", config.Name)
		}
		seen[config.Name] = struct{}{}
		path := filepath.Join(directory, config.Name)
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			snapshots = append(snapshots, gatewayJoinConfigSnapshot{path: path})
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumGatewayJoinSnapshotBytes {
			clearGatewayJoinSnapshots(snapshots)
			return nil, errors.Join(fmt.Errorf("gateway join config %s is unsafe", path), err)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			clearGatewayJoinSnapshots(snapshots)
			return nil, err
		}
		snapshots = append(snapshots, gatewayJoinConfigSnapshot{path: path, content: content, mode: info.Mode().Perm(), present: true})
	}
	return snapshots, nil
}

func restoreGatewayJoinConfig(snapshot gatewayJoinConfigSnapshot) error {
	if snapshot.present {
		return writeGatewayJoinConfig(snapshot.path, snapshot.content, snapshot.mode)
	}
	if err := os.Remove(snapshot.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove uncommitted gateway join config %s: %w", snapshot.path, err)
	}
	return syncGatewayJoinDirectory(filepath.Dir(snapshot.path))
}

func writeGatewayJoinConfig(path string, content []byte, mode fs.FileMode) error {
	if len(content) == 0 || mode&0o077 != 0 {
		return fmt.Errorf("restored gateway join config is unsafe")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".vpnctl-join-rollback-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	keep = true
	return syncGatewayJoinDirectory(filepath.Dir(path))
}

func syncGatewayJoinDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func clearGatewayJoinSnapshots(snapshots []gatewayJoinConfigSnapshot) {
	for index := range snapshots {
		clear(snapshots[index].content)
		snapshots[index].content = nil
	}
}

func clearGatewayJoinRoleRequest(request *linuxplatform.RoleInstallationRequest) {
	if request == nil {
		return
	}
	for index := range request.Configs {
		clear(request.Configs[index].Content)
		request.Configs[index].Content = nil
	}
}

func gatewayJoinCandidateUnits() []string {
	return []string{"vpnctl-standard.service", "vpnctl-restricted.service", "vpnctl-tunnel-server.service"}
}

func systemGatewayJoinComponent(manifest model.ComponentManifest, name string) (model.ComponentPin, error) {
	var found *model.ComponentPin
	for index := range manifest.Components {
		if manifest.Components[index].Name != name {
			continue
		}
		if found != nil {
			return model.ComponentPin{}, fmt.Errorf("gateway manifest contains duplicate %s component", name)
		}
		value := manifest.Components[index]
		found = &value
	}
	if found == nil {
		return model.ComponentPin{}, fmt.Errorf("gateway manifest has no %s component", name)
	}
	return *found, nil
}

func systemGatewayJoinTunnelCertificate(state model.State) (model.Certificate, error) {
	var found *model.Certificate
	for index := range state.Certificates {
		if state.Certificates[index].Kind != model.CertificateTunnelServer {
			continue
		}
		if found != nil {
			return model.Certificate{}, fmt.Errorf("gateway state contains multiple tunnel certificates")
		}
		value := state.Certificates[index]
		found = &value
	}
	if found == nil {
		return model.Certificate{}, fmt.Errorf("gateway join candidate has no tunnel certificate")
	}
	return *found, nil
}

func systemGatewayJoinTransport(state model.State, nodeID string, kind model.TransportKind) (model.Transport, error) {
	var found *model.Transport
	for index := range state.Transports {
		value := state.Transports[index]
		if value.OwnerKind != model.TargetNode || value.OwnerID != nodeID || value.Kind != kind {
			continue
		}
		if found != nil {
			return model.Transport{}, fmt.Errorf("gateway join candidate contains duplicate %s transport", kind)
		}
		found = &value
	}
	if found == nil {
		return model.Transport{}, fmt.Errorf("gateway join candidate has no %s transport", kind)
	}
	return *found, nil
}

func systemGatewayJoinRuntimeRole(state model.TransportState) transport.RuntimeRole {
	if state == model.TransportActive {
		return transport.RuntimeActive
	}
	return transport.RuntimeStandby
}

func gatewayJoinPoolAddress(cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix {
		return "", fmt.Errorf("gateway join pool must be a canonical IPv4 prefix")
	}
	return fmt.Sprintf("%s/%d", prefix.Addr().Next(), prefix.Bits()), nil
}

func gatewayJoinPoolHost(cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix {
		return "", fmt.Errorf("gateway join pool must be a canonical IPv4 prefix")
	}
	return prefix.Addr().Next().String(), nil
}

var _ GatewayJoinReadinessChecker = (*SystemGatewayJoinReadiness)(nil)
var _ GatewayJoinReadinessPreparer = (*SystemGatewayJoinReadiness)(nil)
var _ GatewayJoinReadinessPreparation = (*systemGatewayJoinPreparation)(nil)
