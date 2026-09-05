package enrollment

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

// SystemGatewayRepairCandidate retains rendered secrets only in memory. Its
// public accessors return defensive copies and it deliberately has no exported
// data fields, so it cannot be serialized into a CLI result or state file.
type SystemGatewayRepairCandidate struct {
	generation          uint64
	request             linuxplatform.RoleInstallationRequest
	tunnelActive        bool
	gatewayWireGuardKey string
	state               model.State
}

type SystemGatewayRepairRuntime struct {
	paths      store.Paths
	secrets    NodeCredentialSecretStore
	roles      *linuxplatform.RoleSystemdInstaller
	runner     linuxplatform.ProbeRunner
	keyRunner  wireguard.Runner
	binaryPath string
}

func NewSystemGatewayRepairRuntime(
	paths store.Paths,
	secrets NodeCredentialSecretStore,
) (*SystemGatewayRepairRuntime, error) {
	return newSystemGatewayRepairRuntime(paths, secrets, linuxplatform.OSProbeRunner{}, wireguard.ExecRunner{}, linuxplatform.DefaultVPNCTLBinaryPath)
}

func newSystemGatewayRepairRuntime(
	paths store.Paths,
	secrets NodeCredentialSecretStore,
	runner linuxplatform.ProbeRunner,
	keyRunner wireguard.Runner,
	binaryPath string,
) (*SystemGatewayRepairRuntime, error) {
	if secrets == nil || runner == nil || keyRunner == nil {
		return nil, fmt.Errorf("system gateway repair dependencies are incomplete")
	}
	roles, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, runner)
	if err != nil {
		return nil, err
	}
	if _, err := linuxplatform.RenderGatewayRoleInstallation(binaryPath); err != nil {
		return nil, err
	}
	return &SystemGatewayRepairRuntime{paths: paths, secrets: secrets, roles: roles, runner: runner, keyRunner: keyRunner, binaryPath: binaryPath}, nil
}

func (runtime *SystemGatewayRepairRuntime) Compile(ctx context.Context, state model.State) (*SystemGatewayRepairCandidate, error) {
	if ctx == nil || runtime == nil || runtime.secrets == nil || runtime.roles == nil || runtime.runner == nil || runtime.keyRunner == nil {
		return nil, fmt.Errorf("system gateway repair runtime is incomplete")
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway || state.DNS == nil {
		return nil, errors.Join(fmt.Errorf("gateway repair requires valid gateway state with DNS"), err)
	}
	standardPrivate, err := runtime.secrets.Get(transport.GatewayStandardCredentialRef)
	if err != nil {
		return nil, fmt.Errorf("read gateway standard repair credential: %w", err)
	}
	defer clear(standardPrivate)
	standardKey, err := wireguard.PublicKey(ctx, runtime.keyRunner, strings.TrimSpace(string(standardPrivate)))
	if err != nil {
		return nil, fmt.Errorf("derive gateway standard repair identity: %w", err)
	}
	restrictedSecret, err := runtime.secrets.Get(transport.GatewayRestrictedCredentialRef)
	if err != nil {
		return nil, fmt.Errorf("read gateway restricted repair credential: %w", err)
	}
	clear(restrictedSecret)

	readOnly := gatewayRepairReadOnlySecrets{base: runtime.secrets}
	request, tunnelActive, err := runtime.render(ctx, state, readOnly)
	if err != nil {
		return nil, err
	}
	return &SystemGatewayRepairCandidate{
		generation: state.Generation, request: request, tunnelActive: tunnelActive,
		gatewayWireGuardKey: standardKey, state: state,
	}, nil
}

func (runtime *SystemGatewayRepairRuntime) render(
	ctx context.Context,
	state model.State,
	secrets NodeCredentialSecretStore,
) (linuxplatform.RoleInstallationRequest, bool, error) {
	certificate, certificateErr := systemGatewayJoinTunnelCertificate(state)
	tunnelActive := certificateErr == nil
	if !tunnelActive && len(state.Nodes) != 0 {
		return linuxplatform.RoleInstallationRequest{}, false, fmt.Errorf("gateway with node records has no tunnel certificate")
	}
	if tunnelActive {
		certificatePEM, err := secrets.Get(model.SecretRef(certificate.CertificateRef))
		if err != nil {
			return linuxplatform.RoleInstallationRequest{}, false, fmt.Errorf("read gateway repair tunnel certificate: %w", err)
		}
		defer clear(certificatePEM)
		request, err := renderSystemGatewayCandidate(ctx, runtime.paths, secrets, runtime.keyRunner, runtime.binaryPath, state, certificatePEM)
		return request, true, err
	}

	request, err := linuxplatform.RenderGatewayRoleInstallation(runtime.binaryPath)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, false, err
	}
	listeners, err := transport.NewGatewayListenerProvisioner(secrets, runtime.keyRunner, nil)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, false, err
	}
	installation, err := listeners.Provision(ctx, state)
	if err != nil {
		return linuxplatform.RoleInstallationRequest{}, false, fmt.Errorf("render gateway repair listeners: %w", err)
	}
	for _, file := range installation.ConfigFiles() {
		request.Configs = append(request.Configs, linuxplatform.RoleConfigFile{Name: file.Name, Content: file.Content})
	}
	dns, err := routing.RenderGatewayDNSConfig(state)
	if err != nil {
		clearGatewayJoinRoleRequest(&request)
		return linuxplatform.RoleInstallationRequest{}, false, err
	}
	request.Configs = append(request.Configs,
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSConfigFileName, Content: dns.Bytes()},
		linuxplatform.RoleConfigFile{Name: routing.GatewayDNSReadyFileName, Content: []byte("schema_version=1\n")},
	)
	return request, false, nil
}

func (candidate *SystemGatewayRepairCandidate) Generation() uint64 {
	if candidate == nil {
		return 0
	}
	return candidate.generation
}

func (candidate *SystemGatewayRepairCandidate) TunnelActive() bool {
	return candidate != nil && candidate.tunnelActive
}

func (candidate *SystemGatewayRepairCandidate) RoleRequest() linuxplatform.RoleInstallationRequest {
	if candidate == nil {
		return linuxplatform.RoleInstallationRequest{}
	}
	return cloneGatewayRepairRoleRequest(candidate.request)
}

func (candidate *SystemGatewayRepairCandidate) Destroy() {
	if candidate == nil {
		return
	}
	clearGatewayJoinRoleRequest(&candidate.request)
	candidate.request = linuxplatform.RoleInstallationRequest{}
	candidate.gatewayWireGuardKey = ""
	candidate.state = model.State{}
}

// Apply repairs role-owned unit/config files and data-plane processes only
// from the already committed authoritative generation. A later failure keeps
// successfully restored desired artifacts as safe, retryable forward progress;
// it never restores known drift. Network/watchdog and convergence publication
// remain caller-owned so their ordering is explicit.
func (runtime *SystemGatewayRepairRuntime) Apply(ctx context.Context, candidate *SystemGatewayRepairCandidate) error {
	if ctx == nil || runtime == nil || runtime.roles == nil || runtime.runner == nil || candidate == nil || candidate.generation == 0 {
		return fmt.Errorf("system gateway repair apply is incomplete")
	}
	request := candidate.RoleRequest()
	defer clearGatewayJoinRoleRequest(&request)
	if !candidate.tunnelActive {
		removed := false
		for _, name := range []string{tunnel.FRPServerConfigFileName, tunnel.FRPServerReadyFileName, tunnel.FRPServerCertificateName, tunnel.FRPServerPrivateKeyName} {
			if err := os.Remove(gatewayJoinConfigPath(runtime.paths, name)); err == nil {
				removed = true
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove inactive gateway tunnel artifact %s: %w", name, err)
			}
		}
		if removed {
			if err := syncGatewayJoinDirectory(filepath.Join(runtime.paths.ConfigDir, "generated", "gateway")); err != nil {
				return fmt.Errorf("sync inactive gateway tunnel artifact removal: %w", err)
			}
		}
	}
	if _, err := runtime.roles.Apply(ctx, request); err != nil {
		return fmt.Errorf("publish committed gateway repair candidate: %w", err)
	}
	if !candidate.tunnelActive {
		if err := syncGatewayJoinDirectory(filepath.Join(runtime.paths.ConfigDir, "generated", "gateway")); err != nil {
			return fmt.Errorf("sync inactive gateway tunnel artifact removal: %w", err)
		}
	}
	for _, unit := range gatewayRepairDataPlaneUnits() {
		action := "restart"
		if unit == "vpnctl-tunnel-server.service" && !candidate.tunnelActive {
			action = "stop"
		}
		probe, err := runtime.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{action, unit}})
		if err != nil || probe.ExitCode != 0 {
			return errors.Join(fmt.Errorf("%s gateway service %s", action, unit), err)
		}
	}
	if err := runtime.verify(ctx, candidate); err != nil {
		return err
	}
	return nil
}

func (runtime *SystemGatewayRepairRuntime) verify(ctx context.Context, candidate *SystemGatewayRepairCandidate) error {
	for _, unit := range []string{"vpnctl-controller.service", "vpnctl-standard.service", "vpnctl-restricted.service", "vpnctl-dns.service"} {
		probe, err := runtime.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"is-active", "--quiet", unit}})
		if err != nil || probe.ExitCode != 0 {
			return errors.Join(fmt.Errorf("repaired gateway service %s is not active", unit), err)
		}
	}
	if err := runtime.verifyStandard(ctx, candidate); err != nil {
		return err
	}
	if !candidate.tunnelActive {
		probe, err := runtime.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"is-active", "--quiet", "vpnctl-tunnel-server.service"}})
		if err != nil {
			return fmt.Errorf("inspect inactive gateway tunnel service: %w", err)
		}
		if err == nil && probe.ExitCode == 0 {
			return fmt.Errorf("inactive gateway tunnel service remained active")
		}
	} else {
		readiness := &SystemGatewayJoinReadiness{runner: runtime.runner}
		if err := readiness.checkTunnelListener(ctx, candidate.state.Host.NodeCIDR); err != nil {
			return err
		}
	}
	restrictedObserver, _ := transport.NewRestrictedGatewayHealthObserver(runtime.runner)
	condition, _, err := restrictedObserver.ObserveListener(ctx)
	if err != nil || condition != transport.HealthHealthy {
		return errors.Join(fmt.Errorf("repaired gateway restricted listener is not healthy"), err)
	}
	return nil
}

func (runtime *SystemGatewayRepairRuntime) verifyStandard(ctx context.Context, candidate *SystemGatewayRepairCandidate) error {
	query := func(name string, arguments ...string) (string, error) {
		result, err := runtime.runner.Run(ctx, linuxplatform.ProbeCommand{Name: name, Args: arguments})
		if err != nil || result.ExitCode != 0 {
			return "", errors.Join(fmt.Errorf("inspect repaired gateway standard runtime"), err)
		}
		return string(result.Stdout), nil
	}
	publicKey, err := query("wg", "show", transport.StandardInterfaceName, "public-key")
	if err != nil || strings.TrimSpace(publicKey) != candidate.gatewayWireGuardKey {
		return errors.Join(fmt.Errorf("repaired gateway standard public key does not match committed identity"), err)
	}
	listenPort, err := query("wg", "show", transport.StandardInterfaceName, "listen-port")
	if err != nil || strings.TrimSpace(listenPort) != fmt.Sprint(transport.StandardUDPPort) {
		return errors.Join(fmt.Errorf("repaired gateway standard listen port is not ready"), err)
	}
	addresses, err := query("ip", "-4", "-o", "address", "show", "dev", transport.StandardInterfaceName)
	if err != nil {
		return err
	}
	wantAddresses := make([]string, 0, 2)
	for _, cidr := range []string{candidate.state.Host.ClientCIDR, candidate.state.Host.NodeCIDR} {
		address, err := gatewayJoinPoolAddress(cidr)
		if err != nil {
			return err
		}
		wantAddresses = append(wantAddresses, address)
	}
	if got := gatewayRepairInterfaceAddresses(addresses); !equalGatewayRepairStrings(got, wantAddresses) {
		return fmt.Errorf("repaired gateway standard overlay addresses do not match committed pools")
	}
	allowed, err := query("wg", "show", transport.StandardInterfaceName, "allowed-ips")
	if err != nil {
		return err
	}
	gotPeers, err := gatewayRepairRuntimePeers(allowed)
	if err != nil {
		return err
	}
	wantPeers, err := gatewayRepairStatePeers(candidate.state)
	if err != nil {
		return err
	}
	if len(gotPeers) != len(wantPeers) {
		return fmt.Errorf("repaired gateway standard peer set does not match committed identities")
	}
	for publicKey, allowedIP := range wantPeers {
		if gotPeers[publicKey] != allowedIP {
			return fmt.Errorf("repaired gateway standard peer set does not match committed identities")
		}
	}
	return nil
}

func gatewayRepairInterfaceAddresses(output string) []string {
	result := make([]string, 0, 2)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for index, field := range fields {
			if field != "inet" || index+1 >= len(fields) {
				continue
			}
			prefix, err := netip.ParsePrefix(fields[index+1])
			if err == nil && prefix.Addr().Is4() {
				result = append(result, prefix.String())
			}
			break
		}
	}
	sort.Strings(result)
	return result
}

func gatewayRepairRuntimePeers(output string) (map[string]string, error) {
	result := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 || wireguard.ValidateKey(fields[0]) != nil {
			return nil, fmt.Errorf("repaired gateway standard peer output is invalid")
		}
		prefix, err := netip.ParsePrefix(fields[1])
		if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 || prefix.String() != fields[1] {
			return nil, fmt.Errorf("repaired gateway standard peer allowed IP is invalid")
		}
		if _, duplicate := result[fields[0]]; duplicate {
			return nil, fmt.Errorf("repaired gateway standard peer output contains a duplicate")
		}
		result[fields[0]] = fields[1]
	}
	return result, nil
}

func gatewayRepairStatePeers(state model.State) (map[string]string, error) {
	active := make(map[string]string, len(state.Clients)+len(state.Nodes))
	for _, client := range state.Clients {
		if client.Lifecycle == model.LifecycleActive {
			active[string(model.TargetClient)+":"+client.ID] = client.OverlayIPv4
		}
	}
	for _, node := range state.Nodes {
		if node.Lifecycle == model.LifecycleActive {
			active[string(model.TargetNode)+":"+node.ID] = node.OverlayIPv4
		}
	}
	result := make(map[string]string, len(active))
	for _, transportState := range state.Transports {
		if transportState.Kind != model.TransportStandard || transportState.State == model.TransportDisabled {
			continue
		}
		address, ok := active[string(transportState.OwnerKind)+":"+transportState.OwnerID]
		if !ok {
			continue
		}
		if _, duplicate := result[transportState.PublicKey]; duplicate {
			return nil, fmt.Errorf("committed gateway standard peer key is duplicated")
		}
		result[transportState.PublicKey] = address + "/32"
	}
	if len(result) != len(active) {
		return nil, fmt.Errorf("committed active identity has no standard transport")
	}
	return result, nil
}

func equalGatewayRepairStrings(left, right []string) bool {
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func gatewayRepairDataPlaneUnits() []string {
	return []string{"vpnctl-standard.service", "vpnctl-restricted.service", "vpnctl-dns.service", "vpnctl-tunnel-server.service"}
}

func gatewayJoinConfigPath(paths store.Paths, name string) string {
	return filepath.Join(paths.ConfigDir, "generated", "gateway", name)
}

func cloneGatewayRepairRoleRequest(request linuxplatform.RoleInstallationRequest) linuxplatform.RoleInstallationRequest {
	result := request
	result.Units = append([]linuxplatform.RoleUnitFile(nil), request.Units...)
	for index := range result.Units {
		result.Units[index].Content = append([]byte(nil), request.Units[index].Content...)
	}
	result.Configs = append([]linuxplatform.RoleConfigFile(nil), request.Configs...)
	for index := range result.Configs {
		result.Configs[index].Content = append([]byte(nil), request.Configs[index].Content...)
	}
	return result
}

type gatewayRepairReadOnlySecrets struct{ base NodeCredentialSecretStore }

func (store gatewayRepairReadOnlySecrets) Get(reference model.SecretRef) ([]byte, error) {
	return store.base.Get(reference)
}

func (gatewayRepairReadOnlySecrets) PutIfAbsent(model.SecretRef, []byte) error {
	return fmt.Errorf("gateway repair cannot create a missing credential")
}

func (gatewayRepairReadOnlySecrets) Delete(model.SecretRef) (bool, error) {
	return false, fmt.Errorf("gateway repair cannot delete credentials")
}
