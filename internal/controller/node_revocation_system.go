package controller

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

type systemGatewayNodeRevocationRuntime struct {
	paths     store.Paths
	runner    linuxplatform.ProbeRunner
	roles     *linuxplatform.RoleSystemdInstaller
	listeners *transport.GatewayListenerProvisioner
	ingress   *ingress.NginxActivationManager
}

func newSystemGatewayNodeLifecycleManager(paths store.Paths, state *store.StateStore, secrets *store.SecretStore) (*enrollment.NodeLifecycleManager, error) {
	if state == nil || secrets == nil {
		return nil, fmt.Errorf("system gateway node lifecycle stores are required")
	}
	runner := linuxplatform.OSProbeRunner{}
	roles, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, runner)
	if err != nil {
		return nil, err
	}
	listeners, err := transport.NewGatewayListenerProvisioner(secrets, wireguard.ExecRunner{}, nil)
	if err != nil {
		return nil, err
	}
	nginx, err := ingress.NewNginxActivationManager(paths, runner, ingress.OSNginxReloadRunner{})
	if err != nil {
		return nil, err
	}
	runtime := &systemGatewayNodeRevocationRuntime{paths: paths, runner: runner, roles: roles, listeners: listeners, ingress: nginx}
	return enrollment.NewNodeLifecycleManager(state, secrets, runtime, nil)
}

// NewSystemGatewayNodeLifecycleManager composes the production gateway
// adapters used by the public node revoke/delete commands.
func NewSystemGatewayNodeLifecycleManager(paths store.Paths, state *store.StateStore, secrets *store.SecretStore) (*enrollment.NodeLifecycleManager, error) {
	return newSystemGatewayNodeLifecycleManager(paths, state, secrets)
}

// Revoke runs only after NodeLifecycleManager has committed the fail-closed
// authoritative candidate. It then republishes both transport peer sets,
// withdraws disabled expose routes, and restarts the long-lived transport and
// tunnel processes so already-established node sessions are closed.
func (runtime *systemGatewayNodeRevocationRuntime) Revoke(ctx context.Context, candidate model.State, nodeID string) (enrollment.NodeRevocationReport, error) {
	if ctx == nil || runtime == nil || runtime.runner == nil || runtime.roles == nil || runtime.listeners == nil || runtime.ingress == nil {
		return enrollment.NodeRevocationReport{}, fmt.Errorf("system node revocation runtime is incomplete")
	}
	if err := candidate.Validate(); err != nil || candidate.Host.Role != model.RoleGateway {
		return enrollment.NodeRevocationReport{}, fmt.Errorf("system node revocation requires valid gateway state")
	}
	revoked := false
	for _, node := range candidate.Nodes {
		if node.ID == nodeID {
			revoked = node.Lifecycle == model.LifecycleRevoked
			break
		}
	}
	if !revoked {
		return enrollment.NodeRevocationReport{}, fmt.Errorf("authoritative node revocation is not committed")
	}

	listenerFiles, err := runtime.listeners.Provision(ctx, candidate)
	if err != nil {
		return enrollment.NodeRevocationReport{}, err
	}
	roleRequest, err := linuxplatform.RenderGatewayRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	if err != nil {
		return enrollment.NodeRevocationReport{}, err
	}
	for _, file := range listenerFiles.ConfigFiles() {
		roleRequest.Configs = append(roleRequest.Configs, linuxplatform.RoleConfigFile{Name: file.Name, Content: file.Content})
	}
	if _, err := runtime.roles.Apply(ctx, roleRequest); err != nil {
		return enrollment.NodeRevocationReport{}, err
	}

	certificate, err := soleGatewayPublicCertificate(candidate)
	if err != nil {
		return enrollment.NodeRevocationReport{}, err
	}
	nginxCandidate, err := ingress.RenderNginxConfig(ingress.NginxRenderRequest{
		StateGeneration: candidate.Generation, PublicIPv4: candidate.Host.PublicIPv4,
		CertificatePath:  systemSecretPath(runtime.paths, model.SecretRef(certificate.CertificateRef)),
		PrivateKeyPath:   systemSecretPath(runtime.paths, certificate.PrivateKeyRef),
		RuntimeDirectory: ingress.NginxRuntimeDirectory(runtime.paths), Limits: ingress.DefaultGatewayHardLimits(),
		Exposes: append([]model.Expose(nil), candidate.Exposes...),
	})
	if err != nil {
		return enrollment.NodeRevocationReport{}, err
	}
	if _, err := runtime.ingress.Apply(ctx, nginxCandidate); err != nil {
		return enrollment.NodeRevocationReport{}, err
	}
	for _, unit := range []string{"vpnctl-standard.service", "vpnctl-restricted.service", "vpnctl-tunnel-server.service"} {
		result, err := runtime.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: []string{"restart", unit}})
		if err != nil || result.ExitCode != 0 {
			return enrollment.NodeRevocationReport{}, fmt.Errorf("restart revoked node boundary %s", unit)
		}
	}
	return enrollment.NodeRevocationReport{
		ControlClosed: true, StandardClosed: true, RestrictedClosed: true, TunnelClosed: true, ExposesDisabled: true,
	}, nil
}

func (*systemGatewayNodeRevocationRuntime) Delete(context.Context, model.State, string) error {
	// Delete is permitted only after revoke has already removed every runtime
	// reference. The authoritative record and retained metadata are the only
	// remaining resources.
	return nil
}

func soleGatewayPublicCertificate(state model.State) (model.Certificate, error) {
	var result model.Certificate
	found := false
	for _, candidate := range state.Certificates {
		if candidate.Kind != model.CertificatePublicIngress {
			continue
		}
		if found {
			return model.Certificate{}, fmt.Errorf("gateway has multiple public ingress certificates")
		}
		result, found = candidate, true
	}
	if !found {
		return model.Certificate{}, ingress.ErrPublicCertificateNotFound
	}
	return result, nil
}

func systemSecretPath(paths store.Paths, reference model.SecretRef) string {
	kind, id, err := reference.Parts()
	if err != nil || strings.ContainsAny(kind+id, `/\\`) {
		return ""
	}
	return filepath.Join(paths.SecretsDir, kind, id)
}

var _ enrollment.NodeGatewayLifecycleRuntime = (*systemGatewayNodeRevocationRuntime)(nil)
