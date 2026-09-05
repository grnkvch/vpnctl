package enrollment

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

var ErrNodeActivationPending = errors.New("joined node service activation is pending")

var nodeActivationOrder = []string{
	"vpnctl-standard.service",
	"vpnctl-routing-guard.service",
	"vpnctl-routing.service",
	"vpnctl-tunnel-client.service",
}

type NodeConfigurationRoleInstaller interface {
	Apply(context.Context, linuxplatform.RoleInstallationRequest) (linuxplatform.RoleInstallationResult, error)
}

type NodeConfigurationReadinessChecker interface {
	Check(context.Context, NodeConfiguration) error
}

// NodeConfigurationActivator publishes one complete generated generation,
// enables every staged node unit, and starts them in dependency order. On a
// later failure it deliberately leaves an already installed routing guard in
// place; ordinary compensation must never reopen selected traffic to direct.
type NodeConfigurationActivator struct {
	binaryPath string
	roles      NodeConfigurationRoleInstaller
	runner     linuxplatform.ProbeRunner
	readiness  NodeConfigurationReadinessChecker
}

func NewNodeConfigurationActivator(
	binaryPath string,
	roles NodeConfigurationRoleInstaller,
	runner linuxplatform.ProbeRunner,
	readiness NodeConfigurationReadinessChecker,
) (*NodeConfigurationActivator, error) {
	if binaryPath == "" || roles == nil || runner == nil || readiness == nil {
		return nil, fmt.Errorf("node configuration activation dependencies are incomplete")
	}
	if _, err := linuxplatform.RenderNodeRoleInstallation(binaryPath); err != nil {
		return nil, err
	}
	return &NodeConfigurationActivator{binaryPath: binaryPath, roles: roles, runner: runner, readiness: readiness}, nil
}

func (activator *NodeConfigurationActivator) Activate(ctx context.Context, configuration NodeConfiguration) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if activator == nil || activator.roles == nil || activator.runner == nil || activator.readiness == nil {
		return fmt.Errorf("node configuration activator is incomplete")
	}
	if err := validateNodeConfigurationForActivation(configuration); err != nil {
		return err
	}
	request, err := linuxplatform.RenderNodeRoleInstallation(activator.binaryPath)
	if err != nil {
		return err
	}
	for index := range request.Units {
		request.Units[index].Enable = true
		request.Units[index].Start = false
	}
	request.Configs = append(request.Configs, configuration.ConfigFiles()...)
	if _, err := activator.roles.Apply(ctx, request); err != nil {
		return fmt.Errorf("publish joined node service generation: %w", err)
	}
	for _, unit := range nodeActivationOrder {
		if err := activator.systemctl(ctx, "start", unit); err != nil {
			return errors.Join(ErrNodeActivationPending, err)
		}
		if err := activator.systemctl(ctx, "is-active", "--quiet", unit); err != nil {
			return errors.Join(ErrNodeActivationPending, err)
		}
	}
	if err := activator.readiness.Check(ctx, configuration); err != nil {
		return errors.Join(ErrNodeActivationPending, fmt.Errorf("verify joined node service generation: %w", err))
	}
	return nil
}

func (activator *NodeConfigurationActivator) systemctl(ctx context.Context, arguments ...string) error {
	result, err := activator.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "systemctl", Args: arguments})
	if err != nil {
		return fmt.Errorf("systemctl %s: %w", strings.Join(arguments, " "), err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("systemctl %s failed", strings.Join(arguments, " "))
	}
	return nil
}

func validateNodeConfigurationForActivation(configuration NodeConfiguration) error {
	if configuration.stateGeneration == 0 {
		return fmt.Errorf("node service configuration has no state generation")
	}
	if err := configuration.standard.Descriptor().Validate(); err != nil {
		return fmt.Errorf("validate node standard activation candidate: %w", err)
	}
	if err := configuration.routing.Descriptor().Validate(); err != nil {
		return fmt.Errorf("validate node routing activation candidate: %w", err)
	}
	if err := configuration.tunnel.Descriptor().Validate(); err != nil {
		return fmt.Errorf("validate node tunnel activation candidate: %w", err)
	}
	if configuration.standard.Descriptor().OwnerKind != model.TargetNode ||
		configuration.routing.Descriptor().ActiveTransport == "" ||
		configuration.tunnel.Descriptor().HostRole != model.RoleNode ||
		configuration.tunnel.Descriptor().Generation != configuration.stateGeneration ||
		configuration.standard.Descriptor().OwnerID != configuration.tunnel.Descriptor().NodeID ||
		configuration.standard.Descriptor().CredentialGeneration != configuration.routing.Descriptor().CredentialGeneration ||
		configuration.standard.Descriptor().CredentialGeneration != configuration.tunnel.Descriptor().CredentialGeneration ||
		configuration.routing.Descriptor().ActiveTransport != configuration.tunnel.Descriptor().ActiveTransport {
		return fmt.Errorf("node service candidates do not share one joined generation")
	}
	wantNames := []string{
		nodeRoutingGuardReadyFileName, nodeRoutingReadyFileName, nodeStandardReadyFileName,
		routing.NodeDNSIntegrationConfigName, routing.NodeRoutingConfigFileName, routing.NodeRoutingGuardConfigFileName,
		transport.StandardConfigFileName, tunnel.FRPClientConfigFileName, tunnel.FRPClientReadyFileName, tunnel.FRPServerCertificateName,
	}
	gotNames := make([]string, 0, len(configuration.configs))
	seen := make(map[string]struct{}, len(configuration.configs))
	for _, config := range configuration.configs {
		if config.Name == "" || len(config.Content) == 0 {
			return fmt.Errorf("node service configuration contains an empty artifact")
		}
		if _, duplicate := seen[config.Name]; duplicate {
			return fmt.Errorf("node service configuration duplicates artifact %s", config.Name)
		}
		seen[config.Name] = struct{}{}
		gotNames = append(gotNames, config.Name)
	}
	sort.Strings(wantNames)
	sort.Strings(gotNames)
	if !reflect.DeepEqual(gotNames, wantNames) {
		return fmt.Errorf("node service configuration artifact set is incomplete")
	}
	return nil
}
