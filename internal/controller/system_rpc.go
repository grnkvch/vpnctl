package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

// RunSystemController serves the root-only local controller socket and the
// internal-overlay mTLS endpoint as one management process. Both listeners
// share authoritative state, while all data-plane services remain independent
// systemd units and are never started or stopped here.
func RunSystemController(ctx context.Context, paths store.Paths) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return fmt.Errorf("create controller state store: %w", err)
	}
	controller, err := newSystemController(paths, stateStore)
	if err != nil {
		return err
	}
	rpcServer, err := newSystemControlRPC(ctx, controller, stateStore, paths)
	if err != nil {
		return err
	}
	publicEnrollment, err := newSystemPublicEnrollmentServer(controller, stateStore, paths)
	if err != nil {
		return err
	}
	return runSystemManagement(ctx, controller.Serve, rpcServer.ListenAndServe, publicEnrollment.ListenAndServe)
}

func newSystemPublicEnrollmentServer(
	controller *Controller,
	stateStore *store.StateStore,
	paths store.Paths,
) (*enrollment.PublicEnrollmentServer, error) {
	if controller == nil || stateStore == nil {
		return nil, fmt.Errorf("system public enrollment dependencies are incomplete")
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, fmt.Errorf("create public enrollment secret store: %w", err)
	}
	return enrollment.NewSystemPublicEnrollmentServer(paths, stateStore, secrets, &controller.mutationMu)
}

func newSystemControlRPC(ctx context.Context, controller *Controller, stateStore *store.StateStore, paths store.Paths) (*control.RPCServer, error) {
	if ctx == nil || controller == nil || stateStore == nil {
		return nil, fmt.Errorf("system control RPC dependencies are incomplete")
	}
	state, err := stateStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load authoritative gateway state for control RPC: %w", err)
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway {
		return nil, fmt.Errorf("control RPC requires valid gateway state")
	}

	ca, serverLeaf, err := systemControlIdentity(state)
	if err != nil {
		return nil, err
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, fmt.Errorf("create controller secret store: %w", err)
	}
	caPEM, err := secrets.Get(model.SecretRef(ca.CertificateRef))
	if err != nil {
		return nil, fmt.Errorf("load control CA certificate: %w", err)
	}
	defer clearSystemControlSecret(caPEM)
	serverPEM, err := secrets.Get(model.SecretRef(serverLeaf.CertificateRef))
	if err != nil {
		return nil, fmt.Errorf("load gateway control certificate: %w", err)
	}
	defer clearSystemControlSecret(serverPEM)
	serverKeyPEM, err := secrets.Get(serverLeaf.PrivateKeyRef)
	if err != nil {
		return nil, fmt.Errorf("load gateway control private key: %w", err)
	}
	defer clearSystemControlSecret(serverKeyPEM)

	preflight, err := lifecycle.NewGatewayNodeUpdatePreflightHandler(stateStore)
	if err != nil {
		return nil, err
	}
	lifecycleManager, err := newSystemGatewayNodeLifecycleManager(paths, stateStore, secrets)
	if err != nil {
		return nil, err
	}
	uninstall, err := NewGatewayNodeUninstallHandler(controller, lifecycleManager)
	if err != nil {
		return nil, err
	}
	exporter, err := operations.NewPublicCertificateExportEnsurer(secrets)
	if err != nil {
		return nil, err
	}
	runner := linuxplatform.OSProbeRunner{}
	ports, err := operations.NewSystemGatewayExposeUnavailablePorts(runner)
	if err != nil {
		return nil, err
	}
	publisher, err := operations.NewSystemGatewayExposeIngressPublisher(paths, runner)
	if err != nil {
		return nil, err
	}
	deferred, err := operations.NewGatewayExposeStateDeferredWriter(stateStore, nil, nil)
	if err != nil {
		return nil, err
	}
	exposeService, err := operations.NewGatewayExposeCoordinatorService(
		stateStore, exporter, ports, publisher, deferred, ingress.NewExposeNormalizer(ingress.ExposeNormalizerRuntime{}),
		ingress.DefaultPublicCertificateExportPath(paths.ExportsDir),
	)
	if err != nil {
		return nil, err
	}
	expose, err := operations.NewExposeGatewayRPCHandler(&controller.mutationMu, exposeService)
	if err != nil {
		return nil, err
	}
	policyManager, err := routing.NewPolicyManager(paths, stateStore)
	if err != nil {
		return nil, err
	}
	policy, err := operations.NewPolicyGatewayRPCHandler(&controller.mutationMu, policyManager, stateStore)
	if err != nil {
		return nil, err
	}
	handler := systemRPCMux{update: preflight, uninstall: uninstall, expose: expose, policy: policy}
	handlers := make(map[int]control.RPCHandler, len(state.Components.ControlProtocols))
	for _, rawVersion := range state.Components.ControlProtocols {
		version, parseErr := control.ParseRPCProtocolVersion(rawVersion)
		if parseErr != nil {
			return nil, fmt.Errorf("parse installed control protocol: %w", parseErr)
		}
		handlers[version.Major] = handler
	}
	protocols, err := control.NewRPCProtocolRegistryFromVersions(state.Components.ControlProtocols, handlers)
	if err != nil {
		return nil, fmt.Errorf("create installed control protocol registry: %w", err)
	}
	authorizer, err := NewRPCNodeAuthorizer(stateStore)
	if err != nil {
		return nil, err
	}
	rpcServer, err := control.NewRPCServer(control.RPCServerConfig{
		GatewayID: state.Host.ID, NodeCIDR: state.Host.NodeCIDR,
		CertificatePEM: serverPEM, PrivateKeyPEM: serverKeyPEM,
		ClientCACertificatePEM: caPEM, Protocols: protocols, Authorizer: authorizer,
	})
	if err != nil {
		return nil, fmt.Errorf("create system control RPC server: %w", err)
	}

	// A staged CA rotation leaves the old server leaf active while accepting
	// both old and new node CAs. Reconstruct that exact runtime after restart.
	rotator, err := controller.NewGatewayControlCARotator(secrets, rpcServer, GatewayControlCARotationRuntime{})
	if err != nil {
		return nil, err
	}
	if _, err := rotator.RestoreRuntime(ctx); err != nil {
		return nil, fmt.Errorf("restore control CA rotation runtime: %w", err)
	}
	return rpcServer, nil
}

func systemControlIdentity(state model.State) (model.Certificate, model.Certificate, error) {
	_, operation, rotating, err := activeControlCARotation(state)
	if err != nil {
		return model.Certificate{}, model.Certificate{}, err
	}
	if !rotating {
		return soleControlCAAndServer(state)
	}
	oldCA, _, oldServer, _, err := rotationCertificateGenerations(state, operation.ID)
	return oldCA, oldServer, err
}

type systemManagementService func(context.Context) error

func runSystemManagement(ctx context.Context, services ...systemManagementService) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if len(services) == 0 {
		return fmt.Errorf("at least one management service is required")
	}
	for _, service := range services {
		if service == nil {
			return fmt.Errorf("management service is required")
		}
	}
	serviceContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(services))
	for _, service := range services {
		go func(run systemManagementService) { results <- run(serviceContext) }(service)
	}

	first := <-results
	if first == nil && ctx.Err() == nil {
		first = fmt.Errorf("management service stopped unexpectedly")
	}
	cancel()
	all := []error{first}
	for completed := 1; completed < len(services); completed++ {
		all = append(all, <-results)
	}
	if ctx.Err() != nil {
		return nil
	}
	return errors.Join(all...)
}

func clearSystemControlSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
