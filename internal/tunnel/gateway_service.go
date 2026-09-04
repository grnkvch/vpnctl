package tunnel

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

type gatewayTunnelService func(context.Context) error

type gatewayTunnelServiceResult struct {
	name string
	err  error
}

// RunGatewayTunnelService keeps passive tunnel authorization in the same
// independently supervised unit as frps. The management controller can stop
// or restart without removing heartbeat authorization from applied tunnels.
func RunGatewayTunnelService(ctx context.Context, paths store.Paths, probe linuxplatform.ProbeRunner, process FRPProcessRunner) error {
	service, err := NewFRPService(paths, model.RoleGateway, probe, process)
	if err != nil {
		return err
	}
	state, err := store.NewStateStore(paths)
	if err != nil {
		return fmt.Errorf("create tunnel authorization state reader: %w", err)
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return fmt.Errorf("create tunnel authorization secret reader: %w", err)
	}
	credentials, err := NewStoreCredentialSource(secrets)
	if err != nil {
		return err
	}
	authorizer, err := NewAuthorizationServer(state, credentials)
	if err != nil {
		return err
	}
	ready := make(chan struct{})
	var readyOnce sync.Once
	authorizer.ready = func() { readyOnce.Do(func() { close(ready) }) }
	return runGatewayTunnelServices(ctx, ready, authorizer.Serve, service.Run)
}

func runGatewayTunnelServices(
	ctx context.Context,
	authorizationReady <-chan struct{},
	authorizationService gatewayTunnelService,
	frpService gatewayTunnelService,
) error {
	if ctx == nil || authorizationReady == nil || authorizationService == nil || frpService == nil {
		return fmt.Errorf("gateway tunnel services are incomplete")
	}
	serviceContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan gatewayTunnelServiceResult, 2)
	start := func(name string, service gatewayTunnelService) {
		go func() {
			results <- gatewayTunnelServiceResult{name: name, err: service(serviceContext)}
		}()
	}
	start("tunnel authorization", authorizationService)
	select {
	case <-authorizationReady:
	case result := <-results:
		return gatewayTunnelServiceFailure(result, ctx.Err() != nil)
	case <-ctx.Done():
		cancel()
		result := <-results
		return gatewayTunnelServiceFailure(result, true)
	}

	start("frp server", frpService)
	first := <-results
	parentStopped := ctx.Err() != nil
	cancel()
	second := <-results
	for _, result := range []gatewayTunnelServiceResult{first, second} {
		if result.err != nil && !errors.Is(result.err, context.Canceled) {
			return fmt.Errorf("%s failed: %w", result.name, result.err)
		}
	}
	if !parentStopped {
		return fmt.Errorf("%s stopped unexpectedly", first.name)
	}
	return nil
}

func gatewayTunnelServiceFailure(result gatewayTunnelServiceResult, parentStopped bool) error {
	if result.err != nil && !errors.Is(result.err, context.Canceled) {
		return fmt.Errorf("%s failed: %w", result.name, result.err)
	}
	if !parentStopped {
		return fmt.Errorf("%s stopped unexpectedly", result.name)
	}
	return nil
}
