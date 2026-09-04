package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/observability"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

var (
	gatewayControllerServicePaths = store.DefaultPaths
	runGatewayControllerService   = controller.RunSystemController
	runStandardTransportService   = func(ctx context.Context, paths store.Paths, role model.Role) error {
		return transport.RunStandardService(ctx, paths, role, linuxplatform.OSProbeRunner{})
	}
	runRestrictedTransportService = func(ctx context.Context, paths store.Paths) error {
		return transport.RunRestrictedGatewayService(ctx, paths, linuxplatform.OSProbeRunner{}, transport.OSRestrictedProcessRunner{})
	}
	runGatewayDNSService  = routing.RunGatewayDNSService
	runNodeRoutingService = func(ctx context.Context, paths store.Paths) error {
		return routing.RunNodeRoutingService(ctx, paths, linuxplatform.OSProbeRunner{}, routing.OSNodeRoutingProcessRunner{})
	}
	runNodeRoutingGuardService = func(ctx context.Context, paths store.Paths, action string) error {
		return routing.RunNodeRoutingGuardService(ctx, paths, linuxplatform.OSProbeRunner{}, action)
	}
	runNodeDNSIntegrationService = func(ctx context.Context, paths store.Paths, action string) error {
		return routing.RunNodeDNSIntegrationService(ctx, paths, linuxplatform.OSProbeRunner{}, action)
	}
	runFRPServerService = func(ctx context.Context, paths store.Paths) error {
		return tunnel.RunGatewayTunnelService(ctx, paths, linuxplatform.OSProbeRunner{}, tunnel.OSFRPProcessRunner{})
	}
	runFRPClientService = func(ctx context.Context, paths store.Paths) error {
		return tunnel.RunFRPClientService(ctx, paths, linuxplatform.OSProbeRunner{}, tunnel.OSFRPProcessRunner{})
	}
	internalServiceContext = func() (context.Context, context.CancelFunc) {
		return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	}
)

func executeInternalService(args []string, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "unsupported internal service mode")
		return ExitValidation
	}
	ctx, stop := internalServiceContext()
	defer stop()
	paths := gatewayControllerServicePaths()
	if state, stateErr := store.NewStateStore(paths); stateErr == nil {
		logger, loggerErr := operations.NewComponentLogger(state, operations.ComponentLoggerOptions{Journal: stderr})
		if loggerErr == nil {
			ctx = observability.WithEmitter(ctx, logger)
			defer func() { _ = logger.Close() }()
		}
	}
	var serviceName string
	var err error
	switch args[0] {
	case "gateway-controller":
		serviceName = "gateway controller"
		err = runGatewayControllerService(ctx, paths)
	case "gateway-standard":
		serviceName = "gateway standard transport"
		err = runStandardTransportService(ctx, paths, model.RoleGateway)
	case "gateway-restricted":
		serviceName = "gateway restricted transport"
		err = runRestrictedTransportService(ctx, paths)
	case "gateway-dns":
		serviceName = "gateway DNS"
		err = runGatewayDNSService(ctx, paths)
	case "gateway-tunnel-server":
		serviceName = "gateway tunnel server"
		err = runFRPServerService(ctx, paths)
	case "node-standard":
		serviceName = "node standard transport"
		err = runStandardTransportService(ctx, paths, model.RoleNode)
	case "node-routing":
		serviceName = "node routing"
		err = runNodeRoutingService(ctx, paths)
	case "node-tunnel-client":
		serviceName = "node tunnel client"
		err = runFRPClientService(ctx, paths)
	case "node-routing-guard":
		serviceName = "node routing guard"
		err = runNodeRoutingGuardService(ctx, paths, routing.NodeRoutingGuardInstallAction)
	case "node-routing-not-ready":
		serviceName = "node routing guard not-ready"
		err = runNodeRoutingGuardService(ctx, paths, routing.NodeRoutingGuardNotReadyAction)
	case "node-routing-wait-ready":
		serviceName = "node routing guard wait-ready"
		err = runNodeRoutingGuardService(ctx, paths, routing.NodeRoutingGuardWaitReadyAction)
	case "node-dns-install":
		serviceName = "node DNS integration install"
		err = runNodeDNSIntegrationService(ctx, paths, routing.NodeDNSIntegrationInstallAction)
	case "node-dns-restore":
		serviceName = "node DNS integration restore"
		err = runNodeDNSIntegrationService(ctx, paths, routing.NodeDNSIntegrationRestoreAction)
	default:
		fmt.Fprintln(stderr, "unsupported internal service mode")
		return ExitValidation
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s service failed\n", serviceName)
		return ExitInternal
	}
	return ExitSuccess
}
