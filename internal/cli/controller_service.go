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
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

var (
	gatewayControllerServicePaths = store.DefaultPaths
	runGatewayControllerService   = controller.RunSystemController
	runStandardTransportService   = func(ctx context.Context, paths store.Paths, role model.Role) error {
		return transport.RunStandardService(ctx, paths, role, linuxplatform.OSProbeRunner{})
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
	var serviceName string
	var err error
	switch args[0] {
	case "gateway-controller":
		serviceName = "gateway controller"
		err = runGatewayControllerService(ctx, paths)
	case "gateway-standard":
		serviceName = "gateway standard transport"
		err = runStandardTransportService(ctx, paths, model.RoleGateway)
	case "node-standard":
		serviceName = "node standard transport"
		err = runStandardTransportService(ctx, paths, model.RoleNode)
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
