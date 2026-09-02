package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var (
	gatewayControllerServicePaths = store.DefaultPaths
	runGatewayControllerService   = controller.RunSystemController
	gatewayControllerContext      = func() (context.Context, context.CancelFunc) {
		return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	}
)

func executeInternalService(args []string, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "gateway-controller" {
		fmt.Fprintln(stderr, "unsupported internal service mode")
		return ExitValidation
	}
	ctx, stop := gatewayControllerContext()
	defer stop()
	if err := runGatewayControllerService(ctx, gatewayControllerServicePaths()); err != nil {
		fmt.Fprintln(stderr, "gateway controller service failed")
		return ExitInternal
	}
	return ExitSuccess
}
