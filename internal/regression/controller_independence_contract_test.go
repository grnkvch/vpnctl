package regression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControllerAndTunnelAuthorizationHaveIndependentSourceLifecycles(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..")
	controllerSource := readControllerIndependenceSource(t, root, "internal/controller/system_observer.go")
	for _, forbidden := range []string{"internal/tunnel", "NewAuthorizationServer", "NewSecretStore", "runSystemControllerServices"} {
		if strings.Contains(controllerSource, forbidden) {
			t.Errorf("controller process still owns tunnel authorization via %q", forbidden)
		}
	}
	for _, required := range []string{"NewSystemController(paths)", "controller.Serve(ctx)"} {
		if !strings.Contains(controllerSource, required) {
			t.Errorf("controller process omits management-only boundary %q", required)
		}
	}

	tunnelSource := readControllerIndependenceSource(t, root, "internal/tunnel/gateway_service.go")
	for _, required := range []string{
		"NewFRPService", "NewAuthorizationServer", "NewStateStore", "NewSecretStore",
		"authorizationReady", "runGatewayTunnelServices",
	} {
		if !strings.Contains(tunnelSource, required) {
			t.Errorf("gateway tunnel service omits independent authorization boundary %q", required)
		}
	}
	cliSource := readControllerIndependenceSource(t, root, "internal/cli/controller_service.go")
	if !strings.Contains(cliSource, "RunGatewayTunnelService") || strings.Contains(cliSource, "runFRPServerService = func(ctx context.Context, paths store.Paths) error {\n\t\treturn tunnel.RunFRPServerService") {
		t.Error("gateway tunnel unit entry point bypasses the independent authorizer composite")
	}

	unitSource := readControllerIndependenceSource(t, root, "internal/platform/linux/gateway_units.go")
	if strings.Contains(unitSource, "vpnctl-standard.service vpnctl-controller.service") {
		t.Error("gateway tunnel systemd dependencies still couple it to the controller")
	}
}

func readControllerIndependenceSource(t *testing.T, root, relative string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
