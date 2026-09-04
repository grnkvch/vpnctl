package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/observability"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const internalServiceCanary = "vpnctl-secret-canary Authorization: Bearer token /telegram/webhook request-body"

func TestInternalGatewayControllerServiceIsHiddenAndSignalBound(t *testing.T) {
	previousPaths := gatewayControllerServicePaths
	previousRun := runGatewayControllerService
	previousContext := internalServiceContext
	t.Cleanup(func() {
		gatewayControllerServicePaths = previousPaths
		runGatewayControllerService = previousRun
		internalServiceContext = previousContext
	})
	paths, _ := store.NewPaths(t.TempDir())
	gatewayControllerServicePaths = func() store.Paths { return paths }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	internalServiceContext = func() (context.Context, context.CancelFunc) {
		return ctx, func() {}
	}
	called := false
	runGatewayControllerService = func(received context.Context, receivedPaths store.Paths) error {
		called = true
		if received.Done() != ctx.Done() || receivedPaths != paths {
			t.Fatalf("controller service arguments = %v, %+v", received, receivedPaths)
		}
		return nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Execute([]string{"__service", "gateway-controller"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("Execute(service) code = %d, stderr = %q", code, stderr.String())
	}
	if !called || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("service called=%t stdout=%q stderr=%q", called, stdout.String(), stderr.String())
	}

}

func TestInternalServiceLoggingCanaryE2EAllLocalSinksAndNoNetwork(t *testing.T) {
	previousPaths := gatewayControllerServicePaths
	previousRun := runGatewayControllerService
	previousContext := internalServiceContext
	t.Cleanup(func() {
		gatewayControllerServicePaths = previousPaths
		runGatewayControllerService = previousRun
		internalServiceContext = previousContext
	})
	internalServiceContext = func() (context.Context, context.CancelFunc) {
		return context.Background(), func() {}
	}
	runGatewayControllerService = func(ctx context.Context, _ store.Paths) error {
		_ = observability.EmitGeneration(ctx, observability.ControlServiceStarted, 7)
		return errors.New(internalServiceCanary)
	}

	now := time.Now().UTC().Truncate(time.Second)
	root := t.TempDir()
	paths, _ := store.NewPaths(root)
	gatewayControllerServicePaths = func() store.Paths { return paths }
	state := cliDNSState(model.RoleGateway)
	state.Logging = []model.LoggingSession{{
		SchemaVersion: model.ResourceSchemaVersion, ID: "11111111-1111-4111-8111-111111111111",
		Scope: model.LogControl, Level: model.LogTrace, Destination: model.LogToJournald, State: model.LogActive,
		StartedAt: now.Add(-time.Minute), ExpiresAt: now.Add(59 * time.Minute),
	}}
	stateBytes := writeInternalServiceState(t, paths, state)
	var stdout, journalAndStderr bytes.Buffer
	if code := Execute([]string{"__service", "gateway-controller"}, &stdout, &journalAndStderr); code != ExitInternal {
		t.Fatalf("journal service code = %d, stderr = %q", code, journalAndStderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(journalAndStderr.String(), `"code":"control_service_started"`) ||
		!strings.HasSuffix(journalAndStderr.String(), "gateway controller service failed\n") {
		t.Fatalf("stdout=%q journal/stderr=%q", stdout.String(), journalAndStderr.String())
	}
	journalBytes := append([]byte(nil), journalAndStderr.Bytes()...)

	fileDirectory := filepath.Join(root, "var", "log", "vpnctl")
	if err := os.MkdirAll(fileDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fileDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(fileDirectory, "control.log")
	state.Logging[0].Destination = model.LogToFile
	state.Logging[0].FilePath = logPath
	stateBytes = writeInternalServiceState(t, paths, state)
	stdout.Reset()
	journalAndStderr.Reset()
	if code := Execute([]string{"__service", "gateway-controller"}, &stdout, &journalAndStderr); code != ExitInternal {
		t.Fatalf("file service code = %d, stderr = %q", code, journalAndStderr.String())
	}
	fileBytes, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(fileBytes), `"code":"control_service_started"`) {
		t.Fatalf("file=%q err=%v", fileBytes, err)
	}

	packetCapture := []byte{}
	for name, sink := range map[string][]byte{
		"stdout": stdout.Bytes(), "stderr": journalAndStderr.Bytes(), "journal": journalBytes, "file": fileBytes,
		"state": stateBytes, "network capture": packetCapture,
	} {
		if bytes.Contains(sink, []byte(internalServiceCanary)) || bytes.Contains(sink, []byte("Bearer token")) ||
			bytes.Contains(sink, []byte("/telegram/webhook")) || bytes.Contains(sink, []byte("request-body")) {
			t.Errorf("%s leaked canary material: %q", name, sink)
		}
	}
	if len(packetCapture) != 0 {
		t.Fatalf("logging emitted network bytes: %q", packetCapture)
	}
}

func writeInternalServiceState(t *testing.T, paths store.Paths, state model.State) []byte {
	t.Helper()
	encoded, err := model.EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.StateFile, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestInternalGatewayDNSServiceDispatchAndSanitizeFailure(t *testing.T) {
	previousPaths := gatewayControllerServicePaths
	previousRun := runGatewayDNSService
	previousContext := internalServiceContext
	t.Cleanup(func() {
		gatewayControllerServicePaths = previousPaths
		runGatewayDNSService = previousRun
		internalServiceContext = previousContext
	})
	paths, _ := store.NewPaths(t.TempDir())
	gatewayControllerServicePaths = func() store.Paths { return paths }
	internalServiceContext = func() (context.Context, context.CancelFunc) {
		return context.Background(), func() {}
	}
	called := false
	runGatewayDNSService = func(_ context.Context, received store.Paths) error {
		called = true
		if received != paths {
			t.Fatalf("gateway DNS paths = %+v", received)
		}
		return errors.New("query-name-canary")
	}
	var stderr bytes.Buffer
	if code := Execute([]string{"__service", "gateway-dns"}, &bytes.Buffer{}, &stderr); code != ExitInternal {
		t.Fatalf("gateway DNS service code = %d", code)
	}
	if !called || stderr.String() != "gateway DNS service failed\n" || strings.Contains(stderr.String(), "canary") {
		t.Fatalf("gateway DNS dispatch called=%t stderr=%q", called, stderr.String())
	}
}

func TestInternalGatewayControllerServiceFailureIsSanitized(t *testing.T) {
	previousRun := runGatewayControllerService
	previousContext := internalServiceContext
	t.Cleanup(func() {
		runGatewayControllerService = previousRun
		internalServiceContext = previousContext
	})
	internalServiceContext = func() (context.Context, context.CancelFunc) {
		return context.Background(), func() {}
	}
	runGatewayControllerService = func(context.Context, store.Paths) error {
		return errors.New("secret-canary")
	}
	var stderr bytes.Buffer
	if code := Execute([]string{"__service", "gateway-controller"}, &bytes.Buffer{}, &stderr); code != ExitInternal {
		t.Fatalf("Execute(service failure) code = %d", code)
	}
	if bytes.Contains(stderr.Bytes(), []byte("secret-canary")) {
		t.Fatalf("service failure leaked implementation detail: %q", stderr.String())
	}
}

func TestInternalStandardServicesDispatchRoleAndSanitizeFailure(t *testing.T) {
	previousPaths := gatewayControllerServicePaths
	previousRun := runStandardTransportService
	previousContext := internalServiceContext
	t.Cleanup(func() {
		gatewayControllerServicePaths = previousPaths
		runStandardTransportService = previousRun
		internalServiceContext = previousContext
	})
	paths, _ := store.NewPaths(t.TempDir())
	gatewayControllerServicePaths = func() store.Paths { return paths }
	internalServiceContext = func() (context.Context, context.CancelFunc) {
		return context.Background(), func() {}
	}
	var roles []model.Role
	runStandardTransportService = func(_ context.Context, received store.Paths, role model.Role) error {
		if received != paths {
			t.Fatalf("standard service paths = %+v", received)
		}
		roles = append(roles, role)
		if role == model.RoleNode {
			return errors.New("private-key-canary")
		}
		return nil
	}
	var stderr bytes.Buffer
	if code := Execute([]string{"__service", "gateway-standard"}, &bytes.Buffer{}, &stderr); code != ExitSuccess {
		t.Fatalf("gateway standard code = %d, stderr = %q", code, stderr.String())
	}
	stderr.Reset()
	if code := Execute([]string{"__service", "node-standard"}, &bytes.Buffer{}, &stderr); code != ExitInternal {
		t.Fatalf("node standard code = %d, stderr = %q", code, stderr.String())
	}
	if got := fmt.Sprint(roles); got != "[gateway node]" {
		t.Fatalf("standard roles = %s", got)
	}
	if strings.Contains(stderr.String(), "private-key-canary") || stderr.String() != "node standard transport service failed\n" {
		t.Fatalf("standard error was not sanitized: %q", stderr.String())
	}
}

func TestInternalRestrictedServiceDispatchAndSanitizeFailure(t *testing.T) {
	previousPaths := gatewayControllerServicePaths
	previousRun := runRestrictedTransportService
	previousContext := internalServiceContext
	t.Cleanup(func() {
		gatewayControllerServicePaths = previousPaths
		runRestrictedTransportService = previousRun
		internalServiceContext = previousContext
	})
	paths, _ := store.NewPaths(t.TempDir())
	gatewayControllerServicePaths = func() store.Paths { return paths }
	internalServiceContext = func() (context.Context, context.CancelFunc) {
		return context.Background(), func() {}
	}
	called := false
	runRestrictedTransportService = func(_ context.Context, received store.Paths) error {
		called = true
		if received != paths {
			t.Fatalf("restricted service paths = %+v", received)
		}
		return errors.New("shadowtls-password-canary")
	}
	var stderr bytes.Buffer
	if code := Execute([]string{"__service", "gateway-restricted"}, &bytes.Buffer{}, &stderr); code != ExitInternal {
		t.Fatalf("restricted service code = %d", code)
	}
	if !called || stderr.String() != "gateway restricted transport service failed\n" || strings.Contains(stderr.String(), "canary") {
		t.Fatalf("restricted dispatch called=%t stderr=%q", called, stderr.String())
	}
}

func TestInternalNodeRoutingServiceDispatchAndSanitizeFailure(t *testing.T) {
	previousPaths := gatewayControllerServicePaths
	previousRun := runNodeRoutingService
	previousContext := internalServiceContext
	t.Cleanup(func() {
		gatewayControllerServicePaths = previousPaths
		runNodeRoutingService = previousRun
		internalServiceContext = previousContext
	})
	paths, _ := store.NewPaths(t.TempDir())
	gatewayControllerServicePaths = func() store.Paths { return paths }
	internalServiceContext = func() (context.Context, context.CancelFunc) {
		return context.Background(), func() {}
	}
	called := false
	runNodeRoutingService = func(_ context.Context, received store.Paths) error {
		called = true
		if received != paths {
			t.Fatalf("node routing service paths = %+v", received)
		}
		return errors.New("policy-secret-canary")
	}
	var stderr bytes.Buffer
	if code := Execute([]string{"__service", "node-routing"}, &bytes.Buffer{}, &stderr); code != ExitInternal {
		t.Fatalf("node routing service code = %d", code)
	}
	if !called || stderr.String() != "node routing service failed\n" || strings.Contains(stderr.String(), "canary") {
		t.Fatalf("node routing dispatch called=%t stderr=%q", called, stderr.String())
	}
}

func TestInternalNodeRoutingGuardServicesDispatchActionsAndSanitizeFailure(t *testing.T) {
	previousPaths := gatewayControllerServicePaths
	previousRun := runNodeRoutingGuardService
	previousContext := internalServiceContext
	t.Cleanup(func() {
		gatewayControllerServicePaths = previousPaths
		runNodeRoutingGuardService = previousRun
		internalServiceContext = previousContext
	})
	paths, _ := store.NewPaths(t.TempDir())
	gatewayControllerServicePaths = func() store.Paths { return paths }
	internalServiceContext = func() (context.Context, context.CancelFunc) {
		return context.Background(), func() {}
	}
	want := map[string]string{
		"node-routing-guard":      "install",
		"node-routing-not-ready":  "not-ready",
		"node-routing-wait-ready": "wait-ready",
	}
	for mode, action := range want {
		mode, action := mode, action
		t.Run(mode, func(t *testing.T) {
			called := false
			runNodeRoutingGuardService = func(_ context.Context, received store.Paths, receivedAction string) error {
				called = true
				if received != paths || receivedAction != action {
					t.Fatalf("guard service arguments = %+v/%q", received, receivedAction)
				}
				return errors.New("routing-policy-canary")
			}
			var stderr bytes.Buffer
			if code := Execute([]string{"__service", mode}, &bytes.Buffer{}, &stderr); code != ExitInternal {
				t.Fatalf("guard service code = %d", code)
			}
			if !called || strings.Contains(stderr.String(), "canary") || !strings.Contains(stderr.String(), "service failed") {
				t.Fatalf("guard dispatch called=%t stderr=%q", called, stderr.String())
			}
		})
	}
}

func TestInternalNodeDNSIntegrationServicesDispatchActionsAndSanitizeFailure(t *testing.T) {
	previousPaths := gatewayControllerServicePaths
	previousRun := runNodeDNSIntegrationService
	previousContext := internalServiceContext
	t.Cleanup(func() {
		gatewayControllerServicePaths = previousPaths
		runNodeDNSIntegrationService = previousRun
		internalServiceContext = previousContext
	})
	paths, _ := store.NewPaths(t.TempDir())
	gatewayControllerServicePaths = func() store.Paths { return paths }
	internalServiceContext = func() (context.Context, context.CancelFunc) {
		return context.Background(), func() {}
	}
	for mode, action := range map[string]string{"node-dns-install": "install", "node-dns-restore": "restore"} {
		mode, action := mode, action
		t.Run(mode, func(t *testing.T) {
			called := false
			runNodeDNSIntegrationService = func(_ context.Context, received store.Paths, receivedAction string) error {
				called = true
				if received != paths || receivedAction != action {
					t.Fatalf("DNS integration service arguments = %+v/%q", received, receivedAction)
				}
				return errors.New("dns-policy-canary")
			}
			var stderr bytes.Buffer
			if code := Execute([]string{"__service", mode}, &bytes.Buffer{}, &stderr); code != ExitInternal {
				t.Fatalf("DNS integration service code = %d", code)
			}
			if !called || strings.Contains(stderr.String(), "canary") || !strings.Contains(stderr.String(), "service failed") {
				t.Fatalf("DNS integration dispatch called=%t stderr=%q", called, stderr.String())
			}
		})
	}
}

func TestInternalFRPServicesDispatchAndSanitizeFailure(t *testing.T) {
	previousPaths := gatewayControllerServicePaths
	previousServer := runFRPServerService
	previousClient := runFRPClientService
	previousContext := internalServiceContext
	t.Cleanup(func() {
		gatewayControllerServicePaths = previousPaths
		runFRPServerService = previousServer
		runFRPClientService = previousClient
		internalServiceContext = previousContext
	})
	paths, _ := store.NewPaths(t.TempDir())
	gatewayControllerServicePaths = func() store.Paths { return paths }
	internalServiceContext = func() (context.Context, context.CancelFunc) {
		return context.Background(), func() {}
	}
	called := []string{}
	runFRPServerService = func(_ context.Context, received store.Paths) error {
		if received != paths {
			t.Fatalf("frp server paths = %+v", received)
		}
		called = append(called, "server")
		return nil
	}
	runFRPClientService = func(_ context.Context, received store.Paths) error {
		if received != paths {
			t.Fatalf("frp client paths = %+v", received)
		}
		called = append(called, "client")
		return errors.New("tunnel-token-canary")
	}
	var stderr bytes.Buffer
	if code := Execute([]string{"__service", "gateway-tunnel-server"}, &bytes.Buffer{}, &stderr); code != ExitSuccess {
		t.Fatalf("gateway tunnel service code = %d, stderr = %q", code, stderr.String())
	}
	stderr.Reset()
	if code := Execute([]string{"__service", "node-tunnel-client"}, &bytes.Buffer{}, &stderr); code != ExitInternal {
		t.Fatalf("node tunnel service code = %d", code)
	}
	if fmt.Sprint(called) != "[server client]" || stderr.String() != "node tunnel client service failed\n" || strings.Contains(stderr.String(), "canary") {
		t.Fatalf("frp dispatch called=%v stderr=%q", called, stderr.String())
	}
}
