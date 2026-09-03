package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

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
		if received != ctx || receivedPaths != paths {
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

	called = false
	if code := Execute([]string{"__service", "gateway-dns"}, &stdout, &stderr); code != ExitValidation || called {
		t.Fatalf("unsupported service code/called = %d/%t", code, called)
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
