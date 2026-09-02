package cli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestInternalGatewayControllerServiceIsHiddenAndSignalBound(t *testing.T) {
	previousPaths := gatewayControllerServicePaths
	previousRun := runGatewayControllerService
	previousContext := gatewayControllerContext
	t.Cleanup(func() {
		gatewayControllerServicePaths = previousPaths
		runGatewayControllerService = previousRun
		gatewayControllerContext = previousContext
	})
	paths, _ := store.NewPaths(t.TempDir())
	gatewayControllerServicePaths = func() store.Paths { return paths }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	gatewayControllerContext = func() (context.Context, context.CancelFunc) {
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
	previousContext := gatewayControllerContext
	t.Cleanup(func() {
		runGatewayControllerService = previousRun
		gatewayControllerContext = previousContext
	})
	gatewayControllerContext = func() (context.Context, context.CancelFunc) {
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
