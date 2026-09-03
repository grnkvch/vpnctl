package controller

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSystemControllerRunsLocalAndTunnelAuthorizationServicesTogether(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan string, 2)
	stopped := make(chan string, 2)
	service := func(name string) systemControllerService {
		return func(ctx context.Context) error {
			started <- name
			<-ctx.Done()
			stopped <- name
			return nil
		}
	}
	result := make(chan error, 1)
	go func() {
		result <- runSystemControllerServices(ctx, service("controller"), service("authorization"))
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("system controller service did not start")
		}
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("runSystemControllerServices() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("system controller services did not stop")
	}
	if len(stopped) != 2 {
		t.Fatalf("stopped services = %d", len(stopped))
	}
}

func TestSystemControllerFailsWhenEitherLocalServiceFailsAndCancelsTheOther(t *testing.T) {
	t.Parallel()

	for _, failingName := range []string{"controller", "authorization"} {
		failingName := failingName
		t.Run(failingName, func(t *testing.T) {
			t.Parallel()
			failure := errors.New("listener-canary")
			var otherCancelled atomic.Bool
			failing := func(context.Context) error { return failure }
			other := func(ctx context.Context) error {
				<-ctx.Done()
				otherCancelled.Store(true)
				return nil
			}
			controllerService, authorizationService := other, failing
			if failingName == "controller" {
				controllerService, authorizationService = failing, other
			}
			err := runSystemControllerServices(context.Background(), controllerService, authorizationService)
			if !errors.Is(err, failure) || !strings.Contains(err.Error(), failingName) || !otherCancelled.Load() {
				t.Fatalf("service failure = %v cancelled=%t", err, otherCancelled.Load())
			}
		})
	}
}

func TestSystemControllerRejectsIncompleteServiceSet(t *testing.T) {
	t.Parallel()

	if err := runSystemControllerServices(context.Background(), nil, func(context.Context) error { return nil }); err == nil {
		t.Fatal("runSystemControllerServices accepted a missing local controller")
	}
}
