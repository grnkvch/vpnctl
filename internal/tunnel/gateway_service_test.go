package tunnel

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGatewayTunnelServicesKeepAuthorizationWithFRPAndOutsideControllerLifetime(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	authorizationStarted := make(chan struct{})
	frpStarted := make(chan struct{})
	var authorizationStopped atomic.Bool
	var frpStopped atomic.Bool
	authorization := func(ctx context.Context) error {
		close(authorizationStarted)
		close(ready)
		<-ctx.Done()
		authorizationStopped.Store(true)
		return nil
	}
	frp := func(ctx context.Context) error {
		close(frpStarted)
		<-ctx.Done()
		frpStopped.Store(true)
		return nil
	}
	result := make(chan error, 1)
	go func() { result <- runGatewayTunnelServices(ctx, ready, authorization, frp) }()
	for _, started := range []<-chan struct{}{authorizationStarted, frpStarted} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("gateway tunnel service did not start")
		}
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("runGatewayTunnelServices() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("gateway tunnel services did not stop")
	}
	if !authorizationStopped.Load() || !frpStopped.Load() {
		t.Fatalf("services stopped authorization=%t frp=%t", authorizationStopped.Load(), frpStopped.Load())
	}
}

func TestGatewayTunnelServicesRequireAuthorizerReadinessBeforeFRP(t *testing.T) {
	t.Parallel()
	failure := errors.New("authorization-listener-canary")
	ready := make(chan struct{})
	var frpCalls atomic.Int32
	err := runGatewayTunnelServices(context.Background(), ready, func(context.Context) error {
		return failure
	}, func(context.Context) error {
		frpCalls.Add(1)
		return nil
	})
	if !errors.Is(err, failure) || !strings.Contains(err.Error(), "tunnel authorization") || frpCalls.Load() != 0 {
		t.Fatalf("startup error=%v frp calls=%d", err, frpCalls.Load())
	}
}

func TestGatewayTunnelServiceFailureCancelsItsPeer(t *testing.T) {
	t.Parallel()
	for _, failedName := range []string{"authorization", "frp"} {
		failedName := failedName
		t.Run(failedName, func(t *testing.T) {
			t.Parallel()
			ready := make(chan struct{})
			frpStarted := make(chan struct{})
			failure := errors.New("runtime-canary")
			var peerCancelled atomic.Bool
			authorization := func(ctx context.Context) error {
				close(ready)
				if failedName == "authorization" {
					<-frpStarted
					return failure
				}
				<-ctx.Done()
				peerCancelled.Store(true)
				return nil
			}
			frp := func(ctx context.Context) error {
				close(frpStarted)
				if failedName == "frp" {
					return failure
				}
				<-ctx.Done()
				peerCancelled.Store(true)
				return nil
			}
			err := runGatewayTunnelServices(context.Background(), ready, authorization, frp)
			wantService := "frp server"
			if failedName == "authorization" {
				wantService = "tunnel authorization"
			}
			if !errors.Is(err, failure) || !strings.Contains(err.Error(), wantService) || !peerCancelled.Load() {
				t.Fatalf("failure=%v peer cancelled=%t", err, peerCancelled.Load())
			}
		})
	}
}

func TestGatewayTunnelServicesRejectIncompleteSet(t *testing.T) {
	t.Parallel()
	service := func(context.Context) error { return nil }
	if err := runGatewayTunnelServices(context.Background(), nil, service, service); err == nil {
		t.Fatal("nil readiness accepted")
	}
	if err := runGatewayTunnelServices(context.Background(), make(chan struct{}), nil, service); err == nil {
		t.Fatal("nil authorization accepted")
	}
}
