package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestNginxBaselineRouteCheckProvesHealthAndEnrollmentUpstream(t *testing.T) {
	t.Parallel()
	requests := []*http.Request{}
	transport := nginxBaselineRoundTripper(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request)
		status := http.StatusNoContent
		if request.URL.Path == model.ReservedEnrollmentPath {
			status = http.StatusBadRequest
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("bounded"))}, nil
	})
	if err := checkNginxBaselineRoutes(context.Background(), transport, "https://203.0.113.10:443"); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[0].Method != http.MethodGet || requests[0].URL.Path != model.ReservedHealthPath ||
		requests[1].Method != http.MethodPost || requests[1].URL.Path != model.ReservedEnrollmentPath || requests[1].Header.Get("Authorization") != "" {
		t.Fatalf("baseline route probes = %+v", requests)
	}
}

func TestNginxBaselineRouteCheckRejectsEnrollmentProxyFailure(t *testing.T) {
	t.Parallel()
	call := 0
	transport := nginxBaselineRoundTripper(func(*http.Request) (*http.Response, error) {
		call++
		status := http.StatusNoContent
		if call == 2 {
			status = http.StatusBadGateway
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if err := checkNginxBaselineRoutes(context.Background(), transport, "https://203.0.113.10:443"); err == nil || !strings.Contains(err.Error(), "reserved enrollment") {
		t.Fatalf("enrollment proxy failure = %v", err)
	}
}

func TestNginxBaselineRouteCheckRetriesOnlyTransientStartupFailure(t *testing.T) {
	t.Parallel()
	requests := 0
	transport := nginxBaselineRoundTripper(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		}
		status := http.StatusNoContent
		if request.URL.Path == model.ReservedEnrollmentPath {
			status = http.StatusBadRequest
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := checkNginxBaselineRoutesUntilReady(ctx, transport, "https://203.0.113.10:443", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if requests != 3 {
		t.Fatalf("route requests = %d, want one failed health plus health/enrollment", requests)
	}

	requests = 0
	deterministic := nginxBaselineRoundTripper(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if err := checkNginxBaselineRoutesUntilReady(ctx, deterministic, "https://203.0.113.10:443", time.Millisecond); err == nil || requests != 1 {
		t.Fatalf("deterministic failure = %v after %d requests", err, requests)
	}
}

type nginxBaselineRoundTripper func(*http.Request) (*http.Response, error)

func (roundTripper nginxBaselineRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTripper(request)
}

func TestNginxBaselineAppliesHealthChecksAndCommitsInOrder(t *testing.T) {
	t.Parallel()
	manager, paths, calls, activation, service, health := nginxBaselineFixture(t)
	plan, err := manager.Plan()
	if err != nil {
		t.Fatal(err)
	}
	request := nginxBaselineRequest(paths)
	result, installation, err := manager.Apply(context.Background(), plan, request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.ConfigHash == "" || result.ActiveExposeCount != 0 || result.DropInPath != plan.Service.DropInPath {
		t.Fatalf("Apply() result = %+v", result)
	}
	if activation.candidate.StateGeneration() != request.StateGeneration || activation.candidate.PublicIPv4() != request.PublicIPv4 {
		t.Fatalf("activation candidate = generation %d IP %s", activation.candidate.StateGeneration(), activation.candidate.PublicIPv4())
	}
	if health.publicIPv4 != request.PublicIPv4 {
		t.Fatalf("health public IPv4 = %q", health.publicIPv4)
	}
	if err := manager.Commit(context.Background(), installation); err != nil {
		t.Fatal(err)
	}
	want := []string{"service.plan", "service.plan", "activation.apply", "service.apply", "service.activate", "health", "activation.commit", "service.commit"}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("calls = %#v, want %#v", *calls, want)
	}
	if service.rollbackCalls != 0 || activation.rollbackCalls != 0 {
		t.Fatalf("unexpected rollback service=%d activation=%d", service.rollbackCalls, activation.rollbackCalls)
	}
}

func TestNginxBaselineHealthFailureRollsBackServiceBeforeGeneration(t *testing.T) {
	t.Parallel()
	manager, paths, calls, activation, service, health := nginxBaselineFixture(t)
	health.err = errors.New("synthetic health failure")
	plan, err := manager.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if _, installation, err := manager.Apply(context.Background(), plan, nginxBaselineRequest(paths)); err == nil || installation != nil {
		t.Fatalf("Apply() = installation %+v, error %v", installation, err)
	}
	wantSuffix := []string{"service.rollback", "activation.rollback"}
	if got := (*calls)[len(*calls)-2:]; !reflect.DeepEqual(got, wantSuffix) {
		t.Fatalf("rollback order = %#v", got)
	}
	if service.rollbackCalls != 1 || activation.rollbackCalls != 1 {
		t.Fatalf("rollback calls service=%d activation=%d", service.rollbackCalls, activation.rollbackCalls)
	}
}

func TestNginxBaselineServiceFailureRollsBackPublishedGeneration(t *testing.T) {
	t.Parallel()
	manager, paths, calls, activation, service, _ := nginxBaselineFixture(t)
	service.applyErr = errors.New("synthetic service failure")
	plan, err := manager.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := manager.Apply(context.Background(), plan, nginxBaselineRequest(paths)); err == nil {
		t.Fatal("Apply() error = nil")
	}
	if activation.rollbackCalls != 1 || service.rollbackCalls != 0 {
		t.Fatalf("rollback calls service=%d activation=%d", service.rollbackCalls, activation.rollbackCalls)
	}
	if got := (*calls)[len(*calls)-1]; got != "activation.rollback" {
		t.Fatalf("last call = %q", got)
	}
}

type recordingNginxBaselineActivation struct {
	calls         *[]string
	candidate     NginxCandidate
	rollbackCalls int
}

func (activation *recordingNginxBaselineActivation) ActivateRetained(_ context.Context, candidate NginxCandidate) (NginxActivationResult, *NginxRetainedActivation, error) {
	*activation.calls = append(*activation.calls, "activation.apply")
	activation.candidate = candidate
	return NginxActivationResult{Changed: true}, &NginxRetainedActivation{}, nil
}

func (activation *recordingNginxBaselineActivation) CommitRetained(_ context.Context, _ *NginxRetainedActivation) error {
	*activation.calls = append(*activation.calls, "activation.commit")
	return nil
}

func (activation *recordingNginxBaselineActivation) RollbackRetained(_ context.Context, _ *NginxRetainedActivation) error {
	*activation.calls = append(*activation.calls, "activation.rollback")
	activation.rollbackCalls++
	return nil
}

type recordingNginxBaselineService struct {
	calls         *[]string
	plan          NginxServicePlan
	applyErr      error
	rollbackCalls int
}

func (service *recordingNginxBaselineService) Plan() (NginxServicePlan, error) {
	*service.calls = append(*service.calls, "service.plan")
	return service.plan, nil
}

func (service *recordingNginxBaselineService) Apply(_ context.Context, _ NginxServicePlan) (*NginxServiceInstallation, error) {
	*service.calls = append(*service.calls, "service.apply")
	if service.applyErr != nil {
		return nil, service.applyErr
	}
	return &NginxServiceInstallation{}, nil
}

func (service *recordingNginxBaselineService) Activate(_ context.Context, _ *NginxServiceInstallation) error {
	*service.calls = append(*service.calls, "service.activate")
	return nil
}

func (service *recordingNginxBaselineService) Commit(_ *NginxServiceInstallation) error {
	*service.calls = append(*service.calls, "service.commit")
	return nil
}

func (service *recordingNginxBaselineService) Rollback(_ context.Context, _ *NginxServiceInstallation) error {
	*service.calls = append(*service.calls, "service.rollback")
	service.rollbackCalls++
	return nil
}

type recordingNginxBaselineHealth struct {
	calls      *[]string
	publicIPv4 string
	err        error
}

func (health *recordingNginxBaselineHealth) Check(_ context.Context, publicIPv4 string) error {
	*health.calls = append(*health.calls, "health")
	health.publicIPv4 = publicIPv4
	return health.err
}

func nginxBaselineFixture(t *testing.T) (*NginxBaselineManager, store.Paths, *[]string, *recordingNginxBaselineActivation, *recordingNginxBaselineService, *recordingNginxBaselineHealth) {
	t.Helper()
	root := t.TempDir()
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{paths.ConfigDir, paths.RuntimeDir, filepath.Join(root, "etc", "systemd", "system")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	calls := &[]string{}
	activation := &recordingNginxBaselineActivation{calls: calls}
	service := &recordingNginxBaselineService{calls: calls, plan: NginxServicePlan{DropInPath: NginxServiceDropInPath(paths), Changed: true}}
	health := &recordingNginxBaselineHealth{calls: calls}
	manager, err := NewNginxBaselineManager(paths, activation, service, health)
	if err != nil {
		t.Fatal(err)
	}
	return manager, paths, calls, activation, service, health
}

func nginxBaselineRequest(paths store.Paths) NginxBaselineRequest {
	return NginxBaselineRequest{
		StateGeneration: 1, PublicIPv4: "203.0.113.10",
		CertificatePath: filepath.Join(paths.SecretsDir, "ingress-cert", "public-g1"),
		PrivateKeyPath:  filepath.Join(paths.SecretsDir, "ingress-key", "public-g1"),
		Exposes:         []model.Expose{},
	}
}
