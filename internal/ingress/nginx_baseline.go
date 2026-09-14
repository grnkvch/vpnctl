package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	DefaultNginxBaselineHealthTimeout = 5 * time.Second
	nginxBaselineHealthRetryInterval  = 50 * time.Millisecond
)

type NginxBaselinePlan struct {
	Service NginxServicePlan
}

type NginxBaselineRequest struct {
	StateGeneration uint64
	PublicIPv4      string
	CertificatePath string
	PrivateKeyPath  string
	Exposes         []model.Expose
}

type NginxBaselineResult struct {
	Changed           bool
	ConfigHash        string
	ActiveExposeCount int
	DropInPath        string
}

type NginxBaselineInstallation struct {
	managerRoot string
	activation  *NginxRetainedActivation
	service     *NginxServiceInstallation
	result      NginxBaselineResult
}

type nginxBaselineActivator interface {
	ActivateRetained(context.Context, NginxCandidate) (NginxActivationResult, *NginxRetainedActivation, error)
	CommitRetained(context.Context, *NginxRetainedActivation) error
	RollbackRetained(context.Context, *NginxRetainedActivation) error
}

type nginxBaselineService interface {
	Plan() (NginxServicePlan, error)
	Apply(context.Context, NginxServicePlan) (*NginxServiceInstallation, error)
	Activate(context.Context, *NginxServiceInstallation) error
	Commit(*NginxServiceInstallation) error
	Rollback(context.Context, *NginxServiceInstallation) error
}

type NginxBaselineHealthChecker interface {
	Check(context.Context, string) error
}

type NginxBaselineManager struct {
	paths      store.Paths
	activation nginxBaselineActivator
	service    nginxBaselineService
	health     NginxBaselineHealthChecker
}

func NewNginxBaselineManager(paths store.Paths, activation nginxBaselineActivator, service nginxBaselineService, health NginxBaselineHealthChecker) (*NginxBaselineManager, error) {
	want, err := store.NewPaths(paths.Root)
	if err != nil || paths != want || activation == nil || service == nil || health == nil {
		return nil, fmt.Errorf("nginx baseline dependencies are incomplete")
	}
	return &NginxBaselineManager{paths: paths, activation: activation, service: service, health: health}, nil
}

func NewSystemNginxBaselineManager(paths store.Paths) (*NginxBaselineManager, error) {
	runner := linuxplatform.OSProbeRunner{}
	activation, err := NewNginxActivationManager(paths, runner, OSNginxReloadRunner{})
	if err != nil {
		return nil, err
	}
	service, err := NewNginxServiceManager(paths, runner)
	if err != nil {
		return nil, err
	}
	return NewNginxBaselineManager(paths, activation, service, OSNginxBaselineHealthChecker{})
}

func (manager *NginxBaselineManager) Plan() (NginxBaselinePlan, error) {
	if manager == nil || manager.activation == nil || manager.service == nil || manager.health == nil {
		return NginxBaselinePlan{}, fmt.Errorf("nginx baseline manager is incomplete")
	}
	service, err := manager.service.Plan()
	if err != nil {
		return NginxBaselinePlan{}, err
	}
	return NginxBaselinePlan{Service: service}, nil
}

func (manager *NginxBaselineManager) Apply(ctx context.Context, approved NginxBaselinePlan, request NginxBaselineRequest) (NginxBaselineResult, *NginxBaselineInstallation, error) {
	if ctx == nil {
		return NginxBaselineResult{}, nil, fmt.Errorf("context is required")
	}
	if manager == nil || manager.activation == nil || manager.service == nil || manager.health == nil {
		return NginxBaselineResult{}, nil, fmt.Errorf("nginx baseline manager is incomplete")
	}
	fresh, err := manager.Plan()
	if err != nil || fresh != approved {
		if err == nil {
			err = fmt.Errorf("%w: nginx baseline plan changed", ErrNginxServiceConflict)
		}
		return NginxBaselineResult{}, nil, err
	}
	exposes := make([]model.Expose, len(request.Exposes))
	copy(exposes, request.Exposes)
	candidate, err := RenderNginxConfig(NginxRenderRequest{
		StateGeneration: request.StateGeneration, PublicIPv4: request.PublicIPv4,
		CertificatePath: request.CertificatePath, PrivateKeyPath: request.PrivateKeyPath,
		RuntimeDirectory: NginxRuntimeDirectory(manager.paths), Limits: DefaultGatewayHardLimits(),
		Exposes: exposes,
	})
	if err != nil {
		return NginxBaselineResult{}, nil, err
	}
	activationResult, activation, err := manager.activation.ActivateRetained(ctx, candidate)
	if err != nil {
		return NginxBaselineResult{}, nil, err
	}
	rollbackActivation := func(applyErr error) (NginxBaselineResult, *NginxBaselineInstallation, error) {
		if activation == nil {
			return NginxBaselineResult{}, nil, applyErr
		}
		return NginxBaselineResult{}, nil, errors.Join(applyErr, manager.activation.RollbackRetained(context.Background(), activation))
	}
	service, err := manager.service.Apply(ctx, approved.Service)
	if err != nil {
		return rollbackActivation(err)
	}
	rollbackAll := func(applyErr error) (NginxBaselineResult, *NginxBaselineInstallation, error) {
		return NginxBaselineResult{}, nil, errors.Join(
			applyErr,
			manager.service.Rollback(context.Background(), service),
			func() error {
				if activation == nil {
					return nil
				}
				return manager.activation.RollbackRetained(context.Background(), activation)
			}(),
		)
	}
	if err := manager.service.Activate(ctx, service); err != nil {
		return rollbackAll(err)
	}
	if err := manager.health.Check(ctx, request.PublicIPv4); err != nil {
		return rollbackAll(fmt.Errorf("validate baseline public HTTPS: %w", err))
	}
	result := NginxBaselineResult{
		Changed: activationResult.Changed || approved.Service.Changed, ConfigHash: candidate.ConfigHash(),
		ActiveExposeCount: candidate.ActiveExposeCount(), DropInPath: approved.Service.DropInPath,
	}
	return result, &NginxBaselineInstallation{
		managerRoot: manager.paths.Root, activation: activation, service: service, result: result,
	}, nil
}

func (manager *NginxBaselineManager) Commit(ctx context.Context, installation *NginxBaselineInstallation) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := manager.validateInstallation(installation); err != nil {
		return err
	}
	if installation.activation != nil {
		if err := manager.activation.CommitRetained(ctx, installation.activation); err != nil {
			return err
		}
	}
	return manager.service.Commit(installation.service)
}

func (manager *NginxBaselineManager) Rollback(ctx context.Context, installation *NginxBaselineInstallation) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := manager.validateInstallation(installation); err != nil {
		return err
	}
	serviceErr := manager.service.Rollback(ctx, installation.service)
	var activationErr error
	if installation.activation != nil {
		activationErr = manager.activation.RollbackRetained(ctx, installation.activation)
	}
	return errors.Join(serviceErr, activationErr)
}

func (manager *NginxBaselineManager) validateInstallation(installation *NginxBaselineInstallation) error {
	if manager == nil || installation == nil || installation.managerRoot != manager.paths.Root || installation.service == nil {
		return fmt.Errorf("nginx baseline installation is invalid")
	}
	return nil
}

type OSNginxBaselineHealthChecker struct {
	Dialer net.Dialer
	Now    func() time.Time
}

func (checker OSNginxBaselineHealthChecker) Check(ctx context.Context, publicIPv4 string) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if net.ParseIP(publicIPv4) == nil {
		return fmt.Errorf("public IPv4 is invalid")
	}
	if checker.Now == nil {
		checker.Now = time.Now
	}
	if checker.Dialer.Timeout == 0 {
		checker.Dialer.Timeout = DefaultNginxBaselineHealthTimeout
	}
	bounded, cancel := context.WithTimeout(ctx, DefaultNginxBaselineHealthTimeout)
	defer cancel()
	tlsConfiguration := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         publicIPv4,
		InsecureSkipVerify: true, //nolint:gosec -- the closed verifier below replaces default PKI verification
		VerifyConnection: func(connection tls.ConnectionState) error {
			if len(connection.PeerCertificates) != 1 {
				return fmt.Errorf("nginx baseline must present exactly one certificate")
			}
			return ValidateLivePublicCertificate(connection.PeerCertificates[0], publicIPv4, checker.Now())
		},
	}
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: true, DisableCompression: true,
		TLSHandshakeTimeout: DefaultNginxBaselineHealthTimeout, TLSClientConfig: tlsConfiguration,
		DialContext: func(dialContext context.Context, network, _ string) (net.Conn, error) {
			return checker.Dialer.DialContext(dialContext, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(NginxPublicHTTPSPort)))
		},
	}
	defer transport.CloseIdleConnections()
	return checkNginxBaselineRoutesUntilReady(
		bounded, transport, "https://"+net.JoinHostPort(publicIPv4, strconv.Itoa(NginxPublicHTTPSPort)), nginxBaselineHealthRetryInterval,
	)
}

// checkNginxBaselineRoutesUntilReady closes the systemd Type=simple startup
// race without weakening the health contract. Only transport-level failures
// are retried: a bad certificate or an unexpected HTTP status remains an
// immediate deterministic failure.
func checkNginxBaselineRoutesUntilReady(ctx context.Context, transport http.RoundTripper, endpoint string, interval time.Duration) error {
	if ctx == nil || transport == nil || endpoint == "" || interval <= 0 {
		return fmt.Errorf("nginx baseline retry check is incomplete")
	}
	var last error
	for {
		last = checkNginxBaselineRoutes(ctx, transport, endpoint)
		if last == nil {
			return nil
		}
		if errors.Is(last, context.Canceled) || errors.Is(last, context.DeadlineExceeded) || !isTransientNginxBaselineError(last) {
			return last
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("nginx baseline did not become ready: %w", last)
		case <-timer.C:
		}
	}
}

func isTransientNginxBaselineError(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError)
}

func checkNginxBaselineRoutes(ctx context.Context, transport http.RoundTripper, endpoint string) error {
	if ctx == nil || transport == nil || endpoint == "" {
		return fmt.Errorf("nginx baseline route check is incomplete")
	}
	checks := []struct {
		name, method, path string
		status             int
	}{
		{name: "reserved health", method: http.MethodGet, path: model.ReservedHealthPath, status: http.StatusNoContent},
		// An empty unauthenticated request cannot consume an invite or mutate
		// enrollment state. The handler's deterministic validation response
		// proves that nginx reached the loopback upstream rather than merely
		// serving the public TLS edge.
		{name: "reserved enrollment", method: http.MethodPost, path: model.ReservedEnrollmentPath, status: http.StatusBadRequest},
	}
	for _, check := range checks {
		request, err := http.NewRequestWithContext(ctx, check.method, endpoint+check.path, nil)
		if err != nil {
			return err
		}
		request.Header.Set("User-Agent", "vpnctl-init/readiness")
		response, err := transport.RoundTrip(request)
		if err != nil {
			return fmt.Errorf("%s route: %w", check.name, err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		closeErr := response.Body.Close()
		if closeErr != nil {
			return fmt.Errorf("%s response close: %w", check.name, closeErr)
		}
		if response.StatusCode != check.status {
			return fmt.Errorf("%s returned status %d", check.name, response.StatusCode)
		}
	}
	return nil
}
