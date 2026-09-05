package tunnel

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

const (
	FRPClientRecoveryGuardDelay   = 2 * time.Second
	FRPClientRecoveryPollInterval = 250 * time.Millisecond

	frpClientRecoveryStopTimeout = 2 * time.Second
)

type FRPClientRecoveryState uint8

const (
	FRPClientRecoveryIndeterminate FRPClientRecoveryState = iota
	FRPClientRecoveryConnected
	FRPClientRecoveryUnavailable
)

type FRPClientRecoveryProber interface {
	RecoveryState(context.Context) FRPClientRecoveryState
}

type FRPClientRecoveryMapping struct {
	Name       string
	LocalAddr  string
	RemoteAddr string
}

type FRPClientStatusRecoveryProber struct {
	status        FRPClientStatusSource
	adminPassword string
	mappings      []FRPClientRecoveryMapping
}

func NewFRPClientStatusRecoveryProber(
	status FRPClientStatusSource,
	adminPassword string,
	mappings []FRPClientRecoveryMapping,
) (*FRPClientStatusRecoveryProber, error) {
	if status == nil || len(mappings) == 0 {
		return nil, fmt.Errorf("frpc recovery probe is incomplete")
	}
	decoded, err := hex.DecodeString(adminPassword)
	defer clear(decoded)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != adminPassword {
		return nil, fmt.Errorf("frpc recovery probe is incomplete")
	}
	seen := make(map[string]struct{}, len(mappings))
	copyMappings := make([]FRPClientRecoveryMapping, len(mappings))
	for index, mapping := range mappings {
		if mapping.Name == "" || strings.TrimSpace(mapping.Name) != mapping.Name || strings.ContainsAny(mapping.Name, " \t\r\n") {
			return nil, fmt.Errorf("frpc recovery mapping is invalid")
		}
		if _, duplicate := seen[mapping.Name]; duplicate {
			return nil, fmt.Errorf("frpc recovery mapping is invalid")
		}
		seen[mapping.Name] = struct{}{}
		local, localErr := netip.ParseAddrPort(mapping.LocalAddr)
		remote, remoteErr := netip.ParseAddrPort(mapping.RemoteAddr)
		if localErr != nil || !local.Addr().IsLoopback() || local.String() != mapping.LocalAddr ||
			remoteErr != nil || !remote.Addr().Is4() || !remote.Addr().IsPrivate() || remote.String() != mapping.RemoteAddr {
			return nil, fmt.Errorf("frpc recovery mapping is invalid")
		}
		copyMappings[index] = mapping
	}
	return &FRPClientStatusRecoveryProber{status: status, adminPassword: adminPassword, mappings: copyMappings}, nil
}

func (prober *FRPClientStatusRecoveryProber) RecoveryState(ctx context.Context) FRPClientRecoveryState {
	if ctx == nil || prober == nil || prober.status == nil || len(prober.mappings) == 0 {
		return FRPClientRecoveryIndeterminate
	}
	statuses, err := prober.status.Status(ctx, prober.adminPassword)
	if err != nil || len(statuses) != len(prober.mappings) {
		return FRPClientRecoveryUnavailable
	}
	byName := make(map[string]FRPProxyStatus, len(statuses))
	for _, status := range statuses {
		if _, duplicate := byName[status.Name]; duplicate {
			return FRPClientRecoveryUnavailable
		}
		byName[status.Name] = status
	}
	connected := false
	indeterminate := false
	for _, mapping := range prober.mappings {
		status, present := byName[mapping.Name]
		if !present || status.Type != "tcp" || status.LocalAddr != mapping.LocalAddr ||
			status.RemoteAddr != mapping.RemoteAddr || status.Plugin != "" || status.Source != "" || status.Err != "" && status.Status == "running" {
			return FRPClientRecoveryUnavailable
		}
		switch status.Status {
		case "running", "check failed":
			connected = true
		case "new", "wait start":
			indeterminate = true
		case "start error", "closed":
		default:
			return FRPClientRecoveryUnavailable
		}
	}
	if connected {
		return FRPClientRecoveryConnected
	}
	if indeterminate {
		return FRPClientRecoveryIndeterminate
	}
	return FRPClientRecoveryUnavailable
}

type frpClientRecoveryTiming struct {
	guardDelay   time.Duration
	pollInterval time.Duration
	stopTimeout  time.Duration
}

func defaultFRPClientRecoveryTiming() frpClientRecoveryTiming {
	return frpClientRecoveryTiming{
		guardDelay: FRPClientRecoveryGuardDelay, pollInterval: FRPClientRecoveryPollInterval,
		stopTimeout: frpClientRecoveryStopTimeout,
	}
}

// RunFRPClientProcessWithRecovery runs one active frpc child. After a working
// client becomes unavailable, one bounded corrective recycle resets a stale
// provider-owned dial/backoff cycle. If that recycle cannot reconnect, frpc
// keeps its own indefinite bounded exponential retry; no standby is attempted.
func RunFRPClientProcessWithRecovery(
	ctx context.Context,
	process FRPProcessRunner,
	binaryPath string,
	arguments []string,
	prober FRPClientRecoveryProber,
) error {
	return runFRPClientProcessWithRecovery(ctx, process, binaryPath, arguments, prober, defaultFRPClientRecoveryTiming())
}

func runFRPClientProcessWithRecovery(
	ctx context.Context,
	process FRPProcessRunner,
	binaryPath string,
	arguments []string,
	prober FRPClientRecoveryProber,
	timing frpClientRecoveryTiming,
) error {
	if ctx == nil || process == nil || prober == nil || binaryPath == "" || !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath ||
		timing.guardDelay <= 0 || timing.pollInterval <= 0 || timing.pollInterval >= timing.guardDelay || timing.stopTimeout <= 0 {
		return fmt.Errorf("frpc recovery supervisor is incomplete")
	}
	start := func() (context.CancelFunc, <-chan error) {
		childContext, cancel := context.WithCancel(ctx)
		result := make(chan error, 1)
		go func() {
			result <- process.Run(childContext, binaryPath, append([]string(nil), arguments...))
		}()
		return cancel, result
	}
	stop := func(cancel context.CancelFunc, result <-chan error) error {
		cancel()
		timer := time.NewTimer(timing.stopTimeout)
		defer timer.Stop()
		select {
		case <-result:
			return nil
		case <-timer.C:
			return fmt.Errorf("frpc recovery supervisor could not stop its child")
		}
	}

	childCancel, childResult := start()
	defer childCancel()
	ticker := time.NewTicker(timing.pollInterval)
	defer ticker.Stop()
	connectedOnce := false
	guardUsed := false
	var unavailableSince time.Time
	for {
		select {
		case <-ctx.Done():
			_ = stop(childCancel, childResult)
			return nil
		case err := <-childResult:
			if ctx.Err() != nil {
				return nil
			}
			if err == nil {
				return errors.New("frpc process exited unexpectedly")
			}
			return errors.New("frpc process failed")
		case observedAt := <-ticker.C:
			switch prober.RecoveryState(ctx) {
			case FRPClientRecoveryConnected:
				connectedOnce = true
				guardUsed = false
				unavailableSince = time.Time{}
			case FRPClientRecoveryUnavailable:
				if !connectedOnce || guardUsed {
					continue
				}
				if unavailableSince.IsZero() {
					unavailableSince = observedAt
					continue
				}
				if observedAt.Sub(unavailableSince) < timing.guardDelay {
					continue
				}
				if err := stop(childCancel, childResult); err != nil {
					return err
				}
				if ctx.Err() != nil {
					return nil
				}
				childCancel, childResult = start()
				guardUsed = true
				unavailableSince = time.Time{}
			case FRPClientRecoveryIndeterminate:
				unavailableSince = time.Time{}
			default:
				unavailableSince = time.Time{}
			}
		}
	}
}

func newFRPClientStatusRecoveryProber(document frpClientDocument, status FRPClientStatusSource) (*FRPClientStatusRecoveryProber, error) {
	if len(document.Mappings) == 0 {
		return nil, nil
	}
	mappings := make([]FRPClientRecoveryMapping, len(document.Mappings))
	for index, mapping := range document.Mappings {
		mappings[index] = FRPClientRecoveryMapping{
			Name: mapping.Name, LocalAddr: mapping.NodeUpstream,
			RemoteAddr: netip.AddrPortFrom(document.ServerEndpoint.Addr(), mapping.GatewayEndpoint.Port()).String(),
		}
	}
	return NewFRPClientStatusRecoveryProber(status, frpAdminPassword(document.TunnelCredential), mappings)
}

var _ FRPClientRecoveryProber = (*FRPClientStatusRecoveryProber)(nil)
