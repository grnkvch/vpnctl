package tunnel

import (
	"context"
	"fmt"
	"strings"
	"time"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const (
	frpClientConnectionTimeout  = 10 * time.Second
	frpClientConnectionInterval = 250 * time.Millisecond
)

// FRPClientConnectionProber proves that the zero-mapping initial frpc has one
// established control connection to the exact active-path gateway endpoint.
// The admin status API cannot prove this when its mapping set is empty.
type FRPClientConnectionProber struct {
	runner   linuxplatform.ProbeRunner
	timeout  time.Duration
	interval time.Duration
}

func NewFRPClientConnectionProber(runner linuxplatform.ProbeRunner) (*FRPClientConnectionProber, error) {
	return newFRPClientConnectionProber(runner, frpClientConnectionTimeout, frpClientConnectionInterval)
}

func newFRPClientConnectionProber(runner linuxplatform.ProbeRunner, timeout, interval time.Duration) (*FRPClientConnectionProber, error) {
	if runner == nil || timeout <= 0 || interval <= 0 || interval >= timeout {
		return nil, fmt.Errorf("frp client connection prober dependencies are invalid")
	}
	return &FRPClientConnectionProber{runner: runner, timeout: timeout, interval: interval}, nil
}

func (prober *FRPClientConnectionProber) Probe(ctx context.Context, candidate FRPCandidate) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if prober == nil || prober.runner == nil || prober.timeout <= 0 || prober.interval <= 0 {
		return fmt.Errorf("frp client connection prober is incomplete")
	}
	if candidate.Descriptor().HostRole != "node" {
		return fmt.Errorf("frp client connection readiness requires a node candidate")
	}
	endpoint, err := candidate.ServerEndpoint()
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, prober.timeout)
	defer cancel()
	ticker := time.NewTicker(prober.interval)
	defer ticker.Stop()
	for {
		ready, err := prober.observe(bounded, endpoint.String())
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-bounded.Done():
			return fmt.Errorf("frp client control connection is not ready")
		case <-ticker.C:
		}
	}
}

func (prober *FRPClientConnectionProber) observe(ctx context.Context, endpoint string) (bool, error) {
	result, err := prober.runner.Run(ctx, linuxplatform.ProbeCommand{
		Name: "ss", Args: []string{"-H", "-tnp", "state", "established", "dst", endpoint},
	})
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, fmt.Errorf("observe frp client control connection: %w", err)
	}
	if result.ExitCode != 0 {
		return false, nil
	}
	lines := []string{}
	for _, raw := range strings.Split(string(result.Stdout), "\n") {
		if line := strings.TrimSpace(raw); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) != 1 || !strings.Contains(lines[0], `users:(("frpc",pid=`) {
		return false, nil
	}
	for _, field := range strings.Fields(lines[0]) {
		if field == endpoint {
			return true, nil
		}
	}
	return false, nil
}
