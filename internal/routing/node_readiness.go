package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

var ErrNodeRoutingNotReady = errors.New("node routing engine is not ready")

type NodeRoutingProbeState string

const (
	NodeRoutingProbePassed NodeRoutingProbeState = "passed"
	NodeRoutingProbeFailed NodeRoutingProbeState = "failed"
)

type NodeRoutingProbeResult struct {
	State NodeRoutingProbeState
	Code  string
}

func (result NodeRoutingProbeResult) Validate() error {
	if result.State != NodeRoutingProbePassed && result.State != NodeRoutingProbeFailed {
		return fmt.Errorf("node routing probe has invalid state")
	}
	if result.Code == "" || strings.TrimSpace(result.Code) != result.Code || strings.ContainsAny(result.Code, " \t\r\n") {
		return fmt.Errorf("node routing probe has invalid code")
	}
	return nil
}

type NodeRoutingReadinessResult struct {
	Candidate NodeRoutingDescriptor
	Service   NodeRoutingProbeResult
	TUN       NodeRoutingProbeResult
	DNSUDP    NodeRoutingProbeResult
	DNSTCP    NodeRoutingProbeResult
}

func (result NodeRoutingReadinessResult) Validate() error {
	if err := result.Candidate.Validate(); err != nil {
		return err
	}
	for name, probe := range map[string]NodeRoutingProbeResult{
		"service": result.Service, "tun": result.TUN, "dns_udp": result.DNSUDP, "dns_tcp": result.DNSTCP,
	} {
		if err := probe.Validate(); err != nil {
			return fmt.Errorf("%s readiness: %w", name, err)
		}
	}
	return nil
}

func (result NodeRoutingReadinessResult) Ready() bool {
	return result.Validate() == nil && result.Service.State == NodeRoutingProbePassed && result.TUN.State == NodeRoutingProbePassed &&
		result.DNSUDP.State == NodeRoutingProbePassed && result.DNSTCP.State == NodeRoutingProbePassed
}

type NodeRoutingReadinessProber interface {
	Probe(context.Context, NodeRoutingCandidate) (NodeRoutingReadinessResult, error)
}

type NodeRoutingReadinessGate struct{ prober NodeRoutingReadinessProber }

func NewNodeRoutingReadinessGate(prober NodeRoutingReadinessProber) (*NodeRoutingReadinessGate, error) {
	if prober == nil {
		return nil, fmt.Errorf("node routing readiness prober is required")
	}
	return &NodeRoutingReadinessGate{prober: prober}, nil
}

type NodeRoutingReadyCandidate struct {
	candidate NodeRoutingCandidate
	result    NodeRoutingReadinessResult
	verified  bool
}

func (candidate NodeRoutingReadyCandidate) Bytes() []byte { return candidate.candidate.Bytes() }

func (candidate NodeRoutingReadyCandidate) Descriptor() NodeRoutingDescriptor {
	return candidate.candidate.Descriptor()
}

func (candidate NodeRoutingReadyCandidate) Readiness() NodeRoutingReadinessResult {
	return candidate.result
}

func (candidate NodeRoutingReadyCandidate) Valid() bool {
	return candidate.verified && candidate.result.Ready() && candidate.result.Candidate == candidate.candidate.Descriptor()
}

type NodeRoutingNotReadyError struct{ Code string }

func (failure *NodeRoutingNotReadyError) Error() string {
	if failure == nil || failure.Code == "" {
		return ErrNodeRoutingNotReady.Error()
	}
	return ErrNodeRoutingNotReady.Error() + ": " + failure.Code
}

func (failure *NodeRoutingNotReadyError) Unwrap() error { return ErrNodeRoutingNotReady }

func (gate *NodeRoutingReadinessGate) Check(ctx context.Context, candidate NodeRoutingCandidate) (NodeRoutingReadyCandidate, NodeRoutingReadinessResult, error) {
	if ctx == nil {
		return NodeRoutingReadyCandidate{}, NodeRoutingReadinessResult{}, fmt.Errorf("context is required")
	}
	if gate == nil || gate.prober == nil {
		return NodeRoutingReadyCandidate{}, NodeRoutingReadinessResult{}, fmt.Errorf("node routing readiness gate is incomplete")
	}
	if err := candidate.Descriptor().Validate(); err != nil {
		return NodeRoutingReadyCandidate{}, NodeRoutingReadinessResult{}, err
	}
	if err := ValidateNodeRoutingConfig(candidate.Bytes(), candidate.Descriptor().DNSMode); err != nil {
		return NodeRoutingReadyCandidate{}, NodeRoutingReadinessResult{}, fmt.Errorf("validate node routing candidate before readiness: %w", err)
	}
	result, err := gate.prober.Probe(ctx, candidate)
	if err != nil {
		return NodeRoutingReadyCandidate{}, NodeRoutingReadinessResult{}, fmt.Errorf("probe node routing readiness: %w", err)
	}
	if err := result.Validate(); err != nil {
		return NodeRoutingReadyCandidate{}, NodeRoutingReadinessResult{}, err
	}
	if result.Candidate != candidate.Descriptor() {
		return NodeRoutingReadyCandidate{}, result, fmt.Errorf("node routing readiness belongs to another candidate")
	}
	if !result.Ready() {
		return NodeRoutingReadyCandidate{}, result, &NodeRoutingNotReadyError{Code: nodeRoutingReadinessFailureCode(result)}
	}
	ready := NodeRoutingReadyCandidate{candidate: candidate, result: result, verified: true}
	return ready, result, nil
}

func nodeRoutingReadinessFailureCode(result NodeRoutingReadinessResult) string {
	for _, probe := range []NodeRoutingProbeResult{result.Service, result.TUN, result.DNSUDP, result.DNSTCP} {
		if probe.State != NodeRoutingProbePassed {
			return probe.Code
		}
	}
	return "node-routing-readiness-invalid"
}

type NodeRoutingSystemReadinessProber struct {
	paths  store.Paths
	runner linuxplatform.ProbeRunner
}

func NewNodeRoutingSystemReadinessProber(paths store.Paths, runner linuxplatform.ProbeRunner) (*NodeRoutingSystemReadinessProber, error) {
	if runner == nil {
		return nil, fmt.Errorf("node routing system readiness runner is required")
	}
	wantConfigDir := filepath.Join(paths.Root, "etc", "vpnctl")
	wantStateDir := filepath.Join(paths.Root, "var", "lib", "vpnctl")
	if paths.Root == "" || !filepath.IsAbs(paths.Root) || filepath.Clean(paths.Root) != paths.Root ||
		paths.ConfigDir != wantConfigDir || paths.StateDir != wantStateDir {
		return nil, fmt.Errorf("node routing readiness paths are invalid")
	}
	return &NodeRoutingSystemReadinessProber{paths: paths, runner: runner}, nil
}

// Probe is passive. It verifies that the installed root-only artifact is the
// exact candidate, then observes the system service, managed TUN, and both DNS
// listener protocols. It does not create traffic or mutate readiness/routes.
func (prober *NodeRoutingSystemReadinessProber) Probe(ctx context.Context, candidate NodeRoutingCandidate) (NodeRoutingReadinessResult, error) {
	if ctx == nil {
		return NodeRoutingReadinessResult{}, fmt.Errorf("context is required")
	}
	if prober == nil || prober.runner == nil {
		return NodeRoutingReadinessResult{}, fmt.Errorf("node routing system readiness prober is incomplete")
	}
	if err := candidate.Descriptor().Validate(); err != nil {
		return NodeRoutingReadinessResult{}, err
	}
	content, err := readNodeRoutingServiceConfig(nodeRoutingConfigPath(prober.paths))
	if err != nil {
		return NodeRoutingReadinessResult{}, err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != candidate.Descriptor().ConfigHash {
		return NodeRoutingReadinessResult{}, fmt.Errorf("installed node routing config differs from readiness candidate")
	}
	result := NodeRoutingReadinessResult{Candidate: candidate.Descriptor()}
	result.Service, err = prober.observe(ctx, []string{"systemctl", "is-active", "--quiet", "vpnctl-routing.service"}, validNodeRoutingService,
		"node-routing-service-ready", "node-routing-service-unavailable")
	if err != nil {
		return NodeRoutingReadinessResult{}, err
	}
	result.TUN, err = prober.observe(ctx, []string{"ip", "-o", "link", "show", "dev", NodeRoutingTUNDevice}, validNodeRoutingTUN,
		"node-routing-tun-ready", "node-routing-tun-unavailable")
	if err != nil {
		return NodeRoutingReadinessResult{}, err
	}
	result.DNSUDP, err = prober.observe(ctx, []string{"ss", "-H", "-lunp", "sport = :1053"}, validNodeRoutingDNSListener,
		"node-routing-dns-udp-ready", "node-routing-dns-udp-unavailable")
	if err != nil {
		return NodeRoutingReadinessResult{}, err
	}
	result.DNSTCP, err = prober.observe(ctx, []string{"ss", "-H", "-ltnp", "sport = :1053"}, validNodeRoutingDNSListener,
		"node-routing-dns-tcp-ready", "node-routing-dns-tcp-unavailable")
	if err != nil {
		return NodeRoutingReadinessResult{}, err
	}
	return result, result.Validate()
}

func (prober *NodeRoutingSystemReadinessProber) observe(
	ctx context.Context,
	command []string,
	validate func(string) bool,
	passedCode, failedCode string,
) (NodeRoutingProbeResult, error) {
	observed, err := prober.runner.Run(ctx, linuxplatform.ProbeCommand{Name: command[0], Args: command[1:]})
	if err != nil {
		return NodeRoutingProbeResult{}, fmt.Errorf("observe node routing readiness: %w", err)
	}
	if observed.ExitCode == 0 && validate(string(observed.Stdout)) {
		return NodeRoutingProbeResult{State: NodeRoutingProbePassed, Code: passedCode}, nil
	}
	return NodeRoutingProbeResult{State: NodeRoutingProbeFailed, Code: failedCode}, nil
}

func validNodeRoutingService(output string) bool { return strings.TrimSpace(output) == "" }

func validNodeRoutingTUN(output string) bool {
	line := strings.TrimSpace(output)
	if line == "" || strings.Count(line, "\n") != 0 || !strings.Contains(line, ": "+NodeRoutingTUNDevice+": <") {
		return false
	}
	start := strings.Index(line, "<")
	if start < 0 {
		return false
	}
	end := strings.Index(line[start:], ">")
	if end < 0 {
		return false
	}
	for _, flag := range strings.Split(line[start+1:start+end], ",") {
		if flag == "UP" {
			return true
		}
	}
	return false
}

func validNodeRoutingDNSListener(output string) bool {
	line := strings.TrimSpace(output)
	if line == "" || strings.Count(line, "\n") != 0 || !strings.Contains(line, `(("mihomo",pid=`) {
		return false
	}
	for _, field := range strings.Fields(line) {
		if field == NodeRoutingDNSListener {
			return true
		}
	}
	return false
}
