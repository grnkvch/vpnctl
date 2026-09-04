package operations

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const (
	DefaultDoctorOverallTimeout = 30 * time.Second
	DefaultDoctorProbeTimeout   = 5 * time.Second
	minimumDoctorTimeout        = 10 * time.Millisecond
	maximumDoctorTimeout        = 5 * time.Minute
)

func ParseDoctorScope(value string) (DoctorScope, error) {
	if value == "" {
		return DoctorScopeDefault, nil
	}
	scope := DoctorScope(value)
	if !validDoctorScope(scope) {
		return "", fmt.Errorf("doctor scope %q is invalid", value)
	}
	return scope, nil
}

type DoctorScope string

const (
	DoctorScopeDefault   DoctorScope = "default"
	DoctorScopeDNS       DoctorScope = "dns"
	DoctorScopeTransport DoctorScope = "transport"
	DoctorScopeTunnel    DoctorScope = "tunnel"
	DoctorScopeIngress   DoctorScope = "ingress"
)

type DoctorProbeKind string

const (
	DoctorProbeDirectDNS       DoctorProbeKind = "direct_dns"
	DoctorProbeGatewayDNS      DoctorProbeKind = "gateway_dns"
	DoctorProbeActiveTransport DoctorProbeKind = "active_transport"
	DoctorProbeTunnelSession   DoctorProbeKind = "tunnel_session"
	DoctorProbeTunnelMapping   DoctorProbeKind = "tunnel_mapping"
	DoctorProbeIngressTLS      DoctorProbeKind = "ingress_tls"
	DoctorProbeIngressHealth   DoctorProbeKind = "ingress_health"
	DoctorProbeLocalUpstream   DoctorProbeKind = "local_upstream"
)

type DoctorProtocol string

const (
	DoctorProtocolDNSUDP DoctorProtocol = "dns_udp"
	DoctorProtocolDNSTCP DoctorProtocol = "dns_tcp"
	DoctorProtocolTCP    DoctorProtocol = "tcp"
	DoctorProtocolUDP    DoctorProtocol = "udp"
	DoctorProtocolTLS    DoctorProtocol = "tls"
	DoctorProtocolHTTPS  DoctorProtocol = "https"
)

type DoctorCheckStatus string

const (
	DoctorCheckPassed  DoctorCheckStatus = "passed"
	DoctorCheckFailed  DoctorCheckStatus = "failed"
	DoctorCheckSkipped DoctorCheckStatus = "skipped"
)

type DoctorLimits struct {
	Overall time.Duration
	Probe   time.Duration
}

func (limits DoctorLimits) normalized() (DoctorLimits, error) {
	if limits.Overall == 0 {
		limits.Overall = DefaultDoctorOverallTimeout
	}
	if limits.Probe == 0 {
		limits.Probe = DefaultDoctorProbeTimeout
	}
	for _, item := range []struct {
		name  string
		value time.Duration
	}{{"overall", limits.Overall}, {"probe", limits.Probe}} {
		if item.value < minimumDoctorTimeout || item.value > maximumDoctorTimeout {
			return DoctorLimits{}, fmt.Errorf("doctor %s timeout must be between %s and %s", item.name, minimumDoctorTimeout, maximumDoctorTimeout)
		}
	}
	if limits.Probe > limits.Overall {
		return DoctorLimits{}, fmt.Errorf("doctor probe timeout must not exceed overall timeout")
	}
	return limits, nil
}

// DoctorProbeRequest is the complete allowlisted input to an active probe
// adapter. Endpoint and HealthPath are execution-only and never enter a report.
// HealthPath can only be vpnctl's fixed reserved health path; an expose/webhook
// path is therefore not representable as a valid doctor request.
type DoctorProbeRequest struct {
	ProbeID       string
	Scope         DoctorScope
	Name          string
	Kind          DoctorProbeKind
	Protocol      DoctorProtocol
	ResourceKind  string
	ResourceID    string
	Endpoint      string
	HealthPath    string
	Transport     model.TransportKind
	OuterProtocol model.NetworkProtocol
}

func (request DoctorProbeRequest) Validate() error {
	if !doctorProbeIDPattern.MatchString(request.ProbeID) {
		return fmt.Errorf("doctor probe ID is invalid")
	}
	if request.Scope != DoctorScopeDNS && request.Scope != DoctorScopeTransport && request.Scope != DoctorScopeTunnel && request.Scope != DoctorScopeIngress {
		return fmt.Errorf("doctor probe scope is invalid")
	}
	if request.Name == "" || len(request.Name) > 128 || !doctorNamePattern.MatchString(request.Name) {
		return fmt.Errorf("doctor probe name is invalid")
	}
	if !statusCodePattern.MatchString(request.ResourceKind) || request.ResourceID == "" || len(request.ResourceKind) > 64 || len(request.ResourceID) > 256 ||
		strings.ContainsAny(request.ResourceKind+request.ResourceID, "\x00\t\r\n") {
		return fmt.Errorf("doctor probe resource identity is invalid")
	}
	if request.Endpoint != "" {
		if err := model.ValidateExposeUpstream(request.Endpoint); err != nil {
			return fmt.Errorf("doctor probe endpoint is invalid: %w", err)
		}
	}
	if request.HealthPath != "" && request.HealthPath != model.ReservedHealthPath {
		return fmt.Errorf("doctor probe HTTP path is not the reserved health path")
	}
	if !validDoctorKindScope(request.Kind, request.Scope) {
		return fmt.Errorf("doctor probe kind/scope is invalid")
	}
	switch request.Kind {
	case DoctorProbeDirectDNS, DoctorProbeGatewayDNS:
		if request.Protocol != DoctorProtocolDNSUDP && request.Protocol != DoctorProtocolDNSTCP {
			return fmt.Errorf("DNS probe protocol is invalid")
		}
		if request.Endpoint == "" || request.HealthPath != "" || request.Transport != "" || request.OuterProtocol != "" {
			return fmt.Errorf("DNS probe target is invalid")
		}
	case DoctorProbeActiveTransport:
		if request.Protocol != DoctorProtocolTCP && request.Protocol != DoctorProtocolUDP {
			return fmt.Errorf("active transport probe protocol is invalid")
		}
		if request.Transport != model.TransportStandard && request.Transport != model.TransportRestricted {
			return fmt.Errorf("active transport selection is invalid")
		}
		if request.OuterProtocol != model.ProtocolTCP && request.OuterProtocol != model.ProtocolUDP {
			return fmt.Errorf("active transport outer protocol is invalid")
		}
		if request.Endpoint != "" || request.HealthPath != "" {
			return fmt.Errorf("active transport probe cannot carry an arbitrary endpoint or path")
		}
	case DoctorProbeTunnelSession, DoctorProbeTunnelMapping, DoctorProbeLocalUpstream:
		if request.Protocol != DoctorProtocolTCP || request.Endpoint == "" || request.HealthPath != "" || request.Transport != "" || request.OuterProtocol != "" {
			return fmt.Errorf("TCP probe target is invalid")
		}
	case DoctorProbeIngressTLS:
		if request.Protocol != DoctorProtocolTLS || request.Endpoint == "" || request.HealthPath != "" || request.Transport != "" || request.OuterProtocol != "" {
			return fmt.Errorf("ingress TLS probe target is invalid")
		}
	case DoctorProbeIngressHealth:
		if request.Protocol != DoctorProtocolHTTPS || request.Endpoint == "" || request.HealthPath != model.ReservedHealthPath || request.Transport != "" || request.OuterProtocol != "" {
			return fmt.Errorf("ingress health probe target is invalid")
		}
	default:
		return fmt.Errorf("doctor probe kind is invalid")
	}
	return nil
}

type DoctorProbeObservation struct {
	Passed bool
	Code   string
}

func (observation DoctorProbeObservation) validate() error {
	if observation.Code == "" || len(observation.Code) > 128 || !statusCodePattern.MatchString(observation.Code) {
		return fmt.Errorf("doctor probe observation code is invalid")
	}
	return nil
}

// DoctorProbeRunner can execute only a prevalidated, closed probe request. It
// receives no desired state, credential reference, expose path, mutation
// coordinator, transport switcher, or provider-registration capability.
type DoctorProbeRunner interface {
	Probe(context.Context, DoctorProbeRequest) (DoctorProbeObservation, error)
}

type DoctorCheck struct {
	Name         string            `json:"name"`
	Scope        DoctorScope       `json:"scope"`
	Kind         DoctorProbeKind   `json:"kind"`
	Protocol     DoctorProtocol    `json:"protocol"`
	ResourceKind string            `json:"resource_kind"`
	ResourceID   string            `json:"resource_id"`
	Status       DoctorCheckStatus `json:"status"`
	Code         string            `json:"code"`
	ElapsedMS    int64             `json:"elapsed_ms"`
}

func (check DoctorCheck) validate() error {
	if check.Name == "" || len(check.Name) > 128 || !doctorNamePattern.MatchString(check.Name) || !statusCodePattern.MatchString(check.ResourceKind) || check.ResourceID == "" ||
		len(check.ResourceKind) > 64 || len(check.ResourceID) > 256 || strings.ContainsAny(check.ResourceKind+check.ResourceID, "\x00\t\r\n") {
		return fmt.Errorf("doctor check identity is invalid")
	}
	if check.Scope != DoctorScopeDNS && check.Scope != DoctorScopeTransport && check.Scope != DoctorScopeTunnel && check.Scope != DoctorScopeIngress {
		return fmt.Errorf("doctor check scope is invalid")
	}
	switch check.Status {
	case DoctorCheckPassed, DoctorCheckFailed, DoctorCheckSkipped:
	default:
		return fmt.Errorf("doctor check status is invalid")
	}
	if check.Code == "" || len(check.Code) > 128 || !statusCodePattern.MatchString(check.Code) || check.ElapsedMS < 0 {
		return fmt.Errorf("doctor check result is invalid")
	}
	if !validDoctorKindProtocol(check.Kind, check.Protocol) {
		return fmt.Errorf("doctor check kind/protocol is invalid")
	}
	if !validDoctorKindScope(check.Kind, check.Scope) {
		return fmt.Errorf("doctor check kind/scope is invalid")
	}
	return nil
}

type DoctorReport struct {
	Role    model.Role    `json:"role"`
	Scope   DoctorScope   `json:"scope"`
	RunID   string        `json:"run_id"`
	Overall StatusOverall `json:"overall"`
	Checks  []DoctorCheck `json:"checks"`
}

func (report DoctorReport) Validate() error {
	if report.Role != model.RoleGateway && report.Role != model.RoleNode {
		return fmt.Errorf("doctor role is invalid")
	}
	if !validDoctorScope(report.Scope) || model.ValidateResourceID(report.RunID) != nil || report.Checks == nil || len(report.Checks) == 0 {
		return fmt.Errorf("doctor report identity or checks are invalid")
	}
	failed := false
	previous := ""
	for index, check := range report.Checks {
		if err := check.validate(); err != nil {
			return fmt.Errorf("doctor check %d: %w", index, err)
		}
		order := doctorCheckOrder(check)
		if previous != "" && order <= previous {
			return fmt.Errorf("doctor checks must be ordered and unique")
		}
		previous = order
		failed = failed || check.Status == DoctorCheckFailed
	}
	if failed && report.Overall != StatusOverallDegraded {
		return fmt.Errorf("failed doctor checks require degraded overall status")
	}
	if !failed && report.Overall != StatusOverallHealthy {
		return fmt.Errorf("doctor report without failures must be healthy")
	}
	return nil
}

type Doctor struct {
	role     model.Role
	state    StatusStateSource
	runner   DoctorProbeRunner
	limits   DoctorLimits
	newRunID func() (string, error)
}

func NewDoctor(role model.Role, state StatusStateSource, runner DoctorProbeRunner, limits DoctorLimits, newRunID func() (string, error)) (*Doctor, error) {
	if role != model.RoleGateway && role != model.RoleNode {
		return nil, fmt.Errorf("doctor role is invalid")
	}
	if nilInterface(state) || nilInterface(runner) {
		return nil, fmt.Errorf("doctor dependencies are incomplete")
	}
	normalized, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	if newRunID == nil {
		newRunID = model.NewUUID
	}
	return &Doctor{role: role, state: state, runner: runner, limits: normalized, newRunID: newRunID}, nil
}

func (doctor *Doctor) Run(ctx context.Context, scope DoctorScope) (DoctorReport, error) {
	if ctx == nil {
		return DoctorReport{}, fmt.Errorf("context is required")
	}
	if doctor == nil || nilInterface(doctor.state) || nilInterface(doctor.runner) || doctor.newRunID == nil {
		return DoctorReport{}, fmt.Errorf("doctor is incomplete")
	}
	if !validDoctorScope(scope) {
		return DoctorReport{}, fmt.Errorf("doctor scope %q is invalid", scope)
	}
	if err := ctx.Err(); err != nil {
		return DoctorReport{}, err
	}
	state, err := doctor.state.ReadStatusState(ctx)
	if err != nil {
		return DoctorReport{}, fmt.Errorf("read doctor state: %w", err)
	}
	if state.Host.Role != doctor.role {
		return DoctorReport{}, fmt.Errorf("doctor state role %q differs from host role %q", state.Host.Role, doctor.role)
	}
	if err := state.Validate(); err != nil {
		return DoctorReport{}, fmt.Errorf("validate doctor state: %w", err)
	}
	runID, err := doctor.newRunID()
	if err != nil || model.ValidateResourceID(runID) != nil {
		return DoctorReport{}, fmt.Errorf("generate doctor run ID")
	}
	requests, checks, err := planDoctorProbes(state, scope, runID)
	if err != nil {
		return DoctorReport{}, err
	}

	overallContext, cancelOverall := context.WithTimeout(ctx, doctor.limits.Overall)
	defer cancelOverall()
	for requestIndex, request := range requests {
		if err := ctx.Err(); err != nil {
			return DoctorReport{}, err
		}
		if overallContext.Err() != nil {
			for _, remaining := range requests[requestIndex:] {
				checks = append(checks, doctorCheckFromRequest(remaining, DoctorCheckSkipped, "overall_deadline_exceeded", 0))
			}
			break
		}
		started := time.Now()
		probeContext, cancelProbe := context.WithTimeout(overallContext, doctor.limits.Probe)
		observation, probeErr := doctor.runner.Probe(probeContext, request)
		probeContextErr := probeContext.Err()
		cancelProbe()
		elapsed := time.Since(started).Milliseconds()
		if err := ctx.Err(); err != nil {
			return DoctorReport{}, err
		}
		status, code := DoctorCheckPassed, observation.Code
		switch {
		case errors.Is(overallContext.Err(), context.DeadlineExceeded):
			status, code = DoctorCheckFailed, "overall_deadline_exceeded"
		case errors.Is(probeContextErr, context.DeadlineExceeded):
			status, code = DoctorCheckFailed, "probe_timeout"
		case probeErr != nil:
			status, code = DoctorCheckFailed, "probe_failed"
		case observation.validate() != nil:
			status, code = DoctorCheckFailed, "invalid_probe_result"
		case !observation.Passed:
			status = DoctorCheckFailed
		}
		checks = append(checks, doctorCheckFromRequest(request, status, code, elapsed))
	}
	sort.Slice(checks, func(left, right int) bool { return doctorCheckOrder(checks[left]) < doctorCheckOrder(checks[right]) })
	report := DoctorReport{Role: doctor.role, Scope: scope, RunID: runID, Overall: StatusOverallHealthy, Checks: checks}
	for _, check := range checks {
		if check.Status == DoctorCheckFailed {
			report.Overall = StatusOverallDegraded
			break
		}
	}
	return report, report.Validate()
}

func planDoctorProbes(state model.State, scope DoctorScope, runID string) ([]DoctorProbeRequest, []DoctorCheck, error) {
	requests := []DoctorProbeRequest{}
	checks := []DoctorCheck{}
	include := func(candidate DoctorScope) bool { return scope == DoctorScopeDefault || scope == candidate }
	if include(DoctorScopeDNS) {
		planned, unavailable, err := planDoctorDNS(state)
		if err != nil {
			return nil, nil, err
		}
		requests = append(requests, planned...)
		checks = append(checks, unavailable...)
	}
	if include(DoctorScopeTransport) {
		planned, skipped := planDoctorTransports(state)
		requests = append(requests, planned...)
		checks = append(checks, skipped...)
	}
	if include(DoctorScopeTunnel) {
		planned, skipped := planDoctorTunnel(state)
		requests = append(requests, planned...)
		checks = append(checks, skipped...)
	}
	if include(DoctorScopeIngress) {
		planned, skipped, err := planDoctorIngress(state)
		if err != nil {
			return nil, nil, err
		}
		requests = append(requests, planned...)
		checks = append(checks, skipped...)
	}
	sort.Slice(requests, func(left, right int) bool {
		return doctorRequestOrder(requests[left]) < doctorRequestOrder(requests[right])
	})
	for index := range requests {
		requests[index].ProbeID = fmt.Sprintf("%s-%03d", runID, index+1)
		if err := requests[index].Validate(); err != nil {
			return nil, nil, fmt.Errorf("validate doctor probe %d: %w", index, err)
		}
	}
	return requests, checks, nil
}

func planDoctorDNS(state model.State) ([]DoctorProbeRequest, []DoctorCheck, error) {
	direct := []string{}
	gateway := []string{}
	if state.Host.Role == model.RoleGateway {
		if state.DNS != nil && state.DNS.Scope == model.DNSUpstreamGateway {
			direct = append(direct, state.DNS.IPv4...)
		}
		for _, cidr := range []string{state.Host.ClientCIDR, state.Host.NodeCIDR} {
			address, err := doctorGatewayAddress(cidr)
			if err != nil {
				return nil, nil, err
			}
			gateway = append(gateway, address)
		}
	} else {
		if state.DNS != nil && state.DNS.Scope == model.DNSUpstreamDirect {
			direct = append(direct, state.DNS.IPv4...)
		}
		if node, ok := localDoctorNode(state); ok {
			gateway = append(gateway, node.Gateway.GatewayOverlayIPv4)
		}
	}
	requests := []DoctorProbeRequest{}
	checks := []DoctorCheck{}
	for _, candidate := range []struct {
		kind      DoctorProbeKind
		name      string
		endpoints []string
	}{{DoctorProbeDirectDNS, "dns.direct", direct}, {DoctorProbeGatewayDNS, "dns.gateway", gateway}} {
		if len(candidate.endpoints) == 0 {
			checks = append(checks, DoctorCheck{
				Name: candidate.name, Scope: DoctorScopeDNS, Kind: candidate.kind, Protocol: DoctorProtocolDNSUDP,
				ResourceKind: "dns_path", ResourceID: strings.TrimPrefix(candidate.name, "dns."), Status: DoctorCheckFailed, Code: "dns_configuration_missing",
			})
			continue
		}
		for index, address := range candidate.endpoints {
			endpoint := net.JoinHostPort(address, "53")
			for _, protocol := range []DoctorProtocol{DoctorProtocolDNSUDP, DoctorProtocolDNSTCP} {
				requests = append(requests, DoctorProbeRequest{
					Scope: DoctorScopeDNS, Name: candidate.name + "." + strings.TrimPrefix(string(protocol), "dns_") + "." + strconv.Itoa(index+1),
					Kind: candidate.kind, Protocol: protocol, ResourceKind: "dns_path", ResourceID: strings.TrimPrefix(candidate.name, "dns."), Endpoint: endpoint,
				})
			}
		}
	}
	return requests, checks, nil
}

func planDoctorTransports(state model.State) ([]DoctorProbeRequest, []DoctorCheck) {
	type activeTransport struct {
		kind     model.TransportKind
		protocol model.NetworkProtocol
	}
	active := map[model.TransportKind]activeTransport{}
	for _, transport := range state.Transports {
		if transport.State != model.TransportActive && transport.State != model.TransportDegraded {
			continue
		}
		active[transport.Kind] = activeTransport{kind: transport.Kind, protocol: transport.Protocol}
	}
	if len(active) == 0 {
		return nil, []DoctorCheck{{
			Name: "transport.active", Scope: DoctorScopeTransport, Kind: DoctorProbeActiveTransport, Protocol: DoctorProtocolTCP,
			ResourceKind: "transport", ResourceID: "active", Status: DoctorCheckSkipped, Code: "no_active_transport",
		}}
	}
	kinds := make([]model.TransportKind, 0, len(active))
	for kind := range active {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(left, right int) bool { return kinds[left] < kinds[right] })
	requests := []DoctorProbeRequest{}
	for _, kind := range kinds {
		for _, protocol := range []DoctorProtocol{DoctorProtocolTCP, DoctorProtocolUDP} {
			requests = append(requests, DoctorProbeRequest{
				Scope: DoctorScopeTransport, Name: "transport." + string(kind) + "." + string(protocol), Kind: DoctorProbeActiveTransport,
				Protocol: protocol, ResourceKind: "transport", ResourceID: string(kind), Transport: kind, OuterProtocol: active[kind].protocol,
			})
		}
	}
	return requests, nil
}

func planDoctorTunnel(state model.State) ([]DoctorProbeRequest, []DoctorCheck) {
	requests := []DoctorProbeRequest{}
	if state.Host.Role == model.RoleGateway {
		requests = append(requests, DoctorProbeRequest{
			Scope: DoctorScopeTunnel, Name: "tunnel.server.tcp", Kind: DoctorProbeTunnelSession, Protocol: DoctorProtocolTCP,
			ResourceKind: "tunnel", ResourceID: "server", Endpoint: net.JoinHostPort("127.0.0.1", strconv.Itoa(tunnel.FRPServerPort)),
		})
	} else if node, ok := localDoctorNode(state); ok {
		requests = append(requests, DoctorProbeRequest{
			Scope: DoctorScopeTunnel, Name: "tunnel.session.tcp", Kind: DoctorProbeTunnelSession, Protocol: DoctorProtocolTCP,
			ResourceKind: "node", ResourceID: node.ID, Endpoint: tunnel.FRPClientStatusAddress,
		})
	} else {
		return nil, []DoctorCheck{{
			Name: "tunnel.session", Scope: DoctorScopeTunnel, Kind: DoctorProbeTunnelSession, Protocol: DoctorProtocolTCP,
			ResourceKind: "tunnel", ResourceID: "session", Status: DoctorCheckSkipped, Code: "node_not_joined",
		}}
	}
	for _, expose := range activeDoctorExposes(state) {
		endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(expose.TunnelPort))
		if state.Host.Role == model.RoleNode {
			endpoint = tunnel.FRPClientStatusAddress
		}
		requests = append(requests, DoctorProbeRequest{
			Scope: DoctorScopeTunnel, Name: "tunnel.mapping." + expose.ID, Kind: DoctorProbeTunnelMapping, Protocol: DoctorProtocolTCP,
			ResourceKind: "expose", ResourceID: expose.ID, Endpoint: endpoint,
		})
	}
	return requests, nil
}

func planDoctorIngress(state model.State) ([]DoctorProbeRequest, []DoctorCheck, error) {
	publicIPv4 := state.Host.PublicIPv4
	if state.Host.Role == model.RoleNode {
		if node, ok := localDoctorNode(state); ok {
			publicIPv4 = node.Gateway.PublicIPv4
		} else {
			return nil, []DoctorCheck{{
				Name: "ingress.public", Scope: DoctorScopeIngress, Kind: DoctorProbeIngressTLS, Protocol: DoctorProtocolTLS,
				ResourceKind: "ingress", ResourceID: "public", Status: DoctorCheckSkipped, Code: "node_not_joined",
			}}, nil
		}
	}
	if address, err := netip.ParseAddr(publicIPv4); err != nil || !address.Is4() || address.String() != publicIPv4 {
		return nil, nil, fmt.Errorf("doctor public ingress IPv4 is invalid")
	}
	endpoint := net.JoinHostPort(publicIPv4, "443")
	requests := []DoctorProbeRequest{
		{
			Scope: DoctorScopeIngress, Name: "ingress.public.tls", Kind: DoctorProbeIngressTLS, Protocol: DoctorProtocolTLS,
			ResourceKind: "ingress", ResourceID: "public", Endpoint: endpoint,
		},
		{
			Scope: DoctorScopeIngress, Name: "ingress.reserved_health.https", Kind: DoctorProbeIngressHealth, Protocol: DoctorProtocolHTTPS,
			ResourceKind: "ingress", ResourceID: "reserved_health", Endpoint: endpoint, HealthPath: model.ReservedHealthPath,
		},
	}
	for _, expose := range activeDoctorExposes(state) {
		if state.Host.Role == model.RoleGateway {
			requests = append(requests, DoctorProbeRequest{
				Scope: DoctorScopeIngress, Name: "ingress.tunnel." + expose.ID, Kind: DoctorProbeTunnelMapping, Protocol: DoctorProtocolTCP,
				ResourceKind: "expose", ResourceID: expose.ID, Endpoint: net.JoinHostPort("127.0.0.1", strconv.Itoa(expose.TunnelPort)),
			})
			continue
		}
		requests = append(requests, DoctorProbeRequest{
			Scope: DoctorScopeIngress, Name: "ingress.tunnel." + expose.ID, Kind: DoctorProbeTunnelMapping, Protocol: DoctorProtocolTCP,
			ResourceKind: "expose", ResourceID: expose.ID, Endpoint: tunnel.FRPClientStatusAddress,
		})
		requests = append(requests, DoctorProbeRequest{
			Scope: DoctorScopeIngress, Name: "ingress.local_upstream." + expose.ID, Kind: DoctorProbeLocalUpstream, Protocol: DoctorProtocolTCP,
			ResourceKind: "expose", ResourceID: expose.ID, Endpoint: expose.Upstream,
		})
	}
	return requests, nil, nil
}

func activeDoctorExposes(state model.State) []model.Expose {
	values := []model.Expose{}
	localNodeID := ""
	if node, ok := localDoctorNode(state); ok {
		localNodeID = node.ID
	}
	for _, expose := range state.Exposes {
		if expose.State == model.ExposeDisabled || state.Host.Role == model.RoleNode && expose.NodeID != localNodeID {
			continue
		}
		values = append(values, expose)
	}
	sort.Slice(values, func(left, right int) bool { return values[left].ID < values[right].ID })
	return values
}

func localDoctorNode(state model.State) (model.Node, bool) {
	if state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Lifecycle != model.LifecycleActive || state.Nodes[0].Gateway == nil {
		return model.Node{}, false
	}
	return state.Nodes[0], true
}

func doctorGatewayAddress(cidr string) (string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix {
		return "", fmt.Errorf("doctor gateway DNS CIDR is invalid")
	}
	address := prefix.Addr().Next()
	if !address.IsValid() || !prefix.Contains(address) {
		return "", fmt.Errorf("doctor gateway DNS CIDR has no listener address")
	}
	return address.String(), nil
}

func doctorCheckFromRequest(request DoctorProbeRequest, status DoctorCheckStatus, code string, elapsedMS int64) DoctorCheck {
	return DoctorCheck{
		Name: request.Name, Scope: request.Scope, Kind: request.Kind, Protocol: request.Protocol,
		ResourceKind: request.ResourceKind, ResourceID: request.ResourceID, Status: status, Code: code, ElapsedMS: elapsedMS,
	}
}

func doctorRequestOrder(request DoctorProbeRequest) string {
	return doctorScopeOrder(request.Scope) + "\x00" + request.Name + "\x00" + request.ResourceKind + "\x00" + request.ResourceID
}

func doctorCheckOrder(check DoctorCheck) string {
	return doctorScopeOrder(check.Scope) + "\x00" + check.Name + "\x00" + check.ResourceKind + "\x00" + check.ResourceID
}

func doctorScopeOrder(scope DoctorScope) string {
	switch scope {
	case DoctorScopeDNS:
		return "1"
	case DoctorScopeTransport:
		return "2"
	case DoctorScopeTunnel:
		return "3"
	case DoctorScopeIngress:
		return "4"
	default:
		return "9"
	}
}

func validDoctorScope(scope DoctorScope) bool {
	return scope == DoctorScopeDefault || scope == DoctorScopeDNS || scope == DoctorScopeTransport || scope == DoctorScopeTunnel || scope == DoctorScopeIngress
}

func validDoctorKindProtocol(kind DoctorProbeKind, protocol DoctorProtocol) bool {
	switch kind {
	case DoctorProbeDirectDNS, DoctorProbeGatewayDNS:
		return protocol == DoctorProtocolDNSUDP || protocol == DoctorProtocolDNSTCP
	case DoctorProbeActiveTransport:
		return protocol == DoctorProtocolTCP || protocol == DoctorProtocolUDP
	case DoctorProbeTunnelSession, DoctorProbeTunnelMapping, DoctorProbeLocalUpstream:
		return protocol == DoctorProtocolTCP
	case DoctorProbeIngressTLS:
		return protocol == DoctorProtocolTLS
	case DoctorProbeIngressHealth:
		return protocol == DoctorProtocolHTTPS
	default:
		return false
	}
}

func validDoctorKindScope(kind DoctorProbeKind, scope DoctorScope) bool {
	switch kind {
	case DoctorProbeDirectDNS, DoctorProbeGatewayDNS:
		return scope == DoctorScopeDNS
	case DoctorProbeActiveTransport:
		return scope == DoctorScopeTransport
	case DoctorProbeTunnelSession:
		return scope == DoctorScopeTunnel
	case DoctorProbeTunnelMapping:
		return scope == DoctorScopeTunnel || scope == DoctorScopeIngress
	case DoctorProbeIngressTLS, DoctorProbeIngressHealth, DoctorProbeLocalUpstream:
		return scope == DoctorScopeIngress
	default:
		return false
	}
}

var (
	doctorProbeIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}-[0-9]{3}$`)
	doctorNamePattern    = regexp.MustCompile(`^[a-z][a-z0-9_.-]*$`)
)
