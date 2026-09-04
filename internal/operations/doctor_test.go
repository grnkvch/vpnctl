package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	doctorRunID             = "11111111-1111-4111-8111-111111111111"
	doctorNodeID            = "22222222-2222-4222-8222-222222222222"
	doctorExposeID          = "33333333-3333-4333-8333-333333333333"
	doctorWebhookPathCanary = "/telegram/webhook-private-canary"
)

func TestDoctorGatewayDefaultPlanIsRoleAwareActiveOnlyAndPathSafe(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	state := doctorGatewayState(t, now)
	source := &auditedStatusStateSource{state: state}
	runner := &recordingDoctorRunner{}
	doctor, err := NewDoctor(model.RoleGateway, source, runner, DoctorLimits{}, fixedDoctorRunID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := doctor.Run(context.Background(), DoctorScopeDefault)
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall != StatusOverallHealthy || report.Scope != DoctorScopeDefault || len(report.Checks) != 15 || source.reads != 1 || source.writes != 0 {
		t.Fatalf("gateway doctor report = %+v; source=%+v", report, source)
	}
	requests := runner.Requests()
	if len(requests) != len(report.Checks) {
		t.Fatalf("gateway requests/checks = %d/%d", len(requests), len(report.Checks))
	}
	seenIDs := map[string]struct{}{}
	protocols := map[DoctorProtocol]bool{}
	for _, request := range requests {
		if err := request.Validate(); err != nil {
			t.Fatalf("invalid planned request %+v: %v", request, err)
		}
		if _, duplicate := seenIDs[request.ProbeID]; duplicate {
			t.Fatalf("duplicate probe ID %s", request.ProbeID)
		}
		seenIDs[request.ProbeID] = struct{}{}
		protocols[request.Protocol] = true
		if request.Kind == DoctorProbeActiveTransport && request.Transport != model.TransportStandard {
			t.Fatalf("standby transport was probed: %+v", request)
		}
		if request.HealthPath != "" && request.HealthPath != model.ReservedHealthPath {
			t.Fatalf("non-reserved path reached runner: %+v", request)
		}
		if strings.Contains(request.HealthPath, "telegram") || strings.Contains(request.Endpoint, doctorWebhookPathCanary) {
			t.Fatalf("webhook path reached runner: %+v", request)
		}
	}
	for _, protocol := range []DoctorProtocol{DoctorProtocolDNSUDP, DoctorProtocolDNSTCP, DoctorProtocolTCP, DoctorProtocolUDP, DoctorProtocolTLS, DoctorProtocolHTTPS} {
		if !protocols[protocol] {
			t.Fatalf("gateway doctor omitted protocol %s: %+v", protocol, requests)
		}
	}
	if runner.switches != 0 || runner.applies != 0 || runner.repairs != 0 || runner.webhooks != 0 {
		t.Fatalf("doctor invoked a mutation/provider action: %+v", runner)
	}
}

func TestDoctorNodeUsesRestrictedSelectionAndKeepsTargetsOutOfReport(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	state := doctorNodeState(t, now)
	runner := &recordingDoctorRunner{}
	doctor, err := NewDoctor(model.RoleNode, &auditedStatusStateSource{state: state}, runner, DoctorLimits{}, fixedDoctorRunID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := doctor.Run(context.Background(), DoctorScopeDefault)
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall != StatusOverallHealthy || len(report.Checks) != 14 {
		t.Fatalf("node doctor report = %+v", report)
	}
	requests := runner.Requests()
	localUpstream, publicTLS, health, tunnelSession := false, false, false, false
	for _, request := range requests {
		switch request.Kind {
		case DoctorProbeActiveTransport:
			if request.Transport != model.TransportRestricted {
				t.Fatalf("node doctor probed standby: %+v", request)
			}
		case DoctorProbeLocalUpstream:
			localUpstream = request.Endpoint == "127.0.0.1:3000" && request.ResourceID == doctorExposeID
		case DoctorProbeIngressTLS:
			publicTLS = request.Endpoint == "203.0.113.10:443"
		case DoctorProbeIngressHealth:
			health = request.HealthPath == model.ReservedHealthPath
		case DoctorProbeTunnelSession:
			tunnelSession = true
		}
	}
	if !localUpstream || !publicTLS || !health || !tunnelSession {
		t.Fatalf("node role coverage missing: upstream=%v tls=%v health=%v tunnel=%v requests=%+v", localUpstream, publicTLS, health, tunnelSession, requests)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"127.0.0.1:3000", "203.0.113.10:443", doctorWebhookPathCanary, model.ReservedHealthPath, "endpoint", "health_path"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("doctor report leaked execution target %q: %s", forbidden, encoded)
		}
	}
}

func TestDoctorExplicitScopeRunsOnlyThatScope(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	runner := &recordingDoctorRunner{}
	doctor, err := NewDoctor(model.RoleNode, &auditedStatusStateSource{state: doctorNodeState(t, now)}, runner, DoctorLimits{}, fixedDoctorRunID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := doctor.Run(context.Background(), DoctorScopeDNS)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Checks) != 6 {
		t.Fatalf("DNS checks = %+v", report.Checks)
	}
	for _, request := range runner.Requests() {
		if request.Scope != DoctorScopeDNS || request.Kind != DoctorProbeDirectDNS && request.Kind != DoctorProbeGatewayDNS {
			t.Fatalf("explicit DNS scope included %+v", request)
		}
	}
}

func TestDoctorDNSPathsFailIndependently(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	runner := &recordingDoctorRunner{failName: "dns.direct.udp.1"}
	doctor, err := NewDoctor(model.RoleNode, &auditedStatusStateSource{state: doctorNodeState(t, now)}, runner, DoctorLimits{}, fixedDoctorRunID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := doctor.Run(context.Background(), DoctorScopeDNS)
	if err != nil {
		t.Fatal(err)
	}
	if report.Overall != StatusOverallDegraded || len(runner.Requests()) != 6 {
		t.Fatalf("independent DNS report = %+v requests=%+v", report, runner.Requests())
	}
	failedDirect, passedGateway := false, 0
	for _, check := range report.Checks {
		failedDirect = failedDirect || check.Name == "dns.direct.udp.1" && check.Status == DoctorCheckFailed
		if check.Kind == DoctorProbeGatewayDNS && check.Status == DoctorCheckPassed {
			passedGateway++
		}
	}
	if !failedDirect || passedGateway != 2 {
		t.Fatalf("direct/gateway isolation = %+v", report.Checks)
	}
}

func TestDoctorEnforcesProbeAndOverallDeadlinesAndDegrades(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	runner := &recordingDoctorRunner{waitForContext: true}
	doctor, err := NewDoctor(model.RoleGateway, &auditedStatusStateSource{state: doctorGatewayState(t, now)}, runner, DoctorLimits{
		Overall: 75 * time.Millisecond,
		Probe:   40 * time.Millisecond,
	}, fixedDoctorRunID)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	report, err := doctor.Run(context.Background(), DoctorScopeDNS)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed > 300*time.Millisecond || report.Overall != StatusOverallDegraded {
		t.Fatalf("bounded doctor elapsed/report = %s / %+v", elapsed, report)
	}
	failed, skipped := 0, 0
	for _, check := range report.Checks {
		switch check.Status {
		case DoctorCheckFailed:
			failed++
			if check.Code != "probe_timeout" && check.Code != "overall_deadline_exceeded" {
				t.Fatalf("deadline failure code = %+v", check)
			}
		case DoctorCheckSkipped:
			skipped++
			if check.Code != "overall_deadline_exceeded" {
				t.Fatalf("deadline skip code = %+v", check)
			}
		}
	}
	if failed == 0 || skipped == 0 || runner.maximumDeadline > 40*time.Millisecond+10*time.Millisecond {
		t.Fatalf("deadline coverage failed=%d skipped=%d max=%s checks=%+v", failed, skipped, runner.maximumDeadline, report.Checks)
	}
}

func TestDoctorSanitizesProbeErrorsAndRejectsInvalidObservations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	secret := "provider-token-secret-canary"
	runner := &recordingDoctorRunner{err: errors.New(secret)}
	doctor, err := NewDoctor(model.RoleNode, &auditedStatusStateSource{state: doctorNodeState(t, now)}, runner, DoctorLimits{}, fixedDoctorRunID)
	if err != nil {
		t.Fatal(err)
	}
	report, err := doctor.Run(context.Background(), DoctorScopeTransport)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(report)
	if report.Overall != StatusOverallDegraded || !bytes.Contains(encoded, []byte("probe_failed")) || bytes.Contains(encoded, []byte(secret)) {
		t.Fatalf("probe error handling = %s", encoded)
	}

	runner = &recordingDoctorRunner{observation: DoctorProbeObservation{Passed: true, Code: "Invalid Code"}, useObservation: true}
	doctor, _ = NewDoctor(model.RoleNode, &auditedStatusStateSource{state: doctorNodeState(t, now)}, runner, DoctorLimits{}, fixedDoctorRunID)
	report, err = doctor.Run(context.Background(), DoctorScopeTransport)
	if err != nil || report.Overall != StatusOverallDegraded || report.Checks[0].Code != "invalid_probe_result" {
		t.Fatalf("invalid observation = %+v, %v", report, err)
	}
}

func TestDoctorCallerCancellationIsNotConvertedToDiagnosticFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	runner := &recordingDoctorRunner{waitForContext: true}
	doctor, err := NewDoctor(model.RoleGateway, &auditedStatusStateSource{state: doctorGatewayState(t, now)}, runner, DoctorLimits{}, fixedDoctorRunID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := doctor.Run(ctx, DoctorScopeDNS); !errors.Is(err, context.Canceled) || len(runner.Requests()) != 0 {
		t.Fatalf("canceled doctor = %v, requests=%+v", err, runner.Requests())
	}
}

type recordingDoctorRunner struct {
	mu              sync.Mutex
	requests        []DoctorProbeRequest
	observation     DoctorProbeObservation
	useObservation  bool
	err             error
	waitForContext  bool
	failName        string
	maximumDeadline time.Duration
	switches        int
	applies         int
	repairs         int
	webhooks        int
}

func (runner *recordingDoctorRunner) Probe(ctx context.Context, request DoctorProbeRequest) (DoctorProbeObservation, error) {
	runner.mu.Lock()
	runner.requests = append(runner.requests, request)
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > runner.maximumDeadline {
			runner.maximumDeadline = remaining
		}
	}
	wait, err, useObservation, observation, failName := runner.waitForContext, runner.err, runner.useObservation, runner.observation, runner.failName
	runner.mu.Unlock()
	if wait {
		<-ctx.Done()
		return DoctorProbeObservation{}, ctx.Err()
	}
	if err != nil {
		return DoctorProbeObservation{}, err
	}
	if request.Name == failName {
		return DoctorProbeObservation{}, errors.New("selected synthetic failure")
	}
	if useObservation {
		return observation, nil
	}
	return DoctorProbeObservation{Passed: true, Code: "probe_passed"}, nil
}

func (runner *recordingDoctorRunner) Requests() []DoctorProbeRequest {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return append([]DoctorProbeRequest{}, runner.requests...)
}

func (runner *recordingDoctorRunner) SwitchTransport() { runner.switches++ }
func (runner *recordingDoctorRunner) Apply()           { runner.applies++ }
func (runner *recordingDoctorRunner) Repair()          { runner.repairs++ }
func (runner *recordingDoctorRunner) RegisterWebhook() { runner.webhooks++ }

func fixedDoctorRunID() (string, error) { return doctorRunID, nil }

func doctorGatewayState(t *testing.T, now time.Time) model.State {
	t.Helper()
	state := statusGatewayState(t, now)
	state.Invites = []model.Invite{}
	state.Logging = []model.LoggingSession{}
	state.Backups[0].CreatedAt = now
	state.Certificates[0].NotAfter = now.AddDate(1, 0, 0)
	state.DNS = &model.DNSUpstreamState{SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamGateway, IPv4: []string{"1.1.1.1", "8.8.8.8"}}
	state.HandshakeHost = doctorHandshakeHost(now)
	state.Nodes = []model.Node{doctorNode(false, now)}
	state.Transports = doctorTransports(model.TransportStandard)
	state.Exposes = []model.Expose{doctorExpose(now)}
	if err := state.Validate(); err != nil {
		t.Fatalf("gateway doctor fixture: %v", err)
	}
	return state
}

func doctorNodeState(t *testing.T, now time.Time) model.State {
	t.Helper()
	state := statusGatewayState(t, now)
	state.Host = model.Host{
		SchemaVersion: model.ResourceSchemaVersion, ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Role: model.RoleNode, OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: now.Add(-24 * time.Hour),
	}
	state.EnrollmentIdentity = nil
	state.Invites = []model.Invite{}
	state.Clients = []model.Client{}
	state.Presets = []model.Preset{}
	state.Policies = []model.Policy{}
	state.Certificates = []model.Certificate{}
	state.Operations = []model.Operation{}
	state.Logging = []model.LoggingSession{}
	state.Backups = []model.Backup{}
	state.DNS = &model.DNSUpstreamState{SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamDirect, IPv4: []string{"1.1.1.1", "8.8.8.8"}}
	state.HandshakeHost = doctorHandshakeHost(now)
	state.Nodes = []model.Node{doctorNode(true, now)}
	state.Transports = doctorTransports(model.TransportRestricted)
	state.Exposes = []model.Expose{doctorExpose(now)}
	if err := state.Validate(); err != nil {
		t.Fatalf("node doctor fixture: %v", err)
	}
	return state
}

func doctorNode(withGateway bool, now time.Time) model.Node {
	node := model.Node{
		SchemaVersion: model.ResourceSchemaVersion, ID: doctorNodeID, Name: "private-node", Lifecycle: model.LifecycleActive,
		OverlayIPv4: "10.67.0.2", CredentialGeneration: 1, AssignedPresets: []string{}, ActiveTransport: model.TransportStandard,
		IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: now.Add(-time.Hour),
	}
	if withGateway {
		node.ActiveTransport = model.TransportRestricted
		node.Gateway = &model.GatewayTrust{
			PublicIPv4: "203.0.113.10", NodeCIDR: "10.67.0.0/24", GatewayOverlayIPv4: "10.67.0.1", ControlProtocol: "1.0",
			EnrollmentFingerprint: "sha256:" + strings.Repeat("e", 64), EnrollmentPublicKeyRef: "enrollment-public:gateway",
			ControlCAFingerprints: []string{"sha256:" + strings.Repeat("f", 64)}, ControlCACertificateRefs: []string{"control-cert:gateway-ca-g1"},
			StandardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", RestrictedServerCredentialRef: "restricted-upstream:gateway-g1",
			LastKnownGatewayGeneration: 8,
		}
	}
	return node
}

func doctorTransports(active model.TransportKind) []model.Transport {
	standardState, restrictedState := model.TransportStandby, model.TransportStandby
	if active == model.TransportStandard {
		standardState = model.TransportActive
	} else {
		restrictedState = model.TransportActive
	}
	return []model.Transport{
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: doctorNodeID,
			Kind: model.TransportStandard, State: standardState, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: 51820,
			CredentialGeneration: 1, CredentialRef: "wireguard-key:doctor-node-g1", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			ConfigHash: strings.Repeat("a", 64),
		},
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: doctorNodeID,
			Kind: model.TransportRestricted, State: restrictedState, Provider: "mihomo", Protocol: model.ProtocolTCP, Port: 8443,
			CredentialGeneration: 1, CredentialRef: "restricted-user:doctor-node-g1", HandshakeHost: "cdn.example.com",
			ConfigHash: strings.Repeat("b", 64),
		},
	}
}

func doctorExpose(now time.Time) model.Expose {
	return model.Expose{
		SchemaVersion: model.ResourceSchemaVersion, ID: doctorExposeID, NodeID: doctorNodeID, Name: "telegram",
		Upstream: "127.0.0.1:3000", RouteMode: model.RouteExact, Path: doctorWebhookPathCanary,
		BodyLimitBytes: 1 << 20, UpstreamTimeoutSeconds: 15, ConcurrentRequests: 10, TunnelPort: 20001,
		State: model.ExposeReady, Generation: 8, CreatedAt: now.Add(-time.Hour),
	}
}

func doctorHandshakeHost(now time.Time) *model.HandshakeHost {
	return &model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "cdn-example",
		Hostname: "cdn.example.com", SelectedAt: now.Add(-24 * time.Hour),
	}
}

func TestDoctorPlanIsDeterministic(t *testing.T) {
	t.Parallel()
	state := doctorGatewayState(t, time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC))
	first, firstChecks, err := planDoctorProbes(state, DoctorScopeDefault, doctorRunID)
	if err != nil {
		t.Fatal(err)
	}
	second, secondChecks, err := planDoctorProbes(state, DoctorScopeDefault, doctorRunID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(firstChecks, secondChecks) {
		t.Fatal("doctor plan is nondeterministic")
	}
}

func TestDoctorProbeRequestRejectsWebhookPathsAndInvalidScopeKindPairs(t *testing.T) {
	t.Parallel()
	request := DoctorProbeRequest{
		ProbeID: doctorRunID + "-001", Scope: DoctorScopeIngress, Name: "ingress.reserved_health.https",
		Kind: DoctorProbeIngressHealth, Protocol: DoctorProtocolHTTPS, ResourceKind: "ingress", ResourceID: "reserved_health",
		Endpoint: "203.0.113.10:443", HealthPath: model.ReservedHealthPath,
	}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	request.HealthPath = doctorWebhookPathCanary
	if err := request.Validate(); err == nil {
		t.Fatal("doctor request accepted a real webhook path")
	}
	request.HealthPath = model.ReservedHealthPath
	request.Scope = DoctorScopeDNS
	if err := request.Validate(); err == nil {
		t.Fatal("doctor request accepted ingress health in DNS scope")
	}
}

func TestParseDoctorScopeDefaultsAndRejectsUnknownValues(t *testing.T) {
	t.Parallel()
	if scope, err := ParseDoctorScope(""); err != nil || scope != DoctorScopeDefault {
		t.Fatalf("empty doctor scope = %q, %v", scope, err)
	}
	for _, value := range []DoctorScope{DoctorScopeDNS, DoctorScopeTransport, DoctorScopeTunnel, DoctorScopeIngress} {
		if scope, err := ParseDoctorScope(string(value)); err != nil || scope != value {
			t.Fatalf("doctor scope %q = %q, %v", value, scope, err)
		}
	}
	if _, err := ParseDoctorScope("all"); err == nil {
		t.Fatal("unknown doctor scope was accepted")
	}
}
