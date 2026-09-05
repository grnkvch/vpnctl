package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestDoctorCommandParsesGlobalJSONAndRoutesPublicEntryPoint(t *testing.T) {
	paths, restore := stubDoctorCommand(t, RoleGateway)
	defer restore()

	doctorBuild = func(received store.Paths, role HostRole) (*operations.Doctor, error) {
		if received != paths || role != RoleGateway {
			t.Fatalf("build = %+v/%s", received, role)
		}
		return &operations.Doctor{}, nil
	}
	doctorRun = func(ctx context.Context, role HostRole, scope operations.DoctorScope, options operations.DoctorOptions, doctor *operations.Doctor) (output.Result, error) {
		if ctx == nil || role != RoleGateway || scope != operations.DoctorScopeTunnel || options.ProbeURL.Present() || doctor == nil {
			t.Fatalf("run = ctx:%v role:%s scope:%s options:%+v doctor:%v", ctx, role, scope, options, doctor)
		}
		return output.NewResult("doctor", output.StatusOK, output.CategorySuccess, output.SafeObject{
			"role": "gateway", "scope": "tunnel", "run_id": "11111111-1111-4111-8111-111111111111",
			"overall": "healthy", "checks": output.SafeList{output.SafeObject{"name": "tunnel.server.tcp", "status": "passed"}},
		}), nil
	}

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"--json", "doctor", "tunnel"}, &stdout, &stderr); code != ExitSuccess {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var document map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["command"] != "doctor" || document["status"] != "ok" || stderr.Len() != 0 {
		t.Fatalf("document=%+v stderr=%q", document, stderr.String())
	}
}

func TestDoctorCommandExplicitURLRemainsRedacted(t *testing.T) {
	_, restore := stubDoctorCommand(t, RoleNode)
	defer restore()

	const canary = "private-probe-canary.example"
	doctorBuild = func(store.Paths, HostRole) (*operations.Doctor, error) { return &operations.Doctor{}, nil }
	doctorRun = func(_ context.Context, role HostRole, scope operations.DoctorScope, options operations.DoctorOptions, _ *operations.Doctor) (output.Result, error) {
		if role != RoleNode || scope != operations.DoctorScopeIngress || !options.ProbeURL.Present() {
			t.Fatalf("run = role:%s scope:%s options:%+v", role, scope, options)
		}
		if err := options.ProbeURL.Use(func(value string) error {
			if value != "https://"+canary+"/health" {
				t.Fatalf("probe URL = %q", value)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return output.NewResult("doctor", output.StatusDegraded, output.CategoryUnavailable, output.SafeObject{
			"role": "node", "scope": "ingress", "run_id": "11111111-1111-4111-8111-111111111111",
			"overall": "degraded", "checks": output.SafeList{output.SafeObject{"name": "external.explicit_https_get", "status": "failed"}},
		}), nil
	}

	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"doctor", "ingress", "--probe-url", "https://" + canary + "/health", "--json"}, &stdout, &stderr); code != ExitUnavailable {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), canary) || strings.Contains(stderr.String(), canary) {
		t.Fatalf("probe URL leaked: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestDoctorCommandRejectsInvalidArgumentsBeforeHostReads(t *testing.T) {
	oldPaths := doctorSystemPaths
	t.Cleanup(func() { doctorSystemPaths = oldPaths })
	doctorSystemPaths = func() store.Paths {
		t.Fatal("invalid doctor arguments reached host paths")
		return store.Paths{}
	}
	for _, args := range [][]string{
		{"--json", "doctor", "unknown"},
		{"doctor", "--probe-url", "http://example.com"},
		{"doctor", "--probe-url", "https://example.com", "--probe-url", "https://example.net"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Execute(args, &stdout, &stderr); code != ExitValidation {
			t.Fatalf("args=%v exit=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "invalid_arguments") || stderr.Len() != 0 {
			t.Fatalf("args=%v stdout=%s stderr=%s", args, stdout.String(), stderr.String())
		}
	}
}

func TestSystemDoctorBuildsForInitializedUnjoinedNode(t *testing.T) {
	t.Parallel()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := cliDNSState(model.RoleNode)
	state.Generation = 1
	if err := stateStore.Save(0, state); err != nil {
		t.Fatal(err)
	}
	doctor, err := buildSystemDoctor(paths, RoleNode)
	if err != nil || doctor == nil {
		t.Fatalf("doctor=%v err=%v", doctor, err)
	}
}

func TestSystemGatewayActiveTransportDoctorFailsClosedWithoutRemoteOrigin(t *testing.T) {
	t.Parallel()
	doctor := &systemActiveTransportDoctor{
		role: model.RoleGateway, state: &doctorCommandStateStore{state: cliDNSState(model.RoleGateway)},
		network: &doctorCommandProbeRunner{},
	}
	observation, err := doctor.ProbeActiveTransport(context.Background(), operations.DoctorProbeRequest{
		ProbeID: "11111111-1111-4111-8111-111111111111-001", Scope: operations.DoctorScopeTransport,
		Name: "transport.standard.tcp", Kind: operations.DoctorProbeActiveTransport,
		Protocol: operations.DoctorProtocolTCP, ResourceKind: "transport", ResourceID: "standard",
		Transport: model.TransportStandard, OuterProtocol: model.ProtocolUDP,
	})
	if err != nil || observation.Passed || observation.Code != "transport_origin_probe_unavailable" {
		t.Fatalf("observation=%+v err=%v", observation, err)
	}
}

func TestSystemNodeActiveTransportDoctorProvesTCPAndSelectedUDPWithoutMutation(t *testing.T) {
	t.Parallel()
	state := cliDoctorJoinedNodeState(t)
	for _, protocol := range []operations.DoctorProtocol{operations.DoctorProtocolTCP, operations.DoctorProtocolUDP} {
		protocol := protocol
		t.Run(string(protocol), func(t *testing.T) {
			t.Parallel()
			stateStore := &doctorCommandStateStore{state: state}
			gateway := &doctorCommandGatewayProbe{}
			network := &doctorCommandProbeRunner{}
			doctor := &systemActiveTransportDoctor{
				role: model.RoleNode, nodeID: state.Nodes[0].ID, state: stateStore, gateway: gateway, network: network,
			}
			observation, err := doctor.ProbeActiveTransport(context.Background(), operations.DoctorProbeRequest{
				ProbeID: "11111111-1111-4111-8111-111111111111-001", Scope: operations.DoctorScopeTransport,
				Name: "transport.restricted." + string(protocol), Kind: operations.DoctorProbeActiveTransport,
				Protocol: protocol, ResourceKind: "transport", ResourceID: "restricted",
				Transport: model.TransportRestricted, OuterProtocol: model.ProtocolTCP,
			})
			if err != nil || !observation.Passed || stateStore.loads != 2 {
				t.Fatalf("observation=%+v loads=%d err=%v", observation, stateStore.loads, err)
			}
			if protocol == operations.DoctorProtocolTCP {
				if gateway.calls != 1 || network.calls != 0 || observation.Code != "active_transport_tcp_passed" {
					t.Fatalf("TCP gateway=%d network=%d observation=%+v", gateway.calls, network.calls, observation)
				}
			} else if gateway.calls != 0 || network.calls != 1 || observation.Code != "active_transport_udp_passed" ||
				network.request.Kind != operations.DoctorProbeGatewayDNS || network.request.Endpoint != "10.67.0.1:53" {
				t.Fatalf("UDP gateway=%d network=%d request=%+v observation=%+v", gateway.calls, network.calls, network.request, observation)
			}
		})
	}
}

type doctorCommandStateStore struct {
	state model.State
	loads int
}

func (state *doctorCommandStateStore) Load() (model.State, error) {
	state.loads++
	return state.state, nil
}

type doctorCommandProbeRunner struct {
	request operations.DoctorProbeRequest
	calls   int
}

func (runner *doctorCommandProbeRunner) Probe(_ context.Context, request operations.DoctorProbeRequest) (operations.DoctorProbeObservation, error) {
	runner.calls++
	runner.request = request
	return operations.DoctorProbeObservation{Passed: true, Code: "probe_passed"}, nil
}

type doctorCommandGatewayProbe struct{ calls int }

func (probe *doctorCommandGatewayProbe) RequireGateway(_ context.Context, nodeID string) error {
	probe.calls++
	if nodeID != "22222222-2222-4222-8222-222222222222" {
		return ErrCommittedGatewayRepairUnavailable
	}
	return nil
}

func cliDoctorJoinedNodeState(t *testing.T) model.State {
	t.Helper()
	now := time.Date(2026, time.September, 6, 12, 0, 0, 0, time.UTC)
	state := cliDNSState(model.RoleNode)
	state.HandshakeHost = &model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "cdn-example",
		Hostname: "cdn.example.com", SelectedAt: now.Add(-time.Hour),
	}
	state.Nodes = []model.Node{{
		SchemaVersion: model.ResourceSchemaVersion, ID: "22222222-2222-4222-8222-222222222222",
		Name: "private-node", Lifecycle: model.LifecycleActive, OverlayIPv4: "10.67.0.2",
		CredentialGeneration: 1, AssignedPresets: []string{}, ActiveTransport: model.TransportRestricted,
		IdempotencyRecords: []model.IdempotencyRecord{}, CreatedAt: now.Add(-time.Hour),
		Gateway: &model.GatewayTrust{
			GatewayID: "90000000-0000-4000-8000-000000000099", PublicIPv4: "203.0.113.10",
			NodeCIDR: "10.67.0.0/24", GatewayOverlayIPv4: "10.67.0.1", ControlProtocol: "1.0",
			EnrollmentFingerprint: "sha256:" + strings.Repeat("e", 64), EnrollmentPublicKeyRef: "enrollment-public:gateway",
			ControlCAFingerprints: []string{"sha256:" + strings.Repeat("f", 64)}, ControlCACertificateRefs: []string{"control-cert:gateway-ca-g1"},
			TunnelCertificateFingerprint: "sha256:" + strings.Repeat("c", 64), TunnelCertificateRef: "tunnel-cert:gateway-g1",
			StandardPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", RestrictedServerCredentialRef: "restricted-upstream:gateway-g1",
			LastKnownGatewayGeneration: 8,
		},
	}}
	state.Transports = []model.Transport{
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: state.Nodes[0].ID,
			Kind: model.TransportStandard, State: model.TransportStandby, Provider: "wireguard", Protocol: model.ProtocolUDP, Port: 51820,
			CredentialGeneration: 1, CredentialRef: "wireguard-key:doctor-node-g1",
			PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ConfigHash: strings.Repeat("a", 64),
		},
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: state.Nodes[0].ID,
			Kind: model.TransportRestricted, State: model.TransportActive, Provider: "mihomo", Protocol: model.ProtocolTCP, Port: 8443,
			CredentialGeneration: 1, CredentialRef: "restricted-user:doctor-node-g1",
			HandshakeHost: "cdn.example.com", ConfigHash: strings.Repeat("b", 64),
		},
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("joined node doctor fixture: %v", err)
	}
	return state
}

func stubDoctorCommand(t *testing.T, role HostRole) (store.Paths, func()) {
	t.Helper()
	oldPaths, oldRole, oldBuild, oldRun := doctorSystemPaths, doctorLoadRole, doctorBuild, doctorRun
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	doctorSystemPaths = func() store.Paths { return paths }
	doctorLoadRole = func(received store.Paths) (HostRole, error) {
		if received != paths {
			t.Fatalf("role paths = %+v, want %+v", received, paths)
		}
		return role, nil
	}
	return paths, func() {
		doctorSystemPaths, doctorLoadRole, doctorBuild, doctorRun = oldPaths, oldRole, oldBuild, oldRun
	}
}
