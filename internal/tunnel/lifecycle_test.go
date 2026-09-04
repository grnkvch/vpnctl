package tunnel

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestCredentialRotationWindowAdmitsExactNextGenerationThenFollowsAuthoritativeCommit(t *testing.T) {
	t.Parallel()

	before := tunnelLifecycleGatewayState(t)
	candidate := tunnelLifecycleRotatedState(t, before)
	server, state, credentials := loginAuthorizationFixture(t)
	state.state = before
	nextCredential, err := GenerateCredential(bytes.NewReader(bytes.Repeat([]byte{0x42}, CredentialBytes)))
	if err != nil {
		t.Fatal(err)
	}
	credentials.values[testNodeA+"/2"] = nextCredential

	lease, err := server.BeginCredentialRotation(before, candidate, testNodeA)
	if err != nil {
		t.Fatal(err)
	}
	oldPing := pingAuthorizationContent(t, testNodeA, 1, testTunnelCredential)
	newPing := pingAuthorizationContent(t, testNodeA, 2, string(nextCredential))
	if decision := server.authorizeLogin(loginAuthorizationContent(t, testNodeA, 1, testTunnelCredential, 1)); !decision.allowed {
		t.Fatalf("current Login during staging = %+v", decision)
	}
	if decision := server.authorizeLogin(loginAuthorizationContent(t, testNodeA, 2, string(nextCredential), 1)); !decision.allowed {
		t.Fatalf("candidate Login during staging = %+v", decision)
	}
	mappingName, _ := MappingName(testNodeA, testExposeA)
	if decision := server.authorizeNewProxy(newProxyAuthorizationContent(
		t, testNodeA, 2, string(nextCredential), mappingName, "tcp", 20000, 1,
	)); !decision.allowed {
		t.Fatalf("candidate mapping during staging = %+v", decision)
	}
	if decision := server.authorizePing(oldPing); !decision.allowed {
		t.Fatalf("current generation during staging = %+v", decision)
	}
	if decision := server.authorizePing(newPing); !decision.allowed {
		t.Fatalf("candidate generation during staging = %+v", decision)
	}

	state.mu.Lock()
	state.state = candidate
	state.mu.Unlock()
	if decision := server.authorizePing(oldPing); decision.allowed || decision.unavailable || decision.reason != "generation_mismatch" {
		t.Fatalf("old generation after commit = %+v", decision)
	}
	if decision := server.authorizeLogin(loginAuthorizationContent(t, testNodeA, 1, testTunnelCredential, 1)); decision.allowed || decision.unavailable || decision.reason != "generation_mismatch" {
		t.Fatalf("old Login after commit = %+v", decision)
	}
	if decision := server.authorizePing(newPing); !decision.allowed {
		t.Fatalf("new generation after commit = %+v", decision)
	}
	if err := server.EndCredentialRotation(lease); err != nil {
		t.Fatal(err)
	}
	if decision := server.authorizePing(newPing); !decision.allowed {
		t.Fatalf("committed generation after window removal = %+v", decision)
	}
}

func TestCredentialRotationWindowRollbackAndStateAdvanceFailClosed(t *testing.T) {
	t.Parallel()

	before := tunnelLifecycleGatewayState(t)
	candidate := tunnelLifecycleRotatedState(t, before)
	server, state, credentials := loginAuthorizationFixture(t)
	state.state = before
	nextCredential, err := GenerateCredential(bytes.NewReader(bytes.Repeat([]byte{0x43}, CredentialBytes)))
	if err != nil {
		t.Fatal(err)
	}
	credentials.values[testNodeA+"/2"] = nextCredential
	newPing := pingAuthorizationContent(t, testNodeA, 2, string(nextCredential))

	lease, err := server.BeginCredentialRotation(before, candidate, testNodeA)
	if err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	state.state.Generation++
	state.mu.Unlock()
	if decision := server.authorizePing(newPing); decision.allowed || decision.unavailable || decision.reason != "generation_mismatch" {
		t.Fatalf("staged generation after unrelated state advance = %+v", decision)
	}
	state.mu.Lock()
	state.state = before
	state.mu.Unlock()
	if err := server.EndCredentialRotation(lease); err != nil {
		t.Fatal(err)
	}
	if decision := server.authorizePing(newPing); decision.allowed || decision.unavailable || decision.reason != "generation_mismatch" {
		t.Fatalf("rolled-back generation after window removal = %+v", decision)
	}
}

func TestCredentialRotationWindowRejectsStaleOrIdentityChangingCandidate(t *testing.T) {
	t.Parallel()

	before := tunnelLifecycleGatewayState(t)
	candidate := tunnelLifecycleRotatedState(t, before)
	server, state, credentials := loginAuthorizationFixture(t)
	state.state = before
	nextCredential, err := GenerateCredential(bytes.NewReader(bytes.Repeat([]byte{0x44}, CredentialBytes)))
	if err != nil {
		t.Fatal(err)
	}
	credentials.values[testNodeA+"/2"] = nextCredential

	state.mu.Lock()
	state.state.Generation++
	state.mu.Unlock()
	if _, err := server.BeginCredentialRotation(before, candidate, testNodeA); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale BeginCredentialRotation() error = %v", err)
	}
	state.mu.Lock()
	state.state = before
	state.mu.Unlock()
	changed := tunnelLifecycleRotatedState(t, before)
	changed.Exposes[0].Generation++
	if _, err := server.BeginCredentialRotation(before, changed, testNodeA); err == nil || !strings.Contains(err.Error(), "logical tunnel identity") {
		t.Fatalf("identity-changing BeginCredentialRotation() error = %v", err)
	}
}

func TestPlanFromStatePreservesLogicalIdentityAcrossTransportSwitch(t *testing.T) {
	t.Parallel()

	before := tunnelLifecycleNodeState(t)
	after := cloneTunnelLifecycleState(before)
	after.Generation++
	after.Nodes[0].ActiveTransport = model.TransportRestricted
	for index := range after.Transports {
		switch after.Transports[index].Kind {
		case model.TransportStandard:
			after.Transports[index].State = model.TransportStandby
		case model.TransportRestricted:
			after.Transports[index].State = model.TransportActive
		}
	}
	if err := model.ValidateTransition(before, after); err != nil {
		t.Fatal(err)
	}
	beforePlan, err := PlanFromState(before)
	if err != nil {
		t.Fatal(err)
	}
	afterPlan, err := PlanFromState(after)
	if err != nil {
		t.Fatal(err)
	}
	credentials := &recordingAuthorizationCredentials{values: map[string][]byte{
		testNodeA + "/1": []byte(testTunnelCredential),
	}}
	provider, err := NewFRPProvider("/", testFRPComponent(), credentials)
	if err != nil {
		t.Fatal(err)
	}
	beforeValue, err := provider.Render(context.Background(), RenderRequest{Plan: beforePlan})
	if err != nil {
		t.Fatal(err)
	}
	afterValue, err := provider.Render(context.Background(), RenderRequest{Plan: afterPlan})
	if err != nil {
		t.Fatal(err)
	}
	beforeCandidate := beforeValue.(FRPCandidate)
	afterCandidate := afterValue.(FRPCandidate)
	beforeConfig := beforeCandidate.Bytes()
	afterConfig := afterCandidate.Bytes()
	defer clear(beforeConfig)
	defer clear(afterConfig)
	if !bytes.Equal(beforeConfig, afterConfig) || !reflect.DeepEqual(beforePlan.Nodes[0].Mappings, afterPlan.Nodes[0].Mappings) {
		t.Fatal("transport switch changed tunnel config or logical mappings")
	}
	if beforeCandidate.Descriptor().NodeID != afterCandidate.Descriptor().NodeID ||
		beforeCandidate.Descriptor().CredentialGeneration != afterCandidate.Descriptor().CredentialGeneration ||
		beforeCandidate.Descriptor().ConfigHash != afterCandidate.Descriptor().ConfigHash ||
		beforeCandidate.Descriptor().ActiveTransport == afterCandidate.Descriptor().ActiveTransport {
		t.Fatalf("transport switch tunnel descriptors = %+v / %+v", beforeCandidate.Descriptor(), afterCandidate.Descriptor())
	}
}

func TestPlanFromStateRotatesCredentialButPreservesMappingsAndRejectsRevokedNodePlan(t *testing.T) {
	t.Parallel()

	beforeGateway := tunnelLifecycleGatewayState(t)
	afterGateway := tunnelLifecycleRotatedState(t, beforeGateway)
	before := tunnelLifecycleNodeState(t)
	after := cloneTunnelLifecycleState(before)
	after.Generation++
	after.Nodes[0].CredentialGeneration++
	for index := range after.Transports {
		after.Transports[index].CredentialGeneration++
		after.Transports[index].CredentialRef = model.SecretRef(strings.Replace(after.Transports[index].CredentialRef.String(), "-g1", "-g2", 1))
		after.Transports[index].ConfigHash = strings.Repeat("d", 64)
	}
	if err := model.ValidateTransition(before, after); err != nil {
		t.Fatal(err)
	}
	oldPlan, err := PlanFromState(before)
	if err != nil {
		t.Fatal(err)
	}
	newPlan, err := PlanFromState(after)
	if err != nil {
		t.Fatal(err)
	}
	newCredential, err := GenerateCredential(bytes.NewReader(bytes.Repeat([]byte{0x45}, CredentialBytes)))
	if err != nil {
		t.Fatal(err)
	}
	credentials := &recordingAuthorizationCredentials{values: map[string][]byte{
		testNodeA + "/1": []byte(testTunnelCredential), testNodeA + "/2": newCredential,
	}}
	provider, err := NewFRPProvider("/", testFRPComponent(), credentials)
	if err != nil {
		t.Fatal(err)
	}
	oldValue, err := provider.Render(context.Background(), RenderRequest{Plan: oldPlan})
	if err != nil {
		t.Fatal(err)
	}
	newValue, err := provider.Render(context.Background(), RenderRequest{Plan: newPlan})
	if err != nil {
		t.Fatal(err)
	}
	oldCandidate := oldValue.(FRPCandidate)
	newCandidate := newValue.(FRPCandidate)
	if reflect.DeepEqual(oldCandidate.Bytes(), newCandidate.Bytes()) ||
		oldCandidate.Descriptor().CredentialGeneration != 1 || newCandidate.Descriptor().CredentialGeneration != 2 ||
		!reflect.DeepEqual(oldPlan.Nodes[0].Mappings, newPlan.Nodes[0].Mappings) {
		t.Fatalf("credential rotation tunnel candidates = %+v / %+v", oldCandidate.Descriptor(), newCandidate.Descriptor())
	}
	if _, err := PlanFromState(beforeGateway); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanFromState(afterGateway); err != nil {
		t.Fatal(err)
	}
	revoked := cloneTunnelLifecycleState(before)
	revokedAt := revoked.Nodes[0].CreatedAt.Add(time.Hour)
	revoked.Nodes[0].Lifecycle = model.LifecycleRevoked
	revoked.Nodes[0].RevokedAt = &revokedAt
	for index := range revoked.Transports {
		revoked.Transports[index].State = model.TransportDisabled
	}
	revoked.Exposes[0].State = model.ExposeDisabled
	if _, err := PlanFromState(revoked); err == nil || !strings.Contains(err.Error(), "one joined active node") {
		t.Fatalf("revoked node PlanFromState() error = %v", err)
	}
	revokedGateway := cloneTunnelLifecycleState(beforeGateway)
	revokedGateway.Generation++
	revokedGateway.Nodes[0].Lifecycle = model.LifecycleRevoked
	revokedGateway.Nodes[0].RevokedAt = &revokedAt
	for index := range revokedGateway.Transports {
		revokedGateway.Transports[index].State = model.TransportDisabled
	}
	revokedGateway.Exposes[0].State = model.ExposeDisabled
	revokedGateway.Exposes[0].Generation++
	revokedPlan, err := PlanFromState(revokedGateway)
	if err != nil || len(revokedPlan.Nodes) != 0 {
		t.Fatalf("revoked gateway tunnel plan = %+v, %v", revokedPlan, err)
	}
}

func tunnelLifecycleGatewayState(t *testing.T) model.State {
	t.Helper()
	created := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	state := model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 7,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: testGatewayHostID, Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: created,
			PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", SSHPort: 22,
			ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
		},
		HandshakeHost: &model.HandshakeHost{
			SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft",
			Hostname: "www.microsoft.com", SelectedAt: created,
		},
		Nodes: []model.Node{testNode(testNodeA)}, Clients: []model.Client{}, Presets: []model.Preset{}, Policies: []model.Policy{},
		Transports:   tunnelLifecycleTransports(1),
		Exposes:      []model.Expose{testExpose(testExposeA, testNodeA, "telegram", 20000, model.ExposeReady)},
		Certificates: []model.Certificate{}, Operations: []model.Operation{}, Logging: []model.LoggingSession{},
		Backups: []model.Backup{}, Invites: []model.Invite{},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0-dev",
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: 1, StateSchemaMaximum: 1,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1,
			MigrationReversible: true, Components: []model.ComponentPin{testFRPComponent()},
		},
	}
	state.Nodes[0].ActiveTransport = model.TransportStandard
	state.Nodes[0].CreatedAt = created
	state.Exposes[0].CreatedAt = created
	if err := state.Validate(); err != nil {
		t.Fatalf("tunnel lifecycle gateway state: %v", err)
	}
	return state
}

func tunnelLifecycleNodeState(t *testing.T) model.State {
	t.Helper()
	state := cloneTunnelLifecycleState(tunnelLifecycleGatewayState(t))
	state.Host = model.Host{
		SchemaVersion: model.ResourceSchemaVersion, ID: testNodeHostID, Role: model.RoleNode,
		OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: state.Host.InitializedAt,
	}
	state.Nodes[0].Gateway = &model.GatewayTrust{
		PublicIPv4: "203.0.113.10", NodeCIDR: model.DefaultNodeCIDR, GatewayOverlayIPv4: "10.67.0.1",
		ControlProtocol: "1.0", EnrollmentFingerprint: "sha256:" + strings.Repeat("a", 64),
		EnrollmentPublicKeyRef:        "enrollment-public:gateway",
		ControlCAFingerprints:         []string{"sha256:" + strings.Repeat("b", 64)},
		ControlCACertificateRefs:      []string{"control-cert:gateway-ca-g1"},
		StandardPublicKey:             base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32)),
		RestrictedServerCredentialRef: "restricted-upstream:gateway-g1", LastKnownGatewayGeneration: 7,
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("tunnel lifecycle node state: %v", err)
	}
	return state
}

func tunnelLifecycleRotatedState(t *testing.T, before model.State) model.State {
	t.Helper()
	candidate := cloneTunnelLifecycleState(before)
	candidate.Generation++
	candidate.Nodes[0].CredentialGeneration++
	for index := range candidate.Transports {
		candidate.Transports[index].CredentialGeneration++
		candidate.Transports[index].CredentialRef = model.SecretRef(strings.Replace(candidate.Transports[index].CredentialRef.String(), "-g1", "-g2", 1))
		candidate.Transports[index].ConfigHash = strings.Repeat("c", 64)
	}
	if err := model.ValidateTransition(before, candidate); err != nil {
		t.Fatalf("tunnel lifecycle rotation transition: %v", err)
	}
	return candidate
}

func cloneTunnelLifecycleState(source model.State) model.State {
	result := source
	result.Nodes = append([]model.Node(nil), source.Nodes...)
	result.Transports = append([]model.Transport(nil), source.Transports...)
	result.Exposes = append([]model.Expose(nil), source.Exposes...)
	return result
}

func tunnelLifecycleTransports(generation uint64) []model.Transport {
	return []model.Transport{
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: testNodeA,
			Kind: model.TransportStandard, State: model.TransportActive, Provider: "wireguard", Protocol: model.ProtocolUDP,
			Port: 51820, CredentialGeneration: generation, CredentialRef: model.SecretRef("wireguard-key:node-g1"),
			PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32)), ConfigHash: strings.Repeat("a", 64),
		},
		{
			SchemaVersion: model.ResourceSchemaVersion, OwnerKind: model.TargetNode, OwnerID: testNodeA,
			Kind: model.TransportRestricted, State: model.TransportStandby, Provider: "mihomo", Protocol: model.ProtocolTCP,
			Port: 8443, CredentialGeneration: generation, CredentialRef: model.SecretRef("restricted-key:node-g1"),
			HandshakeHost: "www.microsoft.com", ConfigHash: strings.Repeat("b", 64),
		},
	}
}
