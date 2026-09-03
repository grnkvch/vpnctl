package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

const joinTestNodeID = "20000000-0000-4000-8000-000000000004"

func TestAtomicJoinPublishesBothHostsAndConsumesInvite(t *testing.T) {
	for _, test := range []struct {
		name      string
		transport model.TransportKind
		presets   []string
	}{
		{name: "restricted with explicit preset", transport: model.TransportRestricted, presets: []string{"TELEGRAM"}},
		{name: "standard with empty policy", transport: model.TransportStandard, presets: []string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
			defer fixture.destroy()
			result, err := fixture.workflow.Join(context.Background(), fixture.token, test.transport, test.presets)
			if err != nil {
				t.Fatalf("Join() error = %v", err)
			}
			if result.NodeID != joinTestNodeID || result.NodeName != "private-node" || result.OverlayIPv4 != "10.67.0.2" ||
				result.ActiveTransport != test.transport || result.GatewayStateGeneration != 3 || result.LocalStateGeneration != 2 ||
				len(result.ReplayHash) != 64 {
				t.Fatalf("join result = %+v", result)
			}
			gateway, _ := fixture.gatewayState.Load()
			nodeState, _ := fixture.nodeState.Load()
			if gateway.Generation != 3 || len(gateway.Nodes) != 1 || gateway.Nodes[0].Gateway != nil ||
				gateway.Invites[0].State != model.InviteConsumed || gateway.Invites[0].ConsumptionHash != result.ReplayHash {
				t.Fatalf("gateway state after join = generation %d nodes %+v invite %+v", gateway.Generation, gateway.Nodes, gateway.Invites[0])
			}
			if nodeState.Generation != 2 || len(nodeState.Nodes) != 1 || nodeState.Nodes[0].Gateway == nil ||
				nodeState.Nodes[0].Gateway.LastKnownGatewayGeneration != gateway.Generation || len(nodeState.Transports) != 2 ||
				len(nodeState.Certificates) != 2 {
				t.Fatalf("node state after join = generation %d nodes %+v transports %d certs %d", nodeState.Generation, nodeState.Nodes, len(nodeState.Transports), len(nodeState.Certificates))
			}
			if len(test.presets) == 0 {
				if len(gateway.Policies) != 0 || len(nodeState.Policies) != 0 || len(result.Presets) != 0 {
					t.Fatalf("empty assignment created policy: gateway=%+v node=%+v result=%+v", gateway.Policies, nodeState.Policies, result.Presets)
				}
			} else if !reflect.DeepEqual(result.Presets, []string{"telegram"}) || len(gateway.Policies) != 1 || len(nodeState.Policies) != 1 ||
				!reflect.DeepEqual(gateway.Policies[0].Selectors, nodeState.Policies[0].Selectors) {
				t.Fatalf("explicit policy mismatch: result=%+v gateway=%+v node=%+v", result.Presets, gateway.Policies, nodeState.Policies)
			}
			assertJoinTransportSelection(t, gateway, test.transport)
			assertJoinTransportSelection(t, nodeState, test.transport)
			assertJoinSecretsAndPrivateKeyBoundary(t, fixture, gateway, nodeState)
		})
	}
}

func TestJoinReadinessFailureLeavesInviteAndBothStatesUnchanged(t *testing.T) {
	report := healthyJoinReadiness()
	report.Tunnel = false
	checker := &recordingJoinReadiness{report: report}
	fixture := newJoinFixture(t, checker)
	defer fixture.destroy()
	_, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportRestricted, []string{"telegram"})
	if err == nil {
		t.Fatal("Join() accepted failed readiness")
	}
	if checker.calls != 1 {
		t.Fatalf("readiness calls = %d", checker.calls)
	}
	assertRejectedJoinHasNoPartialNode(t, fixture)
}

func TestJoinUnknownPresetDoesNotProbeConsumeOrPersist(t *testing.T) {
	checker := &recordingJoinReadiness{report: healthyJoinReadiness()}
	fixture := newJoinFixture(t, checker)
	defer fixture.destroy()
	_, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportRestricted, []string{"unknown"})
	if err == nil {
		t.Fatal("Join() accepted unknown preset")
	}
	if checker.calls != 0 {
		t.Fatalf("unknown preset ran %d readiness checks", checker.calls)
	}
	assertRejectedJoinHasNoPartialNode(t, fixture)
}

func TestJoinWireRejectsSecretSerialization(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	state, _ := fixture.nodeState.Load()
	installation, err := fixture.workflow.credentials.Provision(context.Background(), joinTestNodeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.workflow.credentials.Rollback(context.Background(), installation)
	shared, err := fixture.workflow.credentials.SharedCredentialPayload(installation)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Destroy()
	requestSecret, err := EncodeNodeJoinRequest(model.TransportRestricted, []string{"telegram"}, installation.PublicExchange, shared)
	if err != nil {
		t.Fatal(err)
	}
	defer requestSecret.Destroy()
	if _, err := requestSecret.MarshalJSON(); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("request MarshalJSON() error = %v", err)
	}
	if state.Generation != 1 {
		t.Fatalf("wire test mutated node state generation %d", state.Generation)
	}
}

func TestJoinIdentityAvailabilityRejectsExistingNameAndID(t *testing.T) {
	state := model.State{Nodes: []model.Node{{
		ID: joinTestNodeID, Name: "private-node", Lifecycle: model.LifecycleActive,
	}}}
	if !errors.Is(validateJoinIdentityAvailable(state, "another-node", joinTestNodeID), ErrJoinConflict) {
		t.Fatal("existing immutable node ID was accepted")
	}
	if !errors.Is(validateJoinIdentityAvailable(state, "PRIVATE-NODE", "30000000-0000-4000-8000-000000000003"), ErrJoinConflict) {
		t.Fatal("case-insensitive existing node name was accepted")
	}
}

func TestJoinRejectsSignedResponseAssignmentSubstitution(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	fixture.workflow.exchanger = tamperJoinExchanger{base: fixture.exchanger}
	_, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportRestricted, []string{"telegram"})
	if !errors.Is(err, ErrJoinUncertain) || !errors.Is(err, ErrEnrollmentSignature) {
		t.Fatalf("Join(tampered response) error = %v", err)
	}
	gateway, _ := fixture.gatewayState.Load()
	nodeState, _ := fixture.nodeState.Load()
	if gateway.Invites[0].State != model.InviteConsumed || len(gateway.Nodes) != 1 {
		t.Fatalf("gateway commit disappeared after response substitution: %+v", gateway)
	}
	if nodeState.Generation != 1 || len(nodeState.Nodes) != 0 {
		t.Fatalf("node accepted substituted response: %+v", nodeState)
	}
	references, _ := NewNodeCredentialReferences(joinTestNodeID, 1)
	if _, err := fixture.nodeSecrets.Get(references.ControlPrivateKey); err != nil {
		t.Fatalf("uncertain join deleted reconcilable local identity: %v", err)
	}
}

func TestJoinReadinessReportRequiresEveryProbe(t *testing.T) {
	for _, mutate := range []func(*JoinReadinessReport){
		func(value *JoinReadinessReport) { value.Gateway = false },
		func(value *JoinReadinessReport) { value.Control = false },
		func(value *JoinReadinessReport) { value.Standard = false },
		func(value *JoinReadinessReport) { value.Restricted = false },
		func(value *JoinReadinessReport) { value.Tunnel = false },
	} {
		report := healthyJoinReadiness()
		mutate(&report)
		if !errors.Is(report.Validate(), ErrJoinNotReady) {
			t.Fatalf("incomplete readiness passed: %+v", report)
		}
	}
}

func TestConcurrentJoinReplayCreatesOneIdentityAndRollsBackLoser(t *testing.T) {
	fixture := newJoinFixture(t, joinReadinessChecker{report: healthyJoinReadiness()})
	defer fixture.destroy()
	secondSecrets := newJoinSecretStore(t)
	secondState := newInviteMemoryState(t, joinInitialNodeState(
		time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC),
		func() model.ComponentManifest { state, _ := fixture.gatewayState.Load(); return state.Components }(),
	))
	secondID := "30000000-0000-4000-8000-000000000003"
	second, err := NewNodeJoinWorkflow(secondState, secondSecrets, fixture.exchanger, NodeJoinRuntime{
		Entropy: rand.Reader, Now: func() time.Time { return time.Date(2026, time.September, 3, 12, 1, 0, 0, time.UTC) },
		NewNodeID: func() (string, error) { return secondID, nil }, WireGuardRunner: &joinWireGuardRunner{},
	})
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result NodeJoinResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	start := make(chan struct{})
	var group sync.WaitGroup
	for _, workflow := range []*NodeJoinWorkflow{fixture.workflow, second} {
		group.Add(1)
		go func(workflow *NodeJoinWorkflow) {
			defer group.Done()
			<-start
			result, err := workflow.Join(context.Background(), fixture.token, model.TransportRestricted, []string{"telegram"})
			outcomes <- outcome{result: result, err: err}
		}(workflow)
	}
	close(start)
	group.Wait()
	close(outcomes)
	winnerID := ""
	failures := 0
	for current := range outcomes {
		if current.err == nil {
			winnerID = current.result.NodeID
		} else {
			failures++
		}
	}
	if winnerID == "" || failures != 1 {
		t.Fatalf("concurrent outcomes winner=%q failures=%d", winnerID, failures)
	}
	gateway, _ := fixture.gatewayState.Load()
	if len(gateway.Nodes) != 1 || gateway.Nodes[0].ID != winnerID || gateway.Invites[0].State != model.InviteConsumed {
		t.Fatalf("concurrent gateway result = %+v", gateway)
	}
	loserID := joinTestNodeID
	loserSecrets := fixture.nodeSecrets
	loserState := fixture.nodeState
	if winnerID == joinTestNodeID {
		loserID, loserSecrets, loserState = secondID, secondSecrets, secondState
	}
	local, _ := loserState.Load()
	if len(local.Nodes) != 0 || local.Generation != 1 {
		t.Fatalf("losing node committed local state: %+v", local)
	}
	loserReferences, _ := NewNodeCredentialReferences(loserID, 1)
	for _, reference := range loserReferences.Values() {
		if _, err := loserSecrets.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("loser retained local credential %s: %v", reference, err)
		}
	}
	for _, reference := range []model.SecretRef{
		model.SecretRef("control-cert:" + loserID + "-g1"),
		model.SecretRef("restricted-user:" + loserID + "-g1"),
		model.SecretRef("tunnel-token:" + loserID + "-g1"),
	} {
		if _, err := fixture.gatewaySecrets.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("loser retained gateway credential %s: %v", reference, err)
		}
	}
}

type joinFixture struct {
	token          *output.Secret
	workflow       *NodeJoinWorkflow
	gatewayState   *inviteMemoryState
	nodeState      *inviteMemoryState
	gatewaySecrets *store.SecretStore
	nodeSecrets    *store.SecretStore
	exchanger      *handlerJoinExchanger
}

func newJoinFixture(t *testing.T, checker GatewayJoinReadinessChecker) *joinFixture {
	t.Helper()
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	gatewaySecrets := newJoinSecretStore(t)
	nodeSecrets := newJoinSecretStore(t)
	gatewayStateValue, identity := joinGatewayState(t, gatewaySecrets, now)
	gatewayState := newInviteMemoryState(t, gatewayStateValue)
	manager, err := NewInviteManager(gatewayState, bytes.NewReader(inviteEntropy(91)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.PlanIssue("private-node")
	if err != nil {
		t.Fatal(err)
	}
	issuedInvite, err := manager.CommitIssue(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEnrollmentTranscriptSigner(identity.EnrollmentPrivateKeyPEM, identity.EnrollmentFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	runner := &joinWireGuardRunner{}
	builder, err := NewGatewayJoinBuilder(manager, gatewaySecrets, GatewayJoinRuntime{
		Entropy: rand.Reader, Now: func() time.Time { return now.Add(time.Minute) }, WireGuardRunner: runner, Readiness: checker,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewInviteEnrollmentCoordinator(manager, builder)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewPublicEnrollmentHandler(PublicEnrollmentHandlerConfig{
		PublicIPv4: "203.0.113.10", Signer: signer, Coordinator: coordinator,
		Entropy: rand.Reader, Now: func() time.Time { return now.Add(time.Minute) },
	})
	if err != nil {
		t.Fatal(err)
	}
	exchanger := &handlerJoinExchanger{handler: handler}
	nodeState := newInviteMemoryState(t, joinInitialNodeState(now, gatewayStateValue.Components))
	workflow, err := NewNodeJoinWorkflow(nodeState, nodeSecrets, exchanger, NodeJoinRuntime{
		Entropy: rand.Reader, Now: func() time.Time { return now.Add(time.Minute) },
		NewNodeID: func() (string, error) { return joinTestNodeID, nil }, WireGuardRunner: runner,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &joinFixture{
		token: issuedInvite.Token, workflow: workflow, gatewayState: gatewayState, nodeState: nodeState,
		gatewaySecrets: gatewaySecrets, nodeSecrets: nodeSecrets, exchanger: exchanger,
	}
}

func (fixture *joinFixture) destroy() {
	if fixture != nil && fixture.token != nil {
		fixture.token.Destroy()
	}
}

func joinGatewayState(t *testing.T, secrets *store.SecretStore, now time.Time) (model.State, control.GatewayControlMaterial) {
	t.Helper()
	identity, err := control.GenerateGatewayControlMaterial(
		rand.Reader, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "10.67.0.1", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	entries := []struct {
		reference model.SecretRef
		content   []byte
	}{
		{model.SecretRef(control.ControlCACertificateRef), identity.ControlCACertificatePEM},
		{control.ControlCAPrivateKeyRef, identity.ControlCAPrivateKeyPEM},
		{model.SecretRef(control.EnrollmentPublicKeyRef), identity.EnrollmentPublicKeyPEM},
		{control.EnrollmentPrivateKeyRef, identity.EnrollmentPrivateKeyPEM},
		{transport.GatewayStandardCredentialRef, []byte(joinGatewayWireGuardPrivate())},
	}
	gatewayRestricted, err := restricted.NewGatewaySecret(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	restrictedBytes, err := restricted.EncodeSecret(gatewayRestricted)
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, struct {
		reference model.SecretRef
		content   []byte
	}{transport.GatewayRestrictedCredentialRef, restrictedBytes})
	for _, entry := range entries {
		if err := secrets.PutIfAbsent(entry.reference, entry.content); err != nil {
			t.Fatal(err)
		}
	}
	state := inviteGatewayState(now)
	state.EnrollmentIdentity.Fingerprint = identity.EnrollmentFingerprint
	state.EnrollmentIdentity.PublicKeyRef = control.EnrollmentPublicKeyRef
	state.EnrollmentIdentity.PrivateKeyRef = control.EnrollmentPrivateKeyRef
	state.HandshakeHost = &model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1,
		CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: now,
	}
	ca, err := parseSingleJoinCertificate(identity.ControlCACertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	state.Certificates = []model.Certificate{localJoinedCertificate(
		"10000000-0000-4000-8000-000000000001", state.Host.ID, model.CertificateControlCA,
		model.SecretRef(control.ControlCACertificateRef), control.ControlCAPrivateKeyRef, ca, []string{},
	)}
	state.Presets = []model.Preset{{
		SchemaVersion: model.ResourceSchemaVersion, Name: "telegram",
		SourceHash: strings.Repeat("a", 64), EffectiveHash: strings.Repeat("b", 64),
		Selectors:  []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "telegram.org"}},
		Generation: 1, AppliedAt: now,
	}}
	if err := state.Validate(); err != nil {
		t.Fatalf("join gateway state: %v", err)
	}
	return state, identity
}

func joinInitialNodeState(now time.Time, components model.ComponentManifest) model.State {
	return model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			Role: model.RoleNode, OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: now,
		},
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{},
		Policies: []model.Policy{}, Transports: []model.Transport{}, Exposes: []model.Expose{},
		Certificates: []model.Certificate{}, Operations: []model.Operation{}, Logging: []model.LoggingSession{},
		Backups: []model.Backup{}, Components: components,
	}
}

func newJoinSecretStore(t *testing.T) *store.SecretStore {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, store.SecretDirectoryMode); err != nil {
		t.Fatal(err)
	}
	result, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type joinWireGuardRunner struct{}

func (runner *joinWireGuardRunner) Run(_ context.Context, name string, arguments []string, stdin string) (string, error) {
	switch {
	case name == "wg" && reflect.DeepEqual(arguments, []string{"genkey"}) && stdin == "":
		return testNodeWireGuardPrivate() + "\n", nil
	case name == "wg" && reflect.DeepEqual(arguments, []string{"pubkey"}) && stdin == testNodeWireGuardPrivate()+"\n":
		return testNodeWireGuardPublic() + "\n", nil
	case name == "wg" && reflect.DeepEqual(arguments, []string{"pubkey"}) && stdin == joinGatewayWireGuardPrivate()+"\n":
		return joinGatewayWireGuardPublic() + "\n", nil
	default:
		return "", fmt.Errorf("unexpected WireGuard command %s %v stdin=%q", name, arguments, stdin)
	}
}

func joinGatewayWireGuardPrivate() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
}

func joinGatewayWireGuardPublic() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
}

type handlerJoinExchanger struct {
	handler http.Handler
}

type tamperJoinExchanger struct {
	base NodeJoinExchanger
}

func (exchanger tamperJoinExchanger) Exchange(ctx context.Context, endpoint string, requestBody *output.Secret) (NodeJoinExchangeResult, error) {
	result, err := exchanger.base.Exchange(ctx, endpoint, requestBody)
	if err != nil {
		return result, err
	}
	var envelope PublicEnrollmentResponse
	if err := json.Unmarshal(result.Response, &envelope); err != nil {
		return NodeJoinExchangeResult{CommitPossible: true}, err
	}
	var response nodeJoinWireResponse
	if err := json.Unmarshal(envelope.Data, &response); err != nil {
		return NodeJoinExchangeResult{CommitPossible: true}, err
	}
	response.Assignment.GatewayStateGeneration++
	envelope.Data, err = json.Marshal(response)
	if err != nil {
		return NodeJoinExchangeResult{CommitPossible: true}, err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return NodeJoinExchangeResult{CommitPossible: true}, err
	}
	return NodeJoinExchangeResult{Response: encoded, CommitPossible: true}, nil
}

func (exchanger *handlerJoinExchanger) Exchange(_ context.Context, endpoint string, requestBody *output.Secret) (NodeJoinExchangeResult, error) {
	var body []byte
	if err := requestBody.Use(func(value []byte) error {
		body = append([]byte(nil), value...)
		return nil
	}); err != nil {
		return NodeJoinExchangeResult{}, err
	}
	defer clear(body)
	request := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Content-Type", PublicEnrollmentContentType)
	recorder := httptest.NewRecorder()
	exchanger.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		return NodeJoinExchangeResult{}, fmt.Errorf("gateway rejected join with status %d", recorder.Code)
	}
	return NodeJoinExchangeResult{Response: recorder.Body.Bytes(), CommitPossible: true}, nil
}

type joinReadinessChecker struct {
	report JoinReadinessReport
}

func (checker joinReadinessChecker) Check(_ context.Context, candidate GatewayJoinCandidate) (JoinReadinessReport, error) {
	if candidate.State.Generation == 0 || candidate.Node.ID == "" || len(candidate.ControlCertificatePEM) == 0 ||
		candidate.GatewayWireGuardPublicKey == "" || len(candidate.RestrictedServerCredential()) == 0 {
		return JoinReadinessReport{}, errors.New("incomplete readiness candidate")
	}
	if err := candidate.UseNodeSharedCredentials(func(restrictedCredential, tunnelCredential []byte) error {
		if len(restrictedCredential) == 0 || len(tunnelCredential) == 0 {
			return errors.New("missing shared credentials")
		}
		return nil
	}); err != nil {
		return JoinReadinessReport{}, err
	}
	return checker.report, nil
}

type recordingJoinReadiness struct {
	calls  int
	report JoinReadinessReport
}

func (checker *recordingJoinReadiness) Check(ctx context.Context, candidate GatewayJoinCandidate) (JoinReadinessReport, error) {
	checker.calls++
	return joinReadinessChecker{report: checker.report}.Check(ctx, candidate)
}

func healthyJoinReadiness() JoinReadinessReport {
	return JoinReadinessReport{Gateway: true, Control: true, Standard: true, Restricted: true, Tunnel: true}
}

func assertJoinTransportSelection(t *testing.T, state model.State, active model.TransportKind) {
	t.Helper()
	if len(state.Transports) != 2 {
		t.Fatalf("transport count = %d", len(state.Transports))
	}
	for _, record := range state.Transports {
		want := model.TransportStandby
		if record.Kind == active {
			want = model.TransportActive
		}
		if record.State != want {
			t.Fatalf("transport %s state = %s, want %s", record.Kind, record.State, want)
		}
	}
}

func assertRejectedJoinHasNoPartialNode(t *testing.T, fixture *joinFixture) {
	t.Helper()
	gateway, _ := fixture.gatewayState.Load()
	nodeState, _ := fixture.nodeState.Load()
	if gateway.Generation != 2 || len(gateway.Nodes) != 0 || gateway.Invites[0].State != model.InviteActive ||
		len(gateway.Transports) != 0 || len(gateway.Policies) != 0 || len(gateway.Certificates) != 1 {
		t.Fatalf("rejected join changed gateway state: generation=%d nodes=%d invite=%s transports=%d policies=%d certs=%d",
			gateway.Generation, len(gateway.Nodes), gateway.Invites[0].State, len(gateway.Transports), len(gateway.Policies), len(gateway.Certificates))
	}
	if nodeState.Generation != 1 || len(nodeState.Nodes) != 0 || len(nodeState.Transports) != 0 || len(nodeState.Certificates) != 0 {
		t.Fatalf("rejected join changed node state: %+v", nodeState)
	}
	references, _ := NewNodeCredentialReferences(joinTestNodeID, 1)
	for _, reference := range references.Values() {
		if _, err := fixture.nodeSecrets.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("rejected join retained node credential %s: %v", reference, err)
		}
	}
	for _, reference := range []model.SecretRef{
		model.SecretRef("control-cert:" + joinTestNodeID + "-g1"),
		model.SecretRef("restricted-user:" + joinTestNodeID + "-g1"),
		model.SecretRef("tunnel-token:" + joinTestNodeID + "-g1"),
	} {
		if _, err := fixture.gatewaySecrets.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("rejected join retained gateway material %s: %v", reference, err)
		}
	}
}

func assertJoinSecretsAndPrivateKeyBoundary(t *testing.T, fixture *joinFixture, gateway, nodeState model.State) {
	t.Helper()
	references, _ := NewNodeCredentialReferences(joinTestNodeID, 1)
	nodeRestricted, err := fixture.nodeSecrets.Get(references.RestrictedCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(nodeRestricted)
	gatewayRestricted, err := fixture.gatewaySecrets.Get(references.RestrictedCredential)
	if err != nil || !bytes.Equal(nodeRestricted, gatewayRestricted) {
		t.Fatalf("restricted credential was not shared exactly: %v", err)
	}
	defer clear(gatewayRestricted)
	nodeTunnel, err := fixture.nodeSecrets.Get(references.TunnelCredential)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(nodeTunnel)
	gatewayTunnel, err := fixture.gatewaySecrets.Get(references.TunnelCredential)
	if err != nil || !bytes.Equal(nodeTunnel, gatewayTunnel) {
		t.Fatalf("tunnel credential was not shared exactly: %v", err)
	}
	defer clear(gatewayTunnel)
	controlPrivate, err := fixture.nodeSecrets.Get(references.ControlPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(controlPrivate)
	wireGuardPrivate, err := fixture.nodeSecrets.Get(references.WireGuardPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wireGuardPrivate)
	for _, privateReference := range []model.SecretRef{references.ControlPrivateKey, references.WireGuardPrivateKey} {
		if _, err := fixture.gatewaySecrets.Get(privateReference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("gateway retained node private key %s: %v", privateReference, err)
		}
	}
	encodedGateway, err := model.EncodeState(gateway)
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string][]byte{"control private": controlPrivate, "WireGuard private": wireGuardPrivate} {
		if bytes.Contains(encodedGateway, secret) {
			t.Fatalf("gateway state contains %s", name)
		}
	}
	if nodeState.Nodes[0].Gateway.StandardPublicKey != joinGatewayWireGuardPublic() {
		t.Fatalf("node trust gateway WireGuard key = %q", nodeState.Nodes[0].Gateway.StandardPublicKey)
	}
}
