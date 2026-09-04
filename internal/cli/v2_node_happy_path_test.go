package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/ingress"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	"github.com/vgrinkevich/vpnctl/internal/output"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

const (
	v2NodeHappyGatewayID  = "71000000-0000-4000-8000-000000000001"
	v2NodeHappyNodeHostID = "71000000-0000-4000-8000-000000000002"
	v2NodeHappyNodeID     = "71000000-0000-4000-8000-000000000003"
	v2NodeHappyExposeID   = "71000000-0000-4000-8000-000000000004"
	v2NodeHappyPublicIP   = "203.0.113.10"
	v2NodeHappyPath       = "/telegram/webhook"
)

// TestV2NodeMinimalCommandsHappyPath is the source-level two-host vertical
// slice for task 16.2. It executes only public CLI arguments. External host
// mutations are deterministic adapters, while state, secret, invite, join,
// certificate export, expose coordination, and controller serialization are
// the production implementations.
func TestV2NodeMinimalCommandsHappyPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	gatewayPaths := newV2NodeHappyPaths(t, "gateway")
	nodePaths := newV2NodeHappyPaths(t, "node")
	gatewayStore, gatewaySecrets, gatewayState := newV2NodeHappyGateway(t, gatewayPaths, now)
	nodeStore, nodeSecrets, nodeState := newV2NodeHappyNode(t, nodePaths, gatewayState.Components, now)
	installV2NodeHappyCommandAdapters(t, gatewayPaths, nodePaths)

	gatewayInitializer := &v2NodeHappyGatewayInitializer{state: gatewayStore, desired: gatewayState}
	gatewayInitBuilder = func(context.Context, store.Paths) (gatewayInitializerAPI, error) { return gatewayInitializer, nil }
	gatewayResult := runV2NodeHappyJSON(t, []string{
		"init", "--gateway", "--public-ip", v2NodeHappyPublicIP,
		"--client-cidr", model.DefaultClientCIDR, "--node-cidr", model.DefaultNodeCIDR,
		"--external-interface", "eth0", "--ssh-port", "22", "--yes", "--json",
	})
	transactionID := gatewayResult.ResourceIDs["transaction_id"]
	if transactionID != "fw-N0DEV2" || gatewayInitializer.applyCalls != 1 {
		t.Fatalf("gateway init result/calls = %+v/%d", gatewayResult, gatewayInitializer.applyCalls)
	}

	confirmResult := runV2NodeHappyJSON(t, []string{"confirm", transactionID, "--json"})
	if confirmResult.Command != "confirm" || confirmResult.Data["changed"] != true {
		t.Fatalf("watchdog confirmation = %+v", confirmResult)
	}

	stopController := startV2NodeHappyController(t, gatewayPaths, gatewayStore, now)
	defer stopController()

	inviteTTY := &v2NodeHappyTerminal{}
	inviteOpenTTY = func() (PromptIO, io.Closer, error) {
		return inviteTTY, io.NopCloser(strings.NewReader("")), nil
	}
	inviteResult := runV2NodeHappyJSON(t, []string{"invite", "bot-server", "--json"})
	if inviteResult.Command != "invite" || inviteTTY.secretWrites != 1 || len(inviteTTY.writtenSecret) == 0 {
		t.Fatalf("invite result/TTY = %+v writes:%d", inviteResult, inviteTTY.secretWrites)
	}
	inviteToken := append([]byte(nil), inviteTTY.writtenSecret...)
	defer clear(inviteToken)
	assertV2NodeHappyAbsent(t, string(inviteToken), inviteResult)

	nodeInitializer := &v2NodeHappyNodeInitializer{state: nodeStore, desired: nodeState}
	nodeInitBuilder = func(context.Context, store.Paths) (nodeInitializerAPI, error) { return nodeInitializer, nil }
	nodeInitResult := runV2NodeHappyJSON(t, []string{"init", "--node", "--yes", "--json"})
	if nodeInitResult.Command != "init.node" || nodeInitializer.applyCalls != 1 {
		t.Fatalf("node init result/calls = %+v/%d", nodeInitResult, nodeInitializer.applyCalls)
	}

	wireGuard := v2NodeHappyWireGuardRunner{}
	inviteManager, err := enrollment.NewInviteManager(gatewayStore, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	joinBuilder, err := enrollment.NewGatewayJoinBuilder(inviteManager, gatewaySecrets, enrollment.GatewayJoinRuntime{
		Now: time.Now, WireGuardRunner: wireGuard, Readiness: v2NodeHappyJoinReadiness{},
	})
	if err != nil {
		t.Fatal(err)
	}
	joinCoordinator, err := enrollment.NewInviteEnrollmentCoordinator(inviteManager, joinBuilder)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentPrivate, err := gatewaySecrets.Get(control.EnrollmentPrivateKeyRef)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(enrollmentPrivate)
	signer, err := enrollment.NewEnrollmentTranscriptSigner(enrollmentPrivate, gatewayState.EnrollmentIdentity.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	publicHandler, err := enrollment.NewPublicEnrollmentHandler(enrollment.PublicEnrollmentHandlerConfig{
		PublicIPv4: v2NodeHappyPublicIP, Signer: signer, Coordinator: joinCoordinator, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	joinWorkflow, err := enrollment.NewNodeJoinWorkflow(
		nodeStore, nodeSecrets, v2NodeHappyJoinExchanger{handler: publicHandler},
		enrollment.NodeJoinRuntime{
			Now: time.Now, NewNodeID: func() (string, error) { return v2NodeHappyNodeID, nil }, WireGuardRunner: wireGuard,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	joinBuild = func(store.Paths) (NodeJoiner, error) { return joinWorkflow, nil }
	joinTTY := &v2NodeHappyTerminal{hiddenSecret: inviteToken}
	joinOpenTTY = func() (PromptIO, io.Closer, error) {
		return joinTTY, io.NopCloser(strings.NewReader("")), nil
	}
	joinResult := runV2NodeHappyJSON(t, []string{"join", "restricted", "telegram", "--yes", "--json"})
	if joinResult.Command != "join" || joinResult.Data["active_transport"] != "restricted" ||
		!equalJSONStrings(joinResult.Data["presets"], []string{"telegram"}) || joinTTY.hiddenReads != 1 {
		t.Fatalf("restricted join result/TTY = %+v reads:%d", joinResult, joinTTY.hiddenReads)
	}
	assertV2NodeHappyAbsent(t, string(inviteToken), joinResult)

	gatewayAfterJoin, err := gatewayStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	nodeAfterJoin, err := nodeStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	assertV2NodeHappyJoinState(t, gatewayAfterJoin, nodeAfterJoin, gatewaySecrets, nodeSecrets)

	trace := &v2NodeHappyTrace{}
	exporter, err := operations.NewPublicCertificateExportEnsurer(gatewaySecrets)
	if err != nil {
		t.Fatal(err)
	}
	exportPath := ingress.DefaultPublicCertificateExportPath(gatewayPaths.ExportsDir)
	normalizer := ingress.NewExposeNormalizer(ingress.ExposeNormalizerRuntime{
		NewUUID: func() (string, error) { return v2NodeHappyExposeID, nil }, Now: time.Now,
	})
	gatewayExpose, err := operations.NewGatewayExposeCoordinatorService(
		gatewayStore, exporter, v2NodeHappyUnavailablePorts{}, &v2NodeHappyIngressPublisher{trace: trace},
		v2NodeHappyDeferredWriter{}, normalizer, exportPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	exposeSaga, err := operations.NewExposeCreateSaga(nodeStore, gatewayExpose, &v2NodeHappyTunnel{trace: trace})
	if err != nil {
		t.Fatal(err)
	}
	exposeBuild = func(store.Paths) (ExposeCreateMutationSaga, error) { return exposeSaga, nil }
	exposeResult := runV2NodeHappyJSON(t, []string{"expose", "3000", "--path", v2NodeHappyPath, "--json"})
	if exposeResult.Command != "expose" || exposeResult.Data["expose_state"] != "ready" ||
		exposeResult.ResourceIDs["expose_id"] != v2NodeHappyExposeID {
		t.Fatalf("first expose result = %+v", exposeResult)
	}
	assertV2NodeHappyAbsent(t, v2NodeHappyPath, exposeResult)
	if !trace.before("tunnel_activate", "ingress_activate") {
		t.Fatalf("expose activation order = %v", trace.events)
	}
	certificatePEM, err := os.ReadFile(exportPath)
	if err != nil || !bytes.Contains(certificatePEM, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("public certificate export = %q, %v", certificatePEM, err)
	}
	gatewayFinal, _ := gatewayStore.Load()
	nodeFinal, _ := nodeStore.Load()
	if len(gatewayFinal.Exposes) != 1 || len(nodeFinal.Exposes) != 1 ||
		gatewayFinal.Exposes[0].Path != v2NodeHappyPath || gatewayFinal.Exposes[0].Upstream != "127.0.0.1:3000" ||
		gatewayFinal.Exposes[0].State != model.ExposeReady || nodeFinal.Exposes[0].State != model.ExposeReady {
		t.Fatalf("final expose state = gateway:%+v node:%+v", gatewayFinal.Exposes, nodeFinal.Exposes)
	}
}

func newV2NodeHappyPaths(t *testing.T, name string) store.Paths {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "vpnctl-v2-"+name+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove owned E2E root %s: %v", root, err)
		}
	})
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{paths.StateDir, paths.RuntimeDir, paths.ExportsDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

func newV2NodeHappyGateway(t *testing.T, paths store.Paths, now time.Time) (*store.StateStore, *store.SecretStore, model.State) {
	t.Helper()
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	identityIDs := v2NodeHappyUUIDs(
		"71000000-0000-4000-8000-000000000011",
		"71000000-0000-4000-8000-000000000012",
	)
	identityProvisioner, err := control.NewGatewayIdentityProvisioner(secrets, control.GatewayIdentityRuntime{
		Entropy: rand.Reader, NewUUID: identityIDs,
	})
	if err != nil {
		t.Fatal(err)
	}
	initializedAt := now.Add(-time.Hour)
	identity, err := identityProvisioner.Provision(context.Background(), control.GatewayIdentityRequest{
		GatewayID: v2NodeHappyGatewayID, NodeCIDR: model.DefaultNodeCIDR, Initialized: initializedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicProvisioner, err := ingress.NewPublicCertificateProvisioner(secrets, ingress.PublicCertificateRuntime{
		Entropy: rand.Reader, NewUUID: v2NodeHappyUUIDs("71000000-0000-4000-8000-000000000013"),
	})
	if err != nil {
		t.Fatal(err)
	}
	publicCertificate, err := publicProvisioner.Provision(context.Background(), ingress.PublicCertificateRequest{
		GatewayID: v2NodeHappyGatewayID, PublicIPv4: v2NodeHappyPublicIP, IssuedAt: initializedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.PutIfAbsent(transport.GatewayStandardCredentialRef, []byte(v2NodeHappyGatewayPrivateKey())); err != nil {
		t.Fatal(err)
	}
	restrictedSecret, err := restricted.NewGatewaySecret(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	restrictedEncoded, err := restricted.EncodeSecret(restrictedSecret)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.PutIfAbsent(transport.GatewayRestrictedCredentialRef, restrictedEncoded); err != nil {
		t.Fatal(err)
	}
	clear(restrictedEncoded)
	manifest := developmentComponentManifest()
	state := model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: v2NodeHappyGatewayID, Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: initializedAt,
			PublicIPv4: v2NodeHappyPublicIP, ExternalInterface: "eth0", SSHPort: 22,
			ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
		},
		EnrollmentIdentity: &identity.EnrollmentIdentity,
		HandshakeHost: &model.HandshakeHost{
			SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1,
			CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: initializedAt,
		},
		DNS: &model.DNSUpstreamState{
			SchemaVersion: model.ResourceSchemaVersion, Scope: model.DNSUpstreamGateway,
			IPv4: model.DefaultGatewayDNSUpstreams(),
		},
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{},
		Presets: []model.Preset{{
			SchemaVersion: model.ResourceSchemaVersion, Name: "telegram",
			SourceHash: strings.Repeat("a", 64), EffectiveHash: strings.Repeat("b", 64),
			Selectors:  []model.Selector{{Kind: model.SelectorDomainSuffix, Value: "telegram.org"}},
			Generation: 1, AppliedAt: initializedAt,
		}},
		Policies: []model.Policy{}, Transports: []model.Transport{}, Exposes: []model.Expose{},
		Certificates: append(append([]model.Certificate{}, identity.Certificates...), publicCertificate.Certificate),
		Operations:   []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{}, Components: manifest,
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("gateway fixture state: %v", err)
	}
	return stateStore, secrets, state
}

func newV2NodeHappyNode(t *testing.T, paths store.Paths, manifest model.ComponentManifest, now time.Time) (*store.StateStore, *store.SecretStore, model.State) {
	t.Helper()
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	state := model.State{
		SchemaVersion: model.StateSchemaVersion, Generation: 1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: v2NodeHappyNodeHostID, Role: model.RoleNode,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: now.Add(-30 * time.Minute),
		},
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{}, Presets: []model.Preset{},
		Policies: []model.Policy{}, Transports: []model.Transport{}, Exposes: []model.Expose{},
		Certificates: []model.Certificate{}, Operations: []model.Operation{}, Logging: []model.LoggingSession{},
		Backups: []model.Backup{}, Components: manifest,
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("node fixture state: %v", err)
	}
	return stateStore, secrets, state
}

type v2NodeHappyGatewayInitializer struct {
	state      *store.StateStore
	desired    model.State
	applyCalls int
}

func (initializer *v2NodeHappyGatewayInitializer) Plan(_ context.Context, input lifecycle.GatewayInitInput) (lifecycle.GatewayInitPlan, error) {
	if input.PublicIPv4 != v2NodeHappyPublicIP || input.ClientCIDR != model.DefaultClientCIDR ||
		input.NodeCIDR != model.DefaultNodeCIDR || input.ExternalInterface != "eth0" || input.ExplicitSSHPort == nil || *input.ExplicitSSHPort != 22 {
		return lifecycle.GatewayInitPlan{}, fmt.Errorf("gateway init did not preserve explicit inputs: %+v", input)
	}
	return lifecycle.GatewayInitPlan{
		Changed: true, HostID: v2NodeHappyGatewayID,
		Network: linuxplatform.GatewayNetworkPlan{
			PublicIPv4: input.PublicIPv4, ClientCIDR: input.ClientCIDR, NodeCIDR: input.NodeCIDR, ExternalInterface: input.ExternalInterface,
		},
		SSH: linuxplatform.SSHPortPlan{Port: 22, Source: linuxplatform.SSHPortFromOverride},
		HandshakeHost: model.HandshakeHost{
			SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1,
			CandidateID: "microsoft", Hostname: "www.microsoft.com", SelectedAt: initializer.desired.Host.InitializedAt,
		},
	}, nil
}

func (initializer *v2NodeHappyGatewayInitializer) Apply(_ context.Context, plan lifecycle.GatewayInitPlan) (lifecycle.GatewayInitResult, error) {
	initializer.applyCalls++
	if err := initializer.state.Save(0, initializer.desired); err != nil {
		return lifecycle.GatewayInitResult{}, err
	}
	return lifecycle.GatewayInitResult{
		Changed: true, HostID: plan.HostID, TransactionID: "fw-N0DEV2", Network: plan.Network,
	}, nil
}

type v2NodeHappyNodeInitializer struct {
	state      *store.StateStore
	desired    model.State
	applyCalls int
}

func (initializer *v2NodeHappyNodeInitializer) Plan(context.Context) (lifecycle.NodeInitPlan, error) {
	return lifecycle.NodeInitPlan{
		Changed: true, HostID: v2NodeHappyNodeHostID,
		Units: []string{"vpnctl-routing-guard.service", "vpnctl-routing.service", "vpnctl-standard.service", "vpnctl-tunnel-client.service"},
	}, nil
}

func (initializer *v2NodeHappyNodeInitializer) Apply(_ context.Context, plan lifecycle.NodeInitPlan) (lifecycle.NodeInitResult, error) {
	initializer.applyCalls++
	if err := initializer.state.Save(0, initializer.desired); err != nil {
		return lifecycle.NodeInitResult{}, err
	}
	return lifecycle.NodeInitResult{Changed: true, HostID: plan.HostID, Units: append([]string{}, plan.Units...)}, nil
}

func installV2NodeHappyCommandAdapters(t *testing.T, gatewayPaths, nodePaths store.Paths) {
	t.Helper()
	originalGatewayPaths, originalGatewayRole, originalGatewayBuilder := gatewayInitSystemPaths, gatewayInitLoadRole, gatewayInitBuilder
	originalGatewayEnv := gatewayInitLookupEnv
	originalConfirmPaths, originalConfirmRole, originalConfirmEnv, originalConfirmRun := confirmSystemPaths, loadConfirmRole, confirmLookupEnv, runWatchdogConfirm
	originalInvitePaths, originalInviteRole, originalInviteBuild, originalInviteTTY := inviteSystemPaths, inviteLoadRole, inviteBuild, inviteOpenTTY
	originalNodePaths, originalNodeRole, originalNodeBuilder := nodeInitSystemPaths, nodeInitLoadRole, nodeInitBuilder
	originalJoinPaths, originalJoinRole, originalJoinBuild, originalJoinTTY := joinSystemPaths, joinLoadRole, joinBuild, joinOpenTTY
	originalExposePaths, originalExposeRole, originalExposeBuild := exposeSystemPaths, exposeLoadRole, exposeBuild
	t.Cleanup(func() {
		gatewayInitSystemPaths, gatewayInitLoadRole, gatewayInitBuilder, gatewayInitLookupEnv = originalGatewayPaths, originalGatewayRole, originalGatewayBuilder, originalGatewayEnv
		confirmSystemPaths, loadConfirmRole, confirmLookupEnv, runWatchdogConfirm = originalConfirmPaths, originalConfirmRole, originalConfirmEnv, originalConfirmRun
		inviteSystemPaths, inviteLoadRole, inviteBuild, inviteOpenTTY = originalInvitePaths, originalInviteRole, originalInviteBuild, originalInviteTTY
		nodeInitSystemPaths, nodeInitLoadRole, nodeInitBuilder = originalNodePaths, originalNodeRole, originalNodeBuilder
		joinSystemPaths, joinLoadRole, joinBuild, joinOpenTTY = originalJoinPaths, originalJoinRole, originalJoinBuild, originalJoinTTY
		exposeSystemPaths, exposeLoadRole, exposeBuild = originalExposePaths, originalExposeRole, originalExposeBuild
	})
	gatewayInitSystemPaths = func() store.Paths { return gatewayPaths }
	gatewayInitLoadRole = loadSystemHostRole
	gatewayInitLookupEnv = func(name string) (string, bool) {
		if name != "SSH_CONNECTION" {
			return "", false
		}
		return "192.0.2.10 55000 203.0.113.10 22", true
	}
	confirmSystemPaths = func() store.Paths { return gatewayPaths }
	loadConfirmRole = loadSystemHostRole
	confirmLookupEnv = func(name string) (string, bool) {
		if name != "SSH_CONNECTION" {
			return "", false
		}
		return "192.0.2.10 55001 203.0.113.10 22", true
	}
	runWatchdogConfirm = func(_ context.Context, paths store.Paths, transactionID, rawSSH string) (operations.WatchdogConfirmation, error) {
		if paths != gatewayPaths || transactionID != "fw-N0DEV2" || rawSSH != "192.0.2.10 55001 203.0.113.10 22" {
			return operations.WatchdogConfirmation{}, fmt.Errorf("watchdog confirmation inputs differ from new SSH session")
		}
		return operations.WatchdogConfirmation{TransactionID: transactionID, CommittedAt: time.Now(), TimerStopped: true}, nil
	}
	inviteSystemPaths = func() store.Paths { return gatewayPaths }
	inviteLoadRole = loadSystemHostRole
	inviteBuild = buildSystemInviteService
	nodeInitSystemPaths = func() store.Paths { return nodePaths }
	nodeInitLoadRole = loadSystemHostRole
	joinSystemPaths = func() store.Paths { return nodePaths }
	joinLoadRole = loadSystemHostRole
	exposeSystemPaths = func() store.Paths { return nodePaths }
	exposeLoadRole = loadSystemHostRole
}

func startV2NodeHappyController(t *testing.T, paths store.Paths, stateStore *store.StateStore, now time.Time) func() {
	t.Helper()
	dns, err := controller.NewGatewayDNSMutationDispatcher(paths, v2NodeHappyProbeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	logging, err := controller.NewGatewayLoggingMutationDispatcher(paths, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := controller.NewGatewayMutationDispatcher(
		dns, logging, controller.NewGatewayInviteMutationDispatcher(nil, time.Now),
	)
	if err != nil {
		t.Fatal(err)
	}
	server, err := controller.NewController(controller.ControllerRuntime{
		Paths: paths, State: stateStore, Observer: v2NodeHappyObserver{}, Dispatcher: dispatcher,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if info, statErr := os.Lstat(paths.ControlSocket); statErr == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		select {
		case serveErr := <-done:
			cancel()
			t.Fatalf("gateway controller stopped before socket readiness: %v", serveErr)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("gateway controller socket did not become ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("gateway controller shutdown: %v", err)
			}
		})
	}
}

type v2NodeHappyProbeRunner struct{}

func (v2NodeHappyProbeRunner) Run(context.Context, linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	return linuxplatform.ProbeResult{}, nil
}

type v2NodeHappyObserver struct{}

func (v2NodeHappyObserver) Observe(_ context.Context, _ model.State) (controller.Observation, error) {
	return controller.Observation{ObservedAt: time.Now(), Units: []controller.UnitObservation{}, Issues: []string{}}, nil
}

type v2NodeHappyTerminal struct {
	hiddenSecret  []byte
	writtenSecret []byte
	hiddenReads   int
	secretWrites  int
}

func (terminal *v2NodeHappyTerminal) ReadVisible(InteractionStep) (string, error) {
	return "yes", nil
}

func (terminal *v2NodeHappyTerminal) ReadHidden(_ InteractionStep, _ int) ([]byte, error) {
	terminal.hiddenReads++
	if len(terminal.hiddenSecret) == 0 {
		return nil, errors.New("no hidden secret configured")
	}
	return append([]byte(nil), terminal.hiddenSecret...), nil
}

func (terminal *v2NodeHappyTerminal) WriteSecret(_ InteractionStep, secret []byte) error {
	terminal.secretWrites++
	terminal.writtenSecret = append([]byte(nil), secret...)
	return nil
}

type v2NodeHappyWireGuardRunner struct{}

func (v2NodeHappyWireGuardRunner) Run(_ context.Context, name string, arguments []string, stdin string) (string, error) {
	switch {
	case name == "wg" && len(arguments) == 1 && arguments[0] == "genkey" && stdin == "":
		return v2NodeHappyNodePrivateKey() + "\n", nil
	case name == "wg" && len(arguments) == 1 && arguments[0] == "pubkey" && stdin == v2NodeHappyNodePrivateKey()+"\n":
		return v2NodeHappyNodePublicKey() + "\n", nil
	case name == "wg" && len(arguments) == 1 && arguments[0] == "pubkey" && stdin == v2NodeHappyGatewayPrivateKey()+"\n":
		return v2NodeHappyGatewayPublicKey() + "\n", nil
	default:
		return "", fmt.Errorf("unexpected WireGuard command %s %v stdin-length=%d", name, arguments, len(stdin))
	}
}

type v2NodeHappyJoinReadiness struct{}

func (v2NodeHappyJoinReadiness) Check(_ context.Context, candidate enrollment.GatewayJoinCandidate) (enrollment.JoinReadinessReport, error) {
	if candidate.State.Generation == 0 || candidate.Node.ID != v2NodeHappyNodeID ||
		len(candidate.ControlCACertificatePEM) == 0 || len(candidate.ControlCertificatePEM) == 0 ||
		candidate.GatewayWireGuardPublicKey != v2NodeHappyGatewayPublicKey() || len(candidate.RestrictedServerCredential()) == 0 {
		return enrollment.JoinReadinessReport{}, errors.New("join readiness received incomplete candidate")
	}
	if err := candidate.UseNodeSharedCredentials(func(restrictedCredential, tunnelCredential []byte) error {
		if len(restrictedCredential) == 0 || len(tunnelCredential) == 0 {
			return errors.New("join readiness received incomplete shared credentials")
		}
		return nil
	}); err != nil {
		return enrollment.JoinReadinessReport{}, err
	}
	return enrollment.JoinReadinessReport{Gateway: true, Control: true, Standard: true, Restricted: true, Tunnel: true}, nil
}

type v2NodeHappyJoinExchanger struct{ handler http.Handler }

func (exchanger v2NodeHappyJoinExchanger) Exchange(_ context.Context, endpoint string, requestBody *output.Secret) (enrollment.NodeJoinExchangeResult, error) {
	var body []byte
	if err := requestBody.Use(func(value []byte) error {
		body = append([]byte(nil), value...)
		return nil
	}); err != nil {
		return enrollment.NodeJoinExchangeResult{}, err
	}
	defer clear(body)
	request := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	request.Header.Set("Content-Type", enrollment.PublicEnrollmentContentType)
	recorder := httptest.NewRecorder()
	exchanger.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		return enrollment.NodeJoinExchangeResult{}, fmt.Errorf("public enrollment status %d", recorder.Code)
	}
	return enrollment.NodeJoinExchangeResult{Response: append([]byte(nil), recorder.Body.Bytes()...), CommitPossible: true}, nil
}

type v2NodeHappyUnavailablePorts struct{}

func (v2NodeHappyUnavailablePorts) Unavailable(context.Context) ([]int, error) { return []int{}, nil }

type v2NodeHappyDeferredWriter struct{}

func (v2NodeHappyDeferredWriter) Register(context.Context, operations.ExposeCreatePlan) (operations.ExposeDeferredRegistration, error) {
	return operations.ExposeDeferredRegistration{}, errors.New("unexpected deferred expose")
}

type v2NodeHappyIngressPublisher struct{ trace *v2NodeHappyTrace }

func (publisher *v2NodeHappyIngressPublisher) Activate(_ context.Context, before, candidate model.State) (operations.GatewayExposeIngressActivation, error) {
	if candidate.Generation != before.Generation+1 || len(candidate.Exposes) == 0 {
		return operations.GatewayExposeIngressActivation{}, errors.New("invalid ingress activation candidate")
	}
	expose := candidate.Exposes[len(candidate.Exposes)-1]
	publisher.trace.add("ingress_activate")
	return operations.GatewayExposeIngressActivation{
		ExposeID: expose.ID, StateGeneration: candidate.Generation, ConfigHash: strings.Repeat("c", 64),
	}, nil
}

func (publisher *v2NodeHappyIngressPublisher) Rollback(context.Context, operations.GatewayExposeIngressActivation) error {
	publisher.trace.add("ingress_rollback")
	return nil
}

func (*v2NodeHappyIngressPublisher) Commit(context.Context, operations.GatewayExposeIngressActivation) error {
	return nil
}

type v2NodeHappyTunnel struct{ trace *v2NodeHappyTrace }

func (runtime *v2NodeHappyTunnel) Activate(_ context.Context, _ model.State, pending model.State, expose model.Expose) (operations.ExposeTunnelActivation, error) {
	runtime.trace.add("tunnel_activate")
	return operations.ExposeTunnelActivation{ExposeID: expose.ID, Candidate: tunnel.CandidateDescriptor{
		Provider: "test", HostRole: model.RoleNode, HostID: pending.Host.ID, Generation: pending.Generation,
		NodeID: expose.NodeID, CredentialGeneration: pending.Nodes[0].CredentialGeneration,
		ActiveTransport: pending.Nodes[0].ActiveTransport, ConfigHash: strings.Repeat("d", 64),
	}}, nil
}

func (runtime *v2NodeHappyTunnel) Observe(_ context.Context, activation operations.ExposeTunnelActivation, expose model.Expose) (tunnel.TunnelReadinessResult, error) {
	runtime.trace.add("tunnel_observe")
	name, err := tunnel.MappingName(expose.NodeID, expose.ID)
	if err != nil {
		return tunnel.TunnelReadinessResult{}, err
	}
	passed := tunnel.TunnelProbeResult{State: tunnel.TunnelProbePassed, Code: "ok"}
	return tunnel.TunnelReadinessResult{
		Candidate: activation.Candidate, Configuration: passed, Connection: passed, MappingSet: passed,
		Mappings: []tunnel.TunnelMappingReadiness{{
			ExposeID: expose.ID, Name: name, Generation: expose.Generation, Registration: passed, Upstream: passed,
		}},
	}, nil
}

func (runtime *v2NodeHappyTunnel) Rollback(context.Context, operations.ExposeTunnelActivation) error {
	runtime.trace.add("tunnel_rollback")
	return nil
}

type v2NodeHappyTrace struct {
	mu     sync.Mutex
	events []string
}

func (trace *v2NodeHappyTrace) add(event string) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	trace.events = append(trace.events, event)
}

func (trace *v2NodeHappyTrace) before(first, second string) bool {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	firstIndex, secondIndex := -1, -1
	for index, event := range trace.events {
		if event == first && firstIndex < 0 {
			firstIndex = index
		}
		if event == second && secondIndex < 0 {
			secondIndex = index
		}
	}
	return firstIndex >= 0 && secondIndex > firstIndex
}

func runV2NodeHappyJSON(t *testing.T, args []string) output.Result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := Execute(args, &stdout, &stderr); code != ExitSuccess || stderr.Len() != 0 {
		t.Fatalf("vpnctl %v: exit=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
	}
	var result output.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode vpnctl %v output: %v: %q", args, err, stdout.String())
	}
	if result.Status != output.StatusOK || result.ExitCategory != output.CategorySuccess {
		t.Fatalf("vpnctl %v result = %+v", args, result)
	}
	return result
}

func assertV2NodeHappyAbsent(t *testing.T, forbidden string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if forbidden != "" && bytes.Contains(encoded, []byte(forbidden)) {
		t.Fatalf("public JSON leaked protected value: %s", encoded)
	}
}

func assertV2NodeHappyJoinState(t *testing.T, gateway, node model.State, gatewaySecrets, nodeSecrets *store.SecretStore) {
	t.Helper()
	if len(gateway.Invites) != 1 || gateway.Invites[0].State != model.InviteConsumed || len(gateway.Nodes) != 1 ||
		gateway.Nodes[0].Name != "bot-server" || gateway.Nodes[0].ActiveTransport != model.TransportRestricted ||
		len(gateway.Nodes[0].AssignedPresets) != 1 || gateway.Nodes[0].AssignedPresets[0] != "telegram" ||
		len(node.Nodes) != 1 || node.Nodes[0].Gateway == nil || node.Nodes[0].ActiveTransport != model.TransportRestricted {
		t.Fatalf("joined state = gateway node/invite:%+v/%+v node:%+v", gateway.Nodes, gateway.Invites, node.Nodes)
	}
	for _, state := range []model.State{gateway, node} {
		active := 0
		for _, transportRecord := range state.Transports {
			if transportRecord.State == model.TransportActive {
				active++
				if transportRecord.Kind != model.TransportRestricted {
					t.Fatalf("unexpected active transport in state: %+v", transportRecord)
				}
			}
		}
		if len(state.Transports) != 2 || active != 1 {
			t.Fatalf("state transport cardinality active/total = %d/%d", active, len(state.Transports))
		}
	}
	references, err := enrollment.NewNodeCredentialReferences(v2NodeHappyNodeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []model.SecretRef{references.ControlPrivateKey, references.WireGuardPrivateKey} {
		local, err := nodeSecrets.Get(reference)
		if err != nil || len(local) == 0 {
			t.Fatalf("node private credential %s = %d bytes, %v", reference, len(local), err)
		}
		defer clear(local)
		if _, err := gatewaySecrets.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("gateway retained node private credential %s: %v", reference, err)
		}
	}
}

func equalJSONStrings(value any, wanted []string) bool {
	values, ok := value.([]any)
	if !ok || len(values) != len(wanted) {
		return false
	}
	for index := range values {
		if values[index] != wanted[index] {
			return false
		}
	}
	return true
}

func v2NodeHappyUUIDs(values ...string) model.UUIDGenerator {
	index := 0
	return func() (string, error) {
		if index >= len(values) {
			return "", errors.New("UUID fixture exhausted")
		}
		value := values[index]
		index++
		return value, nil
	}
}

func v2NodeHappyGatewayPrivateKey() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
}

func v2NodeHappyGatewayPublicKey() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x32}, 32))
}

func v2NodeHappyNodePrivateKey() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))
}

func v2NodeHappyNodePublicKey() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
}
