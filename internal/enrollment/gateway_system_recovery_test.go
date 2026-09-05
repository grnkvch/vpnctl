package enrollment

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestSystemGatewayRecoveryRuntimeActivatesCommittedReplacement(t *testing.T) {
	fixture, runtime, runner, paths, request := newSystemGatewayRecoveryFixture(t)
	defer fixture.destroy()
	defer request.Destroy()
	manager := newSystemGatewayRecoveryManager(t, fixture, runtime)
	baseline := readGatewayJoinTestTree(t, filepath.Join(paths.ConfigDir, "generated", "gateway"))

	preparation, err := manager.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer preparation.Destroy()
	staged := readGatewayJoinTestTree(t, filepath.Join(paths.ConfigDir, "generated", "gateway"))
	if !reflect.DeepEqual(staged, baseline) {
		t.Fatal("gateway recovery staging published files before activation")
	}
	runner.peerPublicKey = rotationWireGuardPublic()
	if err := preparation.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.mutationMu.TryLock() {
		runtime.mutationMu.Unlock()
		t.Fatal("gateway recovery released mutation lock before state commit")
	}
	commit, err := preparation.Commit(context.Background())
	if err != nil || commit.State != NodeRotationCommitNew || commit.GatewayStateGeneration != 5 {
		t.Fatalf("gateway recovery commit = %+v, %v", commit, err)
	}
	if err := preparation.Drain(context.Background(), time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if !runtime.mutationMu.TryLock() {
		t.Fatal("gateway recovery retained mutation lock after drain")
	}
	runtime.mutationMu.Unlock()

	standard, err := os.ReadFile(filepath.Join(paths.ConfigDir, "generated", "gateway", transport.StandardConfigFileName))
	if err != nil || !strings.Contains(string(standard), "PublicKey = "+rotationWireGuardPublic()) ||
		strings.Contains(string(standard), "PublicKey = "+testNodeWireGuardPublic()) {
		t.Fatalf("active gateway recovery config has mixed generations: %v", err)
	}
	state, _ := fixture.gatewayState.Load()
	if state.Nodes[0].CredentialGeneration != 2 || len(runtime.transactions) != 0 {
		t.Fatalf("committed gateway recovery state/runtime = generation:%d transactions:%d", state.Nodes[0].CredentialGeneration, len(runtime.transactions))
	}
}

func TestSystemGatewayRecoveryRuntimeRestoresBaselineAfterActivationFailure(t *testing.T) {
	fixture, runtime, runner, paths, request := newSystemGatewayRecoveryFixture(t)
	defer fixture.destroy()
	defer request.Destroy()
	manager := newSystemGatewayRecoveryManager(t, fixture, runtime)
	baseline := readGatewayJoinTestTree(t, filepath.Join(paths.ConfigDir, "generated", "gateway"))

	preparation, err := manager.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer preparation.Destroy()
	runner.peerPublicKey = rotationWireGuardPublic()
	runner.failTunnelHealth = true
	if err := preparation.Activate(context.Background()); err == nil {
		t.Fatal("gateway recovery activation accepted failed tunnel health")
	}
	if !runtime.mutationMu.TryLock() {
		t.Fatal("failed gateway recovery retained mutation lock")
	}
	runtime.mutationMu.Unlock()
	if err := preparation.Abort(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := readGatewayJoinTestTree(t, filepath.Join(paths.ConfigDir, "generated", "gateway"))
	if !reflect.DeepEqual(after, baseline) {
		t.Fatalf("gateway recovery rollback differs:\nbefore=%v\nafter=%v", baseline, after)
	}
	state, _ := fixture.gatewayState.Load()
	if state.Nodes[0].CredentialGeneration != 1 || len(runtime.transactions) != 0 {
		t.Fatalf("failed gateway recovery changed state/runtime = generation:%d transactions:%d", state.Nodes[0].CredentialGeneration, len(runtime.transactions))
	}
}

func newSystemGatewayRecoveryFixture(
	t *testing.T,
) (*nodeRotationFixture, *SystemGatewayRecoveryRuntime, *gatewayJoinReadinessProbeRunner, store.Paths, *NodeRotationRequest) {
	t.Helper()
	fixture := newNodeRotationFixture(t, "", false)
	ensureJoinFixtureFRPComponent(fixture.joinFixture)
	fixture.gatewayState.mu.Lock()
	fixture.gatewayState.state.Exposes[0].TunnelPort = 20112
	fixture.gatewayState.mu.Unlock()
	paths, runner, _ := newGatewayJoinReadinessFixture(t, fixture.gatewaySecrets)
	publishGatewayRecoveryBaseline(t, paths, runner, fixture)
	runner.systemctl = nil
	runtime, err := newSystemGatewayRecoveryRuntime(
		paths, fixture.gatewaySecrets, &sync.Mutex{}, runner,
		&joinWireGuardRunner{}, linuxplatform.DefaultVPNCTLBinaryPath,
	)
	if err != nil {
		fixture.destroy()
		t.Fatal(err)
	}
	provisioner, err := NewNodeCredentialProvisioner(fixture.nodeSecrets, NodeCredentialRuntime{
		Entropy: randReaderForRotation(),
		WireGuardRunner: &joinWireGuardRunner{
			nodePrivate: rotationWireGuardPrivate(), nodePublic: rotationWireGuardPublic(),
		},
	})
	if err != nil {
		fixture.destroy()
		t.Fatal(err)
	}
	installation, err := provisioner.Provision(context.Background(), joinTestNodeID, 2)
	if err != nil {
		fixture.destroy()
		t.Fatal(err)
	}
	shared, err := provisioner.SharedCredentialPayload(installation)
	if err != nil {
		fixture.destroy()
		t.Fatal(err)
	}
	defer shared.Destroy()
	request, err := newNodeRotationRequest(rotationRequestID, 4, 1, installation, shared)
	if err != nil {
		fixture.destroy()
		t.Fatal(err)
	}
	return fixture, runtime, runner, paths, request
}

func newSystemGatewayRecoveryManager(
	t *testing.T,
	fixture *nodeRotationFixture,
	runtime *SystemGatewayRecoveryRuntime,
) *GatewayNodeRotationManager {
	t.Helper()
	manager, err := NewGatewayNodeRotationManager(
		fixture.gatewayState, fixture.gatewaySecrets, runtime, GatewayNodeRotationOptions{
			Entropy: randReaderForRotation(), Now: func() time.Time { return fixture.now.Add(4 * time.Minute) },
			NewCertificateID: func() (string, error) { return rotationCertificateID, nil },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func publishGatewayRecoveryBaseline(
	t *testing.T,
	paths store.Paths,
	runner *gatewayJoinReadinessProbeRunner,
	fixture *nodeRotationFixture,
) {
	t.Helper()
	state, err := fixture.gatewayState.Load()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := systemGatewayJoinTunnelCertificate(state)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := fixture.gatewaySecrets.Get(model.SecretRef(certificate.CertificateRef))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(certificatePEM)
	request, err := renderSystemGatewayCandidate(
		context.Background(), paths, fixture.gatewaySecrets, &joinWireGuardRunner{},
		linuxplatform.DefaultVPNCTLBinaryPath, state, certificatePEM,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clearGatewayJoinRoleRequest(&request)
	roles, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, runner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roles.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}
