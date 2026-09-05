package enrollment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
)

func TestSystemGatewayJoinReadinessPublishesAndRetainsCommittedCandidate(t *testing.T) {
	late := &lateGatewayJoinReadiness{}
	fixture := newJoinFixture(t, late)
	defer fixture.destroy()
	ensureJoinFixtureFRPComponent(fixture)
	paths, runner, readiness, convergence := newGatewayJoinReadinessFixture(t, fixture.gatewaySecrets)
	late.target = readiness

	result, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportRestricted, []string{"telegram"})
	if err != nil {
		t.Fatal(err)
	}
	if result.GatewayStateGeneration != 3 {
		t.Fatalf("gateway generation = %d", result.GatewayStateGeneration)
	}
	generated := filepath.Join(paths.ConfigDir, "generated", "gateway")
	for _, name := range append(transport.GatewayListenerFileNames(),
		tunnel.FRPServerConfigFileName, tunnel.FRPServerReadyFileName, tunnel.FRPServerCertificateName, tunnel.FRPServerPrivateKeyName,
	) {
		content, err := os.ReadFile(filepath.Join(generated, name))
		if err != nil || len(content) == 0 {
			t.Fatalf("committed gateway config %s: bytes=%d err=%v", name, len(content), err)
		}
	}
	standard, err := os.ReadFile(filepath.Join(generated, transport.StandardConfigFileName))
	if err != nil || !strings.Contains(string(standard), "PublicKey = "+testNodeWireGuardPublic()) ||
		!strings.Contains(string(standard), "AllowedIPs = 10.67.0.2/32") {
		t.Fatalf("committed standard candidate does not contain the joined peer: %v", err)
	}
	if !runner.sawSequence([][]string{
		{"restart", "vpnctl-standard.service"},
		{"restart", "vpnctl-restricted.service"},
		{"restart", "vpnctl-tunnel-server.service"},
	}) {
		t.Fatalf("candidate restart sequence was not observed: %v", runner.systemctl)
	}
	if convergence.stages != 1 || convergence.commits != 1 || convergence.rollbacks != 0 || convergence.generation != 3 || len(convergence.request.Configs) != 12 {
		t.Fatalf("gateway convergence transaction = %+v", convergence)
	}
}

func TestSystemGatewayJoinReadinessFailureRestoresExactBaseline(t *testing.T) {
	late := &lateGatewayJoinReadiness{}
	fixture := newJoinFixture(t, late)
	defer fixture.destroy()
	ensureJoinFixtureFRPComponent(fixture)
	paths, runner, readiness, convergence := newGatewayJoinReadinessFixture(t, fixture.gatewaySecrets)
	baseline := readGatewayJoinTestTree(t, filepath.Join(paths.ConfigDir, "generated", "gateway"))
	runner.failTunnelHealth = true
	late.target = readiness

	_, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportRestricted, []string{"telegram"})
	if err == nil {
		t.Fatalf("Join() error = %v", err)
	}
	after := readGatewayJoinTestTree(t, filepath.Join(paths.ConfigDir, "generated", "gateway"))
	if !reflect.DeepEqual(after, baseline) {
		t.Fatalf("gateway configs differ after rollback:\nbefore=%v\nafter=%v", baseline, after)
	}
	assertRejectedJoinHasNoPartialNode(t, fixture)
	if convergence.stages != 0 || convergence.commits != 0 || convergence.rollbacks != 0 {
		t.Fatalf("failed readiness touched convergence: %+v", convergence)
	}
}

func TestSystemGatewayJoinConvergenceFailureRestoresExactRuntime(t *testing.T) {
	late := &lateGatewayJoinReadiness{}
	fixture := newJoinFixture(t, late)
	defer fixture.destroy()
	ensureJoinFixtureFRPComponent(fixture)
	paths, runner, readiness, convergence := newGatewayJoinReadinessFixture(t, fixture.gatewaySecrets)
	baseline := readGatewayJoinTestTree(t, filepath.Join(paths.ConfigDir, "generated", "gateway"))
	convergence.err = fmt.Errorf("synthetic convergence stage failure")
	late.target = readiness

	if _, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportRestricted, []string{"telegram"}); err == nil {
		t.Fatalf("Join() error = %v", err)
	}
	after := readGatewayJoinTestTree(t, filepath.Join(paths.ConfigDir, "generated", "gateway"))
	if !reflect.DeepEqual(after, baseline) {
		t.Fatalf("gateway configs differ after convergence rollback:\nbefore=%v\nafter=%v", baseline, after)
	}
	if convergence.stages != 1 || convergence.commits != 0 || convergence.rollbacks != 1 {
		t.Fatalf("failed convergence transaction = %+v", convergence)
	}
	if !runner.sawSequence([][]string{{"restart", "vpnctl-standard.service"}, {"restart", "vpnctl-restricted.service"}, {"restart", "vpnctl-tunnel-server.service"}}) {
		t.Fatalf("restored services were not restarted: %v", runner.systemctl)
	}
	assertRejectedJoinHasNoPartialNode(t, fixture)
}

func TestSystemGatewayJoinStateCommitFailureRollsBackRuntimeAndConvergence(t *testing.T) {
	late := &lateGatewayJoinReadiness{}
	fixture := newJoinFixture(t, late)
	defer fixture.destroy()
	ensureJoinFixtureFRPComponent(fixture)
	paths, _, readiness, convergence := newGatewayJoinReadinessFixture(t, fixture.gatewaySecrets)
	baseline := readGatewayJoinTestTree(t, filepath.Join(paths.ConfigDir, "generated", "gateway"))
	fixture.manager.state = &faultingGatewayJoinState{base: fixture.gatewayState}
	late.target = readiness

	if _, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportRestricted, []string{"telegram"}); err == nil {
		t.Fatal("Join() accepted failed authoritative state commit")
	}
	after := readGatewayJoinTestTree(t, filepath.Join(paths.ConfigDir, "generated", "gateway"))
	if !reflect.DeepEqual(after, baseline) {
		t.Fatalf("gateway configs differ after state failure:\nbefore=%v\nafter=%v", baseline, after)
	}
	if convergence.stages != 1 || convergence.commits != 0 || convergence.rollbacks != 1 {
		t.Fatalf("state failure convergence transaction = %+v", convergence)
	}
	assertRejectedJoinHasNoPartialNode(t, fixture)
}

func TestSystemGatewayJoinUncertainCommittedStateRetainsRuntimeAndConvergence(t *testing.T) {
	late := &lateGatewayJoinReadiness{}
	fixture := newJoinFixture(t, late)
	defer fixture.destroy()
	ensureJoinFixtureFRPComponent(fixture)
	_, _, readiness, convergence := newGatewayJoinReadinessFixture(t, fixture.gatewaySecrets)
	fixture.manager.state = &faultingGatewayJoinState{base: fixture.gatewayState, commit: true}
	late.target = readiness

	result, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportRestricted, []string{"telegram"})
	if err != nil {
		t.Fatal(err)
	}
	if result.GatewayStateGeneration != 3 || convergence.stages != 1 || convergence.commits != 1 || convergence.rollbacks != 0 {
		t.Fatalf("uncertain committed join = result:%+v convergence:%+v", result, convergence)
	}
	gateway, err := fixture.gatewayState.Load()
	if err != nil || gateway.Generation != 3 || len(gateway.Nodes) != 1 {
		t.Fatalf("uncertain committed gateway = %+v, %v", gateway, err)
	}
}

func TestPreparedGatewayJoinReadinessRollsBackWhenReportIsRejected(t *testing.T) {
	preparation := &recordingGatewayJoinPreparation{report: JoinReadinessReport{Gateway: true}}
	checker := &preparedGatewayJoinChecker{preparation: preparation}
	fixture := newJoinFixture(t, checker)
	defer fixture.destroy()

	if _, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportStandard, []string{}); err == nil {
		t.Fatal("Join() accepted incomplete prepared readiness")
	}
	if preparation.commits != 0 || preparation.rollbacks != 1 {
		t.Fatalf("prepared readiness finalization = commits:%d rollbacks:%d", preparation.commits, preparation.rollbacks)
	}
	assertRejectedJoinHasNoPartialNode(t, fixture)
}

func TestPreparedGatewayJoinReadinessCommitsWithAuthoritativeJoin(t *testing.T) {
	preparation := &recordingGatewayJoinPreparation{report: healthyJoinReadiness()}
	checker := &preparedGatewayJoinChecker{preparation: preparation}
	fixture := newJoinFixture(t, checker)
	defer fixture.destroy()

	if _, err := fixture.workflow.Join(context.Background(), fixture.token, model.TransportStandard, []string{}); err != nil {
		t.Fatal(err)
	}
	if preparation.commits != 1 || preparation.rollbacks != 0 {
		t.Fatalf("prepared readiness finalization = commits:%d rollbacks:%d", preparation.commits, preparation.rollbacks)
	}
}

func newGatewayJoinReadinessFixture(
	t *testing.T,
	secrets *store.SecretStore,
) (store.Paths, *gatewayJoinReadinessProbeRunner, *SystemGatewayJoinReadiness, *recordingGatewayJoinConvergence) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{paths.ConfigDir, filepath.Join(paths.Root, "etc", "systemd", "system")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	runner := &gatewayJoinReadinessProbeRunner{}
	roles, err := linuxplatform.NewRoleSystemdInstaller(paths.Root, paths.ConfigDir, runner)
	if err != nil {
		t.Fatal(err)
	}
	request, err := linuxplatform.RenderGatewayRoleInstallation(linuxplatform.DefaultVPNCTLBinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roles.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	runner.systemctl = nil
	convergence := &recordingGatewayJoinConvergence{}
	readiness, err := newSystemGatewayJoinReadiness(
		paths, secrets, &sync.Mutex{}, convergence, runner, &joinWireGuardRunner{}, linuxplatform.DefaultVPNCTLBinaryPath,
	)
	if err != nil {
		t.Fatal(err)
	}
	return paths, runner, readiness, convergence
}

func ensureJoinFixtureFRPComponent(fixture *joinFixture) {
	fixture.gatewayState.mu.Lock()
	defer fixture.gatewayState.mu.Unlock()
	fixture.gatewayState.state.Components.Components = append(fixture.gatewayState.state.Components.Components, model.ComponentPin{
		Name: tunnel.FRPProviderName, Version: tunnel.FRPProviderVersion,
		Source: "vpnctl-release-bundle", Bundled: true, SHA256: tunnel.FRPProviderSHA256,
		Capabilities: []string{"dynamic-reload", "http-plugin-authorization", "tcp-mux", "tls-server-verification"},
	})
}

type gatewayJoinReadinessProbeRunner struct {
	systemctl        [][]string
	failTunnelHealth bool
	peerPublicKey    string
}

func (runner *gatewayJoinReadinessProbeRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	if command.Name == "systemctl" {
		runner.systemctl = append(runner.systemctl, append([]string(nil), command.Args...))
		if reflect.DeepEqual(command.Args, []string{"is-active", "--quiet", "vpnctl-tunnel-server.service"}) && runner.failTunnelHealth {
			return linuxplatform.ProbeResult{ExitCode: 3}, nil
		}
		return linuxplatform.ProbeResult{}, nil
	}
	key := command.Name + " " + strings.Join(command.Args, " ")
	switch key {
	case "wg show vpnctl-wg public-key":
		return linuxplatform.ProbeResult{Stdout: []byte(joinGatewayWireGuardPublic() + "\n")}, nil
	case "wg show vpnctl-wg listen-port":
		return linuxplatform.ProbeResult{Stdout: []byte("51820\n")}, nil
	case "ip -4 -o address show dev vpnctl-wg":
		return linuxplatform.ProbeResult{Stdout: []byte("7: vpnctl-wg inet 10.66.0.1/24 scope global vpnctl-wg\n7: vpnctl-wg inet 10.67.0.1/24 scope global vpnctl-wg\n")}, nil
	case "wg show vpnctl-wg allowed-ips":
		peer := runner.peerPublicKey
		if peer == "" {
			peer = testNodeWireGuardPublic()
		}
		return linuxplatform.ProbeResult{Stdout: []byte(peer + "\t10.67.0.2/32\n")}, nil
	case "ss -H -lunp sport = :8443":
		return linuxplatform.ProbeResult{}, nil
	case "ss -H -ltnp sport = :8443":
		return linuxplatform.ProbeResult{Stdout: []byte(`LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:(("mihomo",pid=41,fd=7))` + "\n")}, nil
	case "ss -H -ltnp sport = :17000":
		return linuxplatform.ProbeResult{Stdout: []byte(`LISTEN 0 4096 10.67.0.1:17000 0.0.0.0:* users:(("frps",pid=42,fd=8))` + "\n")}, nil
	default:
		return linuxplatform.ProbeResult{}, fmt.Errorf("unexpected readiness command %q", key)
	}
}

func (runner *gatewayJoinReadinessProbeRunner) sawSequence(want [][]string) bool {
	for start := 0; start+len(want) <= len(runner.systemctl); start++ {
		if reflect.DeepEqual(runner.systemctl[start:start+len(want)], want) {
			return true
		}
	}
	return false
}

func readGatewayJoinTestTree(t *testing.T, directory string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			t.Fatalf("unexpected gateway config entry %s", entry.Name())
		}
		content, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = string(content)
	}
	return result
}

type lateGatewayJoinReadiness struct {
	target GatewayJoinReadinessChecker
}

func (late *lateGatewayJoinReadiness) Check(ctx context.Context, candidate GatewayJoinCandidate) (JoinReadinessReport, error) {
	if late.target == nil {
		return JoinReadinessReport{}, fmt.Errorf("late gateway readiness target is unavailable")
	}
	return late.target.Check(ctx, candidate)
}

func (late *lateGatewayJoinReadiness) Prepare(ctx context.Context, candidate GatewayJoinCandidate) (GatewayJoinReadinessPreparation, error) {
	preparer, ok := late.target.(GatewayJoinReadinessPreparer)
	if !ok {
		return nil, fmt.Errorf("late gateway readiness target cannot prepare")
	}
	return preparer.Prepare(ctx, candidate)
}

type preparedGatewayJoinChecker struct {
	preparation *recordingGatewayJoinPreparation
}

func (checker *preparedGatewayJoinChecker) Check(context.Context, GatewayJoinCandidate) (JoinReadinessReport, error) {
	return JoinReadinessReport{}, fmt.Errorf("prepared checker must use Prepare")
}

func (checker *preparedGatewayJoinChecker) Prepare(context.Context, GatewayJoinCandidate) (GatewayJoinReadinessPreparation, error) {
	return checker.preparation, nil
}

type recordingGatewayJoinPreparation struct {
	report    JoinReadinessReport
	commits   int
	rollbacks int
}

func (preparation *recordingGatewayJoinPreparation) Report() JoinReadinessReport {
	return preparation.report
}
func (preparation *recordingGatewayJoinPreparation) Commit() { preparation.commits++ }
func (preparation *recordingGatewayJoinPreparation) Rollback(context.Context) error {
	preparation.rollbacks++
	return nil
}

type recordingGatewayJoinConvergence struct {
	stages     int
	commits    int
	rollbacks  int
	generation uint64
	request    linuxplatform.RoleInstallationRequest
	err        error
}

func (convergence *recordingGatewayJoinConvergence) PrepareActiveGatewayGeneration(
	_ context.Context,
	generation uint64,
	request linuxplatform.RoleInstallationRequest,
) (GatewayJoinConvergencePreparation, error) {
	convergence.stages++
	convergence.generation = generation
	convergence.request = request
	preparation := &recordingGatewayJoinConvergencePreparation{owner: convergence}
	return preparation, convergence.err
}

type recordingGatewayJoinConvergencePreparation struct {
	owner    *recordingGatewayJoinConvergence
	finished bool
}

type faultingGatewayJoinState struct {
	base   *inviteMemoryState
	commit bool
}

func (state *faultingGatewayJoinState) Load() (model.State, error) {
	return state.base.Load()
}

func (state *faultingGatewayJoinState) Save(expected uint64, candidate model.State) error {
	if state.commit {
		if err := state.base.Save(expected, candidate); err != nil {
			return err
		}
	}
	return fmt.Errorf("synthetic gateway state save failure")
}

func (preparation *recordingGatewayJoinConvergencePreparation) Commit() {
	if preparation.finished {
		return
	}
	preparation.finished = true
	preparation.owner.commits++
}

func (preparation *recordingGatewayJoinConvergencePreparation) Rollback(context.Context) error {
	if preparation.finished {
		return nil
	}
	preparation.finished = true
	preparation.owner.rollbacks++
	return nil
}
