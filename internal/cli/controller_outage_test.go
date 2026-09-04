package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const controllerOutageHelperEnvironment = "VPNCTL_CONTROLLER_OUTAGE_DATA_PLANE_HELPER"

func TestControllerOutageDataPlaneHelper(t *testing.T) {
	if os.Getenv(controllerOutageHelperEnvironment) != "1" {
		return
	}
	listenerFile := os.NewFile(3, "vpnctl-controller-outage-listener")
	if listenerFile == nil {
		t.Fatal("inherited data-plane listener is absent")
	}
	listener, err := net.FileListener(listenerFile)
	_ = listenerFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	config, err := os.ReadFile(os.Getenv("VPNCTL_CONTROLLER_OUTAGE_CONFIG"))
	if err != nil || len(config) == 0 {
		t.Fatalf("read data-plane config: %v", err)
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		request := make([]byte, 1)
		if _, err := io.ReadFull(connection, request); err == nil {
			_, _ = connection.Write(config)
		}
		_ = connection.Close()
	}
}

func TestControllerOutageKeepsAppliedDataPlaneAndReturnsManagementUnavailable(t *testing.T) {
	paths, stateSource := controllerOutageState(t)
	fixtures := startControllerOutageDataPlane(t, filepath.Join(paths.Root, "applied-data-plane"))
	observer := &controllerOutageObserver{fixtures: fixtures}
	dispatcher, err := controller.NewGatewayLoggingMutationDispatcher(paths, func() time.Time {
		return time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC)
	}, func() (string, error) { return "11111111-1111-4111-8111-111111111111", nil })
	if err != nil {
		t.Fatal(err)
	}

	previousPaths, previousRole, previousStore := loggingSystemPaths, loggingLoadRole, loggingNewStore
	previousCall, previousNow, previousUUID := loggingCallGateway, loggingNow, loggingNewUUID
	t.Cleanup(func() {
		loggingSystemPaths, loggingLoadRole, loggingNewStore = previousPaths, previousRole, previousStore
		loggingCallGateway, loggingNow, loggingNewUUID = previousCall, previousNow, previousUUID
	})
	loggingSystemPaths = func() store.Paths { return paths }
	loggingLoadRole = func(store.Paths) (HostRole, error) { return RoleGateway, nil }
	loggingNewStore = func(store.Paths) (loggingStateStore, error) { return stateSource, nil }
	loggingNow = func() time.Time { return time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC) }
	loggingNewUUID = func() (string, error) { return "22222222-2222-4222-8222-222222222222", nil }

	before, err := captureControllerOutageDataPlane(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	baselineProbes := probeControllerOutageDataPlane(t, fixtures)
	cancel, result := startControllerOutageManagement(t, paths, stateSource, observer, dispatcher)
	waitForControllerOutageSocket(t, paths.ControlSocket, result)
	assertControllerOutageManagementResult(t, ExitSuccess, "")

	cancel()
	if err := <-result; err != nil {
		t.Fatalf("stop controller: %v", err)
	}
	if _, err := os.Lstat(paths.ControlSocket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("controller socket remained after outage injection: %v", err)
	}
	assertControllerOutageManagementResult(t, ExitUnavailable, `"code":"gateway_unavailable"`)
	outageProbes := probeControllerOutageDataPlane(t, fixtures)
	during, err := captureControllerOutageDataPlane(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if !equalControllerOutageSnapshots(before, during) {
		t.Fatalf("data plane changed during controller outage:\nbefore=%+v\nduring=%+v", before, during)
	}

	cancel, result = startControllerOutageManagement(t, paths, stateSource, observer, dispatcher)
	waitForControllerOutageSocket(t, paths.ControlSocket, result)
	assertControllerOutageManagementResult(t, ExitSuccess, "")
	afterProbes := probeControllerOutageDataPlane(t, fixtures)
	after, err := captureControllerOutageDataPlane(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	if !equalControllerOutageSnapshots(before, after) {
		t.Fatalf("data plane changed across controller restart:\nbefore=%+v\nafter=%+v", before, after)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("stop restarted controller: %v", err)
	}
	state, err := stateSource.Load()
	if err != nil || state.Generation != 4 || len(state.Logging) != 0 {
		t.Fatalf("authoritative state changed: generation=%d logging=%d error=%v", state.Generation, len(state.Logging), err)
	}
	if baselineProbes != len(fixtures) || outageProbes != len(fixtures) || afterProbes != len(fixtures) {
		t.Fatalf("forwarding probes baseline/outage/restart=%d/%d/%d", baselineProbes, outageProbes, afterProbes)
	}
	if observer.observations < 2 {
		t.Fatalf("passive observations=%d", observer.observations)
	}
}

type controllerOutageFixture struct {
	name       string
	address    string
	configPath string
	config     []byte
	command    *exec.Cmd
	stderr     *bytes.Buffer
}

type controllerOutageSnapshot struct {
	name   string
	pid    int
	config []byte
	hash   [sha256.Size]byte
}

func startControllerOutageDataPlane(t *testing.T, root string) []*controllerOutageFixture {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	names := []string{"standard", "restricted", "routing", "dns", "tunnel", "ingress"}
	fixtures := make([]*controllerOutageFixture, 0, len(names))
	for _, name := range names {
		config := []byte("vpnctl-" + name + "-applied-generation-4")
		configPath := filepath.Join(root, name+".conf")
		if err := os.WriteFile(configPath, config, 0o600); err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		tcpListener, ok := listener.(*net.TCPListener)
		if !ok {
			_ = listener.Close()
			t.Fatal("data-plane fixture did not create a TCP listener")
		}
		listenerFile, err := tcpListener.File()
		if err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
		stderr := &bytes.Buffer{}
		command := exec.Command(os.Args[0], "-test.run=^TestControllerOutageDataPlaneHelper$")
		command.Env = append(os.Environ(), controllerOutageHelperEnvironment+"=1", "VPNCTL_CONTROLLER_OUTAGE_CONFIG="+configPath)
		command.ExtraFiles = []*os.File{listenerFile}
		command.Stdout = io.Discard
		command.Stderr = stderr
		if err := command.Start(); err != nil {
			_ = listenerFile.Close()
			_ = listener.Close()
			t.Fatal(err)
		}
		_ = listenerFile.Close()
		_ = listener.Close()
		fixture := &controllerOutageFixture{
			name: name, address: tcpListener.Addr().String(), configPath: configPath, config: config,
			command: command, stderr: stderr,
		}
		fixtures = append(fixtures, fixture)
		t.Cleanup(func() {
			if fixture.command.Process != nil {
				_ = fixture.command.Process.Kill()
				_ = fixture.command.Wait()
			}
		})
		waitForControllerOutageDataPlane(t, fixture)
	}
	return fixtures
}

func waitForControllerOutageDataPlane(t *testing.T, fixture *controllerOutageFixture) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if response, err := requestControllerOutageDataPlane(fixture); err == nil && bytes.Equal(response, fixture.config) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("data-plane %s did not become ready; stderr=%q", fixture.name, fixture.stderr.String())
}

func requestControllerOutageDataPlane(fixture *controllerOutageFixture) ([]byte, error) {
	connection, err := net.DialTimeout("tcp4", fixture.address, time.Second)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Write([]byte{1}); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(connection, 1024))
}

func probeControllerOutageDataPlane(t *testing.T, fixtures []*controllerOutageFixture) int {
	t.Helper()
	passed := 0
	for _, fixture := range fixtures {
		response, err := requestControllerOutageDataPlane(fixture)
		if err != nil || !bytes.Equal(response, fixture.config) {
			t.Fatalf("data-plane %s forwarding response=%q error=%v stderr=%q", fixture.name, response, err, fixture.stderr.String())
		}
		passed++
	}
	return passed
}

func captureControllerOutageDataPlane(fixtures []*controllerOutageFixture) ([]controllerOutageSnapshot, error) {
	snapshots := make([]controllerOutageSnapshot, 0, len(fixtures))
	for _, fixture := range fixtures {
		if fixture.command.Process == nil || fixture.command.Process.Signal(syscall.Signal(0)) != nil {
			return nil, errors.New("data-plane process is not running")
		}
		config, err := os.ReadFile(fixture.configPath)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, controllerOutageSnapshot{
			name: fixture.name, pid: fixture.command.Process.Pid, config: config, hash: sha256.Sum256(config),
		})
	}
	return snapshots, nil
}

func equalControllerOutageSnapshots(left, right []controllerOutageSnapshot) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].name != right[index].name || left[index].pid != right[index].pid ||
			left[index].hash != right[index].hash || !bytes.Equal(left[index].config, right[index].config) {
			return false
		}
	}
	return true
}

type controllerOutageObserver struct {
	fixtures     []*controllerOutageFixture
	observations int
}

func (observer *controllerOutageObserver) Observe(context.Context, model.State) (controller.Observation, error) {
	observer.observations++
	units := make([]controller.UnitObservation, 0, len(observer.fixtures))
	for _, fixture := range observer.fixtures {
		units = append(units, controller.UnitObservation{
			Name: "vpnctl-" + fixture.name + ".service", LoadState: "loaded", ActiveState: "active", SubState: "running",
		})
	}
	return controller.Observation{Units: units, Issues: []string{}}, nil
}

func controllerOutageState(t *testing.T) (store.Paths, *store.StateStore) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "vpnctl-cout-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	paths, err := store.NewPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{paths.StateDir, paths.RuntimeDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := cliDNSState(model.RoleGateway)
	encoded, err := model.EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.StateFile, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	stateSource, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	return paths, stateSource
}

func startControllerOutageManagement(
	t *testing.T,
	paths store.Paths,
	stateSource *store.StateStore,
	observer controller.PassiveObserver,
	dispatcher controller.MutationDispatcher,
) (context.CancelFunc, <-chan error) {
	t.Helper()
	server, err := controller.NewController(controller.ControllerRuntime{
		Paths: paths, State: stateSource, Observer: observer, Dispatcher: dispatcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- server.Serve(ctx) }()
	return cancel, result
}

func waitForControllerOutageSocket(t *testing.T, path string, result <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-result:
			t.Fatalf("controller stopped before readiness: %v", err)
		default:
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("controller did not create its management socket")
}

func assertControllerOutageManagementResult(t *testing.T, wantCode int, wantFragment string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"log", "disable", "all", "--json"}, &stdout, &stderr)
	if code != wantCode || stderr.Len() != 0 || (wantFragment != "" && !strings.Contains(stdout.String(), wantFragment)) {
		t.Fatalf("management code=%d want=%d stdout=%q stderr=%q", code, wantCode, stdout.String(), stderr.String())
	}
}
