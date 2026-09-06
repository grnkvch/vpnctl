package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/enrollment"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/operations"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/routing"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
	"golang.org/x/sys/unix"
)

const (
	nodeTransportCandidateDirectoryPrefix = ".transport-test-"
	nodeTransportCandidateLockName        = "transport-test.lock"
	nodeTransportCandidateSOCKSReadyWait  = 5 * time.Second
	nodeTransportCandidateSOCKSPoll       = 50 * time.Millisecond
)

type systemNodeTransportCandidatePathFactory struct {
	paths  store.Paths
	runner linuxplatform.ProbeRunner
}

func newSystemNodeTransportCandidatePathFactory(
	paths store.Paths,
	runner linuxplatform.ProbeRunner,
) (*systemNodeTransportCandidatePathFactory, error) {
	want, err := store.NewPaths(paths.Root)
	if err != nil || want != paths || runner == nil {
		return nil, fmt.Errorf("system node transport candidate path dependencies are invalid")
	}
	return &systemNodeTransportCandidatePathFactory{paths: paths, runner: runner}, nil
}

func (factory *systemNodeTransportCandidatePathFactory) Open(
	ctx context.Context,
	kind model.TransportKind,
	configuration enrollment.NodeConfiguration,
) (enrollment.NodeTransportCandidatePath, error) {
	if ctx == nil || factory == nil || factory.runner == nil {
		return nil, fmt.Errorf("system node transport candidate path factory is incomplete")
	}
	if err := configuration.Validate(); err != nil {
		return nil, err
	}
	lock, err := lockNodeTransportCandidatePath(factory.paths.RuntimeDir)
	if err != nil {
		return nil, err
	}
	locked := true
	defer func() {
		if locked {
			_ = lock.Close(context.Background())
		}
	}()
	if err := sweepNodeTransportCandidateDirectories(factory.paths.RuntimeDir); err != nil {
		return nil, err
	}
	endpoint, err := configuration.TunnelCandidate().ServerEndpoint()
	if err != nil {
		return nil, err
	}
	switch kind {
	case model.TransportStandard:
		path, pathErr := newGatewayBoundCandidatePath(endpoint.Addr(), linuxplatform.NewStandardProbePath(), lock.Close)
		if pathErr == nil {
			locked = false
		}
		return path, pathErr
	case model.TransportRestricted:
		path, pathErr := factory.openRestricted(ctx, endpoint.Addr(), configuration.RestrictedCandidate(), lock)
		if pathErr == nil {
			locked = false
		}
		return path, pathErr
	default:
		return nil, fmt.Errorf("unsupported system node transport candidate kind %q", kind)
	}
}

func (factory *systemNodeTransportCandidatePathFactory) openRestricted(
	ctx context.Context,
	gateway netip.Addr,
	candidate transport.RestrictedNodeCandidate,
	lock *nodeTransportCandidateLock,
) (enrollment.NodeTransportCandidatePath, error) {
	directory, err := createNodeTransportCandidateDirectory(factory.paths.RuntimeDir)
	if err != nil {
		return nil, err
	}
	cleanupDirectory := true
	defer func() {
		if cleanupDirectory {
			_ = removeNodeTransportCandidateDirectory(factory.paths.RuntimeDir, directory)
		}
	}()
	stateDirectory := filepath.Join(directory, "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create restricted candidate state directory: %w", err)
	}
	port, err := reserveNodeTransportCandidateSOCKSPort()
	if err != nil {
		return nil, err
	}
	content, err := transport.RenderRestrictedReadinessConfig(candidate, port)
	if err != nil {
		return nil, err
	}
	defer clear(content)
	configPath := filepath.Join(directory, "restricted.yaml")
	if err := writeNodeTransportCandidateConfig(configPath, content); err != nil {
		return nil, err
	}
	binaryPath := filepath.Join(factory.paths.Root, transport.RestrictedBinaryRelativePath)
	if err := transport.ValidatePinnedMihomoConfig(ctx, factory.runner, binaryPath, stateDirectory, configPath); err != nil {
		return nil, err
	}
	process, err := startNodeTransportCandidateProcess(ctx, binaryPath, []string{"-d", stateDirectory, "-f", configPath})
	if err != nil {
		return nil, err
	}
	cleanupProcess := true
	defer func() {
		if cleanupProcess {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = process.Stop(cleanupContext)
		}
	}()
	proxyAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := waitNodeTransportCandidateSOCKS(ctx, proxyAddress, process.Done()); err != nil {
		return nil, err
	}
	if err := verifyNodeTransportCandidateSOCKS(ctx, factory.runner, proxyAddress, process.PID()); err != nil {
		return nil, err
	}
	socks, err := transport.NewRestrictedSOCKSPath(proxyAddress)
	if err != nil {
		return nil, err
	}
	cleanup := func(cleanupContext context.Context) error {
		return errors.Join(
			process.Stop(cleanupContext),
			removeNodeTransportCandidateDirectory(factory.paths.RuntimeDir, directory),
			lock.Close(cleanupContext),
		)
	}
	path, err := newGatewayBoundCandidatePath(gateway, socks, cleanup)
	if err != nil {
		return nil, err
	}
	cleanupProcess = false
	cleanupDirectory = false
	return path, nil
}

type systemNodeTransportControlProbe struct {
	paths store.Paths
	now   func() time.Time
}

func (probe systemNodeTransportControlProbe) Probe(
	ctx context.Context,
	nodeID string,
	dial func(context.Context, string, string) (net.Conn, error),
) error {
	identity, err := control.NewSystemNodeClientWithDialContext(probe.paths, probe.now, dial)
	if err != nil || identity.NodeID != nodeID {
		return errors.Join(fmt.Errorf("load candidate-bound node control identity"), err)
	}
	gateway, err := operations.NewRemoteRepairGatewayProbe(
		identity.Client, identity.Protocol, identity.NodeID, identity.CredentialGeneration,
		probe.now, nil, nil,
	)
	if err != nil {
		return err
	}
	return gateway.RequireGateway(ctx, nodeID)
}

type candidateNetworkPath interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	ExchangeUDP(context.Context, string, []byte) ([]byte, error)
}

type gatewayBoundCandidatePath struct {
	gateway netip.Addr
	path    candidateNetworkPath
	cleanup func(context.Context) error

	closeOnce sync.Once
	closeErr  error
}

func newGatewayBoundCandidatePath(
	gateway netip.Addr,
	path candidateNetworkPath,
	cleanup func(context.Context) error,
) (*gatewayBoundCandidatePath, error) {
	if !gateway.Is4() || !gateway.IsGlobalUnicast() || gateway.IsLoopback() || path == nil {
		return nil, fmt.Errorf("candidate path gateway binding is invalid")
	}
	return &gatewayBoundCandidatePath{gateway: gateway, path: path, cleanup: cleanup}, nil
}

func (path *gatewayBoundCandidatePath) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	endpoint, err := path.target(address)
	if err != nil {
		return nil, err
	}
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("candidate path supports only TCP dialing")
	}
	switch endpoint.Port() {
	case control.RPCControlTCPPort, tunnel.FRPServerPort, routing.GatewayDNSPort:
	default:
		return nil, fmt.Errorf("candidate TCP target port is outside the diagnostic allowlist")
	}
	return path.path.DialContext(ctx, "tcp4", endpoint.String())
}

func (path *gatewayBoundCandidatePath) ExchangeUDP(ctx context.Context, address string, payload []byte) ([]byte, error) {
	endpoint, err := path.target(address)
	if err != nil {
		return nil, err
	}
	if endpoint.Port() != routing.GatewayDNSPort {
		return nil, fmt.Errorf("candidate UDP target must be gateway DNS")
	}
	return path.path.ExchangeUDP(ctx, endpoint.String(), payload)
}

func (path *gatewayBoundCandidatePath) Close(ctx context.Context) error {
	if ctx == nil || path == nil || path.path == nil {
		return fmt.Errorf("candidate path is incomplete")
	}
	path.closeOnce.Do(func() {
		if path.cleanup != nil {
			path.closeErr = path.cleanup(ctx)
		}
	})
	return path.closeErr
}

func (path *gatewayBoundCandidatePath) target(value string) (netip.AddrPort, error) {
	if path == nil || !path.gateway.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("candidate path is incomplete")
	}
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint.String() != value || endpoint.Addr() != path.gateway || endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("candidate path target differs from the authoritative gateway")
	}
	return endpoint, nil
}

type nodeTransportCandidateProcess struct {
	cancel context.CancelFunc
	done   chan struct{}
	pid    int
	once   sync.Once
}

func startNodeTransportCandidateProcess(ctx context.Context, binaryPath string, arguments []string) (*nodeTransportCandidateProcess, error) {
	if ctx == nil || !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath || len(arguments) == 0 {
		return nil, fmt.Errorf("restricted candidate process input is invalid")
	}
	processContext, cancel := context.WithCancel(ctx)
	command := exec.CommandContext(processContext, binaryPath, arguments...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := configureNodeTransportCandidateProcess(command); err != nil {
		cancel()
		return nil, err
	}
	if err := command.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start restricted candidate process: %w", err)
	}
	process := &nodeTransportCandidateProcess{cancel: cancel, done: make(chan struct{}), pid: command.Process.Pid}
	go func() {
		_ = command.Wait()
		close(process.done)
	}()
	return process, nil
}

func (process *nodeTransportCandidateProcess) PID() int {
	if process == nil {
		return 0
	}
	return process.pid
}

func (process *nodeTransportCandidateProcess) Done() <-chan struct{} {
	if process == nil {
		return nil
	}
	return process.done
}

func (process *nodeTransportCandidateProcess) Stop(ctx context.Context) error {
	if ctx == nil || process == nil || process.cancel == nil || process.done == nil {
		return fmt.Errorf("restricted candidate process is incomplete")
	}
	process.once.Do(process.cancel)
	select {
	case <-process.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func createNodeTransportCandidateDirectory(runtimeDirectory string) (string, error) {
	info, err := os.Lstat(runtimeDirectory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.Join(fmt.Errorf("node transport runtime directory is not private"), err)
	}
	directory, err := os.MkdirTemp(runtimeDirectory, nodeTransportCandidateDirectoryPrefix)
	if err != nil {
		return "", fmt.Errorf("create node transport candidate directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.Remove(directory)
		return "", fmt.Errorf("secure node transport candidate directory: %w", err)
	}
	return directory, nil
}

func removeNodeTransportCandidateDirectory(runtimeDirectory, directory string) error {
	if !filepath.IsAbs(runtimeDirectory) || filepath.Clean(runtimeDirectory) != runtimeDirectory ||
		!filepath.IsAbs(directory) || filepath.Clean(directory) != directory || filepath.Dir(directory) != runtimeDirectory ||
		!strings.HasPrefix(filepath.Base(directory), nodeTransportCandidateDirectoryPrefix) ||
		len(filepath.Base(directory)) == len(nodeTransportCandidateDirectoryPrefix) {
		return fmt.Errorf("refusing unsafe node transport candidate cleanup")
	}
	if err := os.RemoveAll(directory); err != nil {
		return fmt.Errorf("remove node transport candidate directory: %w", err)
	}
	return nil
}

type nodeTransportCandidateLock struct {
	file *os.File
	once sync.Once
	err  error
}

func lockNodeTransportCandidatePath(runtimeDirectory string) (*nodeTransportCandidateLock, error) {
	if !filepath.IsAbs(runtimeDirectory) || filepath.Clean(runtimeDirectory) != runtimeDirectory {
		return nil, fmt.Errorf("node transport runtime directory path is invalid")
	}
	info, err := os.Lstat(runtimeDirectory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.Join(fmt.Errorf("node transport runtime directory is not private"), err)
	}
	path := filepath.Join(runtimeDirectory, nodeTransportCandidateLockName)
	descriptor, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open node transport candidate lock: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("open node transport candidate lock file")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil || uint32(stat.Mode)&unix.S_IFMT != unix.S_IFREG ||
		os.FileMode(stat.Mode).Perm() != 0o600 || stat.Uid != uint32(os.Geteuid()) {
		_ = file.Close()
		return nil, errors.Join(fmt.Errorf("node transport candidate lock is not owner-only"), err)
	}
	if err := unix.Flock(descriptor, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("another node transport test is already running")
		}
		return nil, fmt.Errorf("lock node transport candidate path: %w", err)
	}
	return &nodeTransportCandidateLock{file: file}, nil
}

func (lock *nodeTransportCandidateLock) Close(context.Context) error {
	if lock == nil || lock.file == nil {
		return fmt.Errorf("node transport candidate lock is incomplete")
	}
	lock.once.Do(func() {
		descriptor := int(lock.file.Fd())
		lock.err = errors.Join(unix.Flock(descriptor, unix.LOCK_UN), lock.file.Close())
	})
	return lock.err
}

func sweepNodeTransportCandidateDirectories(runtimeDirectory string) error {
	if !filepath.IsAbs(runtimeDirectory) || filepath.Clean(runtimeDirectory) != runtimeDirectory {
		return fmt.Errorf("node transport runtime directory path is invalid")
	}
	entries, err := os.ReadDir(runtimeDirectory)
	if err != nil {
		return fmt.Errorf("inspect stale node transport candidates: %w", err)
	}
	var cleanupErrors []error
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), nodeTransportCandidateDirectoryPrefix) ||
			len(entry.Name()) == len(nodeTransportCandidateDirectoryPrefix) {
			continue
		}
		path := filepath.Join(runtimeDirectory, entry.Name())
		if err := removeNodeTransportCandidateDirectory(runtimeDirectory, path); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if err := errors.Join(cleanupErrors...); err != nil {
		return fmt.Errorf("remove stale node transport candidates: %w", err)
	}
	return nil
}

func writeNodeTransportCandidateConfig(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create restricted candidate config: %w", err)
	}
	writeErr := writeNodeTransportCandidateFile(file, content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write restricted candidate config: %w", err)
	}
	return nil
}

func writeNodeTransportCandidateFile(writer io.Writer, content []byte) error {
	for len(content) != 0 {
		count, err := writer.Write(content)
		if err != nil {
			return err
		}
		if count <= 0 {
			return io.ErrUnexpectedEOF
		}
		content = content[count:]
	}
	return nil
}

func reserveNodeTransportCandidateSOCKSPort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("reserve restricted candidate SOCKS port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, fmt.Errorf("release restricted candidate SOCKS port: %w", err)
	}
	if port < 1024 || port == transport.RestrictedTCPPort {
		return 0, fmt.Errorf("reserved restricted candidate SOCKS port is unsafe")
	}
	return port, nil
}

func waitNodeTransportCandidateSOCKS(ctx context.Context, address string, done <-chan struct{}) error {
	if ctx == nil || done == nil {
		return fmt.Errorf("restricted candidate readiness input is invalid")
	}
	waitContext, cancel := context.WithTimeout(ctx, nodeTransportCandidateSOCKSReadyWait)
	defer cancel()
	ticker := time.NewTicker(nodeTransportCandidateSOCKSPoll)
	defer ticker.Stop()
	for {
		connection, err := (&net.Dialer{Timeout: nodeTransportCandidateSOCKSPoll}).DialContext(waitContext, "tcp4", address)
		if err == nil {
			_ = connection.Close()
			select {
			case <-done:
				return fmt.Errorf("restricted candidate process exited before readiness")
			default:
				return nil
			}
		}
		select {
		case <-waitContext.Done():
			return fmt.Errorf("restricted candidate SOCKS listener did not become ready")
		case <-done:
			return fmt.Errorf("restricted candidate process exited before readiness")
		case <-ticker.C:
		}
	}
}

func verifyNodeTransportCandidateSOCKS(
	ctx context.Context,
	runner linuxplatform.ProbeRunner,
	address string,
	pid int,
) error {
	endpoint, err := netip.ParseAddrPort(address)
	if ctx == nil || runner == nil || err != nil || endpoint.String() != address ||
		!endpoint.Addr().Is4() || !endpoint.Addr().IsLoopback() || endpoint.Port() < 1024 || pid <= 1 {
		return fmt.Errorf("restricted candidate SOCKS ownership input is invalid")
	}
	result, err := runner.Run(ctx, linuxplatform.ProbeCommand{
		Name: "ss", Args: []string{"-H", "-ltnp", "sport = :" + strconv.Itoa(int(endpoint.Port()))},
	})
	if err != nil || result.ExitCode != 0 {
		return errors.Join(fmt.Errorf("inspect restricted candidate SOCKS listener ownership"), err)
	}
	line := strings.TrimSpace(string(result.Stdout))
	fields := strings.Fields(line)
	owner := `(("mihomo",pid=` + strconv.Itoa(pid) + `,`
	if line == "" || strings.Count(line, "\n") != 0 || len(fields) < 6 || fields[3] != address ||
		!strings.Contains(fields[len(fields)-1], owner) {
		return fmt.Errorf("restricted candidate SOCKS listener is not owned by the candidate process")
	}
	return nil
}

var _ enrollment.NodeTransportCandidatePathFactory = (*systemNodeTransportCandidatePathFactory)(nil)
var _ enrollment.NodeTransportCandidateControlProbe = systemNodeTransportControlProbe{}
var _ enrollment.NodeTransportCandidatePath = (*gatewayBoundCandidatePath)(nil)
