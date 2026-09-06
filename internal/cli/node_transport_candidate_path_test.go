package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestGatewayBoundCandidatePathAllowsOnlyManagedProbeEndpointsAndClosesOnce(t *testing.T) {
	network := &recordingCandidateNetworkPath{}
	cleanupCalls := 0
	path, err := newGatewayBoundCandidatePath(mustParseCandidateAddress(t, "10.67.0.1"), network, func(context.Context) error {
		cleanupCalls++
		return errors.New("cleanup failed")
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"10.67.0.1:53", "10.67.0.1:9443", "10.67.0.1:17000"} {
		connection, err := path.DialContext(context.Background(), "tcp", endpoint)
		if err != nil {
			t.Fatalf("allowed candidate endpoint %s: %v", endpoint, err)
		}
		_ = connection.Close()
	}
	response, err := path.ExchangeUDP(context.Background(), "10.67.0.1:53", []byte("query"))
	if err != nil || !bytes.Equal(response, []byte("response")) {
		t.Fatalf("candidate UDP response=%q error=%v", response, err)
	}
	for _, test := range []struct {
		network string
		address string
	}{
		{network: "tcp", address: "10.67.0.2:9443"},
		{network: "tcp", address: "10.67.0.1:443"},
		{network: "udp", address: "10.67.0.1:53"},
	} {
		if connection, err := path.DialContext(context.Background(), test.network, test.address); err == nil {
			_ = connection.Close()
			t.Fatalf("unsafe candidate dial accepted %s %s", test.network, test.address)
		}
	}
	if _, err := path.ExchangeUDP(context.Background(), "10.67.0.1:9443", []byte("query")); err == nil {
		t.Fatal("non-DNS candidate UDP target was accepted")
	}
	if err := path.Close(context.Background()); err == nil || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("candidate cleanup error = %v", err)
	}
	_ = path.Close(context.Background())
	if cleanupCalls != 1 || network.tcpCalls != 3 || network.udpCalls != 1 {
		t.Fatalf("cleanup=%d network=%+v", cleanupCalls, network)
	}
}

func TestNodeTransportCandidateDirectoryAndConfigArePrivateAndOwnerScoped(t *testing.T) {
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.RuntimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := createNodeTransportCandidateDirectory(paths.RuntimeDir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || filepath.Dir(directory) != paths.RuntimeDir {
		t.Fatalf("candidate directory info=%v error=%v", info, err)
	}
	configPath := filepath.Join(directory, "restricted.yaml")
	if err := writeNodeTransportCandidateConfig(configPath, []byte("secret candidate\n")); err != nil {
		t.Fatal(err)
	}
	configInfo, err := os.Lstat(configPath)
	if err != nil || !configInfo.Mode().IsRegular() || configInfo.Mode().Perm() != 0o600 {
		t.Fatalf("candidate config info=%v error=%v", configInfo, err)
	}
	if content, err := os.ReadFile(configPath); err != nil || !bytes.Equal(content, []byte("secret candidate\n")) {
		t.Fatalf("candidate config=%q error=%v", content, err)
	}
	if err := removeNodeTransportCandidateDirectory(paths.RuntimeDir, filepath.Join(paths.Root, "foreign")); err == nil {
		t.Fatal("candidate cleanup accepted a path outside its exact runtime parent")
	}
	if err := removeNodeTransportCandidateDirectory(paths.RuntimeDir, filepath.Join(paths.RuntimeDir, nodeTransportCandidateDirectoryPrefix)); err == nil {
		t.Fatal("candidate cleanup accepted the bare reserved prefix")
	}
	if err := removeNodeTransportCandidateDirectory(paths.RuntimeDir+string(os.PathSeparator)+"..", directory); err == nil {
		t.Fatal("candidate cleanup accepted an unclean runtime path")
	}
	if err := removeNodeTransportCandidateDirectory(paths.RuntimeDir, directory); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate directory remains: %v", err)
	}

	if err := os.Chmod(paths.RuntimeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := createNodeTransportCandidateDirectory(paths.RuntimeDir); err == nil {
		t.Fatal("world-readable runtime directory was accepted")
	}
}

func TestNodeTransportCandidateLockSerializesAndReleases(t *testing.T) {
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.RuntimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := lockNodeTransportCandidatePath(paths.RuntimeDir)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(paths.RuntimeDir, nodeTransportCandidateLockName)
	info, err := os.Lstat(lockPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("candidate lock info=%v error=%v", info, err)
	}
	if second, err := lockNodeTransportCandidatePath(paths.RuntimeDir); err == nil || !strings.Contains(err.Error(), "already running") {
		if second != nil {
			_ = second.Close(context.Background())
		}
		t.Fatalf("concurrent candidate lock error = %v", err)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(context.Background()); err != nil {
		t.Fatalf("repeated candidate unlock: %v", err)
	}
	second, err := lockNodeTransportCandidatePath(paths.RuntimeDir)
	if err != nil {
		t.Fatalf("candidate lock was not released: %v", err)
	}
	if err := second.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSweepNodeTransportCandidateDirectoriesRemovesOnlyReservedChildren(t *testing.T) {
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.RuntimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(paths.RuntimeDir, nodeTransportCandidateDirectoryPrefix+"stale")
	unrelatedDirectory := filepath.Join(paths.RuntimeDir, "unrelated")
	unrelatedFile := filepath.Join(paths.RuntimeDir, "keep.txt")
	barePrefix := filepath.Join(paths.RuntimeDir, nodeTransportCandidateDirectoryPrefix)
	for _, directory := range []string{stale, unrelatedDirectory, barePrefix} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(unrelatedFile, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sweepNodeTransportCandidateDirectories(paths.RuntimeDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale candidate remains: %v", err)
	}
	for _, path := range []string{unrelatedDirectory, unrelatedFile, barePrefix} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("unrelated runtime entry %s was removed: %v", path, err)
		}
	}
}

func TestWaitNodeTransportCandidateSOCKSObservesReadinessOrEarlyExit(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	if err := waitNodeTransportCandidateSOCKS(context.Background(), listener.Addr().String(), done); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	exited := make(chan struct{})
	close(exited)
	if err := waitNodeTransportCandidateSOCKS(context.Background(), listener.Addr().String(), exited); err == nil || !strings.Contains(err.Error(), "exited") {
		_ = listener.Close()
		t.Fatalf("foreign ready listener hid exited process: %v", err)
	}
	_ = listener.Close()
	close(done)

	dead := make(chan struct{})
	close(dead)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitNodeTransportCandidateSOCKS(ctx, listener.Addr().String(), dead); err == nil || !strings.Contains(err.Error(), "exited") {
		t.Fatalf("early candidate exit error = %v", err)
	}
}

func TestVerifyNodeTransportCandidateSOCKSRequiresExactProcessOwnership(t *testing.T) {
	const address = "127.0.0.1:17890"
	runner := &nodeTransportCandidateProbeRunner{result: linuxplatform.ProbeResult{
		Stdout: []byte(`LISTEN 0 4096 127.0.0.1:17890 0.0.0.0:* users:(("mihomo",pid=41,fd=7))` + "\n"),
	}}
	if err := verifyNodeTransportCandidateSOCKS(context.Background(), runner, address, 41); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 1 || runner.command.Name != "ss" ||
		strings.Join(runner.command.Args, " ") != "-H -ltnp sport = :17890" {
		t.Fatalf("listener ownership probe = %+v calls=%d", runner.command, runner.calls)
	}
	for name, output := range map[string]string{
		"another PID":     `LISTEN 0 4096 127.0.0.1:17890 0.0.0.0:* users:(("mihomo",pid=42,fd=7))`,
		"another process": `LISTEN 0 4096 127.0.0.1:17890 0.0.0.0:* users:(("proxy",pid=41,fd=7))`,
		"another binding": `LISTEN 0 4096 0.0.0.0:17890 0.0.0.0:* users:(("mihomo",pid=41,fd=7))`,
		"multiple listeners": `LISTEN 0 4096 127.0.0.1:17890 0.0.0.0:* users:(("mihomo",pid=41,fd=7))` + "\n" +
			`LISTEN 0 4096 127.0.0.1:17890 0.0.0.0:* users:(("proxy",pid=42,fd=7))`,
	} {
		t.Run(name, func(t *testing.T) {
			candidate := &nodeTransportCandidateProbeRunner{result: linuxplatform.ProbeResult{Stdout: []byte(output + "\n")}}
			if err := verifyNodeTransportCandidateSOCKS(context.Background(), candidate, address, 41); err == nil {
				t.Fatal("foreign candidate SOCKS listener ownership was accepted")
			}
		})
	}
}

type recordingCandidateNetworkPath struct {
	tcpCalls int
	udpCalls int
}

type nodeTransportCandidateProbeRunner struct {
	result  linuxplatform.ProbeResult
	err     error
	command linuxplatform.ProbeCommand
	calls   int
}

func (runner *nodeTransportCandidateProbeRunner) Run(
	_ context.Context,
	command linuxplatform.ProbeCommand,
) (linuxplatform.ProbeResult, error) {
	runner.calls++
	runner.command = command
	return runner.result, runner.err
}

func (path *recordingCandidateNetworkPath) DialContext(context.Context, string, string) (net.Conn, error) {
	path.tcpCalls++
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (path *recordingCandidateNetworkPath) ExchangeUDP(context.Context, string, []byte) ([]byte, error) {
	path.udpCalls++
	return []byte("response"), nil
}

func mustParseCandidateAddress(t *testing.T, value string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}
