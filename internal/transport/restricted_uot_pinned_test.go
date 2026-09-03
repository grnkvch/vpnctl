package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const (
	restrictedPinnedReadinessSOCKSPort = 17890
	restrictedPinnedEchoPort           = 18080
)

// The task-8.4 wrapper runs this helper in the gateway fixture. It owns only
// its temporary echo sockets, config/state, and child Mihomo process.
func TestRestrictedPinnedUoTGatewayHelper(t *testing.T) {
	if os.Getenv("VPNCTL_RESTRICTED_UOT_GATEWAY_HELPER") != "1" {
		t.Skip("gateway helper is enabled only by the task-8.4 Linux harness")
	}
	binary := pinnedMihomoPath(t)
	readyPath := os.Getenv("VPNCTL_RESTRICTED_UOT_READY_PATH")
	if !filepath.IsAbs(readyPath) || filepath.Clean(readyPath) != readyPath {
		t.Fatal("VPNCTL_RESTRICTED_UOT_READY_PATH must be clean and absolute")
	}
	tcpEcho, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(restrictedPinnedEchoPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	udpEcho, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: restrictedPinnedEchoPort})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	stopEcho := make(chan struct{})
	defer close(stopEcho)
	go serveRestrictedTCPEcho(tcpEcho, stopEcho)
	go serveRestrictedUDPEcho(udpEcho, stopEcho)

	directory := t.TempDir()
	stateDirectory := filepath.Join(directory, "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	state, credentials := restrictedGatewayFixture(t)
	artifact, err := RenderGatewayRestrictedConfig(GatewayRestrictedRenderRequest{
		State: state, CredentialRef: GatewayRestrictedCredentialRef, Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "gateway-uot.yaml")
	if err := os.WriteFile(configPath, artifact.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePinnedMihomoConfig(context.Background(), linuxplatform.OSProbeRunner{}, binary, stateDirectory, configPath); err != nil {
		t.Fatal(err)
	}
	process := startRestrictedPinnedProcess(t, binary, stateDirectory, configPath, RestrictedTCPPort)
	defer process.Stop(t)
	if output, err := exec.Command("ss", "-H", "-lunp", "sport = :8443").CombinedOutput(); err != nil || len(bytes.TrimSpace(output)) != 0 {
		t.Fatalf("gateway helper observed UDP/8443: %v", err)
	}
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	select {
	case <-interrupt:
	case <-time.After(2 * time.Minute):
		t.Fatal("gateway UoT helper exceeded its bounded lifetime")
	}
}

// The task-8.4 wrapper runs this test in the node fixture while the helper is
// ready. The production gate is exercised once with working UoT and once with
// the same TCP outbound plus explicit UDP reject as a broken-UoT control.
func TestRestrictedPinnedUoTReadinessAndFailClosed(t *testing.T) {
	if os.Getenv("VPNCTL_RESTRICTED_UOT_TEST") != "1" {
		t.Skip("set VPNCTL_RESTRICTED_UOT_TEST=1 in the task-8.4 Linux harness")
	}
	binary := pinnedMihomoPath(t)
	gatewayIP := os.Getenv("VPNCTL_RESTRICTED_UOT_GATEWAY_IP")
	address, err := netip.ParseAddr(gatewayIP)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.String() != gatewayIP {
		t.Fatal("VPNCTL_RESTRICTED_UOT_GATEWAY_IP must be canonical global-unicast IPv4")
	}
	candidate := restrictedPinnedNodeCandidate(t, gatewayIP)
	readinessConfig, err := RenderRestrictedReadinessConfig(candidate, restrictedPinnedReadinessSOCKSPort)
	if err != nil {
		t.Fatal(err)
	}
	prober, err := NewRestrictedNetworkReadinessProber(
		"127.0.0.1:17890", "127.0.0.1:18080",
		[]byte("vpnctl-v2-restricted-tcp-ready"), []byte("vpnctl-v2-restricted-uot-ready"), 20*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := NewRestrictedReadinessGate(prober)
	if err != nil {
		t.Fatal(err)
	}

	working := startRestrictedPinnedConfig(t, binary, readinessConfig, restrictedPinnedReadinessSOCKSPort)
	ready, positive, err := gate.Check(context.Background(), candidate)
	if err != nil || !ready.Valid() || !positive.Ready() {
		diagnosticContext, diagnosticCancel := context.WithTimeout(context.Background(), 3*time.Second)
		diagnosticTCP := restrictedSOCKSTCPRoundTrip(diagnosticContext, prober.proxy, prober.target, prober.tcpChallenge)
		diagnosticCancel()
		capture := restrictedPinnedCaptureSummary(t)
		working.Stop(t)
		t.Fatalf("working restricted UoT readiness = %#v, %v; tcp diagnostic = %v; capture = %s", positive, err, diagnosticTCP, capture)
	}
	working.Stop(t)

	brokenConfig := restrictedBrokenUoTConfig(t, readinessConfig)
	broken := startRestrictedPinnedConfig(t, binary, brokenConfig, restrictedPinnedReadinessSOCKSPort)
	notReady, negative, err := gate.Check(context.Background(), candidate)
	if err == nil || !errors.Is(err, ErrRestrictedNotReady) || !strings.Contains(err.Error(), "restricted-uot-unavailable") {
		broken.Stop(t)
		t.Fatalf("broken UoT readiness error = %v", err)
	}
	if notReady.Valid() || negative.SelectedTCP.State != ProbePassed || negative.SelectedUDP.State != ProbeFailed {
		broken.Stop(t)
		t.Fatalf("broken UoT became activatable: ready=%#v result=%#v", notReady, negative)
	}
	broken.Stop(t)

	unavailableConfig := restrictedUnavailableOuterConfig(t, readinessConfig)
	unavailable := startRestrictedPinnedConfig(t, binary, unavailableConfig, restrictedPinnedReadinessSOCKSPort)
	unavailableProber, err := NewRestrictedNetworkReadinessProber(
		"127.0.0.1:17890", "127.0.0.1:18080",
		[]byte("vpnctl-v2-restricted-tcp-unavailable"), []byte("vpnctl-v2-restricted-uot-unavailable"), time.Second,
	)
	if err != nil {
		unavailable.Stop(t)
		t.Fatal(err)
	}
	unavailableGate, err := NewRestrictedReadinessGate(unavailableProber)
	if err != nil {
		unavailable.Stop(t)
		t.Fatal(err)
	}
	notReady, unavailableResult, err := unavailableGate.Check(context.Background(), candidate)
	if err == nil || !errors.Is(err, ErrRestrictedNotReady) || notReady.Valid() ||
		unavailableResult.SelectedTCP.State != ProbeFailed || unavailableResult.SelectedUDP.State != ProbeFailed {
		unavailable.Stop(t)
		t.Fatalf("unavailable restricted path became activatable: ready=%#v result=%#v error=%v", notReady, unavailableResult, err)
	}
	unavailable.Stop(t)

	capture := restrictedPinnedCapture(t)
	protectedTCP := restrictedCapturePackets(t, string(capture), "protected-tcp")
	nativeUDP := restrictedCapturePackets(t, string(capture), "native-udp-leak")
	directTCP := restrictedCapturePackets(t, string(capture), "direct-tcp-leak")
	directUDP := restrictedCapturePackets(t, string(capture), "direct-udp-leak")
	if protectedTCP == 0 || nativeUDP != 0 || directTCP != 0 || directUDP != 0 {
		t.Fatalf("restricted UoT capture tcp=%d native_udp=%d direct_tcp=%d direct_udp=%d", protectedTCP, nativeUDP, directTCP, directUDP)
	}
	fmt.Fprintf(os.Stderr, "restricted UoT readiness: positive=tcp+udp broken_uot=tcp-only unavailable=blocked activation=blocked protected_tcp=%d native_udp=0 direct_tcp=0 direct_udp=0\n", protectedTCP)
}

func restrictedPinnedCapture(t *testing.T) []byte {
	t.Helper()
	table := os.Getenv("VPNCTL_RESTRICTED_UOT_CAPTURE_TABLE")
	if table == "" || strings.ContainsAny(table, " /\t\r\n") {
		t.Fatal("VPNCTL_RESTRICTED_UOT_CAPTURE_TABLE is invalid")
	}
	capture, err := exec.Command("nft", "list", "table", "inet", table).CombinedOutput()
	if err != nil {
		t.Fatalf("read task-8.4 capture: %v", err)
	}
	return capture
}

func restrictedPinnedCaptureSummary(t *testing.T) string {
	t.Helper()
	capture := string(restrictedPinnedCapture(t))
	return fmt.Sprintf("protected_tcp=%d native_udp=%d direct_tcp=%d direct_udp=%d",
		restrictedCapturePackets(t, capture, "protected-tcp"), restrictedCapturePackets(t, capture, "native-udp-leak"),
		restrictedCapturePackets(t, capture, "direct-tcp-leak"), restrictedCapturePackets(t, capture, "direct-udp-leak"))
}

func restrictedPinnedNodeCandidate(t *testing.T, gatewayIP string) RestrictedNodeCandidate {
	t.Helper()
	state, credentials := restrictedGatewayFixture(t)
	if len(state.Nodes) == 0 {
		t.Fatal("restricted gateway fixture has no nodes")
	}
	node := state.Nodes[0]
	var transport model.Transport
	found := false
	for _, value := range state.Transports {
		if value.OwnerKind == model.TargetNode && value.OwnerID == node.ID && value.Kind == model.TransportRestricted {
			transport = value
			found = true
			break
		}
	}
	if !found {
		t.Fatal("restricted gateway fixture has no node transport")
	}
	serverContent, err := credentials.Get(GatewayRestrictedCredentialRef)
	if err != nil {
		t.Fatal(err)
	}
	serverSecret, err := decodeRestrictedGatewaySecret(serverContent)
	if err != nil {
		t.Fatal(err)
	}
	identitySecret, err := credentials.Get(transport.CredentialRef)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := RenderNodeRestrictedConfig(NodeRestrictedRenderRequest{
		Transport: transport, Node: node, GatewayPublicIPv4: gatewayIP,
		ServerPassword: serverSecret.ShadowsocksPassword, IdentitySecret: identitySecret, Component: restrictedComponentPin(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func restrictedBrokenUoTConfig(t *testing.T, content []byte) []byte {
	t.Helper()
	result := string(content)
	replacements := []struct{ old, new string }{
		{"    udp: true\n", "    udp: false\n"},
		{"    udp-over-tcp: true\n", "    udp-over-tcp: false\n"},
		{"    udp-over-tcp-version: 2\n", ""},
		{"      - VPNCTL-RESTRICTED\n      - REJECT-DROP\n", "      - REJECT-DROP\n      - VPNCTL-RESTRICTED\n"},
	}
	for _, replacement := range replacements {
		if strings.Count(result, replacement.old) != 1 {
			t.Fatalf("broken-UoT fixture expected exactly one %q", replacement.old)
		}
		result = strings.Replace(result, replacement.old, replacement.new, 1)
	}
	return []byte(result)
}

func restrictedUnavailableOuterConfig(t *testing.T, content []byte) []byte {
	t.Helper()
	if strings.Count(string(content), "    port: 8443\n") != 1 {
		t.Fatal("unavailable restricted fixture expected one provider port")
	}
	return bytes.Replace(content, []byte("    port: 8443\n"), []byte("    port: 8444\n"), 1)
}

func startRestrictedPinnedConfig(t *testing.T, binary string, content []byte, port int) *restrictedPinnedProcess {
	t.Helper()
	directory := t.TempDir()
	stateDirectory := filepath.Join(directory, "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "node-uot.yaml")
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePinnedMihomoConfig(context.Background(), linuxplatform.OSProbeRunner{}, binary, stateDirectory, configPath); err != nil {
		t.Fatalf("pinned Mihomo rejected readiness config: %v", err)
	}
	return startRestrictedPinnedProcess(t, binary, stateDirectory, configPath, port)
}

type restrictedPinnedProcess struct {
	cancel  context.CancelFunc
	wait    chan error
	stopped bool
}

func startRestrictedPinnedProcess(t *testing.T, binary, stateDirectory, configPath string, port int) *restrictedPinnedProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, binary, "-d", stateDirectory, "-f", configPath)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	process := &restrictedPinnedProcess{cancel: cancel, wait: make(chan error, 1)}
	go func() { process.wait <- command.Wait() }()
	t.Cleanup(func() { process.Stop(t) })
	deadline := time.Now().Add(10 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return process
		}
		select {
		case <-process.wait:
			process.stopped = true
			t.Fatal("pinned Mihomo exited before readiness socket")
		default:
		}
		if time.Now().After(deadline) {
			process.Stop(t)
			t.Fatal("pinned Mihomo did not open readiness socket")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (process *restrictedPinnedProcess) Stop(t *testing.T) {
	t.Helper()
	if process == nil || process.stopped {
		return
	}
	process.cancel()
	select {
	case <-process.wait:
		process.stopped = true
	case <-time.After(5 * time.Second):
		t.Fatal("pinned Mihomo did not stop")
	}
}

func pinnedMihomoPath(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("VPNCTL_PINNED_MIHOMO")
	if binary == "" || !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		t.Fatal("VPNCTL_PINNED_MIHOMO must be clean and absolute")
	}
	return binary
}

func serveRestrictedTCPEcho(listener net.Listener, stop <-chan struct{}) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-stop:
				return
			default:
				return
			}
		}
		go func() {
			defer connection.Close()
			buffer := make([]byte, maximumRestrictedProbeBytes)
			count, err := connection.Read(buffer)
			if err == nil && count > 0 {
				_ = restrictedWriteAll(connection, buffer[:count])
			}
		}()
	}
}

func serveRestrictedUDPEcho(listener *net.UDPConn, stop <-chan struct{}) {
	buffer := make([]byte, maximumRestrictedProbeBytes)
	for {
		count, peer, err := listener.ReadFromUDPAddrPort(buffer)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				return
			}
		}
		_, _ = listener.WriteToUDPAddrPort(buffer[:count], peer)
	}
}

func restrictedCapturePackets(t *testing.T, output, marker string) uint64 {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, `comment "`+marker+`"`) {
			continue
		}
		fields := strings.Fields(line)
		for index, field := range fields {
			if field == "packets" && index+1 < len(fields) {
				value, err := strconv.ParseUint(fields[index+1], 10, 64)
				if err != nil {
					t.Fatalf("parse %s capture count: %v", marker, err)
				}
				return value
			}
		}
	}
	t.Fatalf("capture marker %s is absent", marker)
	return 0
}
