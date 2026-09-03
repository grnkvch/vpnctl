package transport

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

// This test is opt-in because the exact pinned binary is Linux/amd64. The
// task-8.3 harness runs it inside an owner-scoped disposable network namespace.
func TestRestrictedPinnedMihomoConfigAndSocketContract(t *testing.T) {
	if os.Getenv("VPNCTL_RESTRICTED_SOCKET_TEST") != "1" {
		t.Skip("set VPNCTL_RESTRICTED_SOCKET_TEST=1 inside the isolated Linux harness")
	}
	binary := os.Getenv("VPNCTL_PINNED_MIHOMO")
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("VPNCTL_PINNED_MIHOMO must be an absolute path")
	}
	directory := t.TempDir()
	stateDirectory := filepath.Join(directory, "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	gatewayState, gatewayCredentials := restrictedGatewayFixture(t)
	gatewayArtifact, err := RenderGatewayRestrictedConfig(GatewayRestrictedRenderRequest{
		State: gatewayState, CredentialRef: GatewayRestrictedCredentialRef, Credentials: gatewayCredentials,
	})
	if err != nil {
		t.Fatalf("render production gateway restricted config: %v", err)
	}
	gatewayConfig := gatewayArtifact.Bytes()
	gatewayPath := filepath.Join(directory, RestrictedConfigFileName)
	if err := os.WriteFile(gatewayPath, gatewayConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePinnedMihomoConfig(context.Background(), linuxplatform.OSProbeRunner{}, binary, stateDirectory, gatewayPath); err != nil {
		t.Fatal(err)
	}

	node := restrictedNodeFixture()
	nodeCandidate, err := RenderNodeRestrictedConfig(NodeRestrictedRenderRequest{
		Transport: restrictedTransportFixture(model.TargetNode, node.ID, model.TransportActive, 4, "www.microsoft.com"),
		Node:      node, GatewayPublicIPv4: "203.0.113.10", ServerPassword: restrictedServerPassword(0x11),
		IdentitySecret: restrictedIdentitySecretBytes(t, 0x52), Component: restrictedComponentPin(),
	})
	if err != nil {
		t.Fatal(err)
	}
	nodePath := filepath.Join(directory, "node-restricted.yaml")
	if err := os.WriteFile(nodePath, nodeCandidate.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePinnedMihomoConfig(context.Background(), linuxplatform.OSProbeRunner{}, binary, stateDirectory, nodePath); err != nil {
		t.Fatalf("pinned Mihomo rejected strict node artifact: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, binary, "-d", stateDirectory, "-f", gatewayPath)
	var processOutput bytes.Buffer
	command.Stdout = &processOutput
	command.Stderr = &processOutput
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	processStopped := false
	t.Cleanup(func() {
		if processStopped {
			return
		}
		cancel()
		select {
		case <-wait:
		case <-time.After(5 * time.Second):
			t.Error("pinned Mihomo did not terminate after cancellation")
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp4", "127.0.0.1:8443", 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		select {
		case processErr := <-wait:
			t.Fatalf("pinned Mihomo exited before opening TCP/8443: %v: %s", processErr, processOutput.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("pinned Mihomo did not open TCP/8443: %s", processOutput.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	tcpSockets, err := exec.Command("ss", "-H", "-ltnp", "sport = :8443").CombinedOutput()
	if err != nil || !validRestrictedTCPListener(string(tcpSockets)) {
		t.Fatalf("unexpected TCP/8443 socket: %v: %s", err, tcpSockets)
	}
	udpSockets, err := exec.Command("ss", "-H", "-lunp", "sport = :8443").CombinedOutput()
	if err != nil || len(bytes.TrimSpace(udpSockets)) != 0 {
		t.Fatalf("unexpected UDP/8443 socket: %v: %s", err, udpSockets)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: RestrictedTCPPort})
	if err != nil {
		t.Fatalf("UDP/8443 is not free: %v", err)
	}
	_ = udp.Close()

	cancel()
	select {
	case <-wait:
		processStopped = true
	case <-time.After(5 * time.Second):
		t.Fatal("pinned Mihomo did not stop")
	}
	if output, err := exec.Command("ss", "-H", "-ltnp", "sport = :8443").CombinedOutput(); err != nil || len(bytes.TrimSpace(output)) != 0 {
		t.Fatalf("TCP/8443 remained after stop: %v: %s", err, output)
	}
	fmt.Fprintln(os.Stderr, "restricted pinned socket contract: tcp_8443=present_during_run udp_8443=absent cleanup=passed")
}
