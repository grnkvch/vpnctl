//go:build linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const nodeTransportCandidateParentDeathHelper = "VPNCTL_CANDIDATE_PARENT_DEATH_HELPER"

func TestConfigureNodeTransportCandidateProcessKillsChildWithParent(t *testing.T) {
	command := exec.Command("/bin/true")
	if err := configureNodeTransportCandidateProcess(command); err != nil {
		t.Fatal(err)
	}
	if command.SysProcAttr == nil || command.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("candidate process attributes = %+v", command.SysProcAttr)
	}
}

func TestNodeTransportCandidateProcessDiesWithParent(t *testing.T) {
	if os.Getenv(nodeTransportCandidateParentDeathHelper) == "1" {
		runNodeTransportCandidateParentDeathHelper(t)
		os.Exit(0)
	}
	binaryPath := os.Getenv("VPNCTL_PINNED_MIHOMO")
	if binaryPath == "" {
		t.Skip("VPNCTL_PINNED_MIHOMO is required for the Linux process gate")
	}
	if !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath {
		t.Fatal("VPNCTL_PINNED_MIHOMO must be an absolute clean path")
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	resultPath := filepath.Join(root, "candidate-process.txt")
	command := exec.Command(testBinary, "-test.run=^TestNodeTransportCandidateProcessDiesWithParent$")
	command.Env = append(os.Environ(),
		nodeTransportCandidateParentDeathHelper+"=1",
		"VPNCTL_PINNED_MIHOMO="+binaryPath,
		"VPNCTL_CANDIDATE_TEST_ROOT="+root,
		"VPNCTL_CANDIDATE_RESULT="+resultPath,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("candidate parent helper: %v\n%s", err, output)
	}
	content, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	var pid, port int
	if count, scanErr := fmt.Sscanf(string(content), "%d %d\n", &pid, &port); scanErr != nil || count != 2 || pid <= 1 || port < 1024 {
		t.Fatalf("candidate parent helper result %q: %v", content, scanErr)
	}
	defer killExactTestCandidateProcess(binaryPath, pid)
	deadline := time.Now().Add(5 * time.Second)
	for {
		processErr := syscall.Kill(pid, 0)
		connection, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
		if connection != nil {
			_ = connection.Close()
		}
		if errors.Is(processErr, syscall.ESRCH) && dialErr != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("candidate process %d or its listener survived parent exit: process=%v dial=%v", pid, processErr, dialErr)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func runNodeTransportCandidateParentDeathHelper(t *testing.T) {
	t.Helper()
	binaryPath := os.Getenv("VPNCTL_PINNED_MIHOMO")
	root := os.Getenv("VPNCTL_CANDIDATE_TEST_ROOT")
	resultPath := os.Getenv("VPNCTL_CANDIDATE_RESULT")
	if !filepath.IsAbs(binaryPath) || filepath.Clean(binaryPath) != binaryPath ||
		!filepath.IsAbs(root) || filepath.Clean(root) != root ||
		filepath.Dir(resultPath) != root || filepath.Clean(resultPath) != resultPath {
		t.Fatal("candidate parent helper paths are invalid")
	}
	stateDirectory := filepath.Join(root, "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	port, err := reserveNodeTransportCandidateSOCKSPort()
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "candidate.yaml")
	config := []byte(fmt.Sprintf("socks-port: %d\nallow-lan: false\nbind-address: 127.0.0.1\nmode: rule\nlog-level: silent\nipv6: false\nrules:\n  - MATCH,DIRECT\n", port))
	if err := writeNodeTransportCandidateConfig(configPath, config); err != nil {
		t.Fatal(err)
	}
	process, err := startNodeTransportCandidateProcess(context.Background(), binaryPath, []string{"-d", stateDirectory, "-f", configPath})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = process.Stop(cleanupContext)
	}()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := waitNodeTransportCandidateSOCKS(context.Background(), address, process.Done()); err != nil {
		t.Fatal(err)
	}
	if err := verifyNodeTransportCandidateSOCKS(context.Background(), linuxplatform.OSProbeRunner{}, address, process.PID()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resultPath, []byte(fmt.Sprintf("%d %d\n", process.PID(), port)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func killExactTestCandidateProcess(binaryPath string, pid int) {
	executable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil || strings.TrimSuffix(executable, " (deleted)") != binaryPath {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
