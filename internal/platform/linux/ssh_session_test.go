package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSSHSessionInspectorProvesRealSSHDAncestorAndMonotonicStart(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeTestProcessStat(t, root, 300, "vpnctl", 200, 1_900)
	writeTestProcessStat(t, root, 200, "sudo", 100, 1_800)
	writeTestProcessStat(t, root, 100, "sshd", 1, 1_500)
	writeTestSSHSocket(t, root, 100, "0A7100CB:08AE", "140200C0:D6D9", "12345")
	bootIDPath := filepath.Join(root, "boot_id")
	if err := os.WriteFile(bootIDPath, []byte("12345678-1234-4234-8234-123456789abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := newWatchdogRunner(map[string]ProbeResult{
		watchdogCommandKey("getconf", "CLK_TCK"): {Stdout: []byte("100\n")},
	})
	inspector := &SSHSessionInspector{
		runner: runner, procRoot: root, bootIDPath: bootIDPath,
		currentPID:   func() int { return 300 },
		monotonicNow: func() (int64, error) { return 20_000_000_000, nil },
	}

	boundary, err := inspector.ActivationBoundary(context.Background())
	if err != nil {
		t.Fatalf("ActivationBoundary() error = %v", err)
	}
	if boundary.BootID != "12345678-1234-4234-8234-123456789abc" || boundary.MonotonicNanos != 20_000_000_000 {
		t.Fatalf("boundary = %+v", boundary)
	}
	proof, err := inspector.CurrentSSHSession(context.Background(), "192.0.2.20 55001 203.0.113.10 2222")
	if err != nil {
		t.Fatalf("CurrentSSHSession() error = %v", err)
	}
	if proof.StartedMonotonicNanos != 15_000_000_000 || proof.ObservedMonotonicNanos != 20_000_000_000 || proof.Connection.ServerPort != 2222 {
		t.Fatalf("proof = %+v", proof)
	}
}

func TestSSHSessionInspectorRejectsForgedEnvironmentWithoutSSHDAncestor(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeTestProcessStat(t, root, 300, "vpnctl", 200, 1_900)
	writeTestProcessStat(t, root, 200, "sudo", 1, 1_800)
	writeTestProcessStat(t, root, 1, "systemd", 0, 1)
	bootIDPath := filepath.Join(root, "boot_id")
	if err := os.WriteFile(bootIDPath, []byte("12345678-1234-4234-8234-123456789abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inspector := &SSHSessionInspector{
		runner: newWatchdogRunner(map[string]ProbeResult{
			watchdogCommandKey("getconf", "CLK_TCK"): {Stdout: []byte("100\n")},
		}),
		procRoot: root, bootIDPath: bootIDPath,
		currentPID:   func() int { return 300 },
		monotonicNow: func() (int64, error) { return 20_000_000_000, nil },
	}
	_, err := inspector.CurrentSSHSession(context.Background(), "192.0.2.20 55001 203.0.113.10 22")
	if !errors.Is(err, ErrSSHSessionUnverified) || !strings.Contains(err.Error(), "no sshd ancestor") {
		t.Fatalf("CurrentSSHSession() error = %v", err)
	}
}

func TestReadProcessStatHandlesSpacesAndParenthesesInCommand(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeTestProcessStat(t, root, 42, "strange (worker)", 7, 1234)
	stat, err := readProcessStat(filepath.Join(root, "42", "stat"))
	if err != nil {
		t.Fatal(err)
	}
	if stat.Command != "strange (worker)" || stat.ParentPID != 7 || stat.StartTicks != 1234 {
		t.Fatalf("stat = %+v", stat)
	}
}

func TestTicksToNanosIsBounded(t *testing.T) {
	t.Parallel()

	if got, err := ticksToNanos(155, 100); err != nil || got != 1_550_000_000 {
		t.Fatalf("ticksToNanos() = %d, %v", got, err)
	}
	for _, input := range [][2]uint64{{0, 100}, {100, 0}, {^uint64(0), 1}} {
		if _, err := ticksToNanos(input[0], input[1]); err == nil {
			t.Errorf("ticksToNanos(%d, %d) error = nil", input[0], input[1])
		}
	}
}

func TestParseProcTCPEndpointSupportsIPv4AndIPv6KernelByteOrder(t *testing.T) {
	t.Parallel()

	address, port, err := parseProcTCPEndpoint("0A7100CB:0016", false)
	if err != nil || address.String() != "203.0.113.10" || port != 22 {
		t.Fatalf("IPv4 endpoint = %s:%d, %v", address, port, err)
	}
	address, port, err = parseProcTCPEndpoint("B80D0120000000000000000001000000:08AE", true)
	if err != nil || address.String() != "2001:db8::1" || port != 2222 {
		t.Fatalf("IPv6 endpoint = %s:%d, %v", address, port, err)
	}
}

func writeTestProcessStat(t *testing.T, root string, pid int, command string, parentPID int, startTicks uint64) {
	t.Helper()
	directory := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 50)
	for index := range fields {
		fields[index] = "0"
	}
	fields[0] = "S"
	fields[1] = strconv.Itoa(parentPID)
	fields[19] = strconv.FormatUint(startTicks, 10)
	content := fmt.Sprintf("%d (%s) %s\n", pid, command, strings.Join(fields, " "))
	if err := os.WriteFile(filepath.Join(directory, "stat"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTestSSHSocket(t *testing.T, root string, pid int, local, remote, inode string) {
	t.Helper()
	directory := filepath.Join(root, strconv.Itoa(pid))
	fdDirectory := filepath.Join(directory, "fd")
	netDirectory := filepath.Join(directory, "net")
	if err := os.MkdirAll(fdDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(netDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:["+inode+"]", filepath.Join(fdDirectory, "3")); err != nil {
		t.Fatal(err)
	}
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000 0 0 %s\n", local, remote, inode)
	if err := os.WriteFile(filepath.Join(netDirectory, "tcp"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
