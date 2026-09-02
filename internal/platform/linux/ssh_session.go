package linux

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const maximumSSHSessionAncestors = 64

var (
	ErrSSHSessionUnverified = errors.New("current SSH session could not be verified")
	bootIDPattern           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type MonotonicBoundary struct {
	BootID         string `json:"boot_id"`
	MonotonicNanos int64  `json:"monotonic_nanos"`
}

type SSHSessionProof struct {
	Connection             SSHConnection
	BootID                 string
	StartedMonotonicNanos  int64
	ObservedMonotonicNanos int64
}

type SSHSessionInspector struct {
	runner       ProbeRunner
	procRoot     string
	bootIDPath   string
	currentPID   func() int
	monotonicNow func() (int64, error)
}

func NewOSSSHSessionInspector() *SSHSessionInspector {
	return &SSHSessionInspector{
		runner:       OSProbeRunner{},
		procRoot:     "/proc",
		bootIDPath:   "/proc/sys/kernel/random/boot_id",
		currentPID:   os.Getpid,
		monotonicNow: readMonotonicNanos,
	}
}

func (inspector *SSHSessionInspector) ActivationBoundary(ctx context.Context) (MonotonicBoundary, error) {
	if err := inspector.validate(ctx); err != nil {
		return MonotonicBoundary{}, err
	}
	bootID, err := inspector.readBootID()
	if err != nil {
		return MonotonicBoundary{}, err
	}
	nanos, err := inspector.monotonicNow()
	if err != nil {
		return MonotonicBoundary{}, fmt.Errorf("read monotonic activation boundary: %w", err)
	}
	if nanos <= 0 {
		return MonotonicBoundary{}, fmt.Errorf("read monotonic activation boundary: non-positive value")
	}
	return MonotonicBoundary{BootID: bootID, MonotonicNanos: nanos}, nil
}

func (inspector *SSHSessionInspector) CurrentSSHSession(ctx context.Context, rawConnection string) (SSHSessionProof, error) {
	if err := inspector.validate(ctx); err != nil {
		return SSHSessionProof{}, err
	}
	connection, err := ParseSSHConnection(rawConnection)
	if err != nil {
		return SSHSessionProof{}, fmt.Errorf("%w: %v", ErrSSHSessionUnverified, err)
	}
	bootID, err := inspector.readBootID()
	if err != nil {
		return SSHSessionProof{}, fmt.Errorf("%w: %v", ErrSSHSessionUnverified, err)
	}
	ticksPerSecond, err := inspector.clockTicksPerSecond(ctx)
	if err != nil {
		return SSHSessionProof{}, fmt.Errorf("%w: %v", ErrSSHSessionUnverified, err)
	}
	sshProcess, err := inspector.findSSHAncestor(ctx)
	if err != nil {
		return SSHSessionProof{}, err
	}
	if err := inspector.verifySSHSocket(sshProcess.PID, connection); err != nil {
		return SSHSessionProof{}, err
	}
	startedNanos, err := ticksToNanos(sshProcess.StartTicks, ticksPerSecond)
	if err != nil {
		return SSHSessionProof{}, fmt.Errorf("%w: %v", ErrSSHSessionUnverified, err)
	}
	observedNanos, err := inspector.monotonicNow()
	if err != nil {
		return SSHSessionProof{}, fmt.Errorf("%w: read monotonic observation: %v", ErrSSHSessionUnverified, err)
	}
	if observedNanos <= 0 || startedNanos <= 0 || startedNanos > observedNanos {
		return SSHSessionProof{}, fmt.Errorf("%w: SSH process start time is inconsistent", ErrSSHSessionUnverified)
	}
	return SSHSessionProof{
		Connection:             connection,
		BootID:                 bootID,
		StartedMonotonicNanos:  startedNanos,
		ObservedMonotonicNanos: observedNanos,
	}, nil
}

func (inspector *SSHSessionInspector) validate(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if inspector == nil || inspector.runner == nil || inspector.currentPID == nil || inspector.monotonicNow == nil {
		return fmt.Errorf("SSH session inspector is incomplete")
	}
	if !filepath.IsAbs(inspector.procRoot) || filepath.Clean(inspector.procRoot) != inspector.procRoot ||
		!filepath.IsAbs(inspector.bootIDPath) || filepath.Clean(inspector.bootIDPath) != inspector.bootIDPath {
		return fmt.Errorf("SSH session inspector paths must be clean and absolute")
	}
	return nil
}

func (inspector *SSHSessionInspector) readBootID() (string, error) {
	data, err := os.ReadFile(inspector.bootIDPath)
	if err != nil {
		return "", fmt.Errorf("read kernel boot ID: %w", err)
	}
	value := strings.TrimSpace(string(data))
	if !bootIDPattern.MatchString(value) {
		return "", fmt.Errorf("read kernel boot ID: invalid value")
	}
	return value, nil
}

func (inspector *SSHSessionInspector) clockTicksPerSecond(ctx context.Context) (uint64, error) {
	result, err := inspector.runner.Run(ctx, ProbeCommand{Name: "getconf", Args: []string{"CLK_TCK"}})
	if err != nil {
		return 0, fmt.Errorf("read kernel clock tick rate: %w", err)
	}
	if result.ExitCode != 0 {
		return 0, fmt.Errorf("read kernel clock tick rate: getconf exit code %d", result.ExitCode)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(result.Stdout)), 10, 32)
	if err != nil || value == 0 || value > 1_000_000_000 {
		return 0, fmt.Errorf("read kernel clock tick rate: invalid value")
	}
	return value, nil
}

func (inspector *SSHSessionInspector) findSSHAncestor(ctx context.Context) (sshProcess, error) {
	pid := inspector.currentPID()
	if pid <= 0 {
		return sshProcess{}, fmt.Errorf("%w: invalid current process ID", ErrSSHSessionUnverified)
	}
	seen := make(map[int]struct{})
	for depth := 0; depth < maximumSSHSessionAncestors && pid > 0; depth++ {
		if err := ctx.Err(); err != nil {
			return sshProcess{}, err
		}
		if _, duplicate := seen[pid]; duplicate {
			return sshProcess{}, fmt.Errorf("%w: process ancestry contains a cycle", ErrSSHSessionUnverified)
		}
		seen[pid] = struct{}{}
		stat, err := readProcessStat(filepath.Join(inspector.procRoot, strconv.Itoa(pid), "stat"))
		if err != nil {
			return sshProcess{}, fmt.Errorf("%w: inspect process ancestry: %v", ErrSSHSessionUnverified, err)
		}
		if stat.Command == "sshd" {
			return sshProcess{PID: pid, StartTicks: stat.StartTicks}, nil
		}
		pid = stat.ParentPID
	}
	return sshProcess{}, fmt.Errorf("%w: current process has no sshd ancestor", ErrSSHSessionUnverified)
}

type sshProcess struct {
	PID        int
	StartTicks uint64
}

func (inspector *SSHSessionInspector) verifySSHSocket(pid int, connection SSHConnection) error {
	fdDirectory := filepath.Join(inspector.procRoot, strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(fdDirectory)
	if err != nil {
		return fmt.Errorf("%w: inspect sshd sockets: %v", ErrSSHSessionUnverified, err)
	}
	inodes := make(map[string]struct{})
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDirectory, entry.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, err := strconv.ParseUint(inode, 10, 64); err == nil {
				inodes[inode] = struct{}{}
			}
		}
	}
	if len(inodes) == 0 {
		return fmt.Errorf("%w: sshd ancestor has no socket descriptors", ErrSSHSessionUnverified)
	}
	serverAddress := netip.MustParseAddr(connection.ServerAddress).Unmap()
	clientAddress := netip.MustParseAddr(connection.ClientAddress).Unmap()
	for _, table := range []struct {
		name string
		ipv6 bool
	}{{name: "tcp"}, {name: "tcp6", ipv6: true}} {
		data, err := os.ReadFile(filepath.Join(inspector.procRoot, strconv.Itoa(pid), "net", table.name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: inspect sshd %s sockets: %v", ErrSSHSessionUnverified, table.name, err)
		}
		matched, err := procTCPContainsConnection(data, table.ipv6, inodes, serverAddress, connection.ServerPort, clientAddress, connection.ClientPort)
		if err != nil {
			return fmt.Errorf("%w: inspect sshd %s sockets: %v", ErrSSHSessionUnverified, table.name, err)
		}
		if matched {
			return nil
		}
	}
	return fmt.Errorf("%w: SSH_CONNECTION does not match an established sshd socket", ErrSSHSessionUnverified)
}

func procTCPContainsConnection(data []byte, ipv6 bool, inodes map[string]struct{}, localAddress netip.Addr, localPort int, remoteAddress netip.Addr, remotePort int) (bool, error) {
	lines := strings.Split(string(data), "\n")
	for index, line := range lines {
		fields := strings.Fields(line)
		if index == 0 || len(fields) == 0 {
			continue
		}
		if len(fields) < 10 {
			return false, fmt.Errorf("malformed proc TCP row")
		}
		if fields[3] != "01" {
			continue
		}
		if _, owned := inodes[fields[9]]; !owned {
			continue
		}
		rowLocalAddress, rowLocalPort, err := parseProcTCPEndpoint(fields[1], ipv6)
		if err != nil {
			return false, err
		}
		rowRemoteAddress, rowRemotePort, err := parseProcTCPEndpoint(fields[2], ipv6)
		if err != nil {
			return false, err
		}
		if rowLocalAddress.Unmap() == localAddress && rowLocalPort == localPort && rowRemoteAddress.Unmap() == remoteAddress && rowRemotePort == remotePort {
			return true, nil
		}
	}
	return false, nil
}

func parseProcTCPEndpoint(value string, ipv6 bool) (netip.Addr, int, error) {
	addressHex, portHex, found := strings.Cut(value, ":")
	addressBytes := 4
	if ipv6 {
		addressBytes = 16
	}
	if !found || len(addressHex) != addressBytes*2 || len(portHex) != 4 {
		return netip.Addr{}, 0, fmt.Errorf("invalid proc TCP endpoint")
	}
	decoded := make([]byte, addressBytes)
	for index := 0; index < addressBytes; index++ {
		parsedByte, err := strconv.ParseUint(addressHex[index*2:index*2+2], 16, 8)
		if err != nil {
			return netip.Addr{}, 0, fmt.Errorf("invalid proc TCP address")
		}
		decoded[index] = byte(parsedByte)
	}
	for start := 0; start < len(decoded); start += 4 {
		decoded[start], decoded[start+3] = decoded[start+3], decoded[start]
		decoded[start+1], decoded[start+2] = decoded[start+2], decoded[start+1]
	}
	address, ok := netip.AddrFromSlice(decoded)
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("invalid proc TCP address")
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil || port == 0 {
		return netip.Addr{}, 0, fmt.Errorf("invalid proc TCP port")
	}
	return address, int(port), nil
}

type processStat struct {
	Command    string
	ParentPID  int
	StartTicks uint64
}

func readProcessStat(path string) (processStat, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return processStat{}, err
	}
	text := strings.TrimSpace(string(data))
	open := strings.IndexByte(text, '(')
	close := strings.LastIndex(text, ") ")
	if open <= 0 || close <= open+1 {
		return processStat{}, fmt.Errorf("invalid proc stat format")
	}
	fields := strings.Fields(text[close+2:])
	// fields[0] is proc field 3 (state), fields[1] is field 4 (ppid),
	// and fields[19] is field 22 (starttime).
	if len(fields) <= 19 {
		return processStat{}, fmt.Errorf("incomplete proc stat")
	}
	parentPID, err := strconv.Atoi(fields[1])
	if err != nil || parentPID < 0 {
		return processStat{}, fmt.Errorf("invalid proc parent process ID")
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTicks == 0 {
		return processStat{}, fmt.Errorf("invalid proc process start time")
	}
	return processStat{Command: text[open+1 : close], ParentPID: parentPID, StartTicks: startTicks}, nil
}

func ticksToNanos(ticks, ticksPerSecond uint64) (int64, error) {
	if ticks == 0 || ticksPerSecond == 0 {
		return 0, fmt.Errorf("clock ticks must be positive")
	}
	seconds := ticks / ticksPerSecond
	remainder := ticks % ticksPerSecond
	if seconds > math.MaxInt64/1_000_000_000 {
		return 0, fmt.Errorf("process start time overflows nanoseconds")
	}
	nanos := seconds*1_000_000_000 + remainder*1_000_000_000/ticksPerSecond
	if nanos > math.MaxInt64 {
		return 0, fmt.Errorf("process start time overflows nanoseconds")
	}
	return int64(nanos), nil
}

func readMonotonicNanos() (int64, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &value); err != nil {
		return 0, err
	}
	return value.Nano(), nil
}
