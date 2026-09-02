package linux

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

var ErrSSHPortUnverified = errors.New("SSH listener port could not be verified")

type SSHPortSource string

const (
	SSHPortFromConnection SSHPortSource = "ssh_connection"
	SSHPortFromOverride   SSHPortSource = "explicit_override"
)

type SSHPortInput struct {
	// ExplicitPort is nil when --ssh-port was not supplied. A pointer keeps an
	// explicitly supplied invalid zero distinguishable from an omitted flag.
	ExplicitPort  *int
	SSHConnection string
}

type SSHConnection struct {
	ClientAddress string `json:"client_address"`
	ClientPort    int    `json:"client_port"`
	ServerAddress string `json:"server_address"`
	ServerPort    int    `json:"server_port"`
}

type SSHPortPlan struct {
	Port              int           `json:"port"`
	Source            SSHPortSource `json:"source"`
	ListenerAddresses []string      `json:"listener_addresses"`
	// Connection is retained for the lockout watchdog, but is deliberately
	// omitted from operator-facing plan JSON.
	Connection *SSHConnection `json:"-"`
}

type SSHPortError struct {
	Code       string
	Message    string
	Candidates []int
}

func (err *SSHPortError) Error() string {
	message := fmt.Sprintf("%s: %s", ErrSSHPortUnverified, err.Message)
	if len(err.Candidates) != 0 {
		values := make([]string, len(err.Candidates))
		for index, candidate := range err.Candidates {
			values[index] = strconv.Itoa(candidate)
		}
		message += " (candidate ports: " + strings.Join(values, ", ") + ")"
	}
	return message
}

func (*SSHPortError) Unwrap() error { return ErrSSHPortUnverified }

// ResolveSSHPort only consumes explicit invocation data and the read-only host
// snapshot. It never assumes port 22 and performs no host mutation.
func ResolveSSHPort(input SSHPortInput, snapshot HostSnapshot) (SSHPortPlan, error) {
	if snapshot.SchemaVersion != HostSnapshotSchemaVersion {
		return SSHPortPlan{}, sshPortError("snapshot_version", fmt.Sprintf("requires discovery schema %d", HostSnapshotSchemaVersion), nil)
	}
	if input.ExplicitPort != nil {
		port := *input.ExplicitPort
		if !validTCPPort(port) {
			return SSHPortPlan{}, sshPortError("invalid_override", "--ssh-port must be between 1 and 65535", nil)
		}
		matches := verifiedSSHListeners(snapshot.Listeners, port, netip.Addr{})
		if len(matches) == 0 {
			return SSHPortPlan{}, sshPortError("override_not_listening", fmt.Sprintf("--ssh-port %d is not owned by an active sshd or systemd TCP listener", port), sshListenerPorts(snapshot.Listeners))
		}
		return newSSHPortPlan(port, SSHPortFromOverride, matches, nil), nil
	}

	connection, err := parseSSHConnection(input.SSHConnection)
	if err != nil {
		return SSHPortPlan{}, err
	}
	serverAddress := netip.MustParseAddr(connection.ServerAddress)
	matches := verifiedSSHListeners(snapshot.Listeners, connection.ServerPort, serverAddress)
	if len(matches) == 1 {
		return newSSHPortPlan(connection.ServerPort, SSHPortFromConnection, matches, &connection), nil
	}
	if len(matches) > 1 {
		return SSHPortPlan{}, sshPortError("ambiguous", fmt.Sprintf("SSH_CONNECTION matches multiple active SSH listener bindings on port %d; provide --ssh-port", connection.ServerPort), []int{connection.ServerPort})
	}

	candidates := sshListenerPorts(snapshot.Listeners)
	if len(candidates) > 1 {
		return SSHPortPlan{}, sshPortError("ambiguous", "SSH_CONNECTION does not unambiguously match the active SSH listeners; provide --ssh-port", candidates)
	}
	return SSHPortPlan{}, sshPortError("connection_mismatch", fmt.Sprintf("SSH_CONNECTION server %s:%d does not match an active sshd or systemd TCP listener", connection.ServerAddress, connection.ServerPort), candidates)
}

func parseSSHConnection(value string) (SSHConnection, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return SSHConnection{}, sshPortError("not_ssh", "SSH_CONNECTION is absent; run gateway init over SSH or provide --ssh-port", nil)
	}
	if len(fields) != 4 {
		return SSHConnection{}, sshPortError("invalid_connection", "SSH_CONNECTION must contain client address, client port, server address, and server port", nil)
	}
	clientAddress, err := parseConnectionAddress(fields[0])
	if err != nil {
		return SSHConnection{}, sshPortError("invalid_connection", "SSH_CONNECTION contains an invalid client address", nil)
	}
	clientPort, err := parseConnectionPort(fields[1])
	if err != nil {
		return SSHConnection{}, sshPortError("invalid_connection", "SSH_CONNECTION contains an invalid client port", nil)
	}
	serverAddress, err := parseConnectionAddress(fields[2])
	if err != nil || serverAddress.IsUnspecified() || serverAddress.IsMulticast() || serverAddress.IsLoopback() {
		return SSHConnection{}, sshPortError("invalid_connection", "SSH_CONNECTION contains an invalid server address", nil)
	}
	serverPort, err := parseConnectionPort(fields[3])
	if err != nil {
		return SSHConnection{}, sshPortError("invalid_connection", "SSH_CONNECTION contains an invalid server port", nil)
	}
	return SSHConnection{
		ClientAddress: clientAddress.String(),
		ClientPort:    clientPort,
		ServerAddress: serverAddress.String(),
		ServerPort:    serverPort,
	}, nil
}

func parseConnectionAddress(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	return address.Unmap(), nil
}

func parseConnectionPort(value string) (int, error) {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("invalid TCP port")
	}
	return int(parsed), nil
}

func verifiedSSHListeners(listeners []Listener, port int, serverAddress netip.Addr) []Listener {
	matches := make([]Listener, 0)
	seen := make(map[string]struct{})
	for _, listener := range listeners {
		if listener.Protocol != "tcp" || listener.Port != port || sshListenerOwner(listener.Process) == "" {
			continue
		}
		if serverAddress.IsValid() && !listenerAcceptsAddress(listener.Address, serverAddress) {
			continue
		}
		key := listener.Address + "\x00" + sshListenerOwner(listener.Process)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		matches = append(matches, listener)
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Address == matches[j].Address {
			return sshListenerOwner(matches[i].Process) < sshListenerOwner(matches[j].Process)
		}
		return matches[i].Address < matches[j].Address
	})
	return matches
}

func sshListenerOwner(process string) string {
	trimmed := strings.ToLower(strings.TrimSpace(process))
	for _, owner := range []string{"sshd", "systemd"} {
		if trimmed == owner || strings.Contains(trimmed, `"`+owner+`"`) {
			return owner
		}
	}
	return ""
}

func listenerAcceptsAddress(binding string, serverAddress netip.Addr) bool {
	if binding == "*" {
		return true
	}
	addressText := binding
	if zone := strings.LastIndexByte(addressText, '%'); zone >= 0 {
		addressText = addressText[:zone]
	}
	bindingAddress, err := netip.ParseAddr(addressText)
	if err != nil {
		return false
	}
	bindingAddress = bindingAddress.Unmap()
	if bindingAddress.IsUnspecified() {
		return bindingAddress.Is4() == serverAddress.Is4()
	}
	return bindingAddress == serverAddress
}

func sshListenerPorts(listeners []Listener) []int {
	ports := make(map[int]struct{})
	for _, listener := range listeners {
		if listener.Protocol == "tcp" && validTCPPort(listener.Port) && sshListenerOwner(listener.Process) != "" {
			ports[listener.Port] = struct{}{}
		}
	}
	result := make([]int, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Ints(result)
	return result
}

func newSSHPortPlan(port int, source SSHPortSource, listeners []Listener, connection *SSHConnection) SSHPortPlan {
	addresses := make([]string, 0, len(listeners))
	seen := make(map[string]struct{})
	for _, listener := range listeners {
		if _, exists := seen[listener.Address]; exists {
			continue
		}
		seen[listener.Address] = struct{}{}
		addresses = append(addresses, listener.Address)
	}
	return SSHPortPlan{Port: port, Source: source, ListenerAddresses: addresses, Connection: connection}
}

func sshPortError(code, message string, candidates []int) *SSHPortError {
	return &SSHPortError{Code: code, Message: message, Candidates: append([]int(nil), candidates...)}
}

func validTCPPort(port int) bool { return port >= 1 && port <= 65535 }
