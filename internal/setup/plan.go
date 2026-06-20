package setup

import (
	"fmt"
	"io"
	"strings"
)

const (
	DefaultName      = "main"
	DefaultPort      = 51820
	DefaultInterface = "wg0"
	DefaultSubnet    = "10.66.0.0/24"
	DefaultSSHPort   = 22
	DefaultStateDir  = ".vpnctl"
)

type Options struct {
	StateDir          string
	Endpoint          string
	Name              string
	Port              int
	Interface         string
	Subnet            string
	DNS               []string
	ExternalInterface string
	SSHPort           int
	EnableUFW         bool
}

func Defaults(stateDir string) Options {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	return Options{
		StateDir:  stateDir,
		Name:      DefaultName,
		Port:      DefaultPort,
		Interface: DefaultInterface,
		Subnet:    DefaultSubnet,
		SSHPort:   DefaultSSHPort,
		EnableUFW: true,
	}
}

func (o Options) Validate() error {
	if strings.TrimSpace(o.Endpoint) == "" {
		return fmt.Errorf("--endpoint is required")
	}
	if o.Port <= 0 || o.Port > 65535 {
		return fmt.Errorf("--port must be between 1 and 65535")
	}
	if o.SSHPort <= 0 || o.SSHPort > 65535 {
		return fmt.Errorf("--ssh-port must be between 1 and 65535")
	}
	if strings.TrimSpace(o.Interface) == "" {
		return fmt.Errorf("--interface is required")
	}
	if strings.TrimSpace(o.Subnet) == "" {
		return fmt.Errorf("--subnet is required")
	}
	return nil
}

func PrintDryRun(w io.Writer, o Options) {
	fmt.Fprintln(w, "setup plan (dry-run)")
	fmt.Fprintf(w, "state directory: %s\n", o.StateDir)
	fmt.Fprintf(w, "endpoint: %s\n", o.Endpoint)
	fmt.Fprintf(w, "wireguard interface: %s\n", o.Interface)
	fmt.Fprintf(w, "wireguard port: %d/udp\n", o.Port)
	fmt.Fprintf(w, "wireguard subnet: %s\n", o.Subnet)
	if len(o.DNS) == 0 {
		fmt.Fprintln(w, "client dns: <system default for WireGuard>")
	} else {
		fmt.Fprintf(w, "client dns: %s\n", strings.Join(o.DNS, ", "))
	}
	if o.ExternalInterface == "" {
		fmt.Fprintln(w, "external interface: <auto-detect>")
	} else {
		fmt.Fprintf(w, "external interface: %s\n", o.ExternalInterface)
	}
	fmt.Fprintf(w, "ssh port allowed in firewall: %d/tcp\n", o.SSHPort)
	fmt.Fprintf(w, "enable firewall: %t\n", o.EnableUFW)
	fmt.Fprintln(w)

	actions := []string{
		"would initialize vpnctl state if needed",
		"would verify supported Ubuntu platform",
		"would install required VPN packages",
		"would not perform a full system upgrade",
		"would generate server WireGuard keys",
		"would enable IPv4 forwarding",
		"would detect external network interface if not provided",
		"would write WireGuard server configuration",
		"would configure NAT and forwarding for VPN clients",
		"would allow SSH and WireGuard in firewall",
		"would start and enable WireGuard service",
		"would verify WireGuard status",
	}
	if o.EnableUFW {
		actions = append(actions, "would enable firewall")
	} else {
		actions = append(actions, "would leave firewall disabled")
	}

	for _, action := range actions {
		fmt.Fprintf(w, "- %s\n", action)
	}
}
