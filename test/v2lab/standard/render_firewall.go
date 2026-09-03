package main

import (
	"fmt"
	"os"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func main() {
	artifact, err := linuxplatform.RenderGatewayFirewall(linuxplatform.GatewayFirewallInput{
		ExternalInterface: "eth0", SSHPort: 2222,
		ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24",
		ActiveClientIPv4: []string{"10.66.0.2", "10.66.0.3", "10.66.0.4", "10.66.0.5", "10.66.0.6"},
		ActiveNodeIPv4:   []string{"10.67.0.2", "10.67.0.3"},
		ClientTCPPorts:   []int{53}, ClientUDPPorts: []int{53},
		NodeTCPPorts: []int{53, 9443, 17000}, NodeUDPPorts: []int{53},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(artifact.Definition()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
