package linux

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const (
	GatewayFirewallFamily    = "inet"
	GatewayFirewallTable     = "vpnctl"
	GatewayOverlayInterface  = "vpnctl-wg"
	GatewayHTTPSTCPPort      = 443
	GatewayRestrictedTCPPort = 8443
	GatewayWireGuardUDPPort  = 51820
)

var ErrInvalidGatewayFirewall = errors.New("invalid gateway firewall inputs")

type GatewayFirewallInput struct {
	ExternalInterface string
	SSHPort           int
	ClientCIDR        string
	NodeCIDR          string
	OverlayInterface  string
	ClientTCPPorts    []int
	ClientUDPPorts    []int
	NodeTCPPorts      []int
	NodeUDPPorts      []int
}

type GatewayFirewallArtifact struct {
	definition []byte
}

func (artifact GatewayFirewallArtifact) Family() string { return GatewayFirewallFamily }

func (artifact GatewayFirewallArtifact) Table() string { return GatewayFirewallTable }

func (artifact GatewayFirewallArtifact) Definition() []byte {
	return append([]byte(nil), artifact.definition...)
}

// Transaction produces one nft batch. replaceOwned must only be true after
// the caller has independently proved that inet/vpnctl is owned by vpnctl.
// The batch never flushes the global ruleset or addresses a foreign table.
func (artifact GatewayFirewallArtifact) Transaction(replaceOwned bool) ([]byte, error) {
	if len(artifact.definition) == 0 {
		return nil, fmt.Errorf("invalid gateway firewall artifact")
	}
	var transaction bytes.Buffer
	if replaceOwned {
		fmt.Fprintf(&transaction, "delete table %s %s\n", GatewayFirewallFamily, GatewayFirewallTable)
	}
	transaction.Write(artifact.definition)
	return transaction.Bytes(), nil
}

// RenderGatewayFirewall renders only vpnctl's dedicated inet table. It does
// not inspect or mutate the host; validation completes before bytes are
// returned to a later atomic apply stage.
func RenderGatewayFirewall(input GatewayFirewallInput) (GatewayFirewallArtifact, error) {
	normalized, err := validateGatewayFirewallInput(input)
	if err != nil {
		return GatewayFirewallArtifact{}, err
	}

	publicTCPPorts := uniqueSortedPorts([]int{normalized.SSHPort, GatewayHTTPSTCPPort, GatewayRestrictedTCPPort})
	var rules bytes.Buffer
	fmt.Fprintf(&rules, "table %s %s {\n", GatewayFirewallFamily, GatewayFirewallTable)
	renderAddressSet(&rules, "client_v4", normalized.ClientCIDR)
	renderAddressSet(&rules, "node_v4", normalized.NodeCIDR)
	renderAddressSet(&rules, "overlay_v4", normalized.ClientCIDR+", "+normalized.NodeCIDR)
	rules.WriteString(`  set blocked_egress_v4 {
    type ipv4_addr
    flags interval
    elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }
  }

`)
	renderPortSet(&rules, "client_tcp_ports", normalized.ClientTCPPorts)
	renderPortSet(&rules, "client_udp_ports", normalized.ClientUDPPorts)
	renderPortSet(&rules, "node_tcp_ports", normalized.NodeTCPPorts)
	renderPortSet(&rules, "node_udp_ports", normalized.NodeUDPPorts)

	rules.WriteString("  chain input {\n")
	rules.WriteString("    type filter hook input priority filter; policy drop;\n\n")
	rules.WriteString("    ct state invalid drop\n")
	rules.WriteString("    ct state { established, related } accept\n")
	rules.WriteString("    iifname \"lo\" accept\n")
	if len(normalized.ClientTCPPorts) != 0 {
		fmt.Fprintf(&rules, "    iifname %s ip saddr @client_v4 tcp dport @client_tcp_ports accept\n", nftString(normalized.OverlayInterface))
	}
	if len(normalized.ClientUDPPorts) != 0 {
		fmt.Fprintf(&rules, "    iifname %s ip saddr @client_v4 udp dport @client_udp_ports accept\n", nftString(normalized.OverlayInterface))
	}
	if len(normalized.NodeTCPPorts) != 0 {
		fmt.Fprintf(&rules, "    iifname %s ip saddr @node_v4 tcp dport @node_tcp_ports accept\n", nftString(normalized.OverlayInterface))
	}
	if len(normalized.NodeUDPPorts) != 0 {
		fmt.Fprintf(&rules, "    iifname %s ip saddr @node_v4 udp dport @node_udp_ports accept\n", nftString(normalized.OverlayInterface))
	}
	fmt.Fprintf(&rules, "    ip saddr 0.0.0.0/0 tcp dport { %s } accept\n", renderPorts(publicTCPPorts))
	fmt.Fprintf(&rules, "    ip saddr 0.0.0.0/0 udp dport %d accept\n", GatewayWireGuardUDPPort)
	rules.WriteString("  }\n\n")

	rules.WriteString("  chain forward {\n")
	rules.WriteString("    type filter hook forward priority filter; policy drop;\n\n")
	rules.WriteString("    ct state invalid drop\n")
	rules.WriteString("    ct state { established, related } accept\n")
	rules.WriteString("    ip saddr @client_v4 ip daddr @client_v4 drop\n")
	rules.WriteString("    ip saddr @client_v4 ip daddr @node_v4 drop\n")
	rules.WriteString("    ip saddr @node_v4 ip daddr @client_v4 drop\n")
	rules.WriteString("    ip saddr @node_v4 ip daddr @node_v4 drop\n")
	fmt.Fprintf(&rules, "    iifname %s ip saddr @overlay_v4 ip daddr @blocked_egress_v4 drop\n", nftString(normalized.OverlayInterface))
	fmt.Fprintf(&rules, "    iifname %s oifname %s ip saddr @overlay_v4 accept\n", nftString(normalized.OverlayInterface), nftString(normalized.ExternalInterface))
	rules.WriteString("  }\n\n")

	rules.WriteString("  chain postrouting {\n")
	rules.WriteString("    type nat hook postrouting priority srcnat; policy accept;\n\n")
	fmt.Fprintf(&rules, "    oifname %s ip saddr @overlay_v4 masquerade\n", nftString(normalized.ExternalInterface))
	rules.WriteString("  }\n")
	rules.WriteString("}\n")

	return GatewayFirewallArtifact{definition: append([]byte(nil), rules.Bytes()...)}, nil
}

func validateGatewayFirewallInput(input GatewayFirewallInput) (GatewayFirewallInput, error) {
	issues := make([]string, 0)
	if !interfaceNamePattern.MatchString(input.ExternalInterface) {
		issues = append(issues, "external_interface must be a valid Linux interface name")
	}
	overlayInterface := input.OverlayInterface
	if overlayInterface == "" {
		overlayInterface = GatewayOverlayInterface
	}
	if !interfaceNamePattern.MatchString(overlayInterface) {
		issues = append(issues, "overlay_interface must be a valid Linux interface name")
	} else if overlayInterface == input.ExternalInterface {
		issues = append(issues, "overlay_interface must differ from external_interface")
	}
	if !validTCPPort(input.SSHPort) {
		issues = append(issues, "ssh_port must be between 1 and 65535")
	}
	clientPrefix, clientErr := canonicalFirewallPool(input.ClientCIDR)
	if clientErr != nil {
		issues = append(issues, "client_cidr "+clientErr.Error())
	}
	nodePrefix, nodeErr := canonicalFirewallPool(input.NodeCIDR)
	if nodeErr != nil {
		issues = append(issues, "node_cidr "+nodeErr.Error())
	}
	if clientErr == nil && nodeErr == nil && clientPrefix.Overlaps(nodePrefix) {
		issues = append(issues, "client_cidr overlaps node_cidr")
	}
	clientTCP, clientTCPErr := validatePortList("client_tcp_ports", input.ClientTCPPorts)
	if clientTCPErr != nil {
		issues = append(issues, clientTCPErr.Error())
	}
	clientUDP, clientUDPErr := validatePortList("client_udp_ports", input.ClientUDPPorts)
	if clientUDPErr != nil {
		issues = append(issues, clientUDPErr.Error())
	}
	nodeTCP, nodeTCPErr := validatePortList("node_tcp_ports", input.NodeTCPPorts)
	if nodeTCPErr != nil {
		issues = append(issues, nodeTCPErr.Error())
	}
	nodeUDP, nodeUDPErr := validatePortList("node_udp_ports", input.NodeUDPPorts)
	if nodeUDPErr != nil {
		issues = append(issues, nodeUDPErr.Error())
	}
	if len(issues) != 0 {
		sort.Strings(issues)
		return GatewayFirewallInput{}, fmt.Errorf("%w: %s", ErrInvalidGatewayFirewall, strings.Join(issues, "; "))
	}
	return GatewayFirewallInput{
		ExternalInterface: input.ExternalInterface,
		SSHPort:           input.SSHPort,
		ClientCIDR:        clientPrefix.String(),
		NodeCIDR:          nodePrefix.String(),
		OverlayInterface:  overlayInterface,
		ClientTCPPorts:    clientTCP,
		ClientUDPPorts:    clientUDP,
		NodeTCPPorts:      nodeTCP,
		NodeUDPPorts:      nodeUDP,
	}, nil
}

func canonicalFirewallPool(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || prefix.String() != value || prefix.Bits() > 30 {
		return netip.Prefix{}, fmt.Errorf("must be a canonical usable IPv4 prefix")
	}
	return prefix, nil
}

func validatePortList(field string, ports []int) ([]int, error) {
	for _, port := range ports {
		if !validTCPPort(port) {
			return nil, fmt.Errorf("%s must contain only ports between 1 and 65535", field)
		}
	}
	return uniqueSortedPorts(ports), nil
}

func uniqueSortedPorts(ports []int) []int {
	set := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		set[port] = struct{}{}
	}
	result := make([]int, 0, len(set))
	for port := range set {
		result = append(result, port)
	}
	sort.Ints(result)
	return result
}

func renderAddressSet(rules *bytes.Buffer, name, elements string) {
	fmt.Fprintf(rules, "  set %s {\n", name)
	rules.WriteString("    type ipv4_addr\n")
	rules.WriteString("    flags interval\n")
	fmt.Fprintf(rules, "    elements = { %s }\n", elements)
	rules.WriteString("  }\n\n")
}

func renderPortSet(rules *bytes.Buffer, name string, ports []int) {
	fmt.Fprintf(rules, "  set %s {\n", name)
	rules.WriteString("    type inet_service\n")
	if len(ports) != 0 {
		fmt.Fprintf(rules, "    elements = { %s }\n", renderPorts(ports))
	}
	rules.WriteString("  }\n\n")
}

func renderPorts(ports []int) string {
	values := make([]string, len(ports))
	for index, port := range ports {
		values[index] = strconv.Itoa(port)
	}
	return strings.Join(values, ", ")
}

func nftString(value string) string { return strconv.Quote(value) }
