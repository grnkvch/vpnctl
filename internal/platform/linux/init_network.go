package linux

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

var (
	ErrInvalidGatewayNetwork = errors.New("invalid gateway initialization network inputs")
	interfaceNamePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
	cgnatPrefix              = netip.MustParsePrefix("100.64.0.0/10")
	benchmarkPrefix          = netip.MustParsePrefix("198.18.0.0/15")
)

type GatewayNetworkInput struct {
	PublicIPv4        string
	ClientCIDR        string
	NodeCIDR          string
	ExternalInterface string
}

type GatewayNetworkPlan struct {
	PublicIPv4        string
	ClientCIDR        string
	NodeCIDR          string
	ExternalInterface string
	InterfaceSource   string
}

type InputIssue struct {
	Field   string
	Code    string
	Message string
}

type GatewayNetworkError struct {
	Issues []InputIssue
}

func (err *GatewayNetworkError) Error() string {
	details := make([]string, len(err.Issues))
	for index, issue := range err.Issues {
		details[index] = fmt.Sprintf("%s: %s", issue.Field, issue.Message)
	}
	return fmt.Sprintf("%s: %s", ErrInvalidGatewayNetwork, strings.Join(details, "; "))
}

func (*GatewayNetworkError) Unwrap() error { return ErrInvalidGatewayNetwork }

// ValidateGatewayNetwork is pure: public IP discovery is deliberately absent.
// It validates only explicit input and the read-only host snapshot from task
// 5.1, returning a normalized plan that later init stages may consume.
func ValidateGatewayNetwork(input GatewayNetworkInput, snapshot HostSnapshot) (GatewayNetworkPlan, error) {
	issues := make([]InputIssue, 0)
	addIssue := func(field, code, message string) {
		issues = append(issues, InputIssue{Field: field, Code: code, Message: message})
	}
	if snapshot.SchemaVersion != HostSnapshotSchemaVersion {
		addIssue("host", "snapshot_version", fmt.Sprintf("requires discovery schema %d", HostSnapshotSchemaVersion))
	}

	publicAddress, publicValid := validatePublicIPv4(input.PublicIPv4, addIssue)
	clientText := input.ClientCIDR
	if clientText == "" {
		clientText = model.DefaultClientCIDR
	}
	nodeText := input.NodeCIDR
	if nodeText == "" {
		nodeText = model.DefaultNodeCIDR
	}
	clientPrefix, clientValid := validatePool("client_cidr", clientText, addIssue)
	nodePrefix, nodeValid := validatePool("node_cidr", nodeText, addIssue)
	if clientValid && nodeValid && clientPrefix.Overlaps(nodePrefix) {
		addIssue("client_cidr", "pool_overlap", fmt.Sprintf("%s overlaps node pool %s", clientPrefix, nodePrefix))
	}
	if publicValid && clientValid && clientPrefix.Contains(publicAddress) {
		addIssue("public_ipv4", "pool_overlap", fmt.Sprintf("address belongs to client pool %s", clientPrefix))
	}
	if publicValid && nodeValid && nodePrefix.Contains(publicAddress) {
		addIssue("public_ipv4", "pool_overlap", fmt.Sprintf("address belongs to node pool %s", nodePrefix))
	}

	observed := observedHostNetworks(snapshot)
	if clientValid {
		appendObservedOverlaps("client_cidr", clientPrefix, observed, addIssue)
	}
	if nodeValid {
		appendObservedOverlaps("node_cidr", nodePrefix, observed, addIssue)
	}

	externalInterface, source := validateExternalInterface(input.ExternalInterface, snapshot, addIssue)
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Field == issues[j].Field {
			if issues[i].Code == issues[j].Code {
				return issues[i].Message < issues[j].Message
			}
			return issues[i].Code < issues[j].Code
		}
		return issues[i].Field < issues[j].Field
	})
	if len(issues) != 0 {
		return GatewayNetworkPlan{}, &GatewayNetworkError{Issues: issues}
	}
	return GatewayNetworkPlan{
		PublicIPv4:        publicAddress.String(),
		ClientCIDR:        clientPrefix.String(),
		NodeCIDR:          nodePrefix.String(),
		ExternalInterface: externalInterface,
		InterfaceSource:   source,
	}, nil
}

func validatePublicIPv4(value string, addIssue func(string, string, string)) (netip.Addr, bool) {
	if value == "" {
		addIssue("public_ipv4", "required", "must be supplied explicitly; automatic external lookup is disabled")
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.String() != value {
		addIssue("public_ipv4", "invalid", "must be a canonical IPv4 address")
		return netip.Addr{}, false
	}
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || cgnatPrefix.Contains(address) || benchmarkPrefix.Contains(address) {
		addIssue("public_ipv4", "not_public", "must be a publicly routable unicast IPv4 address")
		return netip.Addr{}, false
	}
	return address, true
}

func validatePool(field, value string, addIssue func(string, string, string)) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || prefix.String() != value {
		addIssue(field, "invalid", "must be a canonical IPv4 prefix")
		return netip.Prefix{}, false
	}
	if prefix.Bits() > 30 {
		addIssue(field, "too_small", "must leave addresses for network, gateway, identity, and broadcast")
		return netip.Prefix{}, false
	}
	return prefix, true
}

func validateExternalInterface(explicit string, snapshot HostSnapshot, addIssue func(string, string, string)) (string, string) {
	selected := explicit
	source := "explicit"
	if explicit == "" {
		source = "default_route"
		devices := make(map[string]struct{})
		for _, route := range snapshot.Routes {
			if route.Family != "ipv4" || route.Destination != "default" || (route.Table != "main" && route.Table != "254") || route.Device == "" {
				continue
			}
			if route.Type == "unreachable" || route.Type == "blackhole" || route.Type == "prohibit" {
				continue
			}
			devices[route.Device] = struct{}{}
		}
		if len(devices) == 0 {
			addIssue("external_interface", "not_discovered", "no usable IPv4 default-route interface was found; provide --external-interface")
			return "", source
		}
		if len(devices) > 1 {
			names := make([]string, 0, len(devices))
			for name := range devices {
				names = append(names, name)
			}
			sort.Strings(names)
			addIssue("external_interface", "ambiguous", "multiple IPv4 default-route interfaces found ("+strings.Join(names, ", ")+"); provide --external-interface")
			return "", source
		}
		for name := range devices {
			selected = name
		}
	}
	if !interfaceNamePattern.MatchString(selected) {
		addIssue("external_interface", "invalid", "must be a valid Linux interface name of at most 15 bytes")
		return "", source
	}
	var found *NetworkInterface
	for index := range snapshot.Interfaces {
		if snapshot.Interfaces[index].Name == selected {
			found = &snapshot.Interfaces[index]
			break
		}
	}
	if found == nil {
		addIssue("external_interface", "not_found", fmt.Sprintf("interface %q is absent", selected))
		return "", source
	}
	if isContainerInterface(selected, snapshot.ContainerNetworks) || hasString(found.Flags, "LOOPBACK") {
		addIssue("external_interface", "unsafe_type", fmt.Sprintf("interface %q is loopback or container-owned", selected))
	}
	if !hasString(found.Flags, "UP") {
		addIssue("external_interface", "not_up", fmt.Sprintf("interface %q is not administratively up", selected))
	}
	hasIPv4 := false
	for _, address := range found.Addresses {
		parsed, err := netip.ParseAddr(address.Address)
		if err == nil && address.Family == "inet" && address.Scope != "host" && parsed.Is4() {
			hasIPv4 = true
			break
		}
	}
	if !hasIPv4 {
		addIssue("external_interface", "no_ipv4", fmt.Sprintf("interface %q has no non-host IPv4 address", selected))
	}
	return selected, source
}

type observedNetwork struct {
	prefix  netip.Prefix
	sources []string
}

func observedHostNetworks(snapshot HostSnapshot) []observedNetwork {
	byPrefix := make(map[string]map[string]struct{})
	add := func(prefix netip.Prefix, source string) {
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			return
		}
		prefix = prefix.Masked()
		key := prefix.String()
		if byPrefix[key] == nil {
			byPrefix[key] = make(map[string]struct{})
		}
		byPrefix[key][source] = struct{}{}
	}
	for _, networkInterface := range snapshot.Interfaces {
		for _, address := range networkInterface.Addresses {
			parsed, err := netip.ParseAddr(address.Address)
			if err == nil && parsed.Is4() && address.PrefixLen >= 0 && address.PrefixLen <= 32 {
				add(netip.PrefixFrom(parsed, address.PrefixLen), "interface "+networkInterface.Name)
			}
		}
	}
	for _, route := range snapshot.Routes {
		if route.Family != "ipv4" || route.Destination == "default" {
			continue
		}
		if prefix, err := netip.ParsePrefix(route.Destination); err == nil && prefix.Addr().Is4() {
			add(prefix, "route table "+route.Table)
		}
	}
	for _, network := range snapshot.ContainerNetworks {
		for _, value := range network.CIDRs {
			if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Is4() {
				add(prefix, "container interface "+network.Interface)
			}
		}
	}
	result := make([]observedNetwork, 0, len(byPrefix))
	for value, sources := range byPrefix {
		prefix := netip.MustParsePrefix(value)
		names := make([]string, 0, len(sources))
		for source := range sources {
			names = append(names, source)
		}
		sort.Strings(names)
		result = append(result, observedNetwork{prefix: prefix, sources: names})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].prefix.String() < result[j].prefix.String() })
	return result
}

func appendObservedOverlaps(field string, prefix netip.Prefix, observed []observedNetwork, addIssue func(string, string, string)) {
	for _, network := range observed {
		if prefix.Overlaps(network.prefix) {
			addIssue(field, "host_overlap", fmt.Sprintf("%s overlaps host network %s (%s)", prefix, network.prefix, strings.Join(network.sources, ", ")))
		}
	}
}

func isContainerInterface(name string, networks []ContainerNetwork) bool {
	for _, network := range networks {
		if network.Interface == name {
			return true
		}
	}
	return false
}

func hasString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
