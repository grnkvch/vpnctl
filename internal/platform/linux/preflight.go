package linux

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	VPNCTLSelectedRouteTable = "20001"
	VPNCTLGatewayRouteTable  = "20002"
	VPNCTLMarkMask           = uint64(0xff000000)
)

var (
	ErrInvalidGatewayPreflight  = errors.New("invalid gateway preflight inputs")
	ErrGatewayPreflightConflict = errors.New("gateway preflight found conflicts")
	quotedProcessPattern        = regexp.MustCompile(`"([^"]+)"`)
)

type GatewayPreflightInput struct {
	Network GatewayNetworkPlan
	SSH     SSHPortPlan
}

type GatewayConflict struct {
	Code           string `json:"code"`
	Resource       string `json:"resource"`
	Problem        string `json:"problem"`
	RequiredAction string `json:"required_action"`
}

type GatewayPreflightPlan struct {
	Ready              bool              `json:"ready"`
	Conflicts          []GatewayConflict `json:"conflicts"`
	PreservedResources []string          `json:"preserved_resources"`
}

type GatewayPreflightError struct {
	Conflicts []GatewayConflict
}

func (err *GatewayPreflightError) Error() string {
	return fmt.Sprintf("%s: %d conflict(s); resolve every required_action before retrying", ErrGatewayPreflightConflict, len(err.Conflicts))
}

func (*GatewayPreflightError) Unwrap() error { return ErrGatewayPreflightConflict }

// AnalyzeGatewayPreflight is a read-only planner. It reports every known
// conflict together and never edits, stops, or adopts the observed resources.
func AnalyzeGatewayPreflight(input GatewayPreflightInput, snapshot HostSnapshot) (GatewayPreflightPlan, error) {
	if err := validateGatewayPreflightInput(input, snapshot); err != nil {
		return GatewayPreflightPlan{}, err
	}

	conflicts := make(map[string]GatewayConflict)
	preserved := make(map[string]struct{})
	addConflict := func(conflict GatewayConflict) {
		key := conflict.Code + "\x00" + conflict.Resource
		conflicts[key] = conflict
	}
	addPreserved := func(resource string) {
		preserved[resource] = struct{}{}
	}

	analyzeFirewallServices(snapshot.Services, addConflict)
	analyzeNFTablesTables(snapshot.NFTablesTables, addConflict, addPreserved)
	analyzeListeners(snapshot.Listeners, input.SSH.Port, addConflict, addPreserved)
	tunnelInterfaces := analyzeTunnelInterfaces(snapshot.Interfaces, input.Network.ExternalInterface, addConflict)
	analyzeRoutes(snapshot.Routes, input.Network.ExternalInterface, tunnelInterfaces, addConflict)
	analyzePolicyRules(snapshot.PolicyRules, addConflict, addPreserved)

	plan := GatewayPreflightPlan{
		Ready:              len(conflicts) == 0,
		Conflicts:          sortedGatewayConflicts(conflicts),
		PreservedResources: sortedResourceNames(preserved),
	}
	if len(plan.Conflicts) != 0 {
		return plan, &GatewayPreflightError{Conflicts: append([]GatewayConflict(nil), plan.Conflicts...)}
	}
	return plan, nil
}

func validateGatewayPreflightInput(input GatewayPreflightInput, snapshot HostSnapshot) error {
	issues := make([]string, 0)
	if snapshot.SchemaVersion != HostSnapshotSchemaVersion {
		issues = append(issues, fmt.Sprintf("host snapshot schema must be %d", HostSnapshotSchemaVersion))
	}
	_, firewallErr := validateGatewayFirewallInput(GatewayFirewallInput{
		ExternalInterface: input.Network.ExternalInterface,
		SSHPort:           input.SSH.Port,
		ClientCIDR:        input.Network.ClientCIDR,
		NodeCIDR:          input.Network.NodeCIDR,
	})
	if firewallErr != nil {
		issues = append(issues, firewallErr.Error())
	}
	validatePublicIPv4(input.Network.PublicIPv4, func(_ string, _ string, message string) {
		issues = append(issues, "network plan public_ipv4 "+message)
	})
	if input.SSH.Source != SSHPortFromConnection && input.SSH.Source != SSHPortFromOverride {
		issues = append(issues, "SSH plan must contain a verified source")
	}
	if len(issues) != 0 {
		sort.Strings(issues)
		return fmt.Errorf("%w: %s", ErrInvalidGatewayPreflight, strings.Join(issues, "; "))
	}
	return nil
}

func analyzeFirewallServices(services []Service, add func(GatewayConflict)) {
	for _, service := range services {
		name := strings.ToLower(service.Name)
		if (name != "ufw.service" && name != "firewalld.service") || service.ActiveState != "active" {
			continue
		}
		add(GatewayConflict{
			Code:           "active_firewall_manager",
			Resource:       "service:" + service.Name,
			Problem:        service.Name + " is active and may race or override the vpnctl nftables policy",
			RequiredAction: "disable the service and remove its active rules, or use the documented v1 migration path, then rerun preflight",
		})
	}
}

func analyzeNFTablesTables(tables []NFTablesTable, add func(GatewayConflict), preserve func(string)) {
	for _, table := range tables {
		resource := "nftables:" + table.Family + "/" + table.Name
		if table.Family == GatewayFirewallFamily && table.Name == GatewayFirewallTable {
			add(GatewayConflict{
				Code:           "owned_table_name_collision",
				Resource:       resource,
				Problem:        "inet/vpnctl already exists but initialization has not proved its ownership",
				RequiredAction: "inspect the table and remove or migrate it explicitly; vpnctl init will not adopt or delete it",
			})
			continue
		}
		lower := strings.ToLower(table.Name)
		if strings.Contains(lower, "ufw") || strings.Contains(lower, "firewalld") {
			add(GatewayConflict{
				Code:           "firewall_table_conflict",
				Resource:       resource,
				Problem:        "an existing firewall-manager table may impose an incompatible policy",
				RequiredAction: "remove the owning firewall-manager rules after reviewing them, then rerun preflight",
			})
			continue
		}
		preserve(resource)
	}
}

func analyzeListeners(listeners []Listener, sshPort int, add func(GatewayConflict), preserve func(string)) {
	for _, listener := range listeners {
		resource := listenerResource(listener)
		portCode, purpose := reservedListenerConflict(listener.Protocol, listener.Port)
		if portCode != "" {
			add(GatewayConflict{
				Code:           portCode,
				Resource:       resource,
				Problem:        fmt.Sprintf("the listener occupies %s", purpose),
				RequiredAction: fmt.Sprintf("stop or rebind the owning process so %s is free, then rerun preflight", purpose),
			})
		}
		proxy := reverseProxyOwner(listener.Process)
		if proxy != "" {
			add(GatewayConflict{
				Code:           "unmanaged_reverse_proxy",
				Resource:       resource,
				Problem:        fmt.Sprintf("unmanaged reverse proxy %q is listening on the dedicated gateway", proxy),
				RequiredAction: "stop and remove or relocate the unmanaged reverse proxy before vpnctl initializes its managed ingress",
			})
		}
		isVerifiedSSH := listener.Protocol == "tcp" && listener.Port == sshPort && sshListenerOwner(listener.Process) != ""
		if portCode == "" && proxy == "" && !isVerifiedSSH {
			preserve(resource)
		}
	}
}

func reservedListenerConflict(protocol string, port int) (string, string) {
	switch {
	case protocol == "tcp" && port == GatewayHTTPSTCPPort:
		return "reserved_port_occupied", "managed HTTPS port 443/TCP"
	case protocol == "tcp" && port == GatewayRestrictedTCPPort:
		return "reserved_port_occupied", "restricted transport port 8443/TCP"
	case protocol == "udp" && port == GatewayWireGuardUDPPort:
		return "reserved_port_occupied", "WireGuard port 51820/UDP"
	case protocol == "udp" && port == GatewayHTTPSTCPPort:
		return "forbidden_udp_listener", "forbidden port 443/UDP"
	case protocol == "udp" && port == GatewayRestrictedTCPPort:
		return "forbidden_udp_listener", "forbidden port 8443/UDP"
	default:
		return "", ""
	}
}

func analyzeTunnelInterfaces(interfaces []NetworkInterface, externalInterface string, add func(GatewayConflict)) map[string]struct{} {
	tunnels := make(map[string]struct{})
	for _, networkInterface := range interfaces {
		if !isTunnelInterface(networkInterface) {
			continue
		}
		tunnels[networkInterface.Name] = struct{}{}
		code := "incompatible_tunnel_interface"
		problem := fmt.Sprintf("tunnel or WireGuard interface %q already exists", networkInterface.Name)
		if networkInterface.Name == externalInterface {
			code = "incompatible_external_interface"
			problem = fmt.Sprintf("selected external interface %q is itself a tunnel or WireGuard interface", networkInterface.Name)
		} else if networkInterface.Name == GatewayOverlayInterface {
			code = "owned_interface_name_collision"
			problem = fmt.Sprintf("reserved vpnctl overlay interface %q already exists without proved ownership", networkInterface.Name)
		}
		add(GatewayConflict{
			Code:           code,
			Resource:       "interface:" + networkInterface.Name,
			Problem:        problem,
			RequiredAction: "remove or migrate the interface and its routes explicitly; vpnctl init will not adopt it",
		})
	}
	return tunnels
}

func isTunnelInterface(networkInterface NetworkInterface) bool {
	name := strings.ToLower(networkInterface.Name)
	kind := strings.ToLower(networkInterface.Type)
	if kind == "wireguard" || kind == "tun" || kind == "tap" {
		return true
	}
	for _, prefix := range []string{"wg", "tun", "tap", "tailscale", "zt"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return kind == "none" && hasString(networkInterface.Flags, "POINTOPOINT")
}

func analyzeRoutes(routes []Route, externalInterface string, tunnelInterfaces map[string]struct{}, add func(GatewayConflict)) {
	for _, route := range routes {
		reasons := make([]string, 0)
		if route.Table == VPNCTLSelectedRouteTable || route.Table == VPNCTLGatewayRouteTable {
			reasons = append(reasons, "uses reserved vpnctl route table "+route.Table)
		}
		if route.Destination == "default" {
			mainTable := route.Table == "main" || route.Table == "254"
			if !mainTable || (route.Device != "" && route.Device != externalInterface) {
				reasons = append(reasons, "defines an alternate default route")
			}
		}
		if _, tunnel := tunnelInterfaces[route.Device]; tunnel {
			reasons = append(reasons, "routes through an incompatible tunnel interface")
		}
		if len(reasons) == 0 {
			continue
		}
		sort.Strings(reasons)
		add(GatewayConflict{
			Code:           "incompatible_route",
			Resource:       routeResource(route),
			Problem:        strings.Join(reasons, "; "),
			RequiredAction: "remove or move the conflicting route outside vpnctl's reserved policy space, then rerun preflight",
		})
	}
}

func analyzePolicyRules(rules []PolicyRule, add func(GatewayConflict), preserve func(string)) {
	reservedPriorities := map[int]struct{}{10000: {}, 10010: {}, 10020: {}}
	for _, rule := range rules {
		reasons := make([]string, 0)
		if _, reserved := reservedPriorities[rule.Priority]; reserved {
			reasons = append(reasons, fmt.Sprintf("uses reserved priority %d", rule.Priority))
		}
		if rule.Table == VPNCTLSelectedRouteTable || rule.Table == VPNCTLGatewayRouteTable {
			reasons = append(reasons, "uses reserved route table "+rule.Table)
		}
		if rule.FWMark != "" {
			mark, markErr := parseRuleNumber(rule.FWMark)
			mask := uint64(0xffffffff)
			var maskErr error
			if rule.FWMask != "" {
				mask, maskErr = parseRuleNumber(rule.FWMask)
			}
			if markErr != nil || maskErr != nil || mark > 0xffffffff || mask > 0xffffffff {
				reasons = append(reasons, "contains an unverifiable fwmark/mask")
			} else if mask&VPNCTLMarkMask != 0 {
				reasons = append(reasons, "claims vpnctl's reserved high-byte fwmark namespace")
			}
		}
		resource := policyRuleResource(rule)
		if len(reasons) == 0 {
			preserve(resource)
			continue
		}
		sort.Strings(reasons)
		add(GatewayConflict{
			Code:           "incompatible_policy_rule",
			Resource:       resource,
			Problem:        strings.Join(reasons, "; "),
			RequiredAction: "move the rule to non-reserved priorities, tables, and mark bits or remove it, then rerun preflight",
		})
	}
}

func parseRuleNumber(value string) (uint64, error) {
	return strconv.ParseUint(value, 0, 64)
}

func reverseProxyOwner(process string) string {
	proxyNames := map[string]struct{}{
		"apache2": {}, "caddy": {}, "envoy": {}, "haproxy": {}, "httpd": {}, "nginx": {}, "traefik": {},
	}
	for _, name := range listenerProcessNames(process) {
		if _, found := proxyNames[name]; found {
			return name
		}
	}
	return ""
}

func listenerProcessNames(process string) []string {
	trimmed := strings.ToLower(strings.TrimSpace(process))
	if trimmed == "" {
		return nil
	}
	matches := quotedProcessPattern.FindAllStringSubmatch(trimmed, -1)
	if len(matches) == 0 {
		return []string{trimmed}
	}
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, match[1])
	}
	return uniqueSortedStrings(names)
}

func listenerResource(listener Listener) string {
	resource := fmt.Sprintf("listener:%s/%s:%d", listener.Protocol, listener.Address, listener.Port)
	if names := listenerProcessNames(listener.Process); len(names) != 0 {
		resource += " (" + strings.Join(names, ",") + ")"
	}
	return resource
}

func routeResource(route Route) string {
	return fmt.Sprintf("route:%s/table=%s/dst=%s/dev=%s", route.Family, route.Table, route.Destination, route.Device)
}

func policyRuleResource(rule PolicyRule) string {
	resource := fmt.Sprintf("policy-rule:%s/priority=%d/table=%s", rule.Family, rule.Priority, rule.Table)
	if rule.FWMark != "" {
		resource += "/fwmark=" + rule.FWMark
		if rule.FWMask != "" {
			resource += "/" + rule.FWMask
		}
	}
	return resource
}

func sortedGatewayConflicts(values map[string]GatewayConflict) []GatewayConflict {
	result := make([]GatewayConflict, 0, len(values))
	for _, conflict := range values {
		result = append(result, conflict)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Code == result[j].Code {
			return result[i].Resource < result[j].Resource
		}
		return result[i].Code < result[j].Code
	})
	return result
}

func sortedResourceNames(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uniqueSortedStrings(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
