package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	NetworkSnapshotSchemaVersion = 1
	VPNCTLNFTablesFamily         = "inet"
	VPNCTLNFTablesTable          = "vpnctl"
)

var (
	ErrInvalidNetworkSnapshot = errors.New("invalid vpnctl network snapshot")
	sysctlInterfacePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
	routeTokenPattern         = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

var ownedRouteTables = []string{VPNCTLSelectedRouteTable, VPNCTLGatewayRouteTable}

var ownedPolicyRules = map[int]PolicyRule{
	VPNCTLRecoveryRulePriority: {Family: "ipv4", Priority: VPNCTLRecoveryRulePriority, From: "all", Table: VPNCTLGatewayRouteTable, FWMark: "0x03000000", FWMask: "0xff000000"},
	VPNCTLIngressRulePriority:  {Family: "ipv4", Priority: VPNCTLIngressRulePriority, From: "all", Table: VPNCTLGatewayRouteTable, FWMark: "0x04000000", FWMask: "0xff000000"},
	VPNCTLSelectedRulePriority: {Family: "ipv4", Priority: VPNCTLSelectedRulePriority, From: "all", Table: VPNCTLSelectedRouteTable, FWMark: "0x02000000", FWMask: "0xff000000"},
}

// OwnedNetworkScope lists the sysctls a lockout-risk operation intends to
// change. nftables, route tables, and RPDB priorities have fixed internal
// ownership and therefore are not caller-configurable.
type OwnedNetworkScope struct {
	Sysctls []string `json:"sysctls"`
}

type NFTablesSnapshot struct {
	Present    bool   `json:"present"`
	Definition string `json:"definition,omitempty"`
}

type SysctlSnapshot struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// NetworkSnapshot contains only resources inside vpnctl's conflict-checked
// ownership boundary. It deliberately cannot represent arbitrary tables,
// routes, policy priorities, or sysctl names.
type NetworkSnapshot struct {
	SchemaVersion int              `json:"schema_version"`
	NFTables      NFTablesSnapshot `json:"nftables"`
	Routes        []Route          `json:"routes"`
	PolicyRules   []PolicyRule     `json:"policy_rules"`
	Sysctls       []SysctlSnapshot `json:"sysctls"`
}

type NetworkManager struct {
	runner ProbeRunner
}

func NewNetworkManager(runner ProbeRunner) (*NetworkManager, error) {
	if runner == nil {
		return nil, fmt.Errorf("network manager runner is required")
	}
	return &NetworkManager{runner: runner}, nil
}

func NewOSNetworkManager() *NetworkManager {
	manager, err := NewNetworkManager(OSProbeRunner{})
	if err != nil {
		panic(err)
	}
	return manager
}

func (manager *NetworkManager) Snapshot(ctx context.Context, scope OwnedNetworkScope) (NetworkSnapshot, error) {
	if ctx == nil {
		return NetworkSnapshot{}, fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil {
		return NetworkSnapshot{}, fmt.Errorf("network manager is incomplete")
	}
	sysctls, err := normalizeSysctlScope(scope.Sysctls)
	if err != nil {
		return NetworkSnapshot{}, err
	}

	nftables, err := manager.snapshotNFTables(ctx)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	routes, err := manager.snapshotRoutes(ctx)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	rules, err := manager.snapshotPolicyRules(ctx)
	if err != nil {
		return NetworkSnapshot{}, err
	}
	values := make([]SysctlSnapshot, 0, len(sysctls))
	for _, name := range sysctls {
		result, runErr := manager.runChecked(ctx, ProbeCommand{Name: "sysctl", Args: []string{"-n", name}})
		if runErr != nil {
			return NetworkSnapshot{}, fmt.Errorf("snapshot sysctl %s: %w", name, runErr)
		}
		value := strings.TrimSpace(string(result.Stdout))
		if !validSysctlValue(value) {
			return NetworkSnapshot{}, fmt.Errorf("snapshot sysctl %s: unsupported value %q", name, value)
		}
		values = append(values, SysctlSnapshot{Name: name, Value: value})
	}

	snapshot := NetworkSnapshot{
		SchemaVersion: NetworkSnapshotSchemaVersion,
		NFTables:      nftables,
		Routes:        routes,
		PolicyRules:   rules,
		Sysctls:       values,
	}
	if err := snapshot.Validate(); err != nil {
		return NetworkSnapshot{}, err
	}
	return snapshot, nil
}

// Restore validates the complete snapshot before mutation, then converges
// each fixed ownership boundary independently. It attempts every resource
// class even after an error so a later systemd retry can finish idempotently.
func (manager *NetworkManager) Restore(ctx context.Context, snapshot NetworkSnapshot) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil {
		return fmt.Errorf("network manager is incomplete")
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}

	var restoreErrors []error
	if err := manager.restoreNFTables(ctx, snapshot.NFTables); err != nil {
		restoreErrors = append(restoreErrors, err)
	}
	if err := manager.restoreRoutes(ctx, snapshot.Routes); err != nil {
		restoreErrors = append(restoreErrors, err)
	}
	if err := manager.restorePolicyRules(ctx, snapshot.PolicyRules); err != nil {
		restoreErrors = append(restoreErrors, err)
	}
	for _, sysctl := range sysctlRestoreOrder(snapshot.Sysctls) {
		if _, err := manager.runChecked(ctx, ProbeCommand{Name: "sysctl", Args: []string{"-q", "-w", sysctl.Name + "=" + sysctl.Value}}); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("restore sysctl %s: %w", sysctl.Name, err))
		}
	}
	return errors.Join(restoreErrors...)
}

func (snapshot NetworkSnapshot) Validate() error {
	issues := make([]string, 0)
	if snapshot.SchemaVersion != NetworkSnapshotSchemaVersion {
		issues = append(issues, fmt.Sprintf("schema_version must be %d", NetworkSnapshotSchemaVersion))
	}
	if snapshot.Routes == nil || snapshot.PolicyRules == nil || snapshot.Sysctls == nil {
		issues = append(issues, "routes, policy_rules, and sysctls must be JSON arrays")
	}
	if snapshot.NFTables.Present {
		if err := validateOwnedNFTablesDefinition(snapshot.NFTables.Definition); err != nil {
			issues = append(issues, err.Error())
		}
	} else if snapshot.NFTables.Definition != "" {
		issues = append(issues, "absent nftables snapshot must not contain a definition")
	}
	for index, route := range snapshot.Routes {
		if err := validateOwnedRoute(route); err != nil {
			issues = append(issues, fmt.Sprintf("routes[%d]: %v", index, err))
		}
	}
	seenRules := make(map[string]struct{})
	for index, rule := range snapshot.PolicyRules {
		normalized, owned := normalizeOwnedPolicyRule(rule)
		if !owned {
			issues = append(issues, fmt.Sprintf("policy_rules[%d]: is outside vpnctl ownership", index))
			continue
		}
		key := normalized.Family + ":" + strconv.Itoa(normalized.Priority)
		if _, duplicate := seenRules[key]; duplicate {
			issues = append(issues, fmt.Sprintf("policy_rules[%d]: duplicates %s", index, key))
		}
		seenRules[key] = struct{}{}
	}
	seenSysctls := make(map[string]struct{})
	for index, sysctl := range snapshot.Sysctls {
		if !allowedSysctl(sysctl.Name) {
			issues = append(issues, fmt.Sprintf("sysctls[%d]: name %q is outside vpnctl ownership", index, sysctl.Name))
		}
		if !validSysctlValue(sysctl.Value) {
			issues = append(issues, fmt.Sprintf("sysctls[%d]: value %q is invalid", index, sysctl.Value))
		}
		if _, duplicate := seenSysctls[sysctl.Name]; duplicate {
			issues = append(issues, fmt.Sprintf("sysctls[%d]: duplicates %q", index, sysctl.Name))
		}
		seenSysctls[sysctl.Name] = struct{}{}
	}
	if len(issues) != 0 {
		sort.Strings(issues)
		return fmt.Errorf("%w: %s", ErrInvalidNetworkSnapshot, strings.Join(issues, "; "))
	}
	return nil
}

func (manager *NetworkManager) snapshotNFTables(ctx context.Context) (NFTablesSnapshot, error) {
	result, err := manager.runChecked(ctx, ProbeCommand{Name: "nft", Args: []string{"--json", "list", "tables"}})
	if err != nil {
		return NFTablesSnapshot{}, fmt.Errorf("list nftables tables: %w", err)
	}
	tables, err := parseNFTables(result.Stdout)
	if err != nil {
		return NFTablesSnapshot{}, fmt.Errorf("parse nftables tables: %w", err)
	}
	present := false
	for _, table := range tables {
		if table.Family == VPNCTLNFTablesFamily && table.Name == VPNCTLNFTablesTable {
			present = true
			break
		}
	}
	if !present {
		return NFTablesSnapshot{}, nil
	}
	definition, err := manager.runChecked(ctx, ProbeCommand{Name: "nft", Args: []string{"--stateless", "-nn", "list", "table", VPNCTLNFTablesFamily, VPNCTLNFTablesTable}})
	if err != nil {
		return NFTablesSnapshot{}, fmt.Errorf("snapshot nftables table: %w", err)
	}
	text := string(definition.Stdout)
	if err := validateOwnedNFTablesDefinition(text); err != nil {
		return NFTablesSnapshot{}, err
	}
	return NFTablesSnapshot{Present: true, Definition: text}, nil
}

func (manager *NetworkManager) snapshotRoutes(ctx context.Context) ([]Route, error) {
	routes := make([]Route, 0)
	for _, family := range []struct {
		name string
		flag string
	}{
		{name: "ipv4", flag: "-4"},
		{name: "ipv6", flag: "-6"},
	} {
		for _, table := range ownedRouteTables {
			result, err := manager.runRouteTableCommand(ctx, ProbeCommand{Name: "ip", Args: []string{"-json", family.flag, "route", "show", "table", table}})
			if err != nil {
				return nil, fmt.Errorf("snapshot %s route table %s: %w", family.name, table, err)
			}
			parsed, err := parseRoutes(result.Stdout, family.name)
			if err != nil {
				return nil, fmt.Errorf("parse %s route table %s: %w", family.name, table, err)
			}
			for _, route := range parsed {
				route.Table = table
				if err := validateOwnedRoute(route); err != nil {
					return nil, fmt.Errorf("snapshot %s route table %s: %w", family.name, table, err)
				}
				routes = append(routes, route)
			}
		}
	}
	sortRoutes(routes)
	return routes, nil
}

func (manager *NetworkManager) snapshotPolicyRules(ctx context.Context) ([]PolicyRule, error) {
	rules := make([]PolicyRule, 0, len(ownedPolicyRules))
	for _, family := range []struct {
		name string
		flag string
	}{
		{name: "ipv4", flag: "-4"},
		{name: "ipv6", flag: "-6"},
	} {
		result, err := manager.runChecked(ctx, ProbeCommand{Name: "ip", Args: []string{"-json", family.flag, "rule", "show"}})
		if err != nil {
			return nil, fmt.Errorf("snapshot %s policy rules: %w", family.name, err)
		}
		parsed, err := parsePolicyRules(result.Stdout, family.name)
		if err != nil {
			return nil, fmt.Errorf("parse %s policy rules: %w", family.name, err)
		}
		seen := make(map[int]struct{})
		for _, rule := range parsed {
			if _, reserved := ownedPolicyRules[rule.Priority]; !reserved {
				continue
			}
			normalized, owned := normalizeOwnedPolicyRule(rule)
			if !owned || family.name != "ipv4" {
				return nil, fmt.Errorf("reserved policy priority %d is occupied by a non-vpnctl %s rule", rule.Priority, family.name)
			}
			if _, duplicate := seen[rule.Priority]; duplicate {
				return nil, fmt.Errorf("reserved policy priority %d has duplicate rules", rule.Priority)
			}
			seen[rule.Priority] = struct{}{}
			rules = append(rules, normalized)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
	return rules, nil
}

func (manager *NetworkManager) restoreNFTables(ctx context.Context, snapshot NFTablesSnapshot) error {
	current, err := manager.snapshotNFTables(ctx)
	if err != nil {
		return err
	}
	var batch bytes.Buffer
	if current.Present {
		fmt.Fprintf(&batch, "delete table %s %s\n", VPNCTLNFTablesFamily, VPNCTLNFTablesTable)
	}
	if snapshot.Present {
		batch.WriteString(snapshot.Definition)
		if !strings.HasSuffix(snapshot.Definition, "\n") {
			batch.WriteByte('\n')
		}
	}
	if batch.Len() == 0 {
		return nil
	}
	if _, err := manager.runChecked(ctx, ProbeCommand{Name: "nft", Args: []string{"--check", "--file", "-"}, Stdin: batch.Bytes()}); err != nil {
		return fmt.Errorf("validate nftables rollback: %w", err)
	}
	if _, err := manager.runChecked(ctx, ProbeCommand{Name: "nft", Args: []string{"--file", "-"}, Stdin: batch.Bytes()}); err != nil {
		return fmt.Errorf("restore nftables table: %w", err)
	}
	return nil
}

func (manager *NetworkManager) restoreRoutes(ctx context.Context, routes []Route) error {
	var restoreErrors []error
	for _, family := range []struct {
		name string
		flag string
	}{
		{name: "ipv4", flag: "-4"},
		{name: "ipv6", flag: "-6"},
	} {
		for _, table := range ownedRouteTables {
			if _, err := manager.runRouteTableCommand(ctx, ProbeCommand{Name: "ip", Args: []string{family.flag, "route", "flush", "table", table}}); err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("flush %s route table %s: %w", family.name, table, err))
			}
		}
	}
	for _, route := range routes {
		args, err := routeRestoreArgs(route)
		if err != nil {
			restoreErrors = append(restoreErrors, err)
			continue
		}
		if _, err := manager.runChecked(ctx, ProbeCommand{Name: "ip", Args: args}); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("restore %s route %s in table %s: %w", route.Family, route.Destination, route.Table, err))
		}
	}
	return errors.Join(restoreErrors...)
}

func (manager *NetworkManager) restorePolicyRules(ctx context.Context, prior []PolicyRule) error {
	var restoreErrors []error
	current, err := manager.currentOwnedPolicyRules(ctx)
	if err != nil {
		restoreErrors = append(restoreErrors, err)
	} else {
		for _, rule := range current {
			args := policyRuleArgs("del", rule)
			if _, err := manager.runChecked(ctx, ProbeCommand{Name: "ip", Args: args}); err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("delete vpnctl policy rule priority %d: %w", rule.Priority, err))
			}
		}
	}
	for _, rule := range prior {
		args := policyRuleArgs("add", rule)
		if _, err := manager.runChecked(ctx, ProbeCommand{Name: "ip", Args: args}); err != nil {
			restoreErrors = append(restoreErrors, fmt.Errorf("restore vpnctl policy rule priority %d: %w", rule.Priority, err))
		}
	}
	return errors.Join(restoreErrors...)
}

func (manager *NetworkManager) currentOwnedPolicyRules(ctx context.Context) ([]PolicyRule, error) {
	result, err := manager.runChecked(ctx, ProbeCommand{Name: "ip", Args: []string{"-json", "-4", "rule", "show"}})
	if err != nil {
		return nil, fmt.Errorf("list current IPv4 policy rules: %w", err)
	}
	parsed, err := parsePolicyRules(result.Stdout, "ipv4")
	if err != nil {
		return nil, fmt.Errorf("parse current IPv4 policy rules: %w", err)
	}
	owned := make([]PolicyRule, 0, len(ownedPolicyRules))
	for _, rule := range parsed {
		if normalized, matches := normalizeOwnedPolicyRule(rule); matches {
			owned = append(owned, normalized)
		}
	}
	sort.Slice(owned, func(i, j int) bool { return owned[i].Priority < owned[j].Priority })
	return owned, nil
}

func (manager *NetworkManager) runChecked(ctx context.Context, command ProbeCommand) (ProbeResult, error) {
	result, err := manager.runner.Run(ctx, command)
	if err != nil {
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		return ProbeResult{}, err
	}
	if result.ExitCode != 0 {
		detail := strings.TrimSpace(string(result.Stderr))
		if detail == "" {
			detail = strings.TrimSpace(string(result.Stdout))
		}
		if detail == "" {
			detail = fmt.Sprintf("exit code %d", result.ExitCode)
		}
		return ProbeResult{}, fmt.Errorf("%s %s: %s", command.Name, strings.Join(command.Args, " "), detail)
	}
	return result, nil
}

func (manager *NetworkManager) runRouteTableCommand(ctx context.Context, command ProbeCommand) (ProbeResult, error) {
	result, err := manager.runner.Run(ctx, command)
	if err != nil {
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		return ProbeResult{}, err
	}
	if result.ExitCode == 0 {
		return result, nil
	}
	// iproute2 reports a missing custom FIB table as an error. For an owned
	// table snapshot/flush this is exactly the empty/absent state, not a
	// rollback failure. Match the stable semantic phrase, not an exit code.
	if strings.Contains(strings.ToLower(string(result.Stderr)), "fib table does not exist") {
		return ProbeResult{Stdout: []byte("[]\n")}, nil
	}
	detail := strings.TrimSpace(string(result.Stderr))
	if detail == "" {
		detail = fmt.Sprintf("exit code %d", result.ExitCode)
	}
	return ProbeResult{}, fmt.Errorf("%s %s: %s", command.Name, strings.Join(command.Args, " "), detail)
}

func normalizeSysctlScope(values []string) ([]string, error) {
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index, value := range result {
		if !allowedSysctl(value) {
			return nil, fmt.Errorf("sysctl %q is outside vpnctl's network ownership allowlist", value)
		}
		if index > 0 && value == result[index-1] {
			return nil, fmt.Errorf("sysctl %q is duplicated", value)
		}
	}
	return result, nil
}

func allowedSysctl(name string) bool {
	switch name {
	case "net.ipv4.ip_forward", "net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.all.src_valid_mark", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter":
		return true
	}
	const prefix = "net.ipv4.conf."
	const suffix = ".rp_filter"
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	interfaceName := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	return interfaceName != "all" && interfaceName != "default" && sysctlInterfacePattern.MatchString(interfaceName)
}

func validSysctlValue(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}

func sysctlRestoreOrder(values []SysctlSnapshot) []SysctlSnapshot {
	ordered := append([]SysctlSnapshot(nil), values...)
	sort.SliceStable(ordered, func(i, j int) bool {
		leftForwarding := ordered[i].Name == "net.ipv4.ip_forward"
		rightForwarding := ordered[j].Name == "net.ipv4.ip_forward"
		if leftForwarding != rightForwarding {
			return leftForwarding
		}
		return ordered[i].Name < ordered[j].Name
	})
	return ordered
}

func validateOwnedNFTablesDefinition(definition string) error {
	trimmed := strings.TrimSpace(definition)
	if !strings.HasPrefix(trimmed, "table "+VPNCTLNFTablesFamily+" "+VPNCTLNFTablesTable+" {") {
		return fmt.Errorf("nftables definition must contain only table %s %s", VPNCTLNFTablesFamily, VPNCTLNFTablesTable)
	}
	for _, forbidden := range []string{"\ninclude ", "\nadd ", "\ndelete ", "\ndestroy ", "\nflush ", "\nrename ", "\nimport ", "\nexport "} {
		if strings.Contains("\n"+trimmed, forbidden) {
			return fmt.Errorf("nftables definition contains forbidden command %q", strings.TrimSpace(forbidden))
		}
	}
	depth := 0
	inString := false
	escaped := false
	closedAt := -1
	for index, character := range trimmed {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if character == '\\' {
				escaped = true
			} else if character == '"' {
				inString = false
			}
			continue
		}
		if character == '"' {
			inString = true
			continue
		}
		switch character {
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				return fmt.Errorf("nftables definition has unbalanced braces")
			}
			if depth == 0 {
				closedAt = index
			}
		}
	}
	if inString || depth != 0 || closedAt != len(trimmed)-1 {
		return fmt.Errorf("nftables definition must be one complete table")
	}
	if strings.Count(trimmed, "table "+VPNCTLNFTablesFamily+" "+VPNCTLNFTablesTable+" {") != 1 {
		return fmt.Errorf("nftables definition must contain one owned table")
	}
	return nil
}

func validateOwnedRoute(route Route) error {
	if route.Family != "ipv4" && route.Family != "ipv6" {
		return fmt.Errorf("unsupported family %q", route.Family)
	}
	if route.Table != VPNCTLSelectedRouteTable && route.Table != VPNCTLGatewayRouteTable {
		return fmt.Errorf("table %q is outside vpnctl ownership", route.Table)
	}
	bits := 32
	if route.Family == "ipv6" {
		bits = 128
	}
	if route.Destination != "default" {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || prefix.Bits() > bits || (prefix.Addr().Is4() != (route.Family == "ipv4")) {
			return fmt.Errorf("invalid destination %q", route.Destination)
		}
	}
	for label, value := range map[string]string{"gateway": route.Gateway, "preferred_source": route.PreferredSource} {
		if value == "" {
			continue
		}
		address, err := netip.ParseAddr(value)
		if err != nil || (address.Is4() != (route.Family == "ipv4")) {
			return fmt.Errorf("invalid %s %q", label, value)
		}
	}
	if route.Device != "" && !interfaceNamePattern.MatchString(route.Device) {
		return fmt.Errorf("invalid device %q", route.Device)
	}
	for label, value := range map[string]string{"protocol": route.Protocol, "scope": route.Scope} {
		if value != "" && !routeTokenPattern.MatchString(value) {
			return fmt.Errorf("invalid %s %q", label, value)
		}
	}
	switch route.Type {
	case "", "unicast", "blackhole", "unreachable", "prohibit", "throw":
	default:
		return fmt.Errorf("unsupported route type %q", route.Type)
	}
	if route.Metric < 0 {
		return fmt.Errorf("metric must not be negative")
	}
	return nil
}

func routeRestoreArgs(route Route) ([]string, error) {
	if err := validateOwnedRoute(route); err != nil {
		return nil, err
	}
	familyFlag := "-4"
	if route.Family == "ipv6" {
		familyFlag = "-6"
	}
	args := []string{familyFlag, "route", "add"}
	if route.Type != "" && route.Type != "unicast" {
		args = append(args, route.Type)
	}
	args = append(args, route.Destination)
	if route.Gateway != "" {
		args = append(args, "via", route.Gateway)
	}
	if route.Device != "" {
		args = append(args, "dev", route.Device)
	}
	if route.PreferredSource != "" {
		args = append(args, "src", route.PreferredSource)
	}
	if route.Protocol != "" {
		args = append(args, "proto", route.Protocol)
	}
	if route.Scope != "" {
		args = append(args, "scope", route.Scope)
	}
	if route.Metric != 0 {
		args = append(args, "metric", strconv.Itoa(route.Metric))
	}
	args = append(args, "table", route.Table)
	return args, nil
}

func normalizeOwnedPolicyRule(rule PolicyRule) (PolicyRule, bool) {
	expected, reserved := ownedPolicyRules[rule.Priority]
	if !reserved || rule.Family != "ipv4" {
		return PolicyRule{}, false
	}
	table := normalizeRouteTable(rule.Table)
	mark, markOK := normalizeHex32(rule.FWMark)
	mask, maskOK := normalizeHex32(rule.FWMask)
	from := rule.From
	if from == "" {
		from = "all"
	}
	to := rule.To
	if to == "" {
		to = "all"
	}
	if !markOK || !maskOK || table != expected.Table || mark != expected.FWMark || mask != expected.FWMask || from != "all" || to != "all" {
		return PolicyRule{}, false
	}
	return expected, true
}

func normalizeRouteTable(value string) string {
	switch value {
	case "20001":
		return VPNCTLSelectedRouteTable
	case "20002":
		return VPNCTLGatewayRouteTable
	default:
		return value
	}
}

func normalizeHex32(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	parsed, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("0x%08x", parsed), true
}

func policyRuleArgs(action string, rule PolicyRule) []string {
	return []string{
		"-4", "rule", action,
		"priority", strconv.Itoa(rule.Priority),
		"fwmark", rule.FWMark + "/" + rule.FWMask,
		"table", rule.Table,
	}
}

func sortRoutes(routes []Route) {
	sort.Slice(routes, func(i, j int) bool {
		left := routes[i]
		right := routes[j]
		leftKey := left.Family + "\x00" + left.Table + "\x00" + left.Destination + "\x00" + left.Type + "\x00" + left.Gateway + "\x00" + left.Device + "\x00" + strconv.Itoa(left.Metric)
		rightKey := right.Family + "\x00" + right.Table + "\x00" + right.Destination + "\x00" + right.Type + "\x00" + right.Gateway + "\x00" + right.Device + "\x00" + strconv.Itoa(right.Metric)
		return leftKey < rightKey
	})
}
