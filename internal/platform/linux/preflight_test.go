package linux

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestAnalyzeGatewayPreflightAllowsNonConflictingForeignResources(t *testing.T) {
	t.Parallel()

	snapshot := discoveryFixtureSnapshot(t, "clean")
	snapshot.NFTablesTables = append(snapshot.NFTablesTables,
		NFTablesTable{Family: "inet", Name: "filter"},
		NFTablesTable{Family: "ip", Name: "nat"},
	)
	snapshot.Listeners = append(snapshot.Listeners, Listener{Protocol: "tcp", Address: "127.0.0.1", Port: 3000, Process: `users:(("pet-app",pid=900,fd=7))`})
	snapshot.PolicyRules = append(snapshot.PolicyRules, PolicyRule{Family: "ipv4", Priority: 12000, Table: "main", FWMark: "0x00001234", FWMask: "0x0000ffff"})

	before, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := AnalyzeGatewayPreflight(validGatewayPreflightInput(), snapshot)
	if err != nil {
		t.Fatalf("AnalyzeGatewayPreflight() error = %v", err)
	}
	if !plan.Ready || len(plan.Conflicts) != 0 {
		t.Fatalf("clean preflight plan = %+v", plan)
	}
	for _, resource := range []string{
		"nftables:inet/filter", "nftables:ip/nat", "listener:tcp/127.0.0.1:3000 (pet-app)",
		"policy-rule:ipv4/priority=12000/table=main/fwmark=0x00001234/0x0000ffff",
	} {
		if !contains(plan.PreservedResources, resource) {
			t.Errorf("preserved resources omit %q: %v", resource, plan.PreservedResources)
		}
	}
	after, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("AnalyzeGatewayPreflight() mutated the host snapshot")
	}
}

func TestAnalyzeGatewayPreflightReportsAllConflictClassesActionably(t *testing.T) {
	t.Parallel()

	snapshot := discoveryFixtureSnapshot(t, "conflicting-host")
	snapshot.NFTablesTables = append(snapshot.NFTablesTables, NFTablesTable{Family: "inet", Name: "ufw-user-input"})
	snapshot.Listeners = append(snapshot.Listeners,
		Listener{Protocol: "udp", Address: "0.0.0.0", Port: 443, Process: `users:(("quic-test",pid=810,fd=4))`},
		Listener{Protocol: "udp", Address: "0.0.0.0", Port: 8443, Process: `users:(("quic-test",pid=811,fd=4))`},
		Listener{Protocol: "tcp", Address: "127.0.0.1", Port: 8080, Process: `users:(("caddy",pid=812,fd=4))`},
	)
	snapshot.Interfaces = append(snapshot.Interfaces, NetworkInterface{Name: GatewayOverlayInterface, Type: "wireguard", Flags: []string{"UP", "POINTOPOINT"}})
	snapshot.Routes = append(snapshot.Routes, Route{Family: "ipv4", Destination: "default", Device: "tun9", Table: "100"})
	snapshot.PolicyRules = append(snapshot.PolicyRules, PolicyRule{Family: "ipv4", Priority: 13000, Table: "main", FWMark: "0x05000000", FWMask: "0xff000000"})

	input := validGatewayPreflightInput()
	input.Network.ClientCIDR = "10.80.0.0/24"
	input.Network.NodeCIDR = "10.81.0.0/24"
	before, marshalErr := json.Marshal(snapshot)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	plan, err := AnalyzeGatewayPreflight(input, snapshot)
	if !errors.Is(err, ErrGatewayPreflightConflict) {
		t.Fatalf("AnalyzeGatewayPreflight() error = %v", err)
	}
	if plan.Ready || len(plan.Conflicts) == 0 {
		t.Fatalf("conflicting plan = %+v", plan)
	}
	wantCodes := []string{
		"active_firewall_manager", "firewall_table_conflict", "forbidden_udp_listener",
		"incompatible_policy_rule", "incompatible_route", "incompatible_tunnel_interface",
		"owned_interface_name_collision", "owned_table_name_collision", "reserved_port_occupied", "unmanaged_reverse_proxy",
	}
	for _, code := range wantCodes {
		if !hasConflictCode(plan.Conflicts, code) {
			t.Errorf("preflight conflicts omit code %q: %+v", code, plan.Conflicts)
		}
	}
	for _, conflict := range plan.Conflicts {
		if conflict.Code == "" || conflict.Resource == "" || conflict.Problem == "" || conflict.RequiredAction == "" {
			t.Errorf("conflict is not actionable: %+v", conflict)
		}
	}
	var typed *GatewayPreflightError
	if !errors.As(err, &typed) || !reflect.DeepEqual(typed.Conflicts, plan.Conflicts) {
		t.Fatalf("error conflicts differ from plan: %#v / %+v", err, plan.Conflicts)
	}
	after, marshalErr := json.Marshal(snapshot)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("conflicting AnalyzeGatewayPreflight() mutated the host snapshot")
	}

	reversed := snapshot
	reversed.Services = reversedServices(snapshot.Services)
	reversed.NFTablesTables = reversedTables(snapshot.NFTablesTables)
	reversed.Listeners = reversedListeners(snapshot.Listeners)
	reversed.Interfaces = reversedInterfaces(snapshot.Interfaces)
	reversed.Routes = reversedRoutes(snapshot.Routes)
	reversed.PolicyRules = reversedPolicyRules(snapshot.PolicyRules)
	reversedPlan, reversedErr := AnalyzeGatewayPreflight(input, reversed)
	if !errors.Is(reversedErr, ErrGatewayPreflightConflict) || !reflect.DeepEqual(reversedPlan, plan) {
		t.Fatalf("snapshot order changed plan:\nnormal=%+v\nreversed=%+v\nerror=%v", plan, reversedPlan, reversedErr)
	}
}

func TestAnalyzeGatewayPreflightRejectsTunnelAsExternalInterface(t *testing.T) {
	t.Parallel()

	snapshot := discoveryFixtureSnapshot(t, "clean")
	snapshot.Interfaces = append(snapshot.Interfaces, NetworkInterface{
		Name: "wg-external", Type: "wireguard", Flags: []string{"UP", "POINTOPOINT"},
	})
	input := validGatewayPreflightInput()
	input.Network.ExternalInterface = "wg-external"
	plan, err := AnalyzeGatewayPreflight(input, snapshot)
	if !errors.Is(err, ErrGatewayPreflightConflict) || !hasConflictCode(plan.Conflicts, "incompatible_external_interface") {
		t.Fatalf("external tunnel plan=%+v err=%v", plan, err)
	}
}

func TestAnalyzeGatewayPreflightReservedPortMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		protocol string
		port     int
		code     string
	}{
		{protocol: "tcp", port: 443, code: "reserved_port_occupied"},
		{protocol: "tcp", port: 8443, code: "reserved_port_occupied"},
		{protocol: "udp", port: 51820, code: "reserved_port_occupied"},
		{protocol: "udp", port: 443, code: "forbidden_udp_listener"},
		{protocol: "udp", port: 8443, code: "forbidden_udp_listener"},
	}
	for _, test := range tests {
		t.Run(test.protocol+"/"+strconv.Itoa(test.port), func(t *testing.T) {
			snapshot := discoveryFixtureSnapshot(t, "clean")
			snapshot.Listeners = append(snapshot.Listeners, Listener{Protocol: test.protocol, Address: "127.0.0.1", Port: test.port, Process: "foreign"})
			plan, err := AnalyzeGatewayPreflight(validGatewayPreflightInput(), snapshot)
			if !errors.Is(err, ErrGatewayPreflightConflict) || !hasConflictCode(plan.Conflicts, test.code) {
				t.Fatalf("listener %s/%d plan=%+v err=%v", test.protocol, test.port, plan, err)
			}
		})
	}
}

func TestAnalyzeGatewayPreflightRejectsInvalidInputsWithoutConflictPlan(t *testing.T) {
	t.Parallel()

	snapshot := discoveryFixtureSnapshot(t, "clean")
	tests := []GatewayPreflightInput{
		{},
		{Network: GatewayNetworkPlan{PublicIPv4: "203.0.113.10", ExternalInterface: "eth0", ClientCIDR: "bad", NodeCIDR: "10.67.0.0/24"}, SSH: SSHPortPlan{Port: 22, Source: SSHPortFromConnection}},
		{Network: validGatewayPreflightInput().Network, SSH: SSHPortPlan{Port: 22, Source: "guessed"}},
	}
	for _, input := range tests {
		plan, err := AnalyzeGatewayPreflight(input, snapshot)
		if !errors.Is(err, ErrInvalidGatewayPreflight) {
			t.Errorf("input %+v error = %v", input, err)
		}
		if !reflect.DeepEqual(plan, GatewayPreflightPlan{}) {
			t.Errorf("invalid input produced partial plan: %+v", plan)
		}
	}

	wrongVersion := snapshot
	wrongVersion.SchemaVersion++
	_, err := AnalyzeGatewayPreflight(validGatewayPreflightInput(), wrongVersion)
	if !errors.Is(err, ErrInvalidGatewayPreflight) || !strings.Contains(err.Error(), "snapshot schema") {
		t.Fatalf("wrong snapshot version error = %v", err)
	}
}

func TestListenerProcessNamesRequireExactQuotedOwner(t *testing.T) {
	t.Parallel()

	if owner := reverseProxyOwner(`users:(("not-nginx",pid=1,fd=2))`); owner != "" {
		t.Fatalf("substring process matched as reverse proxy: %q", owner)
	}
	if owner := reverseProxyOwner(`users:(("worker",pid=1,fd=2),("NGINX",pid=2,fd=3))`); owner != "nginx" {
		t.Fatalf("quoted process owner = %q", owner)
	}
}

func validGatewayPreflightInput() GatewayPreflightInput {
	return GatewayPreflightInput{
		Network: GatewayNetworkPlan{
			PublicIPv4: "203.0.113.10", ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.67.0.0/24", ExternalInterface: "eth0", InterfaceSource: "default_route",
		},
		SSH: SSHPortPlan{Port: 22, Source: SSHPortFromConnection, ListenerAddresses: []string{"0.0.0.0"}},
	}
}

func hasConflictCode(conflicts []GatewayConflict, code string) bool {
	for _, conflict := range conflicts {
		if conflict.Code == code {
			return true
		}
	}
	return false
}

func reversedServices(values []Service) []Service {
	result := append([]Service(nil), values...)
	reverseSlice(result)
	return result
}

func reversedTables(values []NFTablesTable) []NFTablesTable {
	result := append([]NFTablesTable(nil), values...)
	reverseSlice(result)
	return result
}

func reversedListeners(values []Listener) []Listener {
	result := append([]Listener(nil), values...)
	reverseSlice(result)
	return result
}

func reversedInterfaces(values []NetworkInterface) []NetworkInterface {
	result := append([]NetworkInterface(nil), values...)
	reverseSlice(result)
	return result
}

func reversedRoutes(values []Route) []Route {
	result := append([]Route(nil), values...)
	reverseSlice(result)
	return result
}

func reversedPolicyRules(values []PolicyRule) []PolicyRule {
	result := append([]PolicyRule(nil), values...)
	reverseSlice(result)
	return result
}

func reverseSlice[T any](values []T) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
