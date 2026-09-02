package linux

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

func TestValidateGatewayNetworkUsesExplicitIPDefaultsAndDiscoveredInterface(t *testing.T) {
	t.Parallel()

	snapshot := discoveryFixtureSnapshot(t, "clean")
	before, marshalErr := json.Marshal(snapshot)
	if marshalErr != nil {
		t.Fatalf("marshal before snapshot: %v", marshalErr)
	}
	plan, err := ValidateGatewayNetwork(GatewayNetworkInput{PublicIPv4: "203.0.113.10"}, snapshot)
	if err != nil {
		t.Fatalf("ValidateGatewayNetwork() error = %v", err)
	}
	want := GatewayNetworkPlan{
		PublicIPv4:        "203.0.113.10",
		ClientCIDR:        model.DefaultClientCIDR,
		NodeCIDR:          model.DefaultNodeCIDR,
		ExternalInterface: "eth0",
		InterfaceSource:   "default_route",
	}
	if plan != want {
		t.Fatalf("plan = %+v, want %+v", plan, want)
	}
	after, marshalErr := json.Marshal(snapshot)
	if marshalErr != nil {
		t.Fatalf("marshal after snapshot: %v", marshalErr)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("ValidateGatewayNetwork() mutated the discovery snapshot")
	}

	plan, err = ValidateGatewayNetwork(GatewayNetworkInput{
		PublicIPv4: "203.0.113.10", ClientCIDR: "10.80.0.0/24", NodeCIDR: "10.81.0.0/24", ExternalInterface: "eth0",
	}, snapshot)
	if err != nil || plan.InterfaceSource != "explicit" || plan.ClientCIDR != "10.80.0.0/24" || plan.NodeCIDR != "10.81.0.0/24" {
		t.Fatalf("explicit plan = %+v, %v", plan, err)
	}
}

func TestValidateGatewayNetworkRequiresManualPublicIPv4(t *testing.T) {
	t.Parallel()

	snapshot := discoveryFixtureSnapshot(t, "clean")
	_, err := ValidateGatewayNetwork(GatewayNetworkInput{}, snapshot)
	assertGatewayIssue(t, err, "public_ipv4", "required")
	if !strings.Contains(err.Error(), "automatic external lookup is disabled") {
		t.Fatalf("missing public IP error is not actionable: %v", err)
	}

	source, readErr := os.ReadFile("init_network.go")
	if readErr != nil {
		t.Fatalf("read implementation: %v", readErr)
	}
	for _, forbidden := range []string{"net/http", "LookupIP", "LookupHost", "ifconfig.me", "icanhazip", "api.ipify", "curl"} {
		if strings.Contains(string(source), forbidden) {
			t.Errorf("gateway network validation contains external lookup surface %q", forbidden)
		}
	}
}

func TestValidateGatewayNetworkRejectsInvalidOrNonPublicAddresses(t *testing.T) {
	t.Parallel()

	snapshot := discoveryFixtureSnapshot(t, "clean")
	tests := []struct {
		value string
		code  string
	}{
		{value: "203.0.113.010", code: "invalid"},
		{value: "2001:db8::1", code: "invalid"},
		{value: "10.0.0.1", code: "not_public"},
		{value: "100.64.0.1", code: "not_public"},
		{value: "127.0.0.1", code: "not_public"},
		{value: "169.254.1.1", code: "not_public"},
		{value: "198.18.0.1", code: "not_public"},
		{value: "224.0.0.1", code: "not_public"},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			_, err := ValidateGatewayNetwork(GatewayNetworkInput{PublicIPv4: test.value}, snapshot)
			assertGatewayIssue(t, err, "public_ipv4", test.code)
		})
	}
}

func TestValidateGatewayNetworkRejectsPoolAndHostOverlaps(t *testing.T) {
	t.Parallel()

	clean := discoveryFixtureSnapshot(t, "clean")
	tests := []struct {
		name  string
		input GatewayNetworkInput
		field string
		code  string
	}{
		{name: "noncanonical", input: GatewayNetworkInput{PublicIPv4: "203.0.113.10", ClientCIDR: "10.66.0.1/24"}, field: "client_cidr", code: "invalid"},
		{name: "too small", input: GatewayNetworkInput{PublicIPv4: "203.0.113.10", ClientCIDR: "10.66.0.0/31"}, field: "client_cidr", code: "too_small"},
		{name: "pool overlap", input: GatewayNetworkInput{PublicIPv4: "203.0.113.10", ClientCIDR: "10.66.0.0/24", NodeCIDR: "10.66.0.128/25"}, field: "client_cidr", code: "pool_overlap"},
		{name: "public in client pool", input: GatewayNetworkInput{PublicIPv4: "203.0.113.10", ClientCIDR: "203.0.113.0/24", NodeCIDR: "10.67.0.0/24"}, field: "public_ipv4", code: "pool_overlap"},
		{name: "interface subnet", input: GatewayNetworkInput{PublicIPv4: "203.0.113.10", ClientCIDR: "192.0.2.0/24"}, field: "client_cidr", code: "host_overlap"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateGatewayNetwork(test.input, clean)
			assertGatewayIssue(t, err, test.field, test.code)
		})
	}

	conflicting := discoveryFixtureSnapshot(t, "conflicting-host")
	_, err := ValidateGatewayNetwork(GatewayNetworkInput{PublicIPv4: "203.0.113.10"}, conflicting)
	assertGatewayIssue(t, err, "client_cidr", "host_overlap")
	_, err = ValidateGatewayNetwork(GatewayNetworkInput{
		PublicIPv4: "203.0.113.10", ClientCIDR: "172.17.0.0/16", NodeCIDR: "10.90.0.0/24",
	}, conflicting)
	assertGatewayIssue(t, err, "client_cidr", "host_overlap")
}

func TestValidateGatewayNetworkValidatesExternalInterface(t *testing.T) {
	t.Parallel()

	clean := discoveryFixtureSnapshot(t, "clean")
	_, err := ValidateGatewayNetwork(GatewayNetworkInput{PublicIPv4: "203.0.113.10", ExternalInterface: "missing0"}, clean)
	assertGatewayIssue(t, err, "external_interface", "not_found")
	_, err = ValidateGatewayNetwork(GatewayNetworkInput{PublicIPv4: "203.0.113.10", ExternalInterface: strings.Repeat("x", 16)}, clean)
	assertGatewayIssue(t, err, "external_interface", "invalid")

	conflicting := discoveryFixtureSnapshot(t, "conflicting-host")
	_, err = ValidateGatewayNetwork(GatewayNetworkInput{
		PublicIPv4: "203.0.113.10", ClientCIDR: "10.80.0.0/24", NodeCIDR: "10.81.0.0/24", ExternalInterface: "docker0",
	}, conflicting)
	assertGatewayIssue(t, err, "external_interface", "unsafe_type")

	down := clean
	down.Interfaces = append([]NetworkInterface(nil), clean.Interfaces...)
	down.Interfaces = append(down.Interfaces, NetworkInterface{
		Index: 9, Name: "ens9", Flags: []string{"BROADCAST"}, Addresses: []InterfaceAddress{{Family: "inet", Address: "198.51.100.9", PrefixLen: 24, Scope: "global"}},
	})
	_, err = ValidateGatewayNetwork(GatewayNetworkInput{PublicIPv4: "203.0.113.10", ExternalInterface: "ens9"}, down)
	assertGatewayIssue(t, err, "external_interface", "not_up")

	noAddress := clean
	noAddress.Interfaces = append([]NetworkInterface(nil), clean.Interfaces...)
	noAddress.Interfaces = append(noAddress.Interfaces, NetworkInterface{Index: 10, Name: "ens10", Flags: []string{"UP"}, Addresses: []InterfaceAddress{}})
	_, err = ValidateGatewayNetwork(GatewayNetworkInput{PublicIPv4: "203.0.113.10", ExternalInterface: "ens10"}, noAddress)
	assertGatewayIssue(t, err, "external_interface", "no_ipv4")
}

func TestValidateGatewayNetworkRequiresUnambiguousDefaultRoute(t *testing.T) {
	t.Parallel()

	snapshot := discoveryFixtureSnapshot(t, "clean")
	snapshot.Interfaces = append(snapshot.Interfaces, NetworkInterface{
		Index: 9, Name: "ens9", Flags: []string{"UP"}, Addresses: []InterfaceAddress{{Family: "inet", Address: "198.51.100.9", PrefixLen: 24, Scope: "global"}},
	})
	snapshot.Routes = append(snapshot.Routes, Route{Family: "ipv4", Destination: "default", Gateway: "198.51.100.1", Device: "ens9", Table: "main"})
	_, err := ValidateGatewayNetwork(GatewayNetworkInput{PublicIPv4: "203.0.113.10"}, snapshot)
	assertGatewayIssue(t, err, "external_interface", "ambiguous")

	plan, err := ValidateGatewayNetwork(GatewayNetworkInput{PublicIPv4: "203.0.113.10", ExternalInterface: "eth0"}, snapshot)
	if err != nil || plan.ExternalInterface != "eth0" || plan.InterfaceSource != "explicit" {
		t.Fatalf("explicit interface did not resolve ambiguity: %+v, %v", plan, err)
	}
}

func TestValidateGatewayNetworkRejectsWrongSnapshotVersionAndAggregatesIssues(t *testing.T) {
	t.Parallel()

	snapshot := discoveryFixtureSnapshot(t, "clean")
	snapshot.SchemaVersion++
	_, err := ValidateGatewayNetwork(GatewayNetworkInput{ClientCIDR: "invalid", ExternalInterface: "missing"}, snapshot)
	assertGatewayIssue(t, err, "host", "snapshot_version")
	assertGatewayIssue(t, err, "public_ipv4", "required")
	assertGatewayIssue(t, err, "client_cidr", "invalid")
	assertGatewayIssue(t, err, "external_interface", "not_found")
}

func assertGatewayIssue(t *testing.T, err error, field, code string) {
	t.Helper()
	if !errors.Is(err, ErrInvalidGatewayNetwork) {
		t.Fatalf("error = %v, want ErrInvalidGatewayNetwork", err)
	}
	var validation *GatewayNetworkError
	if !errors.As(err, &validation) {
		t.Fatalf("error type = %T", err)
	}
	for _, issue := range validation.Issues {
		if issue.Field == field && issue.Code == code {
			return
		}
	}
	t.Fatalf("issues = %+v, want %s/%s", validation.Issues, field, code)
}

func discoveryFixtureSnapshot(t *testing.T, name string) HostSnapshot {
	t.Helper()
	fixture := loadDiscoveryFixture(t, name)
	discoverer := &Discoverer{
		files: fixtureFileSystem(fixture.Files), runner: &fixtureRunner{commands: fixture.commandMap(t)},
		disk: fixtureDisk{usage: fixture.Disk}, runtime: fixture.Runtime,
	}
	snapshot, err := discoverer.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover(%s) error = %v", name, err)
	}
	return snapshot
}
