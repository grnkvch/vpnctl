package linux

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestDiscoveryFixtures(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"clean", "missing-capabilities", "conflicting-host"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := loadDiscoveryFixture(t, name)
			runner := &fixtureRunner{commands: fixture.commandMap(t)}
			discoverer := &Discoverer{
				files:   fixtureFileSystem(fixture.Files),
				runner:  runner,
				disk:    fixtureDisk{usage: fixture.Disk},
				runtime: fixture.Runtime,
			}
			snapshot, err := discoverer.Discover(context.Background())
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if got := snapshot.MissingMandatoryCapabilities(); !reflect.DeepEqual(got, fixture.Expect.MissingMandatory) {
				t.Fatalf("missing capabilities = %v, want %v", got, fixture.Expect.MissingMandatory)
			}
			if snapshot.SchemaVersion != HostSnapshotSchemaVersion || snapshot.Interfaces == nil || snapshot.Routes == nil || snapshot.PolicyRules == nil || snapshot.ContainerNetworks == nil || snapshot.Listeners == nil || snapshot.NFTablesTables == nil || snapshot.Services == nil || snapshot.ProbeIssues == nil {
				t.Fatalf("snapshot omitted versioned or required collection: %+v", snapshot)
			}
			assertFixtureNames(t, "interfaces", interfaceNames(snapshot.Interfaces), fixture.Expect.Interfaces)
			assertFixtureNames(t, "containers", containerNames(snapshot.ContainerNetworks), fixture.Expect.ContainerInterfaces)
			assertFixtureNames(t, "tables", tableNames(snapshot.NFTablesTables), fixture.Expect.NFTablesTables)
			assertFixtureNames(t, "active services", activeServiceNames(snapshot.Services), fixture.Expect.ActiveServices)
			assertFixtureNames(t, "listeners", listenerNames(snapshot.Listeners), fixture.Expect.Listeners)
			assertFixtureNames(t, "routes", routeNames(snapshot.Routes), fixture.Expect.Routes)
			assertFixtureNames(t, "policy rules", policyRuleNames(snapshot.PolicyRules), fixture.Expect.PolicyRules)

			if snapshot.Resources != fixture.Expect.Resources {
				t.Errorf("resources = %+v, want %+v", snapshot.Resources, fixture.Expect.Resources)
			}
			if snapshot.IPv4ForwardingEnabled != fixture.Expect.IPv4ForwardingEnabled {
				t.Errorf("IPv4 forwarding enabled = %t, want %t", snapshot.IPv4ForwardingEnabled, fixture.Expect.IPv4ForwardingEnabled)
			}
			if len(runner.commands) != 0 {
				t.Errorf("fixture contains unused command results: %v", sortedKeys(runner.commands))
			}
			for _, command := range runner.seen {
				assertReadOnlyProbe(t, command)
			}

			encoded, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatalf("json.Marshal(snapshot): %v", err)
			}
			var roundTrip HostSnapshot
			if err := json.Unmarshal(encoded, &roundTrip); err != nil || !reflect.DeepEqual(roundTrip, snapshot) {
				t.Fatalf("snapshot JSON round trip error=%v equal=%t", err, reflect.DeepEqual(roundTrip, snapshot))
			}
		})
	}
}

func TestMissingCapabilityFixtureReportsEveryFailureTogether(t *testing.T) {
	t.Parallel()

	fixture := loadDiscoveryFixture(t, "missing-capabilities")
	discoverer := &Discoverer{
		files:   fixtureFileSystem(fixture.Files),
		runner:  &fixtureRunner{commands: fixture.commandMap(t)},
		disk:    fixtureDisk{usage: fixture.Disk},
		runtime: fixture.Runtime,
	}
	snapshot, err := discoverer.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	validationErr := snapshot.ValidateMandatoryCapabilities()
	if !errors.Is(validationErr, ErrUnsupportedHost) {
		t.Fatalf("ValidateMandatoryCapabilities() error = %v", validationErr)
	}
	for _, capability := range fixture.Expect.MissingMandatory {
		if !strings.Contains(validationErr.Error(), capability+" (") {
			t.Errorf("unsupported-host error omits actionable detail for %s: %v", capability, validationErr)
		}
	}
	wantIssueProbes := []string{"conntrack_marks", "ipv4_forwarding", "nftables", "policy_rules_ipv4", "systemd_resolved", "tun", "wireguard_module"}
	var mandatory []string
	for _, issue := range snapshot.ProbeIssues {
		if issue.Mandatory {
			mandatory = append(mandatory, issue.Probe)
		}
	}
	mandatory = uniqueSorted(mandatory)
	if !reflect.DeepEqual(mandatory, wantIssueProbes) {
		t.Fatalf("mandatory issue probes = %v, want %v", mandatory, wantIssueProbes)
	}
}

func TestConflictingHostFixturePreservesForeignObservations(t *testing.T) {
	t.Parallel()

	fixture := loadDiscoveryFixture(t, "conflicting-host")
	discoverer := &Discoverer{
		files:   fixtureFileSystem(fixture.Files),
		runner:  &fixtureRunner{commands: fixture.commandMap(t)},
		disk:    fixtureDisk{usage: fixture.Disk},
		runtime: fixture.Runtime,
	}
	snapshot, err := discoverer.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got := snapshot.MissingMandatoryCapabilities(); len(got) != 0 {
		t.Fatalf("conflicting but capable host reported missing %v", got)
	}
	if err := snapshot.ValidateMandatoryCapabilities(); err != nil {
		t.Fatalf("capable conflicting host validation error = %v", err)
	}
	if !contains(listenerNames(snapshot.Listeners), "tcp/0.0.0.0:443") || !contains(listenerNames(snapshot.Listeners), "tcp/0.0.0.0:8443") || !contains(listenerNames(snapshot.Listeners), "udp/0.0.0.0:51820") {
		t.Fatalf("reserved listeners were not preserved: %+v", snapshot.Listeners)
	}
	if !contains(containerNames(snapshot.ContainerNetworks), "docker0") || !contains(tableNames(snapshot.NFTablesTables), "inet/vpnctl") || !contains(policyRuleNames(snapshot.PolicyRules), "ipv4/10020/20001/0x02000000/0xff000000") {
		t.Fatalf("foreign network observations incomplete: containers=%v tables=%v rules=%v", snapshot.ContainerNetworks, snapshot.NFTablesTables, snapshot.PolicyRules)
	}
}

func TestNewDiscovererRejectsUnsafeRoots(t *testing.T) {
	t.Parallel()

	for _, root := range []string{"", ".", "relative/root"} {
		if _, err := NewDiscoverer(root); err == nil {
			t.Errorf("NewDiscoverer(%q) succeeded", root)
		}
	}
	if _, err := NewDiscoverer(t.TempDir()); err != nil {
		t.Fatalf("NewDiscoverer(absolute) error = %v", err)
	}
}

func TestDiscoveryParsersRejectMalformedOrAmbiguousInputs(t *testing.T) {
	t.Parallel()

	if _, err := parseMemory([]byte("MemTotal: 1 kB\n")); err == nil {
		t.Fatal("parseMemory() accepted incomplete meminfo")
	}
	if _, err := parseMemory([]byte("MemTotal: 1 bytes\nMemAvailable: 1 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")); err == nil {
		t.Fatal("parseMemory() accepted non-kB units")
	}
	if _, err := parseOSRelease([]byte("ID=ubuntu\n")); err == nil {
		t.Fatal("parseOSRelease() accepted missing version")
	}
	var decoded []any
	if err := decodeJSON([]byte("[] {}"), &decoded); err == nil {
		t.Fatal("decodeJSON() accepted trailing document")
	}
	for _, socket := range []string{"0.0.0.0:0", "hostname:443", "missing-port"} {
		if _, _, err := splitSocketAddress(socket); err == nil {
			t.Errorf("splitSocketAddress(%q) succeeded", socket)
		}
	}
	for _, socket := range []string{"[::]:443", "[fe80::1%eth0]:53", "127.0.0.1:3000", "*:22"} {
		if _, _, err := splitSocketAddress(socket); err != nil {
			t.Errorf("splitSocketAddress(%q) error = %v", socket, err)
		}
	}
}

type discoveryFixture struct {
	Runtime  RuntimeFacts                `json:"runtime"`
	Files    map[string]fixtureFile      `json:"files"`
	Disk     DiskUsage                   `json:"disk"`
	Commands []fixtureCommand            `json:"commands"`
	Expect   discoveryFixtureExpectation `json:"expect"`
}

type fixtureFile struct {
	Kind     FileKind `json:"kind"`
	Content  string   `json:"content"`
	Writable bool     `json:"writable"`
}

type fixtureCommand struct {
	Name     string   `json:"name"`
	Args     []string `json:"args"`
	ExitCode int      `json:"exit_code"`
	Stdout   string   `json:"stdout"`
	Stderr   string   `json:"stderr"`
}

type discoveryFixtureExpectation struct {
	MissingMandatory      []string      `json:"missing_mandatory"`
	Interfaces            []string      `json:"interfaces"`
	ContainerInterfaces   []string      `json:"container_interfaces"`
	NFTablesTables        []string      `json:"nftables_tables"`
	ActiveServices        []string      `json:"active_services"`
	Listeners             []string      `json:"listeners"`
	Routes                []string      `json:"routes"`
	PolicyRules           []string      `json:"policy_rules"`
	Resources             HostResources `json:"resources"`
	IPv4ForwardingEnabled bool          `json:"ipv4_forwarding_enabled"`
}

func loadDiscoveryFixture(t *testing.T, name string) discoveryFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "discovery", name+".json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture discoveryFixture
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return fixture
}

func (fixture discoveryFixture) commandMap(t *testing.T) map[string]ProbeResult {
	t.Helper()
	commands := make(map[string]ProbeResult, len(fixture.Commands))
	for _, command := range fixture.Commands {
		key := probeCommandKey(ProbeCommand{Name: command.Name, Args: command.Args})
		if _, duplicate := commands[key]; duplicate {
			t.Fatalf("fixture duplicates command %q", key)
		}
		commands[key] = ProbeResult{Stdout: []byte(command.Stdout), Stderr: []byte(command.Stderr), ExitCode: command.ExitCode}
	}
	return commands
}

type fixtureFileSystem map[string]fixtureFile

func (files fixtureFileSystem) ReadFile(path string) ([]byte, error) {
	file, found := files[path]
	if !found {
		return nil, fs.ErrNotExist
	}
	if file.Kind != FileRegular {
		return nil, errors.New("fixture object is not a regular file")
	}
	return []byte(file.Content), nil
}

func (files fixtureFileSystem) Kind(path string) (FileKind, error) {
	file, found := files[path]
	if !found {
		return "", fs.ErrNotExist
	}
	return file.Kind, nil
}

func (files fixtureFileSystem) Writable(path string) (bool, error) {
	file, found := files[path]
	if !found {
		return false, fs.ErrNotExist
	}
	return file.Writable, nil
}

type fixtureRunner struct {
	commands map[string]ProbeResult
	seen     []ProbeCommand
}

func (runner *fixtureRunner) Run(ctx context.Context, command ProbeCommand) (ProbeResult, error) {
	if err := ctx.Err(); err != nil {
		return ProbeResult{}, err
	}
	key := probeCommandKey(command)
	result, found := runner.commands[key]
	if !found {
		return ProbeResult{}, errors.New("unexpected fixture command: " + key)
	}
	delete(runner.commands, key)
	runner.seen = append(runner.seen, command)
	return result, nil
}

type fixtureDisk struct {
	usage DiskUsage
}

func (disk fixtureDisk) Usage(string) (DiskUsage, error) { return disk.usage, nil }

func probeCommandKey(command ProbeCommand) string {
	return strings.Join(append([]string{command.Name}, command.Args...), "\x00")
}

func assertReadOnlyProbe(t *testing.T, command ProbeCommand) {
	t.Helper()
	switch command.Name {
	case "systemctl":
		if len(command.Args) == 0 || (command.Args[0] != "--version" && command.Args[0] != "show") {
			t.Errorf("systemctl probe is not read-only: %v", command.Args)
		}
	case "modprobe":
		if !reflect.DeepEqual(command.Args, []string{"--dry-run", "wireguard"}) {
			t.Errorf("modprobe probe is not dry-run: %v", command.Args)
		}
	case "nft":
		if len(command.Args) == 0 || (command.Args[0] != "--version" && command.Args[0] != "--json" && command.Args[0] != "--check") {
			t.Errorf("nft probe is not read-only/check-only: %v", command.Args)
		}
		if command.Args[0] == "--check" && !bytes.Equal(command.Stdin, conntrackMarkCheck) {
			t.Errorf("nft check does not use the fixed capability ruleset")
		}
		if command.Args[0] != "--check" && len(command.Stdin) != 0 {
			t.Errorf("nft observation unexpectedly has stdin")
		}
	case "uname":
		if !reflect.DeepEqual(command.Args, []string{"--machine"}) {
			t.Errorf("uname probe has unexpected arguments: %v", command.Args)
		}
	case "ip":
		joined := " " + strings.Join(command.Args, " ") + " "
		for _, mutating := range []string{" add ", " del ", " delete ", " replace ", " flush ", " set "} {
			if strings.Contains(joined, mutating) {
				t.Errorf("ip probe is mutating: %v", command.Args)
			}
		}
	case "ss":
		if len(command.Stdin) != 0 {
			t.Errorf("ss probe unexpectedly has stdin")
		}
	default:
		t.Errorf("unexpected host probe command %q", command.Name)
	}
}

func interfaceNames(values []NetworkInterface) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.Name
	}
	return result
}

func containerNames(values []ContainerNetwork) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.Interface
	}
	return result
}

func tableNames(values []NFTablesTable) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.Family + "/" + value.Name
	}
	return result
}

func activeServiceNames(values []Service) []string {
	result := make([]string, 0)
	for _, value := range values {
		if value.ActiveState == "active" {
			result = append(result, value.Name)
		}
	}
	return result
}

func listenerNames(values []Listener) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.Protocol + "/" + value.Address + ":" + strconv.Itoa(value.Port)
	}
	return result
}

func routeNames(values []Route) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.Family + "/" + value.Table + "/" + value.Destination + "/" + value.Device
	}
	return result
}

func policyRuleNames(values []PolicyRule) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.Family + "/" + strconv.Itoa(value.Priority) + "/" + value.Table + "/" + value.FWMark + "/" + value.FWMask
	}
	return result
}

func assertFixtureNames(t *testing.T, label string, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %v, want %v", label, got, want)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortedKeys(values map[string]ProbeResult) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func uniqueSorted(values []string) []string {
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
