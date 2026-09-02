package linux

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

const HostSnapshotSchemaVersion = 1

var conntrackMarkCheck = []byte(`table inet vpnctl_capability_probe {
  chain output {
    type route hook output priority mangle; policy accept;
    ct mark set meta mark
    meta mark set ct mark
  }
}
`)

func (discoverer *Discoverer) Discover(ctx context.Context) (HostSnapshot, error) {
	if ctx == nil {
		return HostSnapshot{}, fmt.Errorf("context is required")
	}
	if discoverer == nil || discoverer.files == nil || discoverer.runner == nil || discoverer.disk == nil {
		return HostSnapshot{}, fmt.Errorf("discoverer dependencies are incomplete")
	}
	snapshot := HostSnapshot{
		SchemaVersion:     HostSnapshotSchemaVersion,
		KernelOS:          discoverer.runtime.GOOS,
		EffectiveUID:      discoverer.runtime.EUID,
		Interfaces:        []NetworkInterface{},
		Routes:            []Route{},
		PolicyRules:       []PolicyRule{},
		ContainerNetworks: []ContainerNetwork{},
		Listeners:         []Listener{},
		NFTablesTables:    []NFTablesTable{},
		Services:          []Service{},
		ProbeIssues:       []ProbeIssue{},
	}
	snapshot.Capabilities.Linux = availability(discoverer.runtime.GOOS == "linux", discoverer.runtime.GOOS)
	snapshot.Capabilities.Root = availability(discoverer.runtime.EUID == 0, fmt.Sprintf("euid=%d", discoverer.runtime.EUID))
	if err := discoverer.discoverArchitecture(ctx, &snapshot); err != nil {
		return HostSnapshot{}, err
	}

	discoverer.discoverOSRelease(&snapshot)
	if err := discoverer.discoverSystemd(ctx, &snapshot); err != nil {
		return HostSnapshot{}, err
	}
	discoverer.discoverTUN(&snapshot)
	if err := discoverer.discoverWireGuard(ctx, &snapshot); err != nil {
		return HostSnapshot{}, err
	}
	if err := discoverer.discoverNFTables(ctx, &snapshot); err != nil {
		return HostSnapshot{}, err
	}
	if err := discoverer.discoverNetworking(ctx, &snapshot); err != nil {
		return HostSnapshot{}, err
	}
	if err := discoverer.discoverListeners(ctx, &snapshot); err != nil {
		return HostSnapshot{}, err
	}
	discoverer.discoverForwarding(&snapshot)
	discoverer.discoverResources(&snapshot)
	discoverer.finalize(&snapshot)
	return snapshot, nil
}

func (discoverer *Discoverer) discoverArchitecture(ctx context.Context, snapshot *HostSnapshot) error {
	result, err := discoverer.run(ctx, "architecture", ProbeCommand{Name: "uname", Args: []string{"--machine"}}, true, snapshot)
	if err != nil {
		return err
	}
	machine := firstLine(result.Stdout, "unknown")
	if machine == "x86_64" || machine == "amd64" {
		snapshot.Architecture = "amd64"
	} else {
		snapshot.Architecture = machine
	}
	available := result.ExitCode == 0 && snapshot.Architecture == "amd64" && discoverer.runtime.GOARCH == "amd64"
	snapshot.Capabilities.AMD64 = availability(available, "kernel="+machine+" binary="+discoverer.runtime.GOARCH)
	return nil
}

func (discoverer *Discoverer) discoverOSRelease(snapshot *HostSnapshot) {
	data, err := discoverer.files.ReadFile("/etc/os-release")
	if err != nil {
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("os_release", err, true))
		snapshot.Capabilities.Ubuntu2404 = availability(false, "cannot read /etc/os-release")
		return
	}
	release, err := parseOSRelease(data)
	if err != nil {
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("os_release", err, true))
		snapshot.Capabilities.Ubuntu2404 = availability(false, "invalid /etc/os-release")
		return
	}
	snapshot.OS = release
	supported := release.ID == "ubuntu" && release.VersionID == "24.04"
	snapshot.Capabilities.Ubuntu2404 = availability(supported, release.ID+" "+release.VersionID)
}

func (discoverer *Discoverer) discoverSystemd(ctx context.Context, snapshot *HostSnapshot) error {
	directory, err := fileExists(discoverer.files, "/run/systemd/system", FileDirectory)
	if err != nil {
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("systemd_runtime", err, true))
	}
	result, runErr := discoverer.run(ctx, "systemd", ProbeCommand{Name: "systemctl", Args: []string{"--version"}}, true, snapshot)
	if runErr != nil {
		return runErr
	}
	available := directory && result.ExitCode == 0
	snapshot.Capabilities.Systemd = availability(available, firstLine(result.Stdout, "systemd unavailable"))

	for _, serviceName := range []string{"systemd-resolved.service", "ufw.service", "firewalld.service"} {
		service, err := discoverer.serviceState(ctx, serviceName, snapshot)
		if err != nil {
			return err
		}
		snapshot.Services = append(snapshot.Services, service)
		if serviceName == "systemd-resolved.service" {
			loaded := service.LoadState == "loaded"
			snapshot.Capabilities.SystemdResolved = availability(loaded, service.LoadState+"/"+service.ActiveState)
			if !loaded {
				snapshot.ProbeIssues = append(snapshot.ProbeIssues, ProbeIssue{Probe: "systemd_resolved", Message: "systemd-resolved.service is not loaded", Mandatory: true})
			}
		}
	}
	return nil
}

func (discoverer *Discoverer) discoverTUN(snapshot *HostSnapshot) {
	kind, err := discoverer.files.Kind("/dev/net/tun")
	if err != nil {
		snapshot.Capabilities.TUN = availability(false, "missing /dev/net/tun character device")
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("tun", err, true))
		return
	}
	snapshot.Capabilities.TUN = availability(kind == FileCharacter, string(kind))
	if kind != FileCharacter {
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, ProbeIssue{Probe: "tun", Message: "/dev/net/tun is not a character device", Mandatory: true})
	}
}

func (discoverer *Discoverer) discoverWireGuard(ctx context.Context, snapshot *HostSnapshot) error {
	loaded, err := fileExists(discoverer.files, "/sys/module/wireguard", FileDirectory)
	if err != nil {
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("wireguard_module", err, true))
	}
	if loaded {
		snapshot.Capabilities.KernelWireGuard = availability(true, "kernel module loaded")
		return nil
	}
	result, runErr := discoverer.run(ctx, "wireguard_module", ProbeCommand{Name: "modprobe", Args: []string{"--dry-run", "wireguard"}}, true, snapshot)
	if runErr != nil {
		return runErr
	}
	available := result.ExitCode == 0
	snapshot.Capabilities.KernelWireGuard = availability(available, commandDetail("modprobe --dry-run wireguard", result))
	return nil
}

func (discoverer *Discoverer) discoverNFTables(ctx context.Context, snapshot *HostSnapshot) error {
	version, err := discoverer.run(ctx, "nftables", ProbeCommand{Name: "nft", Args: []string{"--version"}}, true, snapshot)
	if err != nil {
		return err
	}
	list, err := discoverer.run(ctx, "nftables_tables", ProbeCommand{Name: "nft", Args: []string{"--json", "list", "tables"}}, false, snapshot)
	if err != nil {
		return err
	}
	snapshot.Capabilities.NFTables = availability(version.ExitCode == 0 && list.ExitCode == 0, firstLine(version.Stdout, commandDetail("nft", version)))
	if list.ExitCode == 0 {
		tables, parseErr := parseNFTables(list.Stdout)
		if parseErr != nil {
			snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("nftables_tables", parseErr, false))
		} else {
			snapshot.NFTablesTables = tables
		}
	}
	marks, err := discoverer.run(ctx, "conntrack_marks", ProbeCommand{Name: "nft", Args: []string{"--check", "--file", "-"}, Stdin: conntrackMarkCheck}, true, snapshot)
	if err != nil {
		return err
	}
	snapshot.Capabilities.ConntrackMarks = availability(marks.ExitCode == 0, commandDetail("nft --check conntrack marks", marks))
	return nil
}

func (discoverer *Discoverer) discoverNetworking(ctx context.Context, snapshot *HostSnapshot) error {
	version, err := discoverer.run(ctx, "policy_routing", ProbeCommand{Name: "ip", Args: []string{"-Version"}}, true, snapshot)
	if err != nil {
		return err
	}
	rules4, err := discoverer.run(ctx, "policy_rules_ipv4", ProbeCommand{Name: "ip", Args: []string{"-json", "-4", "rule", "show"}}, true, snapshot)
	if err != nil {
		return err
	}
	rules6, err := discoverer.run(ctx, "policy_rules_ipv6", ProbeCommand{Name: "ip", Args: []string{"-json", "-6", "rule", "show"}}, false, snapshot)
	if err != nil {
		return err
	}
	policyAvailable := version.ExitCode == 0 && rules4.ExitCode == 0
	snapshot.Capabilities.PolicyRouting = availability(policyAvailable, firstLine(version.Stdout, commandDetail("ip rule", rules4)))
	if rules4.ExitCode == 0 {
		snapshot.PolicyRules = append(snapshot.PolicyRules, parsePolicyRulesWithIssue(rules4.Stdout, "ipv4", "policy_rules_ipv4", snapshot)...)
	}
	if rules6.ExitCode == 0 {
		snapshot.PolicyRules = append(snapshot.PolicyRules, parsePolicyRulesWithIssue(rules6.Stdout, "ipv6", "policy_rules_ipv6", snapshot)...)
	}

	links, err := discoverer.run(ctx, "interfaces", ProbeCommand{Name: "ip", Args: []string{"-json", "link", "show"}}, false, snapshot)
	if err != nil {
		return err
	}
	addresses, err := discoverer.run(ctx, "addresses", ProbeCommand{Name: "ip", Args: []string{"-json", "address", "show"}}, false, snapshot)
	if err != nil {
		return err
	}
	if links.ExitCode == 0 && addresses.ExitCode == 0 {
		interfaces, parseErr := parseInterfaces(links.Stdout, addresses.Stdout)
		if parseErr != nil {
			snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("interfaces", parseErr, false))
		} else {
			snapshot.Interfaces = interfaces
			snapshot.ContainerNetworks = deriveContainerNetworks(interfaces)
		}
	}

	for _, routeProbe := range []struct {
		family string
		name   string
		args   []string
	}{
		{family: "ipv4", name: "routes_ipv4", args: []string{"-json", "-4", "route", "show", "table", "all"}},
		{family: "ipv6", name: "routes_ipv6", args: []string{"-json", "-6", "route", "show", "table", "all"}},
	} {
		result, runErr := discoverer.run(ctx, routeProbe.name, ProbeCommand{Name: "ip", Args: routeProbe.args}, false, snapshot)
		if runErr != nil {
			return runErr
		}
		if result.ExitCode != 0 {
			continue
		}
		routes, parseErr := parseRoutes(result.Stdout, routeProbe.family)
		if parseErr != nil {
			snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue(routeProbe.name, parseErr, false))
			continue
		}
		snapshot.Routes = append(snapshot.Routes, routes...)
	}
	return nil
}

func (discoverer *Discoverer) discoverListeners(ctx context.Context, snapshot *HostSnapshot) error {
	result, err := discoverer.run(ctx, "listeners", ProbeCommand{Name: "ss", Args: []string{"--no-header", "--numeric", "--listening", "--tcp", "--udp", "--process"}}, false, snapshot)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return nil
	}
	listeners, parseErr := parseListeners(result.Stdout)
	if parseErr != nil {
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("listeners", parseErr, false))
		return nil
	}
	snapshot.Listeners = listeners
	return nil
}

func (discoverer *Discoverer) discoverForwarding(snapshot *HostSnapshot) {
	data, err := discoverer.files.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		snapshot.Capabilities.IPv4Forwarding = availability(false, "missing IPv4 forwarding sysctl")
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("ipv4_forwarding", err, true))
		return
	}
	value := strings.TrimSpace(string(data))
	if value != "0" && value != "1" {
		snapshot.Capabilities.IPv4Forwarding = availability(false, "invalid net.ipv4.ip_forward value")
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, ProbeIssue{Probe: "ipv4_forwarding", Message: "net.ipv4.ip_forward is neither 0 nor 1", Mandatory: true})
		return
	}
	writable, err := discoverer.files.Writable("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		snapshot.Capabilities.IPv4Forwarding = availability(false, "cannot verify writable IPv4 forwarding sysctl")
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("ipv4_forwarding", err, true))
		return
	}
	if !writable {
		snapshot.Capabilities.IPv4Forwarding = availability(false, "net.ipv4.ip_forward is read-only")
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, ProbeIssue{Probe: "ipv4_forwarding", Message: "net.ipv4.ip_forward cannot be changed", Mandatory: true})
		return
	}
	snapshot.Capabilities.IPv4Forwarding = availability(true, "net.ipv4.ip_forward is writable")
	snapshot.IPv4ForwardingEnabled = value == "1"
}

func (discoverer *Discoverer) discoverResources(snapshot *HostSnapshot) {
	data, err := discoverer.files.ReadFile("/proc/meminfo")
	if err != nil {
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("memory", err, false))
	} else {
		resources, parseErr := parseMemory(data)
		if parseErr != nil {
			snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("memory", parseErr, false))
		} else {
			snapshot.Resources = resources
		}
	}
	usage, err := discoverer.disk.Usage("/")
	if err != nil {
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue("disk", err, false))
		return
	}
	snapshot.Resources.DiskTotalBytes = usage.TotalBytes
	snapshot.Resources.DiskFreeBytes = usage.FreeBytes
}

func (discoverer *Discoverer) serviceState(ctx context.Context, name string, snapshot *HostSnapshot) (Service, error) {
	result, err := discoverer.run(ctx, "service_"+strings.TrimSuffix(name, ".service"), ProbeCommand{
		Name: "systemctl", Args: []string{"show", "--property=LoadState", "--property=ActiveState", name},
	}, name == "systemd-resolved.service", snapshot)
	if err != nil {
		return Service{}, err
	}
	service := Service{Name: name, LoadState: "unknown", ActiveState: "unknown"}
	lines := nonemptyLines(result.Stdout)
	for _, line := range lines {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch key {
		case "LoadState":
			service.LoadState = value
		case "ActiveState":
			service.ActiveState = value
		}
	}
	if result.ExitCode != 0 && len(lines) == 0 {
		service.LoadState = "not-found"
		service.ActiveState = "inactive"
	}
	return service, nil
}

func (discoverer *Discoverer) run(ctx context.Context, probeName string, command ProbeCommand, mandatory bool, snapshot *HostSnapshot) (ProbeResult, error) {
	result, err := discoverer.runner.Run(ctx, command)
	if err != nil {
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue(probeName, err, mandatory))
		return ProbeResult{ExitCode: -1}, nil
	}
	if result.ExitCode != 0 {
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, ProbeIssue{
			Probe: probeName, Message: fmt.Sprintf("probe command exited with code %d", result.ExitCode), Mandatory: mandatory,
		})
	}
	return result, nil
}

func (discoverer *Discoverer) finalize(snapshot *HostSnapshot) {
	sort.Slice(snapshot.Interfaces, func(i, j int) bool { return snapshot.Interfaces[i].Index < snapshot.Interfaces[j].Index })
	sort.Slice(snapshot.Routes, func(i, j int) bool {
		left := snapshot.Routes[i].Family + "\x00" + snapshot.Routes[i].Table + "\x00" + snapshot.Routes[i].Destination + "\x00" + snapshot.Routes[i].Device
		right := snapshot.Routes[j].Family + "\x00" + snapshot.Routes[j].Table + "\x00" + snapshot.Routes[j].Destination + "\x00" + snapshot.Routes[j].Device
		return left < right
	})
	sort.Slice(snapshot.PolicyRules, func(i, j int) bool {
		if snapshot.PolicyRules[i].Family == snapshot.PolicyRules[j].Family {
			return snapshot.PolicyRules[i].Priority < snapshot.PolicyRules[j].Priority
		}
		return snapshot.PolicyRules[i].Family < snapshot.PolicyRules[j].Family
	})
	sort.Slice(snapshot.ContainerNetworks, func(i, j int) bool {
		return snapshot.ContainerNetworks[i].Interface < snapshot.ContainerNetworks[j].Interface
	})
	sort.Slice(snapshot.Listeners, func(i, j int) bool {
		left := snapshot.Listeners[i].Protocol + "\x00" + snapshot.Listeners[i].Address + fmt.Sprintf("\x00%05d", snapshot.Listeners[i].Port)
		right := snapshot.Listeners[j].Protocol + "\x00" + snapshot.Listeners[j].Address + fmt.Sprintf("\x00%05d", snapshot.Listeners[j].Port)
		return left < right
	})
	sort.Slice(snapshot.NFTablesTables, func(i, j int) bool {
		return snapshot.NFTablesTables[i].Family+"\x00"+snapshot.NFTablesTables[i].Name < snapshot.NFTablesTables[j].Family+"\x00"+snapshot.NFTablesTables[j].Name
	})
	sort.Slice(snapshot.Services, func(i, j int) bool { return snapshot.Services[i].Name < snapshot.Services[j].Name })
	sort.Slice(snapshot.ProbeIssues, func(i, j int) bool {
		if snapshot.ProbeIssues[i].Probe == snapshot.ProbeIssues[j].Probe {
			return snapshot.ProbeIssues[i].Message < snapshot.ProbeIssues[j].Message
		}
		return snapshot.ProbeIssues[i].Probe < snapshot.ProbeIssues[j].Probe
	})
}

func parsePolicyRulesWithIssue(data []byte, family, probe string, snapshot *HostSnapshot) []PolicyRule {
	rules, err := parsePolicyRules(data, family)
	if err != nil {
		snapshot.ProbeIssues = append(snapshot.ProbeIssues, probeIssue(probe, err, false))
		return nil
	}
	return rules
}

func availability(available bool, detail string) Capability {
	if strings.TrimSpace(detail) == "" {
		if available {
			detail = "available"
		} else {
			detail = "unavailable"
		}
	}
	return Capability{Available: available, Detail: detail}
}

func probeIssue(probe string, err error, mandatory bool) ProbeIssue {
	message := "unknown probe error"
	if err != nil {
		message = err.Error()
	}
	if errors.Is(err, fs.ErrNotExist) {
		message = "required host object is absent"
	}
	return ProbeIssue{Probe: probe, Message: message, Mandatory: mandatory}
}

func commandDetail(name string, result ProbeResult) string {
	if result.ExitCode == 0 {
		return name + " available"
	}
	return fmt.Sprintf("%s exited with code %d", name, result.ExitCode)
}

func firstLine(data []byte, fallback string) string {
	lines := nonemptyLines(data)
	if len(lines) == 0 {
		return fallback
	}
	return lines[0]
}

func nonemptyLines(data []byte) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
