package linux

import (
	"errors"
	"fmt"
	"strings"
)

var ErrUnsupportedHost = errors.New("host does not satisfy vpnctl v2 requirements")

type Capability struct {
	Available bool   `json:"available"`
	Detail    string `json:"detail"`
}

type Capabilities struct {
	Linux           Capability `json:"linux"`
	AMD64           Capability `json:"amd64"`
	Ubuntu2404      Capability `json:"ubuntu_24_04"`
	Root            Capability `json:"root"`
	Systemd         Capability `json:"systemd"`
	TUN             Capability `json:"tun"`
	KernelWireGuard Capability `json:"kernel_wireguard"`
	NFTables        Capability `json:"nftables"`
	PolicyRouting   Capability `json:"policy_routing"`
	ConntrackMarks  Capability `json:"conntrack_marks"`
	SystemdResolved Capability `json:"systemd_resolved"`
	IPv4Forwarding  Capability `json:"ipv4_forwarding"`
}

type HostSnapshot struct {
	SchemaVersion         int                `json:"schema_version"`
	OS                    OSRelease          `json:"os"`
	KernelOS              string             `json:"kernel_os"`
	Architecture          string             `json:"architecture"`
	EffectiveUID          int                `json:"effective_uid"`
	Capabilities          Capabilities       `json:"capabilities"`
	IPv4ForwardingEnabled bool               `json:"ipv4_forwarding_enabled"`
	DNSResolversIPv4      []string           `json:"dns_resolvers_ipv4"`
	Interfaces            []NetworkInterface `json:"interfaces"`
	Routes                []Route            `json:"routes"`
	PolicyRules           []PolicyRule       `json:"policy_rules"`
	ContainerNetworks     []ContainerNetwork `json:"container_networks"`
	Listeners             []Listener         `json:"listeners"`
	NFTablesTables        []NFTablesTable    `json:"nftables_tables"`
	Services              []Service          `json:"services"`
	Resources             HostResources      `json:"resources"`
	ProbeIssues           []ProbeIssue       `json:"probe_issues"`
}

type OSRelease struct {
	ID         string `json:"id"`
	VersionID  string `json:"version_id"`
	PrettyName string `json:"pretty_name"`
}

type NetworkInterface struct {
	Index        int                `json:"index"`
	Name         string             `json:"name"`
	Type         string             `json:"type"`
	State        string             `json:"state"`
	MTU          int                `json:"mtu"`
	HardwareAddr string             `json:"hardware_address,omitempty"`
	Flags        []string           `json:"flags"`
	Addresses    []InterfaceAddress `json:"addresses"`
}

type InterfaceAddress struct {
	Family    string `json:"family"`
	Address   string `json:"address"`
	PrefixLen int    `json:"prefix_length"`
	Scope     string `json:"scope"`
}

type Route struct {
	Family          string `json:"family"`
	Destination     string `json:"destination"`
	Gateway         string `json:"gateway,omitempty"`
	Device          string `json:"device,omitempty"`
	PreferredSource string `json:"preferred_source,omitempty"`
	Table           string `json:"table"`
	Protocol        string `json:"protocol,omitempty"`
	Scope           string `json:"scope,omitempty"`
	Type            string `json:"type,omitempty"`
	Metric          int    `json:"metric,omitempty"`
}

type PolicyRule struct {
	Family   string `json:"family"`
	Priority int    `json:"priority"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
	Table    string `json:"table"`
	FWMark   string `json:"fwmark,omitempty"`
	FWMask   string `json:"fwmask,omitempty"`
}

type ContainerNetwork struct {
	Interface string   `json:"interface"`
	CIDRs     []string `json:"cidrs"`
}

type Listener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Process  string `json:"process,omitempty"`
}

type NFTablesTable struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

type Service struct {
	Name        string `json:"name"`
	LoadState   string `json:"load_state"`
	ActiveState string `json:"active_state"`
}

type HostResources struct {
	MemoryTotalBytes uint64 `json:"memory_total_bytes"`
	MemoryFreeBytes  uint64 `json:"memory_free_bytes"`
	SwapTotalBytes   uint64 `json:"swap_total_bytes"`
	SwapFreeBytes    uint64 `json:"swap_free_bytes"`
	DiskTotalBytes   uint64 `json:"disk_total_bytes"`
	DiskFreeBytes    uint64 `json:"disk_free_bytes"`
}

type ProbeIssue struct {
	Probe     string `json:"probe"`
	Message   string `json:"message"`
	Mandatory bool   `json:"mandatory"`
}

type CapabilityFailure struct {
	Name   string
	Detail string
}

type UnsupportedHostError struct {
	Failures []CapabilityFailure
}

func (err *UnsupportedHostError) Error() string {
	details := make([]string, len(err.Failures))
	for index, failure := range err.Failures {
		details[index] = fmt.Sprintf("%s (%s)", failure.Name, failure.Detail)
	}
	return fmt.Sprintf("%s: %s", ErrUnsupportedHost, strings.Join(details, "; "))
}

func (*UnsupportedHostError) Unwrap() error { return ErrUnsupportedHost }

func (snapshot HostSnapshot) MissingMandatoryCapabilities() []string {
	checks := snapshot.mandatoryCapabilities()
	missing := make([]string, 0)
	for _, check := range checks {
		if !check.capability.Available {
			missing = append(missing, check.name)
		}
	}
	return missing
}

func (snapshot HostSnapshot) ValidateMandatoryCapabilities() error {
	checks := snapshot.mandatoryCapabilities()
	failures := make([]CapabilityFailure, 0)
	for _, check := range checks {
		if !check.capability.Available {
			failures = append(failures, CapabilityFailure{Name: check.name, Detail: check.capability.Detail})
		}
	}
	if len(failures) == 0 {
		return nil
	}
	return &UnsupportedHostError{Failures: failures}
}

func (snapshot HostSnapshot) mandatoryCapabilities() []struct {
	name       string
	capability Capability
} {
	return []struct {
		name       string
		capability Capability
	}{
		{name: "linux", capability: snapshot.Capabilities.Linux},
		{name: "amd64", capability: snapshot.Capabilities.AMD64},
		{name: "ubuntu_24_04", capability: snapshot.Capabilities.Ubuntu2404},
		{name: "root", capability: snapshot.Capabilities.Root},
		{name: "systemd", capability: snapshot.Capabilities.Systemd},
		{name: "tun", capability: snapshot.Capabilities.TUN},
		{name: "kernel_wireguard", capability: snapshot.Capabilities.KernelWireGuard},
		{name: "nftables", capability: snapshot.Capabilities.NFTables},
		{name: "policy_routing", capability: snapshot.Capabilities.PolicyRouting},
		{name: "conntrack_marks", capability: snapshot.Capabilities.ConntrackMarks},
		{name: "systemd_resolved", capability: snapshot.Capabilities.SystemdResolved},
		{name: "ipv4_forwarding", capability: snapshot.Capabilities.IPv4Forwarding},
	}
}
