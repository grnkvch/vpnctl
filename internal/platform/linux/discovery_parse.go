package linux

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var containerInterfacePattern = regexp.MustCompile(`^(docker[0-9]*|br-[a-f0-9]+|cni[0-9]+|cni-|flannel|virbr[0-9]*|podman[0-9]*|lxcbr[0-9]*)`)

func parseOSRelease(data []byte) (OSRelease, error) {
	values := make(map[string]string)
	for lineNumber, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" {
			return OSRelease{}, fmt.Errorf("os-release line %d is malformed", lineNumber+1)
		}
		if strings.HasPrefix(value, `"`) {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				return OSRelease{}, fmt.Errorf("os-release line %d: %w", lineNumber+1, err)
			}
			value = decoded
		}
		values[key] = value
	}
	if values["ID"] == "" || values["VERSION_ID"] == "" {
		return OSRelease{}, fmt.Errorf("os-release lacks ID or VERSION_ID")
	}
	return OSRelease{ID: values["ID"], VersionID: values["VERSION_ID"], PrettyName: values["PRETTY_NAME"]}, nil
}

func parseMemory(data []byte) (HostResources, error) {
	values := make(map[string]uint64)
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		switch key {
		case "MemTotal", "MemAvailable", "SwapTotal", "SwapFree":
		default:
			continue
		}
		if seen[key] {
			return HostResources{}, fmt.Errorf("duplicate %s value", key)
		}
		seen[key] = true
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || value > ^uint64(0)/1024 {
			return HostResources{}, fmt.Errorf("invalid %s value", key)
		}
		if len(fields) != 3 {
			return HostResources{}, fmt.Errorf("%s must use an explicit kB unit", key)
		}
		if fields[2] != "kB" {
			return HostResources{}, fmt.Errorf("unsupported %s unit %q", key, fields[2])
		}
		values[key] = value * 1024
	}
	for _, key := range []string{"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"} {
		if !seen[key] || (key == "MemTotal" && values[key] == 0) {
			return HostResources{}, fmt.Errorf("%s is absent or invalid", key)
		}
	}
	return HostResources{
		MemoryTotalBytes: values["MemTotal"],
		MemoryFreeBytes:  values["MemAvailable"],
		SwapTotalBytes:   values["SwapTotal"],
		SwapFreeBytes:    values["SwapFree"],
	}, nil
}

func parseInterfaces(linkData, addressData []byte) ([]NetworkInterface, error) {
	var links []struct {
		Index        int      `json:"ifindex"`
		Name         string   `json:"ifname"`
		Type         string   `json:"link_type"`
		State        string   `json:"operstate"`
		MTU          int      `json:"mtu"`
		HardwareAddr string   `json:"address"`
		Flags        []string `json:"flags"`
	}
	if err := decodeJSON(linkData, &links); err != nil {
		return nil, fmt.Errorf("decode links: %w", err)
	}
	var addresses []struct {
		Name     string `json:"ifname"`
		AddrInfo []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	if err := decodeJSON(addressData, &addresses); err != nil {
		return nil, fmt.Errorf("decode addresses: %w", err)
	}
	addressByName := make(map[string][]InterfaceAddress, len(addresses))
	for _, entry := range addresses {
		for _, address := range entry.AddrInfo {
			if address.Family != "inet" && address.Family != "inet6" {
				continue
			}
			addressByName[entry.Name] = append(addressByName[entry.Name], InterfaceAddress{
				Family: address.Family, Address: address.Local, PrefixLen: address.PrefixLen, Scope: address.Scope,
			})
		}
		sort.Slice(addressByName[entry.Name], func(i, j int) bool {
			left := addressByName[entry.Name][i]
			right := addressByName[entry.Name][j]
			return left.Family+"\x00"+left.Address < right.Family+"\x00"+right.Address
		})
	}
	interfaces := make([]NetworkInterface, 0, len(links))
	seen := make(map[string]struct{}, len(links))
	for _, link := range links {
		if link.Index <= 0 || link.Name == "" {
			return nil, fmt.Errorf("link lacks positive index or name")
		}
		if _, duplicate := seen[link.Name]; duplicate {
			return nil, fmt.Errorf("duplicate link %q", link.Name)
		}
		seen[link.Name] = struct{}{}
		interfaces = append(interfaces, NetworkInterface{
			Index: link.Index, Name: link.Name, Type: link.Type, State: link.State, MTU: link.MTU,
			HardwareAddr: link.HardwareAddr, Flags: append([]string(nil), link.Flags...),
			Addresses: append([]InterfaceAddress(nil), addressByName[link.Name]...),
		})
	}
	return interfaces, nil
}

func parseRoutes(data []byte, family string) ([]Route, error) {
	var raw []struct {
		Destination     string          `json:"dst"`
		Gateway         string          `json:"gateway"`
		Device          string          `json:"dev"`
		PreferredSource string          `json:"prefsrc"`
		Table           json.RawMessage `json:"table"`
		Protocol        string          `json:"protocol"`
		Scope           string          `json:"scope"`
		Type            string          `json:"type"`
		Metric          int             `json:"metric"`
	}
	if err := decodeJSON(data, &raw); err != nil {
		return nil, err
	}
	routes := make([]Route, 0, len(raw))
	for _, entry := range raw {
		table, err := rawScalar(entry.Table, "main")
		if err != nil {
			return nil, fmt.Errorf("route table: %w", err)
		}
		destination := entry.Destination
		if destination == "" {
			destination = "default"
		}
		routes = append(routes, Route{
			Family: family, Destination: destination, Gateway: entry.Gateway, Device: entry.Device,
			PreferredSource: entry.PreferredSource, Table: table, Protocol: entry.Protocol, Scope: entry.Scope,
			Type: entry.Type, Metric: entry.Metric,
		})
	}
	return routes, nil
}

func parsePolicyRules(data []byte, family string) ([]PolicyRule, error) {
	var raw []struct {
		Priority int             `json:"priority"`
		From     string          `json:"from"`
		To       string          `json:"to"`
		Table    json.RawMessage `json:"table"`
		FWMark   json.RawMessage `json:"fwmark"`
		FWMask   json.RawMessage `json:"fwmask"`
	}
	if err := decodeJSON(data, &raw); err != nil {
		return nil, err
	}
	rules := make([]PolicyRule, 0, len(raw))
	for _, entry := range raw {
		table, err := rawScalar(entry.Table, "")
		if err != nil {
			return nil, fmt.Errorf("policy table: %w", err)
		}
		mark, err := rawScalar(entry.FWMark, "")
		if err != nil {
			return nil, fmt.Errorf("policy fwmark: %w", err)
		}
		mask, err := rawScalar(entry.FWMask, "")
		if err != nil {
			return nil, fmt.Errorf("policy fwmask: %w", err)
		}
		rules = append(rules, PolicyRule{
			Family: family, Priority: entry.Priority, From: entry.From, To: entry.To,
			Table: table, FWMark: mark, FWMask: mask,
		})
	}
	return rules, nil
}

func parseNFTables(data []byte) ([]NFTablesTable, error) {
	var document struct {
		NFTables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table,omitempty"`
		} `json:"nftables"`
	}
	if err := decodeJSON(data, &document); err != nil {
		return nil, err
	}
	tables := make([]NFTablesTable, 0)
	for _, object := range document.NFTables {
		if object.Table == nil {
			continue
		}
		if object.Table.Family == "" || object.Table.Name == "" {
			return nil, fmt.Errorf("nftables table lacks family or name")
		}
		tables = append(tables, NFTablesTable{Family: object.Table.Family, Name: object.Table.Name})
	}
	return tables, nil
}

func parseListeners(data []byte) ([]Listener, error) {
	listeners := make([]Listener, 0)
	for lineNumber, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return nil, fmt.Errorf("listener line %d has too few fields", lineNumber+1)
		}
		protocol := strings.ToLower(fields[0])
		if strings.HasPrefix(protocol, "tcp") {
			protocol = "tcp"
		} else if strings.HasPrefix(protocol, "udp") {
			protocol = "udp"
		} else {
			continue
		}
		address, port, err := splitSocketAddress(fields[4])
		if err != nil {
			return nil, fmt.Errorf("listener line %d: %w", lineNumber+1, err)
		}
		process := ""
		if len(fields) > 6 {
			process = strings.Join(fields[6:], " ")
		}
		listeners = append(listeners, Listener{Protocol: protocol, Address: address, Port: port, Process: process})
	}
	return listeners, nil
}

func splitSocketAddress(value string) (string, int, error) {
	separator := strings.LastIndexByte(value, ':')
	if separator < 0 || separator == len(value)-1 {
		return "", 0, fmt.Errorf("invalid local socket %q", value)
	}
	address := strings.Trim(value[:separator], "[]")
	port, err := strconv.Atoi(value[separator+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid local socket port in %q", value)
	}
	parseAddress := address
	if zone := strings.LastIndexByte(parseAddress, '%'); zone >= 0 {
		parseAddress = parseAddress[:zone]
	}
	if address != "*" && net.ParseIP(parseAddress) == nil {
		return "", 0, fmt.Errorf("invalid local socket address in %q", value)
	}
	return address, port, nil
}

func deriveContainerNetworks(interfaces []NetworkInterface) []ContainerNetwork {
	networks := make([]ContainerNetwork, 0)
	for _, networkInterface := range interfaces {
		if !containerInterfacePattern.MatchString(networkInterface.Name) {
			continue
		}
		cidrs := make([]string, 0, len(networkInterface.Addresses))
		for _, address := range networkInterface.Addresses {
			ip := net.ParseIP(address.Address)
			if ip == nil {
				continue
			}
			bits := 128
			if address.Family == "inet" {
				bits = 32
			}
			cidrs = append(cidrs, (&net.IPNet{IP: ip, Mask: net.CIDRMask(address.PrefixLen, bits)}).String())
		}
		sort.Strings(cidrs)
		networks = append(networks, ContainerNetwork{Interface: networkInterface.Name, CIDRs: cidrs})
	}
	return networks
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return fmt.Errorf("trailing JSON document")
	} else if err != io.EOF {
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func rawScalar(raw json.RawMessage, fallback string) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return fallback, nil
	}
	var stringValue string
	if err := json.Unmarshal(raw, &stringValue); err == nil {
		return stringValue, nil
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err == nil {
		return number.String(), nil
	}
	return "", fmt.Errorf("expected string or number, got %s", raw)
}
