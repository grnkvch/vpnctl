package routing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	GatewayDNSConfigSchemaVersion = 1
	GatewayDNSConfigFileName      = "gateway-dns.json"
	GatewayDNSReadyFileName       = "gateway-dns.ready"
	GatewayDNSPort                = 53
	maximumGatewayDNSConfigBytes  = 64 << 10
)

// GatewayDNSConfig is intentionally identity-free. A single process binds the
// gateway addresses of both overlay pools and applies one authoritative
// upstream list to every admitted client and node.
type GatewayDNSConfig struct {
	SchemaVersion int      `json:"schema_version"`
	Generation    uint64   `json:"generation"`
	ListenIPv4    []string `json:"listen_ipv4"`
	UpstreamIPv4  []string `json:"upstream_ipv4"`
}

func (config GatewayDNSConfig) Validate() error {
	if config.SchemaVersion != GatewayDNSConfigSchemaVersion || config.Generation == 0 {
		return fmt.Errorf("invalid gateway DNS config version or generation")
	}
	if len(config.ListenIPv4) != 2 || len(config.UpstreamIPv4) == 0 || len(config.UpstreamIPv4) > model.MaximumDNSUpstreams {
		return fmt.Errorf("invalid gateway DNS listener or upstream count")
	}
	if err := validateGatewayDNSAddresses(config.ListenIPv4, false); err != nil {
		return fmt.Errorf("validate gateway DNS listeners: %w", err)
	}
	if err := validateGatewayDNSAddresses(config.UpstreamIPv4, true); err != nil {
		return fmt.Errorf("validate gateway DNS upstreams: %w", err)
	}
	return nil
}

type GatewayDNSCandidate struct {
	config  GatewayDNSConfig
	content []byte
}

func (candidate GatewayDNSCandidate) Config() GatewayDNSConfig {
	result := candidate.config
	result.ListenIPv4 = append([]string(nil), result.ListenIPv4...)
	result.UpstreamIPv4 = append([]string(nil), result.UpstreamIPv4...)
	return result
}

func (candidate GatewayDNSCandidate) Bytes() []byte {
	return append([]byte(nil), candidate.content...)
}

func RenderGatewayDNSConfig(state model.State) (GatewayDNSCandidate, error) {
	if err := state.Validate(); err != nil {
		return GatewayDNSCandidate{}, fmt.Errorf("validate gateway DNS state: %w", err)
	}
	if state.Host.Role != model.RoleGateway || state.DNS == nil || state.DNS.Scope != model.DNSUpstreamGateway {
		return GatewayDNSCandidate{}, fmt.Errorf("gateway DNS requires gateway-owned upstream state")
	}
	client, err := gatewayDNSPoolAddress(state.Host.ClientCIDR)
	if err != nil {
		return GatewayDNSCandidate{}, fmt.Errorf("derive client gateway DNS address: %w", err)
	}
	node, err := gatewayDNSPoolAddress(state.Host.NodeCIDR)
	if err != nil {
		return GatewayDNSCandidate{}, fmt.Errorf("derive node gateway DNS address: %w", err)
	}
	config := GatewayDNSConfig{
		SchemaVersion: GatewayDNSConfigSchemaVersion,
		Generation:    state.Generation,
		ListenIPv4:    []string{client, node},
		UpstreamIPv4:  append([]string(nil), state.DNS.IPv4...),
	}
	if err := config.Validate(); err != nil {
		return GatewayDNSCandidate{}, err
	}
	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return GatewayDNSCandidate{}, fmt.Errorf("encode gateway DNS config: %w", err)
	}
	content = append(content, '\n')
	if len(content) > maximumGatewayDNSConfigBytes {
		return GatewayDNSCandidate{}, fmt.Errorf("gateway DNS config exceeds size limit")
	}
	return GatewayDNSCandidate{config: config, content: content}, nil
}

func DecodeGatewayDNSConfig(content []byte) (GatewayDNSConfig, error) {
	if len(content) == 0 || len(content) > maximumGatewayDNSConfigBytes {
		return GatewayDNSConfig{}, fmt.Errorf("gateway DNS config has invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var config GatewayDNSConfig
	if err := decoder.Decode(&config); err != nil {
		return GatewayDNSConfig{}, fmt.Errorf("decode gateway DNS config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return GatewayDNSConfig{}, fmt.Errorf("decode gateway DNS config: trailing data")
	}
	if err := config.Validate(); err != nil {
		return GatewayDNSConfig{}, err
	}
	return config, nil
}

func gatewayDNSPoolAddress(value string) (string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || prefix.String() != value {
		return "", fmt.Errorf("pool must be a canonical IPv4 prefix")
	}
	address := prefix.Addr().Next()
	if !address.IsValid() || !prefix.Contains(address) || !address.IsGlobalUnicast() {
		return "", fmt.Errorf("pool has no usable gateway address")
	}
	return address.String(), nil
}

func validateGatewayDNSAddresses(values []string, rejectLoopback bool) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.String() != value || rejectLoopback && address.IsLoopback() {
			return fmt.Errorf("%q is not a canonical unicast IPv4 address", value)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate address %s", value)
		}
		seen[value] = struct{}{}
	}
	return nil
}
