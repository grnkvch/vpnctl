package routing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const (
	NodeDNSIntegrationSchemaVersion = 1
	NodeDNSIntegrationConfigName    = "routing-dns.json"
	NodeDNSResolvedDropinName       = "50-vpnctl-node.conf"
	NodeDNSResolvedSnapshotName     = "resolved-original.json"
	NodeDNSNFTablesFamily           = "inet"
	NodeDNSNFTablesTable            = "vpnctl_dns"
	NodeDNSNFTablesOwnerComment     = "vpnctl:v2:node-dns-integration"
	NodeDNSUnderlayHoldDomain       = "~vpnctl-underlay.invalid"
	NodeDNSCapturePriority          = -151

	maximumNodeDNSConfigBytes   = 64 << 10
	maximumNodeDNSSnapshotBytes = 64 << 10
)

var nodeDNSResolvedDropin = []byte(`[Resolve]
DNS=127.0.0.1:1053
FallbackDNS=
Domains=~.
Cache=no
`)

// NodeDNSIntegrationConfig has no raw command or nftables input. LinkName is
// the ordinary underlay whose competing route domain is held aside while the
// local routing resolver owns the global ~. route.
type NodeDNSIntegrationConfig struct {
	SchemaVersion int    `json:"schema_version"`
	LinkName      string `json:"link_name"`
}

func (config NodeDNSIntegrationConfig) Validate() error {
	if config.SchemaVersion != NodeDNSIntegrationSchemaVersion || !nodeRoutingInterfacePattern.MatchString(config.LinkName) ||
		config.LinkName == "lo" || config.LinkName == NodeRoutingTUNDevice || config.LinkName == NodeRoutingStandardInterface {
		return fmt.Errorf("invalid node DNS integration config")
	}
	return nil
}

type NodeDNSIntegrationCandidate struct {
	config   NodeDNSIntegrationConfig
	content  []byte
	dropin   []byte
	nftables []byte
}

func RenderNodeDNSIntegrationConfig(linkName string) (NodeDNSIntegrationCandidate, error) {
	config := NodeDNSIntegrationConfig{SchemaVersion: NodeDNSIntegrationSchemaVersion, LinkName: linkName}
	if err := config.Validate(); err != nil {
		return NodeDNSIntegrationCandidate{}, err
	}
	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return NodeDNSIntegrationCandidate{}, fmt.Errorf("encode node DNS integration config: %w", err)
	}
	content = append(content, '\n')
	return NodeDNSIntegrationCandidate{
		config: config, content: content, dropin: append([]byte(nil), nodeDNSResolvedDropin...),
		nftables: renderNodeDNSCaptureNFTables(),
	}, nil
}

func (candidate NodeDNSIntegrationCandidate) Config() NodeDNSIntegrationConfig {
	return candidate.config
}
func (candidate NodeDNSIntegrationCandidate) Bytes() []byte {
	return append([]byte(nil), candidate.content...)
}
func (candidate NodeDNSIntegrationCandidate) ResolvedDropin() []byte {
	return append([]byte(nil), candidate.dropin...)
}
func (candidate NodeDNSIntegrationCandidate) NFTablesDefinition() []byte {
	return append([]byte(nil), candidate.nftables...)
}

func decodeNodeDNSIntegrationConfig(content []byte) (NodeDNSIntegrationConfig, error) {
	if len(content) == 0 || len(content) > maximumNodeDNSConfigBytes {
		return NodeDNSIntegrationConfig{}, fmt.Errorf("node DNS integration config has invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var config NodeDNSIntegrationConfig
	if err := decoder.Decode(&config); err != nil {
		return NodeDNSIntegrationConfig{}, fmt.Errorf("decode node DNS integration config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return NodeDNSIntegrationConfig{}, fmt.Errorf("decode node DNS integration config: trailing data")
	}
	if err := config.Validate(); err != nil {
		return NodeDNSIntegrationConfig{}, err
	}
	return config, nil
}

func renderNodeDNSCaptureNFTables() []byte {
	mask := nftMark(linuxplatform.VPNCTLMarkMask)
	direct := nftMark(linuxplatform.VPNCTLDirectMark)
	recovery := nftMark(linuxplatform.VPNCTLRecoveryMark)
	return []byte(fmt.Sprintf(`table %s %s {
  comment %s

  counter provider_mark_bypass {}
  counter resolved_stub_passthrough {}
  counter classic_udp_captured {}
  counter classic_tcp_captured {}

  chain output_redirect {
    type nat hook output priority %d; policy accept;

    meta mark & %s == %s counter name provider_mark_bypass return
    meta mark & %s == %s counter name provider_mark_bypass return
    ip daddr 127.0.0.0/8 udp dport 53 counter name resolved_stub_passthrough return
    ip daddr 127.0.0.0/8 tcp dport 53 counter name resolved_stub_passthrough return
    udp dport 53 counter name classic_udp_captured redirect to :1053
    tcp dport 53 counter name classic_tcp_captured redirect to :1053
  }
}
`, NodeDNSNFTablesFamily, NodeDNSNFTablesTable, strconv.Quote(NodeDNSNFTablesOwnerComment), NodeDNSCapturePriority,
		mask, direct, mask, recovery))
}
