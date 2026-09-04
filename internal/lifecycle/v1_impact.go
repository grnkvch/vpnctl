package lifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	v1state "github.com/vgrinkevich/vpnctl/internal/state"
	"github.com/vgrinkevich/vpnctl/internal/transport"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const V1MigrationImpactSchemaVersion = 1

type V1MigrationImpactDisposition string

const (
	V1ImpactTransformed V1MigrationImpactDisposition = "transformed"
	V1ImpactDropped     V1MigrationImpactDisposition = "dropped"
	V1ImpactBlocker     V1MigrationImpactDisposition = "blocker"
)

type V1MigrationImpact struct {
	Code        string                       `json:"code"`
	Disposition V1MigrationImpactDisposition `json:"disposition"`
	Scope       string                       `json:"scope"`
	SourceID    string                       `json:"source_id,omitempty"`
	SourceField string                       `json:"source_field"`
	TargetField string                       `json:"target_field,omitempty"`
	Summary     string                       `json:"summary"`
}

type V1ClientReExport struct {
	SourceClientID string   `json:"source_client_id"`
	TargetClientID string   `json:"target_client_id"`
	Formats        []string `json:"formats"`
	Reasons        []string `json:"reasons"`
	Commands       []string `json:"commands"`
}

type V1MigrationImpactReport struct {
	SchemaVersion     int                 `json:"schema_version"`
	Status            string              `json:"status"`
	ReadyForMigration bool                `json:"ready_for_migration"`
	InspectionStatus  V1InspectionStatus  `json:"inspection_status"`
	Gateway           V1IdentityMapping   `json:"gateway"`
	Clients           []V1IdentityMapping `json:"clients"`
	Impacts           []V1MigrationImpact `json:"impacts"`
	RequiredReExports []V1ClientReExport  `json:"required_re_exports"`
}

func (report V1MigrationImpactReport) String() string {
	data, err := json.Marshal(report)
	if err != nil {
		return "<v1-migration-impact>"
	}
	return string(data)
}

func (report V1MigrationImpactReport) GoString() string { return report.String() }
func (report V1MigrationImpactReport) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, report.String())
}

// InspectV1MigrationImpact is a pure pre-mutation view over an inspected v1
// installation. StageRoot is intentionally ignored: analysis never creates it.
func InspectV1MigrationImpact(input V1ConversionInput) (V1MigrationImpactReport, error) {
	inspection := input.Inspection
	if inspection == nil || inspection.destroyed {
		return V1MigrationImpactReport{}, fmt.Errorf("v1 migration impact requires an undestroyed inspection")
	}
	report := V1MigrationImpactReport{
		SchemaVersion: V1MigrationImpactSchemaVersion, InspectionStatus: inspection.Report.Status,
		Clients: []V1IdentityMapping{}, Impacts: []V1MigrationImpact{}, RequiredReExports: []V1ClientReExport{},
	}
	if inspection.Report.Status != V1InspectionReady && inspection.Report.Status != V1InspectionPartial {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "inspection_not_convertible", Disposition: V1ImpactBlocker, Scope: "inspection",
			SourceField: ".vpnctl", Summary: "the v1 inspection must be ready or partial before conversion",
		})
	}
	for _, issue := range inspection.Report.Issues {
		if issue.Severity != V1IssueError {
			continue
		}
		sourceField := issue.Path
		if sourceField == "" {
			sourceField = ".vpnctl"
		}
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "inspection_" + issue.Code, Disposition: V1ImpactBlocker, Scope: issue.Scope,
			SourceField: sourceField, Summary: issue.Message,
		})
	}
	server := inspection.state.Server
	if server == nil {
		if !hasV1ImpactCode(report.Impacts, "inspection_not_convertible") {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "server_unavailable", Disposition: V1ImpactBlocker, Scope: "server",
				SourceField: "server", Summary: "a configured v1 server is required",
			})
		}
		finishV1MigrationImpact(&report, nil)
		return report, nil
	}

	gateway, clientMappings := mapV1Identities(server.ID, inspection.state.Clients)
	report.Gateway = gateway
	if !gateway.IDPreserved {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "gateway_id_mapped", Disposition: V1ImpactTransformed, Scope: "server", SourceID: server.ID,
			SourceField: "server.id", TargetField: "host.id", Summary: "the v1 gateway identifier becomes a deterministic v2 UUID",
		})
	}
	if server.Name != "" {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "gateway_name_dropped", Disposition: V1ImpactDropped, Scope: "server", SourceID: server.ID,
			SourceField: "server.name", Summary: "v2 gateway host state has no mutable display-name field",
		})
	}
	endpointChanged := server.PublicEndpoint != input.PublicIPv4
	endpointCode := "public_endpoint_normalized"
	endpointSummary := "the v1 general endpoint field becomes the explicit v2 public IPv4 field"
	if endpointChanged {
		endpointCode = "public_endpoint_changed"
		endpointSummary = "the explicit v2 public IPv4 differs from the v1 client endpoint"
	}
	report.Impacts = append(report.Impacts, V1MigrationImpact{
		Code: endpointCode, Disposition: V1ImpactTransformed, Scope: "server", SourceID: server.ID,
		SourceField: "server.public_endpoint", TargetField: "host.public_ipv4", Summary: endpointSummary,
	})
	if server.WireGuardInterface != transport.StandardInterfaceName {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "wireguard_interface_changed", Disposition: V1ImpactTransformed, Scope: "server", SourceID: server.ID,
			SourceField: "server.wireguard_interface", TargetField: "transport.standard.interface",
			Summary: "the v1 interface is replaced by the fixed vpnctl v2 standard interface",
		})
	}
	if prefix, err := netip.ParsePrefix(server.WireGuardSubnet); err == nil && prefix.Addr().Is4() && prefix.Masked().String() != server.WireGuardSubnet {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "client_subnet_normalized", Disposition: V1ImpactTransformed, Scope: "server", SourceID: server.ID,
			SourceField: "server.wireguard_subnet", TargetField: "host.client_cidr",
			Summary: "the v1 client subnet is normalized to its canonical network prefix while retaining client addresses",
		})
	}
	if len(server.DNSServers) == 0 {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "gateway_dns_defaulted", Disposition: V1ImpactTransformed, Scope: "server", SourceID: server.ID,
			SourceField: "server.dns_servers", TargetField: "dns.ipv4",
			Summary: "the empty v1 gateway DNS list becomes the documented v2 gateway defaults",
		})
	} else if !v1DNSListConvertible(server.DNSServers) {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "gateway_dns_not_convertible", Disposition: V1ImpactBlocker, Scope: "server", SourceID: server.ID,
			SourceField: "server.dns_servers", TargetField: "dns.ipv4",
			Summary: "v2 gateway DNS requires one to eight unique canonical non-loopback IPv4 addresses",
		})
	}
	portChanged := server.WireGuardPort != transport.StandardUDPPort
	if portChanged {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "wireguard_port_changed", Disposition: V1ImpactTransformed, Scope: "server", SourceID: server.ID,
			SourceField: "server.wireguard_port", TargetField: "transport.standard.port",
			Summary: "the v1 listener port is replaced by fixed UDP/51820",
		})
	}
	if inspection.Report.WireGuardConfig.Present {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "wireguard_config_replaced", Disposition: V1ImpactTransformed, Scope: "system",
			SourceField: inspection.Report.WireGuardConfig.Path, TargetField: "/etc/vpnctl/transport/vpnctl-wg.conf",
			Summary: "the applied v1 WireGuard file is rendered again from validated v2 state",
		})
	}
	if inspection.Report.ForwardingConfig.Present {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "forwarding_config_replaced", Disposition: V1ImpactTransformed, Scope: "system",
			SourceField: inspection.Report.ForwardingConfig.Path, TargetField: "vpnctl-owned network activation",
			Summary: "the standalone v1 forwarding sysctl file is replaced by the v2 owned network transaction",
		})
	}

	reexports := make(map[string]*v1ReExportAccumulator)
	clients := append([]v1state.ClientState(nil), inspection.state.Clients...)
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	clientNames := make(map[string]string, len(clients))
	for _, client := range clients {
		mapping := clientMappings[client.ID]
		report.Clients = append(report.Clients, mapping)
		if !mapping.IDPreserved {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "client_id_mapped", Disposition: V1ImpactTransformed, Scope: "client", SourceID: client.ID,
				SourceField: "clients." + client.ID + ".id", TargetField: "clients." + mapping.TargetID + ".id",
				Summary: "the v1 client identifier becomes a deterministic v2 UUID",
			})
		}
		if len(client.Tags) != 0 {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "client_tags_dropped", Disposition: V1ImpactDropped, Scope: "client", SourceID: client.ID,
				SourceField: "clients." + client.ID + ".tags", Summary: fmt.Sprintf("v2 has no client-tag field; %d tag values are not copied", len(client.Tags)),
			})
		}
		if client.RevocationReason != "" {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "client_revocation_reason_dropped", Disposition: V1ImpactDropped, Scope: "client", SourceID: client.ID,
				SourceField: "clients." + client.ID + ".revocation_reason", Summary: "v2 retains revocation state and time but not the free-form v1 reason",
			})
		}
		if client.Status == v1state.ClientStatusDeleted && client.RevokedAt == nil {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "deleted_client_revoked_at_synthesized", Disposition: V1ImpactTransformed, Scope: "client", SourceID: client.ID,
				SourceField: "clients." + client.ID + ".revoked_at", TargetField: "clients." + mapping.TargetID + ".revoked_at",
				Summary: "the migration timestamp becomes the deleted tombstone revocation time",
			})
		}
		if client.Status != v1state.ClientStatusDeleted && len(inspection.privateKeys["client:"+client.ID]) == 0 {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "client_private_key_unavailable", Disposition: V1ImpactBlocker, Scope: "client", SourceID: client.ID,
				SourceField: ".vpnctl/secrets/clients/" + client.ID + ".key", Summary: "an active or revoked client private key cannot be omitted",
			})
		}
		if !v2NamePattern.MatchString(client.Name) {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "client_name_not_convertible", Disposition: V1ImpactBlocker, Scope: "client", SourceID: client.ID,
				SourceField: "clients." + client.ID + ".name", Summary: "the v1 client name does not satisfy the v2 stable-name syntax",
			})
		}
		if client.Status != v1state.ClientStatusDeleted {
			key := strings.ToLower(client.Name)
			if previous, duplicate := clientNames[key]; duplicate {
				report.Impacts = append(report.Impacts, V1MigrationImpact{
					Code: "client_name_conflict", Disposition: V1ImpactBlocker, Scope: "client", SourceID: client.ID,
					SourceField: "clients." + client.ID + ".name", Summary: "the v1 client name conflicts case-insensitively with client " + previous,
				})
			} else {
				clientNames[key] = client.ID
			}
		}
		if strings.TrimSpace(client.Platform) == "" || len(client.Platform) > 63 {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "client_platform_not_convertible", Disposition: V1ImpactBlocker, Scope: "client", SourceID: client.ID,
				SourceField: "clients." + client.ID + ".platform", Summary: "the v1 client platform is empty or exceeds the v2 bound",
			})
		}
		if client.Status == v1state.ClientStatusActive && endpointChanged {
			addV1ReExport(reexports, mapping, "clash", "public_endpoint_changed")
			addV1ReExport(reexports, mapping, "wireguard", "public_endpoint_changed")
		}
		if client.Status == v1state.ClientStatusActive && portChanged {
			addV1ReExport(reexports, mapping, "clash", "wireguard_port_changed")
			addV1ReExport(reexports, mapping, "wireguard", "wireguard_port_changed")
		}
	}
	if len(inspection.privateKeys["server"]) == 0 {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "gateway_private_key_unavailable", Disposition: V1ImpactBlocker, Scope: "server", SourceID: server.ID,
			SourceField: ".vpnctl/secrets/server_private.key", Summary: "the gateway WireGuard private key cannot be omitted",
		})
	}

	rulesetNames := make(map[string]string, len(inspection.rulesets))
	for _, id := range sortedStringKeys(inspection.rulesets) {
		ruleset := inspection.rulesets[id]
		key := strings.ToLower(id)
		if previous, duplicate := rulesetNames[key]; duplicate {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "ruleset_name_conflict", Disposition: V1ImpactBlocker, Scope: "ruleset", SourceID: id,
				SourceField: ".vpnctl/rulesets/" + id + ".json", Summary: "v1 ruleset IDs " + previous + " and " + id + " collide in case-insensitive v2 names",
			})
		} else {
			rulesetNames[key] = id
		}
		if _, err := renderV1PresetSource(ruleset); err != nil {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "ruleset_not_convertible", Disposition: V1ImpactBlocker, Scope: "ruleset", SourceID: id,
				SourceField: ".vpnctl/rulesets/" + id + ".json", Summary: "the valid v1 ruleset cannot be represented by the bounded v2 preset schema",
			})
		}
		if ruleset.Name != ruleset.ID {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "ruleset_display_name_dropped", Disposition: V1ImpactDropped, Scope: "ruleset", SourceID: id,
				SourceField: "rulesets." + id + ".name", TargetField: "presets." + id + ".name",
				Summary: "the v1 display name is dropped; the stable ruleset ID becomes the v2 preset name",
			})
		}
	}

	generatedMetadata := make(map[string]V1GeneratedArtifact, len(inspection.Report.Generated))
	for _, artifact := range inspection.Report.Generated {
		generatedMetadata[strings.TrimPrefix(artifact.Path, ".vpnctl/")] = artifact
	}
	clientByID := make(map[string]v1state.ClientState, len(clients))
	for _, client := range clients {
		clientByID[client.ID] = client
	}
	for _, relative := range sortedStringKeys(inspection.generated) {
		artifact := generatedMetadata[relative]
		target := filepath.ToSlash(filepath.Join("/var/lib/vpnctl/exports/v1-preserved", filepath.FromSlash(relative)))
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "generated_artifact_relocated", Disposition: V1ImpactTransformed, Scope: "generated", SourceID: artifact.ClientID,
			SourceField: ".vpnctl/" + relative, TargetField: target,
			Summary: "legacy bytes are retained separately and are not claimed as a current generation-tracked v2 export",
		})
		client, found := clientByID[artifact.ClientID]
		mapping, mapped := clientMappings[artifact.ClientID]
		if !found || !mapped || client.Status != v1state.ClientStatusActive {
			continue
		}
		switch {
		case strings.HasSuffix(relative, "/"+client.ID+".conf"):
			if !v1WireGuardProfileMatches(inspection, client, inspection.generated[relative]) {
				addV1ReExport(reexports, mapping, "wireguard", "legacy_profile_unverified")
			}
		case strings.HasSuffix(relative, "/"+client.ID+".clash.yaml"):
			matches := matchingV1ClientPresets(inspection, client)
			if len(matches) == 0 {
				addV1ReExport(reexports, mapping, "clash", "legacy_profile_unverified")
			}
			if len(matches) != 1 {
				addV1ReExport(reexports, mapping, "clash", "preset_assignment_unresolved")
				report.Impacts = append(report.Impacts, V1MigrationImpact{
					Code: "client_preset_assignment_unresolved", Disposition: V1ImpactDropped, Scope: "client", SourceID: client.ID,
					SourceField: ".vpnctl/" + relative, TargetField: "clients." + mapping.TargetID + ".assigned_presets",
					Summary: "the legacy Clash profile does not identify exactly one v1 ruleset, so no policy assignment is guessed",
				})
			}
		}
	}

	appendV1UFWRuleImpacts(&report, inspection, input.SSHPort)
	if inspection.Report.Status == V1InspectionReady || inspection.Report.Status == V1InspectionPartial {
		probe := input
		probe.StageRoot = ""
		if _, err := buildV1ConversionPlan(probe); err != nil {
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "conversion_preflight_failed", Disposition: V1ImpactBlocker, Scope: "conversion",
				SourceField: ".vpnctl/state.json", Summary: safeV1ConversionImpactError(err),
			})
		}
	}
	finishV1MigrationImpact(&report, reexports)
	return report, nil
}

type v1ReExportAccumulator struct {
	mapping V1IdentityMapping
	formats map[string]struct{}
	reasons map[string]struct{}
}

func addV1ReExport(values map[string]*v1ReExportAccumulator, mapping V1IdentityMapping, format, reason string) {
	entry := values[mapping.SourceID]
	if entry == nil {
		entry = &v1ReExportAccumulator{mapping: mapping, formats: map[string]struct{}{}, reasons: map[string]struct{}{}}
		values[mapping.SourceID] = entry
	}
	entry.formats[format] = struct{}{}
	entry.reasons[reason] = struct{}{}
}

func appendV1UFWRuleImpacts(report *V1MigrationImpactReport, inspection *V1Inspection, sshPort int) {
	if inspection.Report.UFW.Enabled != nil && *inspection.Report.UFW.Enabled {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "ufw_backend_replaced", Disposition: V1ImpactTransformed, Scope: "ufw",
			SourceField: "/etc/ufw/ufw.conf", TargetField: "nftables inet/vpnctl",
			Summary: "enabled v1 UFW ownership is replaced by the v2 vpnctl nftables table",
		})
	} else if inspection.Report.UFW.ConfigPresent && inspection.Report.UFW.Enabled == nil {
		report.Impacts = append(report.Impacts, V1MigrationImpact{
			Code: "ufw_enabled_state_unknown", Disposition: V1ImpactBlocker, Scope: "ufw",
			SourceField: "/etc/ufw/ufw.conf", Summary: "UFW enabled state must be resolved before firewall ownership changes",
		})
	}
	for index, rule := range inspection.Report.UFW.Rules {
		field := fmt.Sprintf("ufw.rules[%d].%s.%s.%d", index, rule.Family, rule.Protocol, rule.Port)
		switch rule.Classification {
		case "wireguard":
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "ufw_wireguard_rule_replaced", Disposition: V1ImpactTransformed, Scope: "ufw",
				SourceField: field, TargetField: "nftables inet/vpnctl standard UDP/51820",
				Summary: "the known v1 WireGuard allow rule is replaced by v2 firewall ownership",
			})
		case "ssh_candidate":
			if rule.Port == sshPort {
				report.Impacts = append(report.Impacts, V1MigrationImpact{
					Code: "ufw_ssh_rule_replaced", Disposition: V1ImpactTransformed, Scope: "ufw",
					SourceField: field, TargetField: "nftables inet/vpnctl SSH allow",
					Summary: "the TCP allow matching the explicit SSH port is replaced by v2 firewall ownership",
				})
			} else {
				report.Impacts = append(report.Impacts, V1MigrationImpact{
					Code: "ufw_tcp_rule_ownership_unresolved", Disposition: V1ImpactBlocker, Scope: "ufw",
					SourceField: field, Summary: "a v1 TCP allow does not match the explicit SSH port and cannot be removed as vpnctl-owned",
				})
			}
		default:
			report.Impacts = append(report.Impacts, V1MigrationImpact{
				Code: "ufw_foreign_rule_conflict", Disposition: V1ImpactBlocker, Scope: "ufw",
				SourceField: field, Summary: "an unrecognized UFW rule requires operator ownership review before migration",
			})
		}
	}
}

func finishV1MigrationImpact(report *V1MigrationImpactReport, reexports map[string]*v1ReExportAccumulator) {
	if reexports != nil {
		for _, id := range sortedStringKeys(reexports) {
			entry := reexports[id]
			formats := sortedSet(entry.formats)
			commands := make([]string, 0, len(formats))
			for _, format := range formats {
				commands = append(commands, "sudo vpnctl client export "+entry.mapping.TargetID+" "+format)
			}
			report.RequiredReExports = append(report.RequiredReExports, V1ClientReExport{
				SourceClientID: entry.mapping.SourceID, TargetClientID: entry.mapping.TargetID,
				Formats: formats, Reasons: sortedSet(entry.reasons), Commands: commands,
			})
		}
	}
	sort.Slice(report.Clients, func(i, j int) bool { return report.Clients[i].SourceID < report.Clients[j].SourceID })
	sort.Slice(report.Impacts, func(i, j int) bool {
		left, right := report.Impacts[i], report.Impacts[j]
		if left.Scope != right.Scope {
			return left.Scope < right.Scope
		}
		if left.SourceID != right.SourceID {
			return left.SourceID < right.SourceID
		}
		if left.SourceField != right.SourceField {
			return left.SourceField < right.SourceField
		}
		return left.Code < right.Code
	})
	report.ReadyForMigration = !hasV1ImpactBlocker(report.Impacts)
	switch {
	case !report.ReadyForMigration:
		report.Status = "blocked"
	case len(report.RequiredReExports) != 0:
		report.Status = "requires-action"
	default:
		report.Status = "compatible"
	}
}

func v1WireGuardProfileMatches(inspection *V1Inspection, client v1state.ClientState, profile []byte) bool {
	if inspection.state.Server == nil {
		return false
	}
	privateKey := inspection.privateKeys["client:"+client.ID]
	if len(privateKey) == 0 {
		return false
	}
	address, err := wireguard.ClientAddress(client.AssignedIP, inspection.state.Server.WireGuardSubnet)
	if err != nil {
		return false
	}
	rendered, err := wireguard.RenderClientConfig(wireguard.ClientConfig{
		PrivateKey: string(privateKey), Address: address, DNSServers: append([]string(nil), inspection.state.Server.DNSServers...),
		ServerPublicKey: inspection.state.Server.WireGuardPublicKey,
		Endpoint:        wireguard.Endpoint(inspection.state.Server.PublicEndpoint, inspection.state.Server.WireGuardPort),
	})
	return err == nil && bytes.Equal(profile, []byte(rendered))
}

func hasV1ImpactBlocker(impacts []V1MigrationImpact) bool {
	for _, impact := range impacts {
		if impact.Disposition == V1ImpactBlocker {
			return true
		}
	}
	return false
}

func hasV1ImpactCode(impacts []V1MigrationImpact, code string) bool {
	for _, impact := range impacts {
		if impact.Code == code {
			return true
		}
	}
	return false
}

func safeV1ConversionImpactError(err error) string {
	if errors.Is(err, ErrV1ConversionNotReady) {
		return "the inspected v1 values do not satisfy the validated v2 conversion model"
	}
	return "the explicit target values do not satisfy the validated v2 conversion model"
}

func v1DNSListConvertible(values []string) bool {
	if len(values) == 0 || len(values) > 8 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || address.String() != value || !address.IsGlobalUnicast() || address.IsLoopback() {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

var v2NamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
