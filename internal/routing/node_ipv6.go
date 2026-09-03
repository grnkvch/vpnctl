package routing

import (
	"context"
	"encoding/json"
	"fmt"

	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

const (
	NodeRoutingIPv6DiagnosticsSchemaVersion = 1
	NodeRoutingIPv6ModeSelectedBlockOnly    = "selected-block-only"
	NodeRoutingIPv6UnmatchedPreserveSystem  = "preserve-system"

	maximumNodeRoutingNFTablesJSONBytes = 1 << 20
)

// NodeRoutingIPv6Diagnostics describes the intentionally limited v2 IPv6
// boundary. It is passive runtime evidence, not a claim that the active
// transport carries IPv6.
type NodeRoutingIPv6Diagnostics struct {
	SchemaVersion           int    `json:"schema_version"`
	Mode                    string `json:"mode"`
	FullDataPlane           bool   `json:"full_data_plane"`
	UnmatchedBehavior       string `json:"unmatched_behavior"`
	SelectedDropPackets     uint64 `json:"selected_drop_packets"`
	SelectedDropBytes       uint64 `json:"selected_drop_bytes"`
	ResolvedSelectedEntries int    `json:"resolved_selected_entries"`
}

func (diagnostics NodeRoutingIPv6Diagnostics) Validate() error {
	if diagnostics.SchemaVersion != NodeRoutingIPv6DiagnosticsSchemaVersion ||
		diagnostics.Mode != NodeRoutingIPv6ModeSelectedBlockOnly || diagnostics.FullDataPlane ||
		diagnostics.UnmatchedBehavior != NodeRoutingIPv6UnmatchedPreserveSystem || diagnostics.ResolvedSelectedEntries < 0 {
		return fmt.Errorf("invalid node routing IPv6 diagnostics")
	}
	return nil
}

// IPv6Diagnostics reads only the owned nftables counter and selected-address
// set. It performs no traffic probe, DNS lookup, policy update, or repair.
func (manager *NodeRoutingGuardManager) IPv6Diagnostics(ctx context.Context) (NodeRoutingIPv6Diagnostics, error) {
	if ctx == nil {
		return NodeRoutingIPv6Diagnostics{}, fmt.Errorf("context is required")
	}
	if manager == nil || manager.runner == nil {
		return NodeRoutingIPv6Diagnostics{}, fmt.Errorf("node routing guard manager is incomplete")
	}
	if err := manager.assertOwnedTable(ctx); err != nil {
		return NodeRoutingIPv6Diagnostics{}, err
	}
	counter, err := manager.readIPv6NFTablesObject(ctx, "counter", NodeRoutingSelectedIPv6Counter)
	if err != nil {
		return NodeRoutingIPv6Diagnostics{}, err
	}
	set, err := manager.readIPv6NFTablesObject(ctx, "set", NodeRoutingSelectedIPv6Set)
	if err != nil {
		return NodeRoutingIPv6Diagnostics{}, err
	}
	diagnostics, err := parseNodeRoutingIPv6Diagnostics(counter, set)
	if err != nil {
		return NodeRoutingIPv6Diagnostics{}, err
	}
	return diagnostics, diagnostics.Validate()
}

func (manager *NodeRoutingGuardManager) readIPv6NFTablesObject(ctx context.Context, kind, name string) ([]byte, error) {
	result, err := manager.runner.Run(ctx, linuxplatform.ProbeCommand{Name: "nft", Args: []string{
		"--json", "list", kind, linuxplatform.VPNCTLNFTablesFamily, linuxplatform.VPNCTLNFTablesTable, name,
	}})
	if err != nil {
		return nil, fmt.Errorf("inspect node routing IPv6 %s: %w", kind, err)
	}
	if result.ExitCode != 0 {
		return nil, commandResultError("inspect node routing IPv6 "+kind, result)
	}
	if len(result.Stdout) == 0 || len(result.Stdout) > maximumNodeRoutingNFTablesJSONBytes {
		return nil, fmt.Errorf("node routing IPv6 %s output has invalid size", kind)
	}
	return append([]byte(nil), result.Stdout...), nil
}

type nodeRoutingNFTablesDocument struct {
	NFTables []struct {
		Counter *struct {
			Family  string `json:"family"`
			Table   string `json:"table"`
			Name    string `json:"name"`
			Packets uint64 `json:"packets"`
			Bytes   uint64 `json:"bytes"`
		} `json:"counter,omitempty"`
		Set *struct {
			Family   string            `json:"family"`
			Table    string            `json:"table"`
			Name     string            `json:"name"`
			Type     string            `json:"type"`
			Elements []json.RawMessage `json:"elem"`
		} `json:"set,omitempty"`
	} `json:"nftables"`
}

func parseNodeRoutingIPv6Diagnostics(counterContent, setContent []byte) (NodeRoutingIPv6Diagnostics, error) {
	var counterDocument, setDocument nodeRoutingNFTablesDocument
	if err := json.Unmarshal(counterContent, &counterDocument); err != nil {
		return NodeRoutingIPv6Diagnostics{}, fmt.Errorf("decode node routing IPv6 counter: %w", err)
	}
	if err := json.Unmarshal(setContent, &setDocument); err != nil {
		return NodeRoutingIPv6Diagnostics{}, fmt.Errorf("decode node routing IPv6 set: %w", err)
	}
	var packets, bytes uint64
	counters := 0
	for _, object := range counterDocument.NFTables {
		if object.Counter == nil {
			continue
		}
		counter := object.Counter
		if counter.Family != linuxplatform.VPNCTLNFTablesFamily || counter.Table != linuxplatform.VPNCTLNFTablesTable || counter.Name != NodeRoutingSelectedIPv6Counter {
			return NodeRoutingIPv6Diagnostics{}, fmt.Errorf("node routing IPv6 counter identity differs from the owned contract")
		}
		counters++
		packets, bytes = counter.Packets, counter.Bytes
	}
	if counters != 1 {
		return NodeRoutingIPv6Diagnostics{}, fmt.Errorf("node routing IPv6 diagnostics require exactly one selected-drop counter")
	}
	selectedEntries := -1
	sets := 0
	for _, object := range setDocument.NFTables {
		if object.Set == nil {
			continue
		}
		set := object.Set
		if set.Family != linuxplatform.VPNCTLNFTablesFamily || set.Table != linuxplatform.VPNCTLNFTablesTable || set.Name != NodeRoutingSelectedIPv6Set || set.Type != "ipv6_addr" {
			return NodeRoutingIPv6Diagnostics{}, fmt.Errorf("node routing selected IPv6 set differs from the owned contract")
		}
		sets++
		selectedEntries = len(set.Elements)
	}
	if sets != 1 {
		return NodeRoutingIPv6Diagnostics{}, fmt.Errorf("node routing IPv6 diagnostics require exactly one selected-address set")
	}
	return NodeRoutingIPv6Diagnostics{
		SchemaVersion: NodeRoutingIPv6DiagnosticsSchemaVersion, Mode: NodeRoutingIPv6ModeSelectedBlockOnly,
		FullDataPlane: false, UnmatchedBehavior: NodeRoutingIPv6UnmatchedPreserveSystem,
		SelectedDropPackets: packets, SelectedDropBytes: bytes, ResolvedSelectedEntries: selectedEntries,
	}, nil
}
