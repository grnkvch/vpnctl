package regression

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type spikeBaseline struct {
	SchemaVersion int    `json:"schema_version"`
	ManifestID    string `json:"manifest_id"`
	Status        string `json:"status"`
	Sources       []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"source_manifests"`
	DecisionRecords []string `json:"decision_records"`
	Providers       []struct {
		Capability  string `json:"capability"`
		Selected    string `json:"selected"`
		Status      string `json:"status"`
		ReleaseGate string `json:"release_gate"`
		Fallback    struct {
			Selected   string `json:"selected"`
			Status     string `json:"status"`
			Activation string `json:"activation"`
		} `json:"fallback"`
	} `json:"conditional_providers"`
	Components map[string]json.RawMessage `json:"components"`
	Limits     struct {
		PublicNetwork struct {
			HTTPSTCP          int  `json:"https_tcp"`
			RestrictedTCP     int  `json:"restricted_tcp"`
			WireGuardUDP      int  `json:"wireguard_udp"`
			HTTPSUDPOpen      bool `json:"https_udp_open"`
			RestrictedUDPOpen bool `json:"restricted_udp_open"`
		} `json:"public_network"`
		Routing struct {
			MarkMask             string `json:"mark_mask"`
			DirectMark           string `json:"direct_mark"`
			SelectedMark         string `json:"selected_mark"`
			RecoveryMark         string `json:"recovery_mark"`
			IngressResponseMark  string `json:"ingress_response_mark"`
			PreservedMarkMask    string `json:"preserved_mark_mask"`
			RecoveryRulePriority int    `json:"recovery_rule_priority"`
			IngressRulePriority  int    `json:"ingress_rule_priority"`
			SelectedRulePriority int    `json:"selected_rule_priority"`
			SelectedTable        int    `json:"selected_table"`
			GatewayTable         int    `json:"gateway_table"`
			WatchdogSeconds      int    `json:"watchdog_seconds"`
		} `json:"routing"`
		DNS struct {
			PolicyMode             string `json:"policy_mode"`
			CompatibilityMode      string `json:"compatibility_mode"`
			SelectedDirectFallback bool   `json:"selected_direct_fallback"`
			FakeIPModeSelected     bool   `json:"fake_ip_mode_selected"`
		} `json:"dns"`
		ControlRPC struct {
			Protocol                 string `json:"protocol"`
			TLSMinimum               string `json:"tls_minimum"`
			HTTP                     string `json:"http"`
			RequestBytes             int    `json:"request_bytes"`
			ResponseBytes            int    `json:"response_bytes"`
			HeaderBytes              int    `json:"header_bytes"`
			MaxJSONDepth             int    `json:"max_json_depth"`
			MaxConcurrentConnections int    `json:"max_concurrent_connections"`
		} `json:"control_rpc"`
		Backup struct {
			Format         string `json:"format"`
			KDF            string `json:"kdf"`
			MemoryKiB      int    `json:"memory_kib"`
			Time           int    `json:"time"`
			Lanes          int    `json:"lanes"`
			AEAD           string `json:"aead"`
			ChunkBytes     int    `json:"chunk_bytes"`
			WarningAgeDays int    `json:"warning_age_days"`
			Scheduled      bool   `json:"scheduled"`
			RemoteDelivery bool   `json:"remote_delivery"`
		} `json:"backup"`
	} `json:"limits"`
	ResolvedParameters   []string `json:"resolved_design_parameters"`
	UnresolvedParameters []string `json:"unresolved_design_parameters"`
	DeferredReleaseGates []struct {
		ID              string `json:"id"`
		Task            string `json:"task"`
		BlocksV2Release bool   `json:"blocks_v2_release"`
		Scope           string `json:"scope"`
	} `json:"deferred_release_gates"`
}

func readSpikeBaseline(t *testing.T) spikeBaseline {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "v2", "COMPONENT_LIMITS.v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read v2 component/limit manifest: %v", err)
	}
	var value spikeBaseline
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode v2 component/limit manifest: %v", err)
	}
	return value
}

func TestV2SpikeBaselinePinsEverySource(t *testing.T) {
	t.Parallel()
	baseline := readSpikeBaseline(t)
	if baseline.SchemaVersion != 1 || baseline.ManifestID != "vpnctl-v2-development-baseline" || baseline.Status != "development-accepted" {
		t.Fatalf("unexpected spike baseline identity: version=%d id=%q status=%q", baseline.SchemaVersion, baseline.ManifestID, baseline.Status)
	}
	if len(baseline.Sources) != 9 {
		t.Fatalf("source manifest count = %d, want 9", len(baseline.Sources))
	}
	repositoryRoot := filepath.Join("..", "..")
	seen := make(map[string]struct{}, len(baseline.Sources))
	for _, source := range baseline.Sources {
		if source.Path == "" || len(source.SHA256) != 64 {
			t.Fatalf("invalid pinned source entry: %#v", source)
		}
		if _, duplicate := seen[source.Path]; duplicate {
			t.Fatalf("duplicate pinned source: %s", source.Path)
		}
		seen[source.Path] = struct{}{}
		data, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(source.Path)))
		if err != nil {
			t.Fatalf("read pinned source %s: %v", source.Path, err)
		}
		hash := sha256.Sum256(data)
		if got := hex.EncodeToString(hash[:]); got != source.SHA256 {
			t.Errorf("pinned source %s changed: got %s, manifest has %s", source.Path, got, source.SHA256)
		}
	}
}

func TestV2SpikeBaselineClosesProviderAndParameterChoices(t *testing.T) {
	t.Parallel()
	baseline := readSpikeBaseline(t)
	if len(baseline.UnresolvedParameters) != 0 {
		t.Fatalf("blocking spike parameters remain unresolved: %v", baseline.UnresolvedParameters)
	}
	requiredParameters := stringSet(
		"conditional-provider-selection",
		"component-versions-and-hashes",
		"nftables-hooks-marks-and-rpdb",
		"split-dns-mode-and-cache-semantics",
		"ingress-provider-and-limits",
		"reverse-tunnel-provider-and-pool-normalization",
		"control-pki-enrollment-and-rpc-limits",
		"backup-kdf-aead-and-resource-limits",
		"backup-warning-age",
		"numeric-cli-exit-codes",
		"public-command-tree",
	)
	resolved := make(map[string]struct{}, len(baseline.ResolvedParameters))
	for _, parameter := range baseline.ResolvedParameters {
		resolved[parameter] = struct{}{}
	}
	for parameter := range requiredParameters {
		if _, ok := resolved[parameter]; !ok {
			t.Errorf("required spike parameter is not resolved: %s", parameter)
		}
	}

	wantProviders := map[string]string{
		"restricted-transport-and-routing": "mihomo-v1.19.30",
		"ip-only-https-ingress":            "ubuntu-nginx-1.24.0-2ubuntu7.17",
		"multiplexed-reverse-tunnel":       "frp-0.69.0",
	}
	if len(baseline.Providers) != len(wantProviders) {
		t.Fatalf("conditional provider count = %d, want %d", len(baseline.Providers), len(wantProviders))
	}
	for _, provider := range baseline.Providers {
		if wantProviders[provider.Capability] != provider.Selected {
			t.Errorf("unexpected provider selection for %s: %s", provider.Capability, provider.Selected)
		}
		if provider.Status != "development-accepted" || provider.Fallback.Selected == "" || provider.Fallback.Status != "inactive" || provider.Fallback.Activation == "" {
			t.Errorf("provider %s lacks an explicit accepted selection and inactive fallback: %#v", provider.Capability, provider)
		}
		if !strings.HasPrefix(provider.ReleaseGate, "16.") {
			t.Errorf("provider %s release gate is outside section 16: %s", provider.Capability, provider.ReleaseGate)
		}
	}
	for _, component := range []string{"mihomo", "nginx", "frp", "systemd_resolved", "nftables", "wireguard", "go_crypto"} {
		if len(baseline.Components[component]) == 0 {
			t.Errorf("consolidated baseline lacks component %s", component)
		}
	}
}

func TestV2SpikeBaselineFreezesCriticalLimits(t *testing.T) {
	t.Parallel()
	limits := readSpikeBaseline(t).Limits
	if limits.PublicNetwork.HTTPSTCP != 443 || limits.PublicNetwork.RestrictedTCP != 8443 || limits.PublicNetwork.WireGuardUDP != 51820 || limits.PublicNetwork.HTTPSUDPOpen || limits.PublicNetwork.RestrictedUDPOpen {
		t.Errorf("unexpected public network contract: %#v", limits.PublicNetwork)
	}
	if limits.Routing.MarkMask != "0xff000000" || limits.Routing.DirectMark != "0x01000000" || limits.Routing.SelectedMark != "0x02000000" || limits.Routing.RecoveryMark != "0x03000000" || limits.Routing.IngressResponseMark != "0x04000000" || limits.Routing.PreservedMarkMask != "0x00ffffff" {
		t.Errorf("unexpected routing mark allocation: %#v", limits.Routing)
	}
	if limits.Routing.RecoveryRulePriority != 10000 || limits.Routing.IngressRulePriority != 10010 || limits.Routing.SelectedRulePriority != 10020 || limits.Routing.SelectedTable != 20001 || limits.Routing.GatewayTable != 20002 || limits.Routing.WatchdogSeconds != 120 {
		t.Errorf("unexpected routing/RPDB/watchdog limits: %#v", limits.Routing)
	}
	if limits.DNS.PolicyMode != "policy-redir-host" || limits.DNS.CompatibilityMode != "direct-redir-host" || limits.DNS.SelectedDirectFallback || limits.DNS.FakeIPModeSelected {
		t.Errorf("unexpected DNS mode contract: %#v", limits.DNS)
	}
	if limits.ControlRPC.Protocol != "1.0" || limits.ControlRPC.TLSMinimum != "1.3" || limits.ControlRPC.HTTP != "1.1" || limits.ControlRPC.RequestBytes != 65536 || limits.ControlRPC.ResponseBytes != 262144 || limits.ControlRPC.HeaderBytes != 8192 || limits.ControlRPC.MaxJSONDepth != 32 || limits.ControlRPC.MaxConcurrentConnections != 16 {
		t.Errorf("unexpected control RPC contract: %#v", limits.ControlRPC)
	}
	if limits.Backup.Format != "vpnctl-backup-v1" || limits.Backup.KDF != "argon2id-v19" || limits.Backup.MemoryKiB != 65536 || limits.Backup.Time != 3 || limits.Backup.Lanes != 4 || limits.Backup.AEAD != "xchacha20-poly1305" || limits.Backup.ChunkBytes != 1048576 {
		t.Errorf("unexpected backup cryptographic contract: %#v", limits.Backup)
	}
	if limits.Backup.WarningAgeDays != 30 || limits.Backup.Scheduled || limits.Backup.RemoteDelivery {
		t.Errorf("unexpected backup operational defaults: %#v", limits.Backup)
	}
}

func TestV2SpikeBaselineAssignsDeferredGatesToSection16(t *testing.T) {
	t.Parallel()
	baseline := readSpikeBaseline(t)
	want := map[string]string{
		"minimum-gateway-target-capacity": "16.9",
		"deployed-clash-mi":               "16.11",
		"deployed-telegram-webhook":       "16.11",
	}
	if len(baseline.DeferredReleaseGates) != len(want) {
		t.Fatalf("deferred release gate count = %d, want %d", len(baseline.DeferredReleaseGates), len(want))
	}
	for _, gate := range baseline.DeferredReleaseGates {
		if want[gate.ID] != gate.Task || !strings.HasPrefix(gate.Task, "16.") || !gate.BlocksV2Release || gate.Scope == "" {
			t.Errorf("invalid deferred release gate: %#v", gate)
		}
	}
	tasks, err := os.ReadFile(filepath.Join("..", "..", "openspec", "changes", "vpnctl-v2", "tasks.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range []string{"16.9", "16.11"} {
		if !strings.Contains(string(tasks), "- [ ] "+task+" ") {
			t.Errorf("deferred release task %s is not present and pending", task)
		}
	}
}

func TestV2SpikeBaselineDecisionRecordsAreAccepted(t *testing.T) {
	t.Parallel()
	baseline := readSpikeBaseline(t)
	if len(baseline.DecisionRecords) != 3 {
		t.Fatalf("decision record count = %d, want 3", len(baseline.DecisionRecords))
	}
	for _, path := range baseline.DecisionRecords {
		data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("read decision record %s: %v", path, err)
		}
		if !strings.Contains(string(data), "Status: Accepted") {
			t.Errorf("decision record is not accepted: %s", path)
		}
	}
	design, err := os.ReadFile(filepath.Join("..", "..", "openspec", "changes", "vpnctl-v2", "design.md"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(design), "## Open Questions") {
		t.Fatal("v2 design still exposes an open-questions section after spike consolidation")
	}
}
