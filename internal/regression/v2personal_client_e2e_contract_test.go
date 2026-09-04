package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2PersonalClientE2EContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "personal")
	var manifest struct {
		Status           string `json:"status"`
		Scope            string `json:"scope"`
		ActualClashMi    string `json:"actual_ios_clash_mi"`
		Delivery         string `json:"delivery"`
		Mihomo           struct {
			Version       string `json:"version"`
			ArchiveSHA256 string `json:"archive_sha256"`
		} `json:"mihomo"`
		Profiles struct {
			ClashSHA256     string `json:"clash_sha256"`
			WireGuardSHA256 string `json:"wireguard_sha256"`
		} `json:"profiles"`
		Selective struct {
			Selected string `json:"selected_destination_source"`
			Direct   string `json:"unmatched_destination_source"`
			Choice   string `json:"default_manual_choice"`
		} `json:"selective_clash"`
		FullTunnel struct {
			Selected  string `json:"selected_destination_source"`
			Direct    string `json:"unmatched_destination_source"`
			Handshake bool   `json:"handshake"`
		} `json:"full_tunnel_wireguard"`
	}
	if err := json.Unmarshal([]byte(readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))), &manifest); err != nil {
		t.Fatalf("decode personal-client E2E manifest: %v", err)
	}
	if manifest.Status != "accepted" || manifest.Scope != "automated-linux-clients" ||
		manifest.ActualClashMi != "deferred-to-task-16.11" || manifest.Delivery != "scp-only" ||
		manifest.Mihomo.Version != "v1.19.30" || len(manifest.Mihomo.ArchiveSHA256) != 64 ||
		len(manifest.Profiles.ClashSHA256) != 64 || len(manifest.Profiles.WireGuardSHA256) != 64 {
		t.Fatalf("personal-client acceptance identity is incomplete: %+v", manifest)
	}
	if manifest.Selective.Selected != "10.66.0.2" || manifest.Selective.Direct != "192.0.2.2" || manifest.Selective.Choice != "standard" {
		t.Fatalf("selective path evidence = %+v", manifest.Selective)
	}
	if manifest.FullTunnel.Selected != "10.66.0.3" || manifest.FullTunnel.Direct != "10.66.0.3" || !manifest.FullTunnel.Handshake {
		t.Fatalf("full-tunnel path evidence = %+v", manifest.FullTunnel)
	}

	generator := readContractFile(t, filepath.Join(fixtureRoot, "generate.go"))
	for _, required := range []string{
		"routing.NewClientManager", "routing.NewClientExporter", "selected-e2e", "fixtureSelectedTarget",
		"AssignedPresets", "AllowedIPs = 0.0.0.0/0", "SCPHint", "Mode().Perm() != 0o600",
	} {
		if !strings.Contains(generator, required) {
			t.Errorf("personal-client fixture generator is missing %q", required)
		}
	}

	harness := readContractFile(t, filepath.Join(fixtureRoot, "happy_path.sh"))
	for _, required := range []string{
		"Mihomo Meta v1.19.30", "verify_delivery_hashes", "--proxy http://127.0.0.1:17890",
		"assert_response \"$selected\" selected 10.66.0.2", "assert_response \"$direct\" direct 192.0.2.2",
		"wg-quick strip", "assert_response \"$selected\" selected 10.66.0.3",
		"assert_response \"$direct\" direct 10.66.0.3", "latest-handshakes", "cleanup_owned",
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("personal-client E2E harness is missing %q", required)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2personal-client-test.sh"))
	for _, required := range []string{
		"limactl copy --backend=scp", "assert_scp_copies", "assert_lab_instance", "assert_spikes_inactive",
		"vpnctl-v2-gateway", "vpnctl-v2-personal-client-e2e", "guest_namespaces_present", "cleanup_all",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("personal-client E2E orchestrator is missing %q", required)
		}
	}
	for _, forbidden := range []string{"curl http://github.com", "curl https://github.com", "rm -rf /etc", "rm -rf /run "} {
		if strings.Contains(orchestrator, forbidden) || strings.Contains(harness, forbidden) {
			t.Errorf("personal-client E2E contains unsafe or network-fetch surface %q", forbidden)
		}
	}
}
