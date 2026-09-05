package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2CapacityE2EContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "capacity")
	manifestData := readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))
	var manifest struct {
		Profile struct {
			LogicalTelegramUsers int `json:"logical_telegram_users"`
			DurationSeconds      int `json:"duration_seconds"`
			WebhookRPS           int `json:"webhook_requests_per_second"`
			BotAPIRPS            int `json:"bot_api_requests_per_second"`
			PersonalClients      int `json:"personal_clients"`
		} `json:"profile"`
		Target struct {
			VCPU             int `json:"vcpu"`
			MemoryBytes      int `json:"memory_bytes"`
			DiskBytes        int `json:"disk_bytes"`
			ManagedSwapBytes int `json:"managed_swap_bytes"`
		} `json:"target"`
		Bounds struct {
			ControllerRSS         int `json:"controller_idle_rss_bytes"`
			WebhookSuccessMinimum int `json:"webhook_successful_requests_minimum"`
			PerExposeConcurrent   int `json:"per_expose_concurrent_requests"`
			GatewayConcurrent     int `json:"gateway_concurrent_requests"`
		} `json:"bounds"`
	}
	if err := json.Unmarshal([]byte(manifestData), &manifest); err != nil {
		t.Fatalf("decode capacity manifest: %v", err)
	}
	if manifest.Profile.LogicalTelegramUsers != 300 || manifest.Profile.DurationSeconds != 300 ||
		manifest.Profile.WebhookRPS != 10 || manifest.Profile.BotAPIRPS != 5 || manifest.Profile.PersonalClients != 5 {
		t.Fatalf("unexpected sustained capacity profile: %+v", manifest.Profile)
	}
	if manifest.Target.VCPU != 1 || manifest.Target.MemoryBytes != 512*1024*1024 ||
		manifest.Target.DiskBytes != 10*1024*1024*1024 || manifest.Target.ManagedSwapBytes != 1024*1024*1024 {
		t.Fatalf("unexpected minimum host target: %+v", manifest.Target)
	}
	if manifest.Bounds.ControllerRSS != 20*1024*1024 || manifest.Bounds.WebhookSuccessMinimum != 2890 ||
		manifest.Bounds.PerExposeConcurrent != 40 ||
		manifest.Bounds.GatewayConcurrent != 64 {
		t.Fatalf("unexpected capacity bounds: %+v", manifest.Bounds)
	}

	backendDropIn := readContractFile(t, filepath.Join(fixtureRoot, "vpnctl-v2-capacity-backend.conf"))
	for _, required := range []string{
		"ExecStart=", "webhook-receiver --listen 127.0.0.1 --port 18121", "TasksMax=96",
	} {
		if !strings.Contains(backendDropIn, required) {
			t.Errorf("capacity backend drop-in is missing %q", required)
		}
	}
	clientDropIn := readContractFile(t, filepath.Join(fixtureRoot, "vpnctl-v2-capacity-client.conf"))
	for _, required := range []string{
		"ExecStart=", "/usr/local/libexec/vpnctl-v2-capacity/tunnel-client --gateway-ip @GATEWAY_IP@",
	} {
		if !strings.Contains(clientDropIn, required) {
			t.Errorf("capacity client drop-in is missing %q", required)
		}
	}
	clientHelper := readContractFile(t, filepath.Join(fixtureRoot, "tunnel_client", "main.go"))
	for _, required := range []string{
		"tunnel.NewFRPClientStatusRecoveryProber", "tunnel.RunFRPClientProcessWithRecovery",
		"cacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca",
	} {
		if !strings.Contains(clientHelper, required) {
			t.Errorf("capacity client helper is missing %q", required)
		}
	}
	faultHelper := readContractFile(t, filepath.Join(fixtureRoot, "fault.sh"))
	for _, required := range []string{
		"systemctl stop --no-block", "--kill-who=main --signal=KILL",
		"down_started=$(monotonic)", "sleep \"$scheduled_down_seconds\"", "restart_pid=$!", "unavailable_status: $unavailable_probe.status",
		"emit_result failed false", "emit_result passed true", "stable_recovery_probes: 5",
		"scheduled_down_seconds: $scheduled_down_seconds", "stable_recovery_observed: $stable_recovery",
	} {
		if !strings.Contains(faultHelper, required) {
			t.Errorf("capacity fault helper is missing %q", required)
		}
	}

	harness := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2capacity-e2e.sh"))
	for _, required := range []string{
		"capacity E2E requires a clean source tree", "--requests 45 --delay-ms 3000",
		"--requests 72 --delay-ms 5000", "gateway-limit-before-connections.txt",
		"gateway-limit-during-connections.txt", ".status_counts[\"200\"] == 64",
		".status_counts[\"503\"] == 8", ".max_active_requests == 64",
		"log-level: silent", "log.level = \"error\"", "production-log-validation.txt",
		"frps_stop_after_seconds", "/usr/local/libexec/vpnctl-v2-capacity/fault",
		"./test/v2lab/capacity/tunnel_client", "webServer.user = \"vpnctl\"",
		"/etc/systemd/system/$tunnel_client_unit.d/$capacity_client_dropin",
		"expected one active tunnel client service and supervised frpc child", "frpc_child_recycled:",
		"recovered_without_client_service_restart:",
		".reconnect.status == \"passed\"",
		".reconnect.requested_down_seconds == $limits[0].fault.frps_down_seconds",
		".reconnect.down_seconds <= ($limits[0].fault.frps_down_seconds + 0.5)",
		"cleanup: {owner_scoped: true, temporary_resources_absent: true, prior_fixture_states_restored: true}",
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("capacity E2E harness is missing %q", required)
		}
	}
}
