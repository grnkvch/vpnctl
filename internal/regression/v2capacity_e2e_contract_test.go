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
		"b29cf595a13d39c8445e2d42b6a5d8e7a50772b7703b26f9f7d8da9f45f4c485",
	} {
		if !strings.Contains(clientHelper, required) {
			t.Errorf("capacity client helper is missing %q", required)
		}
	}
	wireGuardClients := readContractFile(t, filepath.Join(fixtureRoot, "clients.sh"))
	for _, required := range []string{
		"client_ready_attempts=12", "client_ready_interval_seconds=0.25",
		"capacity client handshake did not become ready: $namespace",
	} {
		if !strings.Contains(wireGuardClients, required) {
			t.Errorf("capacity WireGuard helper is missing %q", required)
		}
	}
	faultHelper := readContractFile(t, filepath.Join(fixtureRoot, "fault.sh"))
	for _, required := range []string{
		"runtime_dropin_directory=/run/systemd/system/vpnctl-v2-spike-tunnel-server.service.d",
		"runtime_dropin=$runtime_dropin_directory/vpnctl-v2-capacity-fault.conf",
		"printf '[Service]\\nRestart=no\\n'", "FRPS temporary restart policy was not applied",
		"restore_restart_policy", "--kill-whom=main --signal=KILL",
		"down_started=$(monotonic)", "systemd-run --quiet --collect", "--timer-property=AccuracySec=10ms", "unavailable_status: $unavailable_probe.status",
		"ActiveEnterTimestampMonotonic",
		"emit_result failed false", "emit_result passed true", "stable_recovery_probes: 5",
		"fault_stage: $fault_stage", "result_emitted=false", "fault_incomplete",
		"load armed-probe", "load armed-recover", "prepare_armed_probe", "run_armed_probe", "run_armed_recovery", "cleanup_armed_probe",
		"armed_probe_root=/var/lib/vpnctl-v2-capacity/fault-probe", "--trigger-timeout 30",
		"--timeout 2", "--connect-timeout 5",
		"--recovery-limit-seconds \"$recovery_limit_seconds\"", "recovery-trigger", "recovery-ready", "recovery-result.json",
		"scheduled_down_seconds: $scheduled_down_seconds", "stable_recovery_observed: $stable_recovery",
		"first_recovery_seconds: $first_recovery_seconds", "maximum_stable_recovery_probes: $maximum_stable_recovery_probes",
		"last_recovery_seconds: $last_recovery_seconds", "successful_recovery_probes: $successful_recovery_probes",
		"recovery_probe_attempts: $recovery_probe_attempts", "run_armed_recovery",
		"--stable-probes 5 --probe-interval 0.1",
	} {
		if !strings.Contains(faultHelper, required) {
			t.Errorf("capacity fault helper is missing %q", required)
		}
	}
	restartTimer := strings.Index(faultHelper, "systemd-run --quiet --collect")
	downStarted := strings.Index(faultHelper, "down_started=$(monotonic)")
	hardKill := strings.LastIndex(faultHelper, "systemctl kill --kill-whom=main --signal=KILL")
	if restartTimer < 0 || downStarted < 0 || hardKill < 0 || !(restartTimer < downStarted && downStarted < hardKill) {
		t.Fatal("capacity fault helper must arm restart before measuring and hard-killing FRPS")
	}
	temporaryPolicyApplied := strings.Index(faultHelper, "FRPS temporary restart policy was not applied")
	armedProbe := strings.LastIndex(faultHelper, "prepare_armed_probe\n")
	if temporaryPolicyApplied < 0 || armedProbe < 0 || !(temporaryPolicyApplied < armedProbe && armedProbe < restartTimer) {
		t.Fatal("capacity HTTPS probe must be armed after slow policy setup and immediately before the restart timer")
	}
	recoveryWorker := strings.Index(faultHelper, "load armed-recover")
	outageWorker := strings.Index(faultHelper, "load armed-probe")
	if recoveryWorker < 0 || outageWorker < 0 || recoveryWorker >= outageWorker {
		t.Fatal("capacity recovery worker must become ready before the timeout-sensitive TLS outage worker starts")
	}
	stoppedCheck := strings.Index(faultHelper, "stop_state=")
	unavailableProbe := strings.Index(faultHelper, "run_armed_probe\n")
	if stoppedCheck < 0 || unavailableProbe < 0 || !(hardKill < stoppedCheck && stoppedCheck < unavailableProbe) {
		t.Fatal("capacity fault helper must observe the stopped state before the slower HTTPS probe")
	}
	restartTimestamp := strings.Index(faultHelper, "restart_started=$(awk")
	recoveryTrigger := strings.LastIndex(faultHelper, "run_armed_recovery || true")
	policyRestore := strings.LastIndex(faultHelper, "restore_restart_policy\n")
	if restartTimestamp < 0 || recoveryTrigger < 0 || policyRestore < 0 ||
		!(restartTimestamp < recoveryTrigger && recoveryTrigger < policyRestore) {
		t.Fatal("capacity recovery must start from the observed timestamp before slow policy restoration")
	}

	harness := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2capacity-e2e.sh"))
	for _, required := range []string{
		"capacity E2E requires a clean source tree", "--requests 45 --delay-ms 3000",
		"v2restricted-spike.sh\" prepare > \"$run_root/restricted-prepare.log\" 2>&1",
		"v2tunnel-spike.sh\" prepare > \"$run_root/tunnel-prepare.log\" 2>&1",
		"v2ingress-spike.sh\" prepare \"$gateway_ip\" > \"$run_root/ingress-prepare.log\" 2>&1",
		"--requests 72 --delay-ms 5000", "gateway-limit-before-connections.txt",
		"gateway-limit-during-connections.txt", ".status_counts[\"200\"] == 64",
		".status_counts[\"503\"] == 8", ".max_active_requests == 64",
		"log-level: silent", "log.level = \"error\"", "production-log-validation.txt",
		"frps_stop_after_seconds", "/usr/local/libexec/vpnctl-v2-capacity/fault",
		"./test/v2lab/capacity/tunnel_client", "webServer.user = \"vpnctl\"",
		"/var/lib/vpnctl-v2-capacity",
		"capacity_admin_password=b29cf595a13d39c8445e2d42b6a5d8e7a50772b7703b26f9f7d8da9f45f4c485",
		"/etc/systemd/system/$tunnel_client_unit.d/$capacity_client_dropin",
		"expected one active tunnel client service and supervised frpc child", "frpc_child_recycled:",
		"recovered_without_client_service_restart:",
		".reconnect.status == \"passed\"",
		".reconnect.requested_down_seconds == $limits[0].fault.frps_down_seconds",
		".reconnect.down_seconds <= ($limits[0].fault.frps_down_seconds + 0.5)",
		"status: \"candidate\"", "finalize_summary", ".status = \"passed\"",
		"cleanup_capacity_fault", "capacity_fault_dropin_dir=/run/systemd/system/$tunnel_server_unit.d",
		"capacity_fault_dropin=$capacity_fault_dropin_dir/vpnctl-v2-capacity-fault.conf",
		"assert_transient_unit_absent \"$capacity_fault_restart_job.timer\"",
		"cleanup: {owner_scoped: true, temporary_resources_absent: true, prior_fixture_states_restored: true}",
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("capacity E2E harness is missing %q", required)
		}
	}
	if strings.Count(harness, "--failure-window-start \"$fault_start\" --failure-window-end \"$fault_end\"") != 2 {
		t.Fatal("capacity webhook and Bot API loads must record the same fault-window latency partition")
	}
	verifyStart := strings.LastIndex(harness, "verify() {")
	if verifyStart < 0 {
		t.Fatal("capacity verify function is absent")
	}
	verifyHarness := harness[verifyStart:]
	beforeState := strings.Index(verifyHarness, "capture_tunnel_client_process_state_before\n")
	startLoads := strings.Index(verifyHarness, "start_loads\n")
	fault := strings.Index(verifyHarness, "inject_reconnect\n")
	waitLoads := strings.Index(verifyHarness, "wait_loads\n")
	afterState := strings.Index(verifyHarness, "finalize_reconnect_process_state\n")
	if beforeState < 0 || startLoads < 0 || fault < 0 || waitLoads < 0 || afterState < 0 ||
		!(beforeState < startLoads && startLoads < fault && fault < waitLoads && waitLoads < afterState) {
		t.Fatal("capacity tunnel PID snapshots must remain outside the measured workload")
	}
	if !strings.Contains(harness, "guest \"$node_instance\" sudo bash -c") {
		t.Fatal("capacity tunnel process snapshot must use one bounded guest session")
	}
	loadReporter := readContractFile(t, filepath.Join(fixtureRoot, "load.py"))
	for _, required := range []string{
		"successful_latency_by_30_second_start_bucket", "dispatch_lag_ms",
		"latency_by_start_bucket", "annotate_dispatch_lag",
	} {
		if !strings.Contains(loadReporter, required) {
			t.Errorf("capacity load reporter is missing aggregate temporal diagnostic %q", required)
		}
	}
}
