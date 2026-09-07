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
		SchemaVersion int `json:"schema_version"`
		Profile       struct {
			LogicalTelegramUsers int `json:"logical_telegram_users"`
			DurationSeconds      int `json:"duration_seconds"`
			WebhookRPS           int `json:"webhook_requests_per_second"`
			BotAPIRPS            int `json:"bot_api_requests_per_second"`
			PersonalClients      int `json:"personal_clients"`
		} `json:"profile"`
		Topology struct {
			CapacityBoundaryRole string `json:"capacity_boundary_role"`
			LoadGeneratorRole    string `json:"load_generator_role"`
			Contract             string `json:"contract"`
		} `json:"topology"`
		GatewayTarget struct {
			VCPU                           int `json:"vcpu"`
			MemoryBytes                    int `json:"memory_bytes"`
			DiskBytes                      int `json:"disk_bytes"`
			ManagedSwapBytes               int `json:"managed_swap_bytes"`
			ManagedSwapKernelReservedBytes int `json:"managed_swap_kernel_reserved_bytes"`
		} `json:"gateway_target"`
		NodeFixture struct {
			VCPU                           int  `json:"vcpu"`
			MemoryBytes                    int  `json:"memory_bytes"`
			DiskBytes                      int  `json:"disk_bytes"`
			ManagedSwapBytes               int  `json:"managed_swap_bytes"`
			ManagedSwapKernelReservedBytes int  `json:"managed_swap_kernel_reserved_bytes"`
			NormativeCapacityTarget        bool `json:"normative_capacity_target"`
		} `json:"node_fixture"`
		LoadGenerator struct {
			WarmupSeconds         int `json:"warmup_seconds"`
			RequestTimeoutSeconds int `json:"request_timeout_seconds"`
			WorkerHeadroomPercent int `json:"worker_headroom_percent"`
			WebhookWorkers        int `json:"webhook_workers"`
			BotAPIWorkers         int `json:"bot_api_workers"`
		} `json:"load_generator"`
		Bounds struct {
			ControllerRSS            int     `json:"controller_idle_rss_bytes"`
			MinimumMemoryAvailable   int     `json:"minimum_mem_available_bytes"`
			MaximumSwapUsed          int     `json:"maximum_swap_used_bytes"`
			MaximumAverageCPU        int     `json:"maximum_average_cpu_percent"`
			MinimumFreeDisk          int     `json:"minimum_free_disk_bytes"`
			MaximumDiskGrowth        int     `json:"maximum_disk_growth_bytes"`
			WebhookSuccessMinimum    int     `json:"webhook_successful_requests_minimum"`
			WebhookFailuresOutside   int     `json:"webhook_failures_outside_client_disruption"`
			WebhookSteadyP95Millis   int     `json:"webhook_steady_state_success_p95_ms"`
			WebhookSteadyP99Millis   int     `json:"webhook_steady_state_success_p99_ms"`
			BotAPIGlobalP95Millis    int     `json:"bot_api_success_p95_ms"`
			BotAPIGlobalP99Millis    int     `json:"bot_api_success_p99_ms"`
			DispatchLagP99Millis     int     `json:"load_generator_dispatch_lag_p99_ms"`
			TailSeconds              int     `json:"load_generator_tail_seconds"`
			StableRecoveryProbes     int     `json:"client_disruption_stable_recovery_probes"`
			MaximumDisruptionSeconds float64 `json:"maximum_client_disruption_seconds"`
			ReconnectSeconds         int     `json:"tunnel_reconnect_seconds"`
			PerExposeConcurrent      int     `json:"per_expose_concurrent_requests"`
			GatewayConcurrent        int     `json:"gateway_concurrent_requests"`
		} `json:"bounds"`
		Fault struct {
			StopAfter   int `json:"frps_stop_after_seconds"`
			DownSeconds int `json:"frps_down_seconds"`
			SanityStart int `json:"accepted_failure_window_start_seconds"`
			SanityEnd   int `json:"accepted_failure_window_end_seconds"`
		} `json:"fault"`
	}
	if err := json.Unmarshal([]byte(manifestData), &manifest); err != nil {
		t.Fatalf("decode capacity manifest: %v", err)
	}
	if manifest.Profile.LogicalTelegramUsers != 300 || manifest.Profile.DurationSeconds != 300 ||
		manifest.Profile.WebhookRPS != 10 || manifest.Profile.BotAPIRPS != 5 || manifest.Profile.PersonalClients != 5 {
		t.Fatalf("unexpected sustained capacity profile: %+v", manifest.Profile)
	}
	if manifest.SchemaVersion != 3 || manifest.Topology.CapacityBoundaryRole != "gateway" ||
		manifest.Topology.LoadGeneratorRole != "node" || manifest.Topology.Contract != "test/v2lab/fixtures.json" {
		t.Fatalf("unexpected capacity topology: %+v", manifest.Topology)
	}
	if manifest.GatewayTarget.VCPU != 1 || manifest.GatewayTarget.MemoryBytes != 512*1024*1024 ||
		manifest.GatewayTarget.DiskBytes != 10*1024*1024*1024 || manifest.GatewayTarget.ManagedSwapBytes != 1024*1024*1024 ||
		manifest.GatewayTarget.ManagedSwapKernelReservedBytes != 4096 {
		t.Fatalf("unexpected minimum Gateway target: %+v", manifest.GatewayTarget)
	}
	if manifest.NodeFixture.VCPU != 4 || manifest.NodeFixture.MemoryBytes != 2*1024*1024*1024 ||
		manifest.NodeFixture.DiskBytes != 10*1024*1024*1024 || manifest.NodeFixture.ManagedSwapBytes != 1024*1024*1024 ||
		manifest.NodeFixture.ManagedSwapKernelReservedBytes != 4096 ||
		manifest.NodeFixture.NormativeCapacityTarget {
		t.Fatalf("unexpected functional Node fixture: %+v", manifest.NodeFixture)
	}
	if manifest.LoadGenerator.WarmupSeconds != 10 || manifest.LoadGenerator.RequestTimeoutSeconds != 8 ||
		manifest.LoadGenerator.WorkerHeadroomPercent != 20 || manifest.LoadGenerator.WebhookWorkers != 96 ||
		manifest.LoadGenerator.BotAPIWorkers != 48 ||
		manifest.LoadGenerator.WebhookWorkers != manifest.Profile.WebhookRPS*manifest.LoadGenerator.RequestTimeoutSeconds*120/100 ||
		manifest.LoadGenerator.BotAPIWorkers != manifest.Profile.BotAPIRPS*manifest.LoadGenerator.RequestTimeoutSeconds*120/100 {
		t.Fatalf("unexpected load-generator contract: %+v", manifest.LoadGenerator)
	}
	if manifest.Bounds.ControllerRSS != 20*1024*1024 || manifest.Bounds.WebhookSuccessMinimum != 2890 ||
		manifest.Bounds.MinimumMemoryAvailable != 64*1024*1024 || manifest.Bounds.MaximumSwapUsed != 512*1024*1024 ||
		manifest.Bounds.MaximumAverageCPU != 85 || manifest.Bounds.MinimumFreeDisk != 512*1024*1024 ||
		manifest.Bounds.MaximumDiskGrowth != 64*1024*1024 || manifest.Bounds.WebhookFailuresOutside != 0 ||
		manifest.Bounds.WebhookSteadyP95Millis != 1000 || manifest.Bounds.WebhookSteadyP99Millis != 2000 ||
		manifest.Bounds.BotAPIGlobalP95Millis != 1000 || manifest.Bounds.BotAPIGlobalP99Millis != 2000 ||
		manifest.Bounds.DispatchLagP99Millis != 1000 || manifest.Bounds.TailSeconds != 30 ||
		manifest.Bounds.StableRecoveryProbes != 5 || manifest.Bounds.MaximumDisruptionSeconds != 11.5 ||
		manifest.Bounds.ReconnectSeconds != 8 || manifest.Bounds.PerExposeConcurrent != 40 ||
		manifest.Bounds.GatewayConcurrent != 64 {
		t.Fatalf("unexpected capacity bounds: %+v", manifest.Bounds)
	}
	if manifest.Fault.StopAfter != 145 || manifest.Fault.DownSeconds != 3 ||
		manifest.Fault.SanityStart != 135 || manifest.Fault.SanityEnd != 175 {
		t.Fatalf("unexpected capacity fault contract: %+v", manifest.Fault)
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
		"scheduled_start_after_seconds: $scheduled_start_after_seconds", "trap 'exit 129' HUP",
		"first_recovery_seconds: $first_recovery_seconds", "maximum_stable_recovery_probes: $maximum_stable_recovery_probes",
		"last_recovery_seconds: $last_recovery_seconds", "successful_recovery_probes: $successful_recovery_probes",
		"recovery_probe_attempts: $recovery_probe_attempts", "run_armed_recovery",
		"--stable-probes 5 --probe-interval 0.1",
		"--start-after-seconds", "fault_stage=scheduled", "sleep \"$start_after_seconds\"",
		"fault-start.ready", "fault-start.trigger", "wait_for_start_trigger", "seq 1 1200",
		"refusing existing capacity fault schedule files", "cleanup_start_schedule",
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
	delayedStart := strings.Index(faultHelper, "sleep \"$start_after_seconds\"")
	armedProbe := strings.LastIndex(faultHelper, "prepare_armed_probe\n")
	if delayedStart < 0 || temporaryPolicyApplied < 0 || armedProbe < 0 ||
		!(delayedStart < temporaryPolicyApplied && temporaryPolicyApplied < armedProbe && armedProbe < restartTimer) {
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
		"--diagnostic-start \"$fault_start\" --diagnostic-end \"$fault_end\"",
		"--fault-unit \"$tunnel_server_unit\"",
		"VPNCTL_CAPACITY_FRPC_PASSWORD=\"$capacity_admin_password\"", "capture_node_health",
		"wait_reconnect || reconnect_status=$?", "wait_loads || load_status=$?",
		"run_warmup", "webhook-warmup.json", "api-warmup.json", "wait_background_group",
		"webhook-load-generator", "gateway-resource-monitor",
		"evaluate.py", "fixture_topology_sha256", "measurement_classification", "measurement_validity",
		".gateway_capacity.within_contract", ".node_fixture_health.within_contract",
		".load_generator_validity.within_contract", ".fault_reconnect.within_contract",
		".client_disruption.within_contract", ".steady_state_latency.within_contract",
		"resource_acceptance_thresholds_applied == false",
		"cleanup_capacity_fault", "capacity_fault_dropin_dir=/run/systemd/system/$tunnel_server_unit.d",
		"capacity_fault_dropin=$capacity_fault_dropin_dir/vpnctl-v2-capacity-fault.conf",
		"assert_transient_unit_absent \"$capacity_fault_restart_job.timer\"",
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
	startFault := strings.Index(verifyHarness, "start_reconnect\n")
	startLoads := strings.Index(verifyHarness, "start_loads\n")
	waitFault := strings.Index(verifyHarness, "wait_reconnect || reconnect_status=$?")
	waitLoads := strings.Index(verifyHarness, "wait_loads || load_status=$?")
	afterState := strings.Index(verifyHarness, "finalize_reconnect_process_state\n")
	if beforeState < 0 || startFault < 0 || startLoads < 0 || waitFault < 0 || waitLoads < 0 || afterState < 0 ||
		!(beforeState < startFault && startFault < startLoads && startLoads < waitFault && waitFault < waitLoads && waitLoads < afterState) {
		t.Fatal("capacity tunnel PID snapshots must remain outside the measured workload")
	}
	if strings.Contains(verifyHarness[startLoads:waitFault], "guest \"") {
		t.Fatal("capacity must not open a new Lima guest session to deliver or diagnose the scheduled fault")
	}
	if !strings.Contains(harness, "--start-after-seconds \"$fault_after\"") ||
		!strings.Contains(harness, "reconnect_pid=$!") ||
		!strings.Contains(harness, "capacity reconnect fault did not become ready before load") ||
		!strings.Contains(harness, "sudo install -m 0600 /dev/null \"$capacity_fault_start_trigger\"") {
		t.Fatal("capacity fault must enter its guest before load and delay there until the manifest offset")
	}
	if !strings.Contains(harness, "guest \"$node_instance\" sudo bash -c") {
		t.Fatal("capacity tunnel process snapshot must use one bounded guest session")
	}
	if strings.Contains(harness, "limactl edit") {
		t.Fatal("capacity verification must never resize a fixture at runtime")
	}
	loadReporter := readContractFile(t, filepath.Join(fixtureRoot, "load.py"))
	for _, required := range []string{
		"successful_latency_by_30_second_start_bucket", "dispatch_lag_ms",
		"latency_by_start_bucket", "annotate_request_lifecycle", "scheduled_offset_seconds",
		"started_offset_seconds", "completed_offset_seconds", "end_to_end_ms",
		"classify_client_disruption", "stable_recovery_request_indexes", "worker_queue_lag_ms",
	} {
		if !strings.Contains(loadReporter, required) {
			t.Errorf("capacity load reporter is missing aggregate temporal diagnostic %q", required)
		}
	}
	evaluator := readContractFile(t, filepath.Join(fixtureRoot, "evaluate.py"))
	for _, required := range []string{
		`"gateway_capacity"`, `"node_fixture_health"`, `"load_generator_validity"`,
		`"fault_reconnect"`, `"client_disruption"`, `"steady_state_latency"`,
		`"webhook_global_dispatch_lag_p99_within_bound"`, `nested(tail, "dispatch_lag_ms", "max")`,
		`"managed_swap_profile"`,
		`classification = "invalid_measurement_evidence"`, `classification = "invalid_load_generation"`, `classification = "invalid_node_fixture"`,
		`classification = "gateway_capacity_not_demonstrated"`,
		`"resource_acceptance_thresholds_applied": False`,
		`"heuristic_signals_not_causal_proof"`,
	} {
		if !strings.Contains(evaluator, required) {
			t.Errorf("capacity evaluator is missing %q", required)
		}
	}
	monitor := readContractFile(t, filepath.Join(fixtureRoot, "monitor.py"))
	for _, required := range []string{
		"iowait", "steal", "load1", "run_queue", "host_oom_kills", "NRestarts",
		"unit_states", "cgroup_states", "cgroup.events", "cgroup_processes", "tcp_state_counts", "frpc_status", `"timeline": timeline`,
		`"swap_total_bytes": swap_total_bytes`, `"diagnostic_errors": diagnostic_errors`, `"degraded"`,
	} {
		if !strings.Contains(monitor, required) {
			t.Errorf("capacity monitor is missing %q", required)
		}
	}
	if got := strings.Count(monitor, "unit_states(args.unit, groups)"); got != 2 {
		t.Errorf("capacity monitor takes %d systemd state snapshots, want exactly pre/post", got)
	}
}
