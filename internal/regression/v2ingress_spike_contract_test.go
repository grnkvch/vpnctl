package regression

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2IngressSpikeContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "ingress")
	manifestData := readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))
	var manifest struct {
		Status string `json:"status"`
		Nginx  struct {
			Version       string `json:"version"`
			PackageSHA256 string `json:"package_sha256"`
			HTTP2Syntax   string `json:"http2_syntax"`
		} `json:"nginx"`
		Certificate struct {
			KeyAlgorithm       string `json:"key_algorithm"`
			KeyBits            int    `json:"key_bits"`
			SignatureAlgorithm string `json:"signature_algorithm"`
			ValidityDays       int    `json:"validity_days"`
			Identity           string `json:"identity"`
		} `json:"certificate"`
		Listeners struct {
			PublicHTTPSTCP      int  `json:"public_https_tcp"`
			PublicHTTPSUDP      bool `json:"public_https_udp"`
			LoopbackUpstreamTCP int  `json:"loopback_upstream_tcp"`
		} `json:"listeners"`
		Limits struct {
			WorkerConnections                int `json:"worker_connections"`
			GatewayConcurrentRequests        int `json:"gateway_concurrent_requests"`
			HTTP2ConcurrentStreams           int `json:"http2_concurrent_streams"`
			ExposeDefaultConcurrentRequests  int `json:"expose_default_concurrent_requests"`
			GatewayBodyBytes                 int `json:"gateway_body_bytes"`
			ExposeDefaultBodyBytes           int `json:"expose_default_body_bytes"`
			ExposeDefaultUpstreamTimeoutSecs int `json:"expose_default_upstream_timeout_seconds"`
			ExposeMaximumUpstreamTimeoutSecs int `json:"expose_max_upstream_timeout_seconds"`
			GracefulShutdownSeconds          int `json:"graceful_shutdown_seconds"`
		} `json:"limits"`
		Streaming struct {
			RequestBuffering  bool `json:"request_buffering"`
			ResponseBuffering bool `json:"response_buffering"`
			ResponseTempFiles bool `json:"response_temp_files"`
			UpstreamRetry     bool `json:"upstream_retry"`
		} `json:"streaming"`
	}
	if err := json.Unmarshal([]byte(manifestData), &manifest); err != nil {
		t.Fatalf("decode ingress spike manifest: %v", err)
	}
	if manifest.Status != "spike-only" || manifest.Nginx.Version != "1.24.0-2ubuntu7.17" ||
		len(manifest.Nginx.PackageSHA256) != 64 || manifest.Nginx.HTTP2Syntax != "listen-parameter" {
		t.Fatalf("unexpected nginx candidate: %+v", manifest.Nginx)
	}
	if manifest.Certificate.KeyAlgorithm != "RSA" || manifest.Certificate.KeyBits != 2048 ||
		manifest.Certificate.SignatureAlgorithm != "SHA-256" || manifest.Certificate.ValidityDays != 1825 ||
		manifest.Certificate.Identity != "manual-ipv4-san-and-cn" {
		t.Fatalf("unexpected ingress certificate contract: %+v", manifest.Certificate)
	}
	if manifest.Listeners.PublicHTTPSTCP != 443 || manifest.Listeners.PublicHTTPSUDP ||
		manifest.Listeners.LoopbackUpstreamTCP != 18081 {
		t.Fatalf("unexpected ingress listener contract: %+v", manifest.Listeners)
	}
	if manifest.Limits.WorkerConnections != 256 || manifest.Limits.GatewayConcurrentRequests != 64 ||
		manifest.Limits.HTTP2ConcurrentStreams != 64 || manifest.Limits.ExposeDefaultConcurrentRequests != 40 ||
		manifest.Limits.GatewayBodyBytes != 8*1024*1024 || manifest.Limits.ExposeDefaultBodyBytes != 1024*1024 ||
		manifest.Limits.ExposeDefaultUpstreamTimeoutSecs != 15 || manifest.Limits.ExposeMaximumUpstreamTimeoutSecs != 60 ||
		manifest.Limits.GracefulShutdownSeconds != 10 {
		t.Fatalf("unexpected ingress limit candidate: %+v", manifest.Limits)
	}
	if manifest.Streaming.RequestBuffering || manifest.Streaming.ResponseBuffering ||
		manifest.Streaming.ResponseTempFiles || manifest.Streaming.UpstreamRetry {
		t.Fatalf("unsafe ingress streaming contract: %+v", manifest.Streaming)
	}

	nginxConfig := readContractFile(t, filepath.Join(fixtureRoot, "nginx.conf"))
	for _, required := range []string{
		"listen 0.0.0.0:443 ssl http2", "ssl_protocols TLSv1.2 TLSv1.3",
		"worker_shutdown_timeout 10s", "worker_connections 256", "http2_max_concurrent_streams 64",
		"limit_conn_zone $server_name zone=vpnctl_gateway:64k", "limit_conn vpnctl_gateway 64",
		"proxy_connect_timeout 2s", "proxy_send_timeout 15s", "proxy_read_timeout 15s",
		"ssl_certificate /etc/vpnctl-v2-spike/ingress/gateway.crt",
		"location = /telegram/webhook", "proxy_pass http://127.0.0.1:18081",
		"client_max_body_size 1m", "limit_conn vpnctl_expose 40", "location = /hard-limit/webhook",
		"location = /unavailable", "location = /timeout", "error_page 502 =503 @vpnctl_unavailable",
		"access_log off", "return 404",
	} {
		if !strings.Contains(nginxConfig, required) {
			t.Errorf("nginx ingress fixture is missing %q", required)
		}
	}
	if count := strings.Count(nginxConfig, "limit_conn vpnctl_gateway 64;"); count != 8 {
		t.Errorf("gateway hard limit must be compiled at server and every proxy location, got %d copies", count)
	}
	proxyCommon := readContractFile(t, filepath.Join(fixtureRoot, "proxy-common.conf"))
	for _, required := range []string{
		"proxy_http_version 1.1", "proxy_request_buffering off", "proxy_buffering off",
		"proxy_max_temp_file_size 0", "proxy_next_upstream off", "proxy_intercept_errors on",
		"proxy_set_header X-Forwarded-For $remote_addr",
	} {
		if !strings.Contains(proxyCommon, required) {
			t.Errorf("nginx common proxy fixture is missing %q", required)
		}
	}

	receiver := readContractFile(t, filepath.Join(fixtureRoot, "webhook_receiver.py"))
	for _, required := range []string{
		"ThreadingHTTPServer", "MAX_BODY_BYTES", "X-Forwarded-Proto", "body_valid", "def log_message",
		"/__vpnctl_probe/status", "stream_started", "max_active_requests", "READ_CHUNK_BYTES",
	} {
		if !strings.Contains(receiver, required) {
			t.Errorf("webhook receiver is missing %q", required)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2ingress-spike.sh"))
	for _, required := range []string{
		"manual public IP is required", "assert_forward_ignored", "NGINX_INSTALLED_BY_SPIKE=pending",
		"assert_port_free_or_owned 443 \"$ingress_unit\"", "assert_port_free_or_owned 18081 \"$webhook_unit\"",
		"apt-get install --no-install-recommends", "newkey rsa:2048", "subjectAltName=IP:",
		"-verify_ip", "--http$http_version", "node_http_request 1.1", "node_http_request 2",
		"set_webhook_executed: false", "node_stress_load", "body-file-monitor",
		"concurrency-gateway-overload", "development-candidate-passed", "uninstall_spike",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("ingress spike orchestrator is missing %q", required)
		}
	}

	loadProbe := readContractFile(t, filepath.Join(fixtureRoot, "ingress_load.py"))
	for _, required := range []string{"HTTPSConnection", "ThreadPoolExecutor", "status_counts", "chunk_delay_ms"} {
		if !strings.Contains(loadProbe, required) {
			t.Errorf("ingress load probe is missing %q", required)
		}
	}
	bodyMonitor := readContractFile(t, filepath.Join(fixtureRoot, "body_file_monitor.py"))
	for _, required := range []string{"follow_symlinks=False", "max_regular_files", "os.replace", "os.fsync"} {
		if !strings.Contains(bodyMonitor, required) {
			t.Errorf("body-file monitor is missing %q", required)
		}
	}
	for _, forbidden := range []string{"BOT_TOKEN=", "api.telegram.org/bot", "access_log on"} {
		if strings.Contains(orchestrator, forbidden) {
			t.Errorf("ingress spike orchestrator contains forbidden credential/logging surface %q", forbidden)
		}
	}

	telegramGate := readContractFile(t, filepath.Join(fixtureRoot, "telegram_webhook_gate.py"))
	for _, required := range []string{
		"getpass.getpass", "refusing to replace an existing Telegram webhook", "setWebhook", "getWebhookInfo",
		"deleteWebhook", "receiver_count", "has_custom_certificate", "sensitive_values_emitted",
		`open("/dev/tty"`, "cleanup_created_webhook", "current.get(\"url\") != expected_url",
	} {
		if !strings.Contains(telegramGate, required) {
			t.Errorf("real Telegram webhook gate is missing %q", required)
		}
	}
	for _, forbidden := range []string{"os.environ", "token = args.", "print(token", "logging."} {
		if strings.Contains(telegramGate, forbidden) {
			t.Errorf("real Telegram webhook gate contains forbidden token/logging surface %q", forbidden)
		}
	}

	for _, unit := range []string{"vpnctl-v2-spike-ingress.service", "vpnctl-v2-spike-webhook.service"} {
		contents := readContractFile(t, filepath.Join(fixtureRoot, "systemd", unit))
		if !strings.Contains(contents, "NoNewPrivileges=true") || !strings.Contains(contents, "MemoryMax=") {
			t.Errorf("ingress unit %s lacks sandbox/resource limits", unit)
		}
	}
	ingressUnit := readContractFile(t, filepath.Join(fixtureRoot, "systemd", "vpnctl-v2-spike-ingress.service"))
	if !strings.Contains(ingressUnit, "CapabilityBoundingSet=CAP_CHOWN CAP_NET_BIND_SERVICE CAP_SETGID CAP_SETUID") {
		t.Error("ingress unit lacks the bounded capabilities needed to bind and prepare worker temp directories")
	}

	limaTemplate := readContractFile(t, filepath.Join(repositoryRoot, "test", "v2lab", "lima.yaml"))
	if !strings.Contains(limaTemplate, "guestPort: 443") {
		t.Error("Lima template does not isolate guest port 443 from host forwarding")
	}
}

func TestV2IngressReleaseGateContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "ingress")
	harnessPath := filepath.Join(repositoryRoot, "scripts", "v2ingress-release-gate.sh")
	info, err := os.Stat(harnessPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Fatal("ingress release gate is not executable")
	}
	harness := readContractFile(t, harnessPath)
	for _, required := range []string{
		"ingress release gate requires a clean source tree", "assert_lab_instance", "assert_ingress_fixture_absent",
		"TestNginxConfigParsesWithPinnedNginx", "TestNginxRuntimeDoesNotReplayNonIdempotentRequests",
		"TestNginxProductionRuntimeRegression", "VPNCTL_NGINX_PRODUCTION_SUMMARY", "production-native.json",
		"path_query_headers_body == true", ".safe_concurrent == 32", ".expose_accepted == 40",
		".gateway_accepted == 64", ".maximum_rss_bytes < 134217728", ".body_temp_files == 0",
		"v2ingress-spike.sh", "validate_spike_summaries", ".resources.oom_events == 0",
		"run_offline_telegram_harness_tests", "provider_calls_executed: false", "deferred_gate: \"task 16.11\"",
		"cleanup_native_guest", "ingress_cleanup", "ingress release gate refuses to replace evidence", "source_commit",
	} {
		if !strings.Contains(harness, required) {
			t.Errorf("ingress release gate is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"VPNCTL_RELEASE_GATE_ALLOW_DIRTY", "--force", "rm -rf /etc", "setWebhook --token", "BOT_TOKEN=",
	} {
		if strings.Contains(harness, forbidden) {
			t.Errorf("ingress release gate contains forbidden behavior %q", forbidden)
		}
	}

	productionTest := readContractFile(t, filepath.Join(repositoryRoot, "internal", "ingress", "nginx_production_native_test.go"))
	for _, required := range []string{
		"RenderNginxConfig", "ValidatePinnedNginxConfig", "HTTP/1.1", "HTTP/2.0",
		"X-Telegram-Bot-Api-Secret-Token", "X-Original-Forwarded-For", "RequestURI",
		"DefaultExposeConcurrentRequests", "DefaultIngressGatewayConcurrentRequests",
		"nginxProductionRSS", "regularFilesUnder", "request_replay",
	} {
		if !strings.Contains(productionTest, required) {
			t.Errorf("production ingress native test is missing %q", required)
		}
	}

	manifestData := readContractFile(t, filepath.Join(fixtureRoot, "telegram-harness-manifest.json"))
	var manifest struct {
		Status                      string   `json:"status"`
		ProviderGate                string   `json:"provider_gate"`
		TokenInput                  string   `json:"token_input"`
		TokenForbiddenChannels      []string `json:"token_forbidden_channels"`
		Cleanup                     string   `json:"cleanup"`
		MaximumWaitSeconds          int      `json:"maximum_wait_seconds"`
		ProviderCallsDuringTask1211 bool     `json:"provider_calls_during_task_12_11"`
	}
	if err := json.Unmarshal([]byte(manifestData), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "release-gate-only" || manifest.ProviderGate != "task-16.11" ||
		manifest.TokenInput != "hidden-controlling-tty-only" || len(manifest.TokenForbiddenChannels) != 5 ||
		manifest.Cleanup != "delete-only-when-current-url-matches-created-url" || manifest.MaximumWaitSeconds != 600 ||
		manifest.ProviderCallsDuringTask1211 {
		t.Fatalf("Telegram harness manifest = %+v", manifest)
	}

	offlineTests := readContractFile(t, filepath.Join(fixtureRoot, "test_telegram_webhook_gate.py"))
	for _, required := range []string{
		"test_success_registers_observes_and_removes_only_created_webhook",
		"test_existing_webhook_is_never_replaced_or_deleted",
		"test_concurrent_provider_change_is_not_deleted",
		"test_public_certificate_reader_rejects_private_and_symlink_inputs",
		"mock.patch.object", "self.assertNotIn(\"deleteWebhook\"",
	} {
		if !strings.Contains(offlineTests, required) {
			t.Errorf("Telegram harness offline tests are missing %q", required)
		}
	}
}
