package regression

import (
	"encoding/json"
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

	nginxConfig := readContractFile(t, filepath.Join(fixtureRoot, "nginx.conf"))
	for _, required := range []string{
		"listen 0.0.0.0:443 ssl http2", "ssl_protocols TLSv1.2 TLSv1.3",
		"ssl_certificate /etc/vpnctl-v2-spike/ingress/gateway.crt",
		"location = /telegram/webhook", "proxy_pass http://127.0.0.1:18081",
		"proxy_http_version 1.1", "proxy_request_buffering off", "proxy_buffering off",
		"proxy_set_header X-Forwarded-For $remote_addr", "access_log off", "return 404",
	} {
		if !strings.Contains(nginxConfig, required) {
			t.Errorf("nginx ingress fixture is missing %q", required)
		}
	}

	receiver := readContractFile(t, filepath.Join(fixtureRoot, "webhook_receiver.py"))
	for _, required := range []string{
		"ThreadingHTTPServer", "MAX_BODY_BYTES", "X-Forwarded-Proto", "body_valid", "def log_message",
		"/__vpnctl_probe/status", "accepted_requests_lock",
	} {
		if !strings.Contains(receiver, required) {
			t.Errorf("webhook receiver is missing %q", required)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2ingress-spike.sh"))
	for _, required := range []string{
		"manual public IP is required", "assert_forward_ignored", "NGINX_INSTALLED_BY_SPIKE=pending",
		"apt-get install --no-install-recommends", "newkey rsa:2048", "subjectAltName=IP:",
		"-verify_ip", "--http$http_version", "node_http_request 1.1", "node_http_request 2",
		"set_webhook_executed: false", "uninstall_spike",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("ingress spike orchestrator is missing %q", required)
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

	limaTemplate := readContractFile(t, filepath.Join(repositoryRoot, "test", "v2lab", "lima.yaml"))
	if !strings.Contains(limaTemplate, "guestPort: 443") {
		t.Error("Lima template does not isolate guest port 443 from host forwarding")
	}
}
