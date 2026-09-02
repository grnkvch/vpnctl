package regression

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2ControlSpikeContract(t *testing.T) {
	t.Parallel()

	repositoryRoot := filepath.Join("..", "..")
	fixtureRoot := filepath.Join(repositoryRoot, "test", "v2lab", "control")
	manifestData := readContractFile(t, filepath.Join(fixtureRoot, "manifest.json"))
	var manifest struct {
		Status string `json:"status"`
		PKI    struct {
			Algorithm         string `json:"algorithm"`
			SerialBits        int    `json:"serial_bits"`
			CAValidityDays    int    `json:"ca_validity_days"`
			LeafValidityDays  int    `json:"leaf_validity_days"`
			RenewalWindowDays int    `json:"renewal_window_days"`
			NodeURITemplate   string `json:"node_uri_template"`
		} `json:"pki"`
		Enrollment struct {
			Algorithm         string `json:"algorithm"`
			Transcript        string `json:"transcript"`
			InviteSecretBytes int    `json:"invite_secret_bytes"`
			NonceBytes        int    `json:"nonce_bytes"`
			ClockSkewSeconds  int    `json:"clock_skew_seconds"`
		} `json:"enrollment"`
		RPC struct {
			Protocol                 string `json:"protocol"`
			PathPrefix               string `json:"path_prefix"`
			TLSMinimum               string `json:"tls_minimum"`
			HTTP                     string `json:"http"`
			RequestBytes             int    `json:"request_bytes"`
			ResponseBytes            int    `json:"response_bytes"`
			HeaderBytes              int    `json:"header_bytes"`
			MaxJSONDepth             int    `json:"max_json_depth"`
			ReadHeaderSeconds        int    `json:"read_header_seconds"`
			ReadBodySeconds          int    `json:"read_body_seconds"`
			WriteSeconds             int    `json:"write_seconds"`
			IdleSeconds              int    `json:"idle_seconds"`
			MaxConcurrentConnections int    `json:"max_concurrent_connections"`
		} `json:"rpc"`
	}
	if err := json.Unmarshal([]byte(manifestData), &manifest); err != nil {
		t.Fatalf("decode control spike manifest: %v", err)
	}
	if manifest.Status != "spike-only" || manifest.PKI.Algorithm != "Ed25519" || manifest.PKI.SerialBits != 128 ||
		manifest.PKI.CAValidityDays != 3650 || manifest.PKI.LeafValidityDays != 1825 || manifest.PKI.RenewalWindowDays != 180 ||
		manifest.PKI.NodeURITemplate != "urn:vpnctl:node:<uuid>" {
		t.Fatalf("unexpected control PKI contract: %+v", manifest.PKI)
	}
	if manifest.Enrollment.Algorithm != "Ed25519" || manifest.Enrollment.Transcript != "vpnctl-enrollment-transcript-v1" ||
		manifest.Enrollment.InviteSecretBytes != 32 || manifest.Enrollment.NonceBytes != 16 || manifest.Enrollment.ClockSkewSeconds != 120 {
		t.Fatalf("unexpected enrollment signature contract: %+v", manifest.Enrollment)
	}
	if manifest.RPC.Protocol != "1.0" || manifest.RPC.PathPrefix != "/rpc/v1/" || manifest.RPC.TLSMinimum != "1.3" || manifest.RPC.HTTP != "1.1" ||
		manifest.RPC.RequestBytes != 65536 || manifest.RPC.ResponseBytes != 262144 || manifest.RPC.HeaderBytes != 8192 || manifest.RPC.MaxJSONDepth != 32 ||
		manifest.RPC.ReadHeaderSeconds != 2 || manifest.RPC.ReadBodySeconds != 5 || manifest.RPC.WriteSeconds != 5 || manifest.RPC.IdleSeconds != 5 ||
		manifest.RPC.MaxConcurrentConnections != 16 {
		t.Fatalf("unexpected control RPC contract: %+v", manifest.RPC)
	}

	tests := readContractFile(t, filepath.Join(fixtureRoot, "control_spike_test.go"))
	for _, required := range []string{
		"x509.PureEd25519", "randomSerial", "urn:vpnctl:node:", "signNodeCSR",
		"vpnctl-enrollment-transcript-v1", "canonicalTranscript", "signed enrollment transcript replayed",
		"openssl", "pkeyutl", "needsRenewal", "dual trust", "tls.RequireAndVerifyClientCert",
		"tls.VersionTLS13", "http/1.1", "DisallowUnknownFields", "duplicate JSON key",
		"http.MaxBytesReader", "limitedListener", "ReadHeaderTimeout", "MaxHeaderBytes",
	} {
		if !strings.Contains(tests, required) {
			t.Errorf("control spike fixture is missing %q", required)
		}
	}

	orchestrator := readContractFile(t, filepath.Join(repositoryRoot, "scripts", "v2control-spike.sh"))
	for _, required := range []string{
		"assert_lab_instance", "assert_other_spikes_inactive", "refusing to overwrite unowned control spike path",
		"GOOS=linux GOARCH=amd64 CGO_ENABLED=0", "VPNCTL_V2_CONTROL_SPIKE=1", "/usr/bin/time -v",
		"uninstall_internal true", "assert_no_test_process", "private_loopback_listener_only",
	} {
		if !strings.Contains(orchestrator, required) {
			t.Errorf("control spike orchestrator is missing %q", required)
		}
	}
}
