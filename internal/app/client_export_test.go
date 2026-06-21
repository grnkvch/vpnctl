package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/state"
)

func TestExportClientWireGuardWritesConfig(t *testing.T) {
	dir := configuredExportState(t)

	result, err := ExportClient(ExportClientInput{
		StateDir: dir,
		ClientID: "iphone",
		Type:     ExportTypeWireGuard,
		SCPHint:  true,
	})
	if err != nil {
		t.Fatalf("export client: %v", err)
	}
	if result.Path != filepath.Join(dir, "generated", "delivery", "iphone.conf") {
		t.Fatalf("unexpected output path: %s", result.Path)
	}
	if !strings.Contains(result.SCPHint, "scp root@198.211.99.116:") {
		t.Fatalf("unexpected scp hint: %q", result.SCPHint)
	}

	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatalf("read exported config: %v", err)
	}
	got := string(data)
	for _, want := range []string{
		"[Interface]\n",
		"PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
		"Address = 10.66.0.2/24\n",
		"DNS = 1.1.1.1, 8.8.8.8\n",
		"PublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n",
		"Endpoint = 198.211.99.116:51820\n",
		"AllowedIPs = 0.0.0.0/0\n",
		"PersistentKeepalive = 25\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected config to contain %q, got:\n%s", want, got)
		}
	}

	info, err := os.Stat(result.Path)
	if err != nil {
		t.Fatalf("stat exported config: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected export mode 0600, got %o", got)
	}
}

func TestExportClientWireGuardSupportsCustomOutput(t *testing.T) {
	dir := configuredExportState(t)
	output := filepath.Join(t.TempDir(), "custom.conf")

	result, err := ExportClient(ExportClientInput{
		StateDir: dir,
		ClientID: "iphone",
		Type:     ExportTypeWireGuard,
		Output:   output,
	})
	if err != nil {
		t.Fatalf("export client: %v", err)
	}
	if result.Path != output {
		t.Fatalf("unexpected output path: %s", result.Path)
	}
	if result.SCPHint != "" {
		t.Fatalf("expected empty scp hint, got %q", result.SCPHint)
	}
}

func TestExportClientClashWritesProfile(t *testing.T) {
	dir := configuredExportState(t)

	result, err := ExportClient(ExportClientInput{
		StateDir: dir,
		ClientID: "iphone",
		Type:     ExportTypeClash,
		Ruleset:  DefaultRulesetID,
	})
	if err != nil {
		t.Fatalf("export clash profile: %v", err)
	}
	if result.Path != filepath.Join(dir, "generated", "delivery", "iphone.clash.yaml") {
		t.Fatalf("unexpected output path: %s", result.Path)
	}
	if result.Warning != "" {
		t.Fatalf("unexpected warning: %q", result.Warning)
	}

	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatalf("read clash profile: %v", err)
	}
	got := string(data)
	for _, want := range []string{
		"mode: rule\n",
		"    - 1.1.1.1\n",
		"    type: wireguard\n",
		"    server: 198.211.99.116\n",
		"    port: 51820\n",
		"    ip: 10.66.0.2\n",
		"    private-key: \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\n",
		"    public-key: \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"\n",
		"    udp: true\n",
		"      - 0.0.0.0/0\n",
		"  - DOMAIN-SUFFIX,chatgpt.com,VPN\n",
		"  - MATCH,DIRECT\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected clash profile to contain %q, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "MATCH,VPN") {
		t.Fatalf("clash profile should not route all traffic through VPN:\n%s", got)
	}
}

func TestExportClientClashUsesFallbackDNSWarning(t *testing.T) {
	dir := configuredExportState(t)
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	st.Server.DNSServers = nil
	if err := state.Save(dir, st); err != nil {
		t.Fatalf("save state: %v", err)
	}

	result, err := ExportClient(ExportClientInput{
		StateDir: dir,
		ClientID: "iphone",
		Type:     ExportTypeClash,
	})
	if err != nil {
		t.Fatalf("export clash profile: %v", err)
	}
	if result.Warning != ClashDNSWarning {
		t.Fatalf("unexpected warning: %q", result.Warning)
	}
	data, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatalf("read clash profile: %v", err)
	}
	if !strings.Contains(string(data), "    - 1.1.1.1\n    - 8.8.8.8\n") {
		t.Fatalf("expected fallback DNS, got:\n%s", string(data))
	}
}

func TestExportClientRequiresActiveClient(t *testing.T) {
	dir := configuredExportState(t)
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	st.Clients[0].Status = "revoked"
	if err := state.Save(dir, st); err != nil {
		t.Fatalf("save state: %v", err)
	}

	_, err = ExportClient(ExportClientInput{
		StateDir: dir,
		ClientID: "iphone",
		Type:     ExportTypeWireGuard,
	})
	if err == nil {
		t.Fatalf("expected inactive client error")
	}
}

func TestExportClientRequiresServerPublicKey(t *testing.T) {
	dir := configuredExportState(t)
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	st.Server.WireGuardPublicKey = ""
	if err := state.Save(dir, st); err != nil {
		t.Fatalf("save state: %v", err)
	}

	_, err = ExportClient(ExportClientInput{
		StateDir: dir,
		ClientID: "iphone",
		Type:     ExportTypeWireGuard,
	})
	if err == nil {
		t.Fatalf("expected missing server public key error")
	}
}

func configuredExportState(t *testing.T) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), ".vpnctl")
	cfg := state.DefaultServerConfig()
	cfg.PublicEndpoint = "198.211.99.116"
	cfg.DNSServers = []string{"1.1.1.1", "8.8.8.8"}
	if err := state.ConfigureServer(dir, cfg, false); err != nil {
		t.Fatalf("configure server: %v", err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	st.Server.WireGuardPublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	if err := state.Save(dir, st); err != nil {
		t.Fatalf("save state: %v", err)
	}

	_, err = state.CreateClient(context.Background(), dir, state.ClientConfig{ID: "iphone"}, fakeClientKeyGenerator{})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	return dir
}

type fakeClientKeyGenerator struct{}

func (fakeClientKeyGenerator) GenerateClientKeyPair(context.Context) (state.ClientKeyPair, error) {
	return state.ClientKeyPair{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKey:  "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
	}, nil
}
