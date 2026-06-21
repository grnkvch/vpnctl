package state

import (
	"path/filepath"
	"testing"
)

func TestConfigureServerWritesServerState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")
	cfg := DefaultServerConfig()
	cfg.PublicEndpoint = "198.211.99.116"
	cfg.WireGuardSubnet = "10.10.10.0/24"
	cfg.DNSServers = []string{"1.1.1.1", "8.8.8.8"}
	cfg.ExternalInterface = "eth0"

	if err := ConfigureServer(dir, cfg, false); err != nil {
		t.Fatalf("configure server: %v", err)
	}

	st, err := Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.Server == nil {
		t.Fatalf("expected server to be configured")
	}
	if st.Server.PublicEndpoint != "198.211.99.116" {
		t.Fatalf("unexpected endpoint: %q", st.Server.PublicEndpoint)
	}
	if st.Server.WireGuardSubnet != "10.10.10.0/24" {
		t.Fatalf("unexpected subnet: %q", st.Server.WireGuardSubnet)
	}
	if st.Server.ExternalInterface != "eth0" {
		t.Fatalf("unexpected external interface: %q", st.Server.ExternalInterface)
	}
	if len(st.Server.DNSServers) != 2 {
		t.Fatalf("unexpected DNS servers: %#v", st.Server.DNSServers)
	}
}

func TestConfigureServerRejectsOverwriteWithoutForce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")
	cfg := DefaultServerConfig()
	cfg.PublicEndpoint = "198.211.99.116"

	if err := ConfigureServer(dir, cfg, false); err != nil {
		t.Fatalf("configure server: %v", err)
	}

	cfg.PublicEndpoint = "203.0.113.10"
	if err := ConfigureServer(dir, cfg, false); err == nil {
		t.Fatalf("expected overwrite to fail without force")
	}
}

func TestConfigureServerAllowsOverwriteWithForce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")
	cfg := DefaultServerConfig()
	cfg.PublicEndpoint = "198.211.99.116"

	if err := ConfigureServer(dir, cfg, false); err != nil {
		t.Fatalf("configure server: %v", err)
	}

	cfg.PublicEndpoint = "203.0.113.10"
	if err := ConfigureServer(dir, cfg, true); err != nil {
		t.Fatalf("force configure server: %v", err)
	}

	st, err := Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.Server.PublicEndpoint != "203.0.113.10" {
		t.Fatalf("expected endpoint overwrite, got %q", st.Server.PublicEndpoint)
	}
}

func TestConfigureServerPreservesPublicKeyOnForce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")
	cfg := DefaultServerConfig()
	cfg.PublicEndpoint = "198.211.99.116"

	if err := ConfigureServer(dir, cfg, false); err != nil {
		t.Fatalf("configure server: %v", err)
	}
	st, err := Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	st.Server.WireGuardPublicKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	if err := Save(dir, st); err != nil {
		t.Fatalf("save state: %v", err)
	}

	cfg.PublicEndpoint = "203.0.113.10"
	if err := ConfigureServer(dir, cfg, true); err != nil {
		t.Fatalf("force configure server: %v", err)
	}

	st, err = Load(dir)
	if err != nil {
		t.Fatalf("load state after force: %v", err)
	}
	if st.Server.WireGuardPublicKey != "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" {
		t.Fatalf("expected public key to be preserved")
	}
}

func TestConfigureServerValidatesInput(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")
	cfg := DefaultServerConfig()

	if err := ConfigureServer(dir, cfg, false); err == nil {
		t.Fatalf("expected missing endpoint to fail")
	}

	cfg.PublicEndpoint = "198.211.99.116"
	cfg.WireGuardSubnet = "not-cidr"
	if err := ConfigureServer(dir, cfg, false); err == nil {
		t.Fatalf("expected invalid subnet to fail")
	}

	cfg.WireGuardSubnet = DefaultWGSubnet
	cfg.DNSServers = []string{"not-ip"}
	if err := ConfigureServer(dir, cfg, false); err == nil {
		t.Fatalf("expected invalid DNS to fail")
	}
}
