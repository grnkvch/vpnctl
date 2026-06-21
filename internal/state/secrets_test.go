package state

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

type fakeServerKeyGenerator struct {
	calls int
	pair  ServerKeyPair
	err   error
}

func (g *fakeServerKeyGenerator) GenerateServerKeyPair(_ context.Context) (ServerKeyPair, error) {
	g.calls++
	if g.err != nil {
		return ServerKeyPair{}, g.err
	}
	return g.pair, nil
}

func TestEnsureServerKeyPairGeneratesAndStoresServerKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")
	cfg := DefaultServerConfig()
	cfg.PublicEndpoint = "198.211.99.116"
	if err := ConfigureServer(dir, cfg, false); err != nil {
		t.Fatalf("configure server: %v", err)
	}

	gen := &fakeServerKeyGenerator{pair: ServerKeyPair{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKey:  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
	}}
	got, created, err := EnsureServerKeyPair(context.Background(), dir, gen)
	if err != nil {
		t.Fatalf("ensure server key pair: %v", err)
	}
	if !created {
		t.Fatalf("expected keys to be created")
	}
	if got.PublicKey != "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" {
		t.Fatalf("unexpected public key: %q", got.PublicKey)
	}
	if gen.calls != 1 {
		t.Fatalf("expected generator to be called once, got %d", gen.calls)
	}

	privatePath := ServerPrivateKeyPath(dir)
	data, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	if string(data) != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" {
		t.Fatalf("unexpected private key file contents")
	}
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected private key mode 0600, got %o", got)
	}

	st, err := Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.Server.WireGuardPublicKey != "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" {
		t.Fatalf("expected public key in state, got %q", st.Server.WireGuardPublicKey)
	}
}

func TestEnsureServerKeyPairIsIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")
	cfg := DefaultServerConfig()
	cfg.PublicEndpoint = "198.211.99.116"
	if err := ConfigureServer(dir, cfg, false); err != nil {
		t.Fatalf("configure server: %v", err)
	}

	gen := &fakeServerKeyGenerator{pair: ServerKeyPair{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKey:  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
	}}
	if _, _, err := EnsureServerKeyPair(context.Background(), dir, gen); err != nil {
		t.Fatalf("ensure server key pair: %v", err)
	}

	gen.calls = 0
	got, created, err := EnsureServerKeyPair(context.Background(), dir, gen)
	if err != nil {
		t.Fatalf("ensure existing server key pair: %v", err)
	}
	if created {
		t.Fatalf("expected existing keys to be reused")
	}
	if got.PrivateKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" || got.PublicKey != "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" {
		t.Fatalf("unexpected key pair")
	}
	if gen.calls != 0 {
		t.Fatalf("expected generator not to be called, got %d", gen.calls)
	}
}

func TestEnsureServerKeyPairRequiresConfiguredServer(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")
	if _, err := Init(dir, false); err != nil {
		t.Fatalf("init state: %v", err)
	}

	_, _, err := EnsureServerKeyPair(context.Background(), dir, &fakeServerKeyGenerator{})
	if err == nil {
		t.Fatalf("expected missing server error")
	}
}
