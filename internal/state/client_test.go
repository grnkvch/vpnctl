package state

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeClientKeyGenerator struct {
	calls int
	pair  ClientKeyPair
	err   error
}

func (g *fakeClientKeyGenerator) GenerateClientKeyPair(_ context.Context) (ClientKeyPair, error) {
	g.calls++
	if g.err != nil {
		return ClientKeyPair{}, g.err
	}
	return g.pair, nil
}

func TestCreateClientAllocatesIPAndStoresSecret(t *testing.T) {
	dir := configuredServerState(t, "10.66.0.0/24")
	gen := validFakeClientKeyGenerator()
	now := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)

	client, err := CreateClient(context.Background(), dir, ClientConfig{
		ID:       "macbook",
		Platform: "macos",
		Tags:     []string{"laptop", "personal"},
		Now:      now,
	}, gen)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	if client.ID != "macbook" {
		t.Fatalf("unexpected client id: %q", client.ID)
	}
	if client.Name != "macbook" {
		t.Fatalf("unexpected client name: %q", client.Name)
	}
	if client.Platform != "macos" {
		t.Fatalf("unexpected platform: %q", client.Platform)
	}
	if client.AssignedIP != "10.66.0.2" {
		t.Fatalf("unexpected assigned ip: %q", client.AssignedIP)
	}
	if client.Status != ClientStatusActive {
		t.Fatalf("unexpected status: %q", client.Status)
	}
	if client.WireGuardPublicKey != "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" {
		t.Fatalf("unexpected public key")
	}
	if !client.CreatedAt.Equal(now) {
		t.Fatalf("unexpected created_at: %s", client.CreatedAt)
	}

	privatePath := ClientPrivateKeyPath(dir, "macbook")
	data, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatalf("read client private key: %v", err)
	}
	if string(data) != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" {
		t.Fatalf("unexpected private key contents")
	}
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatalf("stat client private key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected client private key mode 0600, got %o", got)
	}

	st, err := Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(st.Clients) != 1 {
		t.Fatalf("expected one client, got %#v", st.Clients)
	}
}

func TestCreateClientRejectsDuplicateID(t *testing.T) {
	dir := configuredServerState(t, "10.66.0.0/24")
	gen := validFakeClientKeyGenerator()

	if _, err := CreateClient(context.Background(), dir, ClientConfig{ID: "iphone"}, gen); err != nil {
		t.Fatalf("create first client: %v", err)
	}
	if _, err := CreateClient(context.Background(), dir, ClientConfig{ID: "iphone"}, gen); err == nil {
		t.Fatalf("expected duplicate client id error")
	}
}

func TestCreateClientAllocatesNextAvailableIP(t *testing.T) {
	dir := configuredServerState(t, "10.66.0.0/24")
	gen := validFakeClientKeyGenerator()

	first, err := CreateClient(context.Background(), dir, ClientConfig{ID: "iphone"}, gen)
	if err != nil {
		t.Fatalf("create first client: %v", err)
	}
	second, err := CreateClient(context.Background(), dir, ClientConfig{ID: "macbook"}, gen)
	if err != nil {
		t.Fatalf("create second client: %v", err)
	}
	if first.AssignedIP != "10.66.0.2" || second.AssignedIP != "10.66.0.3" {
		t.Fatalf("unexpected assigned ips: %s, %s", first.AssignedIP, second.AssignedIP)
	}
}

func TestListGetAndRevokeClient(t *testing.T) {
	dir := configuredServerState(t, "10.66.0.0/24")
	gen := validFakeClientKeyGenerator()

	first, err := CreateClient(context.Background(), dir, ClientConfig{ID: "iphone"}, gen)
	if err != nil {
		t.Fatalf("create first client: %v", err)
	}
	if _, err := CreateClient(context.Background(), dir, ClientConfig{ID: "macbook"}, gen); err != nil {
		t.Fatalf("create second client: %v", err)
	}

	revokedAt := time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)
	revoked, err := RevokeClient(dir, RevokeClientConfig{ID: "iphone", Reason: "lost", Now: revokedAt})
	if err != nil {
		t.Fatalf("revoke client: %v", err)
	}
	if revoked.Status != ClientStatusRevoked {
		t.Fatalf("unexpected revoked status: %q", revoked.Status)
	}
	if revoked.AssignedIP != first.AssignedIP {
		t.Fatalf("revoke should preserve assigned IP")
	}
	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(revokedAt) {
		t.Fatalf("unexpected revoked_at: %#v", revoked.RevokedAt)
	}
	if revoked.RevocationReason != "lost" {
		t.Fatalf("unexpected revocation reason: %q", revoked.RevocationReason)
	}

	active, err := ListClients(dir, false)
	if err != nil {
		t.Fatalf("list active clients: %v", err)
	}
	if len(active) != 1 || active[0].ID != "macbook" {
		t.Fatalf("unexpected active clients: %#v", active)
	}

	all, err := ListClients(dir, true)
	if err != nil {
		t.Fatalf("list all clients: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected two clients, got %#v", all)
	}

	got, err := GetClient(dir, "iphone")
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if got.Status != ClientStatusRevoked {
		t.Fatalf("unexpected client status: %q", got.Status)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(revokedAt) || got.RevocationReason != "lost" {
		t.Fatalf("revocation metadata was not persisted: %#v", got)
	}
}

func TestRevokeClientIsIdempotent(t *testing.T) {
	dir := configuredServerState(t, "10.66.0.0/24")
	gen := validFakeClientKeyGenerator()
	if _, err := CreateClient(context.Background(), dir, ClientConfig{ID: "iphone"}, gen); err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := RevokeClient(dir, RevokeClientConfig{ID: "iphone"}); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if _, err := RevokeClient(dir, RevokeClientConfig{ID: "iphone"}); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
}

func TestRotateClientKeysUpdatesPublicKeyAndSecret(t *testing.T) {
	dir := configuredServerState(t, "10.66.0.0/24")
	if _, err := CreateClient(context.Background(), dir, ClientConfig{ID: "iphone"}, validFakeClientKeyGenerator()); err != nil {
		t.Fatalf("create client: %v", err)
	}

	rotated, err := RotateClientKeys(context.Background(), dir, "iphone", rotatedFakeClientKeyGenerator())
	if err != nil {
		t.Fatalf("rotate client keys: %v", err)
	}
	if rotated.ID != "iphone" {
		t.Fatalf("unexpected client id: %q", rotated.ID)
	}
	if rotated.Status != ClientStatusActive {
		t.Fatalf("unexpected client status: %q", rotated.Status)
	}
	if rotated.AssignedIP != "10.66.0.2" {
		t.Fatalf("unexpected assigned IP: %q", rotated.AssignedIP)
	}
	if rotated.WireGuardPublicKey != "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=" {
		t.Fatalf("unexpected rotated public key: %q", rotated.WireGuardPublicKey)
	}

	privateKey, err := ReadClientPrivateKey(dir, "iphone")
	if err != nil {
		t.Fatalf("read rotated private key: %v", err)
	}
	if privateKey != "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=" {
		t.Fatalf("unexpected rotated private key")
	}

	st, err := Load(dir)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if st.Clients[0].WireGuardPublicKey != rotated.WireGuardPublicKey {
		t.Fatalf("state public key was not updated")
	}
}

func TestRotateClientKeysRequiresActiveClient(t *testing.T) {
	dir := configuredServerState(t, "10.66.0.0/24")
	if _, err := CreateClient(context.Background(), dir, ClientConfig{ID: "iphone"}, validFakeClientKeyGenerator()); err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := RevokeClient(dir, RevokeClientConfig{ID: "iphone"}); err != nil {
		t.Fatalf("revoke client: %v", err)
	}

	if _, err := RotateClientKeys(context.Background(), dir, "iphone", rotatedFakeClientKeyGenerator()); err == nil {
		t.Fatalf("expected inactive client error")
	}
}

func TestDeleteClientMarksDeletedAndRemovesSecret(t *testing.T) {
	dir := configuredServerState(t, "10.66.0.0/24")
	if _, err := CreateClient(context.Background(), dir, ClientConfig{ID: "iphone"}, validFakeClientKeyGenerator()); err != nil {
		t.Fatalf("create client: %v", err)
	}
	privateKeyPath := ClientPrivateKeyPath(dir, "iphone")
	if _, err := os.Stat(privateKeyPath); err != nil {
		t.Fatalf("expected client private key before delete: %v", err)
	}

	deleted, err := DeleteClient(dir, DeleteClientConfig{ID: "iphone"})
	if err != nil {
		t.Fatalf("delete client: %v", err)
	}
	if deleted.Status != ClientStatusDeleted {
		t.Fatalf("unexpected deleted status: %q", deleted.Status)
	}
	if _, err := os.Stat(privateKeyPath); !os.IsNotExist(err) {
		t.Fatalf("expected private key to be removed, stat err: %v", err)
	}

	active, err := ListClients(dir, false)
	if err != nil {
		t.Fatalf("list active clients: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active clients, got %#v", active)
	}
	all, err := ListClients(dir, true)
	if err != nil {
		t.Fatalf("list all clients: %v", err)
	}
	if len(all) != 1 || all[0].Status != ClientStatusDeleted {
		t.Fatalf("expected deleted client in all list, got %#v", all)
	}
}

func TestCreateClientRequiresServer(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".vpnctl")
	if _, err := Init(dir, false); err != nil {
		t.Fatalf("init state: %v", err)
	}

	_, err := CreateClient(context.Background(), dir, ClientConfig{ID: "iphone"}, validFakeClientKeyGenerator())
	if err == nil {
		t.Fatalf("expected missing server error")
	}
}

func TestValidateClientConfig(t *testing.T) {
	for _, cfg := range []ClientConfig{
		{},
		{ID: "../iphone"},
		{ID: "iphone", Platform: "watchos"},
	} {
		if err := ValidateClientConfig(cfg); err == nil {
			t.Fatalf("expected validation error for %#v", cfg)
		}
	}
	if err := ValidateClientConfig(ClientConfig{ID: "iphone-15", Platform: "ios"}); err != nil {
		t.Fatalf("expected valid client config: %v", err)
	}
}

func TestNextClientIPReportsExhaustion(t *testing.T) {
	_, err := NextClientIP("10.66.0.0/30", []ClientState{{ID: "first", AssignedIP: "10.66.0.2"}})
	if err == nil {
		t.Fatalf("expected subnet exhaustion error")
	}
}

func configuredServerState(t *testing.T, subnet string) string {
	t.Helper()

	dir := filepath.Join(t.TempDir(), ".vpnctl")
	cfg := DefaultServerConfig()
	cfg.PublicEndpoint = "198.211.99.116"
	cfg.WireGuardSubnet = subnet
	if err := ConfigureServer(dir, cfg, false); err != nil {
		t.Fatalf("configure server: %v", err)
	}
	return dir
}

func validFakeClientKeyGenerator() *fakeClientKeyGenerator {
	return &fakeClientKeyGenerator{pair: ClientKeyPair{
		PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		PublicKey:  "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
	}}
}

func rotatedFakeClientKeyGenerator() *fakeClientKeyGenerator {
	return &fakeClientKeyGenerator{pair: ClientKeyPair{
		PrivateKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
		PublicKey:  "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
	}}
}
