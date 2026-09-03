package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
)

func TestFRPNativeConfigsWithPinnedBinaries(t *testing.T) {
	frpsBinary := os.Getenv("VPNCTL_FRPS")
	frpcBinary := os.Getenv("VPNCTL_FRPC")
	if frpsBinary == "" || frpcBinary == "" {
		t.Skip("set VPNCTL_FRPS and VPNCTL_FRPC to pinned Linux binaries")
	}
	root := t.TempDir()
	provider, err := NewFRPProvider(root, testFRPComponent(), staticFRPCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	server, err := provider.Render(context.Background(), RenderRequest{Plan: Plan{
		HostRole: model.RoleGateway, HostID: testGatewayHostID, Generation: 1,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := provider.Render(context.Background(), RenderRequest{Plan: Plan{
		HostRole: model.RoleNode, HostID: testNodeHostID, Generation: 1,
		ServerEndpoint: netip.MustParseAddrPort("10.67.0.1:17000"), Nodes: []NodeSession{testFRPSession(t)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	serverDirectory := filepath.Join(root, "etc", "vpnctl", "generated", "gateway")
	clientDirectory := filepath.Join(root, "etc", "vpnctl", "generated", "node")
	for _, directory := range []string{serverDirectory, clientDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	certificatePEM, privateKeyPEM := nativeFRPTLSIdentity(t)
	serverConfigPath := filepath.Join(serverDirectory, FRPServerConfigFileName)
	clientConfigPath := filepath.Join(clientDirectory, FRPClientConfigFileName)
	for path, content := range map[string][]byte{
		serverConfigPath: server.(FRPCandidate).Bytes(), clientConfigPath: client.(FRPCandidate).Bytes(),
		filepath.Join(serverDirectory, FRPServerCertificateName): certificatePEM,
		filepath.Join(serverDirectory, FRPServerPrivateKeyName):  privateKeyPEM,
		filepath.Join(clientDirectory, FRPServerCertificateName): certificatePEM,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := linuxplatform.OSProbeRunner{}
	if err := ValidatePinnedFRPConfig(context.Background(), runner, frpsBinary, serverConfigPath); err != nil {
		t.Fatalf("native frps validation failed: %v", err)
	}
	if err := ValidatePinnedFRPConfig(context.Background(), runner, frpcBinary, clientConfigPath); err != nil {
		t.Fatalf("native frpc validation failed: %v", err)
	}
}

func nativeFRPTLSIdentity(t *testing.T) ([]byte, []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: FRPTLSServerName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{FRPTLSServerName},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return certificatePEM, privateKeyPEM
}
