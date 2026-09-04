package ingress

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const (
	publicCertificateTestGatewayID = "81000000-0000-4000-8000-000000000001"
	publicCertificateTestID        = "81000000-0000-4000-8000-000000000002"
	publicCertificateTestIPv4      = "192.168.104.1"
)

func TestPublicCertificateProvisioningCreatesExactRootOnlyStableMaterial(t *testing.T) {
	t.Parallel()

	paths, secrets := publicCertificateTestStore(t)
	issuedAt := time.Date(2026, time.September, 4, 12, 30, 0, 0, time.UTC)
	provisioner, err := NewPublicCertificateProvisioner(secrets, PublicCertificateRuntime{
		Entropy: rand.Reader,
		NewUUID: func() (string, error) { return publicCertificateTestID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	installation, err := provisioner.Provision(context.Background(), PublicCertificateRequest{
		GatewayID: publicCertificateTestGatewayID, PublicIPv4: publicCertificateTestIPv4, IssuedAt: issuedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(installation); !errors.Is(err, output.ErrSensitiveSerialization) {
		t.Fatalf("installation serialization error = %v", err)
	}
	record := installation.Certificate
	if record.ID != publicCertificateTestID || record.Kind != model.CertificatePublicIngress ||
		record.OwnerID != publicCertificateTestGatewayID || record.Subject != "CN="+publicCertificateTestIPv4 ||
		!reflect.DeepEqual(record.SANs, []string{"IP:" + publicCertificateTestIPv4}) ||
		record.NotAfter.Sub(record.NotBefore) != PublicCertificateValidity || record.WarningDays != PublicCertificateWarningDays ||
		record.Generation != 1 || record.CertificateRef != PublicCertificateRef || record.PrivateKeyRef != PublicCertificatePrivateKeyRef {
		t.Fatalf("public certificate record = %+v", record)
	}
	certificatePEM, err := secrets.Get(model.SecretRef(PublicCertificateRef))
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM, err := secrets.Get(PublicCertificatePrivateKeyRef)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(certificatePEM)
	defer clear(privateKeyPEM)
	certificate, err := ValidatePublicCertificatePEM(certificatePEM, record, publicCertificateTestIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.SignatureAlgorithm != x509.SHA256WithRSA || !certificate.NotBefore.Equal(issuedAt) ||
		certificate.NotAfter.Sub(certificate.NotBefore) != 1825*24*time.Hour {
		t.Fatalf("certificate validity/signature = %s, %s..%s", certificate.SignatureAlgorithm, certificate.NotBefore, certificate.NotAfter)
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.N.BitLen() != 2048 {
		t.Fatalf("certificate public key = %T", certificate.PublicKey)
	}
	block, rest := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("stored ingress private key is not one PKCS#8 PEM block")
	}
	parsedPrivate, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := parsedPrivate.(*rsa.PrivateKey)
	if !ok || privateKey.N.Cmp(publicKey.N) != 0 {
		t.Fatal("stored ingress private key does not match public certificate")
	}
	for _, reference := range []model.SecretRef{model.SecretRef(PublicCertificateRef), PublicCertificatePrivateKeyRef} {
		kind, id, _ := reference.Parts()
		info, err := os.Stat(filepath.Join(paths.SecretsDir, kind, id))
		if err != nil || info.Mode().Perm() != store.SecretFileMode {
			t.Fatalf("stored ingress material %s mode = %v, %v", reference, info, err)
		}
	}
	if _, err := provisioner.Provision(context.Background(), PublicCertificateRequest{
		GatewayID: publicCertificateTestGatewayID, PublicIPv4: publicCertificateTestIPv4, IssuedAt: issuedAt,
	}); !errors.Is(err, store.ErrSecretExists) {
		t.Fatalf("second provisioning error = %v", err)
	}
	certificateAfter, _ := secrets.Get(model.SecretRef(PublicCertificateRef))
	defer clear(certificateAfter)
	if !bytes.Equal(certificateAfter, certificatePEM) {
		t.Fatal("conflicting provisioning replaced stable public certificate")
	}
}

func TestPublicCertificateInspectionWarningBoundaries(t *testing.T) {
	t.Parallel()

	_, _, installation := provisionPublicCertificateFixture(t)
	state := publicCertificateState(installation.Certificate)
	warning := installation.Certificate.NotAfter.Add(-PublicCertificateWarningWindow)
	for _, test := range []struct {
		name string
		now  time.Time
		want PublicCertificateCondition
	}{
		{name: "healthy", now: warning.Add(-time.Second), want: PublicCertificateHealthy},
		{name: "warning boundary", now: warning, want: PublicCertificateExpiring},
		{name: "before expiry", now: installation.Certificate.NotAfter.Add(-time.Second), want: PublicCertificateExpiring},
		{name: "expiry boundary", now: installation.Certificate.NotAfter, want: PublicCertificateExpired},
		{name: "expired", now: installation.Certificate.NotAfter.Add(time.Second), want: PublicCertificateExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, err := InspectPublicCertificate(state, test.now)
			if err != nil {
				t.Fatal(err)
			}
			if status.Condition != test.want || status.WarningStartsAt != warning ||
				status.PublicIPv4 != publicCertificateTestIPv4 || status.Fingerprint != installation.Certificate.Fingerprint {
				t.Fatalf("status = %+v", status)
			}
		})
	}

	missing := state
	missing.Certificates = []model.Certificate{}
	if _, err := InspectPublicCertificate(missing, warning); !errors.Is(err, ErrPublicCertificateNotFound) {
		t.Fatalf("missing certificate error = %v", err)
	}
	wrongIP := state
	wrongIP.Host.PublicIPv4 = "192.168.104.2"
	if _, err := InspectPublicCertificate(wrongIP, warning); !errors.Is(err, ErrPublicCertificateInvalid) {
		t.Fatalf("wrong public IP error = %v", err)
	}
}

func TestPublicCertificateExportWritesOnlyPublicPEMWithoutReplacement(t *testing.T) {
	t.Parallel()

	paths, secrets, installation := provisionPublicCertificateFixture(t)
	state := publicCertificateState(installation.Certificate)
	destination := DefaultPublicCertificateExportPath(paths.ExportsDir)
	result, err := ExportPublicCertificate(state, secrets, destination)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Path != destination || result.Fingerprint != installation.Certificate.Fingerprint {
		t.Fatalf("first export = %+v", result)
	}
	exported, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(exported, []byte("PRIVATE KEY")) || len(exported) > publicCertificateMaximumBytes {
		t.Fatal("public certificate export contains private or oversized material")
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("public certificate export mode = %v, %v", info, err)
	}
	second, err := ExportPublicCertificate(state, secrets, destination)
	if err != nil || second.Changed {
		t.Fatalf("idempotent export = %+v, %v", second, err)
	}

	occupied := filepath.Join(paths.ExportsDir, "occupied.crt")
	if err := os.WriteFile(occupied, []byte("operator-owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportPublicCertificate(state, secrets, occupied); !errors.Is(err, ErrPublicCertificateExported) {
		t.Fatalf("occupied export error = %v", err)
	}
	content, _ := os.ReadFile(occupied)
	if string(content) != "operator-owned\n" {
		t.Fatalf("occupied export changed to %q", content)
	}
	target := filepath.Join(paths.ExportsDir, "target")
	if err := os.WriteFile(target, []byte("target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(paths.ExportsDir, "symlink.crt")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportPublicCertificate(state, secrets, symlink); !errors.Is(err, ErrPublicCertificateUnsafePath) {
		t.Fatalf("symlink export error = %v", err)
	}
	if content, _ := os.ReadFile(target); string(content) != "target\n" {
		t.Fatalf("symlink target changed to %q", content)
	}
}

func TestPublicCertificateOpenSSLAndTelegramFixtureCompatibility(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed")
	}
	material, err := GeneratePublicCertificate(rand.Reader, publicCertificateTestIPv4, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.PrivateKeyPEM)
	path := filepath.Join(t.TempDir(), "gateway.crt")
	if err := os.WriteFile(path, material.CertificatePEM, 0o644); err != nil {
		t.Fatal(err)
	}
	text, err := exec.Command(openssl, "x509", "-in", path, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509: %v: %s", err, text)
	}
	if !bytes.Contains(text, []byte("2048 bit")) || !bytes.Contains(bytes.ToLower(text), []byte("sha256withrsaencryption")) ||
		!bytes.Contains(text, []byte("IP Address:"+publicCertificateTestIPv4)) {
		t.Fatalf("openssl certificate text lacks Telegram-compatible shape: %s", text)
	}
	verification, err := exec.Command(openssl, "verify", "-CAfile", path, "-verify_ip", publicCertificateTestIPv4, path).CombinedOutput()
	if err != nil || !bytes.Contains(verification, []byte(": OK")) {
		t.Fatalf("openssl verify_ip: %v: %s", err, verification)
	}
	fixturePath := os.Getenv("VPNCTL_TELEGRAM_GATE_FIXTURE")
	if fixturePath == "" {
		fixturePath = filepath.Join("..", "..", "test", "v2lab", "ingress", "telegram_webhook_gate.py")
	}
	fixture, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"read_public_certificate", `b"BEGIN CERTIFICATE"`, `b"PRIVATE KEY"`, `name="certificate"`, `filename="gateway.crt"`} {
		if !bytes.Contains(fixture, []byte(required)) {
			t.Fatalf("Telegram upload fixture lacks %q", required)
		}
	}
	if len(material.CertificatePEM) > 64*1024 || bytes.Contains(material.CertificatePEM, []byte("PRIVATE KEY")) {
		t.Fatal("generated certificate violates Telegram fixture public upload boundary")
	}
}

func TestPublicCertificateRejectsInvalidInputsAndMetadataDrift(t *testing.T) {
	t.Parallel()

	issuedAt := time.Date(2026, time.September, 4, 12, 30, 0, 0, time.UTC)
	for _, address := range []string{"", "127.0.0.1", "2001:db8::1", "192.168.104.001"} {
		if _, err := GeneratePublicCertificate(rand.Reader, address, issuedAt); !errors.Is(err, ErrPublicCertificateInvalid) {
			t.Fatalf("GeneratePublicCertificate(%q) error = %v", address, err)
		}
	}
	if _, err := GeneratePublicCertificate(nil, publicCertificateTestIPv4, issuedAt); err == nil {
		t.Fatal("nil entropy was accepted")
	}
	_, secrets, installation := provisionPublicCertificateFixture(t)
	certificatePEM, err := secrets.Get(model.SecretRef(PublicCertificateRef))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(certificatePEM)
	drifted := installation.Certificate
	drifted.Fingerprint = "sha256:" + strings.Repeat("f", 64)
	if _, err := ValidatePublicCertificatePEM(certificatePEM, drifted, publicCertificateTestIPv4); !errors.Is(err, ErrPublicCertificateInvalid) {
		t.Fatalf("metadata drift error = %v", err)
	}
	privateKeyPEM, err := secrets.Get(PublicCertificatePrivateKeyRef)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateKeyPEM)
	if _, err := ValidatePublicCertificatePEM(append(certificatePEM, privateKeyPEM...), installation.Certificate, publicCertificateTestIPv4); !errors.Is(err, ErrPublicCertificateInvalid) {
		t.Fatalf("mixed public/private PEM error = %v", err)
	}
}

func provisionPublicCertificateFixture(t *testing.T) (store.Paths, *store.SecretStore, PublicCertificateInstallation) {
	t.Helper()
	paths, secrets := publicCertificateTestStore(t)
	provisioner, err := NewPublicCertificateProvisioner(secrets, PublicCertificateRuntime{
		Entropy: rand.Reader,
		NewUUID: func() (string, error) { return publicCertificateTestID, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	installation, err := provisioner.Provision(context.Background(), PublicCertificateRequest{
		GatewayID: publicCertificateTestGatewayID, PublicIPv4: publicCertificateTestIPv4,
		IssuedAt: time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return paths, secrets, installation
}

func publicCertificateTestStore(t *testing.T) (store.Paths, *store.SecretStore) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{paths.StateDir, paths.SecretsDir, paths.ExportsDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	return paths, secrets
}

func publicCertificateState(certificate model.Certificate) model.State {
	initializedAt := certificate.NotBefore.Add(-time.Hour)
	return model.State{
		SchemaVersion: model.StateSchemaVersion,
		Generation:    1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion, ID: publicCertificateTestGatewayID, Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: initializedAt,
			PublicIPv4: publicCertificateTestIPv4, ExternalInterface: "eth0", SSHPort: 22,
			ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
		},
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{},
		Presets: []model.Preset{}, Policies: []model.Policy{}, Transports: []model.Transport{},
		Exposes: []model.Expose{}, Certificates: []model.Certificate{certificate}, Operations: []model.Operation{},
		Logging: []model.LoggingSession{}, Backups: []model.Backup{},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1, VPNCTLVersion: "v2.0.0-test",
			ControlProtocols: []string{"1.0"}, StateSchemaMinimum: model.StateSchemaVersion, StateSchemaMaximum: model.StateSchemaVersion,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1, MigrationReversible: true,
			Components: []model.ComponentPin{{
				Name: "vpnctl", Version: "v2.0.0-test", Source: "bundle:vpnctl", Bundled: true,
				SHA256: strings.Repeat("a", 64), Capabilities: []string{"controller"},
			}},
		},
	}
}
