package control

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestGatewayIdentityProvisionerStoresRootOnlyMetadataWithoutPublicIngress(t *testing.T) {
	t.Parallel()

	secretStore, paths := newGatewayIdentitySecretStore(t)
	ids := []string{
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
	}
	provisioner, err := NewGatewayIdentityProvisioner(secretStore, GatewayIdentityRuntime{
		Entropy: rand.Reader,
		NewUUID: func() (string, error) {
			id := ids[0]
			ids = ids[1:]
			return id, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC)
	installation, err := provisioner.Provision(context.Background(), GatewayIdentityRequest{
		GatewayID: testGatewayID, NodeCIDR: "10.67.0.0/24", Initialized: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(installation.Certificates) != 2 || installation.Certificates[0].Kind != model.CertificateControlCA || installation.Certificates[1].Kind != model.CertificateControlServer {
		t.Fatalf("certificate metadata = %+v", installation.Certificates)
	}
	for _, certificate := range installation.Certificates {
		if certificate.Kind == model.CertificatePublicIngress || certificate.OwnerID != testGatewayID || certificate.OwnerKind != "host" || certificate.PrivateKeyRef == "" {
			t.Fatalf("control/public trust boundary = %+v", certificate)
		}
	}
	if installation.EnrollmentIdentity.Algorithm != "Ed25519" || installation.EnrollmentIdentity.Fingerprint == installation.Certificates[0].Fingerprint ||
		installation.EnrollmentIdentity.PrivateKeyRef == installation.Certificates[0].PrivateKeyRef {
		t.Fatalf("enrollment identity boundary = %+v", installation.EnrollmentIdentity)
	}
	wantReferences := []model.SecretRef{
		model.SecretRef(ControlCACertificateRef), ControlCAPrivateKeyRef,
		model.SecretRef(GatewayControlCertificateRef), GatewayControlPrivateKeyRef,
		model.SecretRef(EnrollmentPublicKeyRef), EnrollmentPrivateKeyRef,
	}
	if !reflect.DeepEqual(installation.OwnedReferences, wantReferences) {
		t.Fatalf("owned references = %v, want %v", installation.OwnedReferences, wantReferences)
	}
	for _, reference := range wantReferences {
		content, err := secretStore.Get(reference)
		if err != nil || len(content) == 0 {
			t.Fatalf("stored %s = %d bytes, %v", reference, len(content), err)
		}
		kind, id, _ := reference.Parts()
		for _, path := range []string{paths.SecretsDir, filepath.Join(paths.SecretsDir, kind)} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != store.SecretDirectoryMode {
				t.Fatalf("root-only path %s = %v, %v", path, info, err)
			}
		}
		path := filepath.Join(paths.SecretsDir, kind, id)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != store.SecretFileMode {
			t.Fatalf("root-only secret %s = %v, %v", path, info, err)
		}
	}
	if err := provisioner.Rollback(context.Background(), installation); err != nil {
		t.Fatal(err)
	}
	if err := provisioner.Rollback(context.Background(), installation); err != nil {
		t.Fatalf("idempotent rollback: %v", err)
	}
	for _, reference := range wantReferences {
		if _, err := secretStore.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("rolled-back reference %s error = %v", reference, err)
		}
	}
}

func TestGatewayIdentityProvisionerPreservesConflictingForeignIdentity(t *testing.T) {
	t.Parallel()

	secretStore, _ := newGatewayIdentitySecretStore(t)
	foreign := []byte("foreign-public-certificate")
	if err := secretStore.PutIfAbsent(model.SecretRef(GatewayControlCertificateRef), foreign); err != nil {
		t.Fatal(err)
	}
	sequence := []string{
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
	}
	provisioner, _ := NewGatewayIdentityProvisioner(secretStore, GatewayIdentityRuntime{
		Entropy: rand.Reader,
		NewUUID: func() (string, error) {
			id := sequence[0]
			sequence = sequence[1:]
			return id, nil
		},
	})
	_, err := provisioner.Provision(context.Background(), GatewayIdentityRequest{
		GatewayID: testGatewayID, NodeCIDR: model.DefaultNodeCIDR,
		Initialized: time.Date(2026, time.September, 2, 18, 0, 0, 0, time.UTC),
	})
	if !errors.Is(err, store.ErrSecretExists) {
		t.Fatalf("Provision(conflict) error = %v", err)
	}
	stored, err := secretStore.Get(model.SecretRef(GatewayControlCertificateRef))
	if err != nil || string(stored) != string(foreign) {
		t.Fatalf("foreign identity = %q, %v", stored, err)
	}
	for _, rolledBack := range []model.SecretRef{model.SecretRef(ControlCACertificateRef), ControlCAPrivateKeyRef} {
		if _, err := secretStore.Get(rolledBack); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("partial identity %s remains: %v", rolledBack, err)
		}
	}
}

func TestGatewayIdentityRollbackRefusesUnownedReference(t *testing.T) {
	t.Parallel()

	secretStore, _ := newGatewayIdentitySecretStore(t)
	foreignRef := model.SecretRef("public-key:webhook")
	if err := secretStore.PutIfAbsent(foreignRef, []byte("foreign")); err != nil {
		t.Fatal(err)
	}
	provisioner, _ := NewGatewayIdentityProvisioner(secretStore, GatewayIdentityRuntime{})
	err := provisioner.Rollback(context.Background(), GatewayIdentityInstallation{OwnedReferences: []model.SecretRef{foreignRef}})
	if err == nil {
		t.Fatal("Rollback(foreign) error = nil")
	}
	stored, readErr := secretStore.Get(foreignRef)
	if readErr != nil || string(stored) != "foreign" {
		t.Fatalf("foreign rollback target = %q, %v", stored, readErr)
	}
}

func newGatewayIdentitySecretStore(t *testing.T) (*store.SecretStore, store.Paths) {
	t.Helper()
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secretStore, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	return secretStore, paths
}
