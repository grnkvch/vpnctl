package tunnel

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestGatewayTLSIdentityProvisionerCreatesReusesAndRollsBack(t *testing.T) {
	state := tunnelLifecycleGatewayState(t)
	now := state.Host.InitializedAt.Add(time.Hour)
	secrets := &gatewayTLSMemorySecrets{values: map[model.SecretRef][]byte{}}
	provisioner, err := NewGatewayTLSIdentityProvisioner(secrets, GatewayTLSIdentityRuntime{
		NewUUID: func() (string, error) { return "30000000-0000-4000-8000-000000000099", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	installation, err := provisioner.Provision(context.Background(), state, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(installation.OwnedReferences) != 2 || installation.Certificate.Kind != model.CertificateTunnelServer {
		t.Fatalf("installation = %+v", installation)
	}
	certificatePEM := append([]byte(nil), secrets.values[GatewayTLSCertificateRef]...)
	privateKeyPEM := append([]byte(nil), secrets.values[GatewayTLSPrivateKeyRef]...)
	if err := ValidateGatewayTLSIdentity(certificatePEM, privateKeyPEM, installation.Certificate, state.Host.ID, now); err != nil {
		t.Fatal(err)
	}

	committed := state
	committed.Certificates = append(append([]model.Certificate{}, state.Certificates...), installation.Certificate)
	reused, err := provisioner.Provision(context.Background(), committed, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(reused.OwnedReferences) != 0 || !reflect.DeepEqual(reused.Certificate, installation.Certificate) {
		t.Fatalf("reused installation = %+v", reused)
	}
	if err := provisioner.Rollback(context.Background(), reused); err != nil || len(secrets.values) != 2 {
		t.Fatalf("rollback reused = %v, secrets = %d", err, len(secrets.values))
	}
	if err := provisioner.Rollback(context.Background(), installation); err != nil || len(secrets.values) != 0 {
		t.Fatalf("rollback fresh = %v, secrets = %d", err, len(secrets.values))
	}
}

func TestGatewayTLSIdentityProvisionerRejectsStoredTamper(t *testing.T) {
	state := tunnelLifecycleGatewayState(t)
	now := state.Host.InitializedAt.Add(time.Hour)
	secrets := &gatewayTLSMemorySecrets{values: map[model.SecretRef][]byte{}}
	provisioner, _ := NewGatewayTLSIdentityProvisioner(secrets, GatewayTLSIdentityRuntime{})
	installation, err := provisioner.Provision(context.Background(), state, now)
	if err != nil {
		t.Fatal(err)
	}
	state.Certificates = append(state.Certificates, installation.Certificate)
	secrets.values[GatewayTLSPrivateKeyRef][len(secrets.values[GatewayTLSPrivateKeyRef])-2] ^= 1
	if _, err := provisioner.Provision(context.Background(), state, now); err == nil {
		t.Fatal("tampered stored tunnel TLS key was accepted")
	}
}

func TestGatewayTLSIdentityProvisionerRollsBackPartialWrite(t *testing.T) {
	state := tunnelLifecycleGatewayState(t)
	secrets := &gatewayTLSMemorySecrets{values: map[model.SecretRef][]byte{}, failPut: GatewayTLSPrivateKeyRef}
	provisioner, _ := NewGatewayTLSIdentityProvisioner(secrets, GatewayTLSIdentityRuntime{})
	if _, err := provisioner.Provision(context.Background(), state, state.Host.InitializedAt.Add(time.Hour)); err == nil {
		t.Fatal("partial identity write succeeded")
	}
	if len(secrets.values) != 0 {
		t.Fatalf("partial identity retained %d secrets", len(secrets.values))
	}
}

type gatewayTLSMemorySecrets struct {
	values  map[model.SecretRef][]byte
	failPut model.SecretRef
}

func (secrets *gatewayTLSMemorySecrets) Get(reference model.SecretRef) ([]byte, error) {
	value, ok := secrets.values[reference]
	if !ok {
		return nil, store.ErrSecretNotFound
	}
	return append([]byte(nil), value...), nil
}

func (secrets *gatewayTLSMemorySecrets) PutIfAbsent(reference model.SecretRef, value []byte) error {
	if reference == secrets.failPut {
		return errors.New("injected put failure")
	}
	if _, exists := secrets.values[reference]; exists {
		return store.ErrSecretExists
	}
	secrets.values[reference] = append([]byte(nil), value...)
	return nil
}

func (secrets *gatewayTLSMemorySecrets) Delete(reference model.SecretRef) (bool, error) {
	if _, exists := secrets.values[reference]; !exists {
		return false, nil
	}
	delete(secrets.values, reference)
	return true, nil
}
