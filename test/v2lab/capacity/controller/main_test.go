package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestInitializeCreatesValidFullControllerIdentity(t *testing.T) {
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := initialize(paths); err != nil {
		t.Fatal(err)
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	if state.Host.Role != model.RoleGateway || state.EnrollmentIdentity == nil || len(state.Certificates) != 2 {
		t.Fatalf("capacity state does not carry the complete controller identity: %+v", state)
	}
	for _, reference := range []model.SecretRef{
		model.SecretRef(control.ControlCACertificateRef), control.ControlCAPrivateKeyRef,
		model.SecretRef(control.GatewayControlCertificateRef), control.GatewayControlPrivateKeyRef,
	} {
		kind, id, err := reference.Parts()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(paths.SecretsDir, kind, id)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("secret %s mode = %o", reference, info.Mode().Perm())
		}
	}
}
