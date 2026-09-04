package controller

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/lifecycle"
	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestSystemGatewayRestoreInspectRequiresAnActuallyCleanHost(t *testing.T) {
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	host := &systemGatewayRestoreHost{paths: paths}
	observed, err := host.Inspect(context.Background())
	if err != nil || observed.Initialized {
		t.Fatalf("clean host inspection = %+v, %v", observed, err)
	}

	for _, testCase := range []struct {
		name string
		root func(store.Paths) string
	}{
		{name: "config", root: func(paths store.Paths) string { return paths.ConfigDir }},
		{name: "state", root: func(paths store.Paths) string { return paths.StateDir }},
		{name: "runtime", root: func(paths store.Paths) string { return paths.RuntimeDir }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			isolated, _ := store.NewPaths(t.TempDir())
			candidate := testCase.root(isolated)
			if err := os.MkdirAll(candidate, 0o700); err != nil {
				t.Fatal(err)
			}
			_, err := (&systemGatewayRestoreHost{paths: isolated}).Inspect(context.Background())
			if !errors.Is(err, lifecycle.ErrGatewayRestoreConflict) {
				t.Fatalf("partial host inspection error = %v", err)
			}
		})
	}
}

func TestGatewayRestorePreflightSubtractsOnlyCurrentOwnedListeners(t *testing.T) {
	snapshot := linuxplatform.HostSnapshot{Listeners: []linuxplatform.Listener{
		{Protocol: "tcp", Address: "0.0.0.0", Port: 443},
		{Protocol: "tcp", Address: "0.0.0.0", Port: 8443},
		{Protocol: "udp", Address: "0.0.0.0", Port: 51820},
		{Protocol: "tcp", Address: "127.0.0.1", Port: 20000},
		{Protocol: "tcp", Address: "127.0.0.1", Port: 20001},
		{Protocol: "tcp", Address: "0.0.0.0", Port: 22},
	}}
	filtered := gatewayRestorePreflightSnapshot(snapshot, true, []int{20000})
	want := []linuxplatform.Listener{
		{Protocol: "tcp", Address: "127.0.0.1", Port: 20001},
		{Protocol: "tcp", Address: "0.0.0.0", Port: 22},
	}
	if !reflect.DeepEqual(filtered.Listeners, want) {
		t.Fatalf("filtered listeners = %+v, want %+v", filtered.Listeners, want)
	}
	if clean := gatewayRestorePreflightSnapshot(snapshot, false, nil); !reflect.DeepEqual(clean.Listeners, snapshot.Listeners) {
		t.Fatalf("clean-host preflight hid listeners: %+v", clean.Listeners)
	}
	if unavailable := restoreUnavailableLoopbackPorts(snapshot, []int{20000}); !reflect.DeepEqual(unavailable, []int{20001}) {
		t.Fatalf("unavailable restore ports = %v", unavailable)
	}
}

func TestValidateRestoredEnrollmentIdentityChecksKeyPairAndFingerprint(t *testing.T) {
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, 9, 5, 8, 0, 0, 0, time.UTC)
	material, err := control.GenerateGatewayControlMaterial(rand.Reader, "98000000-0000-4000-8000-000000000001", "10.67.0.1", issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.Put(model.SecretRef(control.EnrollmentPublicKeyRef), material.EnrollmentPublicKeyPEM); err != nil {
		t.Fatal(err)
	}
	if err := secrets.Put(control.EnrollmentPrivateKeyRef, material.EnrollmentPrivateKeyPEM); err != nil {
		t.Fatal(err)
	}
	state := model.State{EnrollmentIdentity: &model.EnrollmentIdentity{
		SchemaVersion: model.ResourceSchemaVersion, Algorithm: "Ed25519", Fingerprint: material.EnrollmentFingerprint,
		PublicKeyRef: control.EnrollmentPublicKeyRef, PrivateKeyRef: control.EnrollmentPrivateKeyRef,
		Generation: 1, CreatedAt: issuedAt,
	}}
	if err := validateRestoredEnrollmentIdentity(state, secrets); err != nil {
		t.Fatalf("valid enrollment identity rejected: %v", err)
	}

	other, err := control.GenerateGatewayControlMaterial(rand.Reader, "98000000-0000-4000-8000-000000000002", "10.67.0.1", issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := secrets.Put(control.EnrollmentPrivateKeyRef, other.EnrollmentPrivateKeyPEM); err != nil {
		t.Fatal(err)
	}
	if err := validateRestoredEnrollmentIdentity(state, secrets); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched enrollment key error = %v", err)
	}
	if err := secrets.Put(control.EnrollmentPrivateKeyRef, material.EnrollmentPrivateKeyPEM); err != nil {
		t.Fatal(err)
	}
	state.EnrollmentIdentity.Fingerprint = "sha256:" + strings.Repeat("0", 64)
	if err := validateRestoredEnrollmentIdentity(state, secrets); err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("mismatched enrollment fingerprint error = %v", err)
	}
}

func TestValidateRestoredCertificatesDoesNotRequireRevokedNodeMaterialExcludedFromBackup(t *testing.T) {
	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	nodeID := "98000000-0000-4000-8000-000000000004"
	state := model.State{
		Nodes: []model.Node{{ID: nodeID, Lifecycle: model.LifecycleRevoked}},
		Certificates: []model.Certificate{{
			ID: "98000000-0000-4000-8000-000000000005", Kind: model.CertificateControlNode,
			OwnerKind: "node", OwnerID: nodeID, CertificateRef: "control-cert:" + nodeID + "-g1",
		}},
	}
	if err := validateRestoredCertificates(state, secrets); err != nil {
		t.Fatalf("revoked node certificate material was required: %v", err)
	}
	state.Nodes[0].Lifecycle = model.LifecycleActive
	if err := validateRestoredCertificates(state, secrets); err == nil {
		t.Fatal("active node certificate material was not required")
	}
}

func TestRestoreTreeCopyAndSwapRollbackStayInsideOwnedRoots(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	destination := filepath.Join(root, "copy")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "value"), []byte("prior"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("value", filepath.Join(source, "current")); err != nil {
		t.Fatal(err)
	}
	if err := copyRestoreTree(context.Background(), source, destination); err != nil {
		t.Fatal(err)
	}
	if link, err := os.Readlink(filepath.Join(destination, "current")); err != nil || link != "value" {
		t.Fatalf("copied restore symlink = %q, %v", link, err)
	}

	unsafe := filepath.Join(root, "unsafe")
	if err := os.Mkdir(unsafe, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside", filepath.Join(unsafe, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := copyRestoreTree(context.Background(), unsafe, filepath.Join(root, "unsafe-copy")); err == nil || !strings.Contains(err.Error(), "unsafe symlink") {
		t.Fatalf("unsafe restore tree copy error = %v", err)
	}

	live := filepath.Join(root, "vpnctl")
	old := filepath.Join(root, ".vpnctl-restore-old-config-98000000-0000-4000-8000-000000000003")
	if err := os.Mkdir(live, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "value"), []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(old, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "value"), []byte("prior"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreSwappedRoot(live, old, true, true, true, "", ""); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(live, "value"))
	if err != nil || string(content) != "prior" {
		t.Fatalf("rolled-back root content = %q, %v", content, err)
	}
	if err := removeRestoreOwnedTree(filepath.Join(root, "foreign")); err == nil {
		t.Fatal("restore cleanup accepted a foreign root")
	}
}
