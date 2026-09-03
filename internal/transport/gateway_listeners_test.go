package transport

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

func TestGatewayListenerProvisionerPublishesBothListenersCreateOnce(t *testing.T) {
	t.Parallel()

	paths, err := store.NewPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	credentials, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	runner := &standardKeyRunner{privateKey: standardTestKey(0x61), publicKey: standardTestKey(0x62)}
	provisioner, err := NewGatewayListenerProvisioner(credentials, runner, bytes.NewReader(bytes.Repeat([]byte{0x63}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	state := emptyGatewayListenerState()

	first, err := provisioner.Provision(context.Background(), state)
	if err != nil {
		t.Fatalf("Provision(first) error = %v", err)
	}
	firstFiles := first.ConfigFiles()
	if got := gatewayListenerConfigNames(firstFiles); !reflect.DeepEqual(got, GatewayListenerFileNames()) {
		t.Fatalf("gateway listener files = %v, want %v", got, GatewayListenerFileNames())
	}
	contents := gatewayListenerConfigContents(firstFiles)
	if err := ValidateGatewayRestrictedConfig(contents[RestrictedConfigFileName]); err != nil {
		t.Fatalf("restricted listener config = %v", err)
	}
	if !bytes.Contains(contents[StandardConfigFileName], []byte("ListenPort = 51820")) ||
		!bytes.Contains(contents[GatewayStandardReadyFileName], []byte("protocol=udp\nport=51820\n")) ||
		!bytes.Contains(contents[GatewayRestrictedReadyFileName], []byte("protocol=tcp\nport=8443\n")) {
		t.Fatalf("gateway listener publication is incomplete: %q", contents)
	}
	if bytes.Contains(contents[RestrictedConfigFileName], []byte("udp: true")) {
		t.Fatal("restricted gateway publication enabled native UDP")
	}
	for _, reference := range []model.SecretRef{GatewayStandardCredentialRef, GatewayRestrictedCredentialRef} {
		if _, err := credentials.Get(reference); err != nil {
			t.Fatalf("gateway credential %s is absent: %v", reference, err)
		}
		kind, id, _ := reference.Parts()
		if info, err := os.Stat(filepath.Join(paths.SecretsDir, kind, id)); err != nil || info.Mode().Perm() != store.SecretFileMode {
			t.Fatalf("gateway credential %s mode = %v, %v", reference, info, err)
		}
	}

	second, err := provisioner.Provision(context.Background(), state)
	if err != nil {
		t.Fatalf("Provision(second) error = %v", err)
	}
	if !reflect.DeepEqual(second.ConfigFiles(), firstFiles) || runner.generateCalls != 1 {
		t.Fatalf("repeat publication changed configs or credential: calls=%d", runner.generateCalls)
	}
	if err := provisioner.Rollback(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	for _, reference := range []model.SecretRef{GatewayStandardCredentialRef, GatewayRestrictedCredentialRef} {
		if _, err := credentials.Get(reference); err != nil {
			t.Fatalf("rollback of adopted publication removed %s: %v", reference, err)
		}
	}
	if err := provisioner.Rollback(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	for _, reference := range []model.SecretRef{GatewayStandardCredentialRef, GatewayRestrictedCredentialRef} {
		if _, err := credentials.Get(reference); !errors.Is(err, store.ErrSecretNotFound) {
			t.Fatalf("rollback retained newly created %s: %v", reference, err)
		}
	}
}

func TestGatewayListenersAndNodeSelectionHaveIndependentLifecycles(t *testing.T) {
	t.Parallel()

	identity := transportIdentity()
	standard := newFakeProvider(model.TransportStandard, RuntimeActive, HealthUnavailable)
	restricted := newFakeProvider(model.TransportRestricted, RuntimeStandby, HealthHealthy)
	manager := newTestManager(t, identity, model.TransportStandard, standard, restricted)
	before := manager.Selection()

	health, err := manager.ObserveActive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Condition != HealthUnavailable || manager.Selection() != before {
		t.Fatalf("node outage changed explicit selection: health=%+v before=%+v after=%+v", health, before, manager.Selection())
	}
	if len(restricted.calls) != 0 {
		t.Fatalf("node outage touched configured standby despite both gateway listeners being available: %v", restricted.calls)
	}
}

func TestGatewayListenerInstallationRejectsPartialOrReorderedPublication(t *testing.T) {
	t.Parallel()
	files := []GatewayListenerConfigFile{
		{Name: GatewayRestrictedReadyFileName, Content: []byte("ready\n")},
		{Name: GatewayStandardReadyFileName, Content: []byte("ready\n")},
		{Name: RestrictedConfigFileName, Content: []byte("restricted\n")},
		{Name: StandardConfigFileName, Content: []byte("standard\n")},
	}
	if _, err := NewGatewayListenerInstallation(files); err != nil {
		t.Fatalf("complete publication rejected: %v", err)
	}
	if _, err := NewGatewayListenerInstallation(files[:3]); err == nil {
		t.Fatal("partial gateway listener publication was accepted")
	}
	files[0], files[1] = files[1], files[0]
	if _, err := NewGatewayListenerInstallation(files); err == nil {
		t.Fatal("reordered gateway listener publication was accepted")
	}
}

func emptyGatewayListenerState() model.State {
	state := standardGatewayState()
	state.Clients = []model.Client{}
	state.Nodes = []model.Node{}
	state.Transports = []model.Transport{}
	state.HandshakeHost = &model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft",
		Hostname: "www.microsoft.com", SelectedAt: state.Host.InitializedAt,
	}
	state.Components.Components = append(state.Components.Components, restrictedComponentPin())
	return state
}

func gatewayListenerConfigNames(files []GatewayListenerConfigFile) []string {
	result := make([]string, len(files))
	for index, file := range files {
		result[index] = file.Name
	}
	return result
}

func gatewayListenerConfigContents(files []GatewayListenerConfigFile) map[string][]byte {
	result := make(map[string][]byte, len(files))
	for _, file := range files {
		result[file.Name] = append([]byte(nil), file.Content...)
	}
	return result
}

func TestGatewayListenerPublicationContainsNoSelectionOrFallbackSurface(t *testing.T) {
	for _, name := range GatewayListenerFileNames() {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "active") || strings.Contains(lower, "standby") || strings.Contains(lower, "fallback") {
			t.Fatalf("gateway listener artifact name exposes node selection semantics: %s", name)
		}
	}
}
