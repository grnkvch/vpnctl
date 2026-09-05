package controller

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	linuxplatform "github.com/vgrinkevich/vpnctl/internal/platform/linux"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/transport"
)

func TestSystemGatewayClientRuntimePublishesAndRestartsBothListeners(t *testing.T) {
	paths, stateStore := controllerTestState(t, model.RoleGateway)
	state, err := stateStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	state.HandshakeHost = &model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: 1, CandidateID: "microsoft",
		Hostname: "www.microsoft.com", SelectedAt: time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC),
	}
	state.Components.Components = append(state.Components.Components, model.ComponentPin{
		Name: transport.RestrictedProviderName, Version: transport.RestrictedProviderVersion, Source: "vpnctl-release-bundle", Bundled: true,
		SHA256:       transport.RestrictedProviderSHA256,
		Capabilities: []string{"tun-routing", "redir-host-split-dns", "shadowsocks-2022-blake3-aes-256-gcm", "shadowtls-v3-strict", "uot-v2"},
	})
	encoded, err := model.EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.StateFile, encoded, store.StateFileMode); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{paths.ConfigDir, filepath.Join(paths.Root, "etc", "systemd", "system")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		t.Fatal(err)
	}
	runner := &clientRuntimeProbeRunner{}
	keyRunner := clientRuntimeKeyRunner{}
	runtime, err := newSystemGatewayClientRuntime(paths, stateStore, secrets, runner, keyRunner)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	for _, name := range transport.GatewayListenerFileNames() {
		path := filepath.Join(paths.ConfigDir, "generated", "gateway", name)
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("published config %s: info=%v err=%v", path, info, err)
		}
	}
	wantTail := [][]string{{"restart", "vpnctl-standard.service"}, {"restart", "vpnctl-restricted.service"}}
	if len(runner.commands) < len(wantTail) {
		t.Fatalf("systemctl commands = %v", runner.commands)
	}
	gotTail := runner.commands[len(runner.commands)-len(wantTail):]
	if !reflect.DeepEqual(gotTail, wantTail) {
		t.Fatalf("restart commands = %v, want %v", gotTail, wantTail)
	}
}

type clientRuntimeProbeRunner struct {
	commands [][]string
}

func (runner *clientRuntimeProbeRunner) Run(_ context.Context, command linuxplatform.ProbeCommand) (linuxplatform.ProbeResult, error) {
	if command.Name == "systemctl" {
		runner.commands = append(runner.commands, append([]string(nil), command.Args...))
	}
	return linuxplatform.ProbeResult{}, nil
}

type clientRuntimeKeyRunner struct{}

func (clientRuntimeKeyRunner) Run(_ context.Context, name string, args []string, _ string) (string, error) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if name == "wg" && len(args) == 1 && (args[0] == "genkey" || args[0] == "pubkey") {
		return key + "\n", nil
	}
	return "", nil
}
