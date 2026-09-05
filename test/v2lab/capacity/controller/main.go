package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/controller"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const gatewayID = "16900000-0000-4000-8000-000000000001"

func main() {
	root := flag.String("root", "", "isolated filesystem root")
	flag.Parse()
	if *root == "" || !strings.HasPrefix(*root, "/") || flag.NArg() != 1 {
		fatal("usage: capacity-controller --root /absolute/root <init|serve>")
	}
	paths, err := store.NewPaths(*root)
	if err != nil {
		fatal(err.Error())
	}
	switch flag.Arg(0) {
	case "init":
		if err := initialize(paths); err != nil {
			fatal(err.Error())
		}
	case "serve":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := controller.RunSystemController(ctx, paths); err != nil {
			fatal(err.Error())
		}
	default:
		fatal("unknown command")
	}
}

func initialize(paths store.Paths) error {
	for _, directory := range []string{paths.StateDir, paths.RuntimeDir, paths.ExportsDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return err
		}
	}
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return err
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return err
	}
	ids := []string{
		"16900000-0000-4000-8000-000000000011",
		"16900000-0000-4000-8000-000000000012",
	}
	nextID := func() (string, error) {
		if len(ids) == 0 {
			return "", fmt.Errorf("capacity identity UUIDs exhausted")
		}
		value := ids[0]
		ids = ids[1:]
		return value, nil
	}
	provisioner, err := control.NewGatewayIdentityProvisioner(secrets, control.GatewayIdentityRuntime{
		Entropy: rand.Reader, NewUUID: nextID,
	})
	if err != nil {
		return err
	}
	initialized := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	identity, err := provisioner.Provision(context.Background(), control.GatewayIdentityRequest{
		GatewayID: gatewayID, NodeCIDR: model.DefaultNodeCIDR, Initialized: initialized,
	})
	if err != nil {
		return err
	}
	state := model.State{
		SchemaVersion: model.StateSchemaVersion,
		Generation:    1,
		Host: model.Host{
			SchemaVersion: model.ResourceSchemaVersion,
			ID:            gatewayID, Role: model.RoleGateway,
			OS: "ubuntu", OSVersion: "24.04", Architecture: "amd64", InitializedAt: initialized,
			PublicIPv4: "192.0.2.1", ExternalInterface: "eth0", SSHPort: 22,
			ClientCIDR: model.DefaultClientCIDR, NodeCIDR: model.DefaultNodeCIDR,
		},
		EnrollmentIdentity: &identity.EnrollmentIdentity,
		DNS: &model.DNSUpstreamState{
			SchemaVersion: model.ResourceSchemaVersion,
			Scope:         model.DNSUpstreamGateway, IPv4: model.DefaultGatewayDNSUpstreams(),
		},
		Invites: []model.Invite{}, Nodes: []model.Node{}, Clients: []model.Client{},
		Presets: []model.Preset{}, Policies: []model.Policy{}, Transports: []model.Transport{},
		Exposes: []model.Expose{}, Certificates: identity.Certificates,
		Operations: []model.Operation{}, Logging: []model.LoggingSession{}, Backups: []model.Backup{},
		Components: model.ComponentManifest{
			SchemaVersion: model.ComponentManifestSchemaVersion, ManifestVersion: 1,
			VPNCTLVersion: "v2-capacity", ControlProtocols: []string{"1.0"},
			StateSchemaMinimum: model.StateSchemaVersion, StateSchemaMaximum: model.StateSchemaVersion,
			TargetOS: "ubuntu 24.04", TargetArchitecture: "amd64", HandshakeHostListVersion: 1,
			Components: []model.ComponentPin{{
				Name: "vpnctl", Version: "v2-capacity", Source: "capacity-gate", Bundled: true,
				SHA256: strings.Repeat("a", 64), Capabilities: []string{"controller"},
			}},
		},
	}
	if err := state.Validate(); err != nil {
		return fmt.Errorf("validate capacity controller state: %w", err)
	}
	return stateStore.Save(0, state)
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
