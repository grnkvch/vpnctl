package transport

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	GatewayStandardReadyFileName   = "gateway-standard.ready"
	GatewayRestrictedReadyFileName = "gateway-restricted.ready"
)

type GatewayListenerCredentialStore interface {
	Get(model.SecretRef) ([]byte, error)
	PutIfAbsent(model.SecretRef, []byte) error
	Delete(model.SecretRef) (bool, error)
}

type GatewayListenerConfigFile struct {
	Name    string
	Content []byte
}

// GatewayListenerInstallation contains the complete role-local publication
// set needed before systemd may start either gateway transport listener.
// Credential creation details remain private so generic orchestration cannot
// serialize or infer secret material.
type GatewayListenerInstallation struct {
	files             []GatewayListenerConfigFile
	standardCreated   bool
	restrictedCreated bool
}

func NewGatewayListenerInstallation(files []GatewayListenerConfigFile) (GatewayListenerInstallation, error) {
	want := GatewayListenerFileNames()
	if len(files) != len(want) {
		return GatewayListenerInstallation{}, fmt.Errorf("gateway listener publication requires exactly %d files", len(want))
	}
	result := GatewayListenerInstallation{files: make([]GatewayListenerConfigFile, len(files))}
	for index, file := range files {
		if file.Name != want[index] || len(file.Content) == 0 {
			return GatewayListenerInstallation{}, fmt.Errorf("gateway listener publication file %d must be non-empty %s", index, want[index])
		}
		result.files[index] = GatewayListenerConfigFile{Name: file.Name, Content: append([]byte(nil), file.Content...)}
	}
	return result, nil
}

func (installation GatewayListenerInstallation) ConfigFiles() []GatewayListenerConfigFile {
	result := make([]GatewayListenerConfigFile, len(installation.files))
	for index, file := range installation.files {
		result[index] = GatewayListenerConfigFile{Name: file.Name, Content: append([]byte(nil), file.Content...)}
	}
	return result
}

func GatewayListenerFileNames() []string {
	result := []string{
		GatewayRestrictedReadyFileName,
		GatewayStandardReadyFileName,
		RestrictedConfigFileName,
		StandardConfigFileName,
	}
	sort.Strings(result)
	return result
}

type GatewayListenerProvisioner struct {
	credentials GatewayListenerCredentialStore
	keyRunner   wireguard.Runner
	random      io.Reader
}

func NewGatewayListenerProvisioner(credentials GatewayListenerCredentialStore, keyRunner wireguard.Runner, random io.Reader) (*GatewayListenerProvisioner, error) {
	if credentials == nil {
		return nil, fmt.Errorf("gateway listener credential store is required")
	}
	if keyRunner == nil {
		keyRunner = wireguard.ExecRunner{}
	}
	if random == nil {
		random = rand.Reader
	}
	return &GatewayListenerProvisioner{credentials: credentials, keyRunner: keyRunner, random: random}, nil
}

// Provision creates both gateway transport credentials, renders both complete
// listener configurations, and emits readiness markers bound to their hashes.
// No node transport selection is read or changed: both public listeners are
// gateway capacity, while active/standby remains per-node desired state.
func (provisioner *GatewayListenerProvisioner) Provision(ctx context.Context, state model.State) (GatewayListenerInstallation, error) {
	if ctx == nil {
		return GatewayListenerInstallation{}, fmt.Errorf("context is required")
	}
	if provisioner == nil || provisioner.credentials == nil || provisioner.keyRunner == nil || provisioner.random == nil {
		return GatewayListenerInstallation{}, fmt.Errorf("gateway listener provisioner is incomplete")
	}
	if err := state.Validate(); err != nil {
		return GatewayListenerInstallation{}, fmt.Errorf("validate gateway listener state: %w", err)
	}
	if state.Host.Role != model.RoleGateway {
		return GatewayListenerInstallation{}, fmt.Errorf("gateway listeners require gateway state")
	}

	standard, standardCreated, err := ensureGatewayStandardCredential(ctx, provisioner.credentials, provisioner.keyRunner)
	if err != nil {
		return GatewayListenerInstallation{}, err
	}
	installation := GatewayListenerInstallation{standardCreated: standardCreated}
	rollback := func(cause error) (GatewayListenerInstallation, error) {
		return GatewayListenerInstallation{}, errors.Join(cause, provisioner.Rollback(context.Background(), installation))
	}

	restricted, restrictedCreated, err := ensureGatewayRestrictedCredential(ctx, provisioner.credentials, provisioner.random)
	if err != nil {
		return rollback(err)
	}
	installation.restrictedCreated = restrictedCreated

	standardConfig, err := RenderGatewayStandardConfig(ctx, GatewayStandardRenderRequest{
		State: state, CredentialRef: standard.Reference, Credentials: provisioner.credentials, KeyRunner: provisioner.keyRunner,
	})
	if err != nil {
		return rollback(err)
	}
	restrictedConfig, err := RenderGatewayRestrictedConfig(GatewayRestrictedRenderRequest{
		State: state, CredentialRef: restricted.Reference, Credentials: provisioner.credentials,
	})
	if err != nil {
		return rollback(err)
	}
	files := []GatewayListenerConfigFile{
		{Name: StandardConfigFileName, Content: standardConfig.Bytes()},
		{Name: RestrictedConfigFileName, Content: restrictedConfig.Bytes()},
		{Name: GatewayStandardReadyFileName, Content: gatewayListenerReadyMarker(model.TransportStandard, model.ProtocolUDP, StandardUDPPort, standard.Generation, standardConfig.ConfigHash())},
		{Name: GatewayRestrictedReadyFileName, Content: gatewayListenerReadyMarker(model.TransportRestricted, model.ProtocolTCP, RestrictedTCPPort, restricted.Generation, restrictedConfig.ConfigHash())},
	}
	sort.Slice(files, func(left, right int) bool { return files[left].Name < files[right].Name })
	publication, err := NewGatewayListenerInstallation(files)
	if err != nil {
		return rollback(err)
	}
	installation.files = publication.files
	return installation, nil
}

// Rollback removes only credentials created by this incomplete publication.
// Pre-existing create-once identities are never removed.
func (provisioner *GatewayListenerProvisioner) Rollback(ctx context.Context, installation GatewayListenerInstallation) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if provisioner == nil || provisioner.credentials == nil {
		return fmt.Errorf("gateway listener provisioner is incomplete")
	}
	var result error
	if installation.restrictedCreated {
		_, err := provisioner.credentials.Delete(GatewayRestrictedCredentialRef)
		result = errors.Join(result, err)
	}
	if installation.standardCreated {
		_, err := provisioner.credentials.Delete(GatewayStandardCredentialRef)
		result = errors.Join(result, err)
	}
	return result
}

func gatewayListenerReadyMarker(kind model.TransportKind, protocol model.NetworkProtocol, port int, generation uint64, configHash string) []byte {
	return []byte(fmt.Sprintf(
		"schema_version=1\ntransport=%s\nprotocol=%s\nport=%d\ncredential_generation=%d\nconfig_sha256=%s\n",
		kind, protocol, port, generation, configHash,
	))
}
