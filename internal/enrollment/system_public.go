package enrollment

import (
	"fmt"
	"sync"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
	"github.com/vgrinkevich/vpnctl/internal/tunnel"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

// NewSystemPublicEnrollmentServer composes the gateway's public bootstrap
// graph behind one loopback-only server boundary. The management controller
// supervises that boundary without importing or owning tunnel/data-plane
// process implementations.
func NewSystemPublicEnrollmentServer(
	paths store.Paths,
	stateStore *store.StateStore,
	secrets *store.SecretStore,
	mutationMu *sync.Mutex,
) (*PublicEnrollmentServer, error) {
	if stateStore == nil || secrets == nil || mutationMu == nil {
		return nil, fmt.Errorf("system public enrollment dependencies are incomplete")
	}
	state, err := stateStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load authoritative gateway state for public enrollment: %w", err)
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleGateway || state.EnrollmentIdentity == nil {
		return nil, fmt.Errorf("public enrollment requires valid gateway state and identity")
	}
	privateKey, err := secrets.Get(state.EnrollmentIdentity.PrivateKeyRef)
	if err != nil {
		return nil, fmt.Errorf("load public enrollment signing key: %w", err)
	}
	defer clear(privateKey)
	signer, err := NewEnrollmentTranscriptSigner(privateKey, state.EnrollmentIdentity.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("create public enrollment signer: %w", err)
	}
	invites, err := NewInviteManager(stateStore, nil, nil)
	if err != nil {
		return nil, err
	}
	readiness, err := NewSystemGatewayJoinReadiness(paths, secrets, mutationMu)
	if err != nil {
		return nil, err
	}
	tunnelTLS, err := tunnel.NewGatewayTLSIdentityProvisioner(secrets, tunnel.GatewayTLSIdentityRuntime{})
	if err != nil {
		return nil, err
	}
	builder, err := NewGatewayJoinBuilder(invites, secrets, GatewayJoinRuntime{
		WireGuardRunner: wireguard.ExecRunner{}, Readiness: readiness, TunnelTLS: tunnelTLS,
	})
	if err != nil {
		return nil, err
	}
	join, err := NewInviteEnrollmentCoordinator(invites, builder)
	if err != nil {
		return nil, err
	}
	recoveryTokens, err := NewRecoveryManager(stateStore, nil, nil)
	if err != nil {
		return nil, err
	}
	recoveryRuntime, err := NewSystemGatewayRecoveryRuntime(paths, secrets, mutationMu)
	if err != nil {
		return nil, err
	}
	rotation, err := NewGatewayNodeRotationManager(
		stateStore, secrets, recoveryRuntime, GatewayNodeRotationOptions{},
	)
	if err != nil {
		return nil, err
	}
	recoveryBuilder, err := NewGatewayRecoveryBuilder(recoveryTokens, rotation)
	if err != nil {
		return nil, err
	}
	recovery, err := NewRecoveryEnrollmentCoordinator(recoveryTokens, recoveryBuilder)
	if err != nil {
		return nil, err
	}
	coordinator, err := NewPublicEnrollmentCoordinatorMux(join, recovery)
	if err != nil {
		return nil, err
	}
	handler, err := NewPublicEnrollmentHandler(PublicEnrollmentHandlerConfig{
		PublicIPv4: state.Host.PublicIPv4, Signer: signer, Coordinator: coordinator,
	})
	if err != nil {
		return nil, err
	}
	return NewPublicEnrollmentServer(handler)
}
