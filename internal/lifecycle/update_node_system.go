package lifecycle

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

// NewSystemNodeUpdateFleetChecker builds the one short-lived authenticated
// gateway preflight used by an explicitly invoked node update. It neither
// writes state nor exposes any remote installation primitive.
func NewSystemNodeUpdateFleetChecker(paths store.Paths, now func() time.Time) (*NodeUpdateFleetChecker, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	state, err := stateStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load node update trust: %w", err)
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleNode {
		return nil, fmt.Errorf("node update requires valid node state")
	}
	if len(state.Nodes) == 0 {
		return NewNodeUpdateFleetChecker(unjoinedUpdatePreflighter{})
	}
	node := state.Nodes[0]
	if node.Gateway == nil {
		return nil, fmt.Errorf("node update gateway trust is missing")
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, err
	}
	caBundle := make([]byte, 0)
	for _, rawReference := range node.Gateway.ControlCACertificateRefs {
		certificate, readErr := secrets.Get(model.SecretRef(rawReference))
		if readErr != nil {
			clearUpdateSecret(caBundle)
			return nil, fmt.Errorf("load node update control CA: %w", readErr)
		}
		caBundle = append(caBundle, certificate...)
		caBundle = append(caBundle, '\n')
		clearUpdateSecret(certificate)
	}
	defer clearUpdateSecret(caBundle)
	leaf, found := currentNodeControlCertificate(state, node)
	if !found {
		return nil, fmt.Errorf("current node control certificate is missing")
	}
	certificatePEM, err := secrets.Get(model.SecretRef(leaf.CertificateRef))
	if err != nil {
		return nil, fmt.Errorf("load node update certificate: %w", err)
	}
	defer clearUpdateSecret(certificatePEM)
	privateKeyPEM, err := secrets.Get(leaf.PrivateKeyRef)
	if err != nil {
		return nil, fmt.Errorf("load node update private key: %w", err)
	}
	defer clearUpdateSecret(privateKeyPEM)
	client, err := control.NewRPCClient(control.RPCClientConfig{
		Address:   net.JoinHostPort(node.Gateway.GatewayOverlayIPv4, strconv.Itoa(control.RPCControlTCPPort)),
		GatewayID: node.Gateway.GatewayID, NodeID: node.ID, CACertificatePEM: caBundle,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM, Now: now,
	})
	if err != nil {
		return nil, err
	}
	preflighter, err := NewNodeUpdatePreflighter(NodeUpdatePreflightRuntime{State: stateStore, Gateway: client, Now: now})
	if err != nil {
		return nil, err
	}
	return NewNodeUpdateFleetChecker(preflighter)
}

func currentNodeControlCertificate(state model.State, node model.Node) (model.Certificate, bool) {
	for _, certificate := range state.Certificates {
		if certificate.Kind == model.CertificateControlNode && certificate.OwnerKind == "node" && certificate.OwnerID == node.ID &&
			certificate.EffectiveCredentialGeneration() == node.CredentialGeneration && certificate.CertificateRef != "" && certificate.PrivateKeyRef != "" {
			return certificate, true
		}
	}
	return model.Certificate{}, false
}

type unjoinedUpdatePreflighter struct{}

func (unjoinedUpdatePreflighter) Preflight(context.Context, model.ComponentManifest) (NodeUpdatePreflightPlan, error) {
	return NodeUpdatePreflightPlan{}, fmt.Errorf("unjoined node update preflight must not be called")
}

func clearUpdateSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
