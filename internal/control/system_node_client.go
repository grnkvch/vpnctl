package control

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

// SystemNodeClient binds the joined node's persisted trust metadata to a
// short-lived mTLS client. Callers receive identities and generations, never
// credential bytes.
type SystemNodeClient struct {
	Client               *RPCClient
	Protocol             RPCProtocolVersion
	NodeID               string
	CredentialGeneration uint64
	LastKnownGeneration  uint64
}

func NewSystemNodeClient(paths store.Paths, now func() time.Time) (SystemNodeClient, error) {
	return NewSystemNodeClientWithDialContext(paths, now, nil)
}

// NewSystemNodeClientWithDialContext loads the same persisted mTLS identity as
// NewSystemNodeClient but sends its short-lived RPC through an explicitly
// selected candidate path. A nil dialer preserves the ordinary system path.
func NewSystemNodeClientWithDialContext(
	paths store.Paths,
	now func() time.Time,
	dial func(context.Context, string, string) (net.Conn, error),
) (SystemNodeClient, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return SystemNodeClient{}, err
	}
	state, err := stateStore.Load()
	if err != nil || state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Gateway == nil {
		return SystemNodeClient{}, fmt.Errorf("joined node control trust is unavailable")
	}
	node := state.Nodes[0]
	protocol, err := ParseRPCProtocolVersion(node.Gateway.ControlProtocol)
	if err != nil {
		return SystemNodeClient{}, err
	}
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return SystemNodeClient{}, err
	}
	caBundle := make([]byte, 0)
	for _, rawReference := range node.Gateway.ControlCACertificateRefs {
		certificate, readErr := secrets.Get(model.SecretRef(rawReference))
		if readErr != nil {
			clearSystemNodeClientSecret(caBundle)
			return SystemNodeClient{}, readErr
		}
		caBundle = append(caBundle, certificate...)
		caBundle = append(caBundle, '\n')
		clearSystemNodeClientSecret(certificate)
	}
	defer clearSystemNodeClientSecret(caBundle)

	leaf, found := currentSystemNodeControlCertificate(state, node)
	if !found {
		return SystemNodeClient{}, fmt.Errorf("current node control certificate is missing")
	}
	certificatePEM, err := secrets.Get(model.SecretRef(leaf.CertificateRef))
	if err != nil {
		return SystemNodeClient{}, err
	}
	defer clearSystemNodeClientSecret(certificatePEM)
	privateKeyPEM, err := secrets.Get(leaf.PrivateKeyRef)
	if err != nil {
		return SystemNodeClient{}, err
	}
	defer clearSystemNodeClientSecret(privateKeyPEM)

	client, err := NewRPCClient(RPCClientConfig{
		Address:   net.JoinHostPort(node.Gateway.GatewayOverlayIPv4, strconv.Itoa(RPCControlTCPPort)),
		GatewayID: node.Gateway.GatewayID, NodeID: node.ID, CACertificatePEM: caBundle,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM, Now: now, DialContext: dial,
	})
	if err != nil {
		return SystemNodeClient{}, err
	}
	return SystemNodeClient{
		Client: client, Protocol: protocol, NodeID: node.ID,
		CredentialGeneration: node.CredentialGeneration,
		LastKnownGeneration:  node.Gateway.LastKnownGatewayGeneration,
	}, nil
}

func currentSystemNodeControlCertificate(state model.State, node model.Node) (model.Certificate, bool) {
	var result model.Certificate
	found := false
	for _, certificate := range state.Certificates {
		if certificate.Kind != model.CertificateControlNode || certificate.OwnerKind != "node" || certificate.OwnerID != node.ID ||
			certificate.EffectiveCredentialGeneration() != node.CredentialGeneration || certificate.CertificateRef == "" || certificate.PrivateKeyRef == "" {
			continue
		}
		if found {
			return model.Certificate{}, false
		}
		result, found = certificate, true
	}
	return result, found
}

func clearSystemNodeClientSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
