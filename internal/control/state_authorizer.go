package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

type GatewayStateReader interface {
	Load() (model.State, error)
}

// StateNodeAuthorizer binds the CA-valid certificate fingerprint and immutable
// URI node ID to the current active credential generation in authoritative
// gateway state. It reloads state for every request, so revoke and rotate take
// effect on the next RPC without waiting for TLS expiry or a cache.
type StateNodeAuthorizer struct {
	state GatewayStateReader
}

func NewStateNodeAuthorizer(state GatewayStateReader) (*StateNodeAuthorizer, error) {
	if state == nil {
		return nil, fmt.Errorf("gateway state reader is required")
	}
	return &StateNodeAuthorizer{state: state}, nil
}

func (authorizer *StateNodeAuthorizer) AuthorizeRPC(_ context.Context, peer RPCPeer, request RPCRequest) (RPCAuthorization, error) {
	if authorizer == nil || authorizer.state == nil {
		return RPCAuthorization{}, fmt.Errorf("control RPC node authorizer is incomplete")
	}
	if peer.NodeID == "" || peer.NodeID != request.NodeID {
		return deniedStateRPC(request, http.StatusForbidden, "validation", 0, "identity_mismatch", "the certificate and request node identities differ"), nil
	}
	state, err := authorizer.state.Load()
	if err != nil {
		return deniedStateRPC(request, http.StatusServiceUnavailable, "unavailable", 0, "authorization_unavailable", "authoritative node identity state is unavailable"), nil
	}
	nodeIndex := -1
	for index := range state.Nodes {
		if state.Nodes[index].ID == peer.NodeID {
			nodeIndex = index
			break
		}
	}
	if nodeIndex < 0 || state.Nodes[nodeIndex].Lifecycle != model.LifecycleActive {
		return deniedStateRPC(request, http.StatusForbidden, "validation", state.Generation, "node_inactive", "the authenticated node is not active"), nil
	}
	node := state.Nodes[nodeIndex]
	if request.CredentialGeneration != node.CredentialGeneration {
		return deniedStateRPC(request, http.StatusForbidden, "validation", state.Generation, "credential_generation_mismatch", "the node credential generation is not current"), nil
	}
	for _, certificate := range state.Certificates {
		if certificate.Kind == model.CertificateControlNode && certificate.OwnerKind == "node" && certificate.OwnerID == node.ID &&
			certificate.EffectiveCredentialGeneration() == node.CredentialGeneration && certificate.Fingerprint == peer.CertificateFingerprint {
			return RPCAuthorization{Authorized: true}, nil
		}
	}
	return deniedStateRPC(request, http.StatusForbidden, "validation", state.Generation, "credential_not_authorized", "the node certificate is not current"), nil
}

func deniedStateRPC(request RPCRequest, statusCode int, category string, generation uint64, code, message string) RPCAuthorization {
	response := NewRPCResponse(category, generation, json.RawMessage(`{}`))
	response.ProtocolMajor = request.ProtocolMajor
	response.ProtocolMinor = request.ProtocolMinor
	response.ErrorCode = code
	response.Message = message
	return RPCAuthorization{Denial: RPCHandlerResult{StatusCode: statusCode, Response: response}}
}

var _ RPCAuthorizer = (*StateNodeAuthorizer)(nil)
