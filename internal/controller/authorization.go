package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
)

type GatewayStateReader interface {
	Load() (model.State, error)
}

// RPCNodeAuthorizer binds the CA-valid certificate fingerprint and immutable
// URI node ID to the current active credential generation in authoritative
// gateway state. It reloads that state for every request, so revoke and rotate
// take effect on the next RPC without waiting for TLS expiry or a cache.
type RPCNodeAuthorizer struct {
	state GatewayStateReader
}

func NewRPCNodeAuthorizer(state GatewayStateReader) (*RPCNodeAuthorizer, error) {
	if state == nil {
		return nil, fmt.Errorf("gateway state reader is required")
	}
	return &RPCNodeAuthorizer{state: state}, nil
}

func (authorizer *RPCNodeAuthorizer) AuthorizeRPC(_ context.Context, peer control.RPCPeer, request control.RPCRequest) (control.RPCAuthorization, error) {
	if authorizer == nil || authorizer.state == nil {
		return control.RPCAuthorization{}, fmt.Errorf("control RPC node authorizer is incomplete")
	}
	if peer.NodeID == "" || peer.NodeID != request.NodeID {
		return deniedRPC(request, http.StatusForbidden, "validation", 0, "identity_mismatch", "the certificate and request node identities differ"), nil
	}
	state, err := authorizer.state.Load()
	if err != nil {
		return deniedRPC(request, http.StatusServiceUnavailable, "unavailable", 0, "authorization_unavailable", "authoritative node identity state is unavailable"), nil
	}
	index := nodeIndexByID(state, peer.NodeID)
	if index < 0 || state.Nodes[index].Lifecycle != model.LifecycleActive {
		return deniedRPC(request, http.StatusForbidden, "validation", state.Generation, "node_inactive", "the authenticated node is not active"), nil
	}
	node := state.Nodes[index]
	if request.CredentialGeneration != node.CredentialGeneration {
		return deniedRPC(request, http.StatusForbidden, "validation", state.Generation, "credential_generation_mismatch", "the node credential generation is not current"), nil
	}
	for _, certificate := range state.Certificates {
		if certificate.Kind == model.CertificateControlNode && certificate.OwnerKind == "node" && certificate.OwnerID == node.ID &&
			certificate.EffectiveCredentialGeneration() == node.CredentialGeneration && certificate.Fingerprint == peer.CertificateFingerprint {
			return control.RPCAuthorization{Authorized: true}, nil
		}
	}
	return deniedRPC(request, http.StatusForbidden, "validation", state.Generation, "credential_not_authorized", "the node certificate is not current"), nil
}

func deniedRPC(request control.RPCRequest, statusCode int, category string, generation uint64, code, message string) control.RPCAuthorization {
	response := control.NewRPCResponse(category, generation, json.RawMessage(`{}`))
	response.ProtocolMajor = request.ProtocolMajor
	response.ProtocolMinor = request.ProtocolMinor
	response.ErrorCode = code
	response.Message = message
	return control.RPCAuthorization{Denial: control.RPCHandlerResult{StatusCode: statusCode, Response: response}}
}
