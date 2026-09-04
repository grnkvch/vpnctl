package lifecycle

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/store"
)

const NodeUninstallOperation = "uninstall"

type NodeUninstallRequest struct {
	ConfirmRevoke bool `json:"confirm_revoke"`
}

type NodeUninstallConfirmation struct {
	Confirmed bool   `json:"confirmed"`
	NodeID    string `json:"node_id"`
}

type NodeUninstallGatewayCaller interface {
	CallManagement(context.Context, control.RPCRequest) (control.RPCCallResult, error)
}

type NodeUninstallGatewayClient struct {
	caller  NodeUninstallGatewayCaller
	now     func() time.Time
	newUUID model.UUIDGenerator
	entropy io.Reader
}

func NewNodeUninstallGatewayClient(caller NodeUninstallGatewayCaller, now func() time.Time, newUUID model.UUIDGenerator, entropy io.Reader) (*NodeUninstallGatewayClient, error) {
	if caller == nil {
		return nil, fmt.Errorf("node uninstall gateway caller is required")
	}
	if now == nil {
		now = time.Now
	}
	if newUUID == nil {
		newUUID = model.NewUUID
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return &NodeUninstallGatewayClient{caller: caller, now: now, newUUID: newUUID, entropy: entropy}, nil
}

func (client *NodeUninstallGatewayClient) RevokeForUninstall(ctx context.Context, state model.State) (UninstallNodeRevocation, error) {
	if ctx == nil || client == nil || client.caller == nil || client.newUUID == nil || client.entropy == nil {
		return UninstallNodeRevocation{}, fmt.Errorf("node uninstall gateway client is incomplete")
	}
	if err := state.Validate(); err != nil || state.Host.Role != model.RoleNode || len(state.Nodes) != 1 {
		return UninstallNodeRevocation{}, fmt.Errorf("node uninstall requires valid enrolled node state")
	}
	node := state.Nodes[0]
	if node.Lifecycle != model.LifecycleActive || node.Gateway == nil || node.Gateway.PendingRequestID != "" {
		return UninstallNodeRevocation{}, fmt.Errorf("node uninstall requires an active identity without an uncertain request")
	}
	version, err := control.ParseRPCProtocolVersion(state.Components.ControlProtocols[0])
	if err != nil {
		return UninstallNodeRevocation{}, err
	}
	requestID, err := model.AllocateUUID(nodeUninstallOccupiedIDs(state), client.newUUID)
	if err != nil {
		return UninstallNodeRevocation{}, err
	}
	nonce := make([]byte, control.RPCNonceBytes)
	if _, err := io.ReadFull(client.entropy, nonce); err != nil {
		return UninstallNodeRevocation{}, fmt.Errorf("generate uninstall nonce: %w", err)
	}
	payload, _ := json.Marshal(NodeUninstallRequest{ConfirmRevoke: true})
	call, err := client.caller.CallManagement(ctx, control.RPCRequest{
		ProtocolMajor: version.Major, ProtocolMinor: version.Minor, RequestID: requestID,
		ExpectedStateGeneration: node.Gateway.LastKnownGatewayGeneration, NodeID: node.ID,
		CredentialGeneration: node.CredentialGeneration, Timestamp: client.now().UTC(),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Operation: NodeUninstallOperation, Payload: payload,
	})
	if err != nil {
		return UninstallNodeRevocation{}, err
	}
	if call.Response.Category != "success" || call.StatusCode != http.StatusOK || call.Response.AuthoritativeGeneration == 0 {
		return UninstallNodeRevocation{}, fmt.Errorf("%w: gateway category=%s code=%s", ErrUninstallGatewayUnavailable, call.Response.Category, call.Response.ErrorCode)
	}
	var confirmation NodeUninstallConfirmation
	if err := control.DecodeRPCPayload(call.Response.Data, &confirmation); err != nil {
		return UninstallNodeRevocation{}, fmt.Errorf("decode uninstall revocation confirmation: %w", err)
	}
	if !confirmation.Confirmed || confirmation.NodeID != node.ID {
		return UninstallNodeRevocation{}, fmt.Errorf("gateway returned an invalid uninstall revocation confirmation")
	}
	return UninstallNodeRevocation{Confirmed: true, GatewayGeneration: call.Response.AuthoritativeGeneration}, nil
}

func NewSystemNodeUninstallGateway(paths store.Paths, now func() time.Time) (*NodeUninstallGatewayClient, error) {
	stateStore, err := store.NewStateStore(paths)
	if err != nil {
		return nil, err
	}
	state, err := stateStore.Load()
	if err != nil || state.Host.Role != model.RoleNode || len(state.Nodes) != 1 || state.Nodes[0].Gateway == nil {
		return nil, fmt.Errorf("node uninstall gateway trust is unavailable")
	}
	node := state.Nodes[0]
	secrets, err := store.NewSecretStore(paths)
	if err != nil {
		return nil, err
	}
	caBundle := make([]byte, 0)
	for _, rawReference := range node.Gateway.ControlCACertificateRefs {
		certificate, err := secrets.Get(model.SecretRef(rawReference))
		if err != nil {
			clearUpdateSecret(caBundle)
			return nil, err
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
		return nil, err
	}
	defer clearUpdateSecret(certificatePEM)
	privateKeyPEM, err := secrets.Get(leaf.PrivateKeyRef)
	if err != nil {
		return nil, err
	}
	defer clearUpdateSecret(privateKeyPEM)
	rpc, err := control.NewRPCClient(control.RPCClientConfig{
		Address:   net.JoinHostPort(node.Gateway.GatewayOverlayIPv4, strconv.Itoa(control.RPCControlTCPPort)),
		GatewayID: node.Gateway.GatewayID, NodeID: node.ID, CACertificatePEM: caBundle,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM, Now: now,
	})
	if err != nil {
		return nil, err
	}
	return NewNodeUninstallGatewayClient(rpc, now, nil, nil)
}

func nodeUninstallOccupiedIDs(state model.State) map[string]struct{} {
	occupied := map[string]struct{}{state.Host.ID: {}}
	for _, node := range state.Nodes {
		occupied[node.ID] = struct{}{}
		for _, record := range node.IdempotencyRecords {
			occupied[record.RequestID] = struct{}{}
		}
	}
	for _, operation := range state.Operations {
		occupied[operation.ID] = struct{}{}
		if operation.RequestID != "" {
			occupied[operation.RequestID] = struct{}{}
		}
	}
	return occupied
}
