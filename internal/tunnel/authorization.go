package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	FRPAuthorizationAddress       = "127.0.0.1:19091"
	FRPAuthorizationPath          = "/handler"
	FRPAuthorizationProtocol      = "0.1.0"
	FRPAuthorizationMaximumBytes  = 64 << 10
	FRPAuthorizationMaximumDepth  = 8
	FRPAuthorizationMaxConcurrent = 32

	frpAuthorizationTimeout = 3 * time.Second
)

type AuthorizationStateReader interface {
	// Load returns validated authoritative state. The production StateStore
	// enforces schema and invariant validation before returning a value.
	Load() (model.State, error)
}

// AuthorizationServer implements the pinned frp HTTP-plugin boundary.
// It has no mutation interface and reloads authoritative state for every
// decision, so revocation and generation changes take effect without restart.
type AuthorizationServer struct {
	state       AuthorizationStateReader
	credentials FRPNodeCredentialSource
	listen      func(string, string) (net.Listener, error)
	admission   chan struct{}
	observe     func(string, bool, bool, string)
	rotationMu  sync.RWMutex
	rotations   map[string]credentialRotationWindow
	nextLeaseID uint64
}

type credentialRotationWindow struct {
	currentGeneration   uint64
	candidateGeneration uint64
	stateGeneration     uint64
	leaseID             uint64
}

// CredentialRotationLease is an opaque, process-local capability for removing
// exactly the staged authorization window that created it. It contains no
// credential value or store reference and has no useful serialized form.
type CredentialRotationLease struct {
	nodeID              string
	currentGeneration   uint64
	candidateGeneration uint64
	stateGeneration     uint64
	leaseID             uint64
}

type frpAuthorizationRequest struct {
	Version string                     `json:"version"`
	Op      string                     `json:"op"`
	Content map[string]json.RawMessage `json:"content"`
}

type frpAuthorizationResponse struct {
	Reject       bool                       `json:"reject"`
	RejectReason string                     `json:"reject_reason,omitempty"`
	Unchange     *bool                      `json:"unchange,omitempty"`
	Content      map[string]json.RawMessage `json:"content,omitempty"`
}

type authorizationDecision struct {
	allowed     bool
	unavailable bool
	reason      string
	unchange    bool
	content     map[string]json.RawMessage
}

type authorizedNodeIdentity struct {
	state model.State
	node  model.Node
}

func NewAuthorizationServer(state AuthorizationStateReader, credentials FRPNodeCredentialSource) (*AuthorizationServer, error) {
	if state == nil || credentials == nil {
		return nil, fmt.Errorf("tunnel authorization dependencies are incomplete")
	}
	return &AuthorizationServer{
		state: state, credentials: credentials, listen: net.Listen,
		admission: make(chan struct{}, FRPAuthorizationMaxConcurrent), rotations: make(map[string]credentialRotationWindow),
	}, nil
}

// BeginCredentialRotation temporarily admits the exact next tunnel credential
// alongside the current generation while the full node rotation saga performs
// its pre-commit readiness checks. The window remains valid only while the
// authoritative state is byte-identical to the supplied before generation;
// any concurrent commit, revoke, or unrelated state advance fails it closed.
func (server *AuthorizationServer) BeginCredentialRotation(before, candidate model.State, nodeID string) (*CredentialRotationLease, error) {
	if server == nil || server.state == nil || server.credentials == nil || server.rotations == nil {
		return nil, fmt.Errorf("tunnel authorization server is incomplete")
	}
	if err := before.Validate(); err != nil {
		return nil, fmt.Errorf("validate tunnel rotation source state: %w", err)
	}
	if err := candidate.Validate(); err != nil {
		return nil, fmt.Errorf("validate tunnel rotation candidate state: %w", err)
	}
	if before.Host.Role != model.RoleGateway || candidate.Host.Role != model.RoleGateway {
		return nil, fmt.Errorf("tunnel credential rotation requires gateway state")
	}
	if err := model.ValidateTransition(before, candidate); err != nil {
		return nil, fmt.Errorf("validate tunnel credential rotation transition: %w", err)
	}
	current, currentOK := exactNodeByID(before.Nodes, nodeID)
	next, nextOK := exactNodeByID(candidate.Nodes, nodeID)
	if !currentOK || !nextOK || current.Lifecycle != model.LifecycleActive || next.Lifecycle != model.LifecycleActive ||
		current.ActiveTransport != next.ActiveTransport || current.CredentialGeneration == ^uint64(0) ||
		next.CredentialGeneration != current.CredentialGeneration+1 || candidate.Generation != before.Generation+1 {
		return nil, fmt.Errorf("tunnel credential rotation identity or generation is invalid")
	}
	currentSession, err := NewNodeSession(current, before.Exposes, before.Generation)
	if err != nil {
		return nil, fmt.Errorf("compile current tunnel rotation identity: %w", err)
	}
	nextSession, err := NewNodeSession(next, candidate.Exposes, candidate.Generation)
	if err != nil {
		return nil, fmt.Errorf("compile candidate tunnel rotation identity: %w", err)
	}
	if currentSession.NodeID != nextSession.NodeID || !reflect.DeepEqual(currentSession.Mappings, nextSession.Mappings) {
		return nil, fmt.Errorf("tunnel credential rotation changed logical tunnel identity")
	}
	authoritative, err := server.state.Load()
	if err != nil || !reflect.DeepEqual(authoritative, before) {
		return nil, fmt.Errorf("tunnel credential rotation source state is stale")
	}
	credential, err := server.credentials.TunnelCredential(nodeID, next.CredentialGeneration)
	if err != nil {
		return nil, fmt.Errorf("read staged tunnel credential")
	}
	defer clear(credential)
	if err := ValidateCredential(credential); err != nil {
		return nil, fmt.Errorf("validate staged tunnel credential")
	}

	server.rotationMu.Lock()
	defer server.rotationMu.Unlock()
	window := credentialRotationWindow{
		currentGeneration: current.CredentialGeneration, candidateGeneration: next.CredentialGeneration,
		stateGeneration: before.Generation,
	}
	if existing, found := server.rotations[nodeID]; found {
		if existing.currentGeneration != window.currentGeneration || existing.candidateGeneration != window.candidateGeneration ||
			existing.stateGeneration != window.stateGeneration {
			return nil, fmt.Errorf("another tunnel credential rotation is already staged for node %s", nodeID)
		}
		window = existing
	} else {
		if server.nextLeaseID == ^uint64(0) {
			return nil, fmt.Errorf("tunnel credential rotation lease space is exhausted")
		}
		server.nextLeaseID++
		window.leaseID = server.nextLeaseID
		server.rotations[nodeID] = window
	}
	return &CredentialRotationLease{
		nodeID: nodeID, currentGeneration: window.currentGeneration, candidateGeneration: window.candidateGeneration,
		stateGeneration: window.stateGeneration, leaseID: window.leaseID,
	}, nil
}

// EndCredentialRotation removes one exact staged window. After it returns, a
// rolled-back candidate generation cannot pass a new Login or Ping. A
// committed candidate remains authorized through authoritative state alone.
func (server *AuthorizationServer) EndCredentialRotation(lease *CredentialRotationLease) error {
	if server == nil || server.rotations == nil || lease == nil || lease.nodeID == "" || lease.leaseID == 0 {
		return fmt.Errorf("tunnel credential rotation lease is invalid")
	}
	server.rotationMu.Lock()
	defer server.rotationMu.Unlock()
	want := credentialRotationWindow{
		currentGeneration: lease.currentGeneration, candidateGeneration: lease.candidateGeneration,
		stateGeneration: lease.stateGeneration, leaseID: lease.leaseID,
	}
	current, found := server.rotations[lease.nodeID]
	if !found {
		return nil
	}
	if current != want {
		return fmt.Errorf("tunnel credential rotation lease is stale")
	}
	delete(server.rotations, lease.nodeID)
	return nil
}

func (server *AuthorizationServer) Serve(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if server == nil || server.state == nil || server.credentials == nil || server.listen == nil || server.admission == nil {
		return fmt.Errorf("tunnel authorization server is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	listener, err := server.listen("tcp4", FRPAuthorizationAddress)
	if err != nil {
		return fmt.Errorf("listen for local tunnel authorization: %w", err)
	}
	if err := validateAuthorizationListener(listener); err != nil {
		_ = listener.Close()
		return err
	}

	httpServer := &http.Server{
		Handler:           server,
		ReadHeaderTimeout: frpAuthorizationTimeout,
		ReadTimeout:       frpAuthorizationTimeout,
		WriteTimeout:      frpAuthorizationTimeout,
		IdleTimeout:       frpAuthorizationTimeout,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = httpServer.Close()
		case <-stopped:
		}
	}()
	err = httpServer.Serve(listener)
	close(stopped)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	if err != nil {
		return fmt.Errorf("serve local tunnel authorization: %w", err)
	}
	return nil
}

func (server *AuthorizationServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if server == nil || server.state == nil || server.credentials == nil || server.admission == nil {
		writeFRPAuthorizationResponse(writer, http.StatusServiceUnavailable, unavailableFRPAuthorizationResponse())
		return
	}
	select {
	case server.admission <- struct{}{}:
		defer func() { <-server.admission }()
	default:
		writeFRPAuthorizationResponse(writer, http.StatusServiceUnavailable, unavailableFRPAuthorizationResponse())
		return
	}
	operation, validQuery := exactAuthorizationOperationQuery(request)
	if request.Method != http.MethodPost || request.URL.Path != FRPAuthorizationPath || !validQuery {
		writeFRPAuthorizationResponse(writer, http.StatusBadRequest, deniedFRPAuthorizationResponse())
		return
	}
	if request.ContentLength == 0 || request.ContentLength > FRPAuthorizationMaximumBytes {
		writeFRPAuthorizationResponse(writer, http.StatusBadRequest, deniedFRPAuthorizationResponse())
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, FRPAuthorizationMaximumBytes))
	if err != nil || len(body) == 0 {
		clear(body)
		writeFRPAuthorizationResponse(writer, http.StatusBadRequest, deniedFRPAuthorizationResponse())
		return
	}
	defer clear(body)
	parsed, err := decodeFRPAuthorizationRequest(body)
	if err != nil || parsed.Version != FRPAuthorizationProtocol || parsed.Op != operation {
		writeFRPAuthorizationResponse(writer, http.StatusBadRequest, deniedFRPAuthorizationResponse())
		return
	}
	defer clearRawMessageMap(parsed.Content)
	var decision authorizationDecision
	switch operation {
	case "Login":
		decision = server.authorizeLogin(parsed.Content)
	case "NewProxy":
		decision = server.authorizeNewProxy(parsed.Content)
	case "Ping":
		decision = server.authorizePing(parsed.Content)
	default:
		writeFRPAuthorizationResponse(writer, http.StatusBadRequest, deniedFRPAuthorizationResponse())
		return
	}
	defer clearRawMessageMap(decision.content)
	if server.observe != nil {
		server.observe(operation, decision.allowed, decision.unavailable, decision.reason)
	}
	switch {
	case decision.allowed:
		unchange := decision.unchange
		writeFRPAuthorizationResponse(writer, http.StatusOK, frpAuthorizationResponse{
			Reject: false, Unchange: &unchange, Content: decision.content,
		})
	case decision.unavailable:
		writeFRPAuthorizationResponse(writer, http.StatusOK, unavailableFRPAuthorizationResponse())
	default:
		writeFRPAuthorizationResponse(writer, http.StatusOK, deniedFRPAuthorizationResponse())
	}
}

// authorizePing deliberately reloads the same authoritative identity tuple as
// Login and NewProxy. The pinned frpc closes its control session when frps
// returns the rejected heartbeat as a Pong error, which withdraws every proxy
// owned by that session and makes revoke/current-generation changes effective
// without a separate public control or process-kill interface.
func (server *AuthorizationServer) authorizePing(content map[string]json.RawMessage) authorizationDecision {
	user, ok := rawJSONObject(content["user"])
	if !ok {
		return authorizationDecision{reason: "missing_identity"}
	}
	defer clearRawMessageMap(user)
	metadata, ok := rawJSONObject(user["metas"])
	if !ok {
		return authorizationDecision{reason: "missing_identity"}
	}
	defer clearRawMessageMap(metadata)
	_, decision := server.authorizeNodeIdentity(metadata)
	if !decision.allowed {
		return decision
	}
	return authorizationDecision{allowed: true, unchange: true, reason: "identity_valid"}
}

func (server *AuthorizationServer) authorizeLogin(content map[string]json.RawMessage) authorizationDecision {
	metadata, ok := rawJSONObject(content["metas"])
	if !ok {
		return authorizationDecision{reason: "missing_identity"}
	}
	defer clearRawMessageMap(metadata)
	poolCount, ok := rawJSONInteger(content["pool_count"])
	if !ok || poolCount != 1 {
		return authorizationDecision{reason: "pool_input_not_one"}
	}
	_, decision := server.authorizeNodeIdentity(metadata)
	if !decision.allowed {
		return decision
	}
	normalized := cloneRawMessageMap(content)
	normalized["pool_count"] = json.RawMessage("0")
	return authorizationDecision{allowed: true, reason: "identity_valid", content: normalized}
}

func (server *AuthorizationServer) authorizeNewProxy(content map[string]json.RawMessage) authorizationDecision {
	user, ok := rawJSONObject(content["user"])
	if !ok {
		return authorizationDecision{reason: "missing_identity"}
	}
	defer clearRawMessageMap(user)
	identityMetadata, ok := rawJSONObject(user["metas"])
	if !ok {
		return authorizationDecision{reason: "missing_identity"}
	}
	defer clearRawMessageMap(identityMetadata)
	identity, decision := server.authorizeNodeIdentity(identityMetadata)
	if !decision.allowed {
		return decision
	}

	name, nameOK := rawJSONString(content["proxy_name"])
	proxyType, typeOK := rawJSONString(content["proxy_type"])
	remotePort, portOK := rawJSONInteger(content["remote_port"])
	mappingMetadata, metadataOK := rawJSONObject(content["metas"])
	if !metadataOK {
		return authorizationDecision{reason: "mapping_mismatch"}
	}
	defer clearRawMessageMap(mappingMetadata)
	generationText, generationOK := rawJSONString(mappingMetadata["generation"])
	generation, err := strconv.ParseUint(generationText, 10, 64)
	if !nameOK || !typeOK || !portOK || remotePort < 1 || remotePort > 65535 || !generationOK ||
		err != nil || generation == 0 || strconv.FormatUint(generation, 10) != generationText {
		return authorizationDecision{reason: "mapping_mismatch"}
	}

	matches := 0
	for index := range identity.state.Exposes {
		expose := identity.state.Exposes[index]
		if expose.NodeID != identity.node.ID || expose.State == model.ExposeDisabled {
			continue
		}
		mapping, err := MappingFromExpose(expose)
		if err != nil {
			return authorizationDecision{unavailable: true, reason: "controller_error"}
		}
		if mapping.Name == name && string(mapping.Protocol) == proxyType &&
			int64(mapping.GatewayEndpoint.Port()) == remotePort && mapping.Generation == generation {
			matches++
		}
	}
	if matches == 0 {
		return authorizationDecision{reason: "mapping_mismatch"}
	}
	if matches != 1 {
		return authorizationDecision{unavailable: true, reason: "controller_error"}
	}
	return authorizationDecision{allowed: true, unchange: true, reason: "mapping_valid"}
}

func (server *AuthorizationServer) authorizeNodeIdentity(metadata map[string]json.RawMessage) (authorizedNodeIdentity, authorizationDecision) {
	server.rotationMu.RLock()
	defer server.rotationMu.RUnlock()
	nodeID, nodeOK := rawJSONString(metadata["node_id"])
	generationText, generationOK := rawJSONString(metadata["generation"])
	token, tokenOK := rawJSONString(metadata["tunnel_token"])
	if !nodeOK || !generationOK || !tokenOK || validateUUID("tunnel authorization node ID", nodeID) != nil {
		return authorizedNodeIdentity{}, authorizationDecision{reason: "missing_identity"}
	}
	generation, err := strconv.ParseUint(generationText, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != generationText {
		return authorizedNodeIdentity{}, authorizationDecision{reason: "generation_mismatch"}
	}
	state, err := server.state.Load()
	if err != nil || state.Host.Role != model.RoleGateway {
		return authorizedNodeIdentity{}, authorizationDecision{unavailable: true, reason: "controller_error"}
	}
	var authoritative *model.Node
	for index := range state.Nodes {
		if state.Nodes[index].ID != nodeID {
			continue
		}
		if authoritative != nil {
			return authorizedNodeIdentity{}, authorizationDecision{unavailable: true, reason: "controller_error"}
		}
		authoritative = &state.Nodes[index]
	}
	if authoritative == nil {
		return authorizedNodeIdentity{}, authorizationDecision{reason: "unknown_node"}
	}
	if authoritative.Lifecycle != model.LifecycleActive {
		return authorizedNodeIdentity{}, authorizationDecision{reason: "revoked"}
	}
	currentGeneration := authoritative.CredentialGeneration == generation
	window, stagedGeneration := server.rotations[nodeID]
	stagedGeneration = stagedGeneration && window.stateGeneration == state.Generation &&
		window.currentGeneration == authoritative.CredentialGeneration && window.candidateGeneration == generation
	if !currentGeneration && !stagedGeneration {
		return authorizedNodeIdentity{}, authorizationDecision{reason: "generation_mismatch"}
	}
	expected, err := server.credentials.TunnelCredential(nodeID, generation)
	if err != nil {
		return authorizedNodeIdentity{}, authorizationDecision{unavailable: true, reason: "controller_error"}
	}
	defer clear(expected)
	commitment, err := NewCredentialCommitment(nodeID, generation, expected)
	if err != nil {
		return authorizedNodeIdentity{}, authorizationDecision{unavailable: true, reason: "controller_error"}
	}
	tokenBytes := []byte(token)
	defer clear(tokenBytes)
	if !commitment.Matches(nodeID, generation, tokenBytes) {
		return authorizedNodeIdentity{}, authorizationDecision{reason: "token_mismatch"}
	}
	return authorizedNodeIdentity{state: state, node: *authoritative}, authorizationDecision{allowed: true, reason: "identity_valid"}
}

func exactNodeByID(nodes []model.Node, nodeID string) (model.Node, bool) {
	var result model.Node
	found := false
	for _, node := range nodes {
		if node.ID != nodeID {
			continue
		}
		if found {
			return model.Node{}, false
		}
		result = node
		found = true
	}
	return result, found
}

func decodeFRPAuthorizationRequest(body []byte) (frpAuthorizationRequest, error) {
	if err := validateAuthorizationJSON(body); err != nil {
		return frpAuthorizationRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var request frpAuthorizationRequest
	if err := decoder.Decode(&request); err != nil {
		return frpAuthorizationRequest{}, err
	}
	if request.Version == "" || request.Op == "" || request.Content == nil {
		return frpAuthorizationRequest{}, fmt.Errorf("incomplete tunnel authorization request")
	}
	return request, nil
}

func validateAuthorizationJSON(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := walkAuthorizationJSON(decoder, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple tunnel authorization documents")
		}
		return err
	}
	return nil
}

func walkAuthorizationJSON(decoder *json.Decoder, depth int) error {
	if depth > FRPAuthorizationMaximumDepth {
		return fmt.Errorf("tunnel authorization JSON is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, nested := token.(json.Delim)
	if !nested {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("tunnel authorization object key is invalid")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate tunnel authorization field")
			}
			keys[key] = struct{}{}
			if err := walkAuthorizationJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := walkAuthorizationJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid tunnel authorization JSON delimiter")
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter == '{' && closing != json.Delim('}') || delimiter == '[' && closing != json.Delim(']') {
		return fmt.Errorf("invalid tunnel authorization JSON closing token")
	}
	return nil
}

func exactAuthorizationOperationQuery(request *http.Request) (string, bool) {
	query := request.URL.Query()
	if len(query) != 2 {
		return "", false
	}
	operations, operationPresent := query["op"]
	versions, versionPresent := query["version"]
	if !operationPresent || len(operations) != 1 || !versionPresent || len(versions) != 1 || versions[0] != FRPAuthorizationProtocol {
		return "", false
	}
	operation := operations[0]
	return operation, operation == "Login" || operation == "NewProxy" || operation == "Ping"
}

func rawJSONObject(value json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(value) == 0 {
		return nil, false
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(value, &result); err != nil || result == nil {
		return nil, false
	}
	return result, true
}

func rawJSONString(value json.RawMessage) (string, bool) {
	if len(value) == 0 {
		return "", false
	}
	var result string
	if err := json.Unmarshal(value, &result); err != nil || result == "" || strings.ContainsAny(result, "\x00\r\n") {
		return "", false
	}
	return result, true
}

func rawJSONInteger(value json.RawMessage) (int64, bool) {
	if len(value) == 0 {
		return 0, false
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return 0, false
	}
	result, err := number.Int64()
	return result, err == nil && number.String() == strconv.FormatInt(result, 10)
}

func cloneRawMessageMap(source map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(source))
	for key, value := range source {
		result[key] = append(json.RawMessage(nil), value...)
	}
	return result
}

func clearRawMessageMap(values map[string]json.RawMessage) {
	for key, value := range values {
		clear(value)
		delete(values, key)
	}
}

func deniedFRPAuthorizationResponse() frpAuthorizationResponse {
	return frpAuthorizationResponse{Reject: true, RejectReason: "vpnctl authorization denied"}
}

func unavailableFRPAuthorizationResponse() frpAuthorizationResponse {
	return frpAuthorizationResponse{Reject: true, RejectReason: "vpnctl authorization unavailable"}
}

func writeFRPAuthorizationResponse(writer http.ResponseWriter, status int, response frpAuthorizationResponse) {
	body, err := json.Marshal(response)
	if err != nil || len(body) > FRPAuthorizationMaximumBytes {
		status = http.StatusInternalServerError
		body = []byte(`{"reject":true,"reject_reason":"vpnctl authorization unavailable"}`)
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(body)
	clear(body)
}

func validateAuthorizationListener(listener net.Listener) error {
	if listener == nil {
		return fmt.Errorf("tunnel authorization listener is required")
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.IP == nil || !address.IP.IsLoopback() {
		return fmt.Errorf("tunnel authorization listener must be TCP loopback-only")
	}
	return nil
}
