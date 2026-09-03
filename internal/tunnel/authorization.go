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
	"strconv"
	"strings"
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

// LoginAuthorizationServer implements the pinned frp HTTP-plugin boundary.
// It has no mutation interface and reloads authoritative state for every
// Login, so revocation and generation changes take effect without a restart.
type LoginAuthorizationServer struct {
	state       AuthorizationStateReader
	credentials FRPNodeCredentialSource
	listen      func(string, string) (net.Listener, error)
	admission   chan struct{}
	observe     func(bool, bool, string)
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

type loginAuthorizationDecision struct {
	allowed     bool
	unavailable bool
	reason      string
	content     map[string]json.RawMessage
}

func NewLoginAuthorizationServer(state AuthorizationStateReader, credentials FRPNodeCredentialSource) (*LoginAuthorizationServer, error) {
	if state == nil || credentials == nil {
		return nil, fmt.Errorf("tunnel Login authorization dependencies are incomplete")
	}
	return &LoginAuthorizationServer{
		state: state, credentials: credentials, listen: net.Listen,
		admission: make(chan struct{}, FRPAuthorizationMaxConcurrent),
	}, nil
}

func (server *LoginAuthorizationServer) Serve(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if server == nil || server.state == nil || server.credentials == nil || server.listen == nil || server.admission == nil {
		return fmt.Errorf("tunnel Login authorization server is incomplete")
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

func (server *LoginAuthorizationServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
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
	if request.Method != http.MethodPost || request.URL.Path != FRPAuthorizationPath || !exactLoginOperationQuery(request) {
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
	if err != nil || parsed.Version != FRPAuthorizationProtocol || parsed.Op != "Login" {
		writeFRPAuthorizationResponse(writer, http.StatusBadRequest, deniedFRPAuthorizationResponse())
		return
	}
	defer clearRawMessageMap(parsed.Content)
	decision := server.authorizeLogin(parsed.Content)
	defer clearRawMessageMap(decision.content)
	if server.observe != nil {
		server.observe(decision.allowed, decision.unavailable, decision.reason)
	}
	switch {
	case decision.allowed:
		changed := false
		writeFRPAuthorizationResponse(writer, http.StatusOK, frpAuthorizationResponse{
			Reject: false, Unchange: &changed, Content: decision.content,
		})
	case decision.unavailable:
		writeFRPAuthorizationResponse(writer, http.StatusOK, unavailableFRPAuthorizationResponse())
	default:
		writeFRPAuthorizationResponse(writer, http.StatusOK, deniedFRPAuthorizationResponse())
	}
}

func (server *LoginAuthorizationServer) authorizeLogin(content map[string]json.RawMessage) loginAuthorizationDecision {
	metadata, ok := rawJSONObject(content["metas"])
	if !ok {
		return loginAuthorizationDecision{reason: "missing_identity"}
	}
	defer clearRawMessageMap(metadata)
	nodeID, nodeOK := rawJSONString(metadata["node_id"])
	generationText, generationOK := rawJSONString(metadata["generation"])
	token, tokenOK := rawJSONString(metadata["tunnel_token"])
	if !nodeOK || !generationOK || !tokenOK || validateUUID("tunnel Login node ID", nodeID) != nil {
		return loginAuthorizationDecision{reason: "missing_identity"}
	}
	generation, err := strconv.ParseUint(generationText, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != generationText {
		return loginAuthorizationDecision{reason: "generation_mismatch"}
	}
	poolCount, ok := rawJSONInteger(content["pool_count"])
	if !ok || poolCount != 1 {
		return loginAuthorizationDecision{reason: "pool_input_not_one"}
	}
	state, err := server.state.Load()
	if err != nil || state.Host.Role != model.RoleGateway {
		return loginAuthorizationDecision{unavailable: true, reason: "controller_error"}
	}
	var authoritative *model.Node
	for index := range state.Nodes {
		if state.Nodes[index].ID != nodeID {
			continue
		}
		if authoritative != nil {
			return loginAuthorizationDecision{unavailable: true, reason: "controller_error"}
		}
		authoritative = &state.Nodes[index]
	}
	if authoritative == nil {
		return loginAuthorizationDecision{reason: "unknown_node"}
	}
	if authoritative.Lifecycle != model.LifecycleActive {
		return loginAuthorizationDecision{reason: "revoked"}
	}
	if authoritative.CredentialGeneration != generation {
		return loginAuthorizationDecision{reason: "generation_mismatch"}
	}
	expected, err := server.credentials.TunnelCredential(nodeID, generation)
	if err != nil {
		return loginAuthorizationDecision{unavailable: true, reason: "controller_error"}
	}
	defer clear(expected)
	commitment, err := NewCredentialCommitment(nodeID, generation, expected)
	if err != nil {
		return loginAuthorizationDecision{unavailable: true, reason: "controller_error"}
	}
	tokenBytes := []byte(token)
	defer clear(tokenBytes)
	if !commitment.Matches(nodeID, generation, tokenBytes) {
		return loginAuthorizationDecision{reason: "token_mismatch"}
	}
	normalized := cloneRawMessageMap(content)
	normalized["pool_count"] = json.RawMessage("0")
	return loginAuthorizationDecision{allowed: true, reason: "identity_valid", content: normalized}
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

func exactLoginOperationQuery(request *http.Request) bool {
	query := request.URL.Query()
	if len(query) != 2 {
		return false
	}
	operations, operationPresent := query["op"]
	versions, versionPresent := query["version"]
	return operationPresent && len(operations) == 1 && operations[0] == "Login" &&
		versionPresent && len(versions) == 1 && versions[0] == FRPAuthorizationProtocol
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
