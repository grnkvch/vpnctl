package enrollment

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const (
	PublicEnrollmentSchemaVersion = 1
	PublicEnrollmentContentType   = "application/json"
	RecoveryTokenPrefix           = "vpnctl-recovery-v1"
)

var (
	ErrPublicEnrollmentRejected    = errors.New("public enrollment request rejected")
	ErrPublicEnrollmentUnavailable = errors.New("public enrollment is unavailable")
)

// PublicEnrollmentRequest carries the bounded public request into the
// enrollment/recovery coordinator. Token bytes are available only through
// UseToken and are destroyed by the handler when Prepare returns.
type PublicEnrollmentRequest struct {
	Purpose      EnrollmentPurpose
	Endpoint     string
	NodeNonce    [EnrollmentNonceBytes]byte
	GatewayNonce [EnrollmentNonceBytes]byte
	Payload      json.RawMessage

	token *output.Secret
}

func (request PublicEnrollmentRequest) UseToken(callback func([]byte) error) error {
	if request.token == nil {
		return ErrPublicEnrollmentRejected
	}
	return request.token.Use(callback)
}

// PublicEnrollmentTransaction is a prepared, still-uncommitted response. The
// implementation must atomically persist the signed exchange replay hash and
// consume its one-time credential in Commit. Destroy clears retained response
// secrets on every handler exit path.
type PublicEnrollmentTransaction interface {
	Transcript() EnrollmentTranscript
	EnrollmentFingerprint() string
	UseResponseData(func(json.RawMessage) error) error
	Commit(context.Context, string) error
	Destroy()
}

type PublicEnrollmentCoordinator interface {
	PreparePublicEnrollment(context.Context, PublicEnrollmentRequest) (PublicEnrollmentTransaction, error)
}

// PublicEnrollmentCoordinatorMux keeps enrollment and recovery as separate
// purpose-specific implementations while allowing one reserved HTTPS handler
// to serve both paths.
type PublicEnrollmentCoordinatorMux struct {
	enrollment PublicEnrollmentCoordinator
	recovery   PublicEnrollmentCoordinator
}

func NewPublicEnrollmentCoordinatorMux(
	enrollment PublicEnrollmentCoordinator,
	recovery PublicEnrollmentCoordinator,
) (*PublicEnrollmentCoordinatorMux, error) {
	if enrollment == nil || recovery == nil {
		return nil, fmt.Errorf("public enrollment and recovery coordinators are required")
	}
	return &PublicEnrollmentCoordinatorMux{enrollment: enrollment, recovery: recovery}, nil
}

func (mux *PublicEnrollmentCoordinatorMux) PreparePublicEnrollment(
	ctx context.Context,
	request PublicEnrollmentRequest,
) (PublicEnrollmentTransaction, error) {
	if mux == nil || ctx == nil {
		return nil, ErrPublicEnrollmentUnavailable
	}
	switch request.Purpose {
	case PurposeEnroll:
		return mux.enrollment.PreparePublicEnrollment(ctx, request)
	case PurposeRecover:
		return mux.recovery.PreparePublicEnrollment(ctx, request)
	default:
		return nil, ErrPublicEnrollmentRejected
	}
}

type PublicEnrollmentHandlerConfig struct {
	PublicIPv4  string
	Signer      *EnrollmentTranscriptSigner
	Coordinator PublicEnrollmentCoordinator
	Entropy     io.Reader
	Now         func() time.Time
}

type PublicEnrollmentHandler struct {
	publicIPv4  string
	signer      *EnrollmentTranscriptSigner
	coordinator PublicEnrollmentCoordinator
	entropy     io.Reader
	now         func() time.Time
	sessions    chan struct{}
	entropyMu   sync.Mutex
}

type publicEnrollmentWireRequest struct {
	SchemaVersion int               `json:"schema_version"`
	Purpose       EnrollmentPurpose `json:"purpose"`
	Token         string            `json:"token"`
	NodeNonce     string            `json:"node_nonce"`
	Payload       json.RawMessage   `json:"payload"`
}

type PublicEnrollmentResponse struct {
	SchemaVersion    int                        `json:"schema_version"`
	Purpose          EnrollmentPurpose          `json:"purpose"`
	GatewayNonce     string                     `json:"gateway_nonce"`
	SignedTranscript SignedEnrollmentTranscript `json:"signed_transcript"`
	Data             json.RawMessage            `json:"data"`
}

func NewPublicEnrollmentHandler(config PublicEnrollmentHandlerConfig) (*PublicEnrollmentHandler, error) {
	address, err := netip.ParseAddr(config.PublicIPv4)
	if err != nil || !address.Is4() || address.String() != config.PublicIPv4 {
		return nil, fmt.Errorf("public enrollment requires a canonical public IPv4")
	}
	if config.Signer == nil || config.Signer.Fingerprint() == "" || config.Coordinator == nil {
		return nil, fmt.Errorf("public enrollment signer and coordinator are required")
	}
	if config.Entropy == nil {
		config.Entropy = rand.Reader
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &PublicEnrollmentHandler{
		publicIPv4: config.PublicIPv4, signer: config.Signer, coordinator: config.Coordinator,
		entropy: config.Entropy, now: config.Now,
		sessions: make(chan struct{}, control.RPCMaximumConcurrentSessions),
	}, nil
}

func (handler *PublicEnrollmentHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setPublicEnrollmentHeaders(writer, request)
	if handler == nil || handler.signer == nil || handler.coordinator == nil || request == nil {
		writePublicEnrollmentError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	purpose, endpoint, ok := handler.route(request)
	if !ok {
		writePublicEnrollmentError(writer, http.StatusNotFound, "not_found")
		return
	}
	if !handler.acquireSession() {
		writePublicEnrollmentError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	defer handler.releaseSession()
	if publicEnrollmentHeaderBytes(request) > control.RPCMaximumHeaderBytes {
		writePublicEnrollmentError(writer, http.StatusRequestHeaderFieldsTooLarge, "request_too_large")
		return
	}
	if request.Method != http.MethodPost || request.ProtoMajor != 1 || request.ProtoMinor != 1 {
		writePublicEnrollmentError(writer, http.StatusNotFound, "not_found")
		return
	}
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != PublicEnrollmentContentType || len(parameters) != 0 {
		writePublicEnrollmentError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if request.ContentLength > control.RPCMaximumRequestBytes {
		writePublicEnrollmentError(writer, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, control.RPCMaximumRequestBytes)
	body, err := readPublicEnrollmentBody(request.Body, control.RPCMaximumRequestBytes)
	if err != nil {
		writePublicEnrollmentError(writer, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	defer clear(body)
	wireRequest, token, nodeNonce, err := decodePublicEnrollmentRequest(body, purpose)
	if err != nil {
		writePublicEnrollmentError(writer, http.StatusNotFound, "not_found")
		return
	}
	defer token.Destroy()

	gatewayNonce, err := handler.newNonce()
	if err != nil {
		writePublicEnrollmentError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	handlerRequest := PublicEnrollmentRequest{
		Purpose: purpose, Endpoint: endpoint, NodeNonce: nodeNonce, GatewayNonce: gatewayNonce,
		Payload: append(json.RawMessage(nil), wireRequest.Payload...), token: &token,
	}
	defer clear(handlerRequest.Payload)
	handlerContext, cancel := context.WithTimeout(request.Context(), control.RPCWriteTimeout)
	defer cancel()
	transaction, err := handler.coordinator.PreparePublicEnrollment(handlerContext, handlerRequest)
	if err != nil || transaction == nil {
		handler.writeCoordinatorError(writer, err)
		return
	}
	defer transaction.Destroy()
	transcript := transaction.Transcript()
	if err := validatePreparedTranscript(transcript, handlerRequest, handler.now()); err != nil {
		writePublicEnrollmentError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if transaction.EnrollmentFingerprint() != handler.signer.Fingerprint() {
		writePublicEnrollmentError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	signed, err := handler.signer.Sign(transcript)
	if err != nil {
		writePublicEnrollmentError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	encoded, err := encodePublicEnrollmentResponse(transaction, purpose, signed)
	if err != nil {
		writePublicEnrollmentError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	defer clear(encoded)
	replayHash, err := EnrollmentReplayHash(signed)
	if err != nil {
		writePublicEnrollmentError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if err := transaction.Commit(handlerContext, replayHash); err != nil {
		handler.writeCoordinatorError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func DecodePublicEnrollmentResponse(data []byte, expectedPurpose EnrollmentPurpose) (PublicEnrollmentResponse, error) {
	if len(data) == 0 || len(data) > control.RPCMaximumResponseBytes {
		return PublicEnrollmentResponse{}, fmt.Errorf("invalid public enrollment response size")
	}
	var response PublicEnrollmentResponse
	if err := control.DecodeRPCPayload(json.RawMessage(data), &response); err != nil {
		return PublicEnrollmentResponse{}, fmt.Errorf("invalid public enrollment response: %w", err)
	}
	if response.SchemaVersion != PublicEnrollmentSchemaVersion || response.Purpose != expectedPurpose ||
		len(response.Data) == 0 || len(response.Data) > control.RPCMaximumResponseBytes {
		return PublicEnrollmentResponse{}, fmt.Errorf("invalid public enrollment response envelope")
	}
	gatewayNonce, err := decodeCanonicalBase64(response.GatewayNonce)
	if err != nil || len(gatewayNonce) != EnrollmentNonceBytes || allZero(gatewayNonce) {
		clear(gatewayNonce)
		return PublicEnrollmentResponse{}, fmt.Errorf("invalid public enrollment gateway nonce")
	}
	clear(gatewayNonce)
	var object map[string]json.RawMessage
	if err := control.DecodeRPCPayload(response.Data, &object); err != nil {
		return PublicEnrollmentResponse{}, fmt.Errorf("invalid public enrollment response data: %w", err)
	}
	if response.SignedTranscript.SchemaVersion != EnrollmentTranscriptSchemaVersion ||
		response.SignedTranscript.Algorithm != EnrollmentSignatureAlgorithm ||
		!fingerprintPattern.MatchString(response.SignedTranscript.KeyFingerprint) {
		return PublicEnrollmentResponse{}, fmt.Errorf("invalid public enrollment signed transcript")
	}
	return response, nil
}

func (handler *PublicEnrollmentHandler) route(request *http.Request) (EnrollmentPurpose, string, bool) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		return "", "", false
	}
	switch request.URL.Path {
	case InviteEnrollmentPath:
		return PurposeEnroll, "https://" + handler.publicIPv4 + InviteEnrollmentPath, true
	case EnrollmentRecoveryPath:
		return PurposeRecover, "https://" + handler.publicIPv4 + EnrollmentRecoveryPath, true
	default:
		return "", "", false
	}
}

func (handler *PublicEnrollmentHandler) acquireSession() bool {
	select {
	case handler.sessions <- struct{}{}:
		return true
	default:
		return false
	}
}

func (handler *PublicEnrollmentHandler) releaseSession() {
	<-handler.sessions
}

func (handler *PublicEnrollmentHandler) newNonce() ([EnrollmentNonceBytes]byte, error) {
	var nonce [EnrollmentNonceBytes]byte
	handler.entropyMu.Lock()
	_, err := io.ReadFull(handler.entropy, nonce[:])
	handler.entropyMu.Unlock()
	if err != nil || allZero(nonce[:]) {
		return [EnrollmentNonceBytes]byte{}, fmt.Errorf("generate gateway nonce")
	}
	return nonce, nil
}

func (handler *PublicEnrollmentHandler) writeCoordinatorError(writer http.ResponseWriter, err error) {
	if errors.Is(err, ErrPublicEnrollmentUnavailable) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		writePublicEnrollmentError(writer, http.StatusServiceUnavailable, "unavailable")
		return
	}
	writePublicEnrollmentError(writer, http.StatusNotFound, "not_found")
}

func decodePublicEnrollmentRequest(data []byte, pathPurpose EnrollmentPurpose) (publicEnrollmentWireRequest, output.Secret, [EnrollmentNonceBytes]byte, error) {
	var request publicEnrollmentWireRequest
	if err := control.DecodeRPCPayload(json.RawMessage(data), &request); err != nil {
		return request, output.Secret{}, [EnrollmentNonceBytes]byte{}, ErrPublicEnrollmentRejected
	}
	expectedTokenPrefix := InviteTokenPrefix
	if pathPurpose == PurposeRecover {
		expectedTokenPrefix = RecoveryTokenPrefix
	}
	if request.SchemaVersion != PublicEnrollmentSchemaVersion || request.Purpose != pathPurpose ||
		len(request.Token) == 0 || len(request.Token) > maximumInviteTokenBytes ||
		!strings.HasPrefix(request.Token, expectedTokenPrefix+".") {
		return request, output.Secret{}, [EnrollmentNonceBytes]byte{}, ErrPublicEnrollmentRejected
	}
	nonceBytes, err := decodeCanonicalBase64(request.NodeNonce)
	if err != nil || len(nonceBytes) != EnrollmentNonceBytes || allZero(nonceBytes) {
		clear(nonceBytes)
		return request, output.Secret{}, [EnrollmentNonceBytes]byte{}, ErrPublicEnrollmentRejected
	}
	var nonce [EnrollmentNonceBytes]byte
	copy(nonce[:], nonceBytes)
	clear(nonceBytes)
	var payloadObject map[string]json.RawMessage
	if len(request.Payload) == 0 || len(request.Payload) > control.RPCMaximumRequestBytes ||
		control.DecodeRPCPayload(request.Payload, &payloadObject) != nil {
		return request, output.Secret{}, [EnrollmentNonceBytes]byte{}, ErrPublicEnrollmentRejected
	}
	token, err := output.NewSecretString(request.Token)
	request.Token = ""
	if err != nil {
		return request, output.Secret{}, [EnrollmentNonceBytes]byte{}, ErrPublicEnrollmentRejected
	}
	return request, token, nonce, nil
}

func validatePreparedTranscript(transcript EnrollmentTranscript, request PublicEnrollmentRequest, now time.Time) error {
	if err := transcript.Validate(); err != nil {
		return err
	}
	if transcript.Purpose != request.Purpose || transcript.Endpoint != request.Endpoint ||
		transcript.NodeNonce != request.NodeNonce || transcript.GatewayNonce != request.GatewayNonce {
		return fmt.Errorf("prepared transcript does not bind the public request")
	}
	now = now.UTC()
	if now.Before(transcript.IssuedAt.Add(-EnrollmentClockSkew)) || !now.Before(transcript.ExpiresAt) {
		return ErrEnrollmentTranscriptExpired
	}
	return nil
}

func encodePublicEnrollmentResponse(transaction PublicEnrollmentTransaction, purpose EnrollmentPurpose, signed SignedEnrollmentTranscript) ([]byte, error) {
	transcript := transaction.Transcript()
	gatewayNonce, err := CanonicalPublicEnrollmentNonce(transcript.GatewayNonce)
	if err != nil {
		return nil, err
	}
	var encoded []byte
	err = transaction.UseResponseData(func(data json.RawMessage) error {
		if len(data) == 0 || len(data) > control.RPCMaximumResponseBytes {
			return fmt.Errorf("public enrollment response data exceeds its limit")
		}
		var object map[string]json.RawMessage
		if err := control.DecodeRPCPayload(data, &object); err != nil {
			return fmt.Errorf("public enrollment response data is invalid: %w", err)
		}
		response := PublicEnrollmentResponse{
			SchemaVersion: PublicEnrollmentSchemaVersion, Purpose: purpose,
			GatewayNonce: gatewayNonce, SignedTranscript: signed, Data: data,
		}
		var err error
		encoded, err = json.Marshal(response)
		return err
	})
	if err != nil {
		clear(encoded)
		return nil, err
	}
	if len(encoded) > control.RPCMaximumResponseBytes {
		clear(encoded)
		return nil, fmt.Errorf("public enrollment response exceeds its limit")
	}
	return encoded, nil
}

func readPublicEnrollmentBody(reader io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		clear(data)
		return nil, fmt.Errorf("body exceeds %d bytes", maximum)
	}
	return data, nil
}

func publicEnrollmentHeaderBytes(request *http.Request) int {
	if request == nil {
		return 0
	}
	total := len(request.Host)
	for name, values := range request.Header {
		total += len(name)
		for _, value := range values {
			total += len(value)
		}
	}
	return total
}

func setPublicEnrollmentHeaders(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", PublicEnrollmentContentType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Pragma", "no-cache")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Connection", "close")
	if request != nil {
		request.Close = true
	}
}

func writePublicEnrollmentError(writer http.ResponseWriter, status int, code string) {
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, `{"error":"`+code+`"}`)
}

// CanonicalPublicEnrollmentNonce returns the wire representation used by node
// requests and is exported so the node-side join flow cannot choose a subtly
// different encoding.
func CanonicalPublicEnrollmentNonce(nonce [EnrollmentNonceBytes]byte) (string, error) {
	if allZero(nonce[:]) {
		return "", fmt.Errorf("public enrollment nonce must not be zero")
	}
	return base64.RawURLEncoding.EncodeToString(nonce[:]), nil
}
