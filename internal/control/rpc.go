package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	RPCSchemaVersion             = 1
	RPCPathPrefix                = "/rpc/v1/"
	RPCContentType               = "application/json"
	RPCControlTCPPort            = 9443
	RPCMaximumRequestBytes       = 64 << 10
	RPCMaximumResponseBytes      = 256 << 10
	RPCMaximumHeaderBytes        = 8 << 10
	RPCMaximumJSONDepth          = 32
	RPCMaximumConcurrentSessions = 16
	RPCReadHeaderTimeout         = 2 * time.Second
	RPCReadBodyTimeout           = 5 * time.Second
	RPCWriteTimeout              = 5 * time.Second
	RPCIdleTimeout               = 5 * time.Second
	RPCClientTimeout             = 10 * time.Second
	RPCClockSkew                 = 120 * time.Second
	RPCNonceBytes                = 16
)

var (
	ErrInvalidRPCRequest  = errors.New("invalid control RPC request")
	ErrInvalidRPCResponse = errors.New("invalid control RPC response")
	ErrInvalidRPCIdentity = errors.New("invalid control RPC identity")
	rpcOperationPattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)
	rpcCodePattern        = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

type RPCRequest struct {
	ProtocolMajor           int             `json:"protocol_major"`
	ProtocolMinor           int             `json:"protocol_minor"`
	RequestID               string          `json:"request_id"`
	ExpectedStateGeneration uint64          `json:"expected_state_generation"`
	NodeID                  string          `json:"node_id"`
	CredentialGeneration    uint64          `json:"credential_generation"`
	Timestamp               time.Time       `json:"timestamp"`
	Nonce                   string          `json:"nonce"`
	Operation               string          `json:"operation"`
	Payload                 json.RawMessage `json:"payload"`
}

type RPCResponse struct {
	SchemaVersion           int               `json:"schema_version"`
	Category                string            `json:"category"`
	AuthoritativeGeneration uint64            `json:"authoritative_generation"`
	ResourceIDs             map[string]string `json:"resource_ids"`
	Warnings                []string          `json:"warnings"`
	RequiresAction          []string          `json:"requires_action"`
	ResultHash              string            `json:"result_hash,omitempty"`
	ErrorCode               string            `json:"error_code,omitempty"`
	Message                 string            `json:"message,omitempty"`
	Data                    json.RawMessage   `json:"data"`
}

type RPCPeer struct {
	NodeID                 string
	CertificateFingerprint string
}

type RPCHandlerResult struct {
	StatusCode int
	Response   RPCResponse
}

type RPCHandler interface {
	HandleRPC(context.Context, RPCPeer, RPCRequest) (RPCHandlerResult, error)
}

type RPCHandlerFunc func(context.Context, RPCPeer, RPCRequest) (RPCHandlerResult, error)

func (handler RPCHandlerFunc) HandleRPC(ctx context.Context, peer RPCPeer, request RPCRequest) (RPCHandlerResult, error) {
	return handler(ctx, peer, request)
}

func NewRPCResponse(category string, authoritativeGeneration uint64, data json.RawMessage) RPCResponse {
	if len(data) == 0 {
		data = json.RawMessage(`{}`)
	}
	return RPCResponse{
		SchemaVersion: RPCSchemaVersion, Category: category, AuthoritativeGeneration: authoritativeGeneration,
		ResourceIDs: map[string]string{}, Warnings: []string{}, RequiresAction: []string{}, Data: append(json.RawMessage(nil), data...),
	}
}

func DecodeRPCRequest(data []byte) (RPCRequest, error) {
	if len(data) == 0 || len(data) > RPCMaximumRequestBytes {
		return RPCRequest{}, fmt.Errorf("%w: body size is outside the accepted range", ErrInvalidRPCRequest)
	}
	var request RPCRequest
	if err := decodeStrictJSONWithDepth(data, &request, RPCMaximumJSONDepth); err != nil {
		return RPCRequest{}, fmt.Errorf("%w: %v", ErrInvalidRPCRequest, err)
	}
	if err := request.Validate(); err != nil {
		return RPCRequest{}, err
	}
	return request, nil
}

func DecodeRPCResponse(data []byte) (RPCResponse, error) {
	if len(data) == 0 || len(data) > RPCMaximumResponseBytes {
		return RPCResponse{}, fmt.Errorf("%w: body size is outside the accepted range", ErrInvalidRPCResponse)
	}
	var response RPCResponse
	if err := decodeStrictJSONWithDepth(data, &response, RPCMaximumJSONDepth); err != nil {
		return RPCResponse{}, fmt.Errorf("%w: %v", ErrInvalidRPCResponse, err)
	}
	if err := response.Validate(); err != nil {
		return RPCResponse{}, err
	}
	return response, nil
}

func DecodeRPCPayload(data json.RawMessage, destination any) error {
	if destination == nil {
		return fmt.Errorf("RPC payload destination is required")
	}
	if err := validateJSONObject(data); err != nil {
		return fmt.Errorf("invalid RPC payload: %w", err)
	}
	if err := decodeStrictJSONWithDepth(data, destination, RPCMaximumJSONDepth); err != nil {
		return fmt.Errorf("invalid RPC payload: %w", err)
	}
	return nil
}

func (request RPCRequest) Validate() error {
	if len(request.Payload) == 0 || len(request.Payload) > RPCMaximumRequestBytes {
		return fmt.Errorf("%w: payload size is outside the accepted range", ErrInvalidRPCRequest)
	}
	if request.ProtocolMajor < 1 || request.ProtocolMinor < 0 {
		return fmt.Errorf("%w: protocol version must be positive major and non-negative minor", ErrInvalidRPCRequest)
	}
	if !controlUUIDPattern.MatchString(request.RequestID) {
		return fmt.Errorf("%w: request_id must be a canonical lower-case UUID", ErrInvalidRPCRequest)
	}
	if !controlUUIDPattern.MatchString(request.NodeID) {
		return fmt.Errorf("%w: node_id must be a canonical lower-case UUID", ErrInvalidRPCRequest)
	}
	if request.CredentialGeneration == 0 {
		return fmt.Errorf("%w: credential_generation must be positive", ErrInvalidRPCRequest)
	}
	if request.Timestamp.IsZero() {
		return fmt.Errorf("%w: timestamp is required", ErrInvalidRPCRequest)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(request.Nonce)
	if err != nil || len(nonce) != RPCNonceBytes || base64.RawURLEncoding.EncodeToString(nonce) != request.Nonce {
		return fmt.Errorf("%w: nonce must be canonical unpadded base64url for %d bytes", ErrInvalidRPCRequest, RPCNonceBytes)
	}
	if !rpcOperationPattern.MatchString(request.Operation) {
		return fmt.Errorf("%w: operation is invalid", ErrInvalidRPCRequest)
	}
	if err := validateJSONObject(request.Payload); err != nil {
		return fmt.Errorf("%w: payload: %v", ErrInvalidRPCRequest, err)
	}
	return nil
}

func (response RPCResponse) Validate() error {
	if response.SchemaVersion != RPCSchemaVersion {
		return fmt.Errorf("%w: schema_version must be %d", ErrInvalidRPCResponse, RPCSchemaVersion)
	}
	switch response.Category {
	case "success", "validation", "conflict", "unavailable", "internal":
	default:
		return fmt.Errorf("%w: unsupported category", ErrInvalidRPCResponse)
	}
	if response.ResourceIDs == nil || response.Warnings == nil || response.RequiresAction == nil {
		return fmt.Errorf("%w: resource_ids, warnings, and requires_action must be present", ErrInvalidRPCResponse)
	}
	if len(response.Data) == 0 || len(response.Data) > RPCMaximumResponseBytes {
		return fmt.Errorf("%w: data size is outside the accepted range", ErrInvalidRPCResponse)
	}
	if len(response.ResourceIDs) > 256 || len(response.Warnings) > 256 || len(response.RequiresAction) > 256 {
		return fmt.Errorf("%w: response collection exceeds item limit", ErrInvalidRPCResponse)
	}
	for key, value := range response.ResourceIDs {
		if !rpcCodePattern.MatchString(key) || !safeRPCText(value, 256) {
			return fmt.Errorf("%w: resource_ids contains an invalid entry", ErrInvalidRPCResponse)
		}
	}
	for _, warning := range response.Warnings {
		if !safeRPCText(warning, 4096) {
			return fmt.Errorf("%w: warning is invalid", ErrInvalidRPCResponse)
		}
	}
	for _, action := range response.RequiresAction {
		if !safeRPCText(action, 4096) {
			return fmt.Errorf("%w: required action is invalid", ErrInvalidRPCResponse)
		}
	}
	if response.ResultHash != "" {
		value := strings.TrimPrefix(response.ResultHash, "sha256:")
		if len(value) != sha256.Size*2 {
			return fmt.Errorf("%w: result_hash must be SHA-256", ErrInvalidRPCResponse)
		}
		if _, err := hex.DecodeString(value); err != nil || strings.ToLower(value) != value {
			return fmt.Errorf("%w: result_hash must be lower-case SHA-256", ErrInvalidRPCResponse)
		}
	}
	if response.Category == "success" {
		if response.ErrorCode != "" || response.Message != "" {
			return fmt.Errorf("%w: successful response must not carry an error", ErrInvalidRPCResponse)
		}
	} else if !rpcCodePattern.MatchString(response.ErrorCode) || !safeRPCText(response.Message, 4096) {
		return fmt.Errorf("%w: failed response requires a safe error_code and message", ErrInvalidRPCResponse)
	}
	if err := validateJSONObject(response.Data); err != nil {
		return fmt.Errorf("%w: data: %v", ErrInvalidRPCResponse, err)
	}
	return nil
}

func validateJSONObject(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 2 || trimmed[0] != '{' {
		return fmt.Errorf("must be a JSON object")
	}
	var object map[string]json.RawMessage
	if err := decodeStrictJSONWithDepth(trimmed, &object, RPCMaximumJSONDepth); err != nil {
		return err
	}
	if object == nil {
		return fmt.Errorf("must not be null")
	}
	return nil
}

func rpcPeerFromCertificate(certificate *x509.Certificate) (RPCPeer, error) {
	if certificate == nil || certificate.PublicKeyAlgorithm != x509.Ed25519 || len(certificate.URIs) != 1 ||
		len(certificate.DNSNames) != 0 || len(certificate.IPAddresses) != 0 || len(certificate.EmailAddresses) != 0 {
		return RPCPeer{}, fmt.Errorf("%w: client certificate must contain only one Ed25519 node URI identity", ErrInvalidRPCIdentity)
	}
	const prefix = "urn:vpnctl:node:"
	value := certificate.URIs[0].String()
	if !strings.HasPrefix(value, prefix) {
		return RPCPeer{}, fmt.Errorf("%w: client certificate URI namespace is invalid", ErrInvalidRPCIdentity)
	}
	nodeID := strings.TrimPrefix(value, prefix)
	expected, err := controlIdentityURI("node", nodeID)
	if err != nil || expected.String() != value {
		return RPCPeer{}, fmt.Errorf("%w: client certificate node URI is not canonical", ErrInvalidRPCIdentity)
	}
	fingerprint := sha256.Sum256(certificate.Raw)
	return RPCPeer{NodeID: nodeID, CertificateFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:])}, nil
}

func rpcFailure(category, code, message string) RPCResponse {
	response := NewRPCResponse(category, 0, json.RawMessage(`{}`))
	response.ErrorCode = code
	response.Message = message
	return response
}

func validateRPCHandlerResult(result RPCHandlerResult) error {
	if result.StatusCode < http.StatusOK || result.StatusCode > 599 || result.StatusCode == http.StatusNoContent ||
		(result.StatusCode >= http.StatusMultipleChoices && result.StatusCode < http.StatusBadRequest) {
		return fmt.Errorf("handler status code is invalid")
	}
	if err := result.Response.Validate(); err != nil {
		return err
	}
	if result.Response.Category == "success" && result.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("successful RPC response requires a success HTTP status")
	}
	if result.Response.Category != "success" && result.StatusCode < http.StatusBadRequest {
		return fmt.Errorf("failed RPC response requires an error HTTP status")
	}
	return nil
}

func safeRPCText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func readBoundedBody(reader io.Reader, maximum int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("body exceeds %d bytes", maximum)
	}
	return data, nil
}
