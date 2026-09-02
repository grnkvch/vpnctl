package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

type RPCClientConfig struct {
	Address          string
	GatewayID        string
	NodeID           string
	CACertificatePEM []byte
	CertificatePEM   []byte
	PrivateKeyPEM    []byte
	Timeout          time.Duration
	Now              func() time.Time
}

type RPCCallResult struct {
	StatusCode int
	Response   RPCResponse
}

type RPCClient struct {
	address   string
	nodeID    string
	tlsConfig *tls.Config
	timeout   time.Duration
}

// CallManagement preserves local request validation errors, but turns an
// unreachable/failed control transport into the same typed unavailable result
// shape used by a reachable controller. It never retries and never queues the
// request locally, so callers can fail without changing desired state.
func (client *RPCClient) CallManagement(ctx context.Context, request RPCRequest) (RPCCallResult, error) {
	if ctx == nil {
		return RPCCallResult{}, fmt.Errorf("context is required")
	}
	if client == nil || client.tlsConfig == nil {
		return RPCCallResult{}, fmt.Errorf("control RPC client is incomplete")
	}
	if err := request.Validate(); err != nil {
		return RPCCallResult{}, err
	}
	if request.NodeID != client.nodeID {
		return RPCCallResult{}, fmt.Errorf("%w: request node does not match client identity", ErrInvalidRPCIdentity)
	}
	result, err := client.Call(ctx, request)
	if err == nil {
		return result, nil
	}
	response := NewRPCResponse("unavailable", 0, json.RawMessage(`{}`))
	response.ProtocolMajor = request.ProtocolMajor
	response.ProtocolMinor = request.ProtocolMinor
	response.ErrorCode = "controller_unavailable"
	response.Message = "the gateway controller could not be reached for this management request"
	response.RequiresAction = []string{"verify gateway control connectivity and retry the command"}
	return RPCCallResult{StatusCode: http.StatusServiceUnavailable, Response: response}, nil
}

func NewRPCClient(config RPCClientConfig) (*RPCClient, error) {
	host, portText, err := net.SplitHostPort(config.Address)
	if err != nil {
		return nil, fmt.Errorf("control RPC address must be host:port: %w", err)
	}
	address := net.ParseIP(host)
	port, portErr := strconv.Atoi(portText)
	if address == nil || address.To4() == nil || address.IsUnspecified() || address.String() != host || portErr != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("control RPC address must contain canonical gateway overlay IPv4 and a valid port")
	}
	expectedGatewayURI, err := controlIdentityURI("gateway", config.GatewayID)
	if err != nil {
		return nil, err
	}
	if _, err := controlIdentityURI("node", config.NodeID); err != nil {
		return nil, err
	}
	clientCertificate, leaf, err := parseTLSCertificate(config.CertificatePEM, config.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load node control TLS identity: %w", err)
	}
	peer, err := rpcPeerFromCertificate(leaf)
	if err != nil || peer.NodeID != config.NodeID {
		return nil, fmt.Errorf("%w: node certificate does not match configured node", ErrInvalidRPCIdentity)
	}
	controlCAs, err := parseControlCACertificateBundle(config.CACertificatePEM)
	if err != nil {
		return nil, err
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: newCertificatePool(controlCAs...), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: config.Now().UTC(),
	}); err != nil {
		return nil, fmt.Errorf("verify node control TLS identity: %w", err)
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = RPCClientTimeout
	}
	if timeout <= 0 || timeout > time.Minute {
		return nil, fmt.Errorf("control RPC client timeout must be positive and no more than one minute")
	}
	roots := newCertificatePool(controlCAs...)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, Certificates: []tls.Certificate{clientCertificate}, ServerName: host, NextProtos: []string{"http/1.1"}, Time: config.Now,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("%w: gateway certificate is absent", ErrInvalidRPCIdentity)
			}
			certificate := state.PeerCertificates[0]
			if certificate.PublicKeyAlgorithm != x509.Ed25519 || len(certificate.URIs) != 1 || certificate.URIs[0].String() != expectedGatewayURI.String() ||
				len(certificate.IPAddresses) != 1 || certificate.IPAddresses[0].String() != host || len(certificate.DNSNames) != 0 || len(certificate.EmailAddresses) != 0 {
				return fmt.Errorf("%w: gateway certificate identity does not match the configured endpoint", ErrInvalidRPCIdentity)
			}
			return nil
		},
	}
	return &RPCClient{address: config.Address, nodeID: config.NodeID, tlsConfig: tlsConfig, timeout: timeout}, nil
}

func parseControlCACertificateBundle(certificatePEM []byte) ([]*x509.Certificate, error) {
	remaining := bytes.TrimSpace(certificatePEM)
	certificates := make([]*x509.Certificate, 0, 2)
	seen := make(map[string]struct{}, 2)
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("control CA bundle must contain only PEM certificates")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse control CA certificate: %w", err)
		}
		if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.PublicKeyAlgorithm != x509.Ed25519 ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("control CA certificate is not an Ed25519 certificate authority")
		}
		fingerprint := certificateFingerprint(certificate)
		if _, duplicate := seen[fingerprint]; duplicate {
			return nil, fmt.Errorf("control CA bundle contains a duplicate authority")
		}
		seen[fingerprint] = struct{}{}
		certificates = append(certificates, certificate)
		if len(certificates) > 2 {
			return nil, fmt.Errorf("control CA bundle must contain one or two authorities")
		}
		remaining = bytes.TrimSpace(rest)
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("control CA bundle must contain one or two authorities")
	}
	return certificates, nil
}

// Call creates a new HTTP transport for exactly one request and closes it on
// return. The node CLI therefore has no background pool or offline queue.
func (client *RPCClient) Call(ctx context.Context, request RPCRequest) (RPCCallResult, error) {
	if ctx == nil {
		return RPCCallResult{}, fmt.Errorf("context is required")
	}
	if client == nil || client.tlsConfig == nil {
		return RPCCallResult{}, fmt.Errorf("control RPC client is incomplete")
	}
	if err := request.Validate(); err != nil {
		return RPCCallResult{}, err
	}
	if request.NodeID != client.nodeID {
		return RPCCallResult{}, fmt.Errorf("%w: request node does not match client identity", ErrInvalidRPCIdentity)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return RPCCallResult{}, fmt.Errorf("encode control RPC request: %w", err)
	}
	if len(encoded) > RPCMaximumRequestBytes {
		return RPCCallResult{}, fmt.Errorf("control RPC request exceeds %d bytes", RPCMaximumRequestBytes)
	}
	bounded, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(bounded, http.MethodPost, "https://"+client.address+rpcPath(request.ProtocolMajor, request.Operation), bytes.NewReader(encoded))
	if err != nil {
		return RPCCallResult{}, fmt.Errorf("build control RPC request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", RPCContentType)
	httpRequest.Header.Set("Connection", "close")
	httpRequest.Close = true
	transport := &http.Transport{
		TLSClientConfig: client.tlsConfig.Clone(), ForceAttemptHTTP2: false, DisableKeepAlives: true, DisableCompression: true,
		TLSHandshakeTimeout: RPCReadBodyTimeout, ResponseHeaderTimeout: RPCWriteTimeout, MaxResponseHeaderBytes: RPCMaximumHeaderBytes,
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("control RPC redirects are forbidden")
		},
	}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return RPCCallResult{}, fmt.Errorf("perform short-lived control RPC: %w", err)
	}
	defer httpResponse.Body.Close()
	if httpResponse.ProtoMajor != 1 || httpResponse.ProtoMinor != 1 || httpResponse.TLS == nil ||
		httpResponse.TLS.Version != tls.VersionTLS13 || httpResponse.TLS.NegotiatedProtocol != "http/1.1" {
		return RPCCallResult{}, fmt.Errorf("control RPC response did not use TLS 1.3 and HTTP/1.1")
	}
	if mediaType := httpResponse.Header.Get("Content-Type"); mediaType != RPCContentType {
		return RPCCallResult{}, fmt.Errorf("control RPC response content type is invalid")
	}
	body, err := readBoundedBody(httpResponse.Body, RPCMaximumResponseBytes)
	if err != nil {
		return RPCCallResult{}, fmt.Errorf("read bounded control RPC response: %w", err)
	}
	response, err := DecodeRPCResponse(body)
	if err != nil {
		return RPCCallResult{}, err
	}
	if response.ProtocolMajor != request.ProtocolMajor || response.ProtocolMinor != request.ProtocolMinor {
		return RPCCallResult{}, fmt.Errorf("control RPC response protocol does not match the negotiated request version")
	}
	return RPCCallResult{StatusCode: httpResponse.StatusCode, Response: response}, nil
}
