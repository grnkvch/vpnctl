package control

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RPCServerConfig struct {
	GatewayID              string
	NodeCIDR               string
	CertificatePEM         []byte
	PrivateKeyPEM          []byte
	ClientCACertificatePEM []byte
	Protocols              *RPCProtocolRegistry
	Now                    func() time.Time
}

type rpcLimits struct {
	maximumRequestBytes       int64
	maximumResponseBytes      int
	maximumHeaderBytes        int
	maximumConcurrentSessions int
	readHeaderTimeout         time.Duration
	readBodyTimeout           time.Duration
	writeTimeout              time.Duration
	idleTimeout               time.Duration
}

type RPCServer struct {
	overlayIPv4 string
	protocols   *RPCProtocolRegistry
	now         func() time.Time
	tlsConfig   *tls.Config
	limits      rpcLimits
}

func NewRPCServer(config RPCServerConfig) (*RPCServer, error) {
	return newRPCServer(config, defaultRPCLimits())
}

func newRPCServer(config RPCServerConfig, limits rpcLimits) (*RPCServer, error) {
	if config.Protocols == nil {
		return nil, fmt.Errorf("control RPC protocol registry is required")
	}
	overlayIPv4, err := GatewayOverlayIPv4(config.NodeCIDR)
	if err != nil {
		return nil, err
	}
	expectedURI, err := controlIdentityURI("gateway", config.GatewayID)
	if err != nil {
		return nil, err
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if err := validateRPCLimits(limits); err != nil {
		return nil, err
	}
	serverCertificate, leaf, err := parseTLSCertificate(config.CertificatePEM, config.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load gateway control TLS identity: %w", err)
	}
	if leaf.PublicKeyAlgorithm != x509.Ed25519 || len(leaf.URIs) != 1 || leaf.URIs[0].String() != expectedURI.String() ||
		len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != overlayIPv4 || len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 {
		return nil, fmt.Errorf("%w: gateway certificate identity does not match configured overlay", ErrInvalidRPCIdentity)
	}
	clientCA, err := parseControlCACertificate(config.ClientCACertificatePEM)
	if err != nil {
		return nil, err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: newCertificatePool(clientCA), DNSName: overlayIPv4,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, CurrentTime: config.Now().UTC(),
	}); err != nil {
		return nil, fmt.Errorf("verify gateway control TLS identity: %w", err)
	}
	return &RPCServer{
		overlayIPv4: overlayIPv4, protocols: config.Protocols, now: config.Now, limits: limits,
		tlsConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: newCertificatePool(clientCA), NextProtos: []string{"http/1.1"}, Time: config.Now,
		},
	}, nil
}

// ListenAndServe binds the fixed control port on only the derived gateway
// address inside the node overlay. It never listens on a wildcard or public
// address.
func (server *RPCServer) ListenAndServe(ctx context.Context) error {
	if server == nil {
		return fmt.Errorf("control RPC server is required")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(server.overlayIPv4, strconv.Itoa(RPCControlTCPPort)))
	if err != nil {
		return fmt.Errorf("listen on internal control overlay: %w", err)
	}
	return server.Serve(ctx, listener)
}

// Serve accepts a pre-bound listener for orchestration and tests but still
// refuses any address other than the configured gateway overlay identity.
func (server *RPCServer) Serve(ctx context.Context, listener net.Listener) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if server == nil || server.protocols == nil || server.tlsConfig == nil {
		return fmt.Errorf("control RPC server is incomplete")
	}
	if listener == nil {
		return fmt.Errorf("control RPC listener is required")
	}
	if err := server.validateListener(listener); err != nil {
		_ = listener.Close()
		return err
	}

	bounded := &rpcLimitedListener{Listener: listener, tokens: make(chan struct{}, server.limits.maximumConcurrentSessions)}
	tlsListener := tls.NewListener(bounded, server.tlsConfig.Clone())
	httpServer := &http.Server{
		Handler:           server,
		TLSConfig:         server.tlsConfig.Clone(),
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ReadHeaderTimeout: server.limits.readHeaderTimeout,
		ReadTimeout:       server.limits.readBodyTimeout,
		WriteTimeout:      server.limits.writeTimeout,
		IdleTimeout:       server.limits.idleTimeout,
		MaxHeaderBytes:    server.limits.maximumHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.Background(), server.limits.writeTimeout)
			defer cancel()
			_ = httpServer.Shutdown(shutdownContext)
			_ = tlsListener.Close()
		case <-stopped:
		}
	}()
	err := httpServer.Serve(tlsListener)
	close(stopped)
	if errors.Is(err, http.ErrServerClosed) || (ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("serve internal control RPC: %w", err)
	}
	return nil
}

func (server *RPCServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", RPCContentType)
	writer.Header().Set("Connection", "close")
	request.Close = true
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 || request.TLS.Version != tls.VersionTLS13 || request.TLS.NegotiatedProtocol != "http/1.1" {
		server.writeResponse(writer, http.StatusForbidden, rpcFailure("validation", "mtls_required", "a verified node mTLS identity is required"))
		return
	}
	peer, err := rpcPeerFromCertificate(request.TLS.PeerCertificates[0])
	if err != nil {
		server.writeResponse(writer, http.StatusForbidden, rpcFailure("validation", "invalid_identity", "the node certificate identity is invalid"))
		return
	}
	pathMajor, operation, ok := rpcOperationFromRequest(request)
	if !ok {
		server.writeResponse(writer, http.StatusNotFound, rpcFailure("validation", "invalid_endpoint", "the control RPC endpoint is invalid"))
		return
	}
	if request.Method != http.MethodPost || request.ProtoMajor != 1 || request.ProtoMinor != 1 {
		server.writeResponse(writer, http.StatusMethodNotAllowed, rpcFailure("validation", "invalid_http", "control RPC requires POST over HTTP/1.1"))
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != RPCContentType {
		server.writeResponse(writer, http.StatusUnsupportedMediaType, rpcFailure("validation", "invalid_content_type", "control RPC requires application/json"))
		return
	}
	if request.ContentLength > server.limits.maximumRequestBytes {
		server.writeResponse(writer, http.StatusRequestEntityTooLarge, rpcFailure("validation", "request_too_large", "the control RPC request exceeds its size limit"))
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, server.limits.maximumRequestBytes)
	body, err := readBoundedBody(request.Body, server.limits.maximumRequestBytes)
	if err != nil {
		server.writeResponse(writer, http.StatusRequestEntityTooLarge, rpcFailure("validation", "request_too_large", "the control RPC request exceeds its size limit"))
		return
	}
	envelope, err := DecodeRPCRequest(body)
	if err != nil {
		server.writeResponse(writer, http.StatusBadRequest, rpcFailure("validation", "invalid_request", "the control RPC request is invalid"))
		return
	}
	if envelope.Operation != operation {
		server.writeResponse(writer, http.StatusBadRequest, rpcFailure("validation", "operation_mismatch", "the path and request operation differ"))
		return
	}
	if envelope.ProtocolMajor != pathMajor {
		server.writeResponse(writer, http.StatusConflict, rpcFailureForVersion(envelope, "conflict", "protocol_path_mismatch", "the path and request protocol majors differ"))
		return
	}
	if envelope.NodeID != peer.NodeID {
		server.writeResponse(writer, http.StatusForbidden, rpcFailure("validation", "identity_mismatch", "the certificate and request node identities differ"))
		return
	}
	now := server.now().UTC()
	if envelope.Timestamp.Before(now.Add(-RPCClockSkew)) || envelope.Timestamp.After(now.Add(RPCClockSkew)) {
		server.writeResponse(writer, http.StatusBadRequest, rpcFailure("validation", "timestamp_outside_window", "the control RPC timestamp is outside the accepted window"))
		return
	}
	handlerContext, cancel := context.WithTimeout(request.Context(), server.limits.writeTimeout)
	defer cancel()
	result, err := server.protocols.HandleRPC(handlerContext, peer, envelope)
	if err != nil {
		server.writeResponse(writer, http.StatusInternalServerError, rpcFailure("internal", "handler_failed", "the control RPC request could not be completed"))
		return
	}
	if result.Response.Validate() != nil {
		server.writeResponse(writer, http.StatusInternalServerError, result.Response)
		return
	}
	if result.Response.ProtocolMajor != envelope.ProtocolMajor || result.Response.ProtocolMinor != envelope.ProtocolMinor {
		server.writeResponse(writer, http.StatusInternalServerError, rpcFailureForVersion(envelope, "internal", "protocol_response_mismatch", "the control RPC handler returned a mismatched protocol version"))
		return
	}
	if validateRPCHandlerResult(result) != nil {
		server.writeResponse(writer, http.StatusInternalServerError, rpcFailure("internal", "handler_failed", "the control RPC request could not be completed"))
		return
	}
	server.writeResponse(writer, result.StatusCode, result.Response)
}

func (server *RPCServer) writeResponse(writer http.ResponseWriter, status int, response RPCResponse) {
	validationErr := response.Validate()
	var encoded []byte
	var err error
	if validationErr == nil {
		encoded, err = json.Marshal(response)
	}
	if validationErr != nil || err != nil || len(encoded) > server.limits.maximumResponseBytes {
		status = http.StatusInternalServerError
		encoded, _ = json.Marshal(rpcFailure("internal", "response_too_large", "the control RPC response exceeded its safety boundary"))
	}
	writer.Header().Set("Content-Type", RPCContentType)
	writer.Header().Set("Connection", "close")
	writer.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func (server *RPCServer) validateListener(listener net.Listener) error {
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address.IP == nil || address.IP.To4() == nil || address.IP.IsUnspecified() || address.IP.String() != server.overlayIPv4 {
		return fmt.Errorf("control RPC listener must bind only %s", server.overlayIPv4)
	}
	return nil
}

func rpcOperationFromRequest(request *http.Request) (int, string, bool) {
	const prefix = "/rpc/v"
	if request.URL.RawPath != "" || request.URL.RawQuery != "" || !strings.HasPrefix(request.URL.Path, prefix) {
		return 0, "", false
	}
	majorText, operation, found := strings.Cut(strings.TrimPrefix(request.URL.Path, prefix), "/")
	if !found || majorText == "" || (len(majorText) > 1 && majorText[0] == '0') || !rpcOperationPattern.MatchString(operation) {
		return 0, "", false
	}
	major, err := strconv.Atoi(majorText)
	if err != nil || major < 1 {
		return 0, "", false
	}
	return major, operation, true
}

func parseTLSCertificate(certificatePEM, privateKeyPEM []byte) (tls.Certificate, *x509.Certificate, error) {
	certificateDER, err := decodeSinglePEM(certificatePEM, "CERTIFICATE")
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	privateKeyDER, err := decodeSinglePEM(privateKeyPEM, "PRIVATE KEY")
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	parsedPrivateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("TLS private key must use PKCS#8: %w", err)
	}
	privateKey, ok := parsedPrivateKey.(ed25519.PrivateKey)
	publicKey, publicOK := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !publicOK || !publicKey.Equal(privateKey.Public()) {
		return tls.Certificate{}, nil, fmt.Errorf("TLS identity must use a matching Ed25519 key")
	}
	certificate := tls.Certificate{Certificate: [][]byte{certificateDER}, PrivateKey: privateKey, Leaf: leaf}
	return certificate, leaf, nil
}

func parseControlCACertificate(certificatePEM []byte) (*x509.Certificate, error) {
	der, err := decodeSinglePEM(certificatePEM, "CERTIFICATE")
	if err != nil {
		return nil, fmt.Errorf("parse control client CA: %w", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse control client CA: %w", err)
	}
	if certificate.PublicKeyAlgorithm != x509.Ed25519 || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("%w: client authority must be an Ed25519 control CA", ErrInvalidRPCIdentity)
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return nil, fmt.Errorf("%w: client control CA must be self-signed", ErrInvalidRPCIdentity)
	}
	return certificate, nil
}

func newCertificatePool(certificates ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool
}

func defaultRPCLimits() rpcLimits {
	return rpcLimits{
		maximumRequestBytes: RPCMaximumRequestBytes, maximumResponseBytes: RPCMaximumResponseBytes,
		maximumHeaderBytes: RPCMaximumHeaderBytes, maximumConcurrentSessions: RPCMaximumConcurrentSessions,
		readHeaderTimeout: RPCReadHeaderTimeout, readBodyTimeout: RPCReadBodyTimeout,
		writeTimeout: RPCWriteTimeout, idleTimeout: RPCIdleTimeout,
	}
}

func validateRPCLimits(limits rpcLimits) error {
	if limits.maximumRequestBytes < 1 || limits.maximumResponseBytes < 1 || limits.maximumHeaderBytes < 1 || limits.maximumConcurrentSessions < 1 ||
		limits.readHeaderTimeout <= 0 || limits.readBodyTimeout <= 0 || limits.writeTimeout <= 0 || limits.idleTimeout <= 0 {
		return fmt.Errorf("control RPC limits must all be positive")
	}
	return nil
}

type rpcLimitedListener struct {
	net.Listener
	tokens chan struct{}
}

type rpcLimitedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (connection *rpcLimitedConnection) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}

func (listener *rpcLimitedListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case listener.tokens <- struct{}{}:
			return &rpcLimitedConnection{Conn: connection, release: func() { <-listener.tokens }}, nil
		default:
			_ = connection.Close()
		}
	}
}
