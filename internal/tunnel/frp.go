package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	FRPProviderName           = "frp"
	FRPProviderVersion        = "0.69.0"
	FRPProviderAsset          = "frp_0.69.0_linux_amd64.tar.gz"
	FRPProviderSHA256         = "6b90d1cd28fc661f170c0de90dde03d2c63e4fd7ce0ae2da2ca1c28014b8146e"
	FRPServerPort             = 17000
	FRPClientAdminPort        = 17400
	FRPAuthorizationPort      = 19091
	FRPTLSServerName          = "vpnctl-tunnel-gateway"
	FRPTCPMuxKeepaliveSec     = 5
	FRPHeartbeatSec           = 1
	FRPHeartbeatTimeoutSec    = 4
	FRPHealthCheckTimeoutSec  = 1
	FRPHealthCheckMaxFailed   = 1
	FRPHealthCheckIntervalSec = 3

	FRPServerConfigFileName     = "tunnel-server.toml"
	FRPClientConfigFileName     = "tunnel-client.toml"
	FRPServerReadyFileName      = "gateway-tunnel-server.ready"
	FRPClientReadyFileName      = "node-tunnel-client.ready"
	FRPServerCertificateName    = "tunnel-server.crt"
	FRPServerPrivateKeyName     = "tunnel-server.key"
	FRPServerBinaryRelativePath = "usr/local/libexec/vpnctl/frps"
	FRPClientBinaryRelativePath = "usr/local/libexec/vpnctl/frpc"

	maximumFRPConfigBytes = 1 << 20
)

var frpMappingSuffixPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// FRPNodeCredentialSource supplies the already provisioned per-node tunnel
// token without exposing storage details to the provider contract.
type FRPNodeCredentialSource interface {
	TunnelCredential(nodeID string, generation uint64) ([]byte, error)
}

type FRPProvider struct {
	root        string
	component   model.ComponentPin
	credentials FRPNodeCredentialSource
}

func NewFRPProvider(root string, component model.ComponentPin, credentials FRPNodeCredentialSource) (*FRPProvider, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fmt.Errorf("frp provider root must be clean and absolute")
	}
	if err := validateFRPComponent(component); err != nil {
		return nil, err
	}
	return &FRPProvider{root: root, component: component, credentials: credentials}, nil
}

func (*FRPProvider) Name() string { return FRPProviderName }

func (provider *FRPProvider) Render(ctx context.Context, request RenderRequest) (Candidate, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if provider == nil {
		return nil, fmt.Errorf("frp provider is required")
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if err := validateFRPComponent(provider.component); err != nil {
		return nil, err
	}
	if request.Plan.ServerEndpoint.Port() != FRPServerPort {
		return nil, fmt.Errorf("frp tunnel server must use internal TCP/%d", FRPServerPort)
	}

	descriptor := CandidateDescriptor{
		Provider: FRPProviderName, HostRole: request.Plan.HostRole,
		HostID: request.Plan.HostID, Generation: request.Plan.Generation,
	}
	var content []byte
	if request.Plan.HostRole == model.RoleGateway {
		content = renderFRPServerConfig(request.Plan.ServerEndpoint, provider.serverCertificatePath(), provider.serverPrivateKeyPath())
	} else {
		if provider.credentials == nil {
			return nil, fmt.Errorf("frp node credential source is required")
		}
		session := request.Plan.Nodes[0]
		session.Mappings = sortedFRPMappings(session.Mappings)
		credential, err := provider.credentials.TunnelCredential(session.NodeID, session.CredentialGeneration)
		if err != nil {
			return nil, fmt.Errorf("read frp node credential")
		}
		defer clear(credential)
		if err := ValidateCredential(credential); err != nil {
			return nil, err
		}
		content = renderFRPClientConfig(request.Plan.ServerEndpoint, session, string(credential), provider.nodeTrustedCertificatePath())
		descriptor.NodeID = session.NodeID
		descriptor.CredentialGeneration = session.CredentialGeneration
		descriptor.ActiveTransport = session.ActiveTransport
	}
	digest := sha256.Sum256(content)
	descriptor.ConfigHash = hex.EncodeToString(digest[:])
	candidate := FRPCandidate{content: content, descriptor: descriptor}
	if err := provider.Validate(ctx, candidate); err != nil {
		return nil, fmt.Errorf("validate rendered frp candidate: %w", err)
	}
	return candidate, nil
}

func (provider *FRPProvider) Validate(ctx context.Context, candidate Candidate) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if provider == nil {
		return fmt.Errorf("frp provider is required")
	}
	value, ok := candidate.(FRPCandidate)
	if !ok {
		return fmt.Errorf("candidate is not owned by the frp provider")
	}
	if err := value.descriptor.Validate(); err != nil {
		return err
	}
	if value.descriptor.Provider != FRPProviderName {
		return fmt.Errorf("candidate provider is not frp")
	}
	digest := sha256.Sum256(value.content)
	if hex.EncodeToString(digest[:]) != value.descriptor.ConfigHash {
		return fmt.Errorf("frp candidate config hash mismatch")
	}
	if value.descriptor.HostRole == model.RoleGateway {
		return ValidateFRPServerConfig(value.content)
	}
	document, err := parseFRPClientConfig(value.content)
	if err != nil {
		return err
	}
	if document.NodeID != value.descriptor.NodeID || document.CredentialGeneration != value.descriptor.CredentialGeneration {
		return fmt.Errorf("frp client config identity differs from candidate descriptor")
	}
	return nil
}

type FRPCandidate struct {
	content    []byte
	descriptor CandidateDescriptor
}

var _ Candidate = FRPCandidate{}

func (candidate FRPCandidate) Bytes() []byte { return append([]byte(nil), candidate.content...) }

func (candidate FRPCandidate) Descriptor() CandidateDescriptor { return candidate.descriptor }

func (provider *FRPProvider) serverCertificatePath() string {
	return filepath.Join(provider.root, "etc", "vpnctl", "generated", "gateway", FRPServerCertificateName)
}

func (provider *FRPProvider) serverPrivateKeyPath() string {
	return filepath.Join(provider.root, "etc", "vpnctl", "generated", "gateway", FRPServerPrivateKeyName)
}

func (provider *FRPProvider) nodeTrustedCertificatePath() string {
	return filepath.Join(provider.root, "etc", "vpnctl", "generated", "node", FRPServerCertificateName)
}

func validateFRPComponent(component model.ComponentPin) error {
	if err := component.Validate(); err != nil {
		return fmt.Errorf("validate frp component: %w", err)
	}
	if component.Name != FRPProviderName || component.Version != FRPProviderVersion || !component.Bundled || component.SHA256 != FRPProviderSHA256 || component.Source != "vpnctl-release-bundle" {
		return fmt.Errorf("frp component does not match pinned %s/%s archive", FRPProviderName, FRPProviderVersion)
	}
	required := map[string]bool{
		"dynamic-reload": false, "http-plugin-authorization": false,
		"tcp-mux": false, "tls-server-verification": false,
	}
	for _, capability := range component.Capabilities {
		if _, known := required[capability]; known {
			required[capability] = true
		}
	}
	for capability, present := range required {
		if !present {
			return fmt.Errorf("pinned frp component lacks %s capability", capability)
		}
	}
	return nil
}

func renderFRPServerConfig(endpoint netip.AddrPort, certificatePath, privateKeyPath string) []byte {
	var config strings.Builder
	fmt.Fprintf(&config, "bindAddr = %s\n", strconv.Quote(endpoint.Addr().String()))
	fmt.Fprintf(&config, "bindPort = %d\n", FRPServerPort)
	config.WriteString("proxyBindAddr = \"127.0.0.1\"\n")
	fmt.Fprintf(&config, "maxPortsPerClient = %d\n", DefaultLoopbackPortLast-DefaultLoopbackPortFirst+1)
	config.WriteString("detailedErrorsToClient = false\n")
	fmt.Fprintf(&config, "allowPorts = [{ start = %d, end = %d }]\n\n", DefaultLoopbackPortFirst, DefaultLoopbackPortLast)
	config.WriteString("log.to = \"console\"\n")
	config.WriteString("log.level = \"error\"\n")
	config.WriteString("log.disablePrintColor = true\n\n")
	config.WriteString("transport.tcpMux = true\n")
	fmt.Fprintf(&config, "transport.tcpMuxKeepaliveInterval = %d\n", FRPTCPMuxKeepaliveSec)
	fmt.Fprintf(&config, "transport.heartbeatTimeout = %d\n", FRPHeartbeatTimeoutSec)
	config.WriteString("transport.tls.force = true\n")
	fmt.Fprintf(&config, "transport.tls.certFile = %s\n", strconv.Quote(certificatePath))
	fmt.Fprintf(&config, "transport.tls.keyFile = %s\n\n", strconv.Quote(privateKeyPath))
	config.WriteString("[[httpPlugins]]\n")
	config.WriteString("name = \"vpnctl-authorizer\"\n")
	fmt.Fprintf(&config, "addr = \"127.0.0.1:%d\"\n", FRPAuthorizationPort)
	config.WriteString("path = \"/handler\"\n")
	config.WriteString("ops = [\"Login\", \"NewProxy\", \"Ping\"]\n")
	return []byte(config.String())
}

func renderFRPClientConfig(endpoint netip.AddrPort, session NodeSession, tunnelCredential, certificatePath string) []byte {
	var config strings.Builder
	fmt.Fprintf(&config, "clientID = %s\n", strconv.Quote(frpClientID(session.NodeID)))
	fmt.Fprintf(&config, "serverAddr = %s\n", strconv.Quote(endpoint.Addr().String()))
	fmt.Fprintf(&config, "serverPort = %d\n", FRPServerPort)
	config.WriteString("loginFailExit = false\n\n")
	config.WriteString("log.to = \"console\"\n")
	config.WriteString("log.level = \"error\"\n")
	config.WriteString("log.disablePrintColor = true\n\n")
	config.WriteString("webServer.addr = \"127.0.0.1\"\n")
	fmt.Fprintf(&config, "webServer.port = %d\n", FRPClientAdminPort)
	config.WriteString("webServer.user = \"vpnctl\"\n")
	fmt.Fprintf(&config, "webServer.password = %s\n", strconv.Quote(frpAdminPassword(tunnelCredential)))
	config.WriteString("webServer.pprofEnable = false\n\n")
	config.WriteString("transport.protocol = \"tcp\"\n")
	config.WriteString("transport.wireProtocol = \"v1\"\n")
	config.WriteString("transport.poolCount = 0\n")
	config.WriteString("transport.tcpMux = true\n")
	fmt.Fprintf(&config, "transport.tcpMuxKeepaliveInterval = %d\n", FRPTCPMuxKeepaliveSec)
	fmt.Fprintf(&config, "transport.heartbeatInterval = %d\n", FRPHeartbeatSec)
	fmt.Fprintf(&config, "transport.heartbeatTimeout = %d\n", FRPHeartbeatTimeoutSec)
	config.WriteString("transport.tls.enable = true\n")
	config.WriteString("transport.tls.disableCustomTLSFirstByte = true\n")
	fmt.Fprintf(&config, "transport.tls.trustedCaFile = %s\n", strconv.Quote(certificatePath))
	fmt.Fprintf(&config, "transport.tls.serverName = %s\n\n", strconv.Quote(FRPTLSServerName))
	fmt.Fprintf(&config, "metadatas.node_id = %s\n", strconv.Quote(session.NodeID))
	fmt.Fprintf(&config, "metadatas.generation = %s\n", strconv.Quote(strconv.FormatUint(session.CredentialGeneration, 10)))
	fmt.Fprintf(&config, "metadatas.tunnel_token = %s\n", strconv.Quote(tunnelCredential))
	for _, mapping := range session.Mappings {
		host, portText, _ := net.SplitHostPort(mapping.NodeUpstream)
		localPort, _ := strconv.Atoi(portText)
		config.WriteString("\n[[proxies]]\n")
		fmt.Fprintf(&config, "name = %s\n", strconv.Quote(mapping.Name))
		config.WriteString("type = \"tcp\"\n")
		fmt.Fprintf(&config, "localIP = %s\n", strconv.Quote(host))
		fmt.Fprintf(&config, "localPort = %d\n", localPort)
		fmt.Fprintf(&config, "remotePort = %d\n", mapping.GatewayEndpoint.Port())
		fmt.Fprintf(&config, "metadatas.generation = %s\n", strconv.Quote(strconv.FormatUint(mapping.Generation, 10)))
		config.WriteString("healthCheck.type = \"tcp\"\n")
		fmt.Fprintf(&config, "healthCheck.timeoutSeconds = %d\n", FRPHealthCheckTimeoutSec)
		fmt.Fprintf(&config, "healthCheck.maxFailed = %d\n", FRPHealthCheckMaxFailed)
		fmt.Fprintf(&config, "healthCheck.intervalSeconds = %d\n", FRPHealthCheckIntervalSec)
	}
	return []byte(config.String())
}

func ValidateFRPServerConfig(content []byte) error {
	cursor, err := newFRPConfigCursor(content)
	if err != nil {
		return err
	}
	bindAddress, err := cursor.quoted("bindAddr")
	if err != nil {
		return err
	}
	address, err := netip.ParseAddr(bindAddress)
	if err != nil || !address.Is4() || !address.IsPrivate() || address.String() != bindAddress {
		return fmt.Errorf("frp server bind address must be a canonical private IPv4 address")
	}
	certificatePath := ""
	privateKeyPath := ""
	for _, expected := range []string{
		fmt.Sprintf("bindPort = %d", FRPServerPort),
		"proxyBindAddr = \"127.0.0.1\"",
		fmt.Sprintf("maxPortsPerClient = %d", DefaultLoopbackPortLast-DefaultLoopbackPortFirst+1),
		"detailedErrorsToClient = false",
		fmt.Sprintf("allowPorts = [{ start = %d, end = %d }]", DefaultLoopbackPortFirst, DefaultLoopbackPortLast),
		"", "log.to = \"console\"", "log.level = \"error\"", "log.disablePrintColor = true", "",
		"transport.tcpMux = true", fmt.Sprintf("transport.tcpMuxKeepaliveInterval = %d", FRPTCPMuxKeepaliveSec),
		fmt.Sprintf("transport.heartbeatTimeout = %d", FRPHeartbeatTimeoutSec), "transport.tls.force = true",
	} {
		if err := cursor.expect(expected); err != nil {
			return err
		}
	}
	if certificatePath, err = cursor.quoted("transport.tls.certFile"); err != nil {
		return err
	}
	if privateKeyPath, err = cursor.quoted("transport.tls.keyFile"); err != nil {
		return err
	}
	for _, expected := range []string{
		"", "[[httpPlugins]]", "name = \"vpnctl-authorizer\"",
		fmt.Sprintf("addr = \"127.0.0.1:%d\"", FRPAuthorizationPort),
		"path = \"/handler\"", "ops = [\"Login\", \"NewProxy\", \"Ping\"]",
	} {
		if err := cursor.expect(expected); err != nil {
			return err
		}
	}
	if err := cursor.eof(); err != nil {
		return err
	}
	if err := validateFRPAbsolutePath("server certificate", certificatePath); err != nil {
		return err
	}
	if err := validateFRPAbsolutePath("server private key", privateKeyPath); err != nil {
		return err
	}
	want := renderFRPServerConfig(netip.AddrPortFrom(address, uint16(FRPServerPort)), certificatePath, privateKeyPath)
	if !bytes.Equal(content, want) {
		return fmt.Errorf("frp server config is not canonical")
	}
	return nil
}

type frpClientDocument struct {
	NodeID               string
	CredentialGeneration uint64
	TunnelCredential     string
	ServerEndpoint       netip.AddrPort
	CertificatePath      string
	Mappings             []Mapping
}

func ValidateFRPClientConfig(content []byte) error {
	_, err := parseFRPClientConfig(content)
	return err
}

func parseFRPClientConfig(content []byte) (frpClientDocument, error) {
	cursor, err := newFRPConfigCursor(content)
	if err != nil {
		return frpClientDocument{}, err
	}
	clientID, err := cursor.quoted("clientID")
	if err != nil {
		return frpClientDocument{}, err
	}
	serverAddress, err := cursor.quoted("serverAddr")
	if err != nil {
		return frpClientDocument{}, err
	}
	address, err := netip.ParseAddr(serverAddress)
	if err != nil || !address.Is4() || !address.IsPrivate() || address.String() != serverAddress {
		return frpClientDocument{}, fmt.Errorf("frp client server address must be a canonical private IPv4 address")
	}
	for _, expected := range []string{
		fmt.Sprintf("serverPort = %d", FRPServerPort), "loginFailExit = false", "",
		"log.to = \"console\"", "log.level = \"error\"", "log.disablePrintColor = true", "",
		"webServer.addr = \"127.0.0.1\"", fmt.Sprintf("webServer.port = %d", FRPClientAdminPort),
		"webServer.user = \"vpnctl\"",
	} {
		if err := cursor.expect(expected); err != nil {
			return frpClientDocument{}, err
		}
	}
	adminPassword, err := cursor.quoted("webServer.password")
	if err != nil {
		return frpClientDocument{}, err
	}
	for _, expected := range []string{
		"webServer.pprofEnable = false", "", "transport.protocol = \"tcp\"", "transport.wireProtocol = \"v1\"",
		"transport.poolCount = 0", "transport.tcpMux = true",
		fmt.Sprintf("transport.tcpMuxKeepaliveInterval = %d", FRPTCPMuxKeepaliveSec),
		fmt.Sprintf("transport.heartbeatInterval = %d", FRPHeartbeatSec),
		fmt.Sprintf("transport.heartbeatTimeout = %d", FRPHeartbeatTimeoutSec),
		"transport.tls.enable = true", "transport.tls.disableCustomTLSFirstByte = true",
	} {
		if err := cursor.expect(expected); err != nil {
			return frpClientDocument{}, err
		}
	}
	certificatePath, err := cursor.quoted("transport.tls.trustedCaFile")
	if err != nil {
		return frpClientDocument{}, err
	}
	if err := cursor.expect("transport.tls.serverName = " + strconv.Quote(FRPTLSServerName)); err != nil {
		return frpClientDocument{}, err
	}
	if err := cursor.expect(""); err != nil {
		return frpClientDocument{}, err
	}
	nodeID, err := cursor.quoted("metadatas.node_id")
	if err != nil {
		return frpClientDocument{}, err
	}
	if err := validateUUID("frp client node ID", nodeID); err != nil {
		return frpClientDocument{}, err
	}
	if clientID != frpClientID(nodeID) {
		return frpClientDocument{}, fmt.Errorf("frp client ID does not match node identity")
	}
	generationText, err := cursor.quoted("metadatas.generation")
	if err != nil {
		return frpClientDocument{}, err
	}
	generation, err := strconv.ParseUint(generationText, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != generationText {
		return frpClientDocument{}, fmt.Errorf("frp client credential generation must be canonical and positive")
	}
	tunnelCredential, err := cursor.quoted("metadatas.tunnel_token")
	if err != nil {
		return frpClientDocument{}, err
	}
	if err := ValidateCredential([]byte(tunnelCredential)); err != nil {
		return frpClientDocument{}, err
	}
	if adminPassword != frpAdminPassword(tunnelCredential) {
		return frpClientDocument{}, fmt.Errorf("frp client admin password is not bound to the tunnel credential")
	}
	if err := validateFRPAbsolutePath("trusted certificate", certificatePath); err != nil {
		return frpClientDocument{}, err
	}

	mappings := make([]Mapping, 0)
	usedPorts := make(map[int]struct{})
	previousName := ""
	for !cursor.done() {
		if err := cursor.expect(""); err != nil {
			return frpClientDocument{}, err
		}
		if err := cursor.expect("[[proxies]]"); err != nil {
			return frpClientDocument{}, err
		}
		name, err := cursor.quoted("name")
		if err != nil {
			return frpClientDocument{}, err
		}
		exposeID, err := exposeIDFromFRPMappingName(nodeID, name)
		if err != nil {
			return frpClientDocument{}, err
		}
		if previousName != "" && name <= previousName {
			return frpClientDocument{}, fmt.Errorf("frp client mappings must be ordered by unique deterministic name")
		}
		previousName = name
		if err := cursor.expect("type = \"tcp\""); err != nil {
			return frpClientDocument{}, err
		}
		localIP, err := cursor.quoted("localIP")
		if err != nil {
			return frpClientDocument{}, err
		}
		localPort, err := cursor.integer("localPort")
		if err != nil {
			return frpClientDocument{}, err
		}
		if err := validateUpstream(net.JoinHostPort(localIP, strconv.Itoa(localPort))); err != nil {
			return frpClientDocument{}, err
		}
		remotePort, err := cursor.integer("remotePort")
		if err != nil {
			return frpClientDocument{}, err
		}
		if remotePort < DefaultLoopbackPortFirst || remotePort > DefaultLoopbackPortLast {
			return frpClientDocument{}, fmt.Errorf("frp client remote port is outside the managed loopback range")
		}
		if _, duplicate := usedPorts[remotePort]; duplicate {
			return frpClientDocument{}, fmt.Errorf("frp client mappings share remote port %d", remotePort)
		}
		usedPorts[remotePort] = struct{}{}
		mappingGenerationText, err := cursor.quoted("metadatas.generation")
		if err != nil {
			return frpClientDocument{}, err
		}
		mappingGeneration, err := strconv.ParseUint(mappingGenerationText, 10, 64)
		if err != nil || mappingGeneration == 0 || strconv.FormatUint(mappingGeneration, 10) != mappingGenerationText {
			return frpClientDocument{}, fmt.Errorf("frp mapping generation must be canonical and positive")
		}
		for _, expected := range []string{
			"healthCheck.type = \"tcp\"",
			fmt.Sprintf("healthCheck.timeoutSeconds = %d", FRPHealthCheckTimeoutSec),
			fmt.Sprintf("healthCheck.maxFailed = %d", FRPHealthCheckMaxFailed),
			fmt.Sprintf("healthCheck.intervalSeconds = %d", FRPHealthCheckIntervalSec),
		} {
			if err := cursor.expect(expected); err != nil {
				return frpClientDocument{}, err
			}
		}
		mappings = append(mappings, Mapping{
			ExposeID: exposeID, NodeID: nodeID, Name: name, Protocol: model.ProtocolTCP,
			GatewayEndpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(remotePort)),
			NodeUpstream:    net.JoinHostPort(localIP, strconv.Itoa(localPort)), Generation: mappingGeneration,
		})
	}
	document := frpClientDocument{
		NodeID: nodeID, CredentialGeneration: generation, TunnelCredential: tunnelCredential,
		ServerEndpoint: netip.AddrPortFrom(address, uint16(FRPServerPort)), CertificatePath: certificatePath, Mappings: mappings,
	}
	session := NodeSession{
		NodeID: nodeID, Generation: 1, CredentialGeneration: generation,
		ActiveTransport: model.TransportStandard, Mappings: mappings,
	}
	want := renderFRPClientConfig(document.ServerEndpoint, session, tunnelCredential, certificatePath)
	if !bytes.Equal(content, want) {
		return frpClientDocument{}, fmt.Errorf("frp client config is not canonical")
	}
	return document, nil
}

func frpAdminPassword(tunnelCredential string) string {
	digest := sha256.Sum256([]byte("vpnctl-frpc-admin-v1\x00" + tunnelCredential))
	return hex.EncodeToString(digest[:])
}

func frpClientID(nodeID string) string {
	return "vpnctl-node-" + strings.ReplaceAll(nodeID, "-", "")
}

func exposeIDFromFRPMappingName(nodeID, name string) (string, error) {
	prefix := MappingNamePrefix + strings.ReplaceAll(nodeID, "-", "") + "-e-"
	if !strings.HasPrefix(name, prefix) {
		return "", fmt.Errorf("frp mapping name does not belong to node %s", nodeID)
	}
	compact := strings.TrimPrefix(name, prefix)
	if !frpMappingSuffixPattern.MatchString(compact) {
		return "", fmt.Errorf("frp mapping name contains an invalid expose identity")
	}
	exposeID := compact[:8] + "-" + compact[8:12] + "-" + compact[12:16] + "-" + compact[16:20] + "-" + compact[20:]
	want, _ := MappingName(nodeID, exposeID)
	if want != name {
		return "", fmt.Errorf("frp mapping name is not canonical")
	}
	return exposeID, nil
}

func validateFRPAbsolutePath(label, value string) error {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("frp %s path must be clean and absolute", label)
	}
	return nil
}

type frpConfigCursor struct {
	lines []string
	index int
}

func newFRPConfigCursor(content []byte) (*frpConfigCursor, error) {
	if len(content) == 0 || len(content) > maximumFRPConfigBytes || !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 || bytes.Contains(content, []byte("\r")) || content[len(content)-1] != '\n' {
		return nil, fmt.Errorf("frp config must be non-empty canonical UTF-8 within %d bytes", maximumFRPConfigBytes)
	}
	return &frpConfigCursor{lines: strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")}, nil
}

func (cursor *frpConfigCursor) expect(value string) error {
	if cursor.done() || cursor.lines[cursor.index] != value {
		actual := "<eof>"
		if !cursor.done() {
			actual = cursor.lines[cursor.index]
		}
		return fmt.Errorf("frp config line %d is %q, want %q", cursor.index+1, actual, value)
	}
	cursor.index++
	return nil
}

func (cursor *frpConfigCursor) quoted(key string) (string, error) {
	if cursor.done() {
		return "", fmt.Errorf("frp config is missing %s", key)
	}
	prefix := key + " = "
	raw := cursor.lines[cursor.index]
	if !strings.HasPrefix(raw, prefix) {
		return "", fmt.Errorf("frp config line %d must define %s", cursor.index+1, key)
	}
	encoded := strings.TrimPrefix(raw, prefix)
	value, err := strconv.Unquote(encoded)
	if err != nil || strconv.Quote(value) != encoded {
		return "", fmt.Errorf("frp config %s must be a canonical quoted string", key)
	}
	cursor.index++
	return value, nil
}

func (cursor *frpConfigCursor) integer(key string) (int, error) {
	if cursor.done() {
		return 0, fmt.Errorf("frp config is missing %s", key)
	}
	prefix := key + " = "
	raw := cursor.lines[cursor.index]
	if !strings.HasPrefix(raw, prefix) {
		return 0, fmt.Errorf("frp config line %d must define %s", cursor.index+1, key)
	}
	text := strings.TrimPrefix(raw, prefix)
	value, err := strconv.Atoi(text)
	if err != nil || strconv.Itoa(value) != text || value < 1 || value > 65535 {
		return 0, fmt.Errorf("frp config %s must be a canonical port", key)
	}
	cursor.index++
	return value, nil
}

func (cursor *frpConfigCursor) done() bool { return cursor == nil || cursor.index == len(cursor.lines) }

func (cursor *frpConfigCursor) eof() error {
	if !cursor.done() {
		return fmt.Errorf("frp config has unexpected line %d", cursor.index+1)
	}
	return nil
}

func sortedFRPMappings(values []Mapping) []Mapping {
	result := append([]Mapping(nil), values...)
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result
}
