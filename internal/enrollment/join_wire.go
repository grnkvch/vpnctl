package enrollment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
)

const (
	NodeJoinSchemaVersion               = 1
	NodeRestrictedUpstreamSchemaVersion = 1
	maximumNodeJoinPresets              = 64

	joinControlCAHashName           = "control_ca"
	joinControlCertificateHashName  = "control_certificate"
	joinEnrollmentPublicKeyHashName = "enrollment_public_key"
	joinGatewayWireGuardKeyHashName = "gateway_wireguard_public_key"
	joinRestrictedUpstreamHashName  = "restricted_server_credential"
)

type nodeJoinWireRequest struct {
	SchemaVersion     int                 `json:"schema_version"`
	Transport         model.TransportKind `json:"transport"`
	Presets           []string            `json:"presets"`
	PublicExchange    json.RawMessage     `json:"public_exchange"`
	SharedCredentials json.RawMessage     `json:"shared_credentials"`
}

// NodeJoinRequest exposes only the authenticated non-secret join intent. The
// shared restricted/tunnel values stay behind UseSharedCredentials.
type NodeJoinRequest struct {
	Transport      model.TransportKind
	Presets        []string
	PublicExchange NodePublicExchange
	shared         *NodeSharedCredentialExchange
}

// ValidateNodeJoinIntent is the read-only CLI planning boundary. Gateway
// preset existence remains authoritative and is checked during enrollment.
func ValidateNodeJoinIntent(transportKind model.TransportKind, presets []string) error {
	if transportKind != model.TransportStandard && transportKind != model.TransportRestricted {
		return fmt.Errorf("join requires an explicit standard or restricted transport")
	}
	return validateRequestedJoinPresets(presets)
}

func EncodeNodeJoinRequest(
	transportKind model.TransportKind,
	presets []string,
	publicExchange NodePublicExchange,
	sharedCredentials *output.Secret,
) (*output.Secret, error) {
	if err := ValidateNodeJoinIntent(transportKind, presets); err != nil {
		return nil, err
	}
	publicBytes, err := EncodeNodePublicExchange(publicExchange)
	if err != nil {
		return nil, err
	}
	defer clear(publicBytes)
	if sharedCredentials == nil {
		return nil, fmt.Errorf("node shared credentials are required")
	}
	var encoded []byte
	err = sharedCredentials.Use(func(shared []byte) error {
		validated, err := decodeNodeSharedCredentialExchange(shared, publicExchange)
		if err != nil {
			return err
		}
		validated.Destroy()
		wire := nodeJoinWireRequest{
			SchemaVersion: NodeJoinSchemaVersion, Transport: transportKind,
			Presets: append([]string{}, presets...), PublicExchange: publicBytes,
			SharedCredentials: append(json.RawMessage(nil), shared...),
		}
		defer clear(wire.SharedCredentials)
		encoded, err = json.Marshal(wire)
		return err
	})
	if err != nil {
		clear(encoded)
		return nil, fmt.Errorf("encode node join request: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > control.RPCMaximumRequestBytes {
		clear(encoded)
		return nil, fmt.Errorf("node join request exceeds %d bytes", control.RPCMaximumRequestBytes)
	}
	secret, err := output.NewSecret(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

func DecodeNodeJoinRequest(encoded json.RawMessage) (*NodeJoinRequest, error) {
	if len(encoded) == 0 || len(encoded) > control.RPCMaximumRequestBytes {
		return nil, fmt.Errorf("node join request size is invalid")
	}
	var wire nodeJoinWireRequest
	if err := control.DecodeRPCPayload(encoded, &wire); err != nil {
		return nil, fmt.Errorf("decode node join request: %w", err)
	}
	if wire.SchemaVersion != NodeJoinSchemaVersion ||
		(wire.Transport != model.TransportStandard && wire.Transport != model.TransportRestricted) {
		return nil, fmt.Errorf("node join request version or transport is invalid")
	}
	if err := validateRequestedJoinPresets(wire.Presets); err != nil {
		return nil, err
	}
	publicExchange, err := DecodeNodePublicExchange(wire.PublicExchange)
	if err != nil {
		return nil, err
	}
	shared, err := decodeNodeSharedCredentialExchange(wire.SharedCredentials, publicExchange)
	if err != nil {
		return nil, err
	}
	return &NodeJoinRequest{
		Transport: wire.Transport, Presets: append([]string{}, wire.Presets...),
		PublicExchange: publicExchange, shared: shared,
	}, nil
}

func (request *NodeJoinRequest) UseSharedCredentials(callback func(restrictedCredential, tunnelCredential []byte) error) error {
	if request == nil || request.shared == nil {
		return fmt.Errorf("node join shared credentials are unavailable")
	}
	return request.shared.Use(callback)
}

func (request *NodeJoinRequest) Destroy() {
	if request != nil && request.shared != nil {
		request.shared.Destroy()
		request.shared = nil
	}
}

func (NodeJoinRequest) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

// NodeJoinAssignment is the signed public result of gateway allocation and
// policy normalization. MaterialHashes binds every response credential while
// keeping secret bytes out of the transcript and authoritative state.
type NodeJoinAssignment struct {
	SchemaVersion                 int                 `json:"schema_version"`
	NodeID                        string              `json:"node_id"`
	NodeName                      string              `json:"node_name"`
	OverlayIPv4                   string              `json:"overlay_ipv4"`
	CredentialGeneration          uint64              `json:"credential_generation"`
	ActiveTransport               model.TransportKind `json:"active_transport"`
	Presets                       []string            `json:"presets"`
	Selectors                     []model.Selector    `json:"selectors"`
	PolicyEffectiveHash           string              `json:"policy_effective_hash,omitempty"`
	CreatedAt                     time.Time           `json:"created_at"`
	GatewayPublicIPv4             string              `json:"gateway_public_ipv4"`
	NodeCIDR                      string              `json:"node_cidr"`
	GatewayOverlayIPv4            string              `json:"gateway_overlay_ipv4"`
	GatewayStateGeneration        uint64              `json:"gateway_state_generation"`
	ControlProtocol               string              `json:"control_protocol"`
	EnrollmentFingerprint         string              `json:"enrollment_fingerprint"`
	ControlCAFingerprint          string              `json:"control_ca_fingerprint"`
	ControlCertificateFingerprint string              `json:"control_certificate_fingerprint"`
	HandshakeHostCandidateID      string              `json:"handshake_host_candidate_id"`
	HandshakeHost                 string              `json:"handshake_host"`
	HandshakeHostListVersion      int                 `json:"handshake_host_list_version"`
	HandshakeHostSelectedAt       time.Time           `json:"handshake_host_selected_at"`
	MaterialHashes                map[string]string   `json:"material_hashes"`
}

func (assignment NodeJoinAssignment) Validate() error {
	if assignment.SchemaVersion != NodeJoinSchemaVersion || assignment.CredentialGeneration != 1 ||
		assignment.GatewayStateGeneration == 0 {
		return fmt.Errorf("node join assignment version or generation is invalid")
	}
	if !transcriptUUIDPattern.MatchString(assignment.NodeID) || validateInviteName(assignment.NodeName) != nil {
		return fmt.Errorf("node join assignment identity is invalid")
	}
	if assignment.ActiveTransport != model.TransportStandard && assignment.ActiveTransport != model.TransportRestricted {
		return fmt.Errorf("node join assignment transport is invalid")
	}
	if err := validateCanonicalJoinPresets(assignment.Presets); err != nil {
		return err
	}
	if assignment.CreatedAt.IsZero() || !assignment.CreatedAt.Equal(canonicalTime(assignment.CreatedAt)) {
		return fmt.Errorf("node join created_at must be canonical")
	}
	if len(assignment.Presets) == 0 {
		if len(assignment.Selectors) != 0 || assignment.PolicyEffectiveHash != "" {
			return fmt.Errorf("node join empty preset assignment cannot retain policy")
		}
	} else {
		policy := model.Policy{
			SchemaVersion: model.ResourceSchemaVersion, TargetKind: model.TargetNode,
			TargetID: assignment.NodeID, PresetNames: assignment.Presets,
			Selectors: assignment.Selectors, EffectiveHash: assignment.PolicyEffectiveHash, Generation: 1,
		}
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("node join policy: %w", err)
		}
	}
	publicAddress, err := netip.ParseAddr(assignment.GatewayPublicIPv4)
	if err != nil || !publicAddress.Is4() || !publicAddress.IsGlobalUnicast() || publicAddress.String() != assignment.GatewayPublicIPv4 {
		return fmt.Errorf("node join gateway public IPv4 is invalid")
	}
	prefix, err := netip.ParsePrefix(assignment.NodeCIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || prefix.String() != assignment.NodeCIDR {
		return fmt.Errorf("node join node CIDR is invalid")
	}
	gatewayOverlay, gatewayErr := netip.ParseAddr(assignment.GatewayOverlayIPv4)
	nodeAddress, nodeErr := netip.ParseAddr(assignment.OverlayIPv4)
	if gatewayErr != nil || nodeErr != nil || !gatewayOverlay.Is4() || !nodeAddress.Is4() ||
		gatewayOverlay.String() != assignment.GatewayOverlayIPv4 || nodeAddress.String() != assignment.OverlayIPv4 ||
		!prefix.Contains(gatewayOverlay) || !prefix.Contains(nodeAddress) || prefix.Addr().Next() != gatewayOverlay || nodeAddress == gatewayOverlay {
		return fmt.Errorf("node join overlay allocation is invalid")
	}
	if !protocolPattern.MatchString(assignment.ControlProtocol) ||
		!fingerprintPattern.MatchString(assignment.EnrollmentFingerprint) ||
		!fingerprintPattern.MatchString(assignment.ControlCAFingerprint) ||
		!fingerprintPattern.MatchString(assignment.ControlCertificateFingerprint) {
		return fmt.Errorf("node join control trust is invalid")
	}
	if assignment.HandshakeHostListVersion < 1 {
		return fmt.Errorf("node join handshake-host list version is invalid")
	}
	host := model.HandshakeHost{
		SchemaVersion: model.ResourceSchemaVersion, ListVersion: assignment.HandshakeHostListVersion,
		CandidateID: assignment.HandshakeHostCandidateID, Hostname: assignment.HandshakeHost,
		SelectedAt: assignment.HandshakeHostSelectedAt,
	}
	if err := host.Validate(); err != nil {
		return fmt.Errorf("node join handshake host: %w", err)
	}
	wantedHashes := joinResponseMaterialHashNames()
	if len(assignment.MaterialHashes) != len(wantedHashes) {
		return fmt.Errorf("node join assignment requires exactly %d material hashes", len(wantedHashes))
	}
	for _, name := range wantedHashes {
		if !hashPattern.MatchString(assignment.MaterialHashes[name]) {
			return fmt.Errorf("node join material hash %s is invalid", name)
		}
	}
	return nil
}

func (assignment NodeJoinAssignment) SHA256() ([sha256.Size]byte, error) {
	if err := assignment.Validate(); err != nil {
		return [sha256.Size]byte{}, err
	}
	encoded, err := json.Marshal(assignment)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("encode node join assignment: %w", err)
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return digest, nil
}

type nodeRestrictedUpstreamWire struct {
	SchemaVersion       int    `json:"schema_version"`
	ShadowsocksPassword string `json:"shadowsocks_password"`
}

type nodeJoinWireResponse struct {
	SchemaVersion              int                `json:"schema_version"`
	Assignment                 NodeJoinAssignment `json:"assignment"`
	ControlCACertificatePEM    string             `json:"control_ca_certificate_pem"`
	ControlCertificatePEM      string             `json:"control_certificate_pem"`
	EnrollmentPublicKeyPEM     string             `json:"enrollment_public_key_pem"`
	GatewayWireGuardPublicKey  string             `json:"gateway_wireguard_public_key"`
	RestrictedServerCredential json.RawMessage    `json:"restricted_server_credential"`
}

type NodeJoinResponseMaterial struct {
	Assignment NodeJoinAssignment
	secret     output.Secret
}

type NodeJoinResponseValues struct {
	ControlCACertificatePEM    []byte
	ControlCertificatePEM      []byte
	EnrollmentPublicKeyPEM     []byte
	GatewayWireGuardPublicKey  []byte
	RestrictedServerCredential []byte
}

func (NodeJoinResponseValues) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

func encodeNodeJoinResponse(
	assignment NodeJoinAssignment,
	controlCAPEM, controlCertificatePEM, enrollmentPublicKeyPEM []byte,
	gatewayWireGuardPublicKey string,
	restrictedServerCredential []byte,
) (*output.Secret, error) {
	wire := nodeJoinWireResponse{
		SchemaVersion: NodeJoinSchemaVersion, Assignment: assignment,
		ControlCACertificatePEM: string(controlCAPEM), ControlCertificatePEM: string(controlCertificatePEM),
		EnrollmentPublicKeyPEM: string(enrollmentPublicKeyPEM), GatewayWireGuardPublicKey: gatewayWireGuardPublicKey,
		RestrictedServerCredential: append(json.RawMessage(nil), restrictedServerCredential...),
	}
	defer clear(wire.RestrictedServerCredential)
	if err := validateNodeJoinWireResponse(wire); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode node join response: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > control.RPCMaximumResponseBytes {
		clear(encoded)
		return nil, fmt.Errorf("node join response exceeds %d bytes", control.RPCMaximumResponseBytes)
	}
	secret, err := output.NewSecret(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

func DecodeNodeJoinResponse(data json.RawMessage) (*NodeJoinResponseMaterial, error) {
	if len(data) == 0 || len(data) > control.RPCMaximumResponseBytes {
		return nil, fmt.Errorf("node join response size is invalid")
	}
	var wire nodeJoinWireResponse
	if err := control.DecodeRPCPayload(data, &wire); err != nil {
		return nil, fmt.Errorf("decode node join response: %w", err)
	}
	if err := validateNodeJoinWireResponse(wire); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, data) {
		clear(canonical)
		return nil, fmt.Errorf("node join response must be canonical JSON")
	}
	secret, err := output.NewSecret(canonical)
	clear(canonical)
	if err != nil {
		return nil, err
	}
	return &NodeJoinResponseMaterial{Assignment: cloneNodeJoinAssignment(wire.Assignment), secret: secret}, nil
}

func (material *NodeJoinResponseMaterial) Use(callback func(NodeJoinResponseValues) error) error {
	if material == nil || callback == nil {
		return fmt.Errorf("node join response callback is required")
	}
	return material.secret.Use(func(encoded []byte) error {
		var wire nodeJoinWireResponse
		if err := control.DecodeRPCPayload(json.RawMessage(encoded), &wire); err != nil {
			return err
		}
		values := NodeJoinResponseValues{
			ControlCACertificatePEM:    []byte(wire.ControlCACertificatePEM),
			ControlCertificatePEM:      []byte(wire.ControlCertificatePEM),
			EnrollmentPublicKeyPEM:     []byte(wire.EnrollmentPublicKeyPEM),
			GatewayWireGuardPublicKey:  []byte(wire.GatewayWireGuardPublicKey),
			RestrictedServerCredential: append([]byte(nil), wire.RestrictedServerCredential...),
		}
		defer values.destroy()
		return callback(values)
	})
}

func (material *NodeJoinResponseMaterial) Destroy() {
	if material != nil {
		material.secret.Destroy()
	}
}

func (NodeJoinResponseMaterial) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

func (values *NodeJoinResponseValues) destroy() {
	clear(values.ControlCACertificatePEM)
	clear(values.ControlCertificatePEM)
	clear(values.EnrollmentPublicKeyPEM)
	clear(values.GatewayWireGuardPublicKey)
	clear(values.RestrictedServerCredential)
}

func validateNodeJoinWireResponse(wire nodeJoinWireResponse) error {
	if wire.SchemaVersion != NodeJoinSchemaVersion {
		return fmt.Errorf("unsupported node join response schema")
	}
	if err := wire.Assignment.Validate(); err != nil {
		return err
	}
	if len(wire.ControlCACertificatePEM) == 0 || len(wire.ControlCertificatePEM) == 0 ||
		len(wire.EnrollmentPublicKeyPEM) == 0 || len(wire.GatewayWireGuardPublicKey) == 0 ||
		len(wire.RestrictedServerCredential) == 0 {
		return fmt.Errorf("node join response material is incomplete")
	}
	if _, err := decodeCanonicalWireGuardPublicKey(wire.GatewayWireGuardPublicKey); err != nil {
		return fmt.Errorf("gateway WireGuard public key: %w", err)
	}
	var restrictedWire nodeRestrictedUpstreamWire
	if err := control.DecodeRPCPayload(wire.RestrictedServerCredential, &restrictedWire); err != nil ||
		restrictedWire.SchemaVersion != NodeRestrictedUpstreamSchemaVersion ||
		restricted.ValidateServerPassword(restrictedWire.ShadowsocksPassword) != nil {
		return fmt.Errorf("node restricted server credential is invalid")
	}
	canonicalRestricted, err := json.Marshal(restrictedWire)
	if err != nil || !bytes.Equal(canonicalRestricted, wire.RestrictedServerCredential) {
		clear(canonicalRestricted)
		return fmt.Errorf("node restricted server credential must be canonical JSON")
	}
	clear(canonicalRestricted)
	actualHashes := map[string]string{
		joinControlCAHashName:           sha256Hex([]byte(wire.ControlCACertificatePEM)),
		joinControlCertificateHashName:  sha256Hex([]byte(wire.ControlCertificatePEM)),
		joinEnrollmentPublicKeyHashName: sha256Hex([]byte(wire.EnrollmentPublicKeyPEM)),
		joinGatewayWireGuardKeyHashName: sha256Hex([]byte(wire.GatewayWireGuardPublicKey)),
		joinRestrictedUpstreamHashName:  sha256Hex(wire.RestrictedServerCredential),
	}
	for name, actual := range actualHashes {
		if wire.Assignment.MaterialHashes[name] != actual {
			return fmt.Errorf("node join response material hash %s mismatch", name)
		}
	}
	return nil
}

func validateRequestedJoinPresets(presets []string) error {
	if presets == nil {
		return fmt.Errorf("join presets must be a present array")
	}
	if len(presets) > maximumNodeJoinPresets {
		return fmt.Errorf("join presets exceed %d entries", maximumNodeJoinPresets)
	}
	seen := make(map[string]struct{}, len(presets))
	for _, name := range presets {
		if err := validateInviteName(name); err != nil {
			return fmt.Errorf("invalid join preset %q", name)
		}
		key := strings.ToLower(name)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("join presets duplicate %s", name)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateCanonicalJoinPresets(presets []string) error {
	if err := validateRequestedJoinPresets(presets); err != nil {
		return err
	}
	for index := 1; index < len(presets); index++ {
		left, right := strings.ToLower(presets[index-1]), strings.ToLower(presets[index])
		if left > right || (left == right && presets[index-1] >= presets[index]) {
			return fmt.Errorf("join presets must be in canonical order")
		}
	}
	return nil
}

func joinResponseMaterialHashNames() []string {
	result := []string{
		joinControlCAHashName, joinControlCertificateHashName, joinEnrollmentPublicKeyHashName,
		joinGatewayWireGuardKeyHashName, joinRestrictedUpstreamHashName,
	}
	sort.Strings(result)
	return result
}

func cloneNodeJoinAssignment(value NodeJoinAssignment) NodeJoinAssignment {
	value.Presets = append([]string{}, value.Presets...)
	value.Selectors = append([]model.Selector{}, value.Selectors...)
	value.MaterialHashes = cloneJoinStringMap(value.MaterialHashes)
	return value
}

func cloneJoinStringMap(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, entry := range value {
		result[key] = entry
	}
	return result
}

func encodeRestrictedUpstreamCredential(password string) ([]byte, error) {
	if err := restricted.ValidateServerPassword(password); err != nil {
		return nil, err
	}
	return json.Marshal(nodeRestrictedUpstreamWire{
		SchemaVersion: NodeRestrictedUpstreamSchemaVersion, ShadowsocksPassword: password,
	})
}

func materialFingerprint(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
