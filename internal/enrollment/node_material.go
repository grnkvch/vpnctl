package enrollment

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
	"github.com/vgrinkevich/vpnctl/internal/restricted"
	"github.com/vgrinkevich/vpnctl/internal/wireguard"
)

const (
	NodePublicExchangeSchemaVersion = 1
	NodeSharedExchangeSchemaVersion = 1
	NodeTunnelCredentialBytes       = 32
	maximumNodePublicExchangeBytes  = 64 << 10

	NodeControlCSRHashName           = "control_csr"
	NodeWireGuardPublicKeyHashName   = "wireguard"
	NodeRestrictedCredentialHashName = "restricted_credential"
	NodeTunnelCredentialHashName     = "tunnel_credential"
)

type NodeCredentialReferences struct {
	ControlPrivateKey    model.SecretRef `json:"control_private_key"`
	WireGuardPrivateKey  model.SecretRef `json:"wireguard_private_key"`
	RestrictedCredential model.SecretRef `json:"restricted_credential"`
	TunnelCredential     model.SecretRef `json:"tunnel_credential"`
}

func NewNodeCredentialReferences(nodeID string, generation uint64) (NodeCredentialReferences, error) {
	if generation == 0 {
		return NodeCredentialReferences{}, fmt.Errorf("node credential generation must be positive")
	}
	if !transcriptUUIDPattern.MatchString(nodeID) {
		return NodeCredentialReferences{}, fmt.Errorf("node ID must be a canonical lower-case UUID")
	}
	suffix := fmt.Sprintf("%s-g%d", nodeID, generation)
	controlReference, err := model.NewSecretRef("control-key", suffix)
	if err != nil {
		return NodeCredentialReferences{}, err
	}
	wireGuardReference, err := model.NewSecretRef("wireguard-key", nodeID+"-standard-g"+fmt.Sprint(generation))
	if err != nil {
		return NodeCredentialReferences{}, err
	}
	restrictedReference, err := model.NewSecretRef("restricted-user", suffix)
	if err != nil {
		return NodeCredentialReferences{}, err
	}
	tunnelReference, err := model.NewSecretRef("tunnel-token", suffix)
	if err != nil {
		return NodeCredentialReferences{}, err
	}
	return NodeCredentialReferences{
		ControlPrivateKey: controlReference, WireGuardPrivateKey: wireGuardReference,
		RestrictedCredential: restrictedReference, TunnelCredential: tunnelReference,
	}, nil
}

func (references NodeCredentialReferences) Values() []model.SecretRef {
	return []model.SecretRef{
		references.ControlPrivateKey, references.WireGuardPrivateKey,
		references.RestrictedCredential, references.TunnelCredential,
	}
}

func (NodeCredentialReferences) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type NodePublicExchange struct {
	SchemaVersion        int               `json:"schema_version"`
	NodeID               string            `json:"node_id"`
	CredentialGeneration uint64            `json:"credential_generation"`
	ControlCSRPEM        string            `json:"control_csr_pem"`
	WireGuardPublicKey   string            `json:"wireguard_public_key"`
	MaterialHashes       map[string]string `json:"material_hashes"`
}

func (exchange NodePublicExchange) Validate() error {
	if exchange.SchemaVersion != NodePublicExchangeSchemaVersion || exchange.CredentialGeneration == 0 {
		return fmt.Errorf("invalid node public exchange version or generation")
	}
	csr := []byte(exchange.ControlCSRPEM)
	if err := validateCanonicalNodeCSR(csr, exchange.NodeID); err != nil {
		return err
	}
	wireGuardRaw, err := decodeCanonicalWireGuardPublicKey(exchange.WireGuardPublicKey)
	if err != nil {
		return err
	}
	defer clear(wireGuardRaw)
	if len(exchange.MaterialHashes) != 4 {
		return fmt.Errorf("node public exchange requires exactly four material hashes")
	}
	for _, name := range nodeMaterialHashNames() {
		value, present := exchange.MaterialHashes[name]
		if !present || !hashPattern.MatchString(value) {
			return fmt.Errorf("node public exchange material hash %s is invalid", name)
		}
	}
	if exchange.MaterialHashes[NodeControlCSRHashName] != sha256Hex(csr) ||
		exchange.MaterialHashes[NodeWireGuardPublicKeyHashName] != sha256Hex(wireGuardRaw) {
		return fmt.Errorf("node public exchange key material hash mismatch")
	}
	return nil
}

func (exchange NodePublicExchange) TranscriptHashes() (map[string][sha256.Size]byte, error) {
	if err := exchange.Validate(); err != nil {
		return nil, err
	}
	result := make(map[string][sha256.Size]byte, len(exchange.MaterialHashes))
	for _, name := range nodeMaterialHashNames() {
		decoded, err := hex.DecodeString(exchange.MaterialHashes[name])
		if err != nil || len(decoded) != sha256.Size {
			clear(decoded)
			return nil, fmt.Errorf("decode node material hash %s", name)
		}
		var digest [sha256.Size]byte
		copy(digest[:], decoded)
		clear(decoded)
		result[name] = digest
	}
	return result, nil
}

func EncodeNodePublicExchange(exchange NodePublicExchange) ([]byte, error) {
	if err := exchange.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(exchange)
	if err != nil {
		return nil, fmt.Errorf("encode node public exchange: %w", err)
	}
	if len(encoded) > maximumNodePublicExchangeBytes {
		clear(encoded)
		return nil, fmt.Errorf("node public exchange exceeds %d bytes", maximumNodePublicExchangeBytes)
	}
	return encoded, nil
}

func DecodeNodePublicExchange(encoded []byte) (NodePublicExchange, error) {
	if len(encoded) == 0 || len(encoded) > maximumNodePublicExchangeBytes {
		return NodePublicExchange{}, fmt.Errorf("node public exchange size is invalid")
	}
	var exchange NodePublicExchange
	if err := control.DecodeRPCPayload(json.RawMessage(encoded), &exchange); err != nil {
		return NodePublicExchange{}, fmt.Errorf("decode node public exchange: %w", err)
	}
	if err := exchange.Validate(); err != nil {
		return NodePublicExchange{}, err
	}
	return exchange, nil
}

type NodeCredentialInstallation struct {
	NodeID               string
	CredentialGeneration uint64
	References           NodeCredentialReferences
	PublicExchange       NodePublicExchange
	OwnedReferences      []model.SecretRef
}

func (NodeCredentialInstallation) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type NodeCredentialSecretStore interface {
	PutIfAbsent(model.SecretRef, []byte) error
	Get(model.SecretRef) ([]byte, error)
	Delete(model.SecretRef) (bool, error)
}

type NodeCredentialRuntime struct {
	Entropy         io.Reader
	WireGuardRunner wireguard.Runner
}

type nodeSharedCredentialWire struct {
	SchemaVersion        int    `json:"schema_version"`
	RestrictedCredential string `json:"restricted_credential"`
	TunnelCredential     string `json:"tunnel_credential"`
}

// NodeSharedCredentialExchange keeps the two necessarily shared symmetric
// credentials out of ordinary values and formatting. It deliberately has no
// accessor for either asymmetric private key.
type NodeSharedCredentialExchange struct {
	secret output.Secret
}

func decodeNodeSharedCredentialExchange(encoded []byte, exchange NodePublicExchange) (*NodeSharedCredentialExchange, error) {
	if err := exchange.Validate(); err != nil {
		return nil, err
	}
	var wire nodeSharedCredentialWire
	if err := control.DecodeRPCPayload(json.RawMessage(encoded), &wire); err != nil {
		return nil, fmt.Errorf("decode node shared credentials: %w", err)
	}
	restrictedCredential := []byte(wire.RestrictedCredential)
	tunnelCredential := []byte(wire.TunnelCredential)
	defer clear(restrictedCredential)
	defer clear(tunnelCredential)
	if wire.SchemaVersion != NodeSharedExchangeSchemaVersion {
		return nil, fmt.Errorf("unsupported node shared credential schema")
	}
	if _, err := restricted.DecodeIdentitySecret(restrictedCredential); err != nil ||
		sha256Hex(restrictedCredential) != exchange.MaterialHashes[NodeRestrictedCredentialHashName] {
		return nil, fmt.Errorf("node restricted credential does not match public commitment")
	}
	if validateNodeTunnelCredential(tunnelCredential) != nil ||
		sha256Hex(tunnelCredential) != exchange.MaterialHashes[NodeTunnelCredentialHashName] {
		return nil, fmt.Errorf("node tunnel credential does not match public commitment")
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		return nil, fmt.Errorf("node shared credential exchange must be canonical JSON")
	}
	secret, err := output.NewSecret(canonical)
	clear(canonical)
	if err != nil {
		return nil, err
	}
	return &NodeSharedCredentialExchange{secret: secret}, nil
}

func (exchange *NodeSharedCredentialExchange) Use(callback func(restrictedCredential, tunnelCredential []byte) error) error {
	if exchange == nil || callback == nil {
		return fmt.Errorf("node shared credential callback is required")
	}
	return exchange.secret.Use(func(encoded []byte) error {
		var wire nodeSharedCredentialWire
		if err := control.DecodeRPCPayload(json.RawMessage(encoded), &wire); err != nil {
			return fmt.Errorf("decode retained node shared credentials: %w", err)
		}
		restrictedCredential := []byte(wire.RestrictedCredential)
		tunnelCredential := []byte(wire.TunnelCredential)
		defer clear(restrictedCredential)
		defer clear(tunnelCredential)
		return callback(restrictedCredential, tunnelCredential)
	})
}

func (exchange *NodeSharedCredentialExchange) Destroy() {
	if exchange != nil {
		exchange.secret.Destroy()
	}
}

func (NodeSharedCredentialExchange) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

type NodeCredentialProvisioner struct {
	secrets NodeCredentialSecretStore
	runtime NodeCredentialRuntime
}

func NewNodeCredentialProvisioner(secrets NodeCredentialSecretStore, runtime NodeCredentialRuntime) (*NodeCredentialProvisioner, error) {
	if secrets == nil {
		return nil, fmt.Errorf("node credential secret store is required")
	}
	if runtime.Entropy == nil {
		runtime.Entropy = rand.Reader
	}
	return &NodeCredentialProvisioner{secrets: secrets, runtime: runtime}, nil
}

func (provisioner *NodeCredentialProvisioner) Provision(ctx context.Context, nodeID string, generation uint64) (NodeCredentialInstallation, error) {
	if ctx == nil {
		return NodeCredentialInstallation{}, fmt.Errorf("context is required")
	}
	if provisioner == nil || provisioner.secrets == nil || provisioner.runtime.Entropy == nil {
		return NodeCredentialInstallation{}, fmt.Errorf("node credential provisioner is incomplete")
	}
	references, err := NewNodeCredentialReferences(nodeID, generation)
	if err != nil {
		return NodeCredentialInstallation{}, err
	}
	if err := ctx.Err(); err != nil {
		return NodeCredentialInstallation{}, err
	}
	controlMaterial, err := control.GenerateNodeControlCSR(provisioner.runtime.Entropy, nodeID)
	if err != nil {
		return NodeCredentialInstallation{}, err
	}
	defer clear(controlMaterial.PrivateKeyPEM)
	wireGuardMaterial, err := wireguard.GenerateKeyPair(ctx, provisioner.runtime.WireGuardRunner)
	if err != nil {
		return NodeCredentialInstallation{}, err
	}
	wireGuardPrivate := []byte(wireGuardMaterial.PrivateKey)
	defer clear(wireGuardPrivate)
	wireGuardMaterial.PrivateKey = ""
	restrictedCredential, err := restricted.GenerateIdentitySecret(provisioner.runtime.Entropy)
	if err != nil {
		return NodeCredentialInstallation{}, fmt.Errorf("generate node restricted credential: %w", err)
	}
	defer clear(restrictedCredential)
	tunnelCredential, err := generateNodeTunnelCredential(provisioner.runtime.Entropy)
	if err != nil {
		return NodeCredentialInstallation{}, err
	}
	defer clear(tunnelCredential)
	if err := ctx.Err(); err != nil {
		return NodeCredentialInstallation{}, err
	}
	wireGuardPublicRaw, err := decodeCanonicalWireGuardPublicKey(wireGuardMaterial.PublicKey)
	if err != nil {
		return NodeCredentialInstallation{}, err
	}
	defer clear(wireGuardPublicRaw)
	exchange := NodePublicExchange{
		SchemaVersion: NodePublicExchangeSchemaVersion, NodeID: nodeID, CredentialGeneration: generation,
		ControlCSRPEM: string(controlMaterial.CSRPEM), WireGuardPublicKey: wireGuardMaterial.PublicKey,
		MaterialHashes: map[string]string{
			NodeControlCSRHashName:           sha256Hex(controlMaterial.CSRPEM),
			NodeWireGuardPublicKeyHashName:   sha256Hex(wireGuardPublicRaw),
			NodeRestrictedCredentialHashName: sha256Hex(restrictedCredential),
			NodeTunnelCredentialHashName:     sha256Hex(tunnelCredential),
		},
	}
	if err := exchange.Validate(); err != nil {
		return NodeCredentialInstallation{}, err
	}
	installation := NodeCredentialInstallation{
		NodeID: nodeID, CredentialGeneration: generation, References: references,
		PublicExchange: exchange, OwnedReferences: []model.SecretRef{},
	}
	entries := []struct {
		reference model.SecretRef
		content   []byte
	}{
		{reference: references.ControlPrivateKey, content: controlMaterial.PrivateKeyPEM},
		{reference: references.WireGuardPrivateKey, content: wireGuardPrivate},
		{reference: references.RestrictedCredential, content: restrictedCredential},
		{reference: references.TunnelCredential, content: tunnelCredential},
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			rollbackErr := provisioner.Rollback(context.Background(), installation)
			return NodeCredentialInstallation{}, errors.Join(err, rollbackErr)
		}
		if err := provisioner.secrets.PutIfAbsent(entry.reference, entry.content); err != nil {
			rollbackErr := provisioner.Rollback(context.Background(), installation)
			return NodeCredentialInstallation{}, errors.Join(fmt.Errorf("store node credential %s: %w", entry.reference, err), rollbackErr)
		}
		installation.OwnedReferences = append(installation.OwnedReferences, entry.reference)
	}
	return installation, nil
}

func (provisioner *NodeCredentialProvisioner) Rollback(ctx context.Context, installation NodeCredentialInstallation) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if provisioner == nil || provisioner.secrets == nil {
		return fmt.Errorf("node credential provisioner is incomplete")
	}
	expected, err := NewNodeCredentialReferences(installation.NodeID, installation.CredentialGeneration)
	if err != nil {
		return err
	}
	allowed := make(map[model.SecretRef]struct{}, len(expected.Values()))
	for _, reference := range expected.Values() {
		allowed[reference] = struct{}{}
	}
	seen := make(map[model.SecretRef]struct{}, len(installation.OwnedReferences))
	for _, reference := range installation.OwnedReferences {
		if _, ok := allowed[reference]; !ok {
			return fmt.Errorf("refuse rollback of non-node credential reference %s", reference)
		}
		if _, duplicate := seen[reference]; duplicate {
			return fmt.Errorf("refuse duplicate node credential rollback reference %s", reference)
		}
		seen[reference] = struct{}{}
	}
	var rollbackErrors []error
	for index := len(installation.OwnedReferences) - 1; index >= 0; index-- {
		if _, err := provisioner.secrets.Delete(installation.OwnedReferences[index]); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	return errors.Join(rollbackErrors...)
}

// SharedCredentialPayload reads only the two node-generated symmetric values
// needed by the gateway. The asymmetric control/WireGuard private keys have no
// code path into this payload.
func (provisioner *NodeCredentialProvisioner) SharedCredentialPayload(installation NodeCredentialInstallation) (*output.Secret, error) {
	if provisioner == nil || provisioner.secrets == nil {
		return nil, fmt.Errorf("node credential provisioner is incomplete")
	}
	if installation.NodeID != installation.PublicExchange.NodeID ||
		installation.CredentialGeneration != installation.PublicExchange.CredentialGeneration {
		return nil, fmt.Errorf("node credential installation is inconsistent")
	}
	expected, err := NewNodeCredentialReferences(installation.NodeID, installation.CredentialGeneration)
	if err != nil || expected != installation.References {
		return nil, fmt.Errorf("node credential references are invalid")
	}
	if err := installation.PublicExchange.Validate(); err != nil {
		return nil, err
	}
	restrictedCredential, err := provisioner.secrets.Get(expected.RestrictedCredential)
	if err != nil {
		return nil, fmt.Errorf("read node restricted credential: %w", err)
	}
	defer clear(restrictedCredential)
	if _, err := restricted.DecodeIdentitySecret(restrictedCredential); err != nil ||
		sha256Hex(restrictedCredential) != installation.PublicExchange.MaterialHashes[NodeRestrictedCredentialHashName] {
		return nil, fmt.Errorf("node restricted credential does not match public commitment")
	}
	tunnelCredential, err := provisioner.secrets.Get(expected.TunnelCredential)
	if err != nil {
		return nil, fmt.Errorf("read node tunnel credential: %w", err)
	}
	defer clear(tunnelCredential)
	if validateNodeTunnelCredential(tunnelCredential) != nil ||
		sha256Hex(tunnelCredential) != installation.PublicExchange.MaterialHashes[NodeTunnelCredentialHashName] {
		return nil, fmt.Errorf("node tunnel credential does not match public commitment")
	}
	encoded, err := json.Marshal(nodeSharedCredentialWire{
		SchemaVersion:        NodeSharedExchangeSchemaVersion,
		RestrictedCredential: string(restrictedCredential), TunnelCredential: string(tunnelCredential),
	})
	if err != nil {
		return nil, fmt.Errorf("encode node shared credential payload: %w", err)
	}
	defer clear(encoded)
	secret, err := output.NewSecret(encoded)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

func validateCanonicalNodeCSR(csr []byte, nodeID string) error {
	block, rest := pem.Decode(csr)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 ||
		!bytes.Equal(csr, pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes})) {
		return fmt.Errorf("node control CSR must be one canonical PEM block")
	}
	return control.ValidateNodeControlCSR(csr, nodeID)
}

func decodeCanonicalWireGuardPublicKey(value string) ([]byte, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return nil, fmt.Errorf("WireGuard public key must be canonical base64")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, fmt.Errorf("WireGuard public key must be canonical base64 for 256 bits")
	}
	return decoded, nil
}

func generateNodeTunnelCredential(entropy io.Reader) ([]byte, error) {
	raw := make([]byte, NodeTunnelCredentialBytes)
	if _, err := io.ReadFull(entropy, raw); err != nil {
		clear(raw)
		return nil, fmt.Errorf("generate node tunnel credential: %w", err)
	}
	encoded := []byte(base64.RawURLEncoding.EncodeToString(raw))
	clear(raw)
	return encoded, nil
}

func validateNodeTunnelCredential(encoded []byte) error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(encoded))
	if err != nil || len(decoded) != NodeTunnelCredentialBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != string(encoded) {
		clear(decoded)
		return fmt.Errorf("node tunnel credential must be canonical unpadded base64url for 256 bits")
	}
	clear(decoded)
	return nil
}

func nodeMaterialHashNames() []string {
	result := []string{
		NodeControlCSRHashName, NodeWireGuardPublicKeyHashName,
		NodeRestrictedCredentialHashName, NodeTunnelCredentialHashName,
	}
	sort.Strings(result)
	return result
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
