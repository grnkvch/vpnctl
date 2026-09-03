package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"

	"github.com/vgrinkevich/vpnctl/internal/control"
	"github.com/vgrinkevich/vpnctl/internal/model"
	"github.com/vgrinkevich/vpnctl/internal/output"
)

const (
	NodeRecoverySchemaVersion = 1
	recoveryProofDomain       = "vpnctl-node-recovery-proof-v1\x00"
)

type nodeRecoveryWireRequest struct {
	SchemaVersion     int             `json:"schema_version"`
	RecoveryID        string          `json:"recovery_id"`
	RequestID         string          `json:"request_id"`
	CurrentGeneration uint64          `json:"current_credential_generation"`
	PublicExchange    json.RawMessage `json:"public_exchange"`
	SharedCredentials json.RawMessage `json:"shared_credentials"`
	Proof             string          `json:"proof"`
}

type NodeRecoveryRequest struct {
	RecoveryID        string
	RequestID         string
	CurrentGeneration uint64
	PublicExchange    NodePublicExchange
	Proof             []byte
	shared            *NodeSharedCredentialExchange
}

func (request *NodeRecoveryRequest) Destroy() {
	if request == nil {
		return
	}
	clear(request.Proof)
	request.Proof = nil
	if request.shared != nil {
		request.shared.Destroy()
		request.shared = nil
	}
}

func (NodeRecoveryRequest) MarshalJSON() ([]byte, error) {
	return nil, output.ErrSensitiveSerialization
}

func (request *NodeRecoveryRequest) Validate(nodeNonce [EnrollmentNonceBytes]byte) error {
	if request == nil || request.shared == nil || !recoveryIDPattern.MatchString(request.RecoveryID) ||
		!transcriptUUIDPattern.MatchString(request.RequestID) || request.CurrentGeneration == 0 ||
		len(request.Proof) != ed25519.SignatureSize || allZero(nodeNonce[:]) {
		return fmt.Errorf("node recovery request is incomplete")
	}
	next, err := model.NextGeneration(request.CurrentGeneration)
	if err != nil || request.PublicExchange.CredentialGeneration != next {
		return fmt.Errorf("node recovery credential generation must advance exactly once")
	}
	return request.PublicExchange.Validate()
}

func (request *NodeRecoveryRequest) UseSharedCredentials(callback func([]byte, []byte) error) error {
	if request == nil || request.shared == nil || callback == nil {
		return fmt.Errorf("node recovery shared credentials are unavailable")
	}
	return request.shared.Use(callback)
}

func EncodeNodeRecoveryRequest(
	recoveryID string,
	requestID string,
	currentGeneration uint64,
	nodeNonce [EnrollmentNonceBytes]byte,
	installation NodeCredentialInstallation,
	sharedCredentials *output.Secret,
	currentControlPrivateKeyPEM []byte,
) (*output.Secret, error) {
	if sharedCredentials == nil {
		return nil, fmt.Errorf("node recovery shared credentials are required")
	}
	privateKey, err := parseRecoveryControlPrivateKey(currentControlPrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	unsigned := &NodeRecoveryRequest{
		RecoveryID: recoveryID, RequestID: requestID, CurrentGeneration: currentGeneration,
		PublicExchange: installation.PublicExchange,
	}
	proofInput, err := nodeRecoveryProofInput(unsigned, nodeNonce)
	if err != nil {
		return nil, err
	}
	proof := ed25519.Sign(privateKey, proofInput)
	clear(proofInput)
	defer clear(proof)
	publicBytes, err := EncodeNodePublicExchange(installation.PublicExchange)
	if err != nil {
		return nil, err
	}
	defer clear(publicBytes)
	var encoded []byte
	err = sharedCredentials.Use(func(shared []byte) error {
		validated, err := decodeNodeSharedCredentialExchange(shared, installation.PublicExchange)
		if err != nil {
			return err
		}
		validated.Destroy()
		wire := nodeRecoveryWireRequest{
			SchemaVersion: NodeRecoverySchemaVersion, RecoveryID: recoveryID, RequestID: requestID,
			CurrentGeneration: currentGeneration, PublicExchange: append(json.RawMessage(nil), publicBytes...),
			SharedCredentials: append(json.RawMessage(nil), shared...), Proof: base64.RawURLEncoding.EncodeToString(proof),
		}
		defer clear(wire.PublicExchange)
		defer clear(wire.SharedCredentials)
		encoded, err = json.Marshal(wire)
		return err
	})
	if err != nil {
		clear(encoded)
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > control.RPCMaximumRequestBytes {
		clear(encoded)
		return nil, fmt.Errorf("node recovery request exceeds %d bytes", control.RPCMaximumRequestBytes)
	}
	secret, err := output.NewSecret(encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

func DecodeNodeRecoveryRequest(encoded json.RawMessage, nodeNonce [EnrollmentNonceBytes]byte) (*NodeRecoveryRequest, error) {
	if len(encoded) == 0 || len(encoded) > control.RPCMaximumRequestBytes {
		return nil, fmt.Errorf("node recovery request size is invalid")
	}
	var wire nodeRecoveryWireRequest
	if err := control.DecodeRPCPayload(encoded, &wire); err != nil {
		return nil, fmt.Errorf("decode node recovery request: %w", err)
	}
	if wire.SchemaVersion != NodeRecoverySchemaVersion {
		return nil, fmt.Errorf("node recovery request version is invalid")
	}
	publicExchange, err := DecodeNodePublicExchange(wire.PublicExchange)
	if err != nil {
		return nil, err
	}
	shared, err := decodeNodeSharedCredentialExchange(wire.SharedCredentials, publicExchange)
	if err != nil {
		return nil, err
	}
	proof, err := decodeCanonicalBase64(wire.Proof)
	if err != nil {
		shared.Destroy()
		return nil, fmt.Errorf("node recovery proof encoding is invalid")
	}
	request := &NodeRecoveryRequest{
		RecoveryID: wire.RecoveryID, RequestID: wire.RequestID, CurrentGeneration: wire.CurrentGeneration,
		PublicExchange: publicExchange, Proof: proof, shared: shared,
	}
	if err := request.Validate(nodeNonce); err != nil {
		request.Destroy()
		return nil, err
	}
	return request, nil
}

func VerifyNodeRecoveryProof(
	request *NodeRecoveryRequest,
	nodeNonce [EnrollmentNonceBytes]byte,
	currentCertificatePEM []byte,
	wantedFingerprint string,
) error {
	if request == nil || !fingerprintPattern.MatchString(wantedFingerprint) {
		return ErrPublicEnrollmentRejected
	}
	certificate, err := parseSingleJoinCertificate(currentCertificatePEM)
	if err != nil || joinCertificateFingerprint(certificate) != wantedFingerprint {
		return fmt.Errorf("%w: current recovery certificate differs from binding", ErrPublicEnrollmentRejected)
	}
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: current recovery certificate key is invalid", ErrPublicEnrollmentRejected)
	}
	proofInput, err := nodeRecoveryProofInput(request, nodeNonce)
	if err != nil {
		return fmt.Errorf("%w: recovery proof context is invalid", ErrPublicEnrollmentRejected)
	}
	defer clear(proofInput)
	if !ed25519.Verify(publicKey, proofInput, request.Proof) {
		return fmt.Errorf("%w: recovery proof signature is invalid", ErrPublicEnrollmentRejected)
	}
	return nil
}

func nodeRecoveryProofInput(request *NodeRecoveryRequest, nodeNonce [EnrollmentNonceBytes]byte) ([]byte, error) {
	if request == nil || allZero(nodeNonce[:]) {
		return nil, fmt.Errorf("node recovery proof context is incomplete")
	}
	hashes, err := request.PublicExchange.TranscriptHashes()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(hashes))
	for name := range hashes {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := sha256.New()
	_, _ = digest.Write([]byte(recoveryProofDomain))
	writeRecoveryProofField(digest, "recovery_id", []byte(request.RecoveryID))
	writeRecoveryProofField(digest, "request_id", []byte(request.RequestID))
	writeRecoveryProofField(digest, "node_id", []byte(request.PublicExchange.NodeID))
	writeRecoveryProofField(digest, "current_generation", []byte(fmt.Sprint(request.CurrentGeneration)))
	writeRecoveryProofField(digest, "requested_generation", []byte(fmt.Sprint(request.PublicExchange.CredentialGeneration)))
	writeRecoveryProofField(digest, "node_nonce", nodeNonce[:])
	for _, name := range names {
		writeRecoveryProofField(digest, "material_name", []byte(name))
		value := hashes[name]
		writeRecoveryProofField(digest, "material_hash", value[:])
	}
	return digest.Sum(nil), nil
}

type recoveryProofHash interface {
	Write([]byte) (int, error)
}

func writeRecoveryProofField(writer recoveryProofHash, name string, value []byte) {
	_, _ = fmt.Fprintf(writer, "%08x", len(name))
	_, _ = writer.Write([]byte(name))
	_, _ = fmt.Fprintf(writer, "%08x", len(value))
	_, _ = writer.Write(value)
}

func parseRecoveryControlPrivateKey(encoded []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("current node control private key must be one PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse current node control private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("current node control private key is not Ed25519")
	}
	return privateKey, nil
}
