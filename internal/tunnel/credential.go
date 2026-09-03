package tunnel

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"

	"github.com/vgrinkevich/vpnctl/internal/model"
)

const (
	CredentialBytes         = 32
	CredentialReferenceKind = "tunnel-token"
)

var credentialHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// CredentialSecretReader returns an owned copy of a secret. The production
// store satisfies this contract with no-follow, owner-checked reads.
type CredentialSecretReader interface {
	Get(model.SecretRef) ([]byte, error)
}

// StoreCredentialSource connects the provider to generation-scoped root-only
// storage without exposing paths or storage errors to provider logs.
type StoreCredentialSource struct {
	secrets CredentialSecretReader
}

func NewStoreCredentialSource(secrets CredentialSecretReader) (*StoreCredentialSource, error) {
	if secrets == nil {
		return nil, fmt.Errorf("tunnel credential secret reader is required")
	}
	return &StoreCredentialSource{secrets: secrets}, nil
}

func (source *StoreCredentialSource) TunnelCredential(nodeID string, generation uint64) ([]byte, error) {
	if source == nil || source.secrets == nil {
		return nil, fmt.Errorf("tunnel credential source is incomplete")
	}
	reference, err := CredentialReference(nodeID, generation)
	if err != nil {
		return nil, err
	}
	value, err := source.secrets.Get(reference)
	if err != nil {
		return nil, fmt.Errorf("read tunnel credential")
	}
	defer clear(value)
	if err := ValidateCredential(value); err != nil {
		return nil, err
	}
	return append([]byte(nil), value...), nil
}

func CredentialReference(nodeID string, generation uint64) (model.SecretRef, error) {
	if err := validateUUID("tunnel credential node ID", nodeID); err != nil {
		return "", err
	}
	if generation == 0 {
		return "", fmt.Errorf("tunnel credential generation must be positive")
	}
	return model.NewSecretRef(CredentialReferenceKind, fmt.Sprintf("%s-g%d", nodeID, generation))
}

func GenerateCredential(entropy io.Reader) ([]byte, error) {
	if entropy == nil {
		return nil, fmt.Errorf("tunnel credential entropy source is required")
	}
	raw := make([]byte, CredentialBytes)
	if _, err := io.ReadFull(entropy, raw); err != nil {
		clear(raw)
		return nil, fmt.Errorf("generate tunnel credential: %w", err)
	}
	encoded := []byte(base64.RawURLEncoding.EncodeToString(raw))
	clear(raw)
	return encoded, nil
}

func ValidateCredential(value []byte) error {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(value))
	if err != nil || len(decoded) != CredentialBytes || base64.RawURLEncoding.EncodeToString(decoded) != string(value) {
		clear(decoded)
		return fmt.Errorf("tunnel credential must be canonical unpadded base64url for 256 bits")
	}
	clear(decoded)
	return nil
}

func CredentialSHA256(value []byte) (string, error) {
	if err := ValidateCredential(value); err != nil {
		return "", err
	}
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:]), nil
}

// CredentialCommitment is safe to persist or report: it identifies exactly
// one node generation and contains only a one-way digest, never token bytes or
// a filesystem location.
type CredentialCommitment struct {
	NodeID     string `json:"node_id"`
	Generation uint64 `json:"generation"`
	SHA256     string `json:"sha256"`
}

func NewCredentialCommitment(nodeID string, generation uint64, value []byte) (CredentialCommitment, error) {
	if _, err := CredentialReference(nodeID, generation); err != nil {
		return CredentialCommitment{}, err
	}
	digest, err := CredentialSHA256(value)
	if err != nil {
		return CredentialCommitment{}, err
	}
	return CredentialCommitment{NodeID: nodeID, Generation: generation, SHA256: digest}, nil
}

func (commitment CredentialCommitment) Validate() error {
	if _, err := CredentialReference(commitment.NodeID, commitment.Generation); err != nil {
		return err
	}
	if !credentialHashPattern.MatchString(commitment.SHA256) {
		return fmt.Errorf("tunnel credential commitment must be a SHA-256 hex digest")
	}
	return nil
}

func (commitment CredentialCommitment) Matches(nodeID string, generation uint64, value []byte) bool {
	if commitment.Validate() != nil || commitment.NodeID != nodeID || commitment.Generation != generation || ValidateCredential(value) != nil {
		return false
	}
	digest := sha256.Sum256(value)
	expected, err := hex.DecodeString(commitment.SHA256)
	if err != nil {
		return false
	}
	defer clear(expected)
	return subtle.ConstantTimeCompare(digest[:], expected) == 1
}

var _ FRPNodeCredentialSource = (*StoreCredentialSource)(nil)
